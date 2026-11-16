package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"jailops.net/jailops/internal/auth"
)

// loadOrCreateCert loads the server certificate. With no configured paths (explicit false) it generates a self-signed one
// (ten years: peers pin its fingerprint, so it is not rotated by expiry) on first start; names become subject alternative
// names. A certificate the operator configured is never generated and never overwritten: if it is missing or only one of
// the two files exists, that is an error. A pair that exists but does not parse is an error too.
func loadOrCreateCert(certPath, keyPath string, explicit bool, hostname string, names []string, now time.Time) (tls.Certificate, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("tls: %w", err)
		}
		return cert, nil
	case certErr == nil || keyErr == nil:
		// Never regenerate over half a pair: that would destroy the operator's certificate or key.
		return tls.Certificate{}, fmt.Errorf("tls: %s and %s must both exist (only one does); refusing to generate a certificate over it", certPath, keyPath)
	case explicit:
		return tls.Certificate{}, fmt.Errorf("tls: the configured certificate %s and key %s do not exist (jailopsd generates a certificate only when listen.https.cert and key are not set)", certPath, keyPath)
	case !errors.Is(certErr, fs.ErrNotExist):
		return tls.Certificate{}, fmt.Errorf("tls: %w", certErr)
	case !errors.Is(keyErr, fs.ErrNotExist):
		return tls.Certificate{}, fmt.Errorf("tls: %w", keyErr)
	}
	o := auth.CertOptions{CommonName: hostname, Validity: 10 * 365 * 24 * time.Hour, Now: now}
	if hostname != "" {
		o.DNSNames = append(o.DNSNames, hostname)
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			o.IPs = append(o.IPs, ip)
		} else {
			o.DNSNames = append(o.DNSNames, n)
		}
	}
	c, certPEM, keyPEM, err := auth.GenerateCertificate(o)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return tls.Certificate{}, err
	}
	// the key: a new file of mode 0600 renamed into place, never written through what is at its name
	if err := writeAtomic0600(keyPath, keyPEM); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return c, nil
}

// certReloadEvery bounds how often the certificate files are looked at: once per interval, on a handshake.
const certReloadEvery = 15 * time.Second

// certReloader serves the server certificate and picks up a renewed one without a restart. On a handshake, at most once
// per certReloadEvery, it compares the modification time and size of the certificate and key files with the last
// load; when they changed it parses the pair. A pair that does not parse (a half-written renewal) is logged and the
// certificate in use stays, so a bad renewal never takes the listener down.
type certReloader struct {
	certPath, keyPath string
	log               *slog.Logger
	now               func() time.Time

	mu      sync.Mutex
	cur     *tls.Certificate
	stamp   [2]fileStamp
	checked time.Time
}

type fileStamp struct {
	mod  time.Time
	size int64
}

func stampOf(path string) fileStamp {
	st, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{st.ModTime(), st.Size()}
}

func newCertReloader(certPath, keyPath string, first tls.Certificate, log *slog.Logger, now func() time.Time) *certReloader {
	if now == nil {
		now = time.Now
	}
	r := &certReloader{certPath: certPath, keyPath: keyPath, log: log, now: now, cur: &first, checked: now()}
	r.stamp = [2]fileStamp{stampOf(certPath), stampOf(keyPath)}
	return r
}

// GetCertificate is tls.Config.GetCertificate.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); now.Sub(r.checked) >= certReloadEvery {
		r.checked = now
		st := [2]fileStamp{stampOf(r.certPath), stampOf(r.keyPath)}
		if st != r.stamp {
			c, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
			switch {
			case err != nil:
				// Keep the old pair, and look again at the next interval only if the files change again.
				r.stamp = st
				r.log.Warn("tls certificate changed on disk but does not load; still serving the previous one", "cert", r.certPath, "err", err)
			default:
				r.stamp, r.cur = st, &c
				r.log.Info("tls certificate reloaded", "cert", r.certPath, "fingerprint", fingerprintOf(c))
			}
		}
	}
	return r.cur, nil
}

// Current is the certificate in use.
func (r *certReloader) Current() tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return *r.cur
}

// fingerprintOf returns the SHA-256 pin of the leaf certificate.
func fingerprintOf(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	return auth.Fingerprint(c.Certificate[0])
}

var _ = x509.Certificate{}
var _ = pem.Block{}
