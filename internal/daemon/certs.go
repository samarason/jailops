package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/sdk/api"
)

// certManager decides which certificate the TLS listener serves (docs/exposure.md): the identity pair (generated
// self-signed in <data_dir>/tls/server.{crt,key}, or the files listen.https.cert and key name), an uploaded pair
// (<data_dir>/tls/uploaded.{crt,key}), or the ACME manager's certificate. The identity pair stays the daemon's own
// identity whatever is served: a hub presents it as its client certificate. A choice made through the API is kept in
// <data_dir>/tls/choice.json and wins over listen.https.acme of jailopsd.yaml; the operator's files win over both.
type certManager struct {
	tlsDir     string
	identity   *certReloader
	configured bool
	https      string // listen.https.address
	fileACME   ACMEConf
	log        *slog.Logger
	now        func() time.Time
	roots      *x509.CertPool // nil: the host's trusted roots
	acmeHTTP   *http.Client
	acmeClock  clock
	// listenChallenge opens the http-01 listener (tests listen on a free port).
	listenChallenge func(addr string) (net.Listener, error)
	tlsAddr         func() string
	onAttempt       func(error)

	mu       sync.Mutex
	ctx      context.Context
	source   api.CertificateSource
	stored   bool
	uploaded *certReloader
	acme     *acmeManager
	acmeAddr string // the challenge listener's address in use

	hstsMu   sync.Mutex
	hstsCert *tls.Certificate // the certificate hstsOK was decided for
	hstsOK   bool
}

// certChoice is choice.json.
type certChoice struct {
	Source   api.CertificateSource `json:"source"`
	ACME     *api.ACMESpec         `json:"acme,omitempty"`
	Hostname string                `json:"hostname,omitempty"`
	Time     time.Time             `json:"time"`
	By       string                `json:"by,omitempty"`
}

func (m *certManager) choicePath() string { return filepath.Join(m.tlsDir, "choice.json") }
func (m *certManager) uploadedPaths() (string, string) {
	return filepath.Join(m.tlsDir, "uploaded.crt"), filepath.Join(m.tlsDir, "uploaded.key")
}
func (m *certManager) acmeDir() string { return filepath.Join(m.tlsDir, "acme") }

// begin picks the source at start: the operator's files, else the stored choice, else listen.https.acme, else the
// self-signed certificate. A stored choice that no longer works (a broken upload) falls back to self-signed, logged.
func (m *certManager) begin(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctx = ctx
	if m.configured {
		m.source = api.CertSourceConfigured
		if _, err := os.Stat(m.choicePath()); err == nil {
			m.log.Warn("tls: listen.https.cert and key of jailopsd.yaml are served; the certificate chosen in the console is ignored", "choice", m.choicePath())
		}
		return
	}
	m.source = api.CertSourceSelfSigned
	var ch certChoice
	if b, err := os.ReadFile(m.choicePath()); err == nil && json.Unmarshal(b, &ch) == nil {
		m.stored = true
		switch ch.Source {
		case api.CertSourceUploaded:
			crt, key := m.uploadedPaths()
			c, err := tls.LoadX509KeyPair(crt, key)
			if err != nil {
				m.log.Error("tls: the uploaded certificate does not load; serving the self-signed one", "err", err)
				return
			}
			m.uploaded = newCertReloader(crt, key, c, m.log, m.now)
			m.source = api.CertSourceUploaded
			return
		case api.CertSourceACME:
			if ch.ACME != nil {
				if err := m.startACME(*ch.ACME); err != nil {
					m.log.Error("tls: ACME does not start; serving the self-signed certificate", "err", err)
				}
			}
			return
		case api.CertSourceSelfSigned:
			return
		}
	}
	if m.fileACME.Enabled {
		if err := m.startACME(m.fileACME.Spec()); err != nil {
			m.log.Error("tls: ACME does not start; serving the self-signed certificate", "err", err)
		}
	}
}

// end stops ACME.
func (m *certManager) end() {
	m.mu.Lock()
	a := m.acme
	m.acme = nil
	m.mu.Unlock()
	if a != nil {
		a.stop()
	}
}

// startACME makes ACME the source (m.mu held). The http-01 listener opens here and closes with the manager.
func (m *certManager) startACME(spec api.ACMESpec) error {
	spec = spec.Canonical()
	spec.Enabled = true
	if err := spec.Validate(); err != nil {
		return err
	}
	if m.https == "" {
		return api.Errorf(api.CodeInvalid, "ACME needs the TLS listener").WithHint("set listen.https.address, or jailopsd_web=\"YES\" in /etc/rc.conf")
	}
	addr := m.fileACME.ChallengeAddress
	if addr == "" {
		addr = DefaultChallengeAddress
	}
	var port int
	if spec.Challenge == api.ACMETLSALPN01 {
		if _, err := redirectTarget(m.https); err != nil {
			return api.Errorf(api.CodeInvalid, "tls-alpn-01: listen.https.address %v", err)
		}
		port = listenerPort(m.https, m.tlsAddr)
	} else if _, err := redirectTarget(addr); err != nil {
		return api.Errorf(api.CodeInvalid, "listen.https.acme.challenge_address: %v", err)
	}
	// the old manager holds the challenge port: it closes before the new listener opens
	m.stopACMELocked()
	var ln net.Listener
	if spec.Challenge == api.ACMEHTTP01 {
		listen := m.listenChallenge
		if listen == nil {
			listen = func(a string) (net.Listener, error) { return net.Listen("tcp", a) }
		}
		var err error
		if ln, err = listen(addr); err != nil {
			return api.Errorf(api.CodeInternal, "the ACME challenge listener %s: %v", addr, err)
		}
		port = listenerPort(ln.Addr().String(), nil)
	}
	a, err := newACMEManager(m.acmeDir(), spec, port, addr, m.tlsAddr, m.acmeHTTP, m.acmeClock, m.log)
	if err != nil {
		if ln != nil {
			ln.Close()
		}
		return err
	}
	a.onAttempt = m.onAttempt
	m.acme, m.acmeAddr, m.source = a, addr, api.CertSourceACME
	a.start(m.ctx, ln)
	return nil
}

// listenerPort is the port of a listener's address; with port 0 configured, the port the listener got.
func listenerPort(addr string, actual func() string) int {
	p := consolePort(addr)
	if p == 0 && actual != nil {
		p = consolePort(actual())
	}
	return p
}

// GetCertificate is tls.Config.GetCertificate: the challenge certificate of a tls-alpn-01 handshake, else the source.
func (m *certManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	src, a, up := m.source, m.acme, m.uploaded
	m.mu.Unlock()
	if hello != nil && slices.Equal(hello.SupportedProtos, []string{acme.ALPNProto}) {
		if a == nil {
			return nil, errors.New("acme: no tls-alpn-01 challenge is pending")
		}
		return a.alpnCert(hello.ServerName)
	}
	switch {
	case src == api.CertSourceACME && a != nil:
		if c := a.current(); c != nil {
			return c, nil
		}
	case src == api.CertSourceUploaded && up != nil:
		return up.GetCertificate(hello)
	}
	return m.identity.GetCertificate(hello)
}

// served is the certificate a handshake gets now.
func (m *certManager) served() *tls.Certificate {
	c, err := m.GetCertificate(nil)
	if err != nil {
		return nil
	}
	return c
}

// ServingFingerprint implements service.CertificateManager.
func (m *certManager) ServingFingerprint() string {
	if c := m.served(); c != nil {
		return fingerprintOf(*c)
	}
	return ""
}

// Redirect implements service.CertificateManager.
func (m *certManager) Redirect() *api.HostFirewallACME {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.source != api.CertSourceACME || m.acme == nil {
		return nil
	}
	return &api.HostFirewallACME{Challenge: m.acme.spec.Challenge, Port: m.acme.port}
}

// certInfo describes a certificate chain; roots decide PublicCA (nil: the host's trusted roots).
func certInfo(c *tls.Certificate, roots *x509.CertPool, now time.Time) api.CertificateInfo {
	if c == nil || len(c.Certificate) == 0 {
		return api.CertificateInfo{Names: []string{}}
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return api.CertificateInfo{Names: []string{}}
	}
	out := api.CertificateInfo{Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), Names: []string{}, NotBefore: leaf.NotBefore.UTC(),
		NotAfter: leaf.NotAfter.UTC(), Fingerprint: auth.Fingerprint(leaf.Raw)}
	out.Names = append(out.Names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		out.Names = append(out.Names, ip.String())
	}
	out.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
	if leaf.NotAfter.Before(now) {
		out.DaysLeft = -int(now.Sub(leaf.NotAfter).Hours()/24) - 1
	}
	out.SelfSigned = bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	inter := x509.NewCertPool()
	for _, der := range c.Certificate[1:] {
		if ic, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(ic)
		}
	}
	if !out.SelfSigned {
		_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		out.PublicCA = err == nil
	}
	return out
}

// HSTS reports whether Strict-Transport-Security may be sent: the certificate served now comes from ACME or was uploaded
// or configured, and it verifies against the host's trusted roots. Never for the self-signed certificate (also while
// ACME waits for its first certificate): a browser that saw the header refuses a certificate it does not trust, with no
// way to click through. The answer is kept per served certificate.
func (m *certManager) HSTS() bool {
	m.mu.Lock()
	src := m.source
	m.mu.Unlock()
	if src != api.CertSourceACME && src != api.CertSourceUploaded && src != api.CertSourceConfigured {
		return false
	}
	c := m.served()
	if c == nil {
		return false
	}
	m.hstsMu.Lock()
	defer m.hstsMu.Unlock()
	if c != m.hstsCert {
		info := certInfo(c, m.roots, m.now())
		m.hstsCert, m.hstsOK = c, info.PublicCA && !info.SelfSigned
	}
	return m.hstsOK
}

// Status implements service.CertificateManager.
func (m *certManager) Status(context.Context) api.HostCertificate {
	m.mu.Lock()
	src, a, stored, configured := m.source, m.acme, m.stored, m.configured
	m.mu.Unlock()
	out := api.HostCertificate{Kind: api.KindHostCertificate, Source: src, Current: certInfo(m.served(), m.roots, m.now()),
		Configured: configured, Stored: stored, Listener: m.https != "", Port: listenerPort(m.https, m.tlsAddr)}
	if a != nil {
		st := a.status()
		out.ACME = &st
		if a.current() == nil {
			out.Warnings = append(out.Warnings, "until the CA issues the certificate, the self-signed one is served")
		}
	}
	if src == api.CertSourceSelfSigned {
		out.Warnings = append(out.Warnings, "the certificate is self-signed: browsers warn, and clients pin its fingerprint")
	}
	if out.Current.DaysLeft < 14 && src != api.CertSourceACME && !out.Current.NotAfter.IsZero() {
		out.Warnings = append(out.Warnings, fmt.Sprintf("the certificate expires in %d days and nothing renews it", out.Current.DaysLeft))
	}
	return out
}

func (m *certManager) writable() error {
	if m.configured {
		return api.Errorf(api.CodeConflict, "jailopsd.yaml names the certificate files (listen.https.cert and key): the console cannot change them").
			WithHint("remove listen.https.cert and key from /usr/local/etc/jailops/jailopsd.yaml and restart jailopsd to choose the certificate here")
	}
	if m.https == "" {
		return api.Errorf(api.CodeInvalid, "the daemon has no TLS listener, so it serves no certificate").
			WithHint("set jailopsd_web=\"YES\" in /etc/rc.conf (or listen.https.address) and restart jailopsd")
	}
	return nil
}

func (m *certManager) saveChoice(ch certChoice) error {
	ch.Time = m.now().UTC()
	b, _ := json.MarshalIndent(ch, "", "  ")
	if err := writeAtomic0600(m.choicePath(), append(b, '\n')); err != nil {
		return api.Errorf(api.CodeInternal, "storing the choice: %v", err)
	}
	m.stored = true
	return nil
}

// Upload implements service.CertificateManager.
func (m *certManager) Upload(_ context.Context, in api.HostCertificateUpload, by string) error {
	if err := m.writable(); err != nil {
		return err
	}
	certPEM, keyPEM, _, err := validateUpload(in, m.now())
	if err != nil {
		return err
	}
	crt, key := m.uploadedPaths()
	// the key first: a reader that sees the new certificate finds its key
	if err := writeAtomic0600(key, keyPEM); err != nil {
		return api.Errorf(api.CodeInternal, "writing %s: %v", key, err)
	}
	if err := writeAtomic0600(crt, certPEM); err != nil {
		return api.Errorf(api.CodeInternal, "writing %s: %v", crt, err)
	}
	c, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return api.Errorf(api.CodeInternal, "the written pair does not load: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.saveChoice(certChoice{Source: api.CertSourceUploaded, Hostname: in.Hostname, By: by}); err != nil {
		return err
	}
	m.stopACMELocked()
	m.uploaded = newCertReloader(crt, key, c, m.log, m.now)
	m.source = api.CertSourceUploaded
	m.log.Info("tls: serving an uploaded certificate", "by", by, "fingerprint", fingerprintOf(c), "hostname", in.Hostname)
	return nil
}

// stopACMELocked stops ACME (m.mu held; the manager's stop takes none of m's locks).
func (m *certManager) stopACMELocked() {
	if m.acme != nil {
		m.acme.stop()
		m.acme = nil
	}
}

// UseACME implements service.CertificateManager.
func (m *certManager) UseACME(_ context.Context, spec api.ACMESpec, by string) error {
	if err := m.writable(); err != nil {
		return err
	}
	spec = spec.Canonical()
	spec.Enabled = true
	if err := spec.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if a := m.acme; a != nil && m.source == api.CertSourceACME && slices.Equal(a.spec.Domains, spec.Domains) && a.spec.DirectoryURL == spec.DirectoryURL &&
		a.spec.Challenge == spec.Challenge && a.spec.Email == spec.Email {
		a.request() // the same setting again: ask now (at most once a minute)
		return m.saveChoice(certChoice{Source: api.CertSourceACME, ACME: &spec, By: by})
	}
	// a new setting asks the CA at once: the new manager has no certificate for it
	if err := m.startACME(spec); err != nil {
		return err
	}
	m.log.Info("tls: ACME is the source of the certificate", "by", by, "domains", strings.Join(spec.Domains, ","), "challenge", spec.Challenge, "directory", spec.DirectoryURL)
	return m.saveChoice(certChoice{Source: api.CertSourceACME, ACME: &spec, By: by})
}

// UseSelfSigned implements service.CertificateManager.
func (m *certManager) UseSelfSigned(_ context.Context, by string) error {
	if err := m.writable(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.saveChoice(certChoice{Source: api.CertSourceSelfSigned, By: by}); err != nil {
		return err
	}
	m.stopACMELocked()
	m.uploaded = nil
	m.source = api.CertSourceSelfSigned
	m.log.Info("tls: serving the self-signed certificate again", "by", by)
	return nil
}

// Checks implements service.CertificateManager: tls.certificate (expiry of what is served) and tls.acme.
func (m *certManager) Checks(ctx context.Context) []api.DoctorCheck {
	st := m.Status(ctx)
	if !st.Listener {
		return nil
	}
	var out []api.DoctorCheck
	add := func(name string, s api.DoctorStatus, msg, hint string) {
		out = append(out, api.DoctorCheck{Name: name, Status: s, Message: msg, Hint: hint})
	}
	cur := st.Current
	switch {
	case cur.NotAfter.IsZero():
		add("tls.certificate", api.DoctorUnknown, "the served certificate cannot be read", "")
	case cur.DaysLeft < 0:
		add("tls.certificate", api.DoctorFail, "the served certificate ("+string(st.Source)+") expired on "+cur.NotAfter.Format("2006-01-02"), certHint(st.Source))
	case cur.DaysLeft < 14 && st.Source != api.CertSourceACME:
		add("tls.certificate", api.DoctorWarn, fmt.Sprintf("the served certificate (%s) expires in %d days", st.Source, cur.DaysLeft), certHint(st.Source))
	default:
		add("tls.certificate", api.DoctorOK, fmt.Sprintf("%s, valid for %d more days (%s)", st.Source, cur.DaysLeft, strings.Join(cur.Names, ", ")), "")
	}
	m.mu.Lock()
	a := m.acme
	m.mu.Unlock()
	if a == nil {
		add("tls.acme", api.DoctorOK, "not used (the certificate is "+string(st.Source)+")", "")
		return out
	}
	as := a.status()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	probe := a.selfCheck(cctx)
	leaf := a.current()
	switch {
	case probe != nil:
		add("tls.acme", api.DoctorWarn, "the challenge listener does not answer the daemon itself: "+probe.Error(),
			"check the daemon log; the CA reaches it only through the redirect of port "+fmt.Sprint(api.ACMEChallengePort(as.Spec.Challenge)))
	case as.LastError != "" && leaf == nil:
		add("tls.acme", api.DoctorWarn, "no certificate yet; the last request failed: "+as.LastError, nextHint(as))
	case as.LastError != "":
		add("tls.acme", api.DoctorWarn, fmt.Sprintf("the last renewal failed (%d days left): %s", cur.DaysLeft, as.LastError), nextHint(as))
	case leaf == nil:
		add("tls.acme", api.DoctorWarn, "no certificate yet ("+as.State+"); the self-signed one is served meanwhile", "")
	default:
		renew := ""
		if as.RenewAt != nil {
			renew = ", renewed from " + as.RenewAt.Format("2006-01-02")
		}
		add("tls.acme", api.DoctorOK, fmt.Sprintf("valid for %d more days%s; the challenge listener answers (port %d)", cur.DaysLeft, renew, as.ChallengePort), "")
	}
	return out
}

func certHint(src api.CertificateSource) string {
	if src == api.CertSourceConfigured {
		return "renew the files listen.https.cert and key name; the daemon picks them up without a restart"
	}
	return "upload a new certificate on the console's Host page, or let ACME renew it"
}

func nextHint(as api.ACMEStatus) string {
	if as.NextAttempt != nil {
		return "the next attempt is at " + as.NextAttempt.Format(time.RFC3339) + "; fix the cause, then request it again on the Host page"
	}
	return ""
}

// validateUpload checks an uploaded certificate: PEM certificates (leaf first, each signed by the next), one PEM key
// that matches the leaf, valid now, for server authentication, and valid for the host name. It returns the files to
// write, re-encoded so that nothing but the PEM blocks is kept.
func validateUpload(in api.HostCertificateUpload, now time.Time) (certPEM, keyPEM []byte, leaf *x509.Certificate, err error) {
	bad := func(format string, a ...any) error { return api.Errorf(api.CodeInvalid, format, a...) }
	if len(in.Certificate)+len(in.Key) > api.MaxCertificatePEM {
		return nil, nil, nil, bad("the certificate and the key together exceed %d bytes", api.MaxCertificatePEM)
	}
	host := strings.TrimSpace(strings.ToLower(in.Hostname))
	in.Hostname = host
	if ip := net.ParseIP(host); ip == nil && !api.ValidDNSName(host) {
		return nil, nil, nil, bad("hostname %q is not a host name or an address: give the name clients use to reach the console", in.Hostname)
	}
	var chain []*x509.Certificate
	var out bytes.Buffer
	rest := []byte(in.Certificate)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			if strings.Contains(blk.Type, "PRIVATE KEY") {
				return nil, nil, nil, bad("the certificate field holds a private key: put the key in the key field")
			}
			return nil, nil, nil, bad("the certificate field holds a %s block; only CERTIFICATE blocks belong there", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, nil, bad("certificate %d of the chain does not parse: %v", len(chain)+1, err)
		}
		chain = append(chain, c)
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
	}
	if len(chain) == 0 {
		return nil, nil, nil, bad("the certificate field holds no PEM certificate (-----BEGIN CERTIFICATE-----)")
	}
	if len(chain) > api.MaxCertificateChain {
		return nil, nil, nil, bad("the chain has %d certificates; at most %d", len(chain), api.MaxCertificateChain)
	}
	for i := 1; i < len(chain); i++ {
		if err := chain[i-1].CheckSignatureFrom(chain[i]); err != nil {
			return nil, nil, nil, bad("the chain is not in order: certificate %d is not signed by certificate %d (put the server's certificate first, then its issuers)", i, i+1)
		}
	}
	leaf = chain[0]
	kb, krest := pem.Decode([]byte(in.Key))
	switch {
	case kb == nil:
		return nil, nil, nil, bad("the key field holds no PEM private key (-----BEGIN PRIVATE KEY-----)")
	case kb.Type == "ENCRYPTED PRIVATE KEY" || kb.Headers["Proc-Type"] != "":
		return nil, nil, nil, bad("the key is encrypted: upload it without a passphrase (the daemon must read it at every start)")
	case !strings.HasSuffix(kb.Type, "PRIVATE KEY"):
		return nil, nil, nil, bad("the key field holds a %s block, not a private key", kb.Type)
	}
	if more, _ := pem.Decode(krest); more != nil {
		return nil, nil, nil, bad("the key field holds more than one PEM block")
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: kb.Type, Bytes: kb.Bytes})
	if _, err := tls.X509KeyPair(out.Bytes(), keyPEM); err != nil {
		return nil, nil, nil, bad("the key does not belong to the certificate: %v", err)
	}
	switch {
	case now.Before(leaf.NotBefore):
		return nil, nil, nil, bad("the certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case !now.Before(leaf.NotAfter):
		return nil, nil, nil, bad("the certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, nil, nil, bad("the certificate is not for server authentication (its extended key usage lacks serverAuth)")
	}
	if err := leaf.VerifyHostname(host); err != nil {
		names := append([]string(nil), leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			names = append(names, ip.String())
		}
		return nil, nil, nil, bad("the certificate is not valid for %s (its names: %s)", host, strings.Join(names, ", "))
	}
	return out.Bytes(), keyPEM, leaf, nil
}
