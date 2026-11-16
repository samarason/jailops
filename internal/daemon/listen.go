package daemon

import (
	"cmp"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

func (d *Daemon) listen() error {
	cfg := d.cfg
	if p := cfg.Listen.Unix.Path; p != "" {
		ln, err := listenUnix(p, os.FileMode(cfg.Listen.Unix.Mode))
		if err != nil {
			return err
		}
		d.unixLn = ln
		d.serve(ln, "unix", nil)
	}
	if a := cfg.Listen.HTTPS.Address; a != "" {
		tc := &tls.Config{
			GetCertificate: d.certMgr.GetCertificate, MinVersion: tls.VersionTLS13,
			// Client certificates are optional: a pinned one authenticates a
			// host or hub, everybody else uses a token or the UI login.
			ClientAuth: tls.RequestClientCert,
			// acme-tls/1 is the tls-alpn-01 challenge: answered with the challenge's certificate only
			NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
		}
		ln, err := tls.Listen("tcp", a, tc)
		if err != nil {
			return fmt.Errorf("daemon: listening on %s: %w", a, err)
		}
		d.httpsLn = ln
		d.serve(ln, "https", tc)
	}
	return nil
}

func (d *Daemon) serve(ln net.Listener, name string, _ *tls.Config) {
	hs := &http.Server{
		Handler:           d.srv.Handler(),
		ConnContext:       d.srv.ConnContext,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cmp.Or(d.opts.ReadTimeout, 2*time.Minute),
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(d.log.Handler(), slog.LevelWarn),
	}
	d.servers = append(d.servers, hs)
	d.go_(func() {
		if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Error("listener failed", "listener", name, "err", err)
			select {
			case d.failed <- fmt.Errorf("%s listener: %w", name, err):
			default:
			}
		}
	})
}

// listenUnix creates the socket. A socket nobody listens on is replaced; a
// live one means another daemon runs.
func listenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("daemon: %s is in use: another jailopsd is running", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if mode == 0 {
		mode = 0o666
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// consoleURLs are the addresses of the console, for the setup token: the listener's own address when it names one,
// else the host name (when it is qualified) and the host's unicast addresses, loopback and link-local left out.
func consoleURLs(addr, hostname string, ifaddrs func() ([]net.Addr, error)) []string {
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	url := func(h string) string { return "https://" + net.JoinHostPort(h, port) + "/" }
	if ip := net.ParseIP(host); host != "" && (ip == nil || !ip.IsUnspecified()) {
		return []string{url(host)}
	}
	var out []string
	if strings.Contains(hostname, ".") {
		out = append(out, url(hostname))
	}
	addrs, _ := ifaddrs()
	var v4, v6 []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() || n.IP.IsUnspecified() || n.IP.IsMulticast() {
			continue
		}
		if n.IP.To4() != nil {
			v4 = append(v4, url(n.IP.String()))
		} else if host != "0.0.0.0" {
			v6 = append(v6, url(n.IP.String()))
		}
	}
	out = append(append(out, v4...), v6...)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}
