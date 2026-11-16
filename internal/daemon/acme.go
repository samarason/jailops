package daemon

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"jailops.net/jailops/internal/supervise"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/sdk/api"
)

// ACME (RFC 8555) for the certificate of the console. The daemon is its own client, with golang.org/x/crypto/acme:
// an account key, one order for all domains, the http-01 or tls-alpn-01 challenge answered by the daemon itself (the
// host redirects port 80 or 443 to its unprivileged ports), and the certificate kept in <data_dir>/tls/acme (0700,
// files 0600). A scheduler checks once a day, with jitter, and renews 30 days before expiry; a failure waits longer
// each time (1 h, 2 h, 4 h ... at most a day), so a broken setup never hammers the CA. The new certificate is served
// from the next handshake on.
//
// UNVERIFIED: issuance by a real CA. Tests run the whole flow against a CA written in the test (acme_test.go); a person
// runs it once against the staging directory (docs/exposure.md says how).

const (
	acmeCheckEvery  = 24 * time.Hour
	acmeJitter      = time.Hour
	acmeBackoffBase = time.Hour
	acmeBackoffMax  = 24 * time.Hour
	// acmeManualGap is the least time between two attempts an administrator asks for.
	acmeManualGap = time.Minute
	acmeTimeout   = 10 * time.Minute
)

// acmeBackoff is the wait after the n-th failure in a row: 1 h, doubling, at most a day.
func acmeBackoff(failures int) time.Duration {
	d := acmeBackoffBase
	for i := 1; i < failures && d < acmeBackoffMax; i++ {
		d *= 2
	}
	return min(d, acmeBackoffMax)
}

// acmeCovers reports whether a certificate is valid now for every domain.
func acmeCovers(leaf *x509.Certificate, domains []string, now time.Time) bool {
	if leaf == nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	for _, d := range domains {
		if leaf.VerifyHostname(d) != nil {
			return false
		}
	}
	return true
}

// acmeRenewAt is when a certificate is renewed: api.ACMERenewBefore before it expires.
func acmeRenewAt(leaf *x509.Certificate) time.Time { return leaf.NotAfter.Add(-api.ACMERenewBefore) }

// acmeDue says whether the scheduler requests a certificate now: none covers the domains, or renewal time has come;
// never while a backoff runs, unless an administrator asked (manual), and then not twice within acmeManualGap.
func acmeDue(now time.Time, leaf *x509.Certificate, domains []string, st acmeState, manual bool) bool {
	if manual {
		return st.LastAttempt.IsZero() || !now.Before(st.LastAttempt.Add(acmeManualGap))
	}
	if st.Failures > 0 && now.Before(st.NextAttempt) {
		return false
	}
	return !acmeCovers(leaf, domains, now) || !now.Before(acmeRenewAt(leaf))
}

// acmeNext is when the scheduler looks again: at the end of a backoff, at the end of the gap of a manual request
// that came too early, or a day later with jitter.
func acmeNext(now time.Time, st acmeState, manual bool, jitter time.Duration) time.Time {
	if manual && !st.LastAttempt.IsZero() && now.Before(st.LastAttempt.Add(acmeManualGap)) {
		return st.LastAttempt.Add(acmeManualGap)
	}
	if st.Failures > 0 && now.Before(st.NextAttempt) {
		return st.NextAttempt
	}
	return now.Add(acmeCheckEvery + jitter)
}

// acmeState is status.json: what the scheduler did last.
type acmeState struct {
	Domains     []string  `json:"domains,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures,omitempty"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`
}

// clock is time for the scheduler; tests move it by hand.
type clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// acmeManager obtains and renews one certificate.
type acmeManager struct {
	dir  string
	spec api.ACMESpec
	// port is the daemon's port the CA's port is redirected to (status and the firewall); challengeAddr is the
	// http-01 listener's address, tlsAddr the TLS listener's (the self-check of tls-alpn-01).
	port          int
	challengeAddr string
	tlsAddr       func() string
	hc            *http.Client
	clock         clock
	jitter        func() time.Duration
	log           *slog.Logger
	// obtain gets a certificate; tests replace it to drive the scheduler alone. onAttempt hears how each ended.
	obtain    func(ctx context.Context) error
	onAttempt func(error)

	mu       sync.Mutex
	cert     *tls.Certificate
	leaf     *x509.Certificate
	st       acmeState
	state    string // idle, requesting, valid, error
	terms    string
	tokens   map[string]string
	alpn     map[string]*tls.Certificate
	manual   bool
	kick     chan struct{}
	httpLn   net.Listener
	httpSrv  *http.Server
	cancel   context.CancelFunc
	done     chan struct{}
	acctKey  crypto.Signer
	attempts int
}

func newACMEManager(dir string, spec api.ACMESpec, port int, challengeAddr string, tlsAddr func() string, hc *http.Client, c clock, log *slog.Logger) (*acmeManager, error) {
	if c == nil {
		c = realClock{}
	}
	m := &acmeManager{dir: dir, spec: spec.Canonical(), port: port, challengeAddr: challengeAddr, tlsAddr: tlsAddr, hc: hc, clock: c, log: log,
		jitter: func() time.Duration { return time.Duration(mrand.Int64N(int64(acmeJitter))) }, state: "idle",
		tokens: map[string]string{}, alpn: map[string]*tls.Certificate{}, kick: make(chan struct{}, 1)}
	m.obtain = m.obtainCert
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	m.loadState()
	m.loadCert()
	return m, nil
}

func (m *acmeManager) path(name string) string { return filepath.Join(m.dir, name) }

func (m *acmeManager) loadState() {
	b, err := os.ReadFile(m.path("status.json"))
	if err != nil {
		return
	}
	var st acmeState
	if json.Unmarshal(b, &st) == nil {
		// a failure counted for other domains says nothing about these
		if strings.Join(st.Domains, ",") != strings.Join(m.spec.Domains, ",") {
			st.Failures, st.NextAttempt, st.LastError = 0, time.Time{}, ""
		}
		m.st = st
	}
}

func (m *acmeManager) saveState() {
	m.st.Domains = m.spec.Domains
	b, _ := json.MarshalIndent(m.st, "", "  ")
	if err := writeAtomic0600(m.path("status.json"), append(b, '\n')); err != nil {
		m.log.Warn("acme: status not saved", "err", err)
	}
}

// loadCert serves the certificate of the cache when it covers the domains.
func (m *acmeManager) loadCert() {
	c, err := tls.LoadX509KeyPair(m.path("cert.pem"), m.path("key.pem"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.log.Warn("acme: the cached certificate does not load", "err", err)
		}
		return
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || !acmeCovers(leaf, m.spec.Domains, m.clock.Now()) {
		return
	}
	m.cert, m.leaf, m.state = &c, leaf, "valid"
}

// start opens the challenge listener (http-01) and runs the scheduler until stop.
func (m *acmeManager) start(parent context.Context, ln net.Listener) {
	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	m.cancel, m.done = cancel, make(chan struct{})
	if ln != nil {
		m.httpLn = ln
		m.httpSrv = &http.Server{Handler: http.HandlerFunc(m.serveChallenge), ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10,
			ErrorLog: slog.NewLogLogger(m.log.Handler(), slog.LevelDebug)}
		srv := m.httpSrv
		go func() { _ = srv.Serve(ln) }()
	}
	done := m.done
	m.mu.Unlock()
	go func() {
		defer close(done)
		supervise.Run(ctx, m.log, "acme", m.run)
	}()
}

// stop ends the scheduler and closes the challenge listener.
func (m *acmeManager) stop() {
	m.mu.Lock()
	cancel, done, srv := m.cancel, m.done, m.httpSrv
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	if srv != nil {
		_ = srv.Close()
	}
}

// request asks for an attempt now (the administrator's button), within acmeManualGap of the last one.
func (m *acmeManager) request() {
	m.mu.Lock()
	m.manual = true
	m.mu.Unlock()
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *acmeManager) run(ctx context.Context) {
	for {
		now := m.clock.Now()
		m.mu.Lock()
		manual := m.manual
		due := acmeDue(now, m.leaf, m.spec.Domains, m.st, manual)
		m.mu.Unlock()
		if due {
			m.attempt(ctx)
			if ctx.Err() != nil {
				return
			}
			continue
		}
		m.mu.Lock()
		next := acmeNext(now, m.st, manual, m.jitter())
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-m.kick:
		case <-m.clock.After(next.Sub(now)):
		}
	}
}

// attempt runs one order and records how it ended.
func (m *acmeManager) attempt(ctx context.Context) {
	m.mu.Lock()
	m.manual = false
	m.state = "requesting"
	m.attempts++
	m.st.LastAttempt = m.clock.Now().UTC()
	m.mu.Unlock()
	actx, cancel := context.WithTimeout(ctx, acmeTimeout)
	err := m.obtain(actx)
	cancel()
	if ctx.Err() != nil {
		return
	}
	defer func() {
		if m.onAttempt != nil {
			m.onAttempt(err)
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now().UTC()
	if err != nil {
		m.st.Failures++
		m.st.LastError = err.Error()
		m.st.NextAttempt = now.Add(acmeBackoff(m.st.Failures))
		m.state = "error"
		m.log.Warn("acme: the certificate request failed", "domains", strings.Join(m.spec.Domains, ","), "failures", m.st.Failures,
			"next_attempt", m.st.NextAttempt.Format(time.RFC3339), "err", err)
	} else {
		m.st.Failures, m.st.LastError, m.st.NextAttempt, m.st.LastSuccess = 0, "", time.Time{}, now
		m.state = "valid"
		m.log.Info("acme: certificate obtained", "domains", strings.Join(m.spec.Domains, ","), "not_after", m.leaf.NotAfter.Format(time.RFC3339),
			"fingerprint", auth.Fingerprint(m.leaf.Raw))
	}
	m.saveState()
}

// accountKey is the key of the ACME account, created once (P-256, 0600).
func (m *acmeManager) accountKey() (crypto.Signer, error) {
	if m.acctKey != nil {
		return m.acctKey, nil
	}
	b, err := os.ReadFile(m.path("account.key"))
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("acme: %s is not a PEM key", m.path("account.key"))
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme: %s: %w", m.path("account.key"), err)
		}
		m.acctKey = k
		return k, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := writeAtomic0600(m.path("account.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	m.acctKey = k
	return k, nil
}

func (m *acmeManager) client() (*acme.Client, error) {
	k, err := m.accountKey()
	if err != nil {
		return nil, err
	}
	return &acme.Client{Key: k, DirectoryURL: m.spec.DirectoryURL, HTTPClient: m.hc, UserAgent: "jailops"}, nil
}

// obtainCert runs one order: the account, the authorizations with the chosen challenge, the CSR, the chain.
func (m *acmeManager) obtainCert(ctx context.Context) error {
	cl, err := m.client()
	if err != nil {
		return err
	}
	dir, err := cl.Discover(ctx)
	if err != nil {
		return fmt.Errorf("reading the CA's directory %s: %w", m.spec.DirectoryURL, err)
	}
	m.mu.Lock()
	m.terms = dir.Terms
	m.mu.Unlock()
	acct := &acme.Account{}
	if m.spec.Email != "" {
		acct.Contact = []string{"mailto:" + m.spec.Email}
	}
	if _, err := cl.Register(ctx, acct, func(string) bool { return m.spec.AcceptTOS }); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("registering the account: %w", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(m.spec.Domains...))
	if err != nil {
		return fmt.Errorf("creating the order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		if err := m.authorize(ctx, cl, z); err != nil {
			return err
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("waiting for the order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: m.spec.Domains[0]}, DNSNames: m.spec.Domains}, key)
	if err != nil {
		return err
	}
	chain, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalizing the order: %w", err)
	}
	return m.keep(chain, key)
}

// authorize answers one authorization with the chosen challenge and waits for the CA's verdict.
func (m *acmeManager) authorize(ctx context.Context, cl *acme.Client, z *acme.Authorization) error {
	name := z.Identifier.Value
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == string(m.spec.Challenge) {
			chal = c
		}
	}
	if chal == nil {
		return fmt.Errorf("the CA offers no %s challenge for %s", m.spec.Challenge, name)
	}
	switch m.spec.Challenge {
	case api.ACMETLSALPN01:
		cert, err := cl.TLSALPN01ChallengeCert(chal.Token, name)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.alpn[name] = &cert
		m.mu.Unlock()
		defer func() { m.mu.Lock(); delete(m.alpn, name); m.mu.Unlock() }()
	default:
		resp, err := cl.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.tokens[chal.Token] = resp
		m.mu.Unlock()
		defer func() { m.mu.Lock(); delete(m.tokens, chal.Token); m.mu.Unlock() }()
	}
	if _, err := cl.Accept(ctx, chal); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("%s: the CA could not verify the %s challenge (is port %d redirected to the daemon, and does the name point at this host?): %w",
			name, m.spec.Challenge, api.ACMEChallengePort(m.spec.Challenge), err)
	}
	return nil
}

// keep checks the chain the CA returned and writes it with its key (0600, atomically), then serves it.
func (m *acmeManager) keep(chain [][]byte, key *ecdsa.PrivateKey) error {
	if len(chain) == 0 {
		return errors.New("the CA returned no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return fmt.Errorf("the CA's certificate does not parse: %w", err)
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("the CA's certificate is not for the key of the request")
	}
	if !acmeCovers(leaf, m.spec.Domains, m.clock.Now()) {
		return fmt.Errorf("the CA's certificate is not valid now for %s", strings.Join(m.spec.Domains, ", "))
	}
	var certPEM bytes.Buffer
	for _, der := range chain {
		_ = pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	c, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM)
	if err != nil {
		return err
	}
	if err := writeAtomic0600(m.path("key.pem"), keyPEM); err != nil {
		return err
	}
	if err := writeAtomic0600(m.path("cert.pem"), certPEM.Bytes()); err != nil {
		return err
	}
	c.Leaf = leaf
	m.mu.Lock()
	m.cert, m.leaf = &c, leaf
	m.mu.Unlock()
	return nil
}

// serveChallenge answers http-01: /.well-known/acme-challenge/<token> with the key authorization, 404 for
// everything else. This listener serves nothing but the challenges.
func (m *acmeManager) serveChallenge(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	m.mu.Lock()
	v, found := m.tokens[tok]
	m.mu.Unlock()
	if !ok || !found || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, v)
}

// alpnCert is the certificate of a tls-alpn-01 challenge for name.
func (m *acmeManager) alpnCert(name string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.alpn[strings.ToLower(name)]; c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("acme: no tls-alpn-01 challenge for %q", name)
}

// current is the certificate to serve, nil while there is none.
func (m *acmeManager) current() *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cert
}

func (m *acmeManager) status() api.ACMEStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := api.ACMEStatus{Spec: m.spec, State: m.state, LastError: m.st.LastError, Failures: m.st.Failures, ChallengePort: m.port, TermsURL: m.terms}
	tp := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		u := t.UTC()
		return &u
	}
	out.LastAttempt, out.LastSuccess, out.NextAttempt = tp(m.st.LastAttempt), tp(m.st.LastSuccess), tp(m.st.NextAttempt)
	if m.leaf != nil {
		out.RenewAt = tp(acmeRenewAt(m.leaf))
	}
	if m.state == "idle" && m.leaf == nil && m.st.LastError != "" {
		out.State = "error"
	}
	return out
}

// selfCheck connects from the daemon to its own challenge listener: http-01 fetches a probe token, tls-alpn-01
// completes a handshake that asks for acme-tls/1. It proves the listener answers, not that the CA reaches it.
func (m *acmeManager) selfCheck(ctx context.Context) error {
	probe := make([]byte, 16)
	_, _ = rand.Read(probe)
	tok := "jailops-selfcheck-" + hex.EncodeToString(probe)
	if m.spec.Challenge == api.ACMETLSALPN01 {
		name := "selfcheck.jailops.invalid"
		cert, err := selfCheckCert(name)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.alpn[name] = cert
		m.mu.Unlock()
		defer func() { m.mu.Lock(); delete(m.alpn, name); m.mu.Unlock() }()
		addr := loopbackOf(m.tlsAddr())
		d := tls.Dialer{Config: &tls.Config{ServerName: name, NextProtos: []string{acme.ALPNProto}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("the TLS listener %s does not answer a tls-alpn-01 handshake: %w", addr, err)
		}
		defer c.Close()
		cs := c.(*tls.Conn).ConnectionState()
		if cs.NegotiatedProtocol != acme.ALPNProto || len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, cert.Certificate[0]) {
			return fmt.Errorf("the TLS listener %s answered acme-tls/1 with the wrong certificate", addr)
		}
		return nil
	}
	m.mu.Lock()
	ln := m.httpLn
	m.tokens[tok] = tok + ".probe"
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.tokens, tok); m.mu.Unlock() }()
	if ln == nil {
		return errors.New("the challenge listener is not open")
	}
	addr := loopbackOf(ln.Addr().String())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/.well-known/acme-challenge/"+tok, nil)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("the challenge listener %s does not answer: %w", addr, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	if res.StatusCode != 200 || string(b) != tok+".probe" {
		return fmt.Errorf("the challenge listener %s answered %d %q", addr, res.StatusCode, b)
	}
	return nil
}

// loopbackOf turns a listener's address into one to connect to: an unspecified host becomes 127.0.0.1.
func loopbackOf(addr string) string {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(h); h == "" || (ip != nil && ip.IsUnspecified()) {
		h = "127.0.0.1"
	}
	return net.JoinHostPort(h, p)
}

func selfCheckCert(name string) (*tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

// writeAtomic0600 writes a file only the daemon reads: a temporary file in the same directory, synced, renamed.
func writeAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
