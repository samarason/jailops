package daemon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

func TestACMEBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{1: time.Hour, 2: 2 * time.Hour, 3: 4 * time.Hour, 5: 16 * time.Hour, 6: 24 * time.Hour, 40: 24 * time.Hour} {
		if got := acmeBackoff(n); got != want {
			t.Errorf("failure %d: %s, want %s", n, got, want)
		}
	}
}

func leafFor(t *testing.T, names []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// When the scheduler asks the CA: no certificate, one for other names, renewal time (30 days before expiry); never
// during a backoff, except for an administrator's request, which itself waits a minute after the last attempt.
func TestACMEDueAndNext(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	dom := []string{"console.example.com"}
	fresh := leafFor(t, dom, now.Add(-24*time.Hour), now.Add(89*24*time.Hour))
	renew := leafFor(t, dom, now.Add(-61*24*time.Hour), now.Add(29*24*time.Hour))
	other := leafFor(t, []string{"other.example.com"}, now.Add(-time.Hour), now.Add(80*24*time.Hour))
	expired := leafFor(t, dom, now.Add(-91*24*time.Hour), now.Add(-time.Hour))
	failed := acmeState{Failures: 2, LastAttempt: now.Add(-30 * time.Minute), NextAttempt: now.Add(90 * time.Minute)}
	for _, c := range []struct {
		name   string
		leaf   *x509.Certificate
		st     acmeState
		manual bool
		due    bool
	}{
		{"none", nil, acmeState{}, false, true},
		{"fresh", fresh, acmeState{}, false, false},
		{"renewal time", renew, acmeState{}, false, true},
		{"other names", other, acmeState{}, false, true},
		{"expired", expired, acmeState{}, false, true},
		{"backoff", nil, failed, false, false},
		{"backoff over", nil, acmeState{Failures: 2, NextAttempt: now.Add(-time.Second)}, false, true},
		{"manual in a backoff", nil, failed, true, true},
		{"manual too soon", fresh, acmeState{LastAttempt: now.Add(-30 * time.Second)}, true, false},
		{"manual on a fresh one", fresh, acmeState{LastAttempt: now.Add(-2 * time.Minute)}, true, true},
	} {
		if got := acmeDue(now, c.leaf, dom, c.st, c.manual); got != c.due {
			t.Errorf("%s: due %v", c.name, got)
		}
	}
	j := 17 * time.Minute
	if got := acmeNext(now, acmeState{}, false, j); !got.Equal(now.Add(24*time.Hour + j)) {
		t.Errorf("daily: %s", got)
	}
	if got := acmeNext(now, failed, false, j); !got.Equal(failed.NextAttempt) {
		t.Errorf("backoff: %s", got)
	}
	if got := acmeNext(now, acmeState{LastAttempt: now.Add(-20 * time.Second)}, true, j); !got.Equal(now.Add(40 * time.Second)) {
		t.Errorf("manual gap: %s", got)
	}
}

// fakeClock is moved by the test; After registers a wake-up and tells the test how long the scheduler waits.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	waits chan time.Duration
	ch    chan time.Time
	at    time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	ch := make(chan time.Time, 1)
	c.ch, c.at = ch, c.now.Add(d)
	c.mu.Unlock()
	c.waits <- d
	return ch
}

// advance moves the clock to the wake-up the scheduler asked for and fires it.
func (c *fakeClock) fire() {
	c.mu.Lock()
	c.now = c.at
	ch, now := c.ch, c.now
	c.mu.Unlock()
	ch <- now
}

func (c *fakeClock) set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }

// fireAt wakes the scheduler with the clock at t (a jump past the wake-up it asked for).
func (c *fakeClock) fireAt(t time.Time) {
	c.mu.Lock()
	c.now = t
	ch := c.ch
	c.mu.Unlock()
	ch <- t
}

// The scheduler with an injected clock: the first attempt at once, a daily check with jitter, a renewal 30 days
// before expiry, a backoff of 1 h, 2 h after failures, and an administrator's request that cuts a backoff short.
func TestACMESchedulerTiming(t *testing.T) {
	start := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	clk := &fakeClock{now: start, waits: make(chan time.Duration)}
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := newACMEManager(dir, api.ACMESpec{Enabled: true, Domains: []string{"console.example.com"}, AcceptTOS: true}, 39080, ":39080", nil, nil, clk, log)
	if err != nil {
		t.Fatal(err)
	}
	m.jitter = func() time.Duration { return 10 * time.Minute }
	results := make(chan error, 1)
	attempts := make(chan time.Time, 8)
	m.obtain = func(context.Context) error {
		now := clk.Now()
		attempts <- now
		err := <-results
		if err == nil {
			m.mu.Lock()
			m.leaf = leafFor(t, []string{"console.example.com"}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
			m.cert = &tls.Certificate{Certificate: [][]byte{m.leaf.Raw}}
			m.mu.Unlock()
		}
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	expectAttempt := func(at time.Time, res error) {
		t.Helper()
		if got := <-attempts; !got.Equal(at) {
			t.Fatalf("attempt at %s, want %s", got, at)
		}
		results <- res
	}
	expectWait := func(d time.Duration) {
		t.Helper()
		if got := <-clk.waits; got != d {
			t.Fatalf("waits %s, want %s", got, d)
		}
	}
	// no certificate: at once; it fails, the next try is an hour later
	expectAttempt(start, errors.New("connection refused"))
	expectWait(time.Hour)
	clk.fire()
	expectAttempt(start.Add(time.Hour), errors.New("connection refused"))
	expectWait(2 * time.Hour)
	if st := m.status(); st.State != "error" || st.Failures != 2 || !strings.Contains(st.LastError, "refused") || st.NextAttempt == nil {
		t.Fatalf("%+v", st)
	}
	// the administrator asks twice: within a minute of the last attempt it waits for the rest of the minute, after that
	// the backoff is cut short
	m.request()
	expectWait(time.Minute)
	clk.set(start.Add(time.Hour + 2*time.Minute))
	m.request()
	expectAttempt(start.Add(time.Hour+2*time.Minute), nil)
	// success: the daily check with jitter
	expectWait(24*time.Hour + 10*time.Minute)
	if st := m.status(); st.State != "valid" || st.Failures != 0 || st.LastError != "" || st.RenewAt == nil {
		t.Fatalf("%+v", st)
	}
	renewAt := *m.status().RenewAt
	// daily checks find nothing to do until the renewal time
	clk.fire()
	expectWait(24*time.Hour + 10*time.Minute)
	clk.fireAt(renewAt.Add(-time.Hour)) // the day before the renewal time: nothing
	expectWait(24*time.Hour + 10*time.Minute)
	clk.fire() // past the renewal time: renewed
	expectAttempt(renewAt.Add(-time.Hour).Add(24*time.Hour+10*time.Minute), nil)
	expectWait(24*time.Hour + 10*time.Minute)
	// the state survives in status.json, 0600
	if fi, err := os.Stat(filepath.Join(dir, "status.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", fi, err)
	}
}

// The http-01 listener answers the tokens of pending challenges and nothing else.
func TestACMEChallengeHandler(t *testing.T) {
	m := &acmeManager{tokens: map[string]string{"tok1": "tok1.thumb"}, alpn: map[string]*tls.Certificate{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	m.clock = realClock{}
	m.jitter = func() time.Duration { return 0 }
	m.kick = make(chan struct{}, 1)
	m.obtain = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	m.spec = api.ACMESpec{Challenge: api.ACMEHTTP01}
	m.st.Failures, m.st.NextAttempt = 1, time.Now().Add(time.Hour) // the scheduler waits; only the listener matters
	m.start(context.Background(), ln)
	defer m.stop()
	get := func(path, method string) (int, string) {
		req, _ := http.NewRequest(method, "http://"+ln.Addr().String()+path, nil)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := get("/.well-known/acme-challenge/tok1", "GET"); code != 200 || body != "tok1.thumb" {
		t.Errorf("%d %q", code, body)
	}
	for _, p := range []string{"/.well-known/acme-challenge/other", "/", "/api/v1", "/.well-known/acme-challenge/", "/.well-known/acme-challenge/tok1/x"} {
		if code, _ := get(p, "GET"); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		if code, _ := get("/.well-known/acme-challenge/tok1", method); code != 404 {
			t.Errorf("%s: %d", method, code)
		}
	}
	if code, _ := get("/.well-known/acme-challenge/tok1", "HEAD"); code != 200 {
		t.Errorf("HEAD: %d", code)
	}
	for _, p := range []string{"/.well-known/acme-challenge/TOK1", "/.well-known/acme-challenge/tok1%2F..", "/.well-known/acme-challenge/../acme-challenge/tok2", "/x/.well-known/acme-challenge/tok1"} {
		if code, _ := get(p, "GET"); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
	if err := m.selfCheck(context.Background()); err != nil {
		t.Errorf("self-check: %v", err)
	}
	if len(m.tokens) != 1 {
		t.Errorf("the probe token stayed: %v", m.tokens)
	}
}

// Atomic writes: mode 0600 from the start, no temporary file left, the old content intact when the write fails.
func TestWriteAtomic0600(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key.pem")
	if err := writeAtomic0600(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic0600(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Errorf("%q", b)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("left behind: %v", ents)
	}
	if err := writeAtomic0600(filepath.Join(dir, "missing", "x"), []byte("x")); err == nil {
		t.Error("a write into a missing directory succeeded")
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Errorf("%q", b)
	}
}

// pemPair makes a key and a certificate signed by parent (self-signed without one).
type pemPair struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM string
	keyPEM  string
}

func makePair(t *testing.T, tpl *x509.Certificate, parent *pemPair) *pemPair {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, signerCert := k, tpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, &k.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return &pemPair{cert: c, key: k, certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))}
}

// What an upload must be: a chain that parses and is in order, a key of the leaf (not encrypted), valid now, for
// server authentication and for the host name.
func TestValidateUpload(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	root := makePair(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 3650)}, nil)
	inter := makePair(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "inter"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 3650)}, root)
	leafTpl := func(names []string, nb, na time.Time, eku ...x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: nb, NotAfter: na, ExtKeyUsage: eku}
	}
	leaf := makePair(t, leafTpl([]string{"console.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), x509.ExtKeyUsageServerAuth), inter)
	other := makePair(t, leafTpl([]string{"console.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour)), inter)
	expired := makePair(t, leafTpl([]string{"console.example.com"}, now.Add(-100*24*time.Hour), now.Add(-time.Hour)), inter)
	future := makePair(t, leafTpl([]string{"console.example.com"}, now.Add(time.Hour), now.Add(90*24*time.Hour)), inter)
	client := makePair(t, leafTpl([]string{"console.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), x509.ExtKeyUsageClientAuth), inter)
	chain := leaf.certPEM + inter.certPEM
	good := api.HostCertificateUpload{Certificate: "text before\n" + chain + "after", Key: leaf.keyPEM, Hostname: "Console.Example.com"}
	certPEM, keyPEM, l, err := validateUpload(good, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(certPEM) != chain || string(keyPEM) != leaf.keyPEM || l.Subject.CommonName != "console.example.com" {
		t.Errorf("not re-encoded:\n%s", certPEM)
	}
	encKey := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
	for name, c := range map[string]struct {
		in   api.HostCertificateUpload
		want string
	}{
		"no certificate":    {api.HostCertificateUpload{Certificate: "hello", Key: leaf.keyPEM, Hostname: "console.example.com"}, "no PEM certificate"},
		"key in cert field": {api.HostCertificateUpload{Certificate: leaf.keyPEM, Key: leaf.keyPEM, Hostname: "console.example.com"}, "holds a private key"},
		"garbage cert":      {api.HostCertificateUpload{Certificate: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", Key: leaf.keyPEM, Hostname: "console.example.com"}, "does not parse"},
		"chain out of order": {api.HostCertificateUpload{Certificate: inter.certPEM + leaf.certPEM, Key: leaf.keyPEM, Hostname: "console.example.com"},
			"not in order"},
		"wrong key":       {api.HostCertificateUpload{Certificate: chain, Key: other.keyPEM, Hostname: "console.example.com"}, "does not belong"},
		"no key":          {api.HostCertificateUpload{Certificate: chain, Key: "", Hostname: "console.example.com"}, "no PEM private key"},
		"encrypted key":   {api.HostCertificateUpload{Certificate: chain, Key: encKey, Hostname: "console.example.com"}, "encrypted"},
		"two keys":        {api.HostCertificateUpload{Certificate: chain, Key: leaf.keyPEM + leaf.keyPEM, Hostname: "console.example.com"}, "more than one"},
		"cert as key":     {api.HostCertificateUpload{Certificate: chain, Key: leaf.certPEM, Hostname: "console.example.com"}, "not a private key"},
		"expired":         {api.HostCertificateUpload{Certificate: expired.certPEM, Key: expired.keyPEM, Hostname: "console.example.com"}, "expired on"},
		"not yet":         {api.HostCertificateUpload{Certificate: future.certPEM, Key: future.keyPEM, Hostname: "console.example.com"}, "not valid before"},
		"client only":     {api.HostCertificateUpload{Certificate: client.certPEM, Key: client.keyPEM, Hostname: "console.example.com"}, "serverAuth"},
		"other host":      {api.HostCertificateUpload{Certificate: chain, Key: leaf.keyPEM, Hostname: "www.example.com"}, "not valid for www.example.com"},
		"bad host":        {api.HostCertificateUpload{Certificate: chain, Key: leaf.keyPEM, Hostname: "a b"}, "is not a host name"},
		"no host":         {api.HostCertificateUpload{Certificate: chain, Key: leaf.keyPEM}, "is not a host name"},
		"too big":         {api.HostCertificateUpload{Certificate: strings.Repeat("x", api.MaxCertificatePEM), Key: leaf.keyPEM, Hostname: "console.example.com"}, "exceed"},
		"too long chain":  {api.HostCertificateUpload{Certificate: strings.Repeat(root.certPEM, 9), Key: root.keyPEM, Hostname: "root"}, "at most 8"},
		"other pem block": {api.HostCertificateUpload{Certificate: "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n", Key: leaf.keyPEM, Hostname: "console.example.com"}, "X509 CRL"},
	} {
		_, _, _, err := validateUpload(c.in, now)
		if !api.IsCode(err, api.CodeInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// an address the certificate names is a host name too
	ipCert := makePair(t, &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "x"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, nil)
	if _, _, _, err := validateUpload(api.HostCertificateUpload{Certificate: ipCert.certPEM, Key: ipCert.keyPEM, Hostname: "192.0.2.10"}, now); err != nil {
		t.Error(err)
	}
}

func TestConsoleURLs(t *testing.T) {
	addrs := func() ([]net.Addr, error) {
		var out []net.Addr
		for _, s := range []string{"127.0.0.1/8", "::1/128", "fe80::1/64", "192.0.2.10/24", "2001:db8::10/64"} {
			ip, n, _ := net.ParseCIDR(s)
			n.IP = ip
			out = append(out, n)
		}
		return out, nil
	}
	got := strings.Join(consoleURLs(":39110", "web1.example.com", addrs), " ")
	if got != "https://web1.example.com:39110/ https://192.0.2.10:39110/ https://[2001:db8::10]:39110/" {
		t.Errorf("%q", got)
	}
	if got := strings.Join(consoleURLs("192.0.2.20:8443", "web1", addrs), " "); got != "https://192.0.2.20:8443/" {
		t.Errorf("%q", got)
	}
	if got := strings.Join(consoleURLs(":39110", "web1", addrs), " "); strings.Contains(got, "web1") {
		t.Errorf("an unqualified name: %q", got)
	}
	if consoleURLs("", "web1", addrs) != nil {
		t.Error("no listener")
	}
}

var _ = bytes.Equal
