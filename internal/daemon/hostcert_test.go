package daemon_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// acmeEnv is a daemon with its TLS listener, the test CA, an http-01 listener on a free port the CA validates
// against, and a channel that hears every ACME attempt.
type acmeEnv struct {
	*dtest.Env
	ca       *dtest.ACMECA
	attempts chan error
}

func newACMEEnv(t *testing.T, mutate func(*daemon.Config), reuse *acmeEnv, helperModules ...string) *acmeEnv {
	t.Helper()
	a := &acmeEnv{attempts: make(chan error, 8)}
	if reuse != nil {
		a.ca = reuse.ca
	} else {
		a.ca = dtest.NewACMECA(t)
	}
	o := dtest.Options{Listen: true, ACMEHTTPClient: a.ca.HTTPClient(), TLSRoots: a.ca.Roots(), Mutate: mutate,
		ACMEAttempted: func(err error) { a.attempts <- err },
		ListenChallenge: func(string) (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				a.ca.SetTargets(ln.Addr().String(), "")
			}
			return ln, err
		}}
	if reuse != nil {
		o.Reuse = reuse.Env
	}
	o.HostManage = helperModules
	a.Env = dtest.New(t, o)
	return a
}

func (a *acmeEnv) attempt(t *testing.T) error {
	t.Helper()
	select {
	case err := <-a.attempts:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("no ACME attempt; log:\n%s", a.Log())
		return nil
	}
}

// handshake connects to the TLS listener as a client that trusts roots and asks for name.
func handshake(t *testing.T, addr, name string, roots *x509.CertPool) (*x509.Certificate, error) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: name, RootCAs: roots})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0], nil
}

func ctx30(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// ACME with http-01 end to end against the test CA: the account, the order for two names, the CA fetching the key
// authorization from the daemon's challenge listener, the chain written 0600, served from the next handshake on,
// a public certificate (no pin in the remote add command), the cache used again after a restart, and the refusals
// of a setting that cannot work.
func TestACMEHTTP01ThroughTheAPI(t *testing.T) {
	a := newACMEEnv(t, nil, nil)
	cc := a.Admin.HostSystem().Certificate()
	st, err := cc.Get(ctx30(t))
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != api.CertSourceSelfSigned || !st.Current.SelfSigned || st.Current.PublicCA || !strings.Contains(st.RemoteAdd, "--fingerprint "+st.Current.Fingerprint) || !st.Listener {
		t.Fatalf("%+v", st)
	}
	ok := api.ACMESpec{Domains: []string{"console.example.com", "jo.example.com"}, Email: "admin@example.com", DirectoryURL: a.ca.DirectoryURL(), AcceptTOS: true}
	for name, c := range map[string]struct {
		spec api.ACMESpec
		code api.Code
	}{
		"terms":      {api.ACMESpec{Domains: ok.Domains, DirectoryURL: ok.DirectoryURL}, api.CodeInvalid},
		"wildcard":   {api.ACMESpec{Domains: []string{"*.example.com"}, DirectoryURL: ok.DirectoryURL, AcceptTOS: true}, api.CodeUnsupported},
		"no domain":  {api.ACMESpec{DirectoryURL: ok.DirectoryURL, AcceptTOS: true}, api.CodeInvalid},
		"address":    {api.ACMESpec{Domains: []string{"192.0.2.10"}, DirectoryURL: ok.DirectoryURL, AcceptTOS: true}, api.CodeInvalid},
		"single":     {api.ACMESpec{Domains: []string{"localhost"}, DirectoryURL: ok.DirectoryURL, AcceptTOS: true}, api.CodeInvalid},
		"email":      {api.ACMESpec{Domains: ok.Domains, Email: "Admin <admin@example.com>", DirectoryURL: ok.DirectoryURL, AcceptTOS: true}, api.CodeInvalid},
		"plain http": {api.ACMESpec{Domains: ok.Domains, DirectoryURL: "http://ca.example.com/dir", AcceptTOS: true}, api.CodeInvalid},
		"dns-01":     {api.ACMESpec{Domains: ok.Domains, DirectoryURL: ok.DirectoryURL, AcceptTOS: true, Challenge: "dns-01"}, api.CodeInvalid},
		"twice":      {api.ACMESpec{Domains: []string{"a.example.com", "A.example.com"}, DirectoryURL: ok.DirectoryURL, AcceptTOS: true}, api.CodeInvalid},
		"bad label":  {api.ACMESpec{Domains: []string{"-a.example.com"}, DirectoryURL: ok.DirectoryURL, AcceptTOS: true}, api.CodeInvalid},
		"many domains": {api.ACMESpec{Domains: func() []string {
			var d []string
			for i := range 21 {
				d = append(d, string(rune('a'+i))+".example.com")
			}
			return d
		}(), DirectoryURL: ok.DirectoryURL, AcceptTOS: true}, api.CodeInvalid},
	} {
		if _, err := cc.UseACME(ctx30(t), c.spec); !api.IsCode(err, c.code) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a readonly identity reads but does not change
	if _, err := a.Client(api.PermReadonly).HostSystem().Certificate().UseACME(ctx30(t), ok); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("readonly: %v", err)
	}
	st, err = cc.UseACME(ctx30(t), ok)
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != api.CertSourceACME || st.ACME == nil || st.Redirect == nil || len(st.Redirect.Lines) != 2 || st.Redirect.Managed {
		t.Fatalf("%+v", st)
	}
	if err := a.attempt(t); err != nil {
		t.Fatalf("the request failed: %v\n%s", err, a.Log())
	}
	st, _ = cc.Get(ctx30(t))
	if st.ACME.State != "valid" || !st.Current.PublicCA || st.Current.SelfSigned || !slices.Equal(st.Current.Names, ok.Domains) ||
		st.ACME.RenewAt == nil || st.ACME.TermsURL != a.ca.Terms() || strings.Contains(st.RemoteAdd, "--fingerprint") ||
		!strings.HasPrefix(st.RemoteAdd, "jailops remote add console https://console.example.com:") {
		t.Fatalf("%+v %+v", st, st.ACME)
	}
	if !strings.Contains(st.Redirect.Lines[0], "port 80 rdr-to 127.0.0.1 port ") {
		t.Errorf("%q", st.Redirect.Lines)
	}
	leaf, err := handshake(t, a.D.HTTPSAddr(), "jo.example.com", a.ca.Roots())
	if err != nil || leaf.Subject.CommonName != "console.example.com" {
		t.Fatalf("%v %v", leaf, err)
	}
	vals, issued := a.ca.Log()
	if issued != 1 || !slices.Contains(vals, "http-01 console.example.com ok") || !slices.Contains(vals, "http-01 jo.example.com ok") {
		t.Errorf("%v %d", vals, issued)
	}
	dir := filepath.Join(a.Cfg.DataDir, "tls", "acme")
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("%v %v", fi, err)
	}
	for _, f := range []string{"account.key", "key.pem", "cert.pem", "status.json"} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(a.Cfg.DataDir, "tls", "choice.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("choice: %v %v", fi, err)
	}
	// doctor: the daemon reaches its own challenge listener; the redirect is the administrator's (no firewall module)
	rep, err := a.Admin.Doctor(ctx30(t))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]api.DoctorCheck{}
	for _, c := range rep.Checks {
		checks[c.Name] = c
	}
	if c := checks["tls.acme"]; c.Status != api.DoctorOK || !strings.Contains(c.Message, "the challenge listener answers") || !strings.Contains(c.Message, "does not manage") {
		t.Errorf("tls.acme: %+v", c)
	}
	if c := checks["tls.certificate"]; c.Status != api.DoctorOK || !strings.Contains(c.Message, "acme, valid for 89 more days") {
		t.Errorf("tls.certificate: %+v", c)
	}
	// a trust token pins what is served now
	tt, err := a.Admin.Trust().CreateToken(ctx30(t), api.TrustTokenRequest{Name: "laptop", Permission: api.PermReadonly, Global: true})
	if err != nil {
		t.Fatal(err)
	}
	if fp, _ := sdk.TrustTokenFingerprint(tt.Token); fp != st.Current.Fingerprint {
		t.Errorf("trust token pins %s, served %s", fp, st.Current.Fingerprint)
	}
	// a restart serves the cached certificate at once; the CA is not asked again
	a.Stop()
	b := newACMEEnv(t, nil, a)
	if leaf, err := handshake(t, b.D.HTTPSAddr(), "console.example.com", b.ca.Roots()); err != nil || leaf.Subject.CommonName != "console.example.com" {
		t.Fatalf("after a restart: %v %v", leaf, err)
	}
	if _, issued := b.ca.Log(); issued != 1 {
		t.Errorf("issued %d", issued)
	}
	// back to the self-signed certificate
	st, err = b.Admin.HostSystem().Certificate().UseSelfSigned(ctx30(t))
	if err != nil || st.Source != api.CertSourceSelfSigned || !st.Current.SelfSigned || st.ACME != nil {
		t.Fatalf("%v %+v", err, st)
	}
	if _, err := handshake(t, b.D.HTTPSAddr(), "console.example.com", b.ca.Roots()); err == nil {
		t.Error("the CA's certificate is still served")
	}
}

// tls-alpn-01 is answered on the TLS listener itself; a failed request is surfaced with its error and a backoff,
// the doctor warns, and the certificate in use is kept.
func TestACMETLSALPN01AndFailure(t *testing.T) {
	a := newACMEEnv(t, nil, nil)
	a.ca.SetTargets("", a.D.HTTPSAddr())
	cc := a.Admin.HostSystem().Certificate()
	spec := api.ACMESpec{Domains: []string{"console.example.com"}, DirectoryURL: a.ca.DirectoryURL(), AcceptTOS: true, Challenge: api.ACMETLSALPN01}
	st, err := cc.UseACME(ctx30(t), spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.attempt(t); err != nil {
		t.Fatalf("%v\n%s", err, a.Log())
	}
	vals, _ := a.ca.Log()
	if !slices.Contains(vals, "tls-alpn-01 console.example.com ok") {
		t.Errorf("%v", vals)
	}
	if leaf, err := handshake(t, a.D.HTTPSAddr(), "console.example.com", a.ca.Roots()); err != nil || leaf.Subject.CommonName != "console.example.com" {
		t.Fatalf("%v %v", leaf, err)
	}
	if st.Redirect == nil || !strings.Contains(st.Redirect.Lines[0], "port 443 rdr-to 127.0.0.1 port ") {
		t.Errorf("%+v", st.Redirect)
	}
	// an acme-tls/1 handshake without a pending challenge is refused
	if c, err := tls.Dial("tcp", a.D.HTTPSAddr(), &tls.Config{ServerName: "console.example.com", NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true}); err == nil {
		c.Close()
		t.Error("an acme-tls/1 handshake without a challenge succeeded")
	}
	// the CA refuses: the error, the failure count and the next attempt are shown; nothing is retried at once
	a.ca.SetFail(true)
	if _, err := cc.UseACME(ctx30(t), api.ACMESpec{Domains: []string{"other.example.com"}, DirectoryURL: a.ca.DirectoryURL(), AcceptTOS: true, Challenge: api.ACMETLSALPN01}); err != nil {
		t.Fatal(err)
	}
	if err := a.attempt(t); err == nil || !strings.Contains(err.Error(), "could not verify the tls-alpn-01 challenge") {
		t.Fatalf("%v", err)
	}
	st, _ = cc.Get(ctx30(t))
	if st.ACME.State != "error" || st.ACME.Failures != 1 || st.ACME.NextAttempt == nil || !strings.Contains(st.ACME.LastError, "port 443") {
		t.Fatalf("%+v", st.ACME)
	}
	if d := time.Until(*st.ACME.NextAttempt); d < 50*time.Minute || d > 61*time.Minute {
		t.Errorf("next attempt in %s", d)
	}
	rep, _ := a.Admin.Doctor(ctx30(t))
	for _, c := range rep.Checks {
		if c.Name == "tls.acme" && (c.Status != api.DoctorWarn || !strings.Contains(c.Message, "the last request failed")) {
			t.Errorf("%+v", c)
		}
	}
	select {
	case err := <-a.attempts:
		t.Fatalf("a retry storm: %v", err)
	default:
	}
}

// selfSignedPair is a certificate for name signed by a test root, with its key, as PEM.
func certChain(t *testing.T, names []string, notAfter time.Time) (chain, key string, roots *x509.CertPool) {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rtpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upload root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	rder, _ := x509.CreateCertificate(rand.Reader, rtpl, rtpl, &rk.PublicKey, rk)
	root, _ := x509.ParseCertificate(rder)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ltpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	lder, err := x509.CreateCertificate(rand.Reader, ltpl, root, &lk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(lk)
	roots = x509.NewCertPool()
	roots.AddCert(root)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lder})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rder})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})), roots
}

// An uploaded certificate: refused when it cannot work, written 0600 and served from the next handshake on, kept
// over a restart; the operator's files in jailopsd.yaml cannot be replaced from the API.
func TestCertificateUpload(t *testing.T) {
	e := dtest.New(t, dtest.Options{Listen: true})
	cc := e.Admin.HostSystem().Certificate()
	chain, key, roots := certChain(t, []string{"console.example.com"}, time.Now().Add(30*24*time.Hour))
	_, otherKey, _ := certChain(t, []string{"console.example.com"}, time.Now().Add(30*24*time.Hour))
	for name, in := range map[string]api.HostCertificateUpload{
		"wrong key":  {Certificate: chain, Key: otherKey, Hostname: "console.example.com"},
		"wrong name": {Certificate: chain, Key: key, Hostname: "www.example.com"},
		"no pem":     {Certificate: "x", Key: key, Hostname: "console.example.com"},
	} {
		if _, err := cc.Upload(ctx30(t), in); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := operatorCerts(e).Upload(ctx30(t), api.HostCertificateUpload{Certificate: chain, Key: key, Hostname: "console.example.com"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("operator: %v", err)
	}
	st, err := cc.Upload(ctx30(t), api.HostCertificateUpload{Certificate: chain, Key: key, Hostname: "console.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != api.CertSourceUploaded || st.Current.SelfSigned || st.Current.PublicCA || st.Current.DaysLeft != 29 || !strings.Contains(st.RemoteAdd, "--fingerprint") {
		t.Fatalf("%+v", st)
	}
	if leaf, err := handshake(t, e.D.HTTPSAddr(), "console.example.com", roots); err != nil || leaf.Subject.CommonName != "console.example.com" {
		t.Fatalf("%v %v", leaf, err)
	}
	for _, f := range []string{"uploaded.crt", "uploaded.key", "choice.json"} {
		if fi, err := os.Stat(filepath.Join(e.Cfg.DataDir, "tls", f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
	}
	e.Stop()
	e2 := dtest.New(t, dtest.Options{Listen: true, Reuse: e})
	if leaf, err := handshake(t, e2.D.HTTPSAddr(), "console.example.com", roots); err != nil || leaf.Subject.CommonName != "console.example.com" {
		t.Fatalf("after a restart: %v %v", leaf, err)
	}
	// the operator's files win, and the API cannot change them
	dir := t.TempDir()
	crt, k := filepath.Join(dir, "own.crt"), filepath.Join(dir, "own.key")
	writeCert(t, crt, k, "own.example.test")
	e3 := dtest.New(t, dtest.Options{Listen: true, Mutate: func(c *daemon.Config) { c.Listen.HTTPS.Cert, c.Listen.HTTPS.Key = crt, k }})
	st, err = e3.Admin.HostSystem().Certificate().Get(ctx30(t))
	if err != nil || st.Source != api.CertSourceConfigured || !st.Configured {
		t.Fatalf("%v %+v", err, st)
	}
	for _, f := range []func() error{
		func() error { _, err := e3.Admin.HostSystem().Certificate().UseSelfSigned(ctx30(t)); return err },
		func() error {
			_, err := e3.Admin.HostSystem().Certificate().Upload(ctx30(t), api.HostCertificateUpload{Certificate: chain, Key: key, Hostname: "console.example.com"})
			return err
		},
	} {
		if err := f(); !api.IsCode(err, api.CodeConflict) {
			t.Errorf("configured: %v", err)
		}
	}
	// no TLS listener: nothing to serve
	e4 := dtest.New(t, dtest.Options{})
	if _, err := e4.Admin.HostSystem().Certificate().Upload(ctx30(t), api.HostCertificateUpload{Certificate: chain, Key: key, Hostname: "console.example.com"}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("no listener: %v", err)
	}
}

func operatorCerts(e *dtest.Env) *sdk.CertificateClient {
	return e.Client(api.PermOperator).HostSystem().Certificate()
}

// listen.https.acme in jailopsd.yaml: validated at load, and what depends on the listeners after the flags.
func TestACMEConfig(t *testing.T) {
	base := "pool: tank\nlisten:\n  https:\n    address: \":39110\"\n    acme:\n"
	for name, c := range map[string]struct{ body, want string }{
		"ok":                {"      enabled: true\n      domains: [console.example.com]\n      accept_tos: true\n", ""},
		"off and empty":     {"      enabled: false\n", ""},
		"terms":             {"      enabled: true\n      domains: [console.example.com]\n", "accept_tos must be true"},
		"no domain":         {"      enabled: true\n      accept_tos: true\n", "at least one domain"},
		"wildcard":          {"      enabled: true\n      domains: ['*.example.com']\n      accept_tos: true\n", "dns-01"},
		"address":           {"      enabled: true\n      domains: [192.0.2.1]\n      accept_tos: true\n", "is an address"},
		"email":             {"      enabled: true\n      domains: [a.example.com]\n      email: not-an-address\n      accept_tos: true\n", "not an email address"},
		"directory":         {"      enabled: true\n      domains: [a.example.com]\n      directory_url: ftp://x\n      accept_tos: true\n", "https URL"},
		"challenge":         {"      enabled: true\n      domains: [a.example.com]\n      challenge: dns-01\n      accept_tos: true\n", "not http-01 or tls-alpn-01"},
		"privileged port":   {"      enabled: true\n      domains: [a.example.com]\n      challenge_address: \":80\"\n      accept_tos: true\n", "1024 to 65535"},
		"public address":    {"      enabled: true\n      domains: [a.example.com]\n      challenge_address: \"192.0.2.1:39080\"\n      accept_tos: true\n", "loopback"},
		"loopback is fine":  {"      enabled: true\n      domains: [a.example.com]\n      challenge_address: \"127.0.0.1:39080\"\n      accept_tos: true\n", ""},
		"unknown key":       {"      enabled: true\n      dns_provider: x\n", "dns_provider"},
		"staging directory": {"      enabled: true\n      domains: [a.example.com]\n      directory_url: " + api.ACMEDirectoryStaging + "\n      accept_tos: true\n", ""},
	} {
		_, err := daemon.Decode(strings.NewReader(base + c.body))
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := daemon.Decode(strings.NewReader("pool: tank\nlisten:\n  https:\n    address: \":39110\"\n    cert: /a.crt\n    key: /a.key\n    acme:\n      enabled: true\n      domains: [a.example.com]\n      accept_tos: true\n")); err == nil || !strings.Contains(err.Error(), "exclude each other") {
		t.Errorf("cert and acme: %v", err)
	}
	noListener, err := daemon.Decode(strings.NewReader("pool: tank\nlisten:\n  https:\n    acme:\n      enabled: true\n      domains: [a.example.com]\n      accept_tos: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := noListener.CheckListeners(); err == nil || !strings.Contains(err.Error(), "needs the TLS listener") {
		t.Errorf("no listener: %v", err)
	}
	if err := daemon.ApplyWebOverride(noListener, true, false).CheckListeners(); err != nil {
		t.Errorf("-web opens the listener: %v", err)
	}
	alpn, _ := daemon.Decode(strings.NewReader("pool: tank\nlisten:\n  https:\n    address: \"192.0.2.10:39110\"\n    acme:\n      enabled: true\n      domains: [a.example.com]\n      accept_tos: true\n      challenge: tls-alpn-01\n"))
	if err := alpn.CheckListeners(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("tls-alpn-01 on one address: %v", err)
	}
}

// The rc.conf switch reaches the daemon as -appliance-modules: the union with jailopsd.yaml, "all" for every module.
func TestApplyAppliance(t *testing.T) {
	cfg, _ := daemon.Decode(strings.NewReader("pool: tank\nhost:\n  manage:\n    modules: [firewall]\n"))
	for in, want := range map[string]string{"": "firewall", "all": "firewall,identity", "identity": "firewall,identity", "firewall": "firewall"} {
		var mods []string
		if in != "" {
			mods = []string{in}
		}
		got, err := daemon.ApplyAppliance(cfg, mods)
		if err != nil || strings.Join(got.Host.Manage.Modules, ",") != want {
			t.Errorf("%q: %v %v", in, got.Host.Manage.Modules, err)
		}
	}
	if _, err := daemon.ApplyAppliance(cfg, []string{"network"}); err == nil || !strings.Contains(err.Error(), "not a module") {
		t.Errorf("unknown: %v", err)
	}
}

// doctor appliance: ok when the daemon and the helper manage the same modules, a warning with the line to add when
// one side has a module the other does not.
func TestDoctorAppliance(t *testing.T) {
	check := func(e *dtest.Env) api.DoctorCheck {
		rep, err := e.Admin.Doctor(ctx30(t))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range rep.Checks {
			if c.Name == "appliance" {
				return c
			}
		}
		t.Fatal("no appliance check")
		return api.DoctorCheck{}
	}
	if c := check(dtest.New(t, dtest.Options{})); c.Status != api.DoctorOK || !strings.HasPrefix(c.Message, "off") {
		t.Errorf("off: %+v", c)
	}
	if c := check(dtest.New(t, dtest.Options{ApplianceModules: []string{"all"}, HostManage: []string{"identity", "firewall"}})); c.Status != api.DoctorOK ||
		!strings.Contains(c.Message, "both manage identity, firewall (from jailops_appliance") {
		t.Errorf("both: %+v", c)
	}
	if c := check(dtest.New(t, dtest.Options{ApplianceModules: []string{"all"}, HostManage: []string{"identity"}})); c.Status != api.DoctorWarn ||
		!strings.Contains(c.Message, "the daemon manages firewall but the helper does not") || !strings.Contains(c.Hint, "host-manage = firewall") {
		t.Errorf("daemon only: %+v", c)
	}
	if c := check(dtest.New(t, dtest.Options{HostManage: []string{"identity"}})); c.Status != api.DoctorWarn ||
		!strings.Contains(c.Message, "the helper manages identity") || !strings.Contains(c.Hint, "service jailopsd restart") {
		t.Errorf("helper only: %+v", c)
	}
}

// First-run setup over HTTP: the status for anyone, the token issued by an administrator (root on the socket in
// production), wrong tokens refused and locked out per source, the right one creating the first administrator once,
// and every setup route answering not_found afterwards.
func TestSetupFlow(t *testing.T) {
	e := dtest.New(t, dtest.Options{Listen: true, NoAdmin: true})
	code, body := e.Raw("GET", "/api/v1/setup", "", "")
	if code != 200 || !strings.Contains(body, `"required":true`) || !strings.Contains(body, `"token_issued":false`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := e.Raw("POST", "/api/v1/setup/token", e.Token(api.PermOperator), "{}"); code != 403 {
		t.Errorf("operator: %d", code)
	}
	tok, err := rootSetupToken(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Token) != 52 || strings.ToUpper(tok.Token) != tok.Token || len(tok.URLs) == 0 || time.Until(tok.ExpiresAt) < 23*time.Hour {
		t.Fatalf("%+v", tok)
	}
	if strings.Contains(e.Log(), tok.Token) {
		t.Error("the token is in the daemon's log")
	}
	raw, _ := os.ReadFile(filepath.Join(e.Cfg.StateDir, "setup", "token.json"))
	if strings.Contains(string(raw), tok.Token) || !strings.Contains(string(raw), "sha256") {
		t.Errorf("stored: %s", raw)
	}
	if fi, err := os.Stat(filepath.Join(e.Cfg.StateDir, "setup", "token.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%v %v", fi, err)
	}
	post := func(token, name, pw string) (int, string) {
		b, _ := json.Marshal(api.SetupRequest{Token: token, Name: name, Password: pw})
		return e.Raw("POST", "/api/v1/setup", "", string(b))
	}
	// the password policy is checked after the token, and costs no try
	if code, body := post(tok.Token, "admin", "short"); code != 400 || !strings.Contains(body, "at least 12") {
		t.Errorf("%d %s", code, body)
	}
	if code, body := post(tok.Token, "Admin!", "a long enough passphrase 42"); code != 400 || !strings.Contains(body, "lower case letters, digits and hyphens") {
		t.Errorf("%d %s", code, body)
	}
	for i := range 5 {
		code, body := post("AAAA"+tok.Token[4:], "admin", "a long enough passphrase 42")
		want := 401
		if i == 4 {
			want = 429
		}
		if code != want {
			t.Fatalf("try %d: %d %s", i+1, code, body)
		}
	}
	// locked out: even the right token waits
	if code, _ := post(tok.Token, "admin", "a long enough passphrase 42"); code != 429 {
		t.Fatalf("locked: %d", code)
	}
	// from another source (the unix socket) it works; spaces and lower case are forgiven
	res, err := e.D.Service().Setup(context.Background(), api.SetupRequest{Token: strings.ToLower(tok.Token[:26]) + " " + tok.Token[26:], Name: "admin", Password: "a long enough passphrase 42"}, "192.0.2.77")
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Metadata.Name != "admin" || res.User.Spec.Permission != api.PermAdmin || !res.User.Spec.Global || res.ClientAddress != "192.0.2.77" {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(filepath.Join(e.Cfg.StateDir, "setup", "token.json")); !os.IsNotExist(err) {
		t.Errorf("the token was not consumed: %v", err)
	}
	// the new administrator signs in
	if code, body := e.Raw("POST", "/api/v1/auth/login", "", `{"username":"admin","password":"a long enough passphrase 42"}`); code != 200 {
		t.Errorf("login: %d %s", code, body)
	}
	for _, r := range [][2]string{{"GET", ""}, {"POST", `{"token":"x","name":"b","password":"y"}`}} {
		if code, _ := e.Raw(r[0], "/api/v1/setup", "", r[1]); code != 404 {
			t.Errorf("%s after setup: %d", r[0], code)
		}
	}
	if _, err := rootSetupToken(e); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("a token after setup: %v", err)
	}
	// neither the token nor the password is in anything the daemon wrote: the audit log, the events, the database,
	// the state directory, its log
	pw := "a long enough passphrase 42"
	if strings.Contains(e.Log(), pw) || strings.Contains(e.Log(), tok.Token) {
		t.Error("the daemon's log holds the token or the password")
	}
	audit, err := e.D.Service().ListAudit(rootActor(), service.AuditQuery{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := json.Marshal(audit)
	if strings.Contains(string(ab), pw) || strings.Contains(string(ab), tok.Token[:26]) {
		t.Errorf("the audit log holds a secret: %s", ab)
	}
	if !slices.ContainsFunc(audit, func(a api.AuditEntry) bool { return a.Requestor == "setup" && a.Resource == "/api/v1/users/admin" }) {
		t.Errorf("the setup is not audited: %+v", audit)
	}
	// the events (kept in the database) are searched with everything else the daemon wrote below
	sawAudit := false // the walk reaches the database: the audit entry of the setup is in it
	_ = filepath.WalkDir(e.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		sawAudit = sawAudit || strings.Contains(string(b), "first administrator created with the setup token")
		for _, secret := range []string{pw, tok.Token, strings.ToLower(tok.Token)} {
			if strings.Contains(string(b), secret) {
				t.Errorf("%s holds a secret of the setup", p)
			}
		}
		return nil
	})
	if !sawAudit {
		t.Error("the search did not reach the database")
	}
}

// rootActor is root on the socket: the daemon's recovery access, a global administrator that is no stored identity.
func rootActor() context.Context {
	return service.WithActor(context.Background(), service.Actor{Name: "root", Kind: "unix", Perm: api.PermAdmin, Global: true})
}

// rootSetupToken asks for a setup token as root on the socket does (jailops-priv setup-token).
func rootSetupToken(e *dtest.Env) (api.SetupToken, error) {
	return e.D.Service().IssueSetupToken(rootActor())
}

// Two people with the right token at once: exactly one becomes the first administrator.
func TestSetupRace(t *testing.T) {
	e := dtest.New(t, dtest.Options{NoAdmin: true})
	tok, err := rootSetupToken(e)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var oks, notFound int
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.D.Service().Setup(context.Background(), api.SetupRequest{Token: tok.Token, Name: "admin" + string(rune('a'+i)), Password: "a long enough passphrase 42"}, "192.0.2.1")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				oks++
			case api.IsCode(err, api.CodeNotFound):
				notFound++
			default:
				t.Errorf("%v", err)
			}
		}()
	}
	wg.Wait()
	if oks != 1 || notFound != 7 {
		t.Errorf("ok %d, not found %d", oks, notFound)
	}
}

// An expired token is refused like a wrong one.
func TestSetupTokenExpires(t *testing.T) {
	var mu sync.Mutex
	now := time.Now()
	e := dtest.New(t, dtest.Options{NoAdmin: true, Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	tok, err := rootSetupToken(e)
	if err != nil {
		t.Fatal(err)
	}
	st, err := e.Anonymous().SetupStatus(ctx30(t))
	if err != nil || !st.TokenIssued || st.ExpiresAt == nil {
		t.Fatalf("%v %+v", err, st)
	}
	mu.Lock()
	now = now.Add(api.SetupTokenTTL + time.Second)
	mu.Unlock()
	if _, err := e.D.Service().Setup(context.Background(), api.SetupRequest{Token: tok.Token, Name: "admin", Password: "a long enough passphrase 42"}, "192.0.2.1"); !api.IsCode(err, api.CodeUnauthorized) {
		t.Errorf("expired: %v", err)
	}
	if st, _ := e.Anonymous().SetupStatus(ctx30(t)); st.TokenIssued {
		t.Errorf("%+v", st)
	}
}

// With the host firewall module, the daemon fills in the redirect of the challenge port: the firewall's view has it,
// the doctor asks to apply the firewall again until it is, and the helper renders the rdr and pass rules.
func TestACMERedirectThroughTheFirewallModule(t *testing.T) {
	a := newACMEEnv(t, func(c *daemon.Config) { c.Host.Manage.Modules = []string{"firewall"} }, nil, "firewall")
	st, err := a.Admin.HostSystem().Certificate().UseACME(ctx30(t), api.ACMESpec{Domains: []string{"console.example.com"}, DirectoryURL: a.ca.DirectoryURL(), AcceptTOS: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Redirect == nil || !st.Redirect.Managed || st.Redirect.Applied || len(st.Redirect.Lines) != 0 {
		t.Fatalf("%+v", st.Redirect)
	}
	if err := a.attempt(t); err != nil {
		t.Fatal(err)
	}
	doctor := func() api.DoctorCheck {
		rep, _ := a.Admin.Doctor(ctx30(t))
		for _, c := range rep.Checks {
			if c.Name == "tls.acme" {
				return c
			}
		}
		return api.DoctorCheck{}
	}
	if c := doctor(); c.Status != api.DoctorWarn || !strings.Contains(c.Message, "does not redirect port 80 yet") || !strings.Contains(c.Hint, "apply the host firewall again") {
		t.Errorf("%+v", c)
	}
	fw, err := a.Admin.HostSystem().Firewall().Get(ctx30(t))
	if err != nil || fw.Spec.ACME == nil || fw.Spec.ACME.Challenge != api.ACMEHTTP01 || fw.Spec.ACME.Port == 0 {
		t.Fatalf("%v %+v", err, fw.Spec)
	}
	// what a client sends as acme is replaced by the daemon's
	spec := fw.Spec
	spec.ACME = &api.HostFirewallACME{Challenge: api.ACMETLSALPN01, Port: 40000}
	res, err := a.Admin.HostSystem().Firewall().Apply(ctx30(t), api.HostFirewallApply{Spec: spec, ConfirmWithin: 60})
	if err != nil {
		t.Fatal(err)
	}
	pf, _ := os.ReadFile(filepath.Join(a.Host.Etc, "pf.conf"))
	want := "match in inet proto tcp from any to (self) port 80 rdr-to 127.0.0.1 port " + strconv.Itoa(fw.Spec.ACME.Port)
	if !strings.Contains(string(pf), want) || strings.Contains(string(pf), "40000") {
		t.Fatalf("pf.conf:\n%s", pf)
	}
	if _, err := a.Admin.HostSystem().Confirm(ctx30(t), res.Pending.ID); err != nil {
		t.Fatal(err)
	}
	st, _ = a.Admin.HostSystem().Certificate().Get(ctx30(t))
	if !st.Redirect.Applied {
		t.Errorf("%+v", st.Redirect)
	}
	if c := doctor(); c.Status != api.DoctorOK {
		t.Errorf("%+v", c)
	}
}
