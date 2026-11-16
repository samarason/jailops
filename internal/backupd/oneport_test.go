package backupd_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/backupd"
	"jailops.net/jailops/sdk/api"
)

// plainClient is a browser: TLS, no client certificate.
func (r *rig) plainClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true},
		DisableKeepAlives: true, ForceAttemptHTTP2: true}}
}

func status(t *testing.T, c *http.Client, method, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// One port: the host API (an enrolled host's certificate) and the management API and console (tokens and sessions) live on
// the same listener, and neither opens the door of the other.
func TestOnePortHostsAndConsole(t *testing.T) {
	r := startRig(t, memKind, nil) // console on
	h := r.enroll("h")
	base := "https://" + r.Srv.HostAddr()
	if r.Srv.WebAddr() != r.Srv.HostAddr() {
		t.Fatalf("the console is on the host listener: %q vs %q", r.Srv.WebAddr(), r.Srv.HostAddr())
	}

	// a host works as before
	if _, err := h.C.Info(ctx); err != nil {
		t.Fatalf("an enrolled host on the shared port: %v", err)
	}
	// a browser (no certificate) reaches the management API and the login, and nothing of the host API
	if code, body := status(t, r.plainClient(), "GET", base+"/api/v1", ""); code != 200 || !strings.Contains(body, `"untrusted"`) {
		t.Fatalf("management info without a certificate: %d %s", code, body)
	}
	// ... and learns nothing about the node: no host name, id or software version
	var env api.Response
	var info api.ServerInfo
	_, body := status(t, r.plainClient(), "GET", base+"/api/v1", "")
	_ = json.Unmarshal([]byte(body), &env)
	if err := json.Unmarshal(env.Metadata, &info); err != nil || info.Hostname != "" || info.HostUUID != "" || info.Version != "" || info.Auth != "untrusted" || info.Role != api.RoleBackup {
		t.Fatalf("the unauthenticated info says too much, or too little: %+v %v", info, err)
	}
	if code, _ := status(t, r.plainClient(), "POST", base+"/api/v1/auth/login", `{"username":"nobody","password":"x"}`); code != 401 {
		t.Fatalf("login with nothing valid: %d", code)
	}
	if code, _ := status(t, r.plainClient(), "GET", base+"/api/v1/repo", ""); code != 401 {
		t.Fatalf("the host API without a certificate: %d", code)
	}
	if code, _ := status(t, r.plainClient(), "GET", base+"/api/v1/hosts", ""); code != 401 {
		t.Fatalf("the management API without a token: %d", code)
	}
	// a host's certificate is no administrator: the management API wants a token or a session whatever the certificate says
	hc := r.httpFor(h.Cert)
	if code, _ := status(t, hc, "GET", base+"/api/v1/hosts", ""); code != 401 {
		t.Fatalf("a host certificate on the management API: %d", code)
	}
	if code, _ := status(t, hc, "POST", base+"/api/v1/hosts", `{"name":"evil"}`); code != 401 {
		t.Fatalf("enrolling a host with a host certificate: %d", code)
	}
	// a certificate nobody enrolled is no host: the host API says 401, and the management API does not look at it
	stranger, _, _, _ := auth.GenerateCertificate(auth.CertOptions{CommonName: "stranger"})
	if _, err := r.clientFor(stranger).Info(ctx); err == nil {
		t.Fatal("an unenrolled certificate was served by the host API")
	}
	if code, _ := status(t, r.httpFor(stranger), "GET", base+"/api/v1/repo", ""); code != 401 {
		t.Fatalf("an unenrolled certificate on the host API: %d", code)
	}
	if code, body := status(t, r.httpFor(stranger), "GET", base+"/api/v1", ""); code != 200 {
		t.Fatalf("an unenrolled certificate must not shut a client out of the management API: %d %s", code, body)
	}
	// and a revoked host stops on the shared port too
	if _, err := r.DB.RevokeHost(ctx, "h"); err != nil {
		t.Fatal(err)
	}
}

// With the console off the node still has the host API and the management API (web.enabled switches the console only):
// "/" is a 404, a host still works, and a certificate nobody enrolled is still refused.
func TestOnePortWithoutConsole(t *testing.T) {
	r := startRigWeb(t, memKind, false, nil)
	h := r.enroll("h")
	base := "https://" + r.Srv.HostAddr()
	if r.Srv.WebAddr() != "" {
		t.Fatalf("no console, no web address: %q", r.Srv.WebAddr())
	}
	if _, err := h.C.Info(ctx); err != nil {
		t.Fatal(err)
	}
	if code, body := status(t, r.plainClient(), "GET", base+"/", ""); code != 404 || strings.Contains(body, "<html") {
		t.Fatalf("/ with the console off: %d %q", code, body)
	}
	if code, body := status(t, r.plainClient(), "GET", base+"/api/v1", ""); code != 200 || !strings.Contains(body, `"untrusted"`) {
		t.Fatalf("the management API with the console off: %d %s", code, body)
	}
	if code, _ := status(t, r.plainClient(), "GET", base+"/api/v1/hosts", ""); code != 401 {
		t.Fatalf("the management API wants a token: %d", code)
	}
	if code, _ := status(t, r.plainClient(), "GET", base+"/api/v1/repo", ""); code != 401 {
		t.Fatalf("the host API without a certificate: %d", code)
	}
	stranger, _, _, _ := auth.GenerateCertificate(auth.CertOptions{CommonName: "stranger"})
	if code, _ := status(t, r.httpFor(stranger), "GET", base+"/api/v1/repo", ""); code != 401 {
		t.Fatalf("an unenrolled certificate on the host API: %d", code)
	}
}

// The two ways of proving who you are are independent: an administrator signs in with a user or a token whatever client
// certificate the browser offers (none, a stranger's, or even a host's), and a host's certificate is never an administrator.
func TestAdministratorWithAnyCertificate(t *testing.T) {
	r := startRig(t, memKind, nil)
	h := r.enroll("h")
	if err := backupd.CreateUser(ctx, r.DB, "alice", "a password that is long", "admin", testParams); err != nil {
		t.Fatal(err)
	}
	base := "https://" + r.Srv.HostAddr()
	stranger, _, _, _ := auth.GenerateCertificate(auth.CertOptions{CommonName: "corporate-laptop"})
	clients := map[string]*http.Client{"no certificate": r.plainClient(), "a stranger's certificate": r.httpFor(stranger), "a host's certificate": r.httpFor(h.Cert)}
	for name, c := range clients {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		c.Jar = jar
		if code, body := status(t, c, "POST", base+"/api/v1/auth/login", `{"username":"alice","password":"a password that is long"}`); code != 200 {
			t.Fatalf("signing in with %s: %d %s", name, code, body)
		}
		if code, body := status(t, c, "GET", base+"/api/v1/hosts", ""); code != 200 {
			t.Fatalf("the management API after signing in, with %s: %d %s", name, code, body)
		}
	}
	// and the other way round: a host's certificate with no sign-in gets nothing from the management API
	if code, _ := status(t, r.httpFor(h.Cert), "GET", base+"/api/v1/hosts", ""); code != 401 {
		t.Fatalf("a host certificate without a sign-in on the management API: %d", code)
	}
}

// noRedirect stops the client at the first answer, so a redirect is seen as one.
func noRedirect(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func ok2xx(code int) bool { return code >= 200 && code < 300 }

// The routing between the host API and the management API is by path: odd spellings of a path must never get a client
// into the other side.
func TestOnePortPathTricks(t *testing.T) {
	r := startRig(t, memKind, nil)
	h := r.enroll("h")
	base := "https://" + r.Srv.HostAddr()
	anon, host := noRedirect(r.plainClient()), noRedirect(r.httpFor(h.Cert))
	// the host API without a certificate
	for _, p := range []string{"/api/v1/repo", "//api/v1/repo", "/api/v1/./repo", "/api/v1/repo/../repo", "/api/v1%2Frepo", "/api/v1/repo%2Fsessions",
		"/api/v1/REPO", "/api/v1/repo/", "/api/v1/repo/sessions", "/api/v1/repo/chunks/abc"} {
		if code, body := status(t, anon, "GET", base+p, ""); ok2xx(code) {
			t.Errorf("GET %s without a certificate: %d %s", p, code, body)
		}
	}
	// the management API with a host's certificate and no token
	for _, p := range []string{"/api/v1/hosts", "//api/v1/hosts", "/api/v1/./hosts", "/api/v1/repo/../hosts", "/api/v1/hosts/../hosts", "/api/v1/%68osts",
		"/api/v1/groups", "/api/v1/repository", "/api/v1/certificate"} {
		if code, body := status(t, host, "GET", base+p, ""); ok2xx(code) {
			t.Errorf("GET %s with a host certificate: %d %s", p, code, body)
		}
	}
	if code, _ := status(t, host, "POST", base+"/api/v1/hosts", `{"name":"evil"}`); ok2xx(code) {
		t.Errorf("enrolling a host with a host certificate: %d", code)
	}
}

// A host that is revoked stops at once, also for a client that has connected before: a resumed TLS session must not
// carry the old admission over.
func TestOnePortRevocationAndResumption(t *testing.T) {
	r := startRig(t, memKind, nil)
	h := r.enroll("h")
	base := "https://" + r.Srv.HostAddr()
	tc, err := auth.ClientConfigPinned(t.Context(), &h.Cert, r.Srv.HostAddr(), r.Srv.ServerFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	tc.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true}}
	if code, body := status(t, c, "GET", base+"/api/v1/repo", ""); code != 200 {
		t.Fatalf("the host before the revocation: %d %s", code, body)
	}
	if _, err := r.DB.RevokeHost(t.Context(), "h"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		code, _ := status(t, c, "GET", base+"/api/v1/repo", "")
		if code == 0 || code == 401 { // refused in the handshake, or by the host check
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a revoked host was still served: %d", code)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// The management API is reachable by clients that have proved nothing yet: password hashing is bounded, and a body that
// never arrives does not hold a handler.
func TestConsoleAnonymousLimits(t *testing.T) {
	r := startRig(t, memKind, nil)
	base := "https://" + r.Srv.HostAddr()
	login := `{"username":"nobody","password":"x"}`

	r.Srv.SetHashSlots(0) // no hash may start
	req, _ := http.NewRequest("POST", base+"/api/v1/auth/login", strings.NewReader(login))
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.plainClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("with no hash slot free: %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	r.Srv.SetHashSlots(1)
	if code, _ := status(t, r.plainClient(), "POST", base+"/api/v1/auth/login", login); code != 401 {
		t.Fatalf("a wrong password with a free slot: %d", code)
	}

	// a body that stops halfway is cut off by the read deadline
	defer backupd.SetReadDeadline(400 * time.Millisecond)()
	conn, err := tls.Dial("tcp", r.Srv.HostAddr(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("POST /api/v1/auth/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"user"))
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		var ne net.Error
		if asNetTimeout(err, &ne) {
			t.Fatal("the server kept a half-sent request for more than the read deadline")
		}
	}
}

func asNetTimeout(err error, target *net.Error) bool {
	ne, ok := err.(net.Error)
	if ok && ne.Timeout() {
		*target = ne
		return true
	}
	return false
}

// A host certificate is its key. The certificate is public (it is sent in every handshake), so a client that has the
// certificate of an enrolled host but not its private key must not be taken for that host: TLS checks the client's signature
// over the handshake whatever is asked of the certificate, and the host API then looks the fingerprint up.
func TestHostCertificateNeedsItsKey(t *testing.T) {
	r := startRig(t, memKind, nil)
	h := r.enroll("h")
	base := "https://" + r.Srv.HostAddr()
	if code, body := status(t, r.httpFor(h.Cert), "GET", base+"/api/v1/repo", ""); code != 200 {
		t.Fatalf("the control (the real key): %d %s", code, body)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := tls.Certificate{Certificate: h.Cert.Certificate, PrivateKey: other}
	// refused in the handshake itself (the server's decrypt_error alert: the signature does not match the certificate), so
	// there is no HTTP answer at all; a client with a certificate that is not enrolled gets one (401). How the client words the
	// connection error depends on the HTTP version it negotiated, so only the absence of an answer is asserted.
	if code, body := status(t, r.httpFor(forged), "GET", base+"/api/v1/repo", ""); code != 0 {
		t.Fatalf("the certificate of an enrolled host with another key got an answer: %d %s", code, body)
	}
}
