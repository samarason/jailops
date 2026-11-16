package cli_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/cli"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

// esc sets the window title, clears the screen, paints in red, writes to the clipboard and reverses the text that
// follows: what a hostile or compromised server would put in any string it returns.
const esc = "\x1b]0;PWNED-TITLE\x07\x1b[2J\x1b[31mFAKE\x1b[0m\x1b]52;c;ZWNobyBwd25lZA==\x07\xe2\x80\xaeevil"

// terminalSafe reports output that a terminal would act on: an escape other than the CLI's colours, a bell, a
// carriage return or a bidirectional override.
func terminalSafe(s string) bool {
	return !strings.Contains(s, "\x1b]") && !strings.Contains(s, "\x1b[2J") && !strings.Contains(s, "\x1b[31mFAKE") &&
		!strings.ContainsAny(s, "\x07\r") && !strings.Contains(s, "\xe2\x80\xae")
}

func hostileHarness(t *testing.T) *harness {
	t.Helper()
	okJSON := func(w http.ResponseWriter, v any) {
		b, _ := json.Marshal(v)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.Response{Type: api.ResponseSync, Status: "Success", StatusCode: 200, Metadata: b})
	}
	h := newHarnessWith(t, func(srv *fake.Server) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/jails/boom":
				e := api.Errorf(api.CodeNotFound, "jail not found"+esc).WithHint("hint" + esc)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(api.Response{Type: api.ResponseError, Status: "Failure", StatusCode: 404, Error: e})
			case "/api/v1/audit":
				okJSON(w, []api.AuditEntry{{ID: "1", Timestamp: time.Now(), Requestor: "bob" + esc, Action: "POST /x", Resource: "/r" + esc, Result: "ok", Detail: "d" + esc}})
			case "/api/v1/doctor":
				okJSON(w, api.DoctorReport{Time: time.Now(), Host: "h" + esc, Status: "warn",
					Checks: []api.DoctorCheck{{Name: "c" + esc, Status: "warn", Message: "msg" + esc, Hint: "hint" + esc}}})
			default:
				srv.ServeHTTP(w, r)
			}
		})
	})
	h.seed()
	h.srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "web", Project: "main", Labels: map[string]string{"role": "x" + esc}},
		Spec: api.JailSpec{Image: "freebsd-15", Hostname: "web" + esc}})
	h.srv.SeedApp(api.App{Name: "evil", Description: "nice app" + esc, Notes: "notes" + esc})
	return h
}

// Every string a server returns reaches the terminal cleaned: tables, show and get, errors and hints, the audit
// log, doctor, labels and the catalog.
func TestServerTextCannotDriveTheTerminal(t *testing.T) {
	h := hostileHarness(t)
	for _, args := range [][]string{
		{"jail", "list"}, {"jail", "list", "-o", "wide"}, {"jail", "list", "-o", "csv"}, {"jail", "list", "-o", "name"},
		{"jail", "show", "web"}, {"jail", "show", "boom"}, {"audit"}, {"audit", "-o", "wide"}, {"doctor"}, {"app", "info", "evil"},
	} {
		out, errs, _ := h.run("", args...)
		if !terminalSafe(out) || !terminalSafe(errs) {
			t.Errorf("jailops %s:\nstdout %q\nstderr %q", strings.Join(args, " "), out, errs)
		}
	}
	// the hint and the message are still there, cleaned
	_, errs, _ := h.run("", "jail", "show", "boom")
	if !strings.Contains(errs, "jail not found") || !strings.Contains(errs, "hint: hint") {
		t.Errorf("error: %q", errs)
	}
	// JSON stays faithful: the encoder escapes the controls
	out, _, code := h.run("", "jail", "show", "web", "-o", "json")
	if code != 0 || !strings.Contains(out, `\u001b]0;PWNED-TITLE\u0007`) || strings.Contains(out, "\x1b") {
		t.Errorf("json: %d %q", code, out)
	}
	out, _, code = h.run("", "jail", "show", "web", "-o", "yaml")
	if code != 0 || strings.Contains(out, "\x1b") || !strings.Contains(out, `\e]0;PWNED-TITLE\a`) {
		t.Errorf("yaml: %d %q", code, out)
	}
}

// 'remote add' shows a self-signed certificate before it pins it. The subject and the issuer are the server's text:
// they are quoted, and the fingerprint comes first on its own line, so they cannot paint a fake fingerprint over it
// or hide the question.
func TestRemoteAddShowsTheFingerprintBeforeTheServersText(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fakeFP := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "jailops.example\x1b]0;title\x07",
			Organization: []string{"x\r\x1b[2K  Issuer:   CN=Example CA\n  SHA-256:  " + fakeFP + "\x1b[8m"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := newHarness(t)
	h.probe = func(ctx context.Context, hp string) (*cli.CertProbe, error) {
		c, err := x509.ParseCertificate(der)
		return &cli.CertProbe{Cert: c}, err
	}
	_, errs, code := h.run("tok\nn\n", "remote", "add", "evil", ts.URL, "--token-file", "-")
	if code == 0 {
		t.Fatalf("pinned without a yes: %s", errs)
	}
	if !terminalSafe(errs) || strings.Contains(errs, "\x1b[8m") || strings.Contains(errs, "\x1b[2K") {
		t.Errorf("raw control characters: %q", errs)
	}
	var fpLines []string
	lines := strings.Split(errs, "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "  SHA-256:") {
			fpLines = append(fpLines, l)
		}
	}
	if len(fpLines) != 1 || strings.Contains(fpLines[0], fakeFP) || !strings.HasPrefix(lines[1], "  SHA-256:") {
		t.Errorf("fingerprint lines %q in %q", fpLines, errs)
	}
	if !strings.Contains(errs, `Subject:  "`) {
		t.Errorf("the subject is not quoted: %q", errs)
	}
}
