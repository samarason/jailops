package daemon_test

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/server"
	"jailops.net/jailops/sdk/api"
)

// securityHeadersOf fetches path over the TLS listener (the certificate is not checked: the test asks what the server
// sends, not whom to trust) and returns the answer's headers.
func securityHeadersOf(t *testing.T, addr, path string) http.Header {
	t.Helper()
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := hc.Get("https://" + addr + path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header
}

// Strict-Transport-Security only while a certificate a browser trusts by itself is served: never with the self-signed
// one (a browser that remembered the header could not be told to accept it again), nor while ACME waits for its
// certificate, nor after going back to self-signed. Never includeSubDomains or preload. Permissions-Policy always.
func TestHSTSOnlyWithATrustedCertificate(t *testing.T) {
	a := newACMEEnv(t, nil, nil)
	check := func(when string, want bool) {
		t.Helper()
		for _, p := range []string{"/api/v1", "/"} {
			h := securityHeadersOf(t, a.D.HTTPSAddr(), p)
			if got := h.Get("Strict-Transport-Security"); (got != "") != want || strings.Contains(got, "includeSubDomains") || strings.Contains(got, "preload") {
				t.Errorf("%s, %s: Strict-Transport-Security %q", when, p, got)
			}
			if h.Get("Permissions-Policy") != server.PermissionsPolicy {
				t.Errorf("%s, %s: Permissions-Policy %q", when, p, h.Get("Permissions-Policy"))
			}
		}
	}
	check("self-signed", false)
	cc := a.Admin.HostSystem().Certificate()
	spec := api.ACMESpec{Domains: []string{"console.example.com"}, Email: "admin@example.com", DirectoryURL: a.ca.DirectoryURL(), AcceptTOS: true}
	if _, err := cc.UseACME(ctx30(t), spec); err != nil {
		t.Fatal(err)
	}
	if err := a.attempt(t); err != nil {
		t.Fatalf("the request failed: %v\n%s", err, a.Log())
	}
	if st, _ := cc.Get(ctx30(t)); !st.Current.PublicCA {
		t.Fatalf("%+v", st.Current)
	}
	check("a certificate of the CA", true)
	if _, err := cc.UseSelfSigned(ctx30(t)); err != nil {
		t.Fatal(err)
	}
	check("self-signed again", false)
}

// An uploaded certificate of a CA the host does not trust gets no Strict-Transport-Security either.
func TestHSTSNotForAnUntrustedUpload(t *testing.T) {
	a := newACMEEnv(t, nil, nil)
	chain, key, _ := certChain(t, []string{"console.example.com"}, time.Now().Add(30*24*time.Hour))
	st, err := a.Admin.HostSystem().Certificate().Upload(ctx30(t), api.HostCertificateUpload{Certificate: chain, Key: key, Hostname: "console.example.com"})
	if err != nil || st.Current.PublicCA {
		t.Fatalf("%v %+v", err, st.Current)
	}
	if h := securityHeadersOf(t, a.D.HTTPSAddr(), "/api/v1"); h.Get("Strict-Transport-Security") != "" {
		t.Errorf("an untrusted upload: %q", h.Get("Strict-Transport-Security"))
	}
}
