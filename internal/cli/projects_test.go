package cli_test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

func TestProjectsStorageNetworks(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("network", "create", "web", "--ipv4", "10.50.0.1/24", "--ipv6", "fd50::1/64")
	tr.do("", "network", "create", "bad", "--ipv4", "10.50.0.1/24", "--subnet", "10.1.0.0/24")
	tr.do("", "network", "create", "bad", "--ipv4", "nonsense")
	tr.ok("network", "show", "web", "-o", "yaml")
	tr.ok("storage", "create", "fast", "--dataset", "tank/fast", "--compression", "zstd")
	tr.do("", "storage", "create", "nodataset")
	tr.do("", "storage", "create", "bad", "--dataset", "nodash")
	tr.ok("storage", "list")
	tr.ok("storage", "show", "fast", "-o", "name")

	tr.ok("project", "create", "web", "--comment", "front end")
	tr.ok("network", "grant", "web", "--project", "web")
	tr.ok("storage", "grant", "fast", "--project", "web", "--quota", "500G")
	tr.ok("project", "set", "web", "--max-jails", "2", "--max-memory", "8G")
	tr.ok("project", "show", "web")
	tr.ok("project", "list")
	tr.do("", "network", "grant", "lan", "--project", "web") // lan belongs to the project main
	tr.do("", "network", "grant", "lan")
	tr.ok("network", "revoke", "web", "--project", "web")
	tr.ok("network", "grant", "web", "--project", "web")
	tr.ok("storage", "revoke", "fast", "--project", "web")
	tr.ok("storage", "grant", "fast", "--project", "web", "--quota", "500G")

	// Jails go to the project that is named; the network and the storage are named too.
	tr.ok("create", "nginx", "--project", "web", "--image", "freebsd-15@stable", "--memory", "1G", "--cpu", "1", "--network", "web", "--storage", "fast")
	tr.ok("list", "--project", "web")
	tr.ok("list")
	tr.do("", "list", "--project", "nowhere")
	tr.ok("project", "show", "web", "-o", "json")
	tr.ok("create", "n2", "--project", "web", "--image", "freebsd-15@stable", "--memory", "1G", "--cpu", "1", "--network", "web", "--storage", "fast")
	_, errs, code := tr.do("", "create", "n3", "--project", "web", "--image", "freebsd-15@stable", "--memory", "1G", "--cpu", "1", "--network", "web", "--storage", "fast")
	if code != 5 || !strings.HasPrefix(errs, "quota_exceeded:") {
		t.Fatalf("quota: %d %s", code, errs)
	}
	tr.do("", "project", "delete", "-y", "web")     // not empty
	tr.do("", "project", "delete", "-y", "default") // there is no such project
	tr.ok("project", "create", "shop", "--new-network", "--hosts", "h1,h2")
	tr.golden("projects")
}

func TestProjectSwitchPerRemote(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.writeConfig(fmt.Sprintf("current: a\nremotes:\n  a:\n    url: %s\n  b:\n    url: %s\n", h.ts.URL, h.ts.URL))
	tr := h.transcript()
	// A client with no project chosen sends nothing for a command that needs one.
	before := len(h.srv.Requests())
	if _, errs, code := tr.do("", "list"); code != 2 || !strings.Contains(errs, "a project is required") || len(h.srv.Requests()) != before {
		t.Fatalf("no project: %d %q (%d requests sent)", code, errs, len(h.srv.Requests())-before)
	}
	if _, errs, code := tr.do("", "create", "x", "--image", "freebsd-15@stable"); code != 2 || len(h.srv.Requests()) != before {
		t.Fatalf("create without a project: %d %q", code, errs)
	}
	tr.ok("project", "create", "web", "--new-network")
	tr.ok("storage", "grant", "default", "--project", "web")
	tr.ok("project", "create", "db", "--new-network")
	tr.ok("storage", "grant", "default", "--project", "db")
	tr.ok("project", "switch")
	tr.ok("project", "switch", "web")
	tr.ok("project", "list")
	tr.do("", "project", "switch", "nowhere")
	tr.ok("--remote", "b", "project", "switch", "db")
	tr.ok("--remote", "b", "project", "switch")
	tr.ok("project", "switch") // remote a keeps web
	tr.ok("remote", "switch", "b")
	tr.ok("project", "switch")
	tr.ok("remote", "switch", "a")
	// A project the jail goes into.
	tr.ok("create", "w1", "--image", "freebsd-15@stable", "--network", "web", "--storage", "default")
	h.env["JAILOPS_PROJECT"] = "db"
	tr.ok("project", "switch")
	tr.ok("create", "d1", "--image", "freebsd-15@stable", "--network", "db", "--storage", "default")
	tr.ok("--project", "web", "project", "switch")
	delete(h.env, "JAILOPS_PROJECT")
	tr.ok("list", "-o", "name")
	tr.ok("--project", "db", "list", "-o", "name")
	tr.ok("--dry-run", "project", "switch", "db")
	tr.do("", "project", "switch", "default") // there is no project of that name
	tr.ok("list", "-o", "name")
	tr.golden("project_switch")
	b, _ := os.ReadFile(h.cfgFile)
	if !strings.Contains(string(b), "projects:") || !strings.Contains(string(b), "b: db") {
		t.Fatalf("config: %s", b)
	}
	if st, _ := statFile(h.cfgFile); st&0o077 != 0 {
		t.Fatalf("mode %o", st)
	}
}

func TestIdentityScopeRefused(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{
		{"token", "create", "x"}, {"user", "create", "x"}, {"cert", "create", "x", "--fingerprint", strings.Repeat("ab", 32)},
		{"cert", "enroll", "x", "--role", "operator"},
		{"token", "create", "x", "--projects", "default", "--global"},
	} {
		out, errs, code := h.run("", args...)
		if code != 2 || out != "" || !strings.Contains(errs, "scope") && !strings.Contains(errs, "exclude") {
			t.Errorf("%v: %d %q %q", args, code, out, errs)
		}
	}
	for _, r := range h.srv.Requests() {
		if r.Method != "GET" {
			t.Fatalf("a refused command sent %s %s", r.Method, r.Path)
		}
	}
}

// tlsFake serves a fake over TLS that asks for client certificates, with the
// server fingerprint a trust token will carry.
func tlsFake(t *testing.T) (*fake.Server, *httptest.Server, string) {
	t.Helper()
	probe := httptest.NewUnstartedServer(nil)
	probe.StartTLS()
	fp := sdk.Fingerprint(probe.Certificate())
	probe.Close()
	srv := fake.New(fake.WithServerFingerprint(fp), fake.WithClock(func() time.Time { return clock }), fake.WithHostName("trusting"), fake.WithToken("admin-token"))
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return srv, ts, fp
}

func TestTrustWorkflow(t *testing.T) {
	srv, ts, fp := tlsFake(t)
	dir := t.TempDir()
	admin := &harness{t: t, srv: srv, ts: ts, dir: dir, env: map[string]string{}, cfgFile: filepath.Join(dir, "admin.yaml")}
	admin.env["JAILOPS_CONFIG"] = admin.cfgFile
	admin.writeConfig(fmt.Sprintf("current: adm\nremotes:\n  adm:\n    url: %s\n    fingerprint: %s\n    token: admin-token\n", ts.URL, fp))
	atr := admin.transcript()
	atr.ok("project", "create", "web")

	out, errs, code := atr.do("", "cert", "enroll", "laptop", "--role", "operator", "--projects", "web", "--expires", "15m")
	token := strings.TrimSpace(out)
	if code != 0 || !strings.HasPrefix(token, sdk.TrustTokenPrefix) || strings.Count(token, "\n") != 0 || !strings.Contains(errs, "shown only once") {
		t.Fatalf("cert enroll: %d %q %q", code, out, errs)
	}
	atr.do("", "cert", "enroll", "laptop", "--role", "operator", "--projects", "web") // name taken? token only
	atr.do("", "cert", "enroll", "--role", "operator", "--global")
	atr.do("", "cert", "enroll", "ghost", "--role", "operator", "--projects", "nope")

	// The new client has its own configuration and joins with the token.
	client := &harness{t: t, srv: srv, ts: ts, dir: filepath.Join(dir, "client"), env: map[string]string{}, cfgFile: filepath.Join(dir, "client", "config.yaml")}
	_ = os.MkdirAll(client.dir, 0o700)
	client.env["JAILOPS_CONFIG"] = client.cfgFile
	ctr := client.transcript()
	host := strings.TrimPrefix(ts.URL, "https://")
	_, errs, code = ctr.do("", "remote", "add", "trusting", host, "--token", "joc_garbage")
	if code != 2 {
		t.Fatalf("garbage token: %d %s", code, errs)
	}
	_, errs, code = ctr.do("", "remote", "add", "trusting", host, "--token", token, "--dry-run")
	if code != 0 {
		t.Fatalf("dry-run: %d %s", code, errs)
	}
	if _, err := os.Stat(client.cfgFile); err == nil {
		t.Fatal("dry-run wrote the config")
	}
	out, errs, code = ctr.do("", "remote", "add", "trusting", host, "--token", token)
	if code != 0 || strings.Contains(errs, "Pin this certificate") || !strings.Contains(out, "trusted as laptop (operator, web)") {
		t.Fatalf("remote add: %d %q %q", code, out, errs)
	}
	raw, _ := os.ReadFile(client.cfgFile)
	if !strings.Contains(string(raw), "fingerprint: "+fp) || !strings.Contains(string(raw), "cert:") || strings.Contains(string(raw), sdk.TrustTokenPrefix) {
		t.Fatalf("config: %s", raw)
	}
	key := filepath.Join(client.dir, "certs", "trusting.key")
	if st, err := statFile(key); err != nil || st != 0o600 {
		t.Fatalf("key file: %v %o", err, st)
	}
	ctr.ok("whoami")
	ctr.ok("whoami", "-o", "json")
	ctr.ok("remote", "list")
	// Single use: the token is spent.
	_, _, code = ctr.do("", "remote", "add", "again", host, "--token", token)
	if code != 3 {
		t.Fatalf("replayed token: %d", code)
	}
	if _, err := os.Stat(filepath.Join(client.dir, "certs", "again.key")); err == nil {
		t.Fatal("a failed join left a key behind")
	}
	// Scope applies: operator in web only.
	_, errs, code = ctr.do("", "project", "create", "other")
	if code != 3 {
		t.Fatalf("restricted identity created a project: %d %s", code, errs)
	}
	ctr.ok("list", "--project", "web")
	_, _, code = ctr.do("", "list", "--project", "default")
	if code != 4 {
		t.Fatalf("other project must be not_found: %d", code)
	}

	atr.ok("cert", "list")
	atr.ok("cert", "show", "laptop")
	atr.ok("cert", "edit", "laptop", "-f", writeFile(t, dir, "e.yaml", "kind: Certificate\nmetadata: {name: laptop}\nspec:\n  permission: readonly\n  fingerprint: "+certFP(t, admin, "laptop")+"\n  kind: client\n  projects: [web]\n", 0o644))
	atr.ok("whoami")
	ctr.ok("whoami")
	atr.do("", "cert", "revoke", "laptop") // needs an answer
	atr.ok("cert", "revoke", "-y", "laptop")
	_, _, code = ctr.do("", "whoami")
	if code != 3 {
		t.Fatalf("revoked identity still works: %d", code)
	}
	atr.ok("cert", "list")
	atr.do("", "cert", "revoke", "-y", "laptop")
	atr.ok("sessions", "list")
	atr.do("", "sessions", "revoke", "-y", "nosuch")
	atr.golden("trust")
	ctr.golden("trust_client")
}

func certFP(t *testing.T, h *harness, name string) string {
	t.Helper()
	out, errs, code := h.run("", "cert", "show", name, "-o", "json")
	var c api.Certificate
	if code != 0 || json.Unmarshal([]byte(out), &c) != nil {
		t.Fatalf("cert show %s: %d %s", name, code, errs)
	}
	return c.Spec.Fingerprint
}

func TestSessions(t *testing.T) {
	h := newHarness(t)
	h.srv.SeedSession(api.Session{ID: "s1", User: "alice", Remote: "192.0.2.5", CreatedAt: clock, LastSeen: clock, ExpiresAt: clock.Add(24 * time.Hour)})
	h.srv.SeedSession(api.Session{ID: "s2", User: "bob", CreatedAt: clock, LastSeen: clock, ExpiresAt: clock.Add(24 * time.Hour)})
	tr := h.transcript()
	tr.ok("sessions", "list")
	tr.ok("sessions", "revoke", "-y", "s1")
	tr.ok("sessions", "list", "-o", "name")
	tr.golden("sessions")
}
