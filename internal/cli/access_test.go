package cli_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

func TestTokensCertsUsers(t *testing.T) {
	h := newHarness(t)
	tr := h.transcript()

	// The secret goes to stdout alone, the warning to stderr.
	out, errs, code := tr.do("", "token", "create", "ci", "--role", "operator", "--projects", "main", "--expires", "720h", "--allow-from", "10.0.0.0/8")
	if code != 0 || !strings.HasPrefix(strings.TrimSpace(out), "jot_") || strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Fatalf("token create: %d %q", code, out)
	}
	if !strings.Contains(errs, "shown only once") {
		t.Fatalf("no warning: %q", errs)
	}
	tr.ok("token", "create", "j", "--global", "-o", "json")
	tr.ok("token", "list")
	list := tr.ok("token", "list", "-o", "json")
	if strings.Contains(list, "jot_") {
		t.Fatalf("a listing leaked a secret: %s", list)
	}
	tr.ok("token", "show", "ci")
	tr.do("", "token", "create", "ci", "--global") // exists
	tr.do("", "token", "create", "noscope")
	tr.do("", "token", "create", "both", "--global", "--projects", "main")
	tr.do("", "token", "create", "ghost", "--projects", "nope")
	tr.do("", "token", "create", "weird", "--role", "", "--global")
	tr.ok("token", "revoke", "-y", "ci", "j")

	pemFile := writeCert(t, h.dir)
	tr.ok("cert", "create", "laptop", "--pem", pemFile, "--role", "operator", "--projects", "main")
	tr.ok("cert", "create", "hostb", "--kind", "host", "--fingerprint", "AB:CD:"+strings.Repeat("00", 30), "--role", "admin", "--global")
	tr.do("", "cert", "create", "bad", "--fingerprint", "xyz", "--global")
	tr.do("", "cert", "create", "noscope", "--fingerprint", strings.Repeat("ab", 32))
	tr.ok("cert", "list")
	tr.ok("cert", "revoke", "-y", "hostb")

	out, errs, code = tr.do("", "user", "create", "alice", "--role", "operator", "--projects", "main")
	if code != 0 || strings.TrimSpace(out) == "" || !strings.Contains(errs, "shown only once") {
		t.Fatalf("user create: %d %q %q", code, out, errs)
	}
	tr.ok("user", "list")
	tr.do("", "user", "create", "bob", "--password-file", "-", "--global") // stdin empty
	out, errs, code = tr.do("hunter2-hunter2\n", "user", "create", "bob", "--password-file", "-", "--global")
	if code != 0 || strings.Contains(out, "hunter2") || !strings.Contains(out, "user/bob created") || errs != "" {
		t.Fatalf("user with password: %d %q %q", code, out, errs)
	}
	tr.ok("user", "disable", "bob")
	tr.ok("user", "list")
	tr.ok("user", "enable", "bob")
	tr.ok("user", "show", "bob", "-o", "yaml")
	tr.ok("user", "delete", "-y", "bob")
	tr.golden("access")
}

func writeCert(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "laptop"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dir, "laptop.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
}

func TestCertFingerprintFromPEM(t *testing.T) {
	h := newHarness(t)
	f := writeCert(t, h.dir)
	if _, errs, code := h.run("", "cert", "create", "laptop", "--pem", f, "--global"); code != 0 {
		t.Fatal(errs)
	}
	out, _, _ := h.run("", "cert", "show", "laptop", "-o", "json")
	b, _ := readPEM(f)
	if !strings.Contains(out, sdk.Fingerprint(b)) {
		t.Fatalf("fingerprint missing: %s", out)
	}
}

func readPEM(path string) (*x509.Certificate, error) {
	raw, err := osReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	return x509.ParseCertificate(blk.Bytes)
}

func TestHubScoping(t *testing.T) {
	b := fake.New(fake.WithHostName("host-b"))
	t.Cleanup(b.Close)
	seedMainProject(b)
	h := newHarness(t, fake.WithHosts(map[string]*fake.Server{"host-b": b}))
	h.seed()
	for _, s := range []*fake.Server{h.srv, b} {
		s.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-15"}, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15", Arch: "amd64"}})
	}
	h.srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "on-hub", Project: "main"}, Spec: api.JailSpec{Image: "freebsd-15"}})
	b.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "on-b", Project: "main"}, Spec: api.JailSpec{Image: "freebsd-15"}})
	h.srv.SeedRemote(api.Remote{Metadata: api.ObjectMeta{Name: "host-b"}, Spec: api.RemoteSpec{Address: "https://10.0.0.2:8443", Fingerprint: "ab"},
		Status: api.RemoteStatus{Online: true, Version: "0.1.0", LastSeen: clock}})
	tr := h.transcript()
	tr.ok("jail", "list")
	tr.ok("--host", "host-b", "jail", "list")
	tr.ok("--host", "host-b", "jail", "start", "on-b")
	h.env["JAILOPS_HOST"] = "host-b"
	tr.ok("jail", "list", "-o", "name")
	h.env["JAILOPS_HOST"] = ""
	tr.do("", "--host", "nowhere", "jail", "list")
	tr.ok("host", "list")
	tr.ok("host", "show", "host-b", "-o", "name")
	tr.golden("hub")
	if j, _ := b.JailIn("main", "on-b"); j.Status.Power != api.PowerRunning {
		t.Fatal("start did not reach host-b")
	}
	if j, _ := h.srv.JailIn("main", "on-hub"); j.Status.Power == api.PowerRunning {
		t.Fatal("start leaked to the hub")
	}
}

func TestEvents(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "jail", "create", "db", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "jail", "start", "web")
	tr := h.transcript()
	tr.ok("events", "--since-id", "0", "--type", "lifecycle", "--count", "3")
	tr.ok("events", "--since-id", "0", "--type", "lifecycle", "--jail", "web", "--count", "2", "-o", "json")
	tr.ok("events", "--since-id", "0", "--type", "lifecycle", "--count", "1", "-o", "name")
	tr.ok("events", "--since-id", "0", "--type", "operation", "--count", "1")
	tr.ok("events", "--since-id", "0", "--type", "lifecycle", "--count", "1", "-o", "yaml")
	tr.do("", "events", "--type", "bogus")
	tr.golden("events")
}

// Identity management from the host: first administrator, passwords that never touch the command line, role changes.
func TestUserIdentityManagement(t *testing.T) {
	h := newHarness(t)
	// the bootstrap: one administrator, global
	out, errs, code := h.run("", "user", "create", "admin", "--admin")
	if code != 0 || !strings.Contains(errs, "shown only once") || strings.TrimSpace(out) == "" {
		t.Fatalf("create --admin: %d %q %q", code, out, errs)
	}
	shown, _, code := h.run("", "user", "show", "admin", "-o", "yaml")
	if code != 0 || !strings.Contains(shown, "permission: admin") || !strings.Contains(shown, "global: true") {
		t.Fatalf("admin: %d %s", code, shown)
	}
	if _, _, code := h.run("", "user", "create", "x", "--admin", "--role", "operator"); code == 0 {
		t.Fatal("--admin with --role accepted")
	}
	if _, _, code := h.run("", "user", "create", "x", "--admin", "--global"); code == 0 {
		t.Fatal("--admin with --global accepted")
	}
	// a password prompt, asked twice and compared
	h.secrets = []string{"correct horse battery staple", "correct horse battery staple"}
	if out, errs, code := h.run("", "user", "create", "carol", "--role", "operator", "--projects", "main", "--password-prompt"); code != 0 || strings.Contains(out+errs, "correct horse") {
		t.Fatalf("prompted create: %d %q %q", code, out, errs)
	}
	h.secrets = []string{"one", "two"}
	if _, _, code := h.run("", "user", "set-password", "carol"); code == 0 {
		t.Fatal("mismatching passwords accepted")
	}
	h.secrets = nil
	// without a terminal and without --password-file - it refuses instead of reading a password from anywhere else
	if _, errs, code := h.run("", "user", "set-password", "carol"); code == 0 || !strings.Contains(errs, "--password-file -") {
		t.Fatalf("no terminal: %d %q", code, errs)
	}
	out, errs, code = h.run("a long new passphrase\n", "user", "set-password", "carol", "--password-file", "-")
	if code != 0 || strings.Contains(out+errs, "passphrase") || !strings.Contains(out, "password set") {
		t.Fatalf("set-password: %d %q %q", code, out, errs)
	}
	out, errs, code = h.run("", "user", "set-password", "carol", "--generate")
	if code != 0 || !strings.Contains(errs, "shown only once") || strings.TrimSpace(out) == "" {
		t.Fatalf("generate: %d %q %q", code, out, errs)
	}
	if _, _, code := h.run("", "user", "set-password", "ghost", "--generate"); code == 0 {
		t.Fatal("unknown user")
	}
	// set-role replaces what it is given (--role is the former name of --role)
	if _, errs, code := h.run("", "user", "set-role", "carol", "--role", "admin", "--global"); code != 0 {
		t.Fatalf("set-role: %d %q", code, errs)
	}
	shown, _, _ = h.run("", "user", "show", "carol", "-o", "yaml")
	if !strings.Contains(shown, "permission: admin") || !strings.Contains(shown, "global: true") || strings.Contains(shown, "main") {
		t.Fatalf("carol: %s", shown)
	}
	if _, errs, code := h.run("", "user", "set-role", "carol", "--role", "readonly", "--projects", "main"); code != 0 {
		t.Fatalf("set-role back: %d %q", code, errs)
	}
	shown, _, _ = h.run("", "user", "show", "carol", "-o", "yaml")
	if !strings.Contains(shown, "permission: readonly") || strings.Contains(shown, "global: true") || !strings.Contains(shown, "main") {
		t.Fatalf("carol again: %s", shown)
	}
	// what is left out stays: the role alone keeps the scope, the scope alone keeps the role
	if out, errs, code := h.run("", "user", "set-role", "carol", "--role", "operator"); code != 0 || !strings.Contains(out, "readonly, main -> operator, main") {
		t.Fatalf("set-role --role: %d %q %q", code, out, errs)
	}
	if out, errs, code := h.run("", "user", "set-role", "carol", "--global"); code != 0 || !strings.Contains(out, "operator, main -> operator, global") {
		t.Fatalf("set-role --global: %d %q %q", code, out, errs)
	}
	shown, _, _ = h.run("", "user", "show", "carol", "-o", "yaml")
	if !strings.Contains(shown, "permission: operator") || !strings.Contains(shown, "global: true") {
		t.Fatalf("carol kept: %s", shown)
	}
	if _, errs, code := h.run("", "user", "set-role", "carol"); code != 2 || !strings.Contains(errs, "give --role") {
		t.Fatalf("set-role without anything: %d %q", code, errs)
	}
	// revoke is how a token ends
	h.run("", "token", "create", "ci", "--global")
	if _, errs, code := h.run("", "token", "revoke", "-y", "ci"); code != 0 {
		t.Fatalf("token revoke: %d %q", code, errs)
	}
}
