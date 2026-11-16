package cli_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

// testCert writes a certificate for name, signed by itself, and its key into dir.
func testCert(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: clock.Add(-time.Hour), NotAfter: clock.AddDate(0, 3, 0), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	c := writeFile(t, dir, name+".crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
	k := writeFile(t, dir, name+".key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})), 0o600)
	return c, k
}

// The certificate of the console from the command line: show, ACME, upload, back to self-signed.
func TestHostCertificateCommands(t *testing.T) {
	h := newHarness(t, fake.WithHostName("alpha.example.org"))
	tr := h.transcript()
	tr.ok("host", "certificate", "show")
	tr.do("", "host", "certificate", "self-signed") // already served: nothing to do
	tr.do("", "host", "certificate", "acme", "--domain", "console.example.com")
	tr.do("", "host", "certificate", "acme", "--domain", "*.example.com", "--accept-tos")
	tr.ok("host", "certificate", "acme", "--domain", "console.example.com", "--email", "admin@example.com", "--accept-tos", "--staging", "--dry-run")
	if h.lastBody("POST", "/api/v1/host/certificate/acme") != nil {
		t.Fatal("the dry run sent the request")
	}
	tr.ok("host", "certificate", "acme", "--domain", "console.example.com", "--email", "admin@example.com", "--accept-tos", "--staging")
	var spec api.ACMESpec
	if err := json.Unmarshal(h.lastBody("POST", "/api/v1/host/certificate/acme"), &spec); err != nil || !spec.AcceptTOS || spec.DirectoryURL != api.ACMEDirectoryStaging || spec.Domains[0] != "console.example.com" {
		t.Fatalf("acme request: %+v %v", spec, err)
	}
	tr.ok("host", "certificate", "show")
	crt, key := testCert(t, h.dir, "console.example.org")
	tr.do("", "host", "certificate", "upload", "--cert", crt)
	tr.do("", "host", "certificate", "upload", "--cert", crt, "--key", key, "--hostname", "www.example.org")
	tr.ok("host", "certificate", "upload", "--cert", crt, "--key", key)
	tr.ok("host", "certificate", "show")
	// going back replaces the uploaded certificate: its name is typed, -y does not answer
	tr.do("", "host", "certificate", "self-signed", "-y")
	tr.do("www.example.org\n", "host", "certificate", "self-signed")
	tr.ok("host", "certificate", "self-signed", "--confirm-replace")
	out := tr.ok("host", "certificate", "show", "-o", "json")
	var st api.HostCertificate
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Source != api.CertSourceSelfSigned {
		t.Fatalf("after self-signed: %+v %v", st, err)
	}
	tr.golden("host_certificate")
}

// The audit log takes --limit, --since and --user to the server and matches --action here.
func TestAuditFilters(t *testing.T) {
	var mu sync.Mutex
	var queries []url.Values
	wrap := func(s *fake.Server) http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			queries = append(queries, r.URL.Query())
			mu.Unlock()
			raw, _ := json.Marshal([]api.AuditEntry{
				{ID: "3", Timestamp: clock, Requestor: "alice", Action: "DELETE /api/v1/jails/{name}", Resource: "web", Result: "ok"},
				{ID: "2", Timestamp: clock.Add(-time.Minute), Requestor: "alice", Action: "POST /api/v1/jails", Resource: "web", Result: "ok"},
				{ID: "1", Timestamp: clock.Add(-2 * time.Minute), Requestor: "alice", Action: "DELETE /api/v1/networks/{name}", Resource: "lan", Result: "denied"},
			})
			fmt.Fprintf(w, `{"type":"sync","status":"Success","status_code":200,"metadata":%s}`, raw)
		})
		mux.Handle("/", s)
		return mux
	}
	h := newHarnessWith(t, wrap)
	tr := h.transcript()
	tr.ok("audit", "--limit", "50", "--since", "24h", "--user", "alice")
	tr.ok("audit", "--action", "delete *", "--limit", "1")
	tr.ok("audit", "--action", "PUT *")
	tr.do("", "audit", "--limit", "5000")
	tr.golden("audit_filters")
	mu.Lock()
	defer mu.Unlock()
	if len(queries) != 3 {
		t.Fatalf("queries: %v", queries)
	}
	since := clock.Add(3 * time.Hour).Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	if q := queries[0]; q.Get("limit") != "50" || q.Get("since") != since || q.Get("actor") != "alice" {
		t.Errorf("first query: %v", q)
	}
	if q := queries[1]; q.Get("limit") != "1000" || q.Get("actor") != "" {
		t.Errorf("an --action query asks for the most the server sends: %v", q)
	}
}

// exec reads its flags up to "--", wherever they are; without "--" a flag-like first word is refused.
func TestExecFlagsBeforeDash(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "shop"}, Spec: api.ProjectSpec{Networks: []api.ProjectNetwork{{Network: "lan"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}})
	h.run("", "create", "web", "--project", "shop", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--start")
	tr := h.transcript()
	tr.ok("exec", "web", "--project", "shop", "--", "echo", "-n", "x")
	tr.ok("exec", "--project", "shop", "web", "--", "echo", "id")
	tr.ok("jail", "exec", "web", "-T", "--project", "shop", "--", "echo", "-T", "is the command's")
	tr.do("", "exec", "web", "--project", "shop", "echo")             // no "--": --project would be the command
	tr.do("", "exec", "web", "echo", "-l", "--project", "shop", "--") // only the name goes before --
	tr.ok("--project", "shop", "exec", "web", "echo", "-l")           // without "--" the command's own options stay its own
	calls := h.srv.ExecCalls()
	if len(calls) != 4 || strings.Join(calls[0].Argv, " ") != "echo -n x" || strings.Join(calls[2].Argv, " ") != "echo -T is the command's" || strings.Join(calls[3].Argv, " ") != "echo -l" {
		t.Fatalf("exec calls: %+v", calls)
	}
	tr.golden("exec_flags")
}

// jail create takes the project's only network and storage, as app install does, and says so.
func TestJailCreateDefaults(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("create", "web", "--image", "freebsd-15@stable")
	var j api.Jail
	if err := json.Unmarshal(h.lastBody("POST", "/api/v1/jails"), &j); err != nil || j.Spec.Storage != "default" || len(j.Spec.Network) != 1 || j.Spec.Network[0].Network != "lan" {
		t.Fatalf("defaults: %+v %v", j.Spec, err)
	}
	h.srv.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "dmz"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.30.0.0/24", Gateway: "10.30.0.1", Range: "10.30.0.10-10.30.0.20"}}})
	tr.ok("network", "grant", "dmz", "--project", "main")
	tr.do("", "create", "db", "--image", "freebsd-15@stable", "--storage", "default") // two networks: never guessed
	tr.ok("--dry-run", "create", "db", "--image", "freebsd-15@stable", "--network", "dmz")
	tr.golden("jail_create_defaults")
}

// The vocabulary: -l, --role, --expires and --X-file for secrets.
func TestVocabularyAliases(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--label", "env=prod")
	tr.ok("list", "--label", "env=prod", "-o", "name")
	tr.ok("stop", "--selector", "env=prod")
	tr.ok("token", "create", "a", "--role", "operator", "--projects", "main", "-o", "name")
	tr.ok("cert", "enroll", "b", "--role", "operator", "--projects", "main", "--expires", "15m", "-o", "name")
	pw := writeFile(t, h.dir, "pw", "a long password\n", 0o600)
	tr.ok("user", "create", "carol", "--role", "operator", "--projects", "main", "--password-file", pw)
	if _, errs, code := tr.do("another long password\n", "user", "set-password", "carol", "--password-file", "-"); code != 0 {
		t.Fatalf("--password-file -: %d %s", code, errs)
	}
	tr.do("pw\n", "user", "set-password", "carol", "--password-file", "-", "--generate")
	tr.ok("backup", "policy", "create", "nightly", "-l", "env=prod", "--schedule", "0 2 * * *", "--target", "usb", "--dry-run")
	tr.golden("vocabulary")
	out, _, _ := h.run("", "__complete", "explain", "")
	if !strings.Contains(out, "data_loss_unconfirmed\n") || !strings.Contains(out, "not_found\n") {
		t.Errorf("explain completion: %q", out)
	}
	out, _, _ = h.run("", "__complete", "create", "x", "--image", "")
	if !strings.Contains(out, "freebsd-15@stable\n") || !strings.Contains(out, "freebsd-15\n") {
		t.Errorf("image completion: %q", out)
	}
	out, _, _ = h.run("", "__complete", "list", "-c", "")
	if !strings.Contains(out, "ipv4\n") || !strings.Contains(out, "age\n") {
		t.Errorf("column completion: %q", out)
	}
	if b := h.lastBody("POST", "/api/v1/users"); !strings.Contains(string(b), `"password":"a long password"`) {
		t.Errorf("user create body: %s", b)
	}
}

// show renders storage, networks, images and projects for a person, and an empty list names the next command.
func TestShowAndEmptyLists(t *testing.T) {
	h := newHarness(t)
	tr := h.transcript()
	tr.ok("list")
	tr.ok("network", "list")
	tr.ok("image", "list")
	tr.ok("list", "web*")
	h.seed()
	h.srv.SeedStorage(api.Storage{Metadata: api.ObjectMeta{Name: "fast"}, Spec: api.StorageSpec{Dataset: "tank/jailops", Compression: "zstd"},
		Status: api.StorageStatus{Pool: "tank", Health: "ONLINE", Size: 1 << 40, Used: 120 << 30, Available: 880 << 30, Fragmentation: 3}})
	tr.ok("storage", "show", "fast")
	tr.ok("network", "show", "lan")
	tr.ok("image", "show", "freebsd-15")
	tr.ok("project", "show", "main")
	tr.ok("storage", "show", "fast", "-o", "yaml")
	h.run("", "create", "web", "--image", "freebsd-15@stable", "--network", "lan=10.20.0.15", "--storage", "default")
	tr.ok("jail", "list", "-c", "name,ipv4", "--sort", "ipv4")
	tr.do("", "jail", "list", "-c", "name,ipv4,gen")
	tr.do("", "firewall", "policy", "list", "-c", "name,age")
	tr.golden("show_human")
}

// What docs/install.md and docs/exposure.md teach for remote access, run as written: trust add on the host, the
// one-argument remote add with the token on standard input on the client.
func TestDocumentedJoinSequence(t *testing.T) {
	srv, ts, fp := tlsFake(t)
	dir := t.TempDir()
	admin := &harness{t: t, srv: srv, ts: ts, dir: dir, env: map[string]string{}, cfgFile: filepath.Join(dir, "admin.yaml")}
	admin.env["JAILOPS_CONFIG"] = admin.cfgFile
	admin.writeConfig(fmt.Sprintf("current: adm\nremotes:\n  adm:\n    url: %s\n    fingerprint: %s\n    token: admin-token\n", ts.URL, fp))
	if _, errs, code := admin.run("", "project", "create", "web"); code != 0 {
		t.Fatal(errs)
	}
	// docs/install.md, "Remote access"
	token, errs, code := admin.run("", "cert", "enroll", "laptop", "--role", "operator", "--projects", "web")
	if code != 0 || !strings.HasPrefix(token, sdk.TrustTokenPrefix) {
		t.Fatalf("cert enroll: %d %s", code, errs)
	}
	client := &harness{t: t, srv: srv, ts: ts, dir: filepath.Join(dir, "client"), env: map[string]string{}, cfgFile: filepath.Join(dir, "client", "config.yaml")}
	_ = os.MkdirAll(client.dir, 0o700)
	client.env["JAILOPS_CONFIG"] = client.cfgFile
	host := strings.TrimPrefix(ts.URL, "https://")
	out, errs, code := client.run(token, "remote", "add", "myhost", host, "--token-file", "-")
	if code != 0 || !strings.Contains(out, "remote/myhost added: trusted as laptop (operator, web)") {
		t.Fatalf("join: %d %q %s", code, out, errs)
	}
	if out, errs, code := client.run("", "whoami"); code != 0 || !strings.Contains(out, "laptop") || !strings.Contains(out, "operator") {
		t.Fatalf("whoami: %d %q %s", code, out, errs)
	}
	// docs/exposure.md, "Join flow": the same with --expires and --cert-expires, the token from a file
	token, errs, code = admin.run("", "cert", "enroll", "ops", "--role", "admin", "--global", "--expires", "15m", "--cert-expires", "2160h")
	if code != 0 {
		t.Fatal(errs)
	}
	tf := writeFile(t, dir, "token", token, 0o600)
	if out, errs, code := client.run("", "remote", "add", "ops", host, "--token-file", tf); code != 0 || !strings.Contains(out, "trusted as ops (admin, global)") {
		t.Fatalf("join from a file: %d %q %s", code, out, errs)
	}
}

// A daemon that cannot be reached is "unavailable", named with its address.
func TestUnreachableRemote(t *testing.T) {
	h := newHarness(t)
	h.writeConfig("current: gone\nremotes:\n  gone:\n    url: https://127.0.0.1:1\nprojects:\n  gone: main\n")
	_, errs, code := h.run("", "jail", "list")
	if code != 1 || !strings.HasPrefix(errs, "unavailable: cannot reach jailopsd at https://127.0.0.1:1 (remote gone)") || !strings.Contains(errs, "hint: check the address") {
		t.Fatalf("%d %q", code, errs)
	}
	// a missing input file is not a transport failure
	_, errs, _ = h.run("", "jail", "create", "-f", filepath.Join(h.dir, "missing.yaml"))
	if strings.Contains(errs, "socket") || strings.Contains(errs, "unavailable") {
		t.Fatalf("a missing file: %q", errs)
	}
}
