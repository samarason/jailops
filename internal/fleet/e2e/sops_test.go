package e2e

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"jailops.net/jailops/internal/fleet/fleettest"
	"jailops.net/jailops/internal/fleet/secrets"
	"jailops.net/jailops/internal/fleet/vault"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

const sopsPolicy = `keys:
  - &operator %s
creation_rules:
  - path_regex: hosts/.*/remote\.sops\.yaml$
    encrypted_regex: '^(client_key|client_cert)$'
    key_groups:
      - age:
          - *operator
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - *operator
`

// useSops points SOPS at the environment's identity and writes .sops.yaml.
func useSops(t *testing.T, e *fleettest.Env) {
	t.Helper()
	t.Setenv(vault.EnvKey, "x")
	t.Setenv(vault.EnvKeyCmd, "x")
	os.Unsetenv(vault.EnvKey)
	os.Unsetenv(vault.EnvKeyCmd)
	t.Setenv(vault.EnvKeyFile, e.Identity)
	e.Write(vault.SopsPolicyFilename, strings.ReplaceAll(sopsPolicy, "%s", e.Recipient))
}

func writeSopsSecrets(t *testing.T, e *fleettest.Env, plain string) {
	t.Helper()
	enc, err := vault.EncryptYAML(e.Dir, vault.SecretsRel, []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.WriteFileAtomic(vault.SecretsPath(e.Dir), enc, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sopsFleet(t *testing.T) *fleettest.Env {
	t.Helper()
	e := fleettest.New(t, "testfleet")
	e.AddHost("web1", apiToken, fake.WithExtensions(append(slices.Clone(api.Extensions), secrets.ExtSealedSecrets)...))
	e.StandardObjects()
	useSops(t, e)
	writeSopsSecrets(t, e, "app:\n  db_password: "+dbSecret+"\n")
	e.Write("projects/main/jails/app.yaml", `apiVersion: jailops/v1
kind: Jail
hosts: [web1]
metadata:
  name: app
spec:
  image: freebsd-15@stable
  storage: default
  network: [{network: internal}]
  firewall: {policies: [web]}
  env:
    DB_PASSWORD: "secret:app.db_password"
    MODE: production
`)
	return e
}

func opensTo(t *testing.T, e *fleettest.Env, sealed string) string {
	t.Helper()
	if !strings.HasPrefix(sealed, secrets.SealedPrefix) {
		t.Fatalf("not sealed: %q", sealed)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, secrets.SealedPrefix))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(e.Identity)
	ids, err := age.ParseIdentities(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	pr, err := age.Decrypt(armor.NewReader(bytes.NewReader(raw)), ids...)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(pr)
	return string(b)
}

func TestSopsSecretReachesTheHostSealedAndStaysInSync(t *testing.T) {
	e := sopsFleet(t)
	var all strings.Builder
	collect := func(r result) result { all.WriteString(r.out + r.err); return r }

	r := collect(mustOK(t, run(t, e, "validate")))
	contains(t, r.out, "sops: 1 secret value(s)")
	collect(mustOK(t, run(t, e, "render")))

	// Planning needs no key: the stand-in is a digest of the stored ciphertext.
	t.Setenv(vault.EnvKeyFile, "")
	os.Unsetenv(vault.EnvKeyFile)
	r = collect(mustOK(t, run(t, e, "plan")))
	contains(t, r.out, "Jail/main/app")
	t.Setenv(vault.EnvKeyFile, e.Identity)

	collect(mustOK(t, run(t, e, "sync", "--apply")))
	j := getJail(t, e.Hosts["web1"], "app")
	if got := opensTo(t, e, j.Spec.Env["DB_PASSWORD"]); got != dbSecret {
		t.Fatalf("the sealed value opens to %q", got)
	}
	if j.Spec.Env["MODE"] != "production" {
		t.Fatal("plain env changed")
	}

	// In sync afterwards, with or without the key: the sealed value on the host
	// is random, the hash decides.
	collect(mustOK(t, run(t, e, "drift")))
	os.Unsetenv(vault.EnvKeyFile)
	collect(mustOK(t, run(t, e, "drift")))
	t.Setenv(vault.EnvKeyFile, e.Identity)

	// Rotating the value is a change the next plan sees, and apply sends the new one.
	writeSopsSecrets(t, e, "app:\n  db_password: rotated-"+dbSecret+"\n")
	r = collect(run(t, e, "drift"))
	if r.code == 0 {
		t.Fatalf("a rotated secret was not seen as drift:\n%s", r.out)
	}
	collect(mustOK(t, run(t, e, "sync", "--apply")))
	j = getJail(t, e.Hosts["web1"], "app")
	if got := opensTo(t, e, j.Spec.Env["DB_PASSWORD"]); got != "rotated-"+dbSecret {
		t.Fatalf("after rotation the sealed value opens to %q", got)
	}
	collect(mustOK(t, run(t, e, "drift")))

	// Nothing printed, logged or sent holds a plaintext.
	logs, _ := filepath.Glob(filepath.Join(e.State, "*"))
	for _, l := range logs {
		if st, _ := os.Stat(l); !st.IsDir() {
			b, _ := os.ReadFile(l)
			all.Write(b)
		}
	}
	for _, rq := range e.Hosts["web1"].Server.Requests() {
		if bytes.Contains(rq.Body, []byte(dbSecret)) {
			t.Fatalf("a request carried the plaintext: %s %s", rq.Method, rq.Path)
		}
	}
	if strings.Contains(all.String(), dbSecret) {
		t.Fatal("the plaintext leaked into output or state")
	}
	err := filepath.WalkDir(e.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(dbSecret)) {
			t.Errorf("plaintext in repository file %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSopsApplyFailsClearlyWithoutAKey(t *testing.T) {
	e := sopsFleet(t)
	os.Unsetenv(vault.EnvKeyFile)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	r := run(t, e, "sync", "--apply")
	if r.code == 0 {
		t.Fatal("applied without a key")
	}
	contains(t, r.all(), "SOPS_AGE_KEY")
	for _, rq := range e.Hosts["web1"].Server.Requests() {
		if rq.Method == http.MethodPost && strings.Contains(rq.Path, "/jails") {
			t.Fatalf("a jail was created without the secret: %s", rq.Path)
		}
	}
	d := run(t, e, "doctor", "--host", "web1")
	contains(t, d.out, "FAIL  sops key")
}

func TestSopsValidateRefusesMistakes(t *testing.T) {
	// a reference to a path that is not in the file
	e := sopsFleet(t)
	e.Write("projects/main/jails/app.yaml", strings.ReplaceAll(readFile(t, e, "projects/main/jails/app.yaml"), "app.db_password", "app.nothing"))
	mustFail(t, run(t, e, "validate"), `no such path in shared/secrets.sops.yaml`)

	// a plaintext secrets file
	e = sopsFleet(t)
	e.Write(vault.SecretsRel, "app:\n  db_password: oops\n")
	mustFail(t, run(t, e, "validate"), "not SOPS-encrypted")

	// a secrets file nobody's policy covers
	e = sopsFleet(t)
	e.Write(vault.SopsPolicyFilename, "keys:\n  - &k "+e.Recipient+"\ncreation_rules:\n  - path_regex: ^nothing$\n    key_groups:\n      - age:\n          - *k\n")
	mustFail(t, run(t, e, "validate"), "no creation_rule matching")

	// a remote file whose private key is in clear
	e = sopsFleet(t)
	e.Write("hosts/web1/remote.sops.yaml", "url: https://web1.example.test:8443\nserver_fingerprint: "+strings.Repeat("ab", 32)+"\nclient_cert: x\nclient_key: y\nsops:\n  version: 3.9.0\n")
	mustFail(t, run(t, e, "validate"), "is not encrypted")
}

func readFile(t *testing.T, e *fleettest.Env, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.Dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestVaultCommands(t *testing.T) {
	e := fleettest.New(t, "testfleet")
	e.AddHost("web1", "")
	useSops(t, e)
	writeSopsSecrets(t, e, "a:\n  b: "+dbSecret+"\n")

	r := mustOK(t, run(t, e, "vault", "status"))
	contains(t, r.out, "SOPS_AGE_KEY_FILE")
	r = mustOK(t, run(t, e, "vault", "list-recipients"))
	contains(t, r.out, "operator")

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r = mustOK(t, run(t, e, "vault", "add-recipient", "ci_runner", other.Recipient().String(), "--comment", "CI"))
	contains(t, r.out, "re-wrapped 1 file(s)")
	contains(t, r.out, "COMMIT THIS NOW")
	// the new recipient opens the secrets file now
	idf := filepath.Join(t.TempDir(), "ci.txt")
	os.WriteFile(idf, []byte(other.String()+"\n"), 0o600)
	t.Setenv(vault.EnvKeyFile, idf)
	if m, err := vault.LoadSecrets(e.Dir, nil); err != nil {
		t.Fatalf("new recipient: %v", err)
	} else if v, _ := vault.Lookup(m, "a.b"); v != dbSecret {
		t.Fatal(v)
	}
	t.Setenv(vault.EnvKeyFile, e.Identity)

	// removing the last recipient of a rule is refused and changes nothing
	before := readFile(t, e, vault.SopsPolicyFilename)
	r = run(t, e, "vault", "remove-recipient", "operator")
	if r.code != 0 { // the CI key still covers the rule, so this one is allowed
		t.Fatalf("%s", r.all())
	}
	if readFile(t, e, vault.SopsPolicyFilename) == before {
		t.Fatal("the policy did not change")
	}
	t.Setenv(vault.EnvKeyFile, idf)
	mustFail(t, run(t, e, "vault", "remove-recipient", "ci_runner"), "zero recipients")

	// the removed operator key can no longer open the file
	t.Setenv(vault.EnvKeyFile, e.Identity)
	if _, err := vault.LoadSecrets(e.Dir, nil); err == nil {
		t.Fatal("a removed recipient still decrypts")
	}
}

// A host that has a remote file is reached over pinned mTLS with the
// client certificate from that file.
func TestRemoteBootstrapAndConnect(t *testing.T) {
	e := fleettest.New(t, "testfleet")
	useSops(t, e)
	srv := fake.New(fake.WithHostName("web1"))
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
			mu.Lock()
			seen = append(seen, hex.EncodeToString(sum[:]))
			mu.Unlock()
		}
		srv.ServeHTTP(w, r)
	}))
	ts.EnableHTTP2 = false
	ts.StartTLS()
	ts.TLS.ClientAuth = tls.RequireAnyClientCert
	t.Cleanup(func() { ts.Close(); srv.Close() })
	serverFP := sha256.Sum256(ts.Certificate().Raw)

	// the host is declared without an address: the remote file gives it
	e.Write("hosts/web1/host.yaml", "apiVersion: jailops/v1\nkind: Host\nmetadata:\n  name: web1\nspec: {}\n")

	// no host.yaml, no bootstrap
	mustFail(t, run(t, e, "remote", "bootstrap", "ghost", "--url", ts.URL, "--fingerprint", hex.EncodeToString(serverFP[:])), "declare the host first")
	mustFail(t, run(t, e, "remote", "bootstrap", "web1", "--url", ts.URL), "required")
	mustFail(t, run(t, e, "remote", "bootstrap", "web1", "--url", "http://x", "--fingerprint", hex.EncodeToString(serverFP[:])), "https://")

	r := mustOK(t, run(t, e, "remote", "bootstrap", "web1", "--url", ts.URL, "--fingerprint", "sha256:"+hex.EncodeToString(serverFP[:])))
	contains(t, r.out, "BEGIN CERTIFICATE")
	if strings.Contains(r.all(), "PRIVATE KEY") {
		t.Fatal("the private key was printed")
	}
	contains(t, r.err, "jailops cert create jailops-sync-web1 --pem CERT.pem --role admin --global")
	raw := readFile(t, e, "hosts/web1/remote.sops.yaml")
	if strings.Contains(raw, "BEGIN CERTIFICATE") || strings.Contains(raw, "PRIVATE KEY") || !strings.Contains(raw, "url: "+ts.URL) {
		t.Fatalf("remote file:\n%s", raw)
	}
	mustFail(t, run(t, e, "remote", "bootstrap", "web1", "--url", ts.URL, "--fingerprint", hex.EncodeToString(serverFP[:])), "already exists")

	r = mustOK(t, run(t, e, "remote", "list"))
	contains(t, r.out, "web1")
	mustOK(t, run(t, e, "validate"))

	d := mustOK(t, run(t, e, "doctor", "--deep", "--host", "web1"))
	contains(t, d.out, "ok    sops hosts/web1/remote.sops.yaml")
	contains(t, d.out, "ok    host web1")
	rem, err := vault.LoadRemote(e.Dir, "web1", nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := rem.ClientFingerprint()
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(seen, want) {
		t.Fatalf("the server never saw the client certificate %s (saw %v)", want, seen)
	}

	// a wrong pin refuses the connection
	rem.ServerFingerprint = strings.Repeat("00", 32)
	enc, err := vault.EncryptYAML(e.Dir, vault.RemoteRel("web1"), []byte(remoteDoc(rem)))
	if err != nil {
		t.Fatal(err)
	}
	vault.WriteFileAtomic(vault.RemotePath(e.Dir, "web1"), enc, 0o644)
	mustFail(t, run(t, e, "doctor", "--host", "web1"), "FAIL  host web1")
}

func remoteDoc(r *vault.Remote) string {
	ind := func(s string) string {
		return "  " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  ") + "\n"
	}
	return "url: " + r.URL + "\nserver_fingerprint: \"" + r.ServerFingerprint + "\"\nclient_cert: |\n" + ind(r.ClientCert) + "client_key: |\n" + ind(r.ClientKey)
}

func TestSecretsPutWritesAnEncryptedValue(t *testing.T) {
	e := fleettest.New(t, "testfleet")
	e.AddHost("web1", apiToken)
	e.StandardObjects()
	useSops(t, e)
	r := mustOK(t, runIn(t, e, "s3cret-value\n", "secrets", "put", "app.db_password"))
	contains(t, r.out, "set app.db_password")
	mustOK(t, runIn(t, e, "second\n", "secrets", "put", "app.api_key"))
	raw, err := os.ReadFile(vault.SecretsPath(e.Dir))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("s3cret-value")) || bytes.Contains(raw, []byte("second")) {
		t.Fatal("plaintext in the secrets file")
	}
	if !bytes.Contains(raw, []byte("db_password")) || !bytes.Contains(raw, []byte("sops")) {
		t.Fatalf("not a sops file with readable keys:\n%s", raw)
	}
	m, err := vault.LoadSecrets(e.Dir, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := vault.Lookup(m, "app.db_password"); v != "s3cret-value" {
		t.Fatalf("value = %q", v)
	}
	if v, _ := vault.Lookup(m, "app.api_key"); v != "second" {
		t.Fatalf("value = %q", v)
	}
	mustFail(t, runIn(t, e, "x\n", "secrets", "put", "app"), "group of values")
	mustFail(t, runIn(t, e, "x\n", "secrets", "put", "app.db_password.sub"), "not a group")
}
