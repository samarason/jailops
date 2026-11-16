package e2e

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"jailops.net/jailops/internal/fleet/cli"
	"jailops.net/jailops/internal/fleet/fleettest"
	"jailops.net/jailops/internal/fleet/secrets"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

const (
	apiToken  = "jot_0123456789abcdef0123456789abcdef"
	dbSecret  = "correct horse battery staple 4711"
	tokenName = "web1-token"
)

func secretsFleet(t *testing.T, withSealedExt bool) *fleettest.Env {
	t.Helper()
	e := fleettest.New(t, "testfleet")
	var opts []fake.Option
	if !withSealedExt { // a host that does not advertise sealed_secrets (an older version)
		opts = append(opts, fake.WithExtensions(slices.DeleteFunc(slices.Clone(api.Extensions), func(x string) bool { return x == secrets.ExtSealedSecrets })...))
	}
	e.AddHost("web1", apiToken, opts...)
	e.StandardObjects()
	e.WriteSecret("db-pass", dbSecret)
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
    DB_PASSWORD: "secret:db-pass"
    MODE: production
`)
	return e
}

func TestSecretsNeverLeakIntoLogsOutputOrRequests(t *testing.T) {
	e := secretsFleet(t, true)

	var all strings.Builder
	collect := func(r result) result { all.WriteString(r.out + r.err); return r }

	collect(mustOK(t, run(t, e, "validate")))
	collect(mustOK(t, run(t, e, "doctor", "--deep")))
	collect(mustOK(t, run(t, e, "plan")))
	collect(mustOK(t, run(t, e, "render")))
	collect(mustOK(t, run(t, e, "sync", "--apply")))
	collect(mustOK(t, run(t, e, "drift")))
	collect(mustOK(t, run(t, e, "secrets", "check")))

	// The token authenticated: doctor says the server trusts us.
	r := mustOK(t, run(t, e, "doctor", "--host", "web1"))
	contains(t, r.out, "ok    host web1")

	// The jail env holds the sealed ciphertext, and it opens to the secret.
	j := getJail(t, e.Hosts["web1"], "app")
	sealed := j.Spec.Env["DB_PASSWORD"]
	if !strings.HasPrefix(sealed, secrets.SealedPrefix) {
		t.Fatalf("env was not sealed: %q", sealed)
	}
	if j.Spec.Env["MODE"] != "production" {
		t.Fatal("plain env value changed")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, secrets.SealedPrefix))
	if err != nil {
		t.Fatal(err)
	}
	idf, _ := os.Open(e.Identity)
	ids, err := age.ParseIdentities(idf)
	idf.Close()
	if err != nil {
		t.Fatal(err)
	}
	pr, err := age.Decrypt(armor.NewReader(bytes.NewReader(raw)), ids...)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(pr); string(got) != dbSecret {
		t.Fatalf("sealed value does not open to the secret: %q", got)
	}

	// Zero diff after the apply: the sealed value is compared through the hash.
	mustOK(t, run(t, e, "drift"))

	// Nothing the tool printed, logged or sent contains a plaintext.
	logs, _ := filepath.Glob(filepath.Join(e.State, "*"))
	if len(logs) == 0 {
		t.Fatal("no state files")
	}
	for _, l := range logs {
		if st, _ := os.Stat(l); st.IsDir() {
			continue
		}
		b, _ := os.ReadFile(l)
		all.Write(b)
	}
	for _, rq := range e.Hosts["web1"].Server.Requests() {
		if bytes.Contains(rq.Body, []byte(dbSecret)) {
			t.Fatalf("a request body carried the plaintext secret: %s %s", rq.Method, rq.Path)
		}
	}
	for _, leak := range []string{apiToken, dbSecret} {
		if strings.Contains(all.String(), leak) {
			t.Fatalf("plaintext %q leaked into output or the state directory", leak)
		}
	}
	// And the repository holds only ciphertext.
	err = filepath.WalkDir(e.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == filepath.Join(e.Dir, "secrets", "recipients.txt") {
			return err
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(dbSecret)) || bytes.Contains(b, []byte(apiToken)) {
			t.Errorf("plaintext in repository file %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecretsRefusedWhereServerCannotTakeSealedValues(t *testing.T) {
	e := secretsFleet(t, false)
	r := mustFail(t, run(t, e, "sync", "--apply"), secrets.ExtSealedSecrets)
	contains(t, r.all(), "never sends secrets in the clear")
	if _, ok := e.Hosts["web1"].Server.JailIn(fleettest.Project, "app"); ok {
		t.Fatal("the jail was created without its secret")
	}
	if _, ok := e.Hosts["web1"].Server.Network("internal"); ok {
		t.Fatal("a plan with errors must not apply anything")
	}
}

func TestMissingIdentityIsAClearError(t *testing.T) {
	e := secretsFleet(t, true)
	var out, errb bytes.Buffer
	code := cli.Run(cli.Env{Stdout: &out, Stderr: &errb, Getenv: func(k string) string {
		if k == cli.EnvStateDir {
			return e.State
		}
		return ""
	}}, []string{"-C", e.Dir, "plan"})
	if code == 0 || !strings.Contains(errb.String()+out.String(), "no age identity configured") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errb.String())
	}
}

func TestIdentityFilePermissionsAreChecked(t *testing.T) {
	e := secretsFleet(t, true)
	if err := os.Chmod(e.Identity, 0o644); err != nil {
		t.Fatal(err)
	}
	mustFail(t, run(t, e, "doctor", "--deep"), "chmod 600")
}

func TestSecretsCommands(t *testing.T) {
	e := fleettest.New(t, "testfleet", "web1")
	const val = "s3cr3t-value-for-set"
	r := mustOK(t, runIn(t, e, val+"\n", "secrets", "set", "api-key"))
	contains(t, r.out, "wrote secrets/api-key.age")
	if strings.Contains(r.all(), val) {
		t.Fatal("set printed the value")
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "secrets", "api-key.age"))
	if err != nil || bytes.Contains(b, []byte(val)) || !bytes.Contains(b, []byte("BEGIN AGE ENCRYPTED FILE")) {
		t.Fatalf("secret file is not armored ciphertext: %v", err)
	}
	r = mustOK(t, run(t, e, "secrets", "list"))
	contains(t, r.out, "api-key")
	r = mustOK(t, run(t, e, "secrets", "check"))
	contains(t, r.out, "ok    api-key")
	// A different identity cannot open it.
	other, _ := secrets.GenerateIdentity()
	var out, errb bytes.Buffer
	code := cli.Run(cli.Env{Stdout: &out, Stderr: &errb, Getenv: func(k string) string {
		if k == secrets.EnvKey {
			return other.String()
		}
		return ""
	}}, []string{"-C", e.Dir, "secrets", "check"})
	if code == 0 || !strings.Contains(out.String(), "FAIL  api-key") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	// keygen prints a usable identity.
	r = mustOK(t, run(t, e, "secrets", "keygen"))
	contains(t, r.out, "AGE-SECRET-KEY-")
	contains(t, r.err, "public key: age1")
}

func TestSecretsAddHostsListsTheHostsKeys(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e := fleettest.New(t, "testfleet")
	e.AddHost("web1", apiToken, fake.WithSecretsRecipient(id.Recipient().String()))
	e.AddHost("web2", apiToken)
	e.StandardObjects()
	e.WriteSecret("db-pass", dbSecret)
	r := mustOK(t, run(t, e, "secrets", "add-hosts"))
	contains(t, r.out, "web1")
	contains(t, r.out, "added")
	contains(t, r.out, "publishes no secrets key")
	b, err := os.ReadFile(filepath.Join(e.Dir, "secrets", "recipients.txt"))
	if err != nil || !strings.Contains(string(b), id.Recipient().String()) || !strings.Contains(string(b), "# host web1") {
		t.Fatalf("recipients.txt: %q %v", b, err)
	}
	r = mustOK(t, run(t, e, "secrets", "add-hosts"))
	contains(t, r.out, "already listed")
}
