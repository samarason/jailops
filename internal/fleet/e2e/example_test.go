package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/fleet/cli"
	"jailops.net/jailops/internal/fleet/fleettest"
	"jailops.net/jailops/internal/fleet/secrets"
	"jailops.net/jailops/internal/fleet/vault"
)

const exampleDir = "../../../examples/minimal-fleet"

// TestGenerateExampleSecret regenerates the example's throwaway identity,
// recipients file and encrypted token. It runs only on request:
//
//	JAILOPS_SYNC_REGEN_EXAMPLE=1 go test ./internal/fleet/e2e -run GenerateExample
//
// It also writes .sops.yaml, shared/secrets.sops.yaml and hosts/web2/remote.sops.yaml,
// encrypted to the same identity.
//
// The identity it writes protects nothing real.
func TestGenerateExampleSecret(t *testing.T) {
	if os.Getenv("JAILOPS_SYNC_REGEN_EXAMPLE") == "" {
		t.Skip("set JAILOPS_SYNC_REGEN_EXAMPLE=1 to regenerate the example secret")
	}
	id, err := secrets.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	header := "# THROWAWAY identity for the example fleet. It protects nothing real.\n"
	if err := os.WriteFile(filepath.Join(exampleDir, "..", "example-identity.txt"), []byte(header+id.String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(exampleDir, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exampleDir, "secrets", secrets.RecipientsFile), []byte("# age public keys the secrets are encrypted to\n"+id.Recipient().String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fleettest.WriteSecret(t, filepath.Join(exampleDir, "secrets"), "fleet-token", "jot_example_token_not_a_real_secret", id.Recipient().String())

	// The SOPS files, encrypted to the same throwaway identity.
	policy := "# Who can decrypt the SOPS files of this fleet: the age public keys below.\n" +
		"# The key of this example is the throwaway identity in examples/example-identity.txt.\n" +
		"keys:\n  - &example_operator " + id.Recipient().String() + "\n" +
		"creation_rules:\n" +
		"  # hosts/<host>/remote.sops.yaml: url and server_fingerprint stay readable in git,\n" +
		"  # only the client certificate and key are encrypted.\n" +
		"  - path_regex: hosts/.*/remote\\.sops\\.yaml$\n" +
		"    encrypted_regex: '^(client_key|client_cert)$'\n" +
		"    key_groups:\n      - age:\n          - *example_operator\n" +
		"  # Every other SOPS file (shared/secrets.sops.yaml): all values encrypted.\n" +
		"  - path_regex: \\.sops\\.ya?ml$\n" +
		"    key_groups:\n      - age:\n          - *example_operator\n"
	if err := os.WriteFile(filepath.Join(exampleDir, vault.SopsPolicyFilename), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(vault.EnvKey, id.String())
	os.Unsetenv(vault.EnvKeyFile)
	os.Unsetenv(vault.EnvKeyCmd)
	enc, err := vault.EncryptYAML(exampleDir, vault.SecretsRel, []byte("blog:\n  db_password: example-db-password-not-real\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.WriteFileAtomic(vault.SecretsPath(exampleDir), enc, 0o644); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _, err := vault.NewClientIdentity("jailops-sync-web2", time.Now(), 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ind := func(s string) string {
		return "  " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  ") + "\n"
	}
	remote := "url: https://web2.example.test:8443\nserver_fingerprint: \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n" +
		"client_cert: |\n" + ind(string(certPEM)) + "client_key: |\n" + ind(string(keyPEM))
	enc, err = vault.EncryptYAML(exampleDir, vault.RemoteRel("web2"), []byte(remote))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.WriteFileAtomic(vault.RemotePath(exampleDir, "web2"), enc, 0o644); err != nil {
		t.Fatal(err)
	}
}

func runExample(t *testing.T, args ...string) result {
	t.Helper()
	idf := filepath.Join(t.TempDir(), "identity.txt")
	b, err := os.ReadFile(filepath.Join(exampleDir, "..", "example-identity.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idf, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(vault.EnvKeyFile, idf)
	os.Unsetenv(vault.EnvKey)
	os.Unsetenv(vault.EnvKeyCmd)
	var out, errb bytes.Buffer
	code := cli.Run(cli.Env{Stdout: &out, Stderr: &errb, Getenv: func(k string) string {
		switch k {
		case secrets.EnvIdentityFile:
			return idf
		case cli.EnvStateDir:
			return t.TempDir()
		case vault.EnvKeyFile:
			return idf
		}
		return ""
	}}, append([]string{"-C", exampleDir}, args...))
	return result{code, out.String(), errb.String()}
}

func TestExampleFleetValidatesAndRenders(t *testing.T) {
	r := mustOK(t, runExample(t, "validate"))
	contains(t, r.out, `fleet "minimal", 2 host(s), 14 object(s)`)
	contains(t, r.out, "1 rollout(s), 1 secret(s)")
	contains(t, r.out, "sops: 1 secret value(s) in shared/secrets.sops.yaml, 1 remote file(s)")

	r = mustOK(t, runExample(t, "render", "--host", "web1"))
	contains(t, r.out, "name: blog")
	contains(t, r.out, "memory: 2G") // the jail's own value over the profile's
	contains(t, r.out, "cpu: 1")     // inherited from the profile
	contains(t, r.out, "managed_by: sync:minimal")
	contains(t, r.out, "project: web")
	contains(t, r.out, "profiles: small, web")
	contains(t, r.out, "jail_port: 443")
	if strings.Contains(r.out, "name: wiki") {
		t.Fatal("web2's jail rendered for web1")
	}

	// The jail's database password is a reference; rendering decrypts nothing.
	contains(t, r.out, "DB_PASSWORD: secret:blog.db_password")
	if strings.Contains(r.all(), "example-db-password") {
		t.Fatal("render printed a SOPS secret")
	}

	// The SOPS files open with the throwaway identity too; nothing is printed.
	r = mustOK(t, runExample(t, "vault", "status"))
	contains(t, r.out, "SOPS_AGE_KEY_FILE")
	r = mustOK(t, runExample(t, "vault", "list-recipients"))
	contains(t, r.out, "example_operator")
	r = mustOK(t, runExample(t, "remote", "list"))
	contains(t, r.out, "web2")
	m, err := vault.LoadSecrets(exampleDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := vault.Lookup(m, "blog.db_password"); err != nil || !strings.HasPrefix(v, "example-db-password") {
		t.Fatalf("%q %v", v, err)
	}
	if rem, err := vault.LoadRemote(exampleDir, "web2", nil); err != nil || rem.URL != "https://web2.example.test:8443" {
		t.Fatalf("%v %v", rem, err)
	}

	// The one secret opens with the throwaway identity; nothing is printed.
	r = mustOK(t, runExample(t, "secrets", "check"))
	contains(t, r.out, "ok    fleet-token")
	if strings.Contains(r.all(), "jot_example") {
		t.Fatal("the example secret was printed")
	}
	mustFail(t, runExample(t, "plan", "--host", "@none"), "unknown group @none")
}
