package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The passphrase flow of encrypted volumes: asked twice on a terminal (a fake one here), refused on a pipe, read
// from a file for scripts; unlock, lock and the change of the passphrase. No passphrase is ever printed or sent
// anywhere but in the request bodies, which the fake records with the passphrase replaced.
func TestEncryptedVolumes(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.env["TERM"], h.env["NO_COLOR"] = "dumb", "1"
	tr := h.transcript()
	const pass, other = "marker-cli-correct-horse", "marker-cli-new-passphrase"
	create := []string{"volume", "create", "vault", "--encrypted", "--uid", "770", "--gid", "770", "--mode", "0700", "--size", "5G"}

	// no terminal and no file: refused before anything is sent
	tr.do("", create...)
	h.tty = true
	h.secrets = []string{pass, pass + "x"}
	tr.do("", create...)
	h.secrets = []string{"too-short", "too-short"}
	tr.do("", create...)
	h.secrets = []string{pass, pass}
	tr.do("", create...)
	h.tty = false

	// a script: the passphrase in a file, warned about when others can read it
	file := filepath.Join(h.dir, "vault.pass")
	if err := os.WriteFile(file, []byte(pass+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr.do("", "volume", "create", "vault2", "--encrypted", "--passphrase-file", file)
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	tr.do("", "volume", "create", "plain", "--passphrase-file", file)
	for _, j := range []string{"vault", "vault2"} {
		tr.ok("jail", "create", j, "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
		tr.ok("volume", "attach", j, j, "/srv/db")
	}
	// an encrypted volume is attached to one jail only
	tr.do("", "volume", "attach", "vault2", "vault", "/srv/other")

	// a host boot locks both; a locked jail does not start
	h.srv.RebootHost()
	tr.ok("volume", "list")
	tr.ok("jail", "list")
	tr.do("", "jail", "start", "vault")
	tr.ok("explain", "locked")
	h.tty = true
	h.secrets = []string{"marker-cli-wrong-passphrase"}
	tr.do("", "volume", "unlock", "vault")
	h.secrets = []string{pass}
	tr.do("", "volume", "unlock", "vault", "--start")
	tr.do("", "volume", "unlock", "vault2", "--passphrase-file", file)
	tr.ok("jail", "list", "--state", "locked")
	tr.ok("jail", "list")
	tr.do("", "volume", "lock", "vault")
	tr.ok("jail", "list", "--state", "locked")
	// the passphrase changes: the current one once, the new one twice
	h.secrets = []string{pass}
	tr.do("", "volume", "unlock", "vault")
	h.secrets = []string{pass, other, other}
	tr.do("", "volume", "passphrase", "vault")
	h.secrets = []string{pass}
	tr.do("", "volume", "lock", "vault")
	tr.do("", "volume", "unlock", "vault")
	h.secrets = []string{other}
	tr.do("", "volume", "unlock", "vault")
	h.tty = false
	tr.do("", "volume", "unlock", "vault")
	tr.golden("volume_encrypted")

	if strings.Contains(tr.buf.String(), "marker-cli") {
		t.Fatal("a passphrase was printed")
	}
	sent := 0
	for _, r := range h.srv.Requests() {
		if strings.Contains(string(r.Body), "marker-cli") || strings.Contains(r.Path+r.Query, "marker-cli") {
			t.Fatalf("the fake recorded a passphrase: %s %s %s", r.Method, r.Path, r.Body)
		}
		if strings.Contains(string(r.Body), `"redacted"`) {
			sent++
		}
	}
	if sent < 6 {
		t.Fatalf("only %d requests carried a passphrase", sent)
	}
}
