package cli_test

import (
	"os"
	"path/filepath"
	"testing"
)

// 'jailops boot' lists the jails a boot starts in order and those it does not start, and 'list' has the AUTOSTART column.
func TestBootPlan(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("boot") // nothing starts at boot yet
	create := func(name string, extra ...string) {
		args := append([]string{"create", name, "--image", "freebsd-15@stable", "--storage", "default", "--network", "lan"}, extra...)
		tr.ok(args...)
	}
	create("db")
	create("web", "--autostart", "--depends", "db", "--boot-priority", "2")
	create("cache", "--autostart")
	create("ghost-user", "--autostart", "--depends", "db")
	// an encrypted volume waits for its passphrase after a boot, and so does what depends on it
	file := filepath.Join(h.dir, "vault.pass")
	if err := os.WriteFile(file, []byte("a long enough passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr.ok("volume", "create", "secrets", "--encrypted", "--passphrase-file", file)
	create("vault", "--autostart")
	tr.ok("volume", "attach", "vault", "secrets", "/srv/db")
	create("report", "--autostart", "--depends", "vault")
	tr.ok("boot")
	tr.ok("boot", "-o", "json")
	tr.ok("boot", "-o", "name")
	tr.do("", "boot", "-o", "csv")
	tr.ok("list", "-c", "name,state,autostart")
	tr.ok("boot", "--project", "main")
	tr.golden("boot")
}
