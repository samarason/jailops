package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/fake"
)

// The host firewall: show, refuse while the module is off, then dry run, set, busy, confirm, apply from a file,
// revert and the pending state.
func TestHostFirewallCommands(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("host", "firewall", "show")
	if _, errs, code := tr.do("", "host", "firewall", "set", "--ssh-from", "192.0.2.0/24"); code != 6 || !strings.Contains(errs, "not_managed") {
		t.Fatalf("not managed: %d %s", code, errs)
	}
	tr.golden("host_firewall_not_managed")

	h = newHarness(t, fake.WithHostFirewall())
	h.seed()
	tr = h.transcript()
	tr.ok("host", "firewall", "show")
	tr.ok("--dry-run", "host", "firewall", "set", "--ssh-from", "192.0.2.0/24", "--ssh-from", "2001:db8:a::/48", "--confirm-within", "5m")
	if p, _, _ := h.run("", "host", "pending", "-o", "name"); p != "" {
		t.Fatalf("the dry run left a pending change: %q", p)
	}
	tr.do("", "host", "firewall", "set", "--ssh-port", "0")
	tr.do("", "host", "firewall", "allow", "add", "--proto", "tcp", "--port", "80")
	tr.do("", "host", "firewall", "allow", "add", "--proto", "tcp", "--comment", "web")
	tr.do("", "host", "firewall", "allow", "remove", "1")
	tr.do("", "host", "firewall", "address-set", "set", "admins", "--member", "192.0.2.0/24")
	tr.do("", "host", "firewall", "set", "--confirm-within", "5")
	tr.do("", "host", "firewall", "set", "--icmp", "sometimes")
	tr.ok("host", "firewall", "address-set", "create", "admins", "--member", "192.0.2.0/24", "--member", "2001:db8:a::/48", "--confirm-within", "90s")
	tr.ok("host", "confirm")
	tr.do("", "host", "firewall", "address-set", "create", "admins", "--member", "192.0.2.0/24")
	tr.ok("host", "firewall", "set", "--template", "custom-rules", "--ssh-from", "@admins", "--confirm-within", "90s")
	tr.ok("host", "confirm")
	tr.ok("host", "firewall", "allow", "add", "--proto", "tcp", "--port", "80,443", "--comment", "web", "--confirm-within", "90s")
	tr.ok("host", "confirm")
	tr.ok("host", "firewall", "allow", "add", "--proto", "udp", "--port", "51820", "--from", "2001:db8:1::/56", "--comment", "WireGuard", "--confirm-within", "90s")
	tr.ok("host", "firewall", "allow", "list")
	tr.ok("host", "pending")
	tr.do("", "host", "firewall", "set", "--icmp", "disable")
	tr.do("", "host", "confirm", "--id", "nothex")
	tr.ok("--dry-run", "host", "confirm")
	tr.ok("host", "confirm")
	tr.ok("host", "firewall", "show")
	tr.ok("host", "firewall", "diff")

	file := filepath.Join(h.dir, "fw.yaml")
	if err := os.WriteFile(file, []byte("kind: HostFirewall\nspec:\n  template: open\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr.ok("host", "firewall", "apply", "-f", file, "--confirm-within", "120")
	tr.ok("-y", "host", "revert")
	tr.ok("host", "pending")
	tr.do("", "host", "revert", "-y")
	if err := os.WriteFile(file, []byte("spec:\n  template: open\n  sshh: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr.do("", "host", "firewall", "apply", "-f", file)
	tr.golden("host_firewall")

	out, _, _ := h.run("", "__complete", "host", "firewall", "set", "--template", "")
	if !strings.Contains(out, "custom-rules") {
		t.Errorf("completion: %q", out)
	}
}
