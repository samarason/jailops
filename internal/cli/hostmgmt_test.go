package cli_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/sdk/fake"
)

// This host's identity: show it, refuse changes while the module is off, then apply, dry-run, list and restore.
func TestHostIdentityCommands(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("host", "show")
	if _, errs, code := tr.do("", "host", "identity", "set", "--hostname", "web1.example.org"); code != 6 || !strings.Contains(errs, "not_managed") {
		t.Fatalf("not managed: %d %s", code, errs)
	}
	tr.golden("host_not_managed")

	h = newHarness(t, fake.WithHostManaged())
	h.seed()
	tr = h.transcript()
	tr.ok("host", "show")
	tr.ok("--dry-run", "host", "identity", "set", "--hostname", "web1.example.org", "--nameserver", "192.0.2.53", "--nameserver", "2001:db8::53")
	if snaps, _, _ := h.run("", "host", "snapshots", "-o", "name"); snaps != "" {
		t.Fatalf("the dry run took a snapshot: %q", snaps)
	}
	tr.ok("host", "identity", "set", "--hostname", "web1.example.org", "--nameserver", "192.0.2.53", "--search", "example.org")
	tr.ok("host", "identity", "set", "--ntp-server", "192.0.2.123", "--ntp", "enable")
	tr.ok("host", "identity", "set", "--hostname", "web1.example.org")
	tr.do("", "host", "identity", "set", "--nameserver", "192.0.2.300")
	tr.do("", "host", "identity", "set", "--ntp", "sometimes")
	tr.do("", "host", "identity", "set")
	tr.ok("host", "snapshots")
	tr.ok("host", "show", "-o", "json")
	tr.ok("host", "restore", "--dry-run")
	tr.ok("-y", "host", "restore")
	tr.do("", "-y", "host", "restore", "../etc")
	tr.ok("host", "show")
	tr.golden("host_identity")

	// the snapshot names complete, with latest first
	out, _, _ := h.run("", "__complete", "host", "restore", "")
	if !strings.HasPrefix(out, "latest\n") || strings.Count(out, "T") < 2 {
		t.Errorf("completion: %q", out)
	}
}
