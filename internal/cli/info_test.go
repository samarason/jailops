package cli_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

// What the server could not measure is said, never shown as a zero: racct
// off, a dataset that cannot be read, and a server without the usage route.
func TestJailInfoUsageUnavailable(t *testing.T) {
	h := newHarness(t)
	h.seedDualStack()
	h.srv.SeedJailUsage("main", "web", api.JailUsage{
		Accounting: &api.JailAccounting{Error: "racct is off: set kern.racct.enable=1 in /boot/loader.conf and reboot"},
		Disk:       api.JailDiskUsage{Error: "cannot open 'tank/jailops/projects/main/jails/web': dataset does not exist"},
	})
	h.srv.SeedJailUsage("main", "db", api.JailUsage{Disk: api.JailDiskUsage{RootBytes: 1536, RootReferencedBytes: 1536}})
	tr := h.transcript()
	tr.ok("jail", "info", "web")
	tr.ok("jail", "info", "db", "-o", "json")
	tr.golden("jail_info_usage")

	old := newHarness(t, fake.WithExtensions("operations", "etag", "events", "jails", "jail_snapshots", "profiles", "updates", "volumes"))
	old.seedDualStack()
	out, errs, code := old.run("", "jail", "info", "web")
	if code != 0 || errs != "" {
		t.Fatalf("%d %s", code, errs)
	}
	if !strings.Contains(out, "  Usage:        not available: ") || !strings.Contains(out, `server does not support "jail_usage"`) || strings.Contains(out, "  Disk:") {
		t.Fatalf("an old server:\n%s", out)
	}
}
