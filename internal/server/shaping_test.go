package server_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/render"
)

// The limits of a device are dummynet pipes, one for each direction: the jail's start configures them, and its anchor
// sends what the jail sends and what the jail receives into them, on the jail's own link.
func TestBandwidthLimitsAreEnforcedWithPipes(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	j := dtest.WebJail("web")
	j.Spec.Network[0].Egress = "5M"
	j.Spec.Network[0].Ingress = "8M"
	startJailIn(t, e.Admin, j)
	var cfg []string
	seen := map[string]bool{}
	for _, a := range e.Run.Argv() {
		// a pass of the reconcile loop that runs meanwhile configures the same pipes again (it is idempotent): once each
		if strings.HasPrefix(a, "dnctl pipe ") && strings.Contains(a, " config bw ") && !seen[a] {
			seen[a] = true
			cfg = append(cfg, a)
		}
	}
	if len(cfg) != 2 || !strings.HasSuffix(cfg[0], "bw 5000000bit/s") || !strings.HasSuffix(cfg[1], "bw 8000000bit/s") {
		t.Fatalf("the pipes are not 5 and 8 Mbit/s: %q", cfg)
	}
	e.D.Reconciler().Pass(c)
	anchor, err := e.PF.Read(c, render.JailAnchorFor("alpha", "web"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(anchor, "dnpipe") != 2 || !strings.Contains(anchor, "match in on ") || !strings.Contains(anchor, "match out on ") {
		t.Fatalf("the anchor does not send both directions into pipes:\n%s", anchor)
	}
	// a jail without a limit has no pipe and no dnpipe
	startJailIn(t, e.Admin, dtest.WebJail("plain"))
	e.D.Reconciler().Pass(c)
	plain, _ := e.PF.Read(c, render.JailAnchorFor("alpha", "plain"))
	if strings.Contains(plain, "dnpipe") {
		t.Fatalf("an unlimited jail has dnpipe:\n%s", plain)
	}
	// a rate that is not a rate is refused, in both directions
	for _, k := range []string{"nic.eth0.egress", "nic.eth0.ingress"} {
		if _, err := e.Admin.Jails().Config(c, "web", map[string]string{k: "fast"}, nil, false); err == nil {
			t.Fatalf("%s: a rate that is not a rate was accepted", k)
		}
	}
}
