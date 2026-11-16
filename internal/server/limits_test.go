package server_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// seededWith is seeded on a host whose jails.max_states is n.
func seededWith(t *testing.T, n int) *dtest.Env {
	t.Helper()
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) { c.Jails.MaxStates = &n }})
	e.Seed()
	return e
}

// A changed disk limit reaches the jail's container dataset, which carries the quota of everything below it, and an
// unset one is "none". The root clone carries none.
func TestDiskLimitFollowsAChange(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	j := dtest.WebJail("web")
	j.Spec.Resources.Disk = "10G"
	op, err := e.Admin.Jails().Create(c, j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	container := "tank/jailops/projects/alpha/jails/web"
	quota := func(ds string) string {
		p, err := e.ZFS.Get(c, ds, "quota")
		if err != nil {
			t.Fatal(err)
		}
		return p["quota"].Value
	}
	if q := quota(container); q != "10G" && q != "10737418240" {
		t.Fatalf("container quota %q", q)
	}
	if q := quota(container + "/root"); q != "" && q != "none" && q != "0" && q != "-" {
		t.Fatalf("the root clone has a quota: %q", q)
	}
	cur, etag, err := e.Admin.Jails().GetETag(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	cur.Spec.Resources.Disk = "20000000000"
	cur.Spec.Resources.DiskReservation = "1000000000"
	if _, err := e.Admin.Jails().Update(c, "web", cur, etag); err != nil {
		t.Fatal(err)
	}
	if q := quota(container); q != "20000000000" {
		t.Fatalf("container quota after the change: %q", q)
	}
	p, _ := e.ZFS.Get(c, container, "reservation")
	if p["reservation"].Value != "1000000000" {
		t.Fatalf("container reservation after the change: %q", p["reservation"].Value)
	}
	cur, etag, _ = e.Admin.Jails().GetETag(c, "web")
	cur.Spec.Resources.Disk = ""
	if _, err := e.Admin.Jails().Update(c, "web", cur, etag); err != nil {
		t.Fatal(err)
	}
	if q := quota(container); q != "none" && q != "" && q != "0" && q != "-" {
		t.Fatalf("container quota after the limit was removed: %q", q)
	}
}

// A running jail with memory, process or CPU limits on a host where kern.racct.enable is 0 says that nothing enforces
// them, and a jail without limits does not.
func TestLimitsNotEnforcedWithoutRacct(t *testing.T) {
	for _, tc := range []struct {
		name  string
		racct string
		res   api.Resources
		warn  bool
	}{
		{"racct off, limits", "0", api.Resources{Memory: "1G", PIDs: 100}, true},
		{"racct on, limits", "1", api.Resources{Memory: "1G", PIDs: 100}, false},
		{"racct off, no limits", "0", api.Resources{Disk: "10G"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := seeded(t)
			e.SetSysctl("kern.racct.enable", tc.racct)
			c := ctxT(t)
			j := dtest.WebJail("web")
			j.Spec.Resources = tc.res
			startJailIn(t, e.Admin, j)
			got, err := e.Admin.Jails().Get(c, "web")
			if err != nil {
				t.Fatal(err)
			}
			warned := false
			for _, w := range got.Status.Warnings {
				warned = warned || strings.Contains(w, "kern.racct.enable")
			}
			cond := false
			for _, cd := range got.Status.Conditions {
				cond = cond || (cd.Type == "Limits" && cd.Status == api.ConditionFalse && cd.Reason == "NotEnforced")
			}
			if warned != tc.warn || cond != tc.warn {
				t.Fatalf("warning %v condition %v, want %v: %+v", warned, cond, tc.warn, got.Status)
			}
		})
	}
}

// The state limit of a jail is its limits.states, or the host's jails.max_states when that is 0, and it reaches the
// pf rules of the jail's anchor.
func TestStateLimitReachesTheAnchor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		states int
		hostly int
		want   string
	}{
		{"jail limit", 777, 10000, "keep state (max 777, if-bound)"},
		{"host default", 0, 4242, "keep state (max 4242, if-bound)"},
		{"no limit anywhere", 0, 0, "keep state (if-bound)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := seededWith(t, tc.hostly)
			j := dtest.WebJail("web")
			j.Spec.Resources.States = tc.states
			startJailIn(t, e.Admin, j)
			anchor := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_web.conf")
			if anchor == "" {
				t.Fatal("the jail has no rendered anchor")
			}
			if tc.hostly == 0 && tc.states == 0 && strings.Contains(anchor, "keep state (max") {
				t.Fatalf("a state limit where there is none:\n%s", anchor)
			}
			if !strings.Contains(anchor, tc.want) {
				t.Fatalf("no %q in the anchor:\n%s", tc.want, anchor)
			}
		})
	}
}
