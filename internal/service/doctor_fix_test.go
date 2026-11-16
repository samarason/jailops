package service_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/mounts"
	"jailops.net/jailops/sdk/api"
)

// Mounts that a stop which did not finish left below the root of a stopped jail are reported by doctor
// (mounts.leftovers, which says to run doctor --fix), listed by --fix --dry-run without touching anything, taken off by
// --fix, and taken off by the daemon's own heal.
func TestDoctorFixTakesStaleMountsOffTheRootOfAStoppedJail(t *testing.T) {
	mountActions := func(r api.DoctorFixResult) (out []api.DoctorFixAction) {
		for _, a := range r.Actions {
			if a.Check == "mounts.leftovers" {
				out = append(out, a)
			}
		}
		return
	}
	e, s := tickingEnv(t)
	e.Files.Stale = []mounts.Stale{
		{Jail: "alpha_web", Path: "/jailops/projects/alpha/jails/web/root/dev", Type: "devfs"},
		{Jail: "alpha_web", Path: "/jailops/projects/alpha/jails/web/root/dev", Type: "devfs"},
	}
	ctx := as(globalAdmin, "")

	var check api.DoctorCheck
	for _, c := range s.Doctor(ctx).Checks {
		if c.Name == "mounts.leftovers" {
			check = c
		}
	}
	if check.Status != api.DoctorWarn || !strings.Contains(check.Message, "alpha_web") || !strings.Contains(check.Hint, "jailops doctor --fix") {
		t.Fatalf("doctor says %+v", check)
	}

	dry, err := s.DoctorFix(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if a := mountActions(dry); len(a) != 1 || a[0].Done || !strings.Contains(a[0].What, "alpha_web") {
		t.Fatalf("dry run %+v", dry)
	}
	if len(e.Files.Stale) != 2 {
		t.Fatal("the dry run took a mount off")
	}

	res, err := s.DoctorFix(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if a := mountActions(res); len(a) != 1 || !a[0].Done || a[0].Error != "" {
		t.Fatalf("fix %+v", res)
	}
	if len(e.Files.Stale) != 0 {
		t.Fatalf("mounts left: %v", e.Files.Stale)
	}
	again, err := s.DoctorFix(ctx, false) // idempotent
	if err != nil || len(mountActions(again)) != 0 {
		t.Fatalf("a second run: %+v %v", again, err)
	}

	// the daemon's own heal does the same without being asked
	e.Files.Stale = []mounts.Stale{{Jail: "alpha_web", Path: "/jailops/projects/alpha/jails/web/root/mnt", Type: "nullfs"}}
	if n := s.HealLeftovers(ctx); n != 1 || len(e.Files.Stale) != 0 {
		t.Errorf("the heal took off %d, %d left", n, len(e.Files.Stale))
	}
}
