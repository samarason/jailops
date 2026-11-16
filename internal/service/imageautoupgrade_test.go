package service_test

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

const autoPkgDryRun = `Installed packages to be UPGRADED:
	curl: 8.5.0 -> 8.6.0

Number of packages to be upgraded: 1
`

// pkgScript answers the package commands the automatic upgrade runs inside the running jails.
type pkgScript struct {
	mu     sync.Mutex
	cmds   []string
	failHC bool
}

func (p *pkgScript) fn(name string, o jailos.ExecOpts) (run.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	line := strings.Join(o.Argv, " ")
	p.cmds = append(p.cmds, name+": "+line)
	switch {
	case line == "/bin/true" && p.failHC:
		return run.Result{Stderr: []byte("not healthy")}, errors.New("exit status 1")
	}
	return run.Result{}, nil
}

// upgrades counts the `pkg -r ROOT upgrade -y` commands the host ran: a FreeBSD jail has no pkg of its own.
func upgrades(e *dtest.Env) int {
	n := 0
	for _, c := range e.Run.Calls() {
		if c.Cmd.Name == "pkg" && len(c.Cmd.Args) > 3 && c.Cmd.Args[0] == "-j" && c.Cmd.Args[2] == "upgrade" && c.Cmd.Args[3] == "-y" {
			n++
		}
	}
	return n
}

func TestAutoUpgradeBuildsMovesAndUpgradesPackages(t *testing.T) {
	e, s := tickingEnv(t)
	twoProjectJails(t, e, s)
	host := as(globalAdmin, "")
	ps := &pkgScript{}
	e.Jails.SetExecFn(ps.fn)
	e.SetPkgUpgrades(autoPkgDryRun)

	if _, err := s.PatchImage(host, "fb", map[string]any{"spec": map[string]any{"auto_upgrade": map[string]any{"enabled": true, "at": "03:00", "packages": true}}}, -1); err != nil {
		t.Fatal(err)
	}
	im, _ := s.GetImage(host, "fb")
	if au := im.Spec.AutoUpgrade; au == nil || !au.Enabled || au.At != "03:00" || !au.Packages {
		t.Fatalf("%+v", im.Spec)
	}
	if im.Status.AutoUpgrade == nil || im.Status.AutoUpgrade.Next.IsZero() || len(im.Status.AutoUpgrade.Recent) != 0 {
		t.Fatalf("status before a run: %+v", im.Status.AutoUpgrade)
	}
	if _, err := s.PatchImage(host, "fb", map[string]any{"spec": map[string]any{"auto_upgrade": map[string]any{"enabled": true, "at": "25:00"}}}, -1); err == nil {
		t.Fatal("a bad time of day was accepted")
	}

	// Nothing new: no generation, no jail moved, but the packages inside the running jail are still upgraded.
	run1 := s.AutoUpgradeImage(host, "fb")
	if run1.Result != api.ImageUpgradeRunOK || run1.Generation != "" || run1.JailsMoved != 0 || run1.JailsUpgraded != 1 || run1.Detail != "" {
		t.Fatalf("%+v\n%s", run1, e.Log())
	}
	// Only the packages the host names are upgraded: the base system (FreeBSD-*) moves with the image generation.
	for _, c := range e.Run.Calls() {
		if c.Cmd.Name == "pkg" && len(c.Cmd.Args) > 3 && c.Cmd.Args[2] == "upgrade" {
			if got := strings.Join(c.Cmd.Args[3:], " "); strings.Contains(got, "FreeBSD-") || !strings.HasSuffix(got, " curl") {
				t.Fatalf("pkg upgrade names %q", got)
			}
		}
	}
	if n := upgrades(e); n != 1 {
		t.Fatalf("pkg upgrade ran %d times (only the running jail, web)", n)
	}

	// A newer package set: g2, three thin jails move (the pin does not), the running jail's packages follow.
	e.SetRepoVersion("15.0p2")
	e.SetPkgUpgrades(autoPkgDryRun) // the repository has newer packages again
	run2 := s.AutoUpgradeImage(host, "fb")
	if run2.Result != api.ImageUpgradeRunOK || run2.Generation != "fb#g2" || run2.JailsMoved != 3 || run2.JailsUpgraded != 1 || run2.JailsFailed != 0 {
		t.Fatalf("%+v\n%s", run2, e.Log())
	}
	if gen, _ := generationOf(t, s, "alpha", "web"); gen != "fb#g2" {
		t.Fatalf("web is on %s", gen)
	}
	h, _ := s.UpdateHistory(as(globalAdmin, dtest.SeedProject), "web")
	var kinds []string
	for _, r := range h {
		if r.Scheduled {
			kinds = append(kinds, string(r.Kind))
		}
	}
	if strings.Join(kinds, ",") != "packages,os,packages" {
		t.Fatalf("web history %v", kinds)
	}

	im, _ = s.GetImage(host, "fb")
	if st := im.Status.AutoUpgrade; st == nil || len(st.Recent) != 2 || st.Recent[0].Generation != "fb#g2" || st.Recent[1].JailsMoved != 0 {
		t.Fatalf("status after two runs: %+v", st)
	}

	// A jail that fails its health check stops the run, and the run says which jail and why.
	e.SetRepoVersion("15.0p3")
	e.SetPkgUpgrades(autoPkgDryRun)
	ps.failHC = true
	run3 := s.AutoUpgradeImage(host, "fb")
	if run3.Result != api.ImageUpgradeRunFailed || run3.JailsFailed != 1 || !strings.Contains(run3.Detail, "alpha/db") || !strings.Contains(run3.Detail, "health check") {
		t.Fatalf("%+v\n%s", run3, e.Log())
	}
	if run3.JailsUpgraded != 0 {
		t.Fatalf("packages were upgraded after a failed move: %+v", run3)
	}
	im, _ = s.GetImage(host, "fb")
	if st := im.Status.AutoUpgrade; len(st.Recent) != 3 || st.Recent[0].Result != api.ImageUpgradeRunFailed {
		t.Fatalf("%+v", st)
	}
}

func TestAutoUpgradeLeavesManualJailsAndNeedsAGeneration(t *testing.T) {
	e, s := tickingEnv(t)
	twoProjectJails(t, e, s)
	host := as(globalAdmin, "")
	ps := &pkgScript{}
	e.Jails.SetExecFn(ps.fn)
	e.SetPkgUpgrades(autoPkgDryRun)
	// web chose to be updated by hand.
	if _, err := s.PatchJail(as(globalAdmin, dtest.SeedProject), "web", map[string]any{"spec": map[string]any{"update": map[string]any{"strategy": "manual"}}}, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PatchImage(host, "fb", map[string]any{"spec": map[string]any{"auto_upgrade": map[string]any{"enabled": true, "packages": true}}}, -1); err != nil {
		t.Fatal(err)
	}
	e.SetRepoVersion("15.0p2")
	r := s.AutoUpgradeImage(host, "fb")
	if r.Result != api.ImageUpgradeRunOK || r.JailsMoved != 2 || r.JailsUpgraded != 0 {
		t.Fatalf("%+v\n%s", r, e.Log())
	}
	if gen, _ := generationOf(t, s, "alpha", "web"); gen != "fb#g1" {
		t.Fatalf("a manual jail moved to %s", gen)
	}
	if upgrades(e) != 0 {
		t.Fatal("packages of a manual jail were upgraded")
	}

	// An image without a generation fails with the command that makes one.
	if _, err := s.CreateImage(host, api.Image{Metadata: api.ObjectMeta{Name: "empty"}, Spec: api.ImageSpec{
		OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"},
		AutoUpgrade: &api.ImageAutoUpgrade{Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	r = s.AutoUpgradeImage(host, "empty")
	if r.Result != api.ImageUpgradeRunFailed || !strings.Contains(r.Detail, "jailops image build empty") {
		t.Fatalf("%+v", r)
	}
}
