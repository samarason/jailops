package lifecycle

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"jailops.net/jailops/internal/lifecycle/fault"
	"jailops.net/jailops/sdk/api"
)

func rollback(w *world, o RollbackOptions) (RollbackResult, error) {
	if o.Stamp == "" {
		o.Stamp = "300"
	}
	return w.S.RollbackJail(bg, "alpha_web", o, false)
}

func upgraded(t *testing.T) *world {
	w := runningSetup(t)
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); err != nil {
		t.Fatal(err)
	}
	return w
}

// TestAcceptanceDesign46 is the acceptance test of design section 4.6:
// upgrade, write new data, root rollback leaves the data intact, all rollback
// warns about data loss.
func TestAcceptanceDesign46(t *testing.T) {
	w := runningSetup(t)
	w.Z.WriteFile(jc+"/home", "/home/user/before", "old data")
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); err != nil {
		t.Fatal(err)
	}
	// new data written on the upgraded jail, after the pre-upgrade snapshot
	w.Z.WriteFile(jc+"/home", "/home/user/after-upgrade", "new data")
	w.Z.WriteFile(dbVol, "/db/rows", "rows written on g2")

	// root rollback is the default scope and never touches data
	homeBefore := w.Z.Dump()
	_ = homeBefore
	res, err := rollback(w, RollbackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scope != api.RollbackRoot || res.Upgrade == nil || res.Upgrade.To != "fb#g1" {
		t.Fatalf("%+v", res)
	}
	if o, _ := w.Z.Origin(bg, jc+"/root"); o != "tank/jailops/images/fb/g1@ro" {
		t.Fatalf("root origin %s", o)
	}
	if got := w.Z.PropOrEmpty(jc+"/root", PropGen); got != "1" {
		t.Fatal(got)
	}
	if !w.Jails.IsUp("alpha_web") {
		t.Fatal("jail not running after rollback")
	}
	for path, want := range map[string]string{"/home/user/before": "old data", "/home/user/after-upgrade": "new data"} {
		if got, _ := w.Z.ReadFile(jc+"/home", path); got != want {
			t.Fatalf("root rollback lost data: %s = %q", path, got)
		}
	}
	if got, _ := w.Z.ReadFile(dbVol, "/db/rows"); got != "rows written on g2" {
		t.Fatal("volume data lost")
	}

	// all rollback without confirmation is refused, with the numbers to show
	before := w.state()
	res, err = rollback(w, RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackAll, Snapshot: "jo-pre-upgrade-100"}, Force: true})
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Code != api.CodeDataLoss {
		t.Fatalf("want data_loss_unconfirmed, got %v", err)
	}
	if ae.Detail["written_bytes"] == "" || ae.Detail["written_bytes"] == "0" || !strings.Contains(ae.Detail["datasets"], jc+"/home=") {
		t.Fatalf("detail %v", ae.Detail)
	}
	if res.TotalWritten <= 0 || res.Written[jc+"/home"] != int64(len("new data")) {
		t.Fatalf("written %v", res.Written)
	}
	if w.state() != before {
		t.Fatal("a refused rollback changed the pool")
	}
	// data scope is refused the same way
	_, err = rollback(w, RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackData, Snapshot: "jo-pre-upgrade-100"}})
	wantCode(t, err, api.CodeDataLoss)
	// with confirmation (and force, because newer snapshots exist) data is discarded
	if _, err = rollback(w, RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackAll, Snapshot: "jo-pre-upgrade-100", ConfirmDataLoss: true}}); !api.IsCode(err, api.CodeConflict) {
		t.Fatalf("newer snapshots must refuse without force: %v", err)
	}
	if _, err = rollback(w, RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackAll, Snapshot: "jo-pre-upgrade-100", ConfirmDataLoss: true}, Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.Z.ReadFile(jc+"/home", "/home/user/after-upgrade"); ok {
		t.Fatal("all rollback kept data written after the snapshot")
	}
	if got, _ := w.Z.ReadFile(jc+"/home", "/home/user/before"); got != "old data" {
		t.Fatal("snapshot content lost")
	}
}

func TestRollbackRootErrors(t *testing.T) {
	w := runningSetup(t)
	_, err := rollback(w, RollbackOptions{})
	wantCode(t, err, api.CodeNotFound)
	w = upgraded(t)
	_, err = rollback(w, RollbackOptions{JailRollback: api.JailRollback{Snapshot: "x"}})
	wantCode(t, err, api.CodeInvalid)
	_, err = rollback(w, RollbackOptions{JailRollback: api.JailRollback{Scope: "weird"}})
	wantCode(t, err, api.CodeInvalid)
	_, err = rollback(w, RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackData}})
	wantCode(t, err, api.CodeInvalid)
	_, err = rollback(w, RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackData, Snapshot: "nope", ConfirmDataLoss: true}})
	wantCode(t, err, api.CodeNotFound)
}

func TestRollbackRootFailureSweep(t *testing.T) {
	sweep(t, upgraded, func(w *world) error { _, err := rollback(w, RollbackOptions{}); return err })
}

func TestRollbackRootKeepsDataAndEtcMergesBack(t *testing.T) {
	w := upgraded(t)
	w.Z.WriteFile(jc+"/etc", "/etc/rc.conf", "user edit")
	w.mergeOut = ""
	if _, err := rollback(w, RollbackOptions{}); err != nil {
		t.Fatal(err)
	}
	if c, _ := w.Z.ReadFile(jc+"/etc", "/etc/rc.conf"); c != "user edit" {
		t.Fatal("etc edit lost by root rollback")
	}
	// the downgrade merge compared against the older generation
	var tars, upd []string
	for _, c := range w.Exec.Commands() {
		if strings.HasPrefix(c, "tar -C") {
			tars = append(tars, c)
		}
		if strings.HasPrefix(c, "etcupdate") {
			upd = append(upd, c)
		}
	}
	// The last merge is the reverse one: g2 is the baseline, g1 the target.
	n := len(tars)
	if n < 2 || !strings.HasPrefix(tars[n-2], "tar -C /jailops/images/fb/g2 -cf") || !strings.HasPrefix(tars[n-1], "tar -C /jailops/projects/alpha/jails/web/root.new -cf") {
		t.Fatalf("%v", tars)
	}
	if m := len(upd); m < 2 || !strings.HasPrefix(upd[m-2], "etcupdate extract -d ") || !strings.Contains(upd[m-1], " -D /jailops/projects/alpha/jails/web/root -L ") {
		t.Fatalf("%v", upd)
	}
	// going back again is possible (prev_gen now points at g2)
	if got := w.Z.PropOrEmpty(jc+"/root", PropPrevGen); got != "2" {
		t.Fatal(got)
	}
}

func dataWorld(t *testing.T) *world {
	w := runningSetup(t)
	w.Z.WriteFile(jc+"/home", "/home/a", "v1")
	w.Z.WriteFile(dbVol, "/db/x", "v1")
	w.Z.WriteFile(jc+"/etc", "/etc/conf", "v1")
	if _, err := w.S.SnapshotJail(bg, "alpha_web", "s1", ""); err != nil {
		t.Fatal(err)
	}
	w.Z.WriteFile(jc+"/home", "/home/a", "version-two")
	w.Z.WriteFile(jc+"/home", "/home/new", "n")
	w.Z.WriteFile(dbVol, "/db/x", "v2")
	w.Z.WriteFile(jc+"/etc", "/etc/conf", "v2")
	return w
}

func TestRollbackDataScope(t *testing.T) {
	w := dataWorld(t)
	opts := RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackData, Snapshot: "s1"}}
	before := w.state()
	res, err := rollback(w, opts)
	wantCode(t, err, api.CodeDataLoss)
	wantW := int64(len("version-two") + len("n")) // a volume is not part of a jail
	if res.TotalWritten != wantW || w.state() != before {
		t.Fatalf("written %d want %d", res.TotalWritten, wantW)
	}
	opts.ConfirmDataLoss = true
	res, err = rollback(w, opts)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := w.Z.ReadFile(jc+"/home", "/home/a"); v != "v1" {
		t.Fatal(v)
	}
	if _, ok := w.Z.ReadFile(jc+"/home", "/home/new"); ok {
		t.Fatal("new file survived")
	}
	if v, _ := w.Z.ReadFile(dbVol, "/db/x"); v != "v2" {
		t.Fatalf("a data rollback of the jail must not touch its volume, got %q", v)
	}
	if v, _ := w.Z.ReadFile(jc+"/etc", "/etc/conf"); v != "v2" {
		t.Fatalf("data scope must not touch /etc, got %q", v)
	}
	if got := w.Z.PropOrEmpty(jc+"/root", PropGen); got != "1" || !w.Jails.IsUp("alpha_web") {
		t.Fatal("root changed or jail not restarted")
	}
}

func TestRollbackRefusesWhenLaterSnapshotsExist(t *testing.T) {
	w := dataWorld(t)
	w.S.SnapshotJail(bg, "alpha_web", "s2", "")
	opts := RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackData, Snapshot: "s1", ConfirmDataLoss: true}}
	before := w.state()
	_, err := rollback(w, opts)
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Code != api.CodeConflict || !strings.Contains(ae.Detail["later_snapshots"], jc+"/home@s2") {
		t.Fatal(err)
	}
	if w.state() != before {
		t.Fatal("refusal changed state")
	}
	opts.Force = true
	if _, err := rollback(w, opts); err != nil {
		t.Fatal(err)
	}
	if ok, _ := w.Z.Exists(bg, jc+"/home@s2"); ok {
		t.Fatal("later snapshot should be destroyed by force")
	}
	if ok, _ := w.Z.Exists(bg, jc+"/home@s1"); !ok {
		t.Fatal("target snapshot must stay")
	}
}

func TestRollbackSkipsDatasetsWithoutSnapshotOnlyWithForce(t *testing.T) {
	w := dataWorld(t)
	w.Z.Create(bg, jc+"/cache", map[string]string{PropManaged: "on", PropKind: KindPersistent, PropClass: "data", PropPath: "/srv/cache"})
	opts := RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackData, Snapshot: "s1", ConfirmDataLoss: true}}
	_, err := rollback(w, opts)
	wantCode(t, err, api.CodeConflict)
	opts.Force = true
	res, err := rollback(w, opts)
	if err != nil || len(res.Skipped) != 1 || res.Skipped[0] != jc+"/cache" {
		t.Fatal(res.Skipped, err)
	}
}

func TestRollbackAllWithGenerationChange(t *testing.T) {
	w := runningSetup(t)
	w.Z.WriteFile(jc+"/home", "/home/a", "v1")
	w.S.SnapshotJail(bg, "alpha_web", "s1", "")
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); err != nil {
		t.Fatal(err)
	}
	w.Z.WriteFile(jc+"/home", "/home/a", "v2")
	opts := RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackAll, Snapshot: "s1", ConfirmDataLoss: true}, Force: true}
	w.started = nil
	if _, err := rollback(w, opts); err != nil {
		t.Fatal(err)
	}
	if got := w.Z.PropOrEmpty(jc+"/root", PropGen); got != "1" {
		t.Fatal("root not on g1:", got)
	}
	if o, _ := w.Z.Origin(bg, jc+"/root"); o != "tank/jailops/images/fb/g1@ro" {
		t.Fatal(o)
	}
	if v, _ := w.Z.ReadFile(jc+"/home", "/home/a"); v != "v1" {
		t.Fatal(v)
	}
	if _, ok := w.Z.ReadFile(jc+"/etc", "/etc/merged"); ok {
		t.Fatal("etc not rolled back with the root")
	}
	if !w.Jails.IsUp("alpha_web") || strings.Join(w.started, ",") != "1" {
		t.Fatal(w.started)
	}
	b, _ := w.Files.ReadFile(bg, "/jailops/projects/alpha/jails/web/bundle.json")
	if !strings.Contains(string(b), `"name": "fb#g1"`) {
		t.Fatal("bundle not updated")
	}
}

func TestRollbackDataFailureIsRetryable(t *testing.T) {
	w := dataWorld(t)
	w.F.Reset(0)
	opts := RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackData, Snapshot: "s1", ConfirmDataLoss: true}}
	if _, err := rollback(w, opts); err != nil {
		t.Fatal(err)
	}
	n := w.F.Count()
	for k := 1; k <= n; k++ {
		w := dataWorld(t)
		w.F.Reset(k)
		_, err := rollback(w, opts)
		if err == nil {
			continue
		}
		if !errors.Is(err, fault.ErrInjected) {
			t.Fatal(err)
		}
		if ok, _ := w.Z.Exists(bg, jc+"/home@s1"); !ok {
			t.Fatalf("op %d lost the snapshot", k)
		}
		if v, _ := w.Z.ReadFile(jc+"/etc", "/etc/conf"); v != "v2" {
			t.Fatalf("op %d: /etc touched by a data rollback", k)
		}
		w.F.Reset(0)
		if _, err := rollback(w, opts); err != nil {
			t.Fatalf("retry after failure %d (%s): %v", k, w.F.Log, err)
		}
		if v, _ := w.Z.ReadFile(jc+"/home", "/home/a"); v != "v1" {
			t.Fatalf("op %d: retry did not complete", k)
		}
		// a failed data rollback leaves the jail stopped (never half-restored
		// data under a running jail); starting it again is the caller's call
		if !w.Jails.IsUp("alpha_web") {
			if err := w.S.StartJail(bg, "alpha_web"); err != nil {
				t.Fatalf("op %d: jail does not start after retry: %v", k, err)
			}
		}
	}
}

func TestRollbackDryRun(t *testing.T) {
	w := dataWorld(t)
	before := w.state()
	w.F.Reset(0)
	res, err := w.S.RollbackJail(bg, "alpha_web", RollbackOptions{JailRollback: api.JailRollback{Scope: api.RollbackData, Snapshot: "s1", ConfirmDataLoss: true}}, true)
	if err != nil || len(res.Plan) == 0 || w.F.Count() != 0 || w.state() != before {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Plan, "\n"), "zfs rollback -r "+jc+"/home@s1") {
		t.Fatal(res.Plan)
	}
	_ = strconv.Itoa
}

func TestRollbackCrashRecoveryRoot(t *testing.T) {
	setup := upgraded
	w := setup(t)
	req := RollbackOptions{Stamp: "300"}
	_, ur, err := w.S.PlanUpgrade(bg, "alpha_web", UpgradeRequest{JailUpgrade: api.JailUpgrade{Generation: "g1"}, Stamp: "300"})
	if err != nil {
		t.Fatal(err)
	}
	_ = req
	steps := 0
	if p, _, _ := w.S.PlanUpgrade(bg, "alpha_web", UpgradeRequest{JailUpgrade: api.JailUpgrade{Generation: "g1"}, Stamp: "300"}); p != nil {
		steps = len(p.Steps)
	}
	for k := 1; k <= steps; k++ {
		w := setup(t)
		before := w.state()
		p, res, err := w.S.PlanUpgrade(bg, "alpha_web", UpgradeRequest{JailUpgrade: api.JailUpgrade{Generation: "g1"}, Stamp: "300"})
		if err != nil {
			t.Fatal(err)
		}
		crash(t, w, "rollback/alpha_web", p, k)
		rp, _, err := w.S.PlanUpgrade(bg, "alpha_web", UpgradeRequest{JailUpgrade: api.JailUpgrade{Generation: "g1"}, Stamp: "300", Resume: &res.State})
		if err != nil {
			t.Fatal(err)
		}
		if found, err := w.S.RecoverRun(bg, "rollback", "alpha_web", rp); !found || err != nil {
			t.Fatal(found, err)
		}
		if w.state() != before {
			t.Fatalf("crash after step %d (%s) not rolled back", k, p.Steps[k-1].Name)
		}
	}
	_ = ur
}
