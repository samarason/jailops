package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

const jc = "tank/jailops/projects/alpha/jails/web"

func runningSetup(t *testing.T) *world { w := newWorld(t); w.running("web"); return w }

func upgrade(w *world, req api.JailUpgrade) (UpgradeResult, error) {
	return w.S.UpgradeJail(bg, "alpha_web", UpgradeRequest{JailUpgrade: req, Stamp: "100"})
}

func TestUpgradeHappyPath(t *testing.T) {
	w := runningSetup(t)
	w.Z.WriteFile(jc+"/home", "/home/user/notes", "keep me")
	w.Z.WriteFile(dbVol, "/db/rows", "rows")
	w.started = nil
	res, err := upgrade(w, api.JailUpgrade{Generation: "g2"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.From != "fb#g1" || res.To != "fb#g2" || res.Snapshot != "jo-pre-upgrade-100" {
		t.Fatalf("%+v", res)
	}
	if o, _ := w.Z.Origin(bg, jc+"/root"); o != "tank/jailops/images/fb/g2@ro" {
		t.Fatal(o)
	}
	if o, _ := w.Z.Origin(bg, jc+"/root.old"); o != "tank/jailops/images/fb/g1@ro" {
		t.Fatal(o)
	}
	if got := w.Z.PropOrEmpty(jc+"/root", PropGen); got != "2" {
		t.Fatal(got)
	}
	if got := w.Z.PropOrEmpty(jc+"/root", PropPrevGen); got != "1" {
		t.Fatal(got)
	}
	if got := w.Z.PropOrEmpty(jc+"/root", "mountpoint"); got != "/jailops/projects/alpha/jails/web/root" {
		t.Fatal(got)
	}
	if got := w.Z.PropOrEmpty(jc+"/root.old", PropCleanupAfter); got != "2026-05-02T12:00:00Z" {
		t.Fatal(got)
	}
	if !w.Jails.IsUp("alpha_web") || len(w.started) != 1 || w.started[0] != "2" {
		t.Fatalf("started on %v", w.started)
	}
	// data survived
	if c, _ := w.Z.ReadFile(jc+"/home", "/home/user/notes"); c != "keep me" {
		t.Fatal(c)
	}
	// the merge ran against the persistent etc with the new root
	if c, _ := w.Z.ReadFile(jc+"/etc", "/etc/merged"); c != "from /jailops/projects/alpha/jails/web/.merge-100/new-etc.tar" {
		t.Fatal(c)
	}
	// pre-upgrade snapshot exists on every dataset, taken in one transaction
	for _, d := range []string{jc, jc + "/etc", jc + "/home", jc + "/root.old"} {
		if ok, _ := w.Z.Exists(bg, d+"@jo-pre-upgrade-100"); !ok {
			t.Errorf("no pre-upgrade snapshot on %s", d)
		}
	}
	// the volume the jail attaches is the project's: no jail snapshot is taken of it
	if ok, _ := w.Z.Exists(bg, dbVol+"@jo-pre-upgrade-100"); ok {
		t.Error("a jail snapshot reached a volume")
	}
	// merge snapshots are gone, bundle records the new generation
	if ok, _ := w.Z.Exists(bg, jc+"/etc@jo-merge-100"); ok {
		t.Fatal("merge snapshot left")
	}
	b, _ := w.Files.ReadFile(bg, "/jailops/projects/alpha/jails/web/bundle.json")
	if !strings.Contains(string(b), `"name": "fb#g2"`) {
		t.Fatal(string(b))
	}
	if len(res.Warnings) != 0 {
		t.Fatal(res.Warnings)
	}
	// upgrading to the generation the jail already uses is a no-op
	w.Images.aliases["fb@stable"] = 2
	r2, err := upgrade(w, api.JailUpgrade{})
	if err != nil || r2.Changed {
		t.Fatal(r2, err)
	}
}

func TestUpgradeFailureSweep(t *testing.T) {
	n := sweep(t, runningSetup, func(w *world) error { _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); return err })
	t.Logf("%d injected failures, each left the jail on g1, running, with the pool unchanged", n)
}

func TestUpgradeFailureSweepStoppedJail(t *testing.T) {
	setup := func(t *testing.T) *world { w := newWorld(t); w.created("web"); return w }
	sweep(t, setup, func(w *world) error { _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); return err })
}

func TestUpgradeStoppedJailStaysStopped(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	res, err := upgrade(w, api.JailUpgrade{Generation: "g2"})
	if err != nil || !res.Changed {
		t.Fatal(res, err)
	}
	if w.Jails.IsUp("alpha_web") {
		t.Fatal("a stopped jail must stay stopped")
	}
	if got := w.Z.PropOrEmpty(jc+"/root", PropGen); got != "2" {
		t.Fatal(got)
	}
	if mounted, _ := w.Z.Mounted(bg, jc+"/root"); mounted {
		t.Fatal("tree left mounted")
	}
}

func TestUpgradeMergeConflictLeavesJailOnOldGeneration(t *testing.T) {
	w := runningSetup(t)
	w.mergeOut = "M /etc/motd\nC /etc/rc.conf\nC /etc/ssh/sshd_config\n"
	w.mergeErr = errors.New("exit status 1")
	before := w.state()
	_, err := upgrade(w, api.JailUpgrade{Generation: "g2"})
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Code != api.CodeConflict {
		t.Fatalf("want conflict error, got %v", err)
	}
	if ae.Detail["files"] != "/etc/rc.conf,/etc/ssh/sshd_config" || ae.Detail["reason"] != "etc_merge_conflict" {
		t.Fatalf("detail %v", ae.Detail)
	}
	if w.state() != before {
		t.Fatalf("conflict left the pool changed:\n%s", w.state())
	}
	if !w.Jails.IsUp("alpha_web") || w.Z.PropOrEmpty(jc+"/root", PropGen) != "1" {
		t.Fatal("jail is not running on the old generation")
	}
	if c, ok := w.Z.ReadFile(jc+"/etc", "/etc/merged"); ok {
		t.Fatalf("partial merge survived: %q", c)
	}
	// a clean merge that still prints conflicts is also a conflict (never guessed)
	w.mergeErr = nil
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); !api.IsCode(err, api.CodeConflict) {
		t.Fatal(err)
	}
	// a plain merge failure is not reported as a conflict
	w.mergeOut, w.mergeErr = "disk full", errors.New("exit status 2")
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); err == nil || api.IsCode(err, api.CodeConflict) {
		t.Fatal(err)
	}
}

func TestUpgradeHealthCheckFailureSwapsBack(t *testing.T) {
	w := runningSetup(t)
	w.Z.WriteFile(jc+"/home", "/home/f", "x")
	before := w.state()
	w.Jails.ExecFn = func(name string, argv []string) ([]byte, error) {
		return []byte("connection refused"), errors.New("exit 1")
	}
	w.started = nil
	_, err := upgrade(w, api.JailUpgrade{Generation: "g2"})
	if err == nil || !strings.Contains(err.Error(), "health check") {
		t.Fatal(err)
	}
	if w.state() != before {
		t.Fatalf("not swapped back:\n%s", w.state())
	}
	// started on the new root once, then the old one again
	if strings.Join(w.started, ",") != "2,1" {
		t.Fatalf("starts %v", w.started)
	}
}

// A failed upgrade swaps the root back, and the data the jail wrote while it ran on the new generation stays: a rollback
// of /var/db to the snapshot taken before the start would drop the databases' last writes, while /home keeps its own.
func TestUpgradeFailureAfterTheStartKeepsWhatTheJailWroteToData(t *testing.T) {
	w := runningSetup(t)
	w.Z.WriteFile(jc+"/var-db", "/before", "x")
	w.Jails.ExecFn = func(name string, argv []string) ([]byte, error) {
		w.Z.WriteFile(jc+"/var-db", "/during", "written while the jail ran on the new generation")
		w.Z.WriteFile(jc+"/home", "/during", "also")
		return []byte("connection refused"), errors.New("exit 1")
	}
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); err == nil || !strings.Contains(err.Error(), "health check") {
		t.Fatal(err)
	}
	for _, ds := range []string{"var-db", "home"} {
		if !strings.Contains(w.Z.Dump(), jc+"/"+ds) {
			t.Fatalf("no dataset %s in this setup", ds)
		}
	}
	if got, _ := w.Z.ReadFile(jc+"/var-db", "/during"); got == "" {
		t.Fatal("what the jail wrote to /var/db was rolled back")
	}
	if got, _ := w.Z.ReadFile(jc+"/home", "/during"); got == "" {
		t.Fatal("what the jail wrote to /home was rolled back")
	}
	if got, _ := w.Z.ReadFile(jc+"/var-db", "/before"); got == "" {
		t.Fatal("/var/db lost what it had before")
	}
}

func TestUpgradeJailDiesAfterStart(t *testing.T) {
	w := runningSetup(t)
	before := w.state()
	w.Jails.Never = true // jail start "succeeds" but the jail is not running
	w.Jails.Never = false
	w.Jails.OnStart = func(name string) error {
		if w.Z.PropOrEmpty(jc+"/root", PropGen) == "2" {
			return errors.New("jail: exec.start failed")
		}
		return nil
	}
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); err == nil {
		t.Fatal("start failure accepted")
	}
	if w.state() != before {
		t.Fatal("not restored")
	}
}

func TestUpgradePreflight(t *testing.T) {
	tests := []struct {
		name string
		mut  func(w *world)
		req  api.JailUpgrade
		code api.Code
	}{
		{"snapshot with clones", func(w *world) {
			w.S.SnapshotJail(bg, "alpha_web", "s", "")
			w.Z.Clone(bg, jc+"/root@s", "tank/jailops/projects/alpha/jails/dev", nil)
		}, api.JailUpgrade{Generation: "g2"}, api.CodeBusy},
		{"replication running", func(w *world) {
			w.S.Cfg.Replicating = func(context.Context, string) (bool, error) { return true, nil }
		}, api.JailUpgrade{Generation: "g2"}, api.CodeBusy},
		{"image newer than host kernel", func(w *world) { w.Jails.Release = "14.2-RELEASE" }, api.JailUpgrade{Generation: "g2"}, api.CodeVersionSkew},
		{"leftover root.new", func(w *world) { w.Z.Create(bg, jc+"/root.new", nil) }, api.JailUpgrade{Generation: "g2"}, api.CodeBusy},
		{"other image", func(w *world) {}, api.JailUpgrade{Generation: "alp#g1"}, api.CodeInvalid},
		{"bad generation", func(w *world) {}, api.JailUpgrade{Generation: "latest-ish"}, api.CodeInvalid},
		{"missing generation", func(w *world) {}, api.JailUpgrade{Generation: "g9"}, api.CodeNotFound},
		{"inplace strategy", func(w *world) {
			r, _ := w.S.readRecord(bg, "alpha_web")
			r.Spec.Update.Strategy = api.UpdateInPlace
			w.Files.Data["/jailops/projects/alpha/jails/web/spec.json"] = marshal(r)
		}, api.JailUpgrade{Generation: "g2"}, api.CodeUnsupported},
		{"thick jail", func(w *world) { w.Z.Set(bg, jc, map[string]string{PropLayout: "thick"}) }, api.JailUpgrade{Generation: "g2"}, api.CodeUnsupported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := runningSetup(t)
			tc.mut(w)
			before := w.state()
			w.F.Reset(0)
			_, err := upgrade(w, tc.req)
			wantCode(t, err, tc.code)
			if w.state() != before || w.F.Count() != 0 {
				t.Fatal("preflight failure must not change anything")
			}
		})
	}
}

func TestUpgradeResolvesAliasAndDryRun(t *testing.T) {
	w := runningSetup(t)
	w.Images.aliases["fb@stable"] = 2 // alias moved; jail spec follows it
	before := w.state()
	w.F.Reset(0)
	res, err := upgrade(w, api.JailUpgrade{DryRun: true})
	if err != nil || !res.Changed || res.To != "fb#g2" || w.state() != before || w.F.Count() != 0 {
		t.Fatal(res, err)
	}
	p, _, err := w.S.PlanUpgrade(bg, "alpha_web", UpgradeRequest{Stamp: "100"})
	if err != nil {
		t.Fatal(err)
	}
	d := strings.Join(p.Describe(), "\n")
	for _, want := range []string{"zfs snapshot " + jc + "@jo-pre-upgrade-100 " + jc + "/root@jo-pre-upgrade-100", "(one atomic transaction)",
		"zfs clone tank/jailops/images/fb/g2@ro " + jc + "/root.new", "tar the /etc of fb#g1 and fb#g2; etcupdate extract",
		"zfs rename " + jc + "/root " + jc + "/root.old", "zfs rename " + jc + "/root.new " + jc + "/root"} {
		if !strings.Contains(d, want) {
			t.Errorf("plan lacks %q\n%s", want, d)
		}
	}
	if r, err := upgrade(w, api.JailUpgrade{}); err != nil || !r.Changed || w.Z.PropOrEmpty(jc+"/root", PropGen) != "2" {
		t.Fatal(r, err)
	}
}

func TestUpgradeCrashRecovery(t *testing.T) {
	p0 := func() int {
		w := runningSetup(t)
		p, _, err := w.S.PlanUpgrade(bg, "alpha_web", UpgradeRequest{UpgradeRequestJSON(), "100", nil})
		if err != nil {
			t.Fatal(err)
		}
		return len(p.Steps)
	}()
	for k := 1; k <= p0; k++ {
		w := runningSetup(t)
		before := w.state()
		req := UpgradeRequest{JailUpgrade: api.JailUpgrade{Generation: "g2"}, Stamp: "100"}
		p, res, err := w.S.PlanUpgrade(bg, "alpha_web", req)
		if err != nil {
			t.Fatal(err)
		}
		crash(t, w, "upgrade/alpha_web", p, k)
		// the daemon restarts: the pool shows a half-done upgrade; the plan is
		// rebuilt from the persisted request and state
		req.Resume = &res.State
		rp, _, err := w.S.PlanUpgrade(bg, "alpha_web", req)
		if err != nil {
			t.Fatal(err)
		}
		if found, err := w.S.RecoverRun(bg, "upgrade", "alpha_web", rp); !found || err != nil {
			t.Fatalf("recover after %d: %v %v", k, found, err)
		}
		if w.state() != before {
			t.Fatalf("crash after step %d (%s) not rolled back\n--- before\n%s\n--- after\n%s", k, p.Steps[k-1].Name, before, w.state())
		}
	}
}

func UpgradeRequestJSON() api.JailUpgrade { return api.JailUpgrade{Generation: "g2"} }

func TestCleanupRootOld(t *testing.T) {
	w := runningSetup(t)
	if ok, err := w.S.CleanupRootOld(bg, "alpha_web"); ok || err != nil {
		t.Fatal("nothing to clean yet", ok, err)
	}
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := w.S.CleanupRootOld(bg, "alpha_web"); ok || err != nil {
		t.Fatal("retention not over", ok, err)
	}
	w.now = w.now.Add(25 * time.Hour)
	if ok, err := w.S.CleanupRootOld(bg, "alpha_web"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ex, _ := w.Z.Exists(bg, jc+"/root.old"); ex {
		t.Fatal("root.old survived")
	}
	// the generation it came from is free again: no clone depends on g1
	if cl, _ := w.Z.Clones(bg, "tank/jailops/images/fb/g1@ro"); len(cl) != 0 {
		t.Fatal(cl)
	}
	// a root.old without the mark is never touched
	w.Z.Create(bg, jc+"/root.old", map[string]string{PropManaged: "on"})
	if ok, _ := w.S.CleanupRootOld(bg, "alpha_web"); ok {
		t.Fatal("unmarked root.old destroyed")
	}
}

func TestSecondUpgradeReplacesStaleRootOld(t *testing.T) {
	w := runningSetup(t)
	w.addGen("fb", 3, "freebsd", "15.0-RELEASE")
	if _, err := upgrade(w, api.JailUpgrade{Generation: "g2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.S.UpgradeJail(bg, "alpha_web", UpgradeRequest{JailUpgrade: api.JailUpgrade{Generation: "g3"}, Stamp: "200"}); err != nil {
		t.Fatal(err)
	}
	if o, _ := w.Z.Origin(bg, jc+"/root.old"); o != "tank/jailops/images/fb/g2@ro" {
		t.Fatal(o)
	}
}
