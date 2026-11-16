package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

func indexOf(log []string, exact string) int {
	for i, l := range log {
		if l == exact || strings.HasPrefix(l, exact+" ") {
			return i
		}
	}
	return -1
}

func TestStartStopOrdering(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	w.F.Reset(0)
	if err := w.S.StartJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	log := w.F.Log
	root := indexOf(log, "zfs mount tank/jailops/projects/alpha/jails/web/root")
	etc := indexOf(log, "zfs mount tank/jailops/projects/alpha/jails/web/etc")
	vol := indexOf(log, "zfs mount tank/jailops/projects/alpha/volumes/db")
	hook := indexOf(log, "prestart alpha_web")
	jail := indexOf(log, "jail start alpha_web")
	if !(root >= 0 && root < etc && etc < vol && vol < hook && hook < jail) {
		t.Fatalf("order wrong: %v", log)
	}
	if indexOf(log, "mkdir /jailops/projects/alpha/jails/web/root/srv/db") < 0 || indexOf(log, "mkdir /jailops/projects/alpha/jails/web/root/srv/db") > hook {
		t.Fatal("the mount point of the volume must exist before the jail starts", log)
	}
	if !w.Jails.IsUp("alpha_web") {
		t.Fatal("not running")
	}
	// idempotent
	w.F.Reset(0)
	if err := w.S.StartJail(bg, "alpha_web"); err != nil || w.F.Count() != 0 {
		t.Fatal(err, w.F.Count())
	}
	w.F.Reset(0)
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	log = w.F.Log
	if !(indexOf(log, "jail stop alpha_web") < indexOf(log, "poststop alpha_web") && indexOf(log, "poststop alpha_web") < indexOf(log, "zfs unmount tank/jailops/projects/alpha/jails/web/etc") &&
		indexOf(log, "zfs unmount tank/jailops/projects/alpha/jails/web/etc") < indexOf(log, "zfs unmount tank/jailops/projects/alpha/jails/web/root")) {
		t.Fatalf("stop order wrong: %v", log)
	}
	if indexOf(log, "zfs unmount "+dbVol) >= 0 {
		t.Fatal("stopping a jail unmounts a volume other jails may use")
	}
	if mounted, _ := w.Z.Mounted(bg, "tank/jailops/projects/alpha/jails/web/root"); mounted {
		t.Fatal("root still mounted")
	}
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal("stop must be idempotent:", err)
	}
}

func TestStartFailureSweep(t *testing.T) {
	setup := func(t *testing.T) *world { w := newWorld(t); w.created("web"); return w }
	sweep(t, setup, func(w *world) error { return w.S.StartJail(bg, "alpha_web") })
}

func TestStartNotReady(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	w.Jails.Never = true
	w.S.Cfg.ReadyTimeout, w.S.Cfg.PollInterval = 3*time.Second, time.Second
	w.S.Cfg.Sleep = func(_ context.Context, d time.Duration) error { w.now = w.now.Add(d); return nil }
	before := w.state()
	err := w.S.StartJail(bg, "alpha_web")
	if err == nil || !strings.Contains(err.Error(), "not running after 3s") {
		t.Fatal(err)
	}
	if w.state() != before {
		t.Fatal("not-ready start was not undone")
	}
}

func TestStartRefusesIncompleteAndUnknown(t *testing.T) {
	w := newWorld(t)
	wantCode(t, w.S.StartJail(bg, "alpha_nope"), api.CodeNotFound)
	w.created("web")
	w.Z.Set(bg, "tank/jailops/projects/alpha/jails/web", map[string]string{PropComplete: "off"})
	wantCode(t, w.S.StartJail(bg, "alpha_web"), api.CodeBusy)
	// a dataset that is not ours is invisible
	w.Z.Create(bg, "tank/jailops/projects/alpha/jails/alien", nil)
	wantCode(t, w.S.StartJail(bg, "alpha_alien"), api.CodeNotFound)
}

func TestDestroy(t *testing.T) {
	w := newWorld(t)
	w.running("web")
	if _, err := w.S.DestroyJail(bg, "alpha_web", false, false); !api.IsCode(err, api.CodeBusy) {
		t.Fatal(err)
	}
	r, err := w.S.DestroyJail(bg, "alpha_web", true, false)
	if err != nil || len(r.Warnings) != 0 {
		t.Fatal(err, r)
	}
	for _, n := range w.Z.Names() {
		if strings.HasPrefix(n, "tank/jailops/projects/alpha/jails/web") {
			t.Fatalf("leaked %s", n)
		}
	}
	if w.Jails.IsUp("alpha_web") || w.Images.collects != 1 || indexOf(w.Hooks.Log, "remove alpha_web") < 0 {
		t.Fatal("follow-up work missing")
	}
	wantCode(t, func() error { _, e := w.S.DestroyJail(bg, "alpha_web", true, false); return e }(), api.CodeNotFound)
}

func TestDestroyRefusesForeignClone(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	if _, err := w.S.SnapshotJail(bg, "alpha_web", "keep", ""); err != nil {
		t.Fatal(err)
	}
	w.Z.Clone(bg, "tank/jailops/projects/alpha/jails/web/home@keep", "tank/jailops/projects/alpha/jails/scratch", nil)
	if _, err := w.S.DestroyJail(bg, "alpha_web", false, false); !api.IsCode(err, api.CodeBusy) {
		t.Fatal(err)
	}
}

func TestDestroyFailureSweep(t *testing.T) {
	setup := func(t *testing.T) *world { w := newWorld(t); w.running("web"); return w }
	sweep(t, setup, func(w *world) error {
		r, err := w.S.DestroyJail(bg, "alpha_web", true, false)
		if err == nil && len(r.Warnings) > 0 {
			return nil // post-destroy cleanup failed: reported, not undone
		}
		return err
	})
}

func TestStartFailureReason(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	w.F.Reset(1)
	if err := w.S.StartJail(bg, "alpha_web"); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatal(err)
	}
	_ = errors.New
}

// A delete takes the runtime state down also for a jail that is not running: it may have been stopped by hand, and its
// rctl rules stay by name.
func TestDestroyTearsDownAStoppedJail(t *testing.T) {
	w := newWorld(t)
	w.running("web")
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	w.Hooks.Log = nil
	if _, err := w.S.DestroyJail(bg, "alpha_web", false, false); err != nil {
		t.Fatal(err)
	}
	if indexOf(w.Hooks.Log, "poststop alpha_web") < 0 {
		t.Fatalf("no teardown of a stopped jail: %v", w.Hooks.Log)
	}
}

// busyZFS refuses to unmount: something on the host holds the datasets of the jail.
type busyZFS struct{ ZFS }

func (busyZFS) Unmount(context.Context, string) error {
	return api.Errorf(api.CodeBusy, "cannot unmount: pool or dataset is busy")
}

// A stop whose datasets stay busy after the jail is gone succeeds, says so, and does not wait for them.
func TestStopDoesNotWaitForABusyRoot(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	if err := w.S.StartJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	w.S.ZFS = busyZFS{w.S.ZFS}
	var warned string
	w.S.Warn = func(_ context.Context, jail, _, what string) { warned = jail + ": " + what }
	t0 := time.Now()
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal("a busy root is not a failed stop:", err)
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Errorf("the stop waited %s", d)
	}
	if !strings.Contains(warned, "alpha_web") || !strings.Contains(warned, "stay mounted") {
		t.Errorf("no warning for the datasets that stay mounted: %q", warned)
	}
}

// forcedJails answers a stop as the helper does when the stop commands of a jail never returned: the jail is removed
// and the answer says it was forced.
type forcedJails struct{ Jails }

func (f forcedJails) Stop(ctx context.Context, name string) error {
	if err := f.Jails.Stop(ctx, name); err != nil {
		return err
	}
	return api.Errorf(api.CodeStopForced, "jail %s did not shut down within 1m5s (still running: 4021 sleep)", name)
}

// A forced stop is a stop with an event that names what still ran; the rest of the stop goes on.
func TestForcedStopIsAStopWithAnEvent(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	if err := w.S.StartJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	w.S.Jails = forcedJails{w.S.Jails}
	var action, what string
	w.S.Warn = func(_ context.Context, _, a, wh string) { action, what = a, wh }
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal("a forced stop is not a failed stop:", err)
	}
	if action != "jail-stop-forced" || !strings.Contains(what, "still running: 4021 sleep") {
		t.Errorf("event %q %q", action, what)
	}
	if mounted, _ := w.Z.Mounted(bg, "tank/jailops/projects/alpha/jails/web/root"); mounted {
		t.Error("the root is still mounted after the forced stop")
	}
}
