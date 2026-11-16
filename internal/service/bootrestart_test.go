package service_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

func firstPass(t *testing.T, e *dtest.Env) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for e.D.Reconciler().Last().At.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("the reconcile loop never ran")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// the boot pass is part of the first pass; give an action that follows it a moment
	time.Sleep(200 * time.Millisecond)
}

func running(t *testing.T, e *dtest.Env, name string) bool {
	t.Helper()
	j, err := e.D.Service().GetJail(as(globalAdmin, dtest.SeedProject), name)
	if err != nil {
		t.Fatal(err)
	}
	return j.Status.Power == api.PowerRunning
}

// The jails with boot.autostart start when the host boots. A daemon that starts again on a host that stayed up (a
// restart, a package upgrade) leaves them as they are: an operator may have stopped one on purpose.
func TestRestartOfTheDaemonDoesNotStartJailsStoppedOnPurpose(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	j := dtest.WebJail("web")
	j.Spec.Boot.Autostart = true
	op, err := e.D.Service().CreateJail(as(globalAdmin, dtest.SeedProject), j)
	mustOp(t, e.D.Service(), op, err)
	firstPass(t, e)
	e.Stop()

	// the daemon starts again, the host has not rebooted: the jail stays stopped
	e2 := dtest.New(t, dtest.Options{Reuse: e})
	firstPass(t, e2)
	if running(t, e2, "web") {
		t.Fatal("a restart of the daemon started a jail with boot.autostart that was stopped")
	}
	e2.Stop()

	// the host booted since the daemon last ran its boot pass: now the jail starts
	if err := os.WriteFile(filepath.Join(e.Cfg.StateDir, "boot-id"), []byte("{ sec = 1600000000, usec = 0 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e3 := dtest.New(t, dtest.Options{Reuse: e})
	deadline := time.Now().Add(10 * time.Second)
	for !running(t, e3, "web") {
		if time.Now().After(deadline) {
			t.Fatal("the boot pass did not start the jail after the host booted")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
