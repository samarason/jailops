package service_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// A start never waits on the shell: bash cannot be fetched before the start and pkg inside the jail never returns (a
// jail whose firewall is closed), and the jail still starts, at the deadline of the setup, with the shell it has.
func TestStartDoesNotWaitOnTheShellSetup(t *testing.T) {
	e, s := tickingEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	e.SetPkgInstallErr(errors.New("pkg: no network"))
	e.Run.SetHangOn(func(c run.Cmd) bool { return c.Name == "pkg" && slices.Contains(c.Args, "-j") })
	defer service.SetShellSetupDeadline(300 * time.Millisecond)()

	op, err := s.CreateJail(alpha, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("create: %+v\n%s", got, e.Log())
	}
	t0 := time.Now()
	op, err = s.JailAction(alpha, "web", api.JailAction{Action: "start"})
	if err != nil {
		t.Fatal(err)
	}
	got := wait(t, s, op)
	if got.Status != api.OpSuccess {
		t.Fatalf("start: %+v\n%s", got, e.Log())
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Errorf("the start took %s", d)
	}
	if _, ok, _ := e.Jails.Get(alpha, "alpha_web"); !ok {
		t.Error("the jail does not run")
	}
	// the setup runs in the background after the start: wait for it to reach the pkg that hangs
	tried := false
	for deadline := time.Now().Add(10 * time.Second); !tried && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, c := range e.Run.Calls() {
			if c.Cmd.Name == "pkg" && slices.Contains(c.Cmd.Args, "-j") {
				tried = true
			}
		}
	}
	if !tried {
		t.Error("pkg was never run inside the jail: the hang was not reached")
	}
}

// The first start waits at most the deadline for the host to fetch bash (a slow mirror), starts the jail with the shell
// it has, and tries again from inside the running jail in the background: the start does not wait for that either.
func TestFirstStartIsBoundedWhenTheHostCannotFetchBash(t *testing.T) {
	e, s := tickingEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	e.Run.SetHangOn(func(c run.Cmd) bool {
		return c.Name == "pkg" && (slices.Contains(c.Args, "-r") || slices.Contains(c.Args, "-j")) && slices.Contains(c.Args, "install")
	})
	defer service.SetBashBeforeStartDeadline(300 * time.Millisecond)()
	defer service.SetShellSetupDeadline(300 * time.Millisecond)()

	op, err := s.CreateJail(alpha, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("create: %+v\n%s", got, e.Log())
	}
	t0 := time.Now()
	op, err = s.JailAction(alpha, "web", api.JailAction{Action: "start"})
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("start: %+v\n%s", got, e.Log())
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Errorf("the start took %s with a deadline of 300 ms", d)
	}
	if _, ok, _ := e.Jails.Get(alpha, "alpha_web"); !ok {
		t.Error("the jail does not run")
	}
	// the host-side install passed the shared cache of the host
	cached := false
	for _, c := range e.Run.Calls() {
		if c.Cmd.Name == "pkg" && slices.Contains(c.Cmd.Args, "-r") && slices.ContainsFunc(c.Cmd.Args, func(a string) bool { return len(a) > 14 && a[:14] == "PKG_CACHEDIR=/" }) {
			cached = true
		}
	}
	if !cached {
		t.Error("the install from the host did not use the cache directory of the host")
	}
}

// A restart of a jail that has run adds nothing for the shell: no pkg from the host, the root is not even looked at
// for bash, and a failed setup in the background is not repeated at every start.
func TestRestartOfAJailThatHasRunNeverFetchesBash(t *testing.T) {
	e, s := tickingEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	e.SetPkgInstallErr(errors.New("pkg: no network"))
	defer service.SetBashBeforeStartDeadline(300 * time.Millisecond)()
	defer service.SetShellSetupDeadline(300 * time.Millisecond)()

	op, err := s.CreateJail(alpha, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("create: %+v\n%s", got, e.Log())
	}
	act := func(action string) {
		t.Helper()
		op, err := s.JailAction(alpha, "web", api.JailAction{Action: action})
		if err != nil {
			t.Fatal(err)
		}
		if got := wait(t, s, op); got.Status != api.OpSuccess {
			t.Fatalf("%s: %+v\n%s", action, got, e.Log())
		}
	}
	pkgCalls := func() (host, inJail int) {
		for _, c := range e.Run.Calls() {
			if c.Cmd.Name != "pkg" || !slices.Contains(c.Cmd.Args, "install") {
				continue
			}
			switch {
			case slices.Contains(c.Cmd.Args, "-j"):
				inJail++
			case slices.ContainsFunc(c.Cmd.Args, func(a string) bool { return strings.HasSuffix(a, "/jails/web/root") }):
				host++ // the root of the jail, not the staging root of an image build
			}
		}
		return
	}
	act("start") // the first start: the host tries once, then the jail's own attempt in the background
	time.Sleep(500 * time.Millisecond)
	host1, jail1 := pkgCalls()
	if host1 != 1 {
		t.Fatalf("the first start made %d installs from the host, want 1\n%v\n%s", host1, e.Run.Calls(), e.Log())
	}
	for i := 0; i < 3; i++ {
		act("restart")
	}
	time.Sleep(500 * time.Millisecond)
	host2, jail2 := pkgCalls()
	if host2 != host1 {
		t.Errorf("a restart fetched bash from the host: %d installs, %d before", host2, host1)
	}
	if jail2 != jail1 {
		t.Errorf("a failed setup was repeated at every start: %d installs in the jail, %d before", jail2, jail1)
	}
}

// An operation lists the steps it ran and how long each took, so that a slow start or stop explains itself in
// `jailops op show`.
func TestOperationListsItsSteps(t *testing.T) {
	e, s := tickingEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	op, err := s.CreateJail(alpha, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("create: %+v\n%s", got, e.Log())
	}
	for _, action := range []string{"start", "stop"} {
		op, err := s.JailAction(alpha, "web", api.JailAction{Action: action})
		if err != nil {
			t.Fatal(err)
		}
		got := wait(t, s, op)
		if got.Status != api.OpSuccess {
			t.Fatalf("%s: %+v\n%s", action, got, e.Log())
		}
		if len(got.Steps) == 0 {
			t.Fatalf("%s: the operation lists no steps: %+v", action, got)
		}
		if action == "stop" {
			names := []string{}
			for _, st := range got.Steps {
				names = append(names, st.Name)
			}
			for _, want := range []string{"jail-stop", "teardown", "unmount"} {
				if !slices.Contains(names, want) {
					t.Errorf("stop: step %q missing from %v", want, names)
				}
			}
		}
	}
}
