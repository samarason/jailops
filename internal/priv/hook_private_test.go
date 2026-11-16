package priv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// The poststart of a jail does not load its anchor again: prestart did, before the jail's first process ran.
func TestHookLoadsTheAnchorBeforeTheJailRuns(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	ctx := context.Background()
	mustWrite(t, h.cfg.PFAnchorFile("alpha_web"), "pass in on "+h.host+" all\n")
	if err := h.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if h.pf.LoadCalls["jailops/alpha/web"] != 1 {
		t.Fatalf("the anchor is not loaded by prestart: %v", h.pf.LoadCalls)
	}
	if err := h.jails.Create(ctx, filepath.Join(h.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if h.pf.LoadCalls["jailops/alpha/web"] != 1 {
		t.Errorf("poststart loaded the anchor again: %v", h.pf.LoadCalls)
	}
}

// The states of the rules of a jail's anchor end with the jail: the next jail given its address must not be reached by a
// connection that an old rule admitted.
func TestHookPostStopEndsTheStatesOfTheAnchor(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	ctx := context.Background()
	h.pf.Load(ctx, "jailops/alpha/web", "pass in quick on "+h.host+" all label \"jo-aaaaaaaaaaaa\"\npass out quick on "+h.host+" all label \"jo-bbbbbbbbbbbb\"\n")
	if err := h.local.RunHook(ctx, PhasePostStop, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.pf.Killed, ","); got != "jo-aaaaaaaaaaaa,jo-bbbbbbbbbbbb" {
		t.Errorf("labels ended: %q", got)
	}
	if a, _ := h.pf.Read(ctx, "jailops/alpha/web"); a != "" {
		t.Errorf("anchor still loaded: %q", a)
	}
}

// localExecer and localRegistrar are copies of the interfaces the service
// layer and the daemon assert on the helper; both implementations must
// satisfy them (the real service.JailExecer is asserted in exec_types.go).
type localExecer interface {
	Exec(ctx context.Context, jail string, argv []string, o ExecOpts) (ExecSession, error)
}

type localRegistrar interface {
	RegisterStorage(ctx context.Context, dataset string) error
	UnregisterStorage(ctx context.Context, dataset string) error
}

func TestHelperSatisfiesTheServiceInterfaces(t *testing.T) {
	var h Host = (*Local)(nil)
	var c Host = (*Client)(nil)
	for _, x := range []Host{h, c} {
		if _, ok := any(x).(localExecer); !ok {
			t.Errorf("%T lacks Exec", x)
		}
		if _, ok := any(x).(localRegistrar); !ok {
			t.Errorf("%T lacks RegisterStorage/UnregisterStorage", x)
		}
		if _, ok := any(x).(service.JailExecer); !ok {
			t.Errorf("%T is not a service.JailExecer", x)
		}
		if _, ok := any(x).(service.StorageRegistrar); !ok {
			t.Errorf("%T is not a service.StorageRegistrar", x)
		}
	}
	// the exec types are the service's own, not look-alikes
	var _ service.ExecOpts = ExecOpts{}
	var _ service.ExecSession = (ExecSession)(nil)
}

// A jail with a network link does not start while pf is disabled (the anchor would be loaded and nothing would
// evaluate it) or when its rendered anchor is missing (the jail would run on the rules of the host alone); a jail with
// no link needs neither. allow-start-without-pf says otherwise for the first.
func TestHookRefusesALinkedJailWithoutPFOrWithoutAnAnchor(t *testing.T) {
	ctx := context.Background()
	newEnvWithPF := func(status string) *hookEnv {
		h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
		h.runner.Add(run.Rule{Name: pfctlBin, Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
			if strings.Join(c.Args, " ") == "-s info" {
				return run.Result{Stdout: []byte("Status: " + status + "          Debug: Urgent\n")}, nil
			}
			return run.Result{}, nil
		}})
		mustWrite(t, h.cfg.PFAnchorFile("alpha_web"), "pass in on "+h.host+" all\n")
		return h
	}
	off := newEnvWithPF("Disabled")
	err := off.local.RunHook(ctx, PhasePreStart, "alpha_web")
	if err == nil || !strings.Contains(err.Error(), "pf is disabled") {
		t.Fatalf("pf is disabled: %v", err)
	}
	if off.pf.LoadCalls["jailops/alpha/web"] != 0 {
		t.Errorf("an anchor was loaded although the start was refused: %v", off.pf.LoadCalls)
	}
	on := newEnvWithPF("Enabled for 0 days 00:01:02")
	if err := on.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatalf("pf runs: %v", err)
	}
	allowed := newEnvWithPF("Disabled")
	allowed.local.cfg.AllowStartWithoutPF = true
	if err := allowed.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatalf("allow-start-without-pf: %v", err)
	}
	missing := newEnvWithPF("Enabled for 0 days 00:01:02")
	if err := os.Remove(missing.cfg.PFAnchorFile("alpha_web")); err != nil {
		t.Fatal(err)
	}
	err = missing.local.RunHook(ctx, PhasePreStart, "alpha_web")
	if err == nil || !strings.Contains(err.Error(), "no rendered pf anchor") {
		t.Fatalf("a linked jail without an anchor: %v", err)
	}
}
