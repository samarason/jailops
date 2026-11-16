package priv

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestRctlRules(t *testing.T) {
	for name, tc := range map[string]struct {
		r    api.Resources
		want []string
	}{
		"none":   {api.Resources{}, nil},
		"all":    {api.Resources{CPU: 2, Memory: "2G", PIDs: 500}, []string{"jail:alpha_web:swapuse:deny=2147483648", "jail:alpha_web:maxproc:deny=500", "jail:alpha_web:pcpu:deny=200"}},
		"memory": {api.Resources{Memory: "512M"}, []string{"jail:alpha_web:swapuse:deny=536870912"}},
		"cpu":    {api.Resources{CPU: 1}, []string{"jail:alpha_web:pcpu:deny=100"}},
		// only the three limits become rules: the disk is ZFS and the states are pf
		"others": {api.Resources{Disk: "10G", States: 5000}, nil},
	} {
		got, err := rctlRules("alpha_web", tc.r)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v %v, want %v", name, got, err, tc.want)
		}
	}
	if _, err := rctlRules("alpha_web", api.Resources{Memory: "lots"}); err == nil {
		t.Error("a memory limit that is not a size made rules")
	}
}

// setLimits writes the resources into the jail's stored spec.
func (h *hookEnv) setLimits(t *testing.T, r api.Resources) {
	t.Helper()
	p := filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "spec.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	_ = json.Unmarshal(doc["spec"], &spec)
	rb, _ := json.Marshal(r)
	var res any
	_ = json.Unmarshal(rb, &res)
	spec["resources"] = res
	doc["spec"], _ = json.Marshal(spec)
	out, _ := json.Marshal(doc)
	mustWrite(t, p, string(out))
}

func (h *hookEnv) rctlCalls() []string {
	var out []string
	for _, c := range h.runner.Calls() {
		if c.Cmd.Name == "rctl" {
			out = append(out, strings.Join(c.Cmd.Args, " "))
		}
	}
	return out
}

// The rules are added after the jail is up, once for each limit that is set.
func TestHookPostStartAddsTheRctlRules(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	h.setLimits(t, api.Resources{CPU: 2, Memory: "1G", PIDs: 100})
	ctx := context.Background()
	if err := h.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if got := h.rctlCalls(); len(got) != 0 {
		t.Fatalf("rules before the jail exists: %v", got)
	}
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	// the rules of an earlier run are removed first (the kernel keeps them by name), then each limit is added
	want := []string{"-r jail:alpha_web", "-a jail:alpha_web:swapuse:deny=1073741824", "-a jail:alpha_web:maxproc:deny=100", "-a jail:alpha_web:pcpu:deny=200"}
	if got := h.rctlCalls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("rctl calls %q, want %q", got, want)
	}
	// and they are removed when the jail stops; a jail that has none (rctl says "No such process") is not an error
	h.rctlStderr = "rctl: failed to remove rule 'jail:alpha_web': No such process"
	before := len(h.rctlCalls())
	if err := h.local.RunHook(ctx, PhasePostStop, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if got := h.rctlCalls(); len(got) != before+1 || got[before] != "-r jail:alpha_web" {
		t.Fatalf("poststop rctl calls %q", got)
	}
}

// A jail without limits adds no rule, and a host that has racct off still starts the jail.
func TestHookPostStartWithoutLimitsOrWithoutRacct(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	ctx := context.Background()
	if err := h.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if got := h.rctlCalls(); len(got) != 0 {
		t.Fatalf("a jail without limits got rules: %v", got)
	}

	h = newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	h.setLimits(t, api.Resources{PIDs: 100})
	h.rctlStderr = "rctl: failed to add rule: RACCT/RCTL present, but disabled; enable using kern.racct.enable=1 tunable"
	if err := h.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Fatalf("a host without racct must still start the jail: %v", err)
	}

	h = newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	h.setLimits(t, api.Resources{PIDs: 100})
	h.rctlStderr = "rctl: some other failure"
	if err := h.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err == nil || !strings.Contains(err.Error(), "resource limits") {
		t.Fatalf("another rctl failure must fail the start: %v", err)
	}
}
