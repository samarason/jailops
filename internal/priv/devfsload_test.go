package priv

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

func (h *hookEnv) devfsAdds() []string {
	var out []string
	for _, c := range h.devfsCmds {
		if strings.Contains(c, " add ") {
			out = append(out, c)
		}
	}
	return out
}

// A jail on the stock ruleset loads nothing and touches no devfs ruleset.
func TestHookPlainFreeBSDJailLoadsNoDevfsRuleset(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12")
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if len(h.devfsCmds) != 0 {
		t.Fatalf("a jail on the stock ruleset ran %q", h.devfsCmds)
	}
}

// A jail given a device gets its private ruleset in the kernel before it is created: the stock sets it includes,
// then the device paths, in the order the renderer gives them.
func TestHookLoadsTheDevfsRulesetOfAJailWithDevices(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12", "tun", "dri")
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	n, rules, err := render.DevfsRuleset([]string{"tun", "dri"})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, r := range rules {
		want = append(want, strings.Join(r[1:], " "))
	}
	if got := h.devfsAdds(); !slices.Equal(got, want) {
		t.Fatalf("loaded %q, want %q", got, want)
	}
	if len(h.devfs[n]) != len(rules) {
		t.Fatalf("the kernel has %q for ruleset %d", h.devfs[n], n)
	}
	// the same jail started again: the set is replaced, never doubled
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if len(h.devfs[n]) != len(rules) {
		t.Fatalf("a second start left %q in ruleset %d", h.devfs[n], n)
	}
}

// Every Linux jail has a private ruleset, devices or not: hide everything, then the nodes of a Linux userland.
func TestHookLoadsTheDevfsRulesetOfALinuxJail(t *testing.T) {
	h := newHookEnv(t, api.OSLinux, "10.20.0.12", "fd00:20::12")
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	n, rules, _ := render.LinuxDevfsRuleset(nil)
	if len(h.devfs[n]) != len(rules) || h.devfs[n][0] != "hide" {
		t.Fatalf("ruleset %d in the kernel: %q", n, h.devfs[n])
	}
	if !slices.Contains(h.devfs[n], "path null unhide") || slices.Contains(h.devfs[n], "path vtbd0 unhide") {
		t.Fatalf("%q", h.devfs[n])
	}
}

// A ruleset that a running jail still mounts cannot be deleted by the kernel: the next start keeps it and loads
// nothing twice.
func TestHookKeepsAnInUseDevfsRuleset(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12", "tun")
	n, rules, _ := render.DevfsRuleset([]string{"tun"})
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	h.devfsCmds = nil
	h.devfsKeepsSets = true // delset fails: a jail mounts the ruleset
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if got := h.devfsAdds(); len(got) != 0 || len(h.devfs[n]) != len(rules) {
		t.Fatalf("an in-use ruleset was loaded again: %q, kernel %q", got, h.devfs[n])
	}
}

// A jail never starts on a ruleset that was not loaded.
func TestHookRefusesToStartWhenTheDevfsRulesetCannotBeLoaded(t *testing.T) {
	h := newHookEnv(t, api.OSLinux, "10.20.0.12", "fd00:20::12")
	h.devfsFail = "devfs: Operation not permitted"
	err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web")
	if err == nil || !strings.Contains(err.Error(), "the jail is not started") {
		t.Fatalf("err = %v", err)
	}
	n, _, _ := render.LinuxDevfsRuleset(nil)
	if _, left := h.devfs[n]; left {
		t.Fatalf("a half-loaded ruleset %d stayed in the kernel: %q", n, h.devfs[n])
	}
	// no interface was touched either: the failure comes before the host side of the start
	if calls := h.ifconfigCalls(); len(calls) != 0 {
		t.Fatalf("the host was configured for a jail that cannot start: %q", calls)
	}
}

// The stock sets the private ruleset includes must be in the kernel; if the devfs service did not load them the
// jail's /dev would not be hidden, so the start is refused.
func TestHookRefusesWhenAStockDevfsRulesetIsMissing(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12", "tun")
	delete(h.devfs, 2)
	err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web")
	if err == nil || !strings.Contains(err.Error(), fmt.Sprint("stock ruleset ", 2)) {
		t.Fatalf("err = %v", err)
	}
	if len(h.devfsAdds()) != 0 {
		t.Fatalf("rules were loaded anyway: %q", h.devfsAdds())
	}
}

// The poststop hook leaves the rulesets alone: a ruleset is shared by every jail with the same devices, and the
// number of possible rulesets is small, so nothing leaks.
func TestHookPostStopKeepsTheDevfsRuleset(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12", "tun")
	ctx := context.Background()
	if err := h.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	h.devfsCmds = nil
	if err := h.local.RunHook(ctx, PhasePostStop, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if len(h.devfsCmds) != 0 {
		t.Fatalf("poststop ran %q", h.devfsCmds)
	}
}

// A ruleset the kernel still has but that holds no rules (a set a mounted devfs kept alive after its rules went) is
// filled again: a jail must never mount an empty ruleset, which hides nothing.
func TestHookFillsAnEmptyDevfsRulesetThatStillExists(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12", "tun")
	n, rules, _ := render.DevfsRuleset([]string{"tun"})
	h.devfs[n] = nil // exists, empty
	h.devfsEmptiesSets = true
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if len(h.devfs[n]) != len(rules) {
		t.Fatalf("the empty ruleset %d was left empty: %q", n, h.devfs[n])
	}
	h.devfsKeepsSets = true // a set that is in use and holds nothing
	h.devfsEmptiesSets = false
	h.devfs[n] = nil
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if len(h.devfs[n]) != len(rules) {
		t.Fatalf("an in-use empty ruleset %d was left empty: %q", n, h.devfs[n])
	}
}

// A ruleset that exists with other rules than the jail's devices need is not trusted and not changed: the jail is
// not started.
func TestHookRefusesADevfsRulesetWithOtherRules(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12", "tun")
	n, _, _ := render.DevfsRuleset([]string{"tun"})
	h.devfs[n] = []string{"include 1", "path kmem unhide"}
	h.devfsKeepsSets = true
	err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web")
	if err == nil || !strings.Contains(err.Error(), "the jail is not started") {
		t.Fatalf("err = %v", err)
	}
	if len(h.devfsAdds()) != 0 {
		t.Fatalf("rules were added to a foreign ruleset: %q", h.devfsAdds())
	}
}
