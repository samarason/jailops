package priv

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// A jail that is given devices, and every Linux jail, mounts its /dev with a private devfs ruleset (jail.conf's
// devfs_ruleset). The kernel makes a ruleset number nobody loaded an empty one, and an empty ruleset hides nothing:
// the jail would see the host's whole /dev, raw disks included. So the rules are loaded here, before the jail is
// created, and a jail whose ruleset cannot be loaded is not started.

// devfsRun runs `devfs <args>` as the helper.
func (l *Local) devfsRun(ctx context.Context, args ...string) (string, error) {
	res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "devfs", Args: args, Timeout: 20 * time.Second})
	if err != nil {
		if ee, ok := run.IsExit(err); ok {
			return string(res.Stdout), fmt.Errorf("devfs %s: %s", strings.Join(args, " "), strings.TrimSpace(ee.Stderr))
		}
		return string(res.Stdout), fmt.Errorf("devfs %s: %w", strings.Join(args, " "), err)
	}
	return string(res.Stdout), nil
}

// devfsSets returns the numbers of the rulesets the kernel has.
func (l *Local) devfsSets(ctx context.Context) (map[int]bool, error) {
	out, err := l.devfsRun(ctx, "rule", "showsets")
	if err != nil {
		return nil, err
	}
	sets := map[int]bool{}
	for _, f := range strings.Fields(out) {
		if n, err := strconv.Atoi(f); err == nil {
			sets[n] = true
		}
	}
	return sets, nil
}

// devfsRules returns the rules of a ruleset as `devfs rule -s N show` prints them, without their numbers.
func (l *Local) devfsRules(ctx context.Context, set string) ([]string, error) {
	out, err := l.devfsRun(ctx, "rule", "-s", set, "show")
	if err != nil {
		return nil, err
	}
	var rules []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		rules = append(rules, normalizeDevfsRule(strings.Join(f[1:], " ")))
	}
	return rules, nil
}

// normalizeDevfsRule makes the text of a rule comparable: single spaces, no quotes.
func normalizeDevfsRule(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "'", "")), " ")
}

// loadDevfs loads the private devfs ruleset of the jail described by rec. A jail on the stock ruleset loads
// nothing. A ruleset that a running jail still mounts cannot be removed; it holds the same rules (the number says
// which devices it has), so it is kept.
func (l *Local) loadDevfs(ctx context.Context, rec *jailRecord) error {
	devices := render.SpecDevfsDevices(rec.Spec)
	var (
		n     int
		rules [][]string
		err   error
	)
	if rec.Spec.OS == api.OSLinux {
		n, rules, err = render.LinuxDevfsRuleset(devices)
	} else {
		n, rules, err = render.DevfsRuleset(devices)
	}
	if err != nil {
		return invalid("devfs: %v", err)
	}
	if len(rules) == 0 {
		return nil
	}
	for _, r := range rules { // the rules are built from the allow-list; the helper's grammar still has the last word
		if err := customDevfs(l.cfg, true, r[1:]); err != nil {
			return err
		}
	}
	have, err := l.devfsSets(ctx)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if len(r) == 7 && r[4] == "add" && r[5] == "include" {
			if m, err := strconv.Atoi(r[6]); err == nil && !have[m] {
				return api.Errorf(api.CodeInternal, "devfs: the stock ruleset %d is not loaded: the jail's /dev would not be hidden; start the devfs service first", m)
			}
		}
	}
	set := strconv.Itoa(n)
	var want []string // the rules the ruleset must hold, in order
	for _, r := range rules {
		want = append(want, normalizeDevfsRule(strings.Join(r[5:], " ")))
	}
	if have[n] {
		_, _ = l.devfsRun(ctx, "rule", "-s", set, "delset") // fails while a jail mounts it, or empties it
		if have, err = l.devfsSets(ctx); err != nil {
			return err
		}
		if have[n] {
			// The set is still there: trust what it holds, not that it is the one we made. A set that a mounted devfs
			// keeps alive can be empty (an empty ruleset hides nothing: the jail would see the whole /dev).
			cur, err := l.devfsRules(ctx, set)
			if err != nil {
				return err
			}
			switch {
			case slices.Equal(cur, want):
				return nil
			case len(cur) != 0:
				return api.Errorf(api.CodeInternal, "devfs ruleset %s exists with other rules than the jail's devices need, so the jail is not started: %v", set, cur)
			}
			// empty: load the rules into it below
		}
	}
	for _, r := range rules {
		if _, err := l.devfsRun(ctx, r[1:]...); err != nil {
			_, _ = l.devfsRun(ctx, "rule", "-s", set, "delset")
			return api.Errorf(api.CodeInternal, "devfs ruleset %s could not be loaded, so the jail is not started: %v", set, err)
		}
	}
	if have, err = l.devfsSets(ctx); err != nil {
		return err
	}
	if !have[n] {
		return api.Errorf(api.CodeInternal, "devfs ruleset %s is not in the kernel after loading it, so the jail is not started", set)
	}
	if cur, err := l.devfsRules(ctx, set); err != nil {
		return err
	} else if !slices.Equal(cur, want) {
		return api.Errorf(api.CodeInternal, "devfs ruleset %s holds %v after loading it, not %v, so the jail is not started", set, cur, want)
	}
	return nil
}
