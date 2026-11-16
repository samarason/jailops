package api

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// BootNode is a jail as the boot order sees it: its project-qualified key (the OS-level name of the jail), and its
// boot policy with Depends holding keys too.
type BootNode struct {
	Key  string
	Boot BootPolicy
}

// BootOrder returns the jails to start, in order, given the autostart jails
// and the set already running. Rules:
//   - a jail starts after everything in boot.depends is running;
//   - a dependency that is not running is started first, even without
//     autostart (the operator declared the need);
//   - among jails that are ready, lower boot.priority starts first, then name;
//   - a dependency cycle or an unknown dependency excludes the jails involved
//     and is reported in skipped, never guessed around.
func BootOrder(jails []BootNode, running map[string]bool) (order []string, skipped map[string]string) {
	by := map[string]BootNode{}
	for _, j := range jails {
		by[j.Key] = j
	}
	skipped = map[string]string{}
	// The set to start: autostart jails not running plus their missing dependencies.
	want := map[string]bool{}
	var add func(name string, path []string) bool
	add = func(name string, path []string) bool {
		if running[name] || want[name] {
			return true
		}
		if slices.Contains(path, name) {
			for _, p := range path[slices.Index(path, name):] {
				skipped[p] = "dependency cycle: " + strings.Join(append(slices.Clone(path[slices.Index(path, name):]), name), " -> ")
			}
			return false
		}
		j, ok := by[name]
		if !ok {
			return false
		}
		ok2 := true
		for _, d := range j.Boot.Depends {
			if _, known := by[d]; !known && !running[d] {
				skipped[name] = fmt.Sprintf("depends on %q, which does not exist", d)
				ok2 = false
				continue
			}
			if !add(d, append(slices.Clone(path), name)) {
				if _, s := skipped[name]; !s {
					skipped[name] = fmt.Sprintf("dependency %q cannot be started", d)
				}
				ok2 = false
			}
		}
		if ok2 {
			want[name] = true
		}
		return ok2
	}
	var auto []string
	for _, j := range jails {
		if j.Boot.Autostart && !running[j.Key] {
			auto = append(auto, j.Key)
		}
	}
	slices.Sort(auto)
	for _, n := range auto {
		if _, bad := skipped[n]; bad {
			continue
		}
		if !add(n, nil) {
			if _, s := skipped[n]; !s {
				skipped[n] = "a dependency cannot be started"
			}
		}
	}
	// Kahn with a priority queue by (priority, name).
	done := map[string]bool{}
	for n := range running {
		done[n] = true
	}
	for len(done)-len(running) < len(want) {
		var ready []string
		for n := range want {
			if done[n] {
				continue
			}
			ok := true
			for _, d := range by[n].Boot.Depends {
				if !done[d] {
					ok = false
				}
			}
			if ok {
				ready = append(ready, n)
			}
		}
		if len(ready) == 0 {
			for n := range want {
				if !done[n] {
					skipped[n] = "dependency cycle"
				}
			}
			break
		}
		slices.SortFunc(ready, func(a, b string) int {
			if pa, pb := by[a].Boot.Priority, by[b].Boot.Priority; pa != pb {
				return pa - pb
			}
			return strings.Compare(a, b)
		})
		order = append(order, ready[0])
		done[ready[0]] = true
	}
	return order, skipped
}

// BootPlan is what the daemon's boot pass would do after a boot of the host: the jails it starts, in order, and the
// jails with autostart it does not start, each with why. Jails that are running now are part of the plan: it says
// what a boot would do, not what is left to do.
type BootPlan struct {
	// Order lists the jails in the order they start. A jail starts after everything in its depends.
	Order []BootEntry `json:"order"`
	// NotStarted lists the jails that have autostart (or that a jail with autostart depends on) and that a boot
	// does not start.
	NotStarted []BootSkip `json:"not_started"`
}

// BootEntry is one jail of the boot order.
type BootEntry struct {
	// Position is the place in the order, from 1.
	Position int    `json:"position"`
	Project  string `json:"project"`
	Jail     string `json:"jail"`
	// Priority is boot.priority: among the jails that are ready, the lower number starts first.
	Priority int `json:"priority"`
	// Depends are the jails of the project that start first (boot.depends).
	Depends []string `json:"depends,omitempty"`
	// Reason is "autostart", or "dependency of NAME" for a jail without autostart that another one needs.
	Reason string `json:"reason"`
	// Running says the jail is running now.
	Running bool `json:"running,omitempty"`
}

// BootSkip is a jail a boot does not start, and why.
type BootSkip struct {
	Project string `json:"project"`
	Jail    string `json:"jail"`
	Reason  string `json:"reason"`
}

// BootJail is a jail for PlanBoot.
type BootJail struct {
	// Key is the project-qualified key (the OS-level name of the jail); Boot.Depends hold keys.
	Key     string
	Project string
	Name    string
	Boot    BootPolicy
	// Encrypted says a volume of the jail is encrypted: after a boot its key is not loaded, so the jail waits for
	// its passphrase.
	Encrypted bool
	Running   bool
}

// PlanBoot computes the boot plan of the jails, with the order of BootOrder as the daemon's boot pass applies it,
// and with nothing running: it is the plan of a boot.
func PlanBoot(jails []BootJail) BootPlan {
	nodes := make([]BootNode, len(jails))
	by := map[string]BootJail{}
	for i, j := range jails {
		nodes[i] = BootNode{Key: j.Key, Boot: j.Boot}
		by[j.Key] = j
	}
	order, skipped := BootOrder(nodes, nil)
	// the jail with autostart each other jail is needed by (the first in key order)
	needed := map[string]string{}
	var autos []string
	for _, j := range jails {
		if j.Boot.Autostart {
			autos = append(autos, j.Key)
		}
	}
	slices.Sort(autos)
	var mark func(a, k string, seen map[string]bool)
	mark = func(a, k string, seen map[string]bool) {
		for _, d := range by[k].Boot.Depends {
			if seen[d] {
				continue
			}
			seen[d] = true
			if _, ok := needed[d]; !ok {
				needed[d] = a
			}
			mark(a, d, seen)
		}
	}
	for _, a := range autos {
		mark(a, a, map[string]bool{a: true})
	}
	name := func(key string) string {
		if j, ok := by[key]; ok {
			return j.Name
		}
		return key
	}
	// the keys in a reason of BootOrder become the names of the jails
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return len(b) - len(a) })
	reasonText := func(project, s string) string {
		for _, k := range keys {
			s = regexp.MustCompile(`\b`+regexp.QuoteMeta(k)+`\b`).ReplaceAllString(s, by[k].Name)
		}
		// a jail that does not exist is named by its key: the project of the jail that depends on it is the same
		return regexp.MustCompile(`\b`+regexp.QuoteMeta(project+"_")).ReplaceAllString(s, "")
	}
	out := BootPlan{Order: []BootEntry{}, NotStarted: []BootSkip{}}
	skip := func(key, why string) {
		j := by[key]
		out.NotStarted = append(out.NotStarted, BootSkip{Project: j.Project, Jail: j.Name, Reason: why})
	}
	for _, k := range sortedStrings(skipped) {
		skip(k, reasonText(by[k].Project, skipped[k]))
	}
	failed := map[string]string{}
	for _, k := range order {
		j := by[k]
		blocked := ""
		for _, d := range j.Boot.Depends {
			if _, f := failed[d]; f {
				blocked = d
				break
			}
		}
		switch {
		case blocked != "":
			failed[k] = "dependency"
			why := "which does not start"
			if failed[blocked] == "locked" {
				why = "which waits for its passphrase"
			}
			skip(k, fmt.Sprintf("depends on %s, %s", name(blocked), why))
		case j.Encrypted:
			failed[k] = "locked"
			skip(k, "waits for the passphrase of an encrypted volume (jailops volume unlock VOLUME), then starts")
		default:
			reason := "autostart"
			if !j.Boot.Autostart {
				reason = "dependency of " + name(needed[k])
			}
			var deps []string
			for _, d := range j.Boot.Depends {
				deps = append(deps, name(d))
			}
			out.Order = append(out.Order, BootEntry{Project: j.Project, Jail: j.Name, Priority: j.Boot.Priority, Depends: deps, Reason: reason, Running: j.Running})
		}
	}
	return out.numbered()
}

func sortedStrings(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (p BootPlan) numbered() BootPlan {
	for i := range p.Order {
		p.Order[i].Position = i + 1
	}
	return p
}

// Visible returns the plan of the jails of the projects ok accepts, in the same order and numbered again.
func (p BootPlan) Visible(ok func(project string) bool) BootPlan {
	out := BootPlan{Order: []BootEntry{}, NotStarted: []BootSkip{}}
	for _, e := range p.Order {
		if ok(e.Project) {
			out.Order = append(out.Order, e)
		}
	}
	for _, s := range p.NotStarted {
		if ok(s.Project) {
			out.NotStarted = append(out.NotStarted, s)
		}
	}
	return out.numbered()
}

// StopOrder returns the order in which running jails are stopped when the host shuts down: the reverse of the order
// they would start in, so a jail stops before the jails it depends on, and among the jails that depend on nothing
// the one with the higher boot.priority stops first, then the name in reverse. Every jail passed is stopped, with or
// without autostart. A dependency on a jail that is not in the list is ignored (it is not running). The members of a
// dependency cycle have no order that is better than another: they stop last, by name.
func StopOrder(running []BootNode) []string {
	in := map[string]bool{}
	for _, j := range running {
		in[j.Key] = true
	}
	nodes := make([]BootNode, 0, len(running))
	for _, j := range running {
		n := BootNode{Key: j.Key, Boot: BootPolicy{Autostart: true, Priority: j.Boot.Priority}}
		for _, d := range j.Boot.Depends {
			if in[d] && d != j.Key {
				n.Boot.Depends = append(n.Boot.Depends, d)
			}
		}
		nodes = append(nodes, n)
	}
	order, skipped := BootOrder(nodes, nil)
	slices.Reverse(order)
	var cyc []string
	for k := range skipped {
		cyc = append(cyc, k)
	}
	slices.Sort(cyc)
	return append(order, cyc...)
}
