package priv

import (
	"context"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/run"
)

// staleMountTypes are the kinds of mount JailOps puts below the root of a jail (devfs, fdescfs, the Linux file
// systems, nullfs for volumes and host directories, tmpfs). A dataset is never one of them.
var staleMountTypes = []string{"devfs", "fdescfs", "linprocfs", "linsysfs", "procfs", "nullfs", "tmpfs"}

// stalePasses is how many times the mount table is read again: mounts stacked on one directory come off one layer at
// a time.
const stalePasses = 8

// cleanStaleMounts unmounts every mount below the root of the jail, deepest first, until none is left: the leftovers
// of a stop that did not finish (a devfs under root/dev, stacked once more by each failed stop). Such a mount keeps
// the root dataset busy for good. The jail does not run when this is called, and the hooks of jail(8) never call it:
// jail(8) mounts its own devfs before exec.prestart and takes it off after exec.poststop, so a cleanup inside a hook
// would take away the mounts of the very jail that is being made or removed. It is called by the unmount of the datasets
// of a jail that does not run and by mounts.heal, before `jail -c` and by the daemon. Only mounts below this jail's own
// root are touched, found in the mount table of the host and not in the fstab. It returns the mount points it could
// not unmount.
func (l *Local) cleanStaleMounts(ctx context.Context, jn JailName) []string {
	var left []string
	for pass := 0; pass < stalePasses; pass++ {
		res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "mount", Args: []string{"-p"}, Timeout: 10 * time.Second})
		if err != nil {
			l.note("the mount table could not be read: stale mounts are not looked for", "jail", jn.Internal(), "err", err.Error())
			return nil
		}
		mps := l.jailMounts(string(res.Stdout), jn)
		if len(mps) == 0 {
			return nil
		}
		left = left[:0]
		for _, mp := range mps {
			if _, err := l.d.Runner.Run(ctx, run.Cmd{Name: "umount", Args: []string{mp}, Timeout: 20 * time.Second}); err != nil {
				if _, err := l.d.Runner.Run(ctx, run.Cmd{Name: "umount", Args: []string{"-f", mp}, Timeout: 20 * time.Second}); err != nil {
					left = append(left, mp)
				}
			}
		}
	}
	return left
}

// jailMounts picks, from the output of mount -p, the mount points of the kinds JailOps makes that lie strictly below
// the root of jn, one entry per mount (a directory with two stacked mounts is listed twice), deepest first.
func (l *Local) jailMounts(table string, jn JailName) []string {
	var out []string
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !slices.Contains(staleMountTypes, f[2]) {
			continue
		}
		key, err := l.cfg.jailOfRoot(f[1])
		if err != nil || key != jn.Internal() {
			continue
		}
		out = append(out, f[1])
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

var reJailDataset = regexp.MustCompile(`/projects/([^/]+)/jails/([^/]+)(/|$)`)

// cleanStaleMountsOfDataset cleans the stale mounts below the root of the jail a dataset belongs to, when that jail
// does not run: a running jail's mounts are its own.
func (l *Local) cleanStaleMountsOfDataset(ctx context.Context, dataset string) {
	m := reJailDataset.FindStringSubmatch(dataset)
	if m == nil {
		return
	}
	jn, err := ParseJailName(m[1] + "_" + m[2])
	if err != nil {
		return
	}
	list, err := l.d.Jails.List(ctx)
	if err != nil {
		return // not known whether it runs: nothing is touched
	}
	for _, j := range list {
		if j.Name == jn.Internal() {
			return
		}
	}
	l.cleanStaleMounts(ctx, jn)
}

// StaleMount is one mount below the root of a jail that does not run.
type StaleMount struct {
	Jail string `json:"jail"`
	Path string `json:"path"`
	Type string `json:"type"`
}

// StaleMountsRes is the reply of mounts.stale.
type StaleMountsRes struct {
	Mounts []StaleMount `json:"mounts"`
}

// HealJailReq asks jail.heal to clean up after one jail.
type HealJailReq struct {
	Jail string `json:"jail"`
}

// HealJailRes says what jail.heal took off below the root and what it could not, and what went wrong in the rest.
type HealJailRes struct {
	Unmounted []string `json:"unmounted,omitempty"`
	Left      []string `json:"left,omitempty"`
	Errors    []string `json:"errors,omitempty"`
}

// runningJailNames is the set of jails that run now; an error is "not known", and then nothing is touched.
func (l *Local) runningJailNames(ctx context.Context) (map[string]bool, error) {
	list, err := l.d.Jails.List(ctx)
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for _, j := range list {
		m[j.Name] = true
	}
	return m, nil
}

// StaleMounts implements Host: every mount of the kinds JailOps makes below the root of a managed jail that does not
// run, read from the mount table. Read-only.
func (l *Local) StaleMounts(ctx context.Context) ([]StaleMount, error) {
	running, err := l.runningJailNames(ctx)
	if err != nil {
		return nil, err
	}
	res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "mount", Args: []string{"-p"}, Timeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	var out []StaleMount
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !slices.Contains(staleMountTypes, f[2]) {
			continue
		}
		key, err := l.cfg.jailOfRoot(f[1])
		if err != nil || running[key] {
			continue
		}
		out = append(out, StaleMount{Jail: key, Path: f[1], Type: f[2]})
	}
	return out, nil
}

// HealJail implements Host: the stale mounts below the root of a jail that does not run are taken off (never from a
// hook of jail(8): see cleanStaleMounts), and the poststop hook is run for it, which is idempotent: rctl rules, the pf
// anchor and the links that a stop, a failed start or a death of jail(8) left are removed.
func (l *Local) HealJail(ctx context.Context, jail string) (HealJailRes, error) {
	jn, err := ParseJailName(jail)
	if err != nil {
		return HealJailRes{}, err
	}
	running, err := l.runningJailNames(ctx)
	if err != nil {
		return HealJailRes{}, err
	}
	if running[jn.Internal()] {
		return HealJailRes{}, forbiddenBusy("jail %s runs: its mounts and links are its own", jail)
	}
	before, err := l.StaleMounts(ctx)
	if err != nil {
		return HealJailRes{}, err
	}
	var mine []string
	for _, m := range before {
		if m.Jail == jn.Internal() {
			mine = append(mine, m.Path)
		}
	}
	left := l.cleanStaleMounts(ctx, jn)
	var res HealJailRes
	for _, p := range mine {
		if !slices.Contains(left, p) {
			res.Unmounted = append(res.Unmounted, p)
		}
	}
	res.Left = left
	if err := l.RunHook(ctx, PhasePostStop, jail); err != nil {
		res.Errors = append(res.Errors, err.Error())
	}
	return res, nil
}
