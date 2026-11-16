package reconcile

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

// StartOrder returns the jails to start, in order, given the jails and the set already running (the rules are those
// of api.BootOrder, which the boot plan of the API shares).
func StartOrder(jails []JailDesired, running map[string]bool) (order []string, skipped map[string]string) {
	nodes := make([]api.BootNode, len(jails))
	for i, j := range jails {
		nodes[i] = api.BootNode{Key: j.Name, Boot: j.Boot}
	}
	return api.BootOrder(nodes, running)
}

// hostBooted says whether the host booted since the boot pass last ran (and records the boot it ran for): a daemon that
// starts again on a host that stayed up leaves the jails as they are.
func (r *Reconciler) hostBooted(ctx context.Context) bool {
	f := r.cfg.BootStateFile
	if f == "" {
		return true
	}
	prev, err := os.ReadFile(f)
	known := err == nil
	id := ""
	if r.env.Sysctl != nil {
		id, _ = r.env.Sysctl(ctx, "kern.boottime")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		// the boot of the host cannot be read: a first start still boots the jails, a later one does not
		return !known
	}
	if known && sameBoot(strings.TrimSpace(string(prev)), id) {
		r.log.Info("the daemon started again on a host that stayed up: no jail is started at boot")
		if strings.TrimSpace(string(prev)) != id { // the clock was set: keep the new reading
			_ = os.WriteFile(f, []byte(id+"\n"), 0o600)
		}
		return false
	}
	if err := os.WriteFile(f, []byte(id+"\n"), 0o600); err != nil {
		r.log.Warn("the boot of the host could not be recorded", "err", err)
	}
	return true
}

func (r *Reconciler) bootPass(ctx context.Context, des Desired, obs *Observed, rep *Report, now time.Time) {
	running := map[string]bool{}
	for n := range obs.Running {
		running[n] = true
	}
	order, skipped := StartOrder(des.Jails, running)
	r.mu.Lock()
	for n, why := range skipped {
		r.bootCond[n] = cond(CondBoot, false, "NotStarted", why, now)
		rep.Failures["jail/"+n] = why
	}
	r.mu.Unlock()
	failed := map[string]bool{}
	by := map[string]JailDesired{}
	for _, j := range des.Jails {
		by[j.Name] = j
	}
	for _, name := range order {
		blocked := ""
		for _, d := range by[name].Boot.Depends {
			if failed[d] {
				blocked = d
			}
		}
		if blocked != "" {
			failed[name] = true
			r.setBootCond(name, cond(CondBoot, false, "DependencyFailed", fmt.Sprintf("dependency %q did not start", blocked), now))
			continue
		}
		if err := r.env.Actions.StartJail(ctx, name); err != nil {
			failed[name] = true
			if api.IsCode(err, api.CodeLocked) {
				// Not a failure: the jail waits for the passphrase of an encrypted volume and starts after its unlock.
				r.setBootCond(name, cond(CondBoot, false, "Locked", "waiting for the passphrase of an encrypted volume (jailops volume unlock)", now))
				continue
			}
			rep.Failures["jail/"+name] = err.Error()
			r.setBootCond(name, cond(CondBoot, false, "StartFailed", err.Error(), now))
			continue
		}
		rep.Started = append(rep.Started, name)
		r.setBootCond(name, cond(CondBoot, true, "Started", "started at boot", now))
	}
}

func (r *Reconciler) setBootCond(name string, c api.Condition) {
	r.mu.Lock()
	r.bootCond[name] = c
	r.mu.Unlock()
}

var bootSecRE = regexp.MustCompile(`sec = (\d+)`)

// sameBoot says whether two readings of kern.boottime are the same boot of the host. FreeBSD moves the boot time when
// the clock is set (ntpd, ntpdate), so the readings of one boot can differ by the step; a host that rebooted was down
// for longer than ten minutes between two readings.
func sameBoot(prev, now string) bool {
	if prev == now {
		return true
	}
	a, b := bootSecRE.FindStringSubmatch(prev), bootSecRE.FindStringSubmatch(now)
	if a == nil || b == nil {
		return false
	}
	x, err1 := strconv.ParseInt(a[1], 10, 64)
	y, err2 := strconv.ParseInt(b[1], 10, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	d := x - y
	if d < 0 {
		d = -d
	}
	return d <= 600
}
