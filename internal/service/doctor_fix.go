package service

import (
	"context"
	"sort"
	"strings"
	"time"

	"jailops.net/jailops/internal/mounts"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// staleMountsByJail groups the mounts below the roots of stopped jails (what a stop that did not finish left) by jail.
func (s *Service) staleMountsByJail(ctx context.Context) (map[string][]string, error) {
	out := map[string][]string{}
	if s.d.Files == nil {
		return out, nil
	}
	ms, err := s.d.Files.StaleMounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		out[m.Jail] = append(out[m.Jail], m.Type+" "+m.Path)
	}
	return out, nil
}

func sortedJails(m map[string][]string) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// HealLeftovers takes the stale mounts off the roots of the jails that do not run (a devfs under root/dev that a failed
// stop left, stacked once more by each failed stop, keeps the root busy for good) and says so with a warning and an
// event for each jail. The daemon calls it at its start and now and then; a jail that runs is never touched. It returns
// the number of mounts it took off.
func (s *Service) HealLeftovers(ctx context.Context) int {
	found, err := s.staleMountsByJail(ctx)
	if err != nil || len(found) == 0 {
		return 0
	}
	n := 0
	for _, key := range sortedJails(found) {
		res, err := s.healJailMounts(ctx, key)
		if err != nil {
			s.log.Warn("stale mounts below the root of a stopped jail could not be taken off", "jail", key, "err", err)
			continue
		}
		n += len(res.Unmounted)
		s.log.Warn("stale mounts below the root of a stopped jail were taken off", "jail", key,
			"unmounted", strings.Join(res.Unmounted, ", "), "left", strings.Join(res.Left, ", "))
		project, name := validate.SplitQualified(key)
		s.emitIn(ctx, project, "jail-stale-mounts-cleaned", "/api/v1/jails/"+name)
	}
	return n
}

// doctorMounts reports the stale mounts below the roots of stopped jails.
func (s *Service) doctorMounts(ctx context.Context, c *checkSet) {
	found, err := s.staleMountsByJail(ctx)
	if err != nil {
		c.add("mounts.leftovers", api.DoctorUnknown, err.Error(), "")
		return
	}
	if len(found) == 0 {
		c.add("mounts.leftovers", api.DoctorOK, "no mount is left below the root of a stopped jail", "")
		return
	}
	var parts []string
	for _, key := range sortedJails(found) {
		parts = append(parts, key+": "+strings.Join(found[key], ", "))
	}
	c.add("mounts.leftovers", api.DoctorWarn,
		"mounts below the root of stopped jails (a stop that did not finish leaves them, and they keep the root busy): "+strings.Join(parts, "; "),
		"run `jailops doctor --fix` (it unmounts them; a jail that runs is never touched); the daemon also takes them off at its start and at the next start or stop of the jail")
}

// DoctorFix performs the safe cleanups the diagnostics report, or with dryRun only lists them: the stale mounts below
// the roots of stopped jails. What an earlier network layout left (an old bridge and its gateway pair) is listed with
// the commands that remove it, for the operator to run once the jails that still hang on it were restarted. It never
// touches the objects of a jail that runs, and it can be run again.
func (s *Service) DoctorFix(ctx context.Context, dryRun bool) (api.DoctorFixResult, error) {
	res := api.DoctorFixResult{DryRun: dryRun, Actions: []api.DoctorFixAction{}}
	found, err := s.staleMountsByJail(ctx)
	if err != nil {
		return res, err
	}
	for _, key := range sortedJails(found) {
		act := api.DoctorFixAction{Check: "mounts.leftovers", What: "unmount " + strings.Join(found[key], ", ") + " (jail " + key + ")"}
		if !dryRun {
			r, herr := s.healJailMounts(ctx, key)
			switch {
			case herr != nil:
				act.Error = herr.Error()
			case len(r.Left) > 0:
				act.Error = "still mounted: " + strings.Join(r.Left, ", ")
			default:
				act.Done = true
				project, name := validate.SplitQualified(key)
				s.emitIn(ctx, project, "jail-stale-mounts-cleaned", "/api/v1/jails/"+name)
			}
		}
		res.Actions = append(res.Actions, act)
	}
	// the interfaces of the earlier network layout that no jail that runs uses; a bridge that a jail which runs still hangs
	// on stays until that jail is restarted
	c := &checkSet{}
	s.doctorOldNetwork(ctx, c)
	for _, ck := range c.list {
		if ck.Name != "network.leftovers" || ck.Status != api.DoctorWarn {
			continue
		}
		if dryRun {
			res.Actions = append(res.Actions, api.DoctorFixAction{Check: "network.leftovers", What: "destroy the interfaces that no jail which runs uses: " + ck.Message})
			continue
		}
		r, herr := s.d.Files.HealNetwork(ctx)
		for _, n := range r.Destroyed {
			res.Actions = append(res.Actions, api.DoctorFixAction{Check: "network.leftovers", What: "destroy " + n, Done: true})
			s.emitIn(ctx, "", "network-leftover-destroyed", "/api/v1/networks")
		}
		for _, sk := range r.Skipped {
			res.Actions = append(res.Actions, api.DoctorFixAction{Check: "network.leftovers", What: "left " + sk, Error: "restart the jails that run on it, then run doctor --fix again"})
		}
		if herr != nil {
			res.Actions = append(res.Actions, api.DoctorFixAction{Check: "network.leftovers", What: "destroy the interfaces", Error: herr.Error()})
		}
		break
	}
	return res, nil
}

// healInterval is how often the stopped jails are looked at for stale mounts after the first look at the daemon's start.
var healInterval = 10 * time.Minute

// healLoop cleans up once the daemon has started (every jail that does not run, and the interfaces of the earlier network
// layout) and again every few minutes (the jails with stale mounts, and the interfaces): a stop that failed while the
// daemon ran leaves them too.
func (s *Service) healLoop(ctx context.Context) {
	s.healAllStopped(ctx)
	for {
		s.HealLeftovers(ctx)
		s.HealNetworkLeftovers(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(healInterval):
		}
	}
}

// healAllStopped runs the clean-up after every jail that does not run: the helper refuses the ones that run.
func (s *Service) healAllStopped(ctx context.Context) {
	s.mu.RLock()
	keys := make([]string, 0, len(s.jails))
	for k := range s.jails {
		keys = append(keys, k)
	}
	s.mu.RUnlock()
	sort.Strings(keys)
	for _, key := range keys {
		if ctx.Err() != nil {
			return
		}
		res, err := s.healJailMounts(ctx, key)
		if err != nil || len(res.Unmounted) == 0 {
			continue
		}
		s.log.Warn("stale mounts below the root of a stopped jail were taken off", "jail", key, "unmounted", strings.Join(res.Unmounted, ", "))
		project, name := validate.SplitQualified(key)
		s.emitIn(ctx, project, "jail-stale-mounts-cleaned", "/api/v1/jails/"+name)
	}
}

// HealNetworkLeftovers destroys the interfaces of the earlier network layout (a bridge and the gateway pair of a network)
// that no jail that runs uses, with a warning and an event for each. It returns how many it destroyed.
func (s *Service) HealNetworkLeftovers(ctx context.Context) int {
	if s.d.Files == nil {
		return 0
	}
	res, err := s.d.Files.HealNetwork(ctx)
	if err != nil {
		s.log.Warn("the interfaces of the earlier network layout could not be looked at", "err", err)
		return 0
	}
	for _, n := range res.Destroyed {
		s.log.Warn("an interface of the earlier network layout was destroyed", "interface", n)
		s.emitIn(ctx, "", "network-leftover-destroyed", "/api/v1/networks")
	}
	return len(res.Destroyed)
}

// healJailMounts cleans up after one jail under the lock of the jail: a start or a stop that is going on has its own
// mounts and links, and the jail is not in the kernel's list yet while jail(8) makes its devfs.
func (s *Service) healJailMounts(ctx context.Context, key string) (mounts.Healed, error) {
	unlock, err := s.locks.tryLock("heal jail "+key, jailLock(key))
	if err != nil {
		return mounts.Healed{}, err // busy: something is going on with the jail, the next look finds what is left
	}
	defer unlock()
	return s.d.Files.HealJail(ctx, key)
}
