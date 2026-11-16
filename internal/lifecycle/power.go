package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

func (s *Service) ready(ctx context.Context, name string) (*jailState, error) {
	st, err := s.observe(ctx, name)
	if err != nil {
		return nil, err
	}
	if !st.Complete {
		return nil, api.Errorf(api.CodeBusy, "jail %q was not created completely", name).WithHint("destroy it or run recovery")
	}
	return st, nil
}

// PlanStart orders a start: mount the persistent datasets, render the
// configuration through the hooks, create the jail with jail(8) and check
// readiness. A failure undoes everything in reverse.
func (s *Service) PlanStart(ctx context.Context, name string) (*plan.Plan, error) {
	if _, err := s.ready(ctx, name); err != nil {
		return nil, err
	}
	return plan.New("start-jail "+name,
		plan.Step{Name: "mount", Describe: "zfs mount root, persistent datasets and volumes of " + name,
			Do:   func(ctx context.Context) error { return s.mountTree(ctx, name) },
			Undo: func(ctx context.Context) error { return s.unmountTree(ctx, name) }, UndoOnFail: true},
		// Before jail(8) makes the devfs of this start (it does that before the hooks run): what an earlier stop that did
		// not finish left below the root would be stacked under it. Best effort; the helper touches a jail that does not
		// run only.
		plan.Step{Name: "heal-mounts", Describe: "take the mounts a stop that did not finish left below the root of " + name + " off",
			Do: func(ctx context.Context) error {
				if s.Files != nil {
					_, _ = s.Files.HealJail(ctx, name)
				}
				return nil
			}},
		plan.Step{Name: "render", Describe: "render jail.conf, rc.conf and firewall anchor for " + name,
			Do:   func(ctx context.Context) error { return s.Hooks.PreStart(ctx, name) },
			Undo: func(ctx context.Context) error { return s.Hooks.PostStop(ctx, name) }},
		plan.Step{Name: "jail-start", Describe: "jail -c " + name,
			Do: func(ctx context.Context) error { return s.Jails.Start(ctx, name) },
			// Jails.Stop succeeds when the jail is not running, so this is safe
			// even if jail(8) failed half-way.
			Undo: func(ctx context.Context) error { return s.stopJail(ctx, name) }, UndoOnFail: true},
		plan.Step{Name: "ready", Describe: fmt.Sprintf("wait until %s runs (timeout %s)", name, s.Cfg.ReadyTimeout),
			Do: func(ctx context.Context) error { return s.waitReady(ctx, name) }},
	), nil
}

// StartJail starts a jail. Starting a running jail does nothing.
func (s *Service) StartJail(ctx context.Context, name string) error {
	p, err := s.PlanStart(ctx, name)
	if err != nil {
		return err
	}
	// Refused here, not in PlanStart: the plan is rebuilt to roll an interrupted start back after a reboot, when the
	// keys are not loaded.
	if st, err := s.observe(ctx, name); err != nil {
		return err
	} else if err := s.refuseLocked(ctx, st); err != nil {
		return err
	}
	if up, err := s.Jails.Running(ctx, name); err != nil {
		return err
	} else if up {
		return nil
	}
	return s.run(ctx, "start", name, p)
}

// stopJail removes the jail. A stop that did not finish within its budget and was forced (the helper removed the jail
// without its stop commands and killed what was left) is a stop with a warning, not a failure: the event names what
// still ran.
func (s *Service) stopJail(ctx context.Context, name string) error {
	err := s.Jails.Stop(ctx, name)
	if api.IsCode(err, api.CodeStopForced) {
		if s.Warn != nil {
			s.Warn(ctx, name, "jail-stop-forced", err.Error())
		}
		return nil
	}
	return err
}

// cleanAfterFailedStop cleans up after a jail that jail(8) failed to remove cleanly but that does not run any more (the
// removal went through and one of its own unmounts or hooks did not): what it left (a devfs, rctl rules, the anchor, the
// links) is taken away now and not at the next stop. Best effort.
func (s *Service) cleanAfterFailedStop(ctx context.Context, name string, stopErr error) {
	if stopErr == nil {
		return
	}
	if up, err := s.Jails.Running(ctx, name); err == nil && !up {
		_ = s.Hooks.PostStop(ctx, name)
	}
}

// stopUnmountBudget is how long a stop waits in all for the datasets of the jail to be released after its processes died.
var stopUnmountBudget = 5 * time.Second

// StopJail stops a jail, tears down its rendered state and unmounts its
// datasets. It is idempotent: each step is safe to repeat after a failure.
func (s *Service) StopJail(ctx context.Context, name string) error {
	if _, err := s.observe(ctx, name); err != nil {
		return err
	}
	p := plan.New("stop-jail "+name,
		plan.Step{Name: "jail-stop", Describe: "jail -r " + name + " (if running)",
			Do: func(ctx context.Context) error {
				if up, err := s.Jails.Running(ctx, name); err != nil || !up {
					return err
				}
				err := s.stopWithLostHostDirs(ctx, name)
				s.cleanAfterFailedStop(ctx, name, err)
				return err
			}},
		plan.Step{Name: "teardown", Describe: "remove runtime state of " + name,
			Do: func(ctx context.Context) error { return s.Hooks.PostStop(ctx, name) }},
		plan.Step{Name: "unmount", Describe: "zfs unmount the tree of " + name,
			Do: func(ctx context.Context) error {
				// The jail is gone. A root that stays busy for a while after its processes died (seen right after an
				// app install) is not a failed stop: the datasets stay mounted until the next start or stop, which
				// are idempotent, and the helper has logged the refusal. A stop never waits for it longer than
				// stopUnmountBudget in all, whatever the number of datasets: the retries of every dataset share it.
				budget, cancel := context.WithTimeout(ctx, stopUnmountBudget)
				defer cancel()
				err := s.unmountTree(budget, name)
				if err != nil && (api.IsCode(err, api.CodeBusy) || (budget.Err() != nil && ctx.Err() == nil)) {
					if s.Warn != nil {
						s.Warn(ctx, name, "jail-unmount-busy", "the datasets of the stopped jail stay mounted, something still holds them"+s.mountsUnder(ctx, name))
					}
					return nil
				}
				return err
			}})
	return s.run(ctx, "stop", name, p)
}

// DestroyResult is the outcome of DestroyJail.
type DestroyResult struct {
	Plan     []string
	Warnings []string
}

// DestroyJail destroys a jail and every dataset below its container. A running
// jail is refused unless force is set. A snapshot of the jail that has a clone
// outside the jail refuses the destroy (the clone would lose its origin).
func (s *Service) DestroyJail(ctx context.Context, name string, force, dryRun bool) (DestroyResult, error) {
	var res DestroyResult
	st, err := s.observe(ctx, name)
	if err != nil {
		return res, err
	}
	up, err := s.Jails.Running(ctx, name)
	if err != nil {
		return res, err
	}
	if up && !force {
		return res, api.Errorf(api.CodeBusy, "jail %q is running", name).WithHint("stop it or use force")
	}
	inTree := func(ds string) bool { return ds == st.Container || strings.HasPrefix(ds, st.Container+"/") }
	all, err := s.ZFS.Descendants(ctx, st.Container)
	if err != nil {
		return res, err
	}
	for _, ds := range append([]string{st.Container}, all...) {
		snaps, err := s.ZFS.Snapshots(ctx, ds)
		if err != nil {
			return res, err
		}
		for _, sn := range snaps {
			cl, err := s.ZFS.Clones(ctx, ds+"@"+sn)
			if err != nil {
				return res, err
			}
			for _, c := range cl {
				if !inTree(c) {
					return res, api.Errorf(api.CodeBusy, "%s@%s has a clone %s outside the jail", ds, sn, c)
				}
			}
		}
	}
	pl := plan.New("destroy-jail " + name)
	if up {
		pl.Add(plan.Step{Name: "stop", Describe: "jail -r " + name,
			Do:   func(ctx context.Context) error { return s.doStop(ctx, name) },
			Undo: func(ctx context.Context) error { return s.doStart(ctx, name) }, UndoOnFail: true})
	}
	// A jail that is not running has had its runtime state taken down when it stopped, unless it was stopped by hand or
	// crashed: the rctl rules of its limits stay by name, so a delete takes the runtime state down again. A failure is a
	// warning, it does not stop the delete.
	var teardownErr, removeErr error
	pl.Add(plan.Step{Name: "teardown", Describe: "remove runtime state of " + name + " (rctl rules, pf anchor, links, mounts)",
		Do: func(ctx context.Context) error { teardownErr = s.Hooks.PostStop(ctx, name); return nil }})
	// The rendered configuration goes before the datasets, not after the point of no return: a delete that dies in
	// between would leave it for good, while a jail that survives a failed destroy renders it again at its next start.
	pl.Add(plan.Step{Name: "remove-config", Describe: "remove the rendered configuration of " + name,
		Do: func(ctx context.Context) error {
			if removeErr = s.Hooks.Remove(ctx, name); removeErr != nil {
				removeErr = s.Hooks.Remove(ctx, name) // once more: a failure of the files is most often not for good
			}
			return nil
		}})
	pl.Add(plan.Step{Name: "destroy-datasets", Describe: "zfs destroy -r " + st.Container,
		Do: func(ctx context.Context) error {
			if s.prop(ctx, st.Container, PropManaged) != "on" {
				return api.Errorf(api.CodeForbidden, "%s is not managed by JailOps", st.Container)
			}
			return s.ZFS.DestroyRecursive(ctx, st.Container)
		}})
	res.Plan = pl.Describe()
	if dryRun {
		return res, nil
	}
	if err := s.run(ctx, "destroy", name, pl); err != nil {
		return res, err
	}
	if teardownErr != nil {
		res.Warnings = append(res.Warnings, "remove runtime state: "+teardownErr.Error())
	}
	if removeErr != nil {
		res.Warnings = append(res.Warnings, "remove rendered configuration: "+removeErr.Error())
	}
	// Generation garbage collection happens after the point of no return; a failure is reported, it cannot undo the destroy.
	if _, err := s.Images.Collect(ctx); err != nil {
		res.Warnings = append(res.Warnings, "collect parked generations: "+err.Error())
	}
	return res, nil
}

// stopWithLostHostDirs stops a jail. When the mount under a host directory was taken away by the system (a box that
// failed is unmounted by force, and the nullfs mounts on it go with it), jail(8) cannot unmount the fstab line and
// refuses to remove the jail: "<target>: not a mount point". Each target it names is given a small tmpfs, so that the
// line has a mount to unmount, and the stop is tried again; the placeholders are removed again when the jail is gone.
func (s *Service) stopWithLostHostDirs(ctx context.Context, name string) (err error) {
	st, oerr := s.observe(ctx, name)
	if oerr != nil {
		return oerr
	}
	var placeholders []string
	defer func() {
		for _, target := range placeholders {
			_, _ = s.Exec.Run(ctx, []string{"umount", "-f", target}) // gone with the jail's own unmount, or here
		}
	}()
	err = s.stopJail(ctx, name)
	for range len(st.HostDirs) {
		if err == nil || !strings.Contains(err.Error(), "not a mount point") {
			return err
		}
		placed := false
		for _, h := range st.HostDirs {
			target := s.Cfg.at(name).rootMP() + h.Path
			if !strings.Contains(err.Error(), target+": not a mount point") {
				continue
			}
			if out, merr := s.Exec.Run(ctx, []string{"mount", "-t", "tmpfs", "-o", "size=1m", "tmpfs", target}); merr != nil {
				return fmt.Errorf("%w (and a placeholder for %s: %v: %s)", err, target, merr, strings.TrimSpace(string(out)))
			}
			placeholders = append(placeholders, target)
			placed = true
		}
		if !placed {
			return err
		}
		err = s.stopJail(ctx, name)
	}
	return err
}

// mountsUnder names the mounts that sit below the root of the jail (nullfs, devfs, fdescfs, a host directory): what
// holds a root busy after its jail is gone is most often one of them. Read-only; "" when the list cannot be read.
func (s *Service) mountsUnder(ctx context.Context, name string) string {
	out, err := s.Exec.Run(ctx, []string{"mount", "-p"})
	if err != nil {
		return ""
	}
	root := s.Cfg.at(name).rootMP()
	var found []string
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && strings.HasPrefix(f[1], root+"/") {
			found = append(found, f[2]+" "+f[1])
		}
	}
	if len(found) == 0 {
		return ""
	}
	return ": " + strings.Join(found, ", ")
}
