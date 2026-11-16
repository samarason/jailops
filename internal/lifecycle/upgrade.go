package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

// UpgradeRequest is api.JailUpgrade plus a Stamp that names the plan's
// snapshots. Persist the request with the journal record and pass the same
// Stamp when rebuilding the plan for crash recovery; empty means "now".
type UpgradeRequest struct {
	api.JailUpgrade
	Stamp string
	// Resume rebuilds the plan after a crash from the state recorded by the
	// original run (UpgradeResult.State). Preflight and the "already current"
	// check are skipped; use it only to roll an interrupted run back.
	Resume *SwitchState
}

// SwitchState is what a plan needs that the pool no longer shows once the
// plan has started. Persist it with the journal record.
type SwitchState struct {
	FromGen    int    `json:"from_gen"`
	Manifest   string `json:"manifest"`
	WasRunning bool   `json:"was_running"`
	// Bundle is the bundle.json content before the switch, restored by undo.
	Bundle []byte `json:"bundle,omitempty"`
}

// UpgradeResult is the outcome of an upgrade (or a root rollback).
type UpgradeResult struct {
	// Changed is false when the jail already uses the target generation.
	Changed  bool
	From, To string
	Plan     []string
	// Snapshot is the atomic pre-upgrade snapshot (the rollback point).
	Snapshot string
	Warnings []string
	// Stamp names the plan's snapshots; Finish uses it.
	Stamp string
	// State must be persisted with the journal record, see SwitchState.
	State SwitchState
}

var genArgRe = regexp.MustCompile(`^g[0-9]+$`)

func (s *Service) stamp(req string) string {
	if req != "" {
		return req
	}
	return strconv.FormatInt(s.Cfg.now().Unix(), 10)
}

func genName(image string, n int) string { return fmt.Sprintf("%s#g%d", image, n) }

// UpgradeJail upgrades a thin jail to a newer generation of its image
// (design 4.3, strategy rebase), or reports Changed=false when it is current.
func (s *Service) UpgradeJail(ctx context.Context, name string, req UpgradeRequest) (UpgradeResult, error) {
	p, res, err := s.PlanUpgrade(ctx, name, req)
	if err != nil {
		return *res, err
	}
	if p == nil || req.DryRun {
		return *res, nil
	}
	if err = s.run(ctx, "upgrade", name, p); err != nil {
		return *res, err
	}
	s.FinishSwitch(ctx, name, res)
	return *res, nil
}

// FinishSwitch is the best-effort work after a successful upgrade or root
// rollback: drop the merge snapshots (the undo of a crashed plan needs them
// until the plan is journalled as finished) and stop the jail again if it was
// stopped before. Failures become warnings; they cannot undo the switch. A
// caller that runs the plan itself must call it after the plan succeeds.
func (s *Service) FinishSwitch(ctx context.Context, name string, res *UpgradeResult) {
	st, err := s.observe(ctx, name)
	if err != nil {
		res.Warnings = append(res.Warnings, err.Error())
		return
	}
	if err := s.dropStale(ctx, st); err != nil {
		res.Warnings = append(res.Warnings, "destroy previous root.old: "+err.Error())
	}
	for _, d := range s.mergeDatasets(st) {
		sn := d + "@jo-merge-" + res.Stamp
		if ok, _ := s.ZFS.Exists(ctx, sn); ok {
			if err := s.ZFS.Destroy(ctx, sn); err != nil {
				res.Warnings = append(res.Warnings, "destroy "+sn+": "+err.Error())
			}
		}
	}
	if !res.State.WasRunning {
		if err := s.doStop(ctx, name); err != nil {
			res.Warnings = append(res.Warnings, "stop after validation: "+err.Error())
		}
	}
}

// PlanUpgrade runs the preflight and builds the plan. The plan is nil when
// there is nothing to do.
func (s *Service) PlanUpgrade(ctx context.Context, name string, req UpgradeRequest) (*plan.Plan, *UpgradeResult, error) {
	res := &UpgradeResult{}
	st, err := s.ready(ctx, name)
	if err != nil {
		return nil, res, err
	}
	// the move ends with a start and a health check: a locked jail cannot have either (a rebuilt plan only rolls back)
	if req.Resume == nil {
		if err := s.refuseLocked(ctx, st); err != nil {
			return nil, res, err
		}
	}
	rec, err := s.readRecord(ctx, name)
	if err != nil {
		return nil, res, fmt.Errorf("read spec.json: %w", err)
	}
	if st.Layout != api.LayoutThin {
		return nil, res, api.Errorf(api.CodeUnsupported, "rebase upgrades apply to thin jails; %s jails update in place, which is not implemented", st.Layout)
	}
	if rec.Spec.Update.Strategy == api.UpdateInPlace {
		return nil, res, api.Errorf(api.CodeUnsupported, "update strategy inplace is not implemented for thin jails")
	}
	ref := rec.Spec.Image
	if g := req.Generation; g != "" {
		switch {
		case strings.ContainsAny(g, "#@"):
			ref = g
		case genArgRe.MatchString(g):
			ref = st.Image + "#" + g
		default:
			return nil, res, api.Errorf(api.CodeInvalid, "bad generation %q", g)
		}
	}
	target, err := s.Images.Ensure(ctx, s.Cfg.at(name).st.Root, ref)
	if err != nil {
		return nil, res, err
	}
	return s.planSwitch(ctx, st, rec, target, "upgrade", req.Stamp, req.Resume, res)
}

// planSwitch builds the plan that moves a thin jail's root to target:
// preflight, snapshot, stop, clone, merge, swap, start, health check. mode is
// "upgrade" or "rollback" (the same plan walks back to an older generation).
func (s *Service) planSwitch(ctx context.Context, st *jailState, rec Record, target api.ImageGeneration, mode, stampIn string, resume *SwitchState, res *UpgradeResult) (*plan.Plan, *UpgradeResult, error) {
	name := st.Name
	if resume != nil {
		cp := *st
		cp.Gen, cp.Manifest = resume.FromGen, resume.Manifest
		st = &cp
	}
	res.From = genName(st.Image, st.Gen)
	res.To = target.Name
	if img, _, _ := strings.Cut(target.Name, "#"); img != st.Image {
		return nil, res, api.Errorf(api.CodeInvalid, "jail %s uses image %s; it cannot switch to %s", name, st.Image, target.Name)
	}
	if resume == nil && target.Number == st.Gen {
		return nil, res, nil
	}
	res.Changed = true
	if resume == nil {
		if err := s.preflight(ctx, st, target); err != nil {
			return nil, res, err
		}
	}
	z := s.ZFS
	stamp := s.stamp(stampIn)
	snapName := "jo-pre-" + mode + "-" + stamp
	mergeSnap := "jo-merge-" + stamp
	res.Snapshot = snapName
	res.Stamp = stamp
	wasRunning := false
	if resume != nil {
		wasRunning = resume.WasRunning
	} else {
		var err error
		if wasRunning, err = s.Jails.Running(ctx, name); err != nil {
			return nil, res, err
		}
	}
	res.State = SwitchState{FromGen: st.Gen, Manifest: st.Manifest, WasRunning: wasRunning}
	pl := plan.New(mode + "-jail " + name)

	// 3. one atomic snapshot over every dataset of the jail
	all := st.all()
	snaps := make([]string, len(all))
	for i, d := range all {
		snaps[i] = d + "@" + snapName
	}
	pl.Add(plan.Step{Name: "snapshot", Describe: "zfs snapshot " + strings.Join(snaps, " ") + "  (one atomic transaction)",
		Do: func(ctx context.Context) error {
			return z.Snapshot(ctx, map[string]string{PropGen: strconv.Itoa(st.Gen), PropImage: st.Image, PropComment: "before " + mode + " to " + target.Name}, snaps...)
		},
		Undo: s.destroySnaps(snaps)})

	// 4. stop
	pl.Add(plan.Step{Name: "stop", Describe: "jail -r " + name + ", unmount (was running: " + strconv.FormatBool(wasRunning) + ")",
		Do: func(ctx context.Context) error { return s.doStop(ctx, name) },
		Undo: func(ctx context.Context) error {
			if !wasRunning {
				return nil
			}
			return s.doStart(ctx, name)
		}, UndoOnFail: true})

	mergeDS := s.mergeDatasets(st)
	dataMerge := map[string]bool{} // the merge datasets that hold data, not configuration
	for _, d := range st.Persist {
		if d.Merge && d.Class != ClassSystem {
			dataMerge[d.DS] = true
		}
	}
	startIdx := -1 // the index of the step that starts the jail on the new generation (set where it is added)
	// the jail has been started on the new generation (or was being): it may have written to its data
	jailRan := func(ctx context.Context) bool { return startIdx >= 0 && plan.BegunSteps(ctx) > startIdx }
	rootMP, newMP := s.Cfg.at(name).rootMP(), s.Cfg.at(name).rootNewMP()
	newDS := s.Cfg.at(name).rootNewDS()

	pl.Add(plan.Step{Name: "mount-old", Describe: "zfs mount root and persistent datasets of " + name,
		Do:   func(ctx context.Context) error { return s.mountTree(ctx, name) },
		Undo: func(ctx context.Context) error { return s.unmountTree(ctx, name) }, UndoOnFail: true})

	// 5. clone the new root
	pl.Add(s.cloneNewRoot(st, rec, target))
	pl.Add(plan.Step{Name: "mount-new", Describe: "zfs mount " + newDS,
		Do: func(ctx context.Context) error { return z.Mount(ctx, newDS) },
		Undo: func(ctx context.Context) error {
			if ok, _ := z.Exists(ctx, newDS); !ok {
				return nil
			}
			return z.Unmount(ctx, newDS)
		}, UndoOnFail: true})

	// 6. three-way merge of /etc. A second snapshot, taken after the stop,
	// bounds what undoing the merge discards: nothing written by the jail.
	var msnaps []string
	for _, d := range mergeDS {
		msnaps = append(msnaps, d+"@"+mergeSnap)
	}
	if len(mergeDS) > 0 {
		pl.Add(plan.Step{Name: "merge-snapshot", Describe: "zfs snapshot " + strings.Join(msnaps, " "),
			Do:   func(ctx context.Context) error { return z.Snapshot(ctx, nil, msnaps...) },
			Undo: s.destroySnaps(msnaps)})
	}
	// The baseline of the merge is the generation the jail runs now. Image
	// generations stay mounted; mounting it is only attempted, and a failure
	// is fine when its /etc is readable anyway.
	oldGen, gerr := s.Images.Resolve(ctx, s.Cfg.at(name).st.Root, genName(st.Image, st.Gen))
	if gerr != nil {
		return nil, res, fmt.Errorf("the current generation %s: %w", genName(st.Image, st.Gen), gerr)
	}
	work := s.Cfg.at(name).containerMP() + "/.merge-" + stamp
	mergeIn := MergeInput{DestRoot: rootMP, NewRoot: newMP, Work: work}
	pl.Add(plan.Step{Name: "locate-baseline", Describe: "mount " + oldGen.Dataset + " if it is not (the baseline of the /etc merge)",
		Do: func(ctx context.Context) error {
			mp := s.prop(ctx, oldGen.Dataset, "mountpoint")
			if mp == "" || mp == "none" || mp == "legacy" || mp == "-" {
				return fmt.Errorf("generation %s has no mountpoint", oldGen.Name)
			}
			if err := z.Mount(ctx, oldGen.Dataset); err != nil {
				if ok, _ := s.Files.Exists(ctx, path.Join(mp, "etc")); !ok {
					return err
				}
			}
			mergeIn.OldRoot = mp
			return nil
		}})
	pl.Add(plan.Step{Name: "merge", Describe: "tar the /etc of " + oldGen.Name + " and " + target.Name + "; etcupdate extract; etcupdate; merge master.passwd and group by key; pwd_mkdb -p",
		Do: func(ctx context.Context) error {
			defer func() { _ = s.Files.RemoveAll(ctx, work) }()
			return s.mergeEtc(ctx, mergeIn, target.Name, res.From)
		},
		Undo: func(ctx context.Context) error {
			_ = s.Files.RemoveAll(ctx, work)
			var errs []error
			for _, d := range mergeDS {
				if ok, _ := z.Exists(ctx, d+"@"+mergeSnap); !ok {
					continue
				}
				// Once the jail has run on the new generation, a dataset of data (/var/db: the databases of the
				// packages) holds what the jail wrote since the snapshot, and a rollback would drop it while /home
				// and the rest keep theirs. Only the configuration is put back then.
				if dataMerge[d] && jailRan(ctx) {
					continue
				}
				if err := z.Rollback(ctx, d+"@"+mergeSnap, false); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		}, UndoOnFail: true})
	pl.Add(plan.Step{Name: "unmount", Describe: "zfs unmount the old and the new root trees",
		Do: func(ctx context.Context) error {
			if err := z.Unmount(ctx, newDS); err != nil {
				return err
			}
			return s.unmountTree(ctx, name)
		}})

	// 7. swap (steps are individually undoable)
	pl.Add(s.swapSteps(st)...)

	// bundle.json records the generation
	var oldBundle []byte
	if resume != nil && len(resume.Bundle) > 0 {
		oldBundle = resume.Bundle
	} else if b, berr := s.Files.ReadFile(ctx, s.Cfg.at(name).bundlePath()); berr == nil {
		oldBundle = b
	} else {
		oldBundle = s.bundleBytes(rec, rec.Spec.Image, st.Image, st.Gen, st.Manifest, "", s.Cfg.now())
	}
	res.State.Bundle = oldBundle
	newBundle := s.bundleBytes(rec, rec.Spec.Image, st.Image, target.Number, target.Manifest, target.Dataset, s.Cfg.now())
	pl.Add(s.bundleStep(name, oldBundle, newBundle))

	// 8. start and health check; failure swaps back (the undo chain)
	startIdx = len(pl.Steps)
	pl.Add(plan.Step{Name: "start", Describe: "mount, render and jail -c " + name + " on " + target.Name,
		Do:   func(ctx context.Context) error { return s.doStart(ctx, name) },
		Undo: func(ctx context.Context) error { return s.doStop(ctx, name) }, UndoOnFail: true})
	hc := strings.Fields(rec.Spec.Update.Healthcheck)
	pl.Add(plan.Step{Name: "health-check", Describe: "jexec " + name + " " + strings.Join(hc, " ") + " (and require the jail to run)",
		Do: func(ctx context.Context) error {
			if up, err := s.Jails.Running(ctx, name); err != nil {
				return err
			} else if !up {
				return fmt.Errorf("jail %s is not running on %s", name, target.Name)
			}
			if len(hc) == 0 {
				return nil
			}
			out, err := s.Jails.Exec(ctx, name, hc)
			if err != nil {
				return fmt.Errorf("health check %q failed: %w: %s", strings.Join(hc, " "), err, strings.TrimSpace(string(out)))
			}
			return nil
		}})

	// 9. root.old is destroyed after the retention period (CleanupRootOld)
	oldDS := s.Cfg.at(name).rootOldDS()
	due := s.Cfg.now().Add(s.Cfg.RootOldRetention).UTC().Format(time.RFC3339)
	pl.Add(plan.Step{Name: "schedule-cleanup", Describe: fmt.Sprintf("zfs set %s=%s %s", PropCleanupAfter, due, oldDS),
		Do: func(ctx context.Context) error { return z.Set(ctx, oldDS, map[string]string{PropCleanupAfter: due}) },
		Undo: func(ctx context.Context) error {
			if ok, _ := z.Exists(ctx, oldDS); !ok {
				return nil
			}
			return z.Inherit(ctx, oldDS, PropCleanupAfter)
		}})
	return pl, res, nil
}

func (s *Service) destroySnaps(snaps []string) func(context.Context) error {
	return func(ctx context.Context) error {
		var errs []error
		for _, sn := range snaps {
			if ok, _ := s.ZFS.Exists(ctx, sn); !ok {
				continue
			}
			if err := s.ZFS.Destroy(ctx, sn); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
}

// cloneNewRoot is "zfs clone <gen>@ro <jail>/root.new".
func (s *Service) cloneNewRoot(st *jailState, rec Record, target api.ImageGeneration) plan.Step {
	newDS := s.Cfg.at(st.Name).rootNewDS()
	props := map[string]string{PropManaged: "on", PropID: st.ID, PropKind: KindRoot, PropName: st.Name,
		"mountpoint": s.Cfg.at(st.Name).rootNewMP(), "canmount": "noauto", PropGen: strconv.Itoa(target.Number),
		PropImage: st.Image, PropManifest: target.Manifest, PropPrevGen: strconv.Itoa(st.Gen)}
	snap := target.Dataset + "@" + roSnap
	return plan.Step{Name: "clone-new-root", Describe: fmt.Sprintf("zfs clone %s %s", snap, newDS),
		Do:   func(ctx context.Context) error { return s.ZFS.Clone(ctx, snap, newDS, props) },
		Undo: s.destroyIfExists(newDS)}
}

// swapSteps replaces root with root.new and keeps the old root as root.old.
// Every step undoes itself, so a failure anywhere restores the old root.
func (s *Service) swapSteps(st *jailState) []plan.Step {
	z := s.ZFS
	name := st.Name
	rootDS, newDS, oldDS, staleDS := s.Cfg.at(name).rootDS(), s.Cfg.at(name).rootNewDS(), s.Cfg.at(name).rootOldDS(), s.Cfg.at(name).rootStaleDS()
	renameBack := func(from, to string) func(context.Context) error {
		// Undo of "rename from -> to": move back only if the move happened.
		return func(ctx context.Context) error {
			if ok, _ := z.Exists(ctx, to); !ok {
				return nil
			}
			if ok, _ := z.Exists(ctx, from); ok {
				return nil
			}
			return z.Rename(ctx, to, from)
		}
	}
	return []plan.Step{
		{Name: "park-previous-root-old", Describe: fmt.Sprintf("zfs rename %s %s (if left by an earlier upgrade; destroyed after success)", oldDS, staleDS),
			Do: func(ctx context.Context) error {
				if ok, err := z.Exists(ctx, oldDS); err != nil || !ok {
					return err
				}
				if s.prop(ctx, oldDS, PropManaged) != "on" || s.prop(ctx, oldDS, PropID) != st.ID {
					return api.Errorf(api.CodeForbidden, "%s is not owned by jail %s", oldDS, name)
				}
				return z.Rename(ctx, oldDS, staleDS)
			},
			Undo: renameBack(oldDS, staleDS)},
		{Name: "demote-root", Describe: fmt.Sprintf("zfs set canmount=noauto mountpoint=%s %s", s.Cfg.at(name).rootOldMP(), rootDS),
			Do: func(ctx context.Context) error {
				return z.Set(ctx, rootDS, map[string]string{"canmount": "noauto", "mountpoint": s.Cfg.at(name).rootOldMP()})
			},
			Undo: func(ctx context.Context) error {
				if ok, _ := z.Exists(ctx, rootDS); !ok {
					return nil
				}
				return z.Set(ctx, rootDS, map[string]string{"canmount": "on", "mountpoint": s.Cfg.at(name).rootMP()})
			}, UndoOnFail: true},
		{Name: "rename-root-to-old", Describe: fmt.Sprintf("zfs rename %s %s", rootDS, oldDS),
			Do: func(ctx context.Context) error { return z.Rename(ctx, rootDS, oldDS) }, Undo: renameBack(rootDS, oldDS)},
		{Name: "rename-new-to-root", Describe: fmt.Sprintf("zfs rename %s %s", newDS, rootDS),
			Do: func(ctx context.Context) error { return z.Rename(ctx, newDS, rootDS) }, Undo: renameBack(newDS, rootDS)},
		{Name: "promote-new-root", Describe: fmt.Sprintf("zfs set canmount=on mountpoint=%s %s", s.Cfg.at(name).rootMP(), rootDS),
			Do: func(ctx context.Context) error {
				return z.Set(ctx, rootDS, map[string]string{"canmount": "on", "mountpoint": s.Cfg.at(name).rootMP()})
			},
			Undo: func(ctx context.Context) error {
				// only demote when rootDS is still the new root (it is renamed back after)
				if ok, _ := z.Exists(ctx, rootDS); !ok {
					return nil
				}
				return z.Set(ctx, rootDS, map[string]string{"canmount": "noauto", "mountpoint": s.Cfg.at(name).rootNewMP()})
			}, UndoOnFail: true},
	}
}

func (s *Service) bundleStep(name string, oldB, newB []byte) plan.Step {
	p := s.Cfg.at(name).bundlePath()
	return plan.Step{Name: "write-bundle", Describe: "write " + p + " atomically",
		Do:   func(ctx context.Context) error { return s.Files.WriteAtomic(ctx, p, newB) },
		Undo: func(ctx context.Context) error { return s.Files.WriteAtomic(ctx, p, oldB) }, UndoOnFail: true}
}

// preflight is design 4.3 step 2.
func (s *Service) preflight(ctx context.Context, st *jailState, target api.ImageGeneration) error {
	z := s.ZFS
	if st.hasRootNew() || st.hasRootStale() {
		return api.Errorf(api.CodeBusy, "%s or %s exists from an interrupted operation", s.Cfg.at(st.Name).rootNewDS(), s.Cfg.at(st.Name).rootStaleDS()).WithHint("run recovery or cleanup first")
	}
	if ok, _ := z.Exists(ctx, target.Dataset+"@"+roSnap); !ok {
		return api.Errorf(api.CodeNotFound, "generation %s has no @ro snapshot", target.Name)
	}
	// snapshots that other clones depend on would make root.old undestroyable
	snaps, err := z.Snapshots(ctx, st.Root)
	if err != nil {
		return err
	}
	for _, sn := range snaps {
		cl, err := z.Clones(ctx, st.Root+"@"+sn)
		if err != nil {
			return err
		}
		if len(cl) > 0 {
			return api.Errorf(api.CodeBusy, "snapshot %s@%s has clones (%s)", st.Root, sn, strings.Join(cl, ",")).
				WithHint("destroy the clones first")
		}
	}
	if s.Cfg.Replicating != nil {
		busy, err := s.Cfg.Replicating(ctx, st.Name)
		if err != nil {
			return err
		}
		if busy {
			return api.Errorf(api.CodeBusy, "replication of jail %s is running", st.Name)
		}
	}
	// UNVERIFIED: the comparison assumes "<major>.<minor>-<TYPE>" releases.
	if rel := s.prop(ctx, target.Dataset, PropOSRelease); rel != "" {
		host, err := s.Jails.HostRelease(ctx)
		if err != nil {
			return err
		}
		newer, err := releaseNewer(rel, host)
		if err != nil {
			return api.Errorf(api.CodeInternal, "compare releases: %v", err)
		}
		if newer {
			return api.Errorf(api.CodeVersionSkew, "image %s is %s but the host kernel is %s", target.Name, rel, host).
				WithHint("upgrade the host first")
		}
	}
	return nil
}

func parseRel(r string) (int, int, error) {
	v, _, _ := strings.Cut(r, "-")
	a, b, ok := strings.Cut(v, ".")
	if !ok {
		return 0, 0, fmt.Errorf("release %q is not <major>.<minor>-<type>", r)
	}
	ma, err := strconv.Atoi(a)
	if err != nil {
		return 0, 0, fmt.Errorf("release %q: %w", r, err)
	}
	mi, err := strconv.Atoi(b)
	if err != nil {
		return 0, 0, fmt.Errorf("release %q: %w", r, err)
	}
	return ma, mi, nil
}

// releaseNewer reports whether image is newer than host.
func releaseNewer(image, host string) (bool, error) {
	a, b, err := parseRel(image)
	if err != nil {
		return false, err
	}
	c, d, err := parseRel(host)
	if err != nil {
		return false, err
	}
	return a > c || (a == c && b > d), nil
}

// dropStale destroys the root.old of an earlier upgrade that this one parked.
func (s *Service) dropStale(ctx context.Context, st *jailState) error {
	if !st.hasRootStale() {
		return nil
	}
	ds := s.Cfg.at(st.Name).rootStaleDS()
	if s.prop(ctx, ds, PropManaged) != "on" || s.prop(ctx, ds, PropID) != st.ID {
		return nil
	}
	return s.ZFS.DestroyRecursive(ctx, ds)
}

// CleanupRootOld destroys root.old once its retention has passed. It returns
// whether it destroyed anything. It never touches a root.old without the
// cleanup mark that an upgrade sets.
func (s *Service) CleanupRootOld(ctx context.Context, name string) (bool, error) {
	st, err := s.observe(ctx, name)
	if err != nil {
		return false, err
	}
	if st.hasRootStale() {
		if err := s.dropStale(ctx, st); err != nil {
			return false, err
		}
	}
	if !st.hasRootOld() {
		return st.hasRootStale(), nil
	}
	oldDS := s.Cfg.at(name).rootOldDS()
	mark := s.prop(ctx, oldDS, PropCleanupAfter)
	if mark == "" || s.prop(ctx, oldDS, PropManaged) != "on" {
		return false, nil
	}
	due, err := time.Parse(time.RFC3339, mark)
	if err != nil {
		return false, api.Errorf(api.CodeInternal, "bad %s on %s: %v", PropCleanupAfter, oldDS, err)
	}
	if s.Cfg.now().Before(due) {
		return false, nil
	}
	if err := s.ZFS.DestroyRecursive(ctx, oldDS); err != nil {
		return false, err
	}
	return true, nil
}
