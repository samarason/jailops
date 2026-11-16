package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/schedule"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Managed updates (design 8.4). The pipeline for one jail is always: policy,
// atomic ZFS snapshot, update, health check, result and history. A failed OS
// update is swapped back by the root-swap plan itself (automatic root
// rollback, application data untouched). A failed package update is
// reported with its snapshot: undoing it is a data rollback (scope all), which
// discards what the jail wrote since, so JailOps never does it on its own.
// UNVERIFIED on FreeBSD: the pkg and apk invocations and the parsing of their
// dry-run output.

// updateState is the in-memory part of the update feature: the latest check
// per jail and when the schedule last ran a jail.
type updateState struct {
	mu      sync.Mutex
	reports map[string]api.UpdateReport
	last    map[string]time.Time
}

func (u *updateState) report(key string) (api.UpdateReport, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	r, ok := u.reports[key]
	return r, ok
}

func (u *updateState) setReport(key string, r api.UpdateReport) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.reports == nil {
		u.reports = map[string]api.UpdateReport{}
	}
	u.reports[key] = r
}

func (u *updateState) forget(key string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.reports, key)
	delete(u.last, key)
}

// ---- history ----

const maxHistory = 100

func (s *Service) historyPath(key string) string {
	return filepath.Join(s.d.StateDir, "updates", key+".json")
}

var histMu sync.Mutex

func (s *Service) readHistory(key string) []api.UpdateRecord {
	if s.d.StateDir == "" {
		s.histMem.mu.Lock()
		defer s.histMem.mu.Unlock()
		return append([]api.UpdateRecord(nil), s.histMem.m[key]...)
	}
	b, err := os.ReadFile(s.historyPath(key))
	if err != nil {
		return nil
	}
	var out []api.UpdateRecord
	_ = json.Unmarshal(b, &out)
	return out
}

func (s *Service) appendHistory(rec api.UpdateRecord) {
	key, _ := validate.QualifiedName(rec.Project, rec.Jail)
	histMu.Lock()
	defer histMu.Unlock()
	h := append(s.readHistory(key), rec)
	if len(h) > maxHistory {
		h = h[len(h)-maxHistory:]
	}
	if s.d.StateDir == "" {
		s.histMem.mu.Lock()
		if s.histMem.m == nil {
			s.histMem.m = map[string][]api.UpdateRecord{}
		}
		s.histMem.m[key] = h
		s.histMem.mu.Unlock()
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.historyPath(key)), 0o750); err != nil {
		s.log.Warn("update history cannot be saved", "jail", key, "err", err)
		return
	}
	b, _ := json.Marshal(h)
	tmp := s.historyPath(key) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err == nil {
		err = os.Rename(tmp, s.historyPath(key))
		if err != nil {
			s.log.Warn("update history cannot be saved", "jail", key, "err", err)
		}
	}
}

type histMemory struct {
	mu sync.Mutex
	m  map[string][]api.UpdateRecord
}

// UpdateHistory returns a jail's update history, newest first.
func (s *Service) UpdateHistory(ctx context.Context, name string) ([]api.UpdateRecord, error) {
	_, key, err := s.jailRef(ctx, name)
	if err != nil {
		return nil, err
	}
	if _, err := s.getByKey(ctx, key); err != nil {
		return nil, err
	}
	h := s.readHistory(key)
	out := make([]api.UpdateRecord, 0, len(h))
	for i := len(h) - 1; i >= 0; i-- {
		out = append(out, h[i])
	}
	return out, nil
}

// ---- parsing ----

var (
	pkgUpgradeRE = regexp.MustCompile(`^\s+(\S+?):\s+(\S+)\s+->\s+(\S+)`)
	apkUpgradeRE = regexp.MustCompile(`Upgrading\s+(\S+)\s+\((\S+)\s+->\s+(\S+)\)`)
)

// parsePackageUpdates reads the dry run of pkg(8) ("pkg upgrade -n") or apk(8)
// ("apk upgrade --simulate"). UNVERIFIED: the exact output formats.
func parsePackageUpdates(out []byte, alpine bool) []api.PackageUpdate {
	var res []api.PackageUpdate
	section := ""
	for _, l := range strings.Split(string(out), "\n") {
		if alpine {
			if m := apkUpgradeRE.FindStringSubmatch(l); m != nil {
				res = append(res, api.PackageUpdate{Name: m[1], From: m[2], To: m[3]})
			}
			continue
		}
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "Installed packages to be UPGRADED"):
			section = "up"
		case strings.HasPrefix(t, "New packages to be INSTALLED"), strings.HasPrefix(t, "Installed packages to be REINSTALLED"),
			strings.HasPrefix(t, "Installed packages to be REMOVED"), strings.HasPrefix(t, "Installed packages to be DOWNGRADED"):
			section = "other"
		case t == "":
			// blank lines separate sections but sections end only at the next header
		case section == "up":
			if m := pkgUpgradeRE.FindStringSubmatch(l); m != nil {
				res = append(res, api.PackageUpdate{Name: m[1], From: m[2], To: m[3]})
			}
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

// ---- check ----

func (s *Service) jailIsLinux(j api.Jail) bool { return j.Spec.OS == api.OSLinux }

// managesPackages says whether JailOps drives the package tool of a jail: pkg for FreeBSD jails and apk for Alpine.
// A Debian jail (or any other Linux jail) keeps its own packages, for instance with unattended-upgrades, and JailOps
// never runs apt in it; the same goes for what a person runs in the jail on his own.
func (s *Service) managesPackages(j api.Jail) bool {
	if !s.jailIsLinux(j) {
		return true
	}
	ref, err := validate.ParseImageRef(j.Spec.Image)
	if err != nil {
		return false
	}
	spec, err := s.imageSpec(context.Background(), ref.Name)
	return err == nil && spec.Source.Type == "minirootfs"
}

func (s *Service) runInJail(ctx context.Context, key string, timeout time.Duration, argv ...string) ([]byte, error) {
	if s.d.Jails == nil {
		return nil, api.Errorf(api.CodeUnsupported, "this daemon cannot run commands in jails")
	}
	res, err := s.d.Jails.Exec(ctx, key, jailos.ExecOpts{Argv: argv, Timeout: timeout})
	out := append(append([]byte(nil), res.Stdout...), res.Stderr...)
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// pkgExec runs a package command for a running jail and returns its output. A Linux jail runs apk inside itself. A
// FreeBSD jail has no package tool of its own (a thin jail is a pkgbase userland without pkg), so the host's pkg runs
// with -j: it enters the jail first, so what it writes and the scripts it runs stay in the jail, and it reads the
// repositories the jail is configured for. argv is the command as it would be typed inside the jail ("pkg",
// "upgrade", "-y") and -j JAIL is put after "pkg".
func (s *Service) pkgExec(ctx context.Context, key string, linux bool, timeout time.Duration, argv ...string) ([]byte, error) {
	if linux {
		return s.runInJail(ctx, key, timeout, argv...)
	}
	host := append([]string{argv[0], "-j", key}, argv[1:]...)
	res, err := s.d.Run.Run(ctx, run.Cmd{Name: host[0], Args: host[1:], Timeout: timeout})
	out := append(append([]byte(nil), res.Stdout...), res.Stderr...)
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", strings.Join(host, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// pkgUpgradeChunk is how many package names one pkg command takes (the helper allows 64 arguments).
const pkgUpgradeChunk = 50

// pkgUpgrade lists (apply false) or runs (apply true) the upgrade of the packages of a jail. A Linux jail upgrades
// everything with apk. For a FreeBSD jail the host names the installed packages that are not part of the base
// system: the base (FreeBSD-*) comes from the image generation and only moves with it, and a bare `pkg upgrade` on
// the host would also take the base packages from the host's FreeBSD-base repository into the jail's root.
func (s *Service) pkgUpgrade(ctx context.Context, key string, linux bool, timeout time.Duration, apply bool) ([]byte, error) {
	if linux {
		if apply {
			return s.pkgExec(ctx, key, true, timeout, "apk", "upgrade", "--no-interactive")
		}
		return s.pkgExec(ctx, key, true, timeout, "apk", "upgrade", "--simulate", "--no-interactive")
	}
	out, err := s.pkgExec(ctx, key, false, timeout, "pkg", "query", "%n")
	if err != nil {
		return out, err
	}
	var names []string
	for _, n := range strings.Fields(string(out)) {
		if !strings.HasPrefix(n, "FreeBSD-") && n != "pkg" {
			names = append(names, n)
		}
	}
	flag := "-n"
	if apply {
		flag = "-y"
	}
	var all []byte
	for len(names) > 0 {
		n := min(len(names), pkgUpgradeChunk)
		o, err := s.pkgExec(ctx, key, false, timeout, append([]string{"pkg", "upgrade", flag}, names[:n]...)...)
		all = append(all, o...)
		if err != nil {
			return all, err
		}
		names = names[n:]
	}
	return all, nil
}

func (s *Service) jailRunning(ctx context.Context, key string) bool {
	if s.d.Jails == nil {
		return false
	}
	_, up, err := s.d.Jails.Get(ctx, key)
	return err == nil && up
}

// checkJail asks one jail what could be updated. It changes the package
// catalog inside the jail (pkg update, apk update) and nothing else.
func (s *Service) checkJail(ctx context.Context, key string) api.UpdateReport {
	j, err := s.jailSnapshot(key)
	rep := api.UpdateReport{Jail: j.Metadata.Name, Project: j.Metadata.Project, Mode: j.Spec.Update.Mode, CheckedAt: s.now().UTC()}
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	var errs []string
	if !s.managesPackages(j) {
		// nothing to check: the jail updates its own packages
	} else if s.jailRunning(ctx, key) {
		alpine := s.jailIsLinux(j)
		upd := []string{"pkg", "update", "-q"}
		if alpine {
			upd = []string{"apk", "update", "--no-interactive"}
		}
		release := func() {}
		var held error
		if !alpine {
			release, held = s.holdJailForPackages(key)
		}
		defer release()
		if held != nil {
			errs = append(errs, "package catalog: "+held.Error())
		} else if _, err := s.pkgExec(ctx, key, alpine, 10*time.Minute, upd...); err != nil {
			errs = append(errs, "package catalog: "+err.Error())
		} else if out, err := s.pkgUpgrade(ctx, key, alpine, 10*time.Minute, false); err != nil {
			errs = append(errs, "package check: "+err.Error())
		} else {
			rep.Packages = parsePackageUpdates(out, alpine)
		}
	} else {
		errs = append(errs, "the jail is stopped; its packages cannot be checked")
	}
	if os, err := s.osUpdate(ctx, key, j); err != nil {
		errs = append(errs, "image: "+err.Error())
	} else {
		rep.OS = os
	}
	rep.Available = len(rep.Packages) > 0 || rep.OS != nil
	rep.Error = strings.Join(errs, "; ")
	return rep
}

// osUpdate reports a newer generation of the jail's image (thin jails).
func (s *Service) osUpdate(ctx context.Context, key string, j api.Jail) (*api.OSUpdate, error) {
	if s.life == nil || j.Spec.Layout == api.LayoutThick || j.Spec.Update.Strategy == api.UpdateInPlace || j.Spec.Update.Strategy == api.UpdateManual {
		return nil, nil
	}
	lay, err := s.life.Layout(ctx, key)
	if err != nil || lay.Layout != api.LayoutThin {
		return nil, nil
	}
	si, ok := s.storageOfJail(key)
	if !ok {
		return nil, nil
	}
	target, err := s.life.Images.Resolve(ctx, si.Root, j.Spec.Image)
	if err != nil {
		return nil, err
	}
	if target.Number <= lay.Generation {
		return nil, nil
	}
	return &api.OSUpdate{From: genRef(lay.Image, lay.Generation), To: target.Name}, nil
}

// updateTargets resolves the jails of a request to keys, in the request's
// project (a jail the caller cannot see is not_found).
func (s *Service) updateTargets(ctx context.Context, names []string, all bool) (project string, keys []string, err error) {
	p, err := s.access(ctx)
	if err != nil {
		return "", nil, err
	}
	project = p.Meta.Name
	if all {
		s.mu.RLock()
		for _, k := range sortedKeys(s.jails) {
			if s.jails[k].jail.Metadata.Project == project {
				keys = append(keys, k)
			}
		}
		s.mu.RUnlock()
		return project, keys, nil
	}
	if len(names) == 0 {
		return project, nil, invalid("name the jails, or ask for all of them")
	}
	for _, n := range names {
		key, err := validate.QualifiedName(project, n)
		if err != nil {
			return "", nil, notFound("jail", n)
		}
		if _, err := s.getByKey(ctx, key); err != nil {
			return "", nil, err
		}
		keys = append(keys, key)
	}
	return project, keys, nil
}

// CheckUpdates checks jails for updates as an operation; its result is the
// list of reports. Nothing is applied.
func (s *Service) CheckUpdates(ctx context.Context, req api.UpdateCheckRequest) (api.Operation, error) {
	if err := s.requireHost("updates"); err != nil {
		return api.Operation{}, err
	}
	project, keys, err := s.updateTargets(ctx, req.Jails, req.All)
	if err != nil {
		return api.Operation{}, err
	}
	return s.Submit(ctx, OpSpec{Description: "Check for updates in project " + project, Project: project,
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			out := make([]api.UpdateReport, 0, len(keys))
			for i, k := range keys {
				rep := s.checkJail(ctx, k)
				s.upd.setReport(k, rep)
				out = append(out, rep)
				h.Progress((i + 1) * 100 / len(keys))
			}
			s.emitIn(ctx, project, "updates-checked", "/api/v1/updates")
			return out, nil
		}})
}

// ListUpdates returns the latest check result of every visible jail that has
// one, narrowed by the request's project.
func (s *Service) ListUpdates(ctx context.Context) ([]api.UpdateReport, error) {
	all, projects, err := s.visibleProjects(ctx)
	if err != nil {
		return nil, err
	}
	s.upd.mu.Lock()
	defer s.upd.mu.Unlock()
	out := []api.UpdateReport{}
	for _, k := range sortedMapKeys(s.upd.reports) {
		r := s.upd.reports[k]
		if all || containsStr(projects, r.Project) {
			out = append(out, r)
		}
	}
	return out, nil
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---- apply ----

type applyWhat struct{ packages, os bool }

// ApplyUpdates applies updates as an operation; its result is the list of
// history records. Jails with nothing to apply are skipped.
func (s *Service) ApplyUpdates(ctx context.Context, req api.UpdateApplyRequest) (api.Operation, error) {
	if err := s.requireHost("updates"); err != nil {
		return api.Operation{}, err
	}
	project, keys, err := s.updateTargets(ctx, req.Jails, req.All)
	if err != nil {
		return api.Operation{}, err
	}
	var locks []string
	for _, k := range keys {
		locks = append(locks, jailLock(k), anchorLock(k))
	}
	return s.Submit(ctx, OpSpec{Description: "Apply updates in project " + project, Project: project, Locks: locks,
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			var out []api.UpdateRecord
			for _, k := range keys {
				out = append(out, s.applyJail(ctx, h, k, applyWhat{req.Packages, req.OS}, false)...)
			}
			if out == nil {
				out = []api.UpdateRecord{}
			}
			return out, nil
		}})
}

// wanted decides what to apply to a jail: what the request restricts to, else
// what its policy allows (a manual policy allows both: the user asked).
func wanted(j api.Jail, w applyWhat, scheduled bool) applyWhat {
	if w.packages || w.os {
		return w
	}
	u := j.Spec.Update
	if scheduled || u.Mode != "" && u.Mode != api.UpdateModeManual {
		return applyWhat{u.Packages, u.OS}
	}
	return applyWhat{true, true}
}

// applyJail runs the pipeline for one jail and returns its history records.
// The caller holds the jail and anchor locks.
func (s *Service) applyJail(ctx context.Context, h *OpHandle, key string, w applyWhat, scheduled bool) []api.UpdateRecord {
	j, err := s.jailSnapshot(key)
	if err != nil {
		return nil
	}
	w = wanted(j, w, scheduled)
	project, name := j.Metadata.Project, j.Metadata.Name
	var recs []api.UpdateRecord
	finish := func(r api.UpdateRecord) {
		r.Finished = s.now().UTC()
		r.Jail, r.Project, r.Scheduled = name, project, scheduled
		if r.ID == "" {
			r.ID = "upd-" + s.stamp() + "-" + randHex(3)
		}
		s.appendHistory(r)
		recs = append(recs, r)
		if r.Result == api.UpdateOK {
			s.emitIn(ctx, project, "update.applied", "/api/v1/jails/"+name+"/updates")
		} else {
			s.emitIn(ctx, project, "update.failed", "/api/v1/jails/"+name+"/updates")
		}
	}
	// OS first: a new root first, then the packages on top of it.
	if w.os {
		if os, err := s.osUpdate(ctx, key, j); err == nil && os != nil {
			rec := api.UpdateRecord{Kind: api.UpdateKindOS, Started: s.now().UTC(), From: os.From, To: os.To}
			rec.Snapshot = "jo-pre-upgrade-" + s.stamp()
			req := lifecycle.UpgradeRequest{JailUpgrade: api.JailUpgrade{Generation: os.To}, Stamp: s.stamp()}
			if _, err := s.upgradeBody(ctx, h, project, name, key, req.JailUpgrade, req); err != nil {
				// The root-swap plan undoes itself when the start or the health check fails.
				rec.Result, rec.Error, rec.RootRolledBack = api.UpdateRolledBack, err.Error(), true
				if api.IsCode(err, api.CodeConflict) {
					rec.Result, rec.RootRolledBack = api.UpdateFailed, false
					rec.Note = "the /etc merge needs a human; the jail stays on " + os.From
				} else {
					rec.Note = "the jail was swapped back to " + os.From + "; application data was not touched"
				}
			} else {
				rec.Result = api.UpdateOK
				if j2, e := s.jailSnapshot(key); e == nil {
					j = j2
				}
			}
			finish(rec)
			if rec.Result != api.UpdateOK {
				return recs
			}
		}
	}
	if w.packages {
		finish(s.applyPackages(ctx, key, j, scheduled))
	}
	return recs
}

// applyPackages updates the packages of a running jail: snapshot, upgrade,
// health check. It never rolls data back on its own.
func (s *Service) applyPackages(ctx context.Context, key string, j api.Jail, scheduled bool) api.UpdateRecord {
	rec := api.UpdateRecord{Kind: api.UpdateKindPackages, Started: s.now().UTC()}
	if !s.managesPackages(j) {
		rec.Result, rec.Note = api.UpdateOK, "this jail keeps its own packages (JailOps drives pkg and apk only); nothing was run"
		return rec
	}
	if !s.jailRunning(ctx, key) {
		rec.Result, rec.Error = api.UpdateFailed, "the jail is not running; packages are updated inside it"
		return rec
	}
	alpine := s.jailIsLinux(j)
	// No session may enter the jail while its packages change.
	if !alpine {
		release, err := s.holdJailForPackages(key)
		if err != nil {
			rec.Result, rec.Error = api.UpdateFailed, "package catalog: "+err.Error()
			return rec
		}
		defer release()
	}
	// The packages that will change, from a dry run.
	upd := []string{"pkg", "update", "-q"}
	if alpine {
		upd = []string{"apk", "update", "--no-interactive"}
	}
	if _, err := s.pkgExec(ctx, key, alpine, 10*time.Minute, upd...); err != nil {
		rec.Result, rec.Error = api.UpdateFailed, "package catalog: "+err.Error()
		return rec
	}
	if out, err := s.pkgUpgrade(ctx, key, alpine, 10*time.Minute, false); err == nil {
		rec.Packages = parsePackageUpdates(out, alpine)
		if len(rec.Packages) == 0 {
			rec.Result, rec.Note = api.UpdateOK, "nothing to update"
			return rec
		}
	}
	snap, err := s.life.SnapshotJail(ctx, key, "update-"+s.stamp()+"-"+randHex(2), "before package update")
	if err != nil {
		rec.Result, rec.Error = api.UpdateFailed, "snapshot: "+err.Error()
		return rec
	}
	rec.Snapshot = snap.Name
	if _, err := s.pkgUpgrade(ctx, key, alpine, 60*time.Minute, true); err != nil {
		rec.Result, rec.Error = api.UpdateFailed, err.Error()
		rec.Note = "restore the snapshot with `jailops jail rollback " + j.Metadata.Name + " --all --snapshot " + snap.Name + "` to undo it; that discards what the jail wrote since"
		return rec
	}
	if !alpine {
		// a program would not find a new library before the library cache is rebuilt
		_, _ = s.runInJail(ctx, key, 5*time.Minute, "/sbin/ldconfig", "-m", "/usr/local/lib")
	}
	if err := s.healthCheck(ctx, key, j); err != nil {
		rec.Result, rec.Error = api.UpdateFailed, err.Error()
		rec.Note = "the packages stay updated: package files live in the jail's own datasets, and a root rollback does not undo them. " +
			"`jailops jail rollback " + j.Metadata.Name + " --all --snapshot " + snap.Name + "` does, and discards what the jail wrote since"
		return rec
	}
	rec.Result = api.UpdateOK
	if j.Spec.Update.Reboot == api.RebootAuto {
		if err := s.restartKey(ctx, key); err != nil {
			rec.Note = "the automatic restart failed: " + err.Error()
		} else {
			rec.Note = "the jail was restarted (updates.reboot=auto)"
		}
	} else {
		rec.Note = "restart the jail to run the updated programs (updates.reboot=manual)"
	}
	return rec
}

func (s *Service) healthCheck(ctx context.Context, key string, j api.Jail) error {
	if !s.jailRunning(ctx, key) {
		return fmt.Errorf("the jail is not running after the update")
	}
	hc := strings.Fields(j.Spec.Update.Healthcheck)
	if len(hc) == 0 {
		return nil
	}
	if out, err := s.runInJail(ctx, key, 5*time.Minute, hc...); err != nil {
		return fmt.Errorf("health check %q failed: %v", strings.Join(hc, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Service) restartKey(ctx context.Context, key string) error {
	if err := s.life.StopJail(ctx, key); err != nil {
		return err
	}
	return s.life.StartJail(ctx, key)
}

// ---- schedule ----

// updateLoop runs the update schedules: a jail with mode notify is checked,
// one with managed is checked and updated, at the times of its cron
// expression. A jail is never run twice for the same time, and a busy jail is
// tried again at the next tick.
func (s *Service) updateLoop(ctx context.Context) {
	tick := s.d.UpdateTick
	if tick <= 0 {
		tick = time.Minute
	}
	start := s.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(tick):
		}
		s.runUpdateSchedules(ctx, start)
	}
}

func (s *Service) runUpdateSchedules(ctx context.Context, start time.Time) {
	now := s.now()
	s.mu.RLock()
	keys := sortedKeys(s.jails)
	jails := make([]api.Jail, len(keys))
	for i, k := range keys {
		jails[i] = cloneJail(s.jails[k].jail)
	}
	s.mu.RUnlock()
	for i, k := range keys {
		j := jails[i]
		u := j.Spec.Update
		if u.Mode != api.UpdateModeNotify && u.Mode != api.UpdateModeManaged || u.Schedule == "" {
			continue
		}
		spec, err := schedule.Parse(u.Schedule)
		if err != nil {
			continue
		}
		s.upd.mu.Lock()
		if s.upd.last == nil {
			s.upd.last = map[string]time.Time{}
		}
		base, ok := s.upd.last[k]
		if !ok {
			base = start
		}
		s.upd.mu.Unlock()
		next, ok := spec.NextWithJitter(base, time.UTC, k, 10*time.Minute)
		if !ok || now.Before(next) {
			continue
		}
		unlock, err := s.locks.tryLock("scheduled update "+k, jailLock(k), anchorLock(k))
		if err != nil {
			continue // busy: the next tick tries again
		}
		s.upd.mu.Lock()
		s.upd.last[k] = now
		s.upd.mu.Unlock()
		s.runScheduled(ctx, k, j, u.Mode == api.UpdateModeManaged)
		unlock()
	}
}

// runScheduled checks a jail and, for managed jails, applies what its policy
// allows. The locks are held; it runs as an operation so that a crash during
// a root swap is recovered like any other.
func (s *Service) runScheduled(ctx context.Context, key string, j api.Jail, apply bool) {
	rep := s.checkJail(ctx, key)
	s.upd.setReport(key, rep)
	if !apply || !rep.Available {
		if rep.Available {
			s.emitIn(ctx, j.Metadata.Project, "update.available", "/api/v1/jails/"+j.Metadata.Name+"/updates")
		}
		return
	}
	op, err := s.Submit(WithActor(ctx, Actor{Name: "updates", Kind: "system", Perm: api.PermAdmin, Global: true}), OpSpec{
		Description: "Scheduled update of jail " + j.Metadata.Name, Project: j.Metadata.Project,
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			return s.applyJail(ctx, h, key, applyWhat{}, true), nil
		}})
	if err != nil {
		s.log.Warn("scheduled update could not start", "jail", key, "err", err)
		return
	}
	if _, err := s.WaitOperation(ctx, op.ID, 4*time.Hour); err != nil {
		s.log.Warn("scheduled update", "jail", key, "err", err)
	}
}
