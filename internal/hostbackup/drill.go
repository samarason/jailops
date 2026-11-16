package hostbackup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"jailops.net/jailops/internal/backup"
	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/internal/repo/engine"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// ErrVerifyFailed means a restore test ran and found the backup damaged. It is
// not retried: the result is recorded and reported to the backup node, which
// then never uses the snapshot as a base.
var ErrVerifyFailed = errors.New("the restore test found the backup damaged")

// drillEnv is the machine a restore test runs on: this host, which holds the
// key. It implements backup.DrillEnv on top of engine.Verify (deep, extract)
// and the restore machinery (full). It is never the backup node.
type drillEnv struct {
	s      *Service
	b      api.Backup
	remote Remote
	// last is the engine's result of the most recent verification.
	last *engine.VerifyResult
	// gen is the generation a full test cloned the root from.
	snap *engine.Snapshot
	// hidden: a full test that restores the backup as a jail of its own (see DrillHost) instead of into a
	// scratch dataset with a runner. jail is set once that restore succeeded.
	hidden bool
	jail   *hiddenJail
}

// hiddenJail is the jail of a full restore test.
type hiddenJail struct{ project, name string }

func hiddenJailName(p backup.DrillPlan) string {
	return "jodrill-" + strings.ToLower(strings.TrimPrefix(path.Base(p.Scratch), "drill-"))
}

func (s *Service) drillHost() DrillHost {
	if h, err := s.host(); err == nil {
		if dh, ok := h.(DrillHost); ok {
			return dh
		}
	}
	return nil
}

var _ backup.DrillEnv = (*drillEnv)(nil)

func (e *drillEnv) Kind() backup.EnvKind { return backup.EnvHost }

func (e *drillEnv) HoldsKey(domain string) bool { return e.s.HoldsKey(domain) }

func (e *drillEnv) verify(ctx context.Context, mode, scratch string) error {
	key := e.s.currentKey()
	res, err := engine.Verify(ctx, engine.VerifyOptions{Key: key, Repo: e.remote, Group: key.Keys.GroupID(e.b.Spec.HostUUID, e.b.Spec.JailUUID),
		Snapshot: e.b.Spec.Snapshot, Mode: mode, Scratch: scratch, Workers: e.s.cfg.EngineWorkers})
	if err != nil {
		return mapEngineErr(err)
	}
	e.last = res
	if !res.OK {
		return fmt.Errorf("%w: %s", ErrVerifyFailed, describeVerify(res))
	}
	return nil
}

func describeVerify(r *engine.VerifyResult) string {
	var parts []string
	if len(r.Bad) > 0 {
		parts = append(parts, fmt.Sprintf("%d bad chunks (first %s: %s)", len(r.Bad), r.Bad[0].ID, r.Bad[0].Reason))
	}
	parts = append(parts, r.Problems...)
	return strings.Join(parts, "; ")
}

// VerifyChunks implements backup.Verifier: every chunk is fetched, decrypted
// and its id recomputed.
func (e *drillEnv) VerifyChunks(ctx context.Context, p backup.DrillPlan) error {
	return e.verify(ctx, engine.VerifyDeep, "")
}

// ExtractScratch implements backup.Verifier: the snapshot is restored into a
// scratch directory under p.Scratch and every file's hash is checked.
func (e *drillEnv) ExtractScratch(ctx context.Context, p backup.DrillPlan) error {
	if err := e.checkScratchDir(p.Scratch); err != nil {
		return err
	}
	if err := ensurePrivateDir(filepath.Clean(e.s.cfg.ScratchDir)); err != nil {
		return err
	}
	if err := os.MkdirAll(p.Scratch, 0o700); err != nil {
		return err
	}
	return e.verify(ctx, engine.VerifyExtract, p.Scratch)
}

// ensurePrivateDir makes the directory a drill extracts decrypted files into, or checks the one that is there: it must be
// a real directory of this user that nobody else can enter. /var/tmp is shared, so another user could have made the
// directory (or a symlink) first and would read what a drill restores into it.
func ensurePrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o077 != 0 {
		return api.Errorf(api.CodeForbidden, "%s must be a directory of this user that nobody else can enter", dir)
	}
	return nil
}

func (e *drillEnv) checkScratchDir(dir string) error {
	root := filepath.Clean(e.s.cfg.ScratchDir)
	d := filepath.Clean(dir)
	if !strings.HasPrefix(d, root+string(filepath.Separator)) || !strings.HasPrefix(filepath.Base(d), "drill-") {
		return api.Errorf(api.CodeInvalid, "scratch directory %q is not a drill directory under %s", dir, root)
	}
	return nil
}

// RemoveScratchDir implements backup.Verifier.
func (e *drillEnv) RemoveScratchDir(_ context.Context, p backup.DrillPlan) error {
	if err := e.checkScratchDir(p.Scratch); err != nil {
		return err
	}
	return os.RemoveAll(p.Scratch)
}

func (e *drillEnv) scratchPlacement(p backup.DrillPlan) Placement {
	return Placement{Container: p.Scratch, Mountpoint: path.Join(e.s.cfg.ScratchMountBase, path.Base(p.Scratch))}
}

func scratchID(p backup.DrillPlan) string { return "drill-" + p.ID }

// RestoreScratch implements backup.Verifier: the whole jail is restored into
// the scratch dataset (container, root from its generation, data), without
// being registered anywhere.
func (e *drillEnv) RestoreScratch(ctx context.Context, p backup.DrillPlan) error {
	if e.hidden {
		return e.restoreHidden(ctx, p)
	}
	s := e.s
	if s.cfg.ScratchDataset == "" || !strings.HasPrefix(p.Scratch, s.cfg.ScratchDataset+"/") {
		return api.Errorf(api.CodeUnsupported, "full restore tests need a scratch dataset (Config.ScratchDataset)")
	}
	key := s.currentKey()
	group := key.Keys.GroupID(e.b.Spec.HostUUID, e.b.Spec.JailUUID)
	snap, err := engine.OpenSnapshot(ctx, e.remote, key.Keys, group, e.b.Spec.Snapshot)
	if err != nil {
		return mapEngineErr(err)
	}
	var rev reverter
	_, err = s.materialize(ctx, &rev, materialize{key: key, remote: e.remote, snap: snap, b: e.b, pl: e.scratchPlacement(p), uuid: scratchID(p),
		name: scratchID(p), storage: e.b.Spec.Bundle.Spec.Storage})
	if err != nil {
		// DestroyScratch also runs (RunDrill registered it first); nothing to undo twice
		_ = rev.revert(ctx)
	}
	return err
}

// DestroyScratch implements backup.Verifier: it destroys the scratch dataset
// when it is the one a drill created.
func (e *drillEnv) DestroyScratch(ctx context.Context, p backup.DrillPlan) error {
	if e.hidden {
		return e.deleteHidden(ctx)
	}
	s := e.s
	if s.cfg.ScratchDataset == "" || !strings.HasPrefix(p.Scratch, s.cfg.ScratchDataset+"/") {
		return nil
	}
	ok, err := s.zfs.Exists(ctx, p.Scratch)
	if err != nil || !ok {
		return err
	}
	pr, err := s.zfs.Get(ctx, p.Scratch, pManaged, pID)
	if err != nil {
		return err
	}
	if pr[pManaged].Value != "on" || pr[pID].Value != scratchID(p) {
		return nil
	}
	return s.zfs.Destroy(ctx, p.Scratch, zfs.DestroyOpts{Recursive: true})
}

type noRunner struct{}

func (noRunner) err() error {
	return api.Errorf(api.CodeUnsupported, "full restore tests need a jail runner; this daemon wires none")
}
func (n noRunner) CreateNetwork(context.Context, string, api.NetworkSpec) error { return n.err() }
func (n noRunner) DestroyNetwork(context.Context, string) error                 { return nil }
func (n noRunner) StartJail(context.Context, backup.DrillPlan) error            { return n.err() }
func (n noRunner) StopJail(context.Context, backup.DrillPlan) error             { return nil }

func (e *drillEnv) runner() backup.JailRunner {
	if e.s.deps.Drill != nil {
		return e.s.deps.Drill
	}
	return noRunner{}
}

// CreateNetwork, DestroyNetwork, StartJail and StopJail implement
// backup.JailRunner by delegating to the daemon's runner.
func (e *drillEnv) CreateNetwork(ctx context.Context, name string, spec api.NetworkSpec) error {
	if e.hidden {
		return nil // the hidden jail has no network: nothing to isolate
	}
	return e.runner().CreateNetwork(ctx, name, spec)
}
func (e *drillEnv) DestroyNetwork(ctx context.Context, name string) error {
	if e.hidden {
		return nil
	}
	return e.runner().DestroyNetwork(ctx, name)
}
func (e *drillEnv) StartJail(ctx context.Context, p backup.DrillPlan) error {
	if e.hidden {
		return e.startHidden(ctx)
	}
	return e.runner().StartJail(ctx, p)
}
func (e *drillEnv) StopJail(ctx context.Context, p backup.DrillPlan) error {
	if e.hidden {
		return e.stopHidden(ctx)
	}
	return e.runner().StopJail(ctx, p)
}

// ---- the hidden jail of a full test ----

// restoreHidden restores the backup as a jail named jodrill-<id> in the backup's project, without network
// interfaces. It is registered like any restored jail, which is what lets the daemon start it the usual way.
func (e *drillEnv) restoreHidden(ctx context.Context, p backup.DrillPlan) error {
	name := hiddenJailName(p)
	res, err := e.s.RestoreWith(ctx, api.RestoreRequest{Backup: e.b.Metadata.Name, As: name, NoVolumes: true}, RestoreOptions{NoNetwork: true, DropVolumes: true})
	if err != nil {
		return fmt.Errorf("restoring the backup for the test: %w", err)
	}
	e.jail = &hiddenJail{project: res.Jail.Metadata.Project, name: res.Jail.Metadata.Name}
	return nil
}

func (e *drillEnv) startHidden(ctx context.Context) error {
	h, err := e.s.host()
	if err != nil {
		return err
	}
	if e.jail == nil {
		return errors.New("the test jail was not restored")
	}
	return h.Start(ctx, e.jail.project, e.jail.name)
}

func (e *drillEnv) stopHidden(ctx context.Context) error {
	dh := e.s.drillHost()
	if dh == nil || e.jail == nil {
		return nil
	}
	return dh.Stop(ctx, e.jail.project, e.jail.name)
}

func (e *drillEnv) deleteHidden(ctx context.Context) error {
	dh := e.s.drillHost()
	if dh == nil || e.jail == nil {
		return nil
	}
	return dh.Delete(ctx, e.jail.project, e.jail.name)
}

// hiddenHealth is the health check of a full test: the jail stays up and a command inside it succeeds, the
// jail's own health check (update.healthcheck) when it has one, else a shell that exits 0. Services take a
// moment, so the command is tried until it works or HealthTimeout passes.
func (e *drillEnv) hiddenHealth(ctx context.Context, p backup.DrillPlan) error {
	h, err := e.s.host()
	if err != nil {
		return err
	}
	dh := e.s.drillHost()
	if dh == nil || e.jail == nil {
		return errors.New("the test jail was not restored")
	}
	argv := []string{"/bin/sh", "-c", "exit 0"}
	if p.Healthcheck != "" {
		argv = []string{"/bin/sh", "-c", p.Healthcheck}
	}
	timeout := e.s.cfg.HealthTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	const step = 2 * time.Second
	attempts := int(timeout/step) + 1
	var last string
	for i := 0; ; i++ {
		up, rerr := h.Running(ctx, e.jail.project, e.jail.name)
		switch {
		case rerr != nil:
			last = rerr.Error()
		case !up:
			last = "the jail is not running"
		default:
			out, code, xerr := dh.Exec(ctx, e.jail.project, e.jail.name, argv)
			if xerr == nil && code == 0 {
				return nil
			}
			last = strings.TrimSpace(fmt.Sprintf("%v (exit %d) %s", xerr, code, out))
		}
		if i+1 >= attempts {
			return fmt.Errorf("%s", last)
		}
		if serr := e.s.cfg.Sleep(ctx, step); serr != nil {
			return serr
		}
	}
}

// RunDrill runs a restore test of one backup on this host and reports the
// result to the repository's owner. A damaged backup is a Run with OK false and
// an error wrapping ErrVerifyFailed.
func (s *Service) RunDrill(ctx context.Context, backupID string, depth backup.Depth) (Run, error) {
	return s.runDrill(ctx, backupID, depth, "", false, 1)
}

func (s *Service) runDrill(ctx context.Context, backupID string, depth backup.Depth, policy string, scheduled bool, attempt int) (run Run, err error) {
	b, err := s.findBackup(ctx, backupID)
	if err != nil {
		return run, err
	}
	run = Run{ID: s.newID("drill"), Kind: RunDrill, Policy: policy, Target: b.Spec.Target, Project: b.Metadata.Project, Jail: b.Spec.Jail,
		JailUUID: b.Spec.JailUUID, Scheduled: scheduled, Attempt: attempt, Started: s.now(), Snapshot: b.Spec.Snapshot, Depth: string(depth)}
	defer func() {
		run.Finished = s.now()
		run.OK = err == nil
		if err != nil {
			run.Error, run.Code = err.Error(), errCode(err)
		}
		_ = s.deps.Catalog.PutRun(context.WithoutCancel(ctx), run)
		if s.deps.Observer != nil {
			s.deps.Observer.RunFinished(context.WithoutCancel(ctx), run)
		}
	}()
	key := s.currentKey()
	if key == nil || key.DomainID() != b.Spec.KeyDomain {
		return run, api.Errorf(api.CodeForbidden, "this host does not hold the key of backup %s (key domain %s)", b.Spec.Snapshot, b.Spec.KeyDomain)
	}
	remote, err := s.remoteFor(ctx, b.Spec.Target)
	if err != nil {
		return run, err
	}
	if err := remote.Refresh(ctx); err != nil {
		return run, err
	}
	scratchRoot := ""
	hidden := false
	switch depth {
	case backup.DepthExtract:
		scratchRoot = s.cfg.ScratchDir
	case backup.DepthFull:
		switch {
		case s.deps.Drill != nil: // a runner of its own: the backup is restored into a scratch dataset
			scratchRoot = s.cfg.ScratchDataset
			if scratchRoot == "" {
				return run, api.Errorf(api.CodeUnsupported, "full restore tests need a scratch dataset (Config.ScratchDataset)")
			}
		case s.drillHost() != nil: // the backup is restored as a hidden jail of the host
			scratchRoot = "hidden-jail"
			hidden = true
		default:
			return run, api.Errorf(api.CodeUnsupported, "full restore tests need a jail runner; this daemon wires none")
		}
	}
	id := strings.TrimPrefix(run.ID, "drill-")
	plan, err := backup.PlanDrill(b, depth, scratchRoot, id)
	if err != nil {
		return run, err
	}
	env := &drillEnv{s: s, b: b, remote: remote, hidden: hidden}
	var check backup.HealthCheck
	if depth == backup.DepthFull && hidden {
		check = env.hiddenHealth
	} else if depth == backup.DepthFull && s.deps.Drill != nil {
		check = s.deps.Drill.Health
	}
	_, err = backup.RunDrill(ctx, plan, env, check)
	group := key.Keys.GroupID(b.Spec.HostUUID, b.Spec.JailUUID)
	rt := wire.RestoreTest{Group: group, Snapshot: b.Spec.Snapshot, Method: string(depth), OK: err == nil}
	if env.last != nil {
		rt.Chunks = env.last.Chunks
		for _, bc := range env.last.Bad {
			rt.Problems = append(rt.Problems, fmt.Sprintf("chunk %s: %s", bc.ID, bc.Reason))
		}
		rt.Problems = append(rt.Problems, env.last.Problems...)
		run.Chunks, run.Files, run.Bytes = env.last.Chunks, int64(env.last.Files), int64(env.last.Bytes)
	}
	if err != nil && len(rt.Problems) == 0 {
		rt.Problems = []string{err.Error()}
	}
	run.Problems = rt.Problems
	// only a verification that ran and found damage, or one that passed, is
	// reported; a failure to run (no node, wrong key) says nothing about the data
	if err == nil || errors.Is(err, ErrVerifyFailed) {
		if rerr := remote.RecordRestoreTest(context.WithoutCancel(ctx), rt); rerr != nil {
			s.cfg.Log.Error("backup: reporting the restore test failed", "snapshot", b.Spec.Snapshot, "err", rerr)
			run.Warnings = append(run.Warnings, "the result could not be reported to the repository: "+rerr.Error())
		}
	}
	return run, err
}

// drillJail picks the newest healthy backup of a jail on the policy's targets
// and tests it at the policy's depth.
func (s *Service) drillJail(ctx context.Context, p api.BackupPolicy, j JailRecord, attempt int) (Run, error) {
	depth, err := backup.ParseDepth(p.Spec.VerifyMode)
	if err != nil {
		return Run{}, err
	}
	if j.IsVolume && depth == backup.DepthFull {
		depth = backup.DepthExtract // a volume is no jail: there is nothing to start
	}
	bs, err := s.deps.Catalog.Backups(ctx)
	if err != nil {
		return Run{}, err
	}
	targets := map[string]bool{}
	for _, t := range p.Spec.Targets {
		targets[t] = true
	}
	for _, b := range bs { // newest first
		if b.Spec.JailUUID == j.UUID && !b.Status.Failed && (len(targets) == 0 || targets[b.Spec.Target]) {
			return s.runDrill(ctx, b.Metadata.Name, depth, p.Metadata.Name, true, attempt)
		}
	}
	return Run{}, nil // nothing to test yet
}
