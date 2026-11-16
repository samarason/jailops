package hostbackup

import (
	"context"
	"errors"
	"jailops.net/jailops/internal/supervise"
	"sort"
	"sync"
	"time"

	"jailops.net/jailops/internal/schedule"
	"jailops.net/jailops/sdk/api"
)

// jobState is the schedule state of one (policy, jail, kind).
type jobState struct {
	spec     string    // the cron expression next was computed from
	next     time.Time // when the job is due (jittered)
	attempt  int       // failed tries of the current scheduled run
	inflight bool
}

// job is a due job.
type job struct {
	key    string
	kind   string // RunBackup or RunDrill
	policy api.BackupPolicy
	jail   JailRecord
	due    time.Time
}

// selects reports whether the policy's selector matches the jail. An empty
// selector matches none; the key "all" matches every jail of the policy's
// project.
func selects(p api.BackupPolicy, j JailRecord) bool {
	if p.Metadata.Project == "" || p.Metadata.Project != j.Project { // a policy and a jail both belong to a named project
		return false
	}
	sel := p.Spec.Selector
	if len(sel) == 0 {
		return false
	}
	if _, all := sel["all"]; all {
		return true
	}
	for k, v := range sel {
		if got, ok := j.Labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

func jobKey(kind, policy, jail string) string { return kind + "|" + policy + "|" + jail }

// nextFire is the next scheduled time after base, with the deterministic
// jitter of this jail and policy.
func (s *Service) nextFire(expr string, base time.Time, jail, policy string) (time.Time, bool) {
	spec, err := schedule.Parse(expr)
	if err != nil {
		return time.Time{}, false
	}
	w := s.cfg.JitterWindow
	if w < 0 {
		w = 0
	}
	return spec.NextWithJitter(base, s.cfg.Location, jail+"/"+policy, w)
}

// stateJail returns the host state record when a policy asks for it.
func (s *Service) stateJail(ctx context.Context) (JailRecord, bool) {
	if s.deps.State == nil {
		return JailRecord{}, false
	}
	j, err := s.deps.State.StateRecord(ctx)
	if err != nil {
		s.cfg.Log.Error("backup: reading the state dataset record failed", "err", err)
		return JailRecord{}, false
	}
	j.IsState = true
	return j, true
}

// members returns the jails a policy applies to, plus the state record when
// include_state is set, plus the volumes (see volumeMembers).
func (s *Service) members(ctx context.Context, p api.BackupPolicy, jails []JailRecord, noVolumes bool) []JailRecord {
	var out []JailRecord
	var chosen []JailRecord
	for _, j := range jails {
		if selects(p, j) {
			out = append(out, j)
			chosen = append(chosen, j)
		}
	}
	if p.Spec.IncludeState {
		if st, ok := s.stateJail(ctx); ok {
			out = append(out, st)
		}
	}
	if !p.Spec.ExcludeVolumes && !noVolumes {
		out = append(out, s.volumeMembers(ctx, p, chosen)...)
	}
	return out
}

// volumeMembers returns the volumes a policy backs up: those the selected jails attach and those whose own labels
// match the selector. A volume is one record, so it is backed up once per run however many jails attach it.
func (s *Service) volumeMembers(ctx context.Context, p api.BackupPolicy, chosen []JailRecord) []JailRecord {
	if s.deps.Volumes == nil {
		return nil
	}
	vols, err := s.deps.Volumes.Volumes(ctx)
	if err != nil {
		s.cfg.Log.Error("backup: listing the volumes failed", "err", err)
		return nil
	}
	attached := map[string]bool{}
	for _, j := range chosen {
		for _, v := range j.Spec.Volumes {
			attached[j.Project+"/"+v.Name] = true
		}
	}
	var out []JailRecord
	seen := map[string]bool{}
	for _, v := range vols {
		v.IsVolume = true
		if v.Project != p.Metadata.Project || seen[v.UUID] {
			continue
		}
		if attached[v.Project+"/"+v.Name] || selects(p, v) {
			seen[v.UUID] = true
			out = append(out, v)
		}
	}
	return out
}

// lastStart finds when the last successful run of the key started.
func lastStart(runs []Run, kind, policy, jailUUID string) time.Time {
	var t time.Time
	for _, r := range runs {
		if r.OK && r.Kind == kind && r.Policy == policy && r.JailUUID == jailUUID && r.Started.After(t) {
			t = r.Started
		}
	}
	return t
}

// dueJobs evaluates every policy and returns the jobs that are due at now,
// oldest due time first. It creates and refreshes the schedule state.
func (s *Service) dueJobs(ctx context.Context, now time.Time) ([]job, error) {
	if s.deps.Policies == nil || s.deps.Jails == nil {
		return nil, nil
	}
	policies, err := s.deps.Policies.BackupPolicies(ctx)
	if err != nil {
		return nil, err
	}
	jails, err := s.deps.Jails.Jails(ctx)
	if err != nil {
		return nil, err
	}
	runs, err := s.deps.Catalog.Runs(ctx)
	if err != nil {
		return nil, err
	}
	var due []job
	seen := map[string]bool{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range policies {
		for _, j := range s.members(ctx, p, jails, false) {
			for _, k := range []struct{ kind, expr string }{{RunBackup, p.Spec.Schedule}, {RunDrill, p.Spec.VerifySchedule}} {
				if k.expr == "" {
					continue
				}
				key := jobKey(k.kind, p.Metadata.Name, j.UUID)
				seen[key] = true
				st := s.sched[key]
				if st == nil || st.spec != k.expr {
					base := lastStart(runs, k.kind, p.Metadata.Name, j.UUID)
					if base.IsZero() || (st != nil && st.spec != k.expr) {
						base = now
					}
					next, ok := s.nextFire(k.expr, base, j.UUID, p.Metadata.Name)
					if !ok {
						continue
					}
					inflight := st != nil && st.inflight
					st = &jobState{spec: k.expr, next: next, inflight: inflight}
					s.sched[key] = st
				}
				if !st.inflight && !now.Before(st.next) {
					due = append(due, job{key: key, kind: k.kind, policy: p, jail: j, due: st.next})
				}
			}
		}
	}
	for key, st := range s.sched {
		if !seen[key] && !st.inflight {
			delete(s.sched, key)
		}
	}
	sort.SliceStable(due, func(a, b int) bool {
		if !due[a].due.Equal(due[b].due) {
			return due[a].due.Before(due[b].due)
		}
		return due[a].key < due[b].key
	})
	return due, nil
}

// Tick starts the jobs that are due, up to the concurrency limit, and returns
// how many it started. Jobs run in the background; Wait waits for them.
func (s *Service) Tick(ctx context.Context) (int, error) {
	due, err := s.dueJobs(ctx, s.now())
	if err != nil {
		return 0, err
	}
	started := 0
	seenJail := map[string]bool{}
	for _, jo := range due {
		if seenJail[jo.jail.UUID] || s.isBusy(jo.jail.UUID) {
			continue // one job per jail at a time; it stays due
		}
		select {
		case s.sem <- struct{}{}:
		default:
			return started, nil
		}
		s.mu.Lock()
		st := s.sched[jo.key]
		if st == nil || st.inflight {
			s.mu.Unlock()
			<-s.sem
			continue
		}
		st.inflight = true
		s.mu.Unlock()
		seenJail[jo.jail.UUID] = true
		started++
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			_ = supervise.Guard(nil, "backup-job", func() { s.runJob(ctx, jo) })
		}()
	}
	return started, nil
}

// Wait blocks until every job that was started has finished.
func (s *Service) Wait() { s.wg.Wait() }

// RunDue runs every due job and the retries that become due while it works,
// then returns. With a deterministic clock this is the test entry point.
func (s *Service) RunDue(ctx context.Context) error {
	for {
		n, err := s.Tick(ctx)
		if err != nil {
			s.Wait()
			return err
		}
		s.Wait()
		if n == 0 {
			// jobs may be left behind busy jails or full slots: try again
			// while some are still due and something finished
			return nil
		}
	}
}

// Run is the scheduler loop of the daemon: it cleans up stale snapshots, then
// looks for due jobs every Config.Tick until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	if n, err := s.CleanupStale(ctx); err != nil {
		s.cfg.Log.Error("backup: removing stale snapshots failed", "err", err)
	} else if n > 0 {
		s.cfg.Log.Info("backup: removed stale snapshots", "count", n)
	}
	for {
		if _, err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Log.Error("backup: evaluating policies failed", "err", err)
		}
		if err := s.cfg.Sleep(ctx, s.cfg.Tick); err != nil {
			s.Wait()
			return err
		}
	}
}

// runJob runs one scheduled job and sets the next time.
func (s *Service) runJob(ctx context.Context, jo job) {
	s.mu.Lock()
	attempt := s.sched[jo.key].attempt + 1
	s.mu.Unlock()
	started := s.now()
	var err error
	switch jo.kind {
	case RunBackup:
		_, err = s.BackupJail(ctx, jo.jail, s.captureOptions(jo.policy, attempt))
	case RunDrill:
		_, err = s.drillJail(ctx, jo.policy, jo.jail, attempt)
	}
	s.finishJob(jo, started, attempt, err)
}

func (s *Service) captureOptions(p api.BackupPolicy, attempt int) CaptureOptions {
	return CaptureOptions{Policy: p.Metadata.Name, Targets: p.Spec.Targets, Scheduled: true, Attempt: attempt,
		FullEvery: time.Duration(p.Spec.FullEvery) * 24 * time.Hour}
}

// retryable says whether a failure is worth another try soon.
func retryable(err error) bool {
	switch errCode(err) {
	case api.CodeKeyNotEscrowed, api.CodePlaintextDenied, api.CodeInvalid, api.CodeForbidden, api.CodeNotFound,
		api.CodeUnsupported, api.CodeAlreadyExists, api.CodeLocked:
		return false
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, ErrVerifyFailed)
}

func (s *Service) finishJob(jo job, started time.Time, attempt int, err error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.sched[jo.key]
	if st == nil {
		return
	}
	st.inflight = false
	nextSlot := func() {
		st.attempt = 0
		if t, ok := s.nextFire(st.spec, now, jo.jail.UUID, jo.policy.Metadata.Name); ok {
			st.next = t
		}
	}
	switch {
	case err == nil:
		nextSlot()
	case errCode(err) == api.CodeBusy:
		st.next = now // another job holds the jail: try again at the next tick
	case errCode(err) == api.CodeMaintenance:
		st.next = now.Add(s.cfg.MaintenanceDelay)
	case !retryable(err):
		s.cfg.Log.Error("backup: job failed and will not be retried until its next slot", "policy", jo.policy.Metadata.Name, "jail", jo.jail.Name, "err", err)
		nextSlot()
	default:
		s.cfg.Log.Warn("backup: job failed", "policy", jo.policy.Metadata.Name, "jail", jo.jail.Name, "attempt", attempt, "err", err)
		if attempt >= s.cfg.Retry.Attempts {
			nextSlot()
			break
		}
		st.attempt = attempt
		st.next = now.Add(s.backoff(attempt, jo.jail.UUID+"/"+jo.policy.Metadata.Name))
	}
}

// backoff is Base * 2^(attempt-1), at most Max, plus a deterministic jitter of
// up to a quarter.
func (s *Service) backoff(attempt int, id string) time.Duration {
	d := s.cfg.Retry.Base
	for i := 1; i < attempt && d < s.cfg.Retry.Max; i++ {
		d *= 2
	}
	d = min(d, s.cfg.Retry.Max)
	return d + schedule.Jitter(id+"/"+string(rune('0'+attempt%10)), d/4)
}

// PolicyByName returns a backup policy of the host.
func (s *Service) policyByName(ctx context.Context, project, name string) (api.BackupPolicy, error) {
	if s.deps.Policies == nil {
		return api.BackupPolicy{}, api.Errorf(api.CodeUnsupported, "no backup policy source is configured")
	}
	ps, err := s.deps.Policies.BackupPolicies(ctx)
	if err != nil {
		return api.BackupPolicy{}, err
	}
	if project == "" {
		return api.BackupPolicy{}, api.Errorf(api.CodeInvalid, "a project is required")
	}
	for _, p := range ps {
		// Policy names are unique per project, not per host.
		if p.Metadata.Name == name && p.Metadata.Project == project {
			return p, nil
		}
	}
	return api.BackupPolicy{}, api.Errorf(api.CodeNotFound, "backup policy %q does not exist in project %q", name, project)
}

// RunNow runs the policy of the project immediately for every jail it selects (and the state
// dataset when include_state is set), outside the schedule, with at most
// Config.Concurrency jobs at once and one per jail. It returns one Run per
// jail and target; a failed job is a Run with OK false, not an error.
func (s *Service) RunNow(ctx context.Context, project, policy string) ([]Run, error) {
	return s.RunNowWith(ctx, project, policy, RunOptions{})
}

// RunOptions change one RunNow.
type RunOptions struct {
	// NoVolumes leaves the volumes out of this run.
	NoVolumes bool
}

// RunNowWith is RunNow with options.
func (s *Service) RunNowWith(ctx context.Context, project, policy string, o RunOptions) ([]Run, error) {
	p, err := s.policyByName(ctx, project, policy)
	if err != nil {
		return nil, err
	}
	var jails []JailRecord
	if s.deps.Jails != nil {
		if jails, err = s.deps.Jails.Jails(ctx); err != nil {
			return nil, err
		}
	}
	members := s.members(ctx, p, jails, o.NoVolumes)
	s.cfg.Log.Info("backup: run policy", "policy", policy, "project", p.Metadata.Project, "selector", p.Spec.Selector, "jails", len(jails), "selected", len(members))
	var (
		mu  sync.Mutex
		out []Run
		wg  sync.WaitGroup
	)
	for _, j := range members {
		s.sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-s.sem }()
			var res *CaptureResult
			var err error
			if perr := supervise.Guard(nil, "backup-jail", func() {
				res, err = s.BackupJail(ctx, j, CaptureOptions{Policy: policy, Targets: p.Spec.Targets,
					FullEvery: time.Duration(p.Spec.FullEvery) * 24 * time.Hour})
			}); perr != nil {
				res, err = nil, perr
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case res != nil && len(res.Targets) > 0:
				for _, t := range res.Targets {
					out = append(out, t.Run)
				}
			default:
				now := s.now()
				out = append(out, Run{ID: s.newID("run"), Kind: RunBackup, Policy: policy, Project: j.Project, Jail: j.Name, JailUUID: j.UUID,
					Started: now, Finished: now, Error: errString(err), Code: errCode(err)})
			}
		}()
	}
	wg.Wait()
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Jail != out[b].Jail {
			return out[a].Jail < out[b].Jail
		}
		return out[a].Target < out[b].Target
	})
	return out, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// NextRun reports when the scheduler will next run a job (zero when unknown).
func (s *Service) NextRun(kind, policy, jailUUID string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.sched[jobKey(kind, policy, jailUUID)]; st != nil {
		return st.next
	}
	return time.Time{}
}
