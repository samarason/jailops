package service

import (
	"context"
	"encoding/json"
	"jailops.net/jailops/internal/supervise"
	"slices"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/schedule"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// ---- remotes (hub) ----

// RemoteProber asks a remote host for its GET /api/v1 over pinned mTLS.
type RemoteProber interface {
	Probe(ctx context.Context, r api.Remote) (api.ServerInfo, error)
}

var remoteStatus sync.Map // remote uuid -> api.RemoteStatus

func (s *Service) remoteToAPI(o object[api.RemoteSpec]) api.Remote {
	r := api.Remote{Metadata: o.Meta, Spec: o.Spec}
	if v, ok := remoteStatus.Load(s.d.HostUUID + "/" + o.Meta.UUID); ok {
		r.Status = v.(api.RemoteStatus)
	}
	return r
}

func (s *Service) requireHub() error {
	if !s.d.Hub {
		return api.Errorf(api.CodeUnsupported, "this daemon is not a hub").WithHint("start jailopsd with hub mode enabled")
	}
	return nil
}

func (s *Service) checkRemote(name string, spec *api.RemoteSpec) error {
	if err := ValidObjectName(name); err != nil {
		return err
	}
	if spec.Address == "" {
		return invalid("spec.address is required")
	}
	fp, err := auth.NormalizeFingerprint(spec.Fingerprint)
	if err != nil {
		return invalid("spec.fingerprint: %v", err)
	}
	spec.Fingerprint = fp
	return nil
}

// ListRemotes lists the registry of remotes.
func (s *Service) ListRemotes(ctx context.Context, labels map[string]string) ([]api.Remote, error) {
	if err := requireGlobal(ctx, "remotes"); err != nil {
		return nil, err
	}
	objs, err := s.remKind.list()
	if err != nil {
		return nil, err
	}
	out := []api.Remote{}
	for _, o := range objs {
		if MatchLabels(o.Meta.Labels, labels) {
			out = append(out, s.remoteToAPI(o))
		}
	}
	return out, nil
}

// GetRemote returns one remote.
func (s *Service) GetRemote(ctx context.Context, name string) (api.Remote, error) {
	if err := requireGlobal(ctx, "remotes"); err != nil {
		return api.Remote{}, err
	}
	o, err := s.remKind.get(name)
	if err != nil {
		return api.Remote{}, err
	}
	return s.remoteToAPI(o), nil
}

// CreateRemote registers a remote host. It is probed once; an unreachable
// remote is still registered (it shows as offline).
func (s *Service) CreateRemote(ctx context.Context, r api.Remote) (api.Remote, error) {
	if err := requireGlobal(ctx, "registering a remote"); err != nil {
		return api.Remote{}, err
	}
	if err := s.requireHub(); err != nil {
		return api.Remote{}, err
	}
	if err := s.remKind.notTaken(r.Metadata.Name); err != nil {
		return api.Remote{}, err
	}
	if err := s.checkRemote(r.Metadata.Name, &r.Spec); err != nil {
		return api.Remote{}, err
	}
	if info, err := s.probe(ctx, api.Remote{Metadata: r.Metadata, Spec: r.Spec}); err == nil && r.Spec.HostUUID == "" {
		r.Spec.HostUUID = info.HostUUID
	}
	o, err := s.remKind.create(ctx, r.Metadata, r.Spec)
	if err != nil {
		return api.Remote{}, err
	}
	s.probeStore(ctx, o)
	return s.remoteToAPI(o), nil
}

// UpdateRemote replaces a remote.
func (s *Service) UpdateRemote(ctx context.Context, name string, r api.Remote, expect int64) (api.Remote, error) {
	if err := requireGlobal(ctx, "changing a remote"); err != nil {
		return api.Remote{}, err
	}
	if err := s.requireHub(); err != nil {
		return api.Remote{}, err
	}
	if r.Metadata.Name != "" && r.Metadata.Name != name {
		return api.Remote{}, invalid("renaming is not supported")
	}
	if err := s.checkRemote(name, &r.Spec); err != nil {
		return api.Remote{}, err
	}
	o, err := s.remKind.update(ctx, name, expect, r.Metadata.Labels, &r.Metadata.ManagedBy, r.Spec)
	if err != nil {
		return api.Remote{}, err
	}
	return s.remoteToAPI(o), nil
}

// PatchRemote applies a merge patch.
func (s *Service) PatchRemote(ctx context.Context, name string, patch map[string]any, expect int64) (api.Remote, error) {
	cur, err := s.GetRemote(ctx, name)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return cur, api.Errorf(api.CodeConflict, "remote %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	var out api.Remote
	if err := MergePatch(cur, patch, &out); err != nil {
		return out, err
	}
	return s.UpdateRemote(ctx, name, out, cur.Metadata.Generation)
}

// DeleteRemote forgets a remote.
func (s *Service) DeleteRemote(ctx context.Context, name string, expect int64) error {
	if err := requireGlobal(ctx, "forgetting a remote"); err != nil {
		return err
	}
	if err := s.requireHub(); err != nil {
		return err
	}
	return s.remKind.delete(ctx, name, expect)
}

func (s *Service) probe(ctx context.Context, r api.Remote) (api.ServerInfo, error) {
	if s.d.Remotes == nil {
		return api.ServerInfo{}, api.Errorf(api.CodeUnsupported, "no remote prober configured")
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.d.Remotes.Probe(pctx, r)
}

func (s *Service) probeStore(ctx context.Context, o object[api.RemoteSpec]) {
	st := api.RemoteStatus{}
	prev, _ := remoteStatus.Load(s.d.HostUUID + "/" + o.Meta.UUID)
	if p, ok := prev.(api.RemoteStatus); ok {
		st.LastSeen = p.LastSeen
	}
	info, err := s.probe(ctx, api.Remote{Metadata: o.Meta, Spec: o.Spec})
	if err == nil {
		st = api.RemoteStatus{Online: true, LastSeen: s.now().UTC(), Version: info.Version, Extensions: len(info.APIExtensions)}
	}
	remoteStatus.Store(s.d.HostUUID+"/"+o.Meta.UUID, st)
}

// ProbeRemotes refreshes the status of every remote (the daemon calls it periodically in hub mode).
func (s *Service) ProbeRemotes(ctx context.Context) {
	objs, err := s.remKind.list()
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	for _, o := range objs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { supervise.Report(s.log, "store-probe", recover()) }()
			s.probeStore(ctx, o)
		}()
	}
	wg.Wait()
}

// ResolveRemote finds a remote by name or host uuid for request forwarding.
func (s *Service) ResolveRemote(key string) (api.Remote, error) {
	if err := s.requireHub(); err != nil {
		return api.Remote{}, err
	}
	objs, err := s.remKind.list()
	if err != nil {
		return api.Remote{}, err
	}
	for _, o := range objs {
		if o.Meta.Name == key || o.Spec.HostUUID == key || o.Meta.UUID == key {
			return s.remoteToAPI(o), nil
		}
	}
	return api.Remote{}, notFound("host", key)
}

// ---- backup targets and policies (host side objects) ----

func (s *Service) checkTarget(name string, t api.BackupTargetSpec) error {
	if err := ValidObjectName(name); err != nil {
		return err
	}
	switch t.Kind {
	case "node":
		if t.Address == "" {
			return invalid("a node target needs an address")
		}
		if _, err := auth.NormalizeFingerprint(t.Fingerprint); err != nil {
			return invalid("a node target needs a pinned fingerprint: %v", err)
		}
	case "directory":
		if err := validate.AbsPath("path", t.Path); err != nil {
			return err
		}
	default:
		return invalid("backup target kind must be node or directory")
	}
	return nil
}

// ListTargets lists backup targets.
func (s *Service) ListTargets(ctx context.Context, labels map[string]string) ([]api.BackupTarget, error) {
	if err := requireGlobal(ctx, "backup targets"); err != nil {
		return nil, err
	}

	objs, err := s.tgtKind.list()
	if err != nil {
		return nil, err
	}
	out := []api.BackupTarget{}
	for _, o := range objs {
		if MatchLabels(o.Meta.Labels, labels) {
			out = append(out, api.BackupTarget{Metadata: o.Meta, Spec: o.Spec})
		}
	}
	return out, nil
}

// GetTarget returns a target.
func (s *Service) GetTarget(ctx context.Context, name string) (api.BackupTarget, error) {
	if err := requireGlobal(ctx, "backup targets"); err != nil {
		return api.BackupTarget{}, err
	}

	o, err := s.tgtKind.get(name)
	return api.BackupTarget{Metadata: o.Meta, Spec: o.Spec}, err
}

// CreateTarget stores a target.
func (s *Service) CreateTarget(ctx context.Context, t api.BackupTarget) (api.BackupTarget, error) {
	if err := requireGlobal(ctx, "backup targets"); err != nil {
		return api.BackupTarget{}, err
	}

	if err := s.tgtKind.notTaken(t.Metadata.Name); err != nil {
		return api.BackupTarget{}, err
	}
	if err := s.checkTarget(t.Metadata.Name, t.Spec); err != nil {
		return api.BackupTarget{}, err
	}
	if t.Spec.Fingerprint != "" {
		t.Spec.Fingerprint, _ = auth.NormalizeFingerprint(t.Spec.Fingerprint)
	}
	o, err := s.tgtKind.create(ctx, t.Metadata, t.Spec)
	return api.BackupTarget{Metadata: o.Meta, Spec: o.Spec}, err
}

// UpdateTarget replaces a target.
func (s *Service) UpdateTarget(ctx context.Context, name string, t api.BackupTarget, expect int64) (api.BackupTarget, error) {
	if err := requireGlobal(ctx, "backup targets"); err != nil {
		return api.BackupTarget{}, err
	}

	if t.Metadata.Name != "" && t.Metadata.Name != name {
		return api.BackupTarget{}, invalid("renaming is not supported")
	}
	if err := s.checkTarget(name, t.Spec); err != nil {
		return api.BackupTarget{}, err
	}
	if t.Spec.Fingerprint != "" {
		t.Spec.Fingerprint, _ = auth.NormalizeFingerprint(t.Spec.Fingerprint)
	}
	o, err := s.tgtKind.update(ctx, name, expect, t.Metadata.Labels, &t.Metadata.ManagedBy, t.Spec)
	return api.BackupTarget{Metadata: o.Meta, Spec: o.Spec}, err
}

// PatchTarget applies a merge patch.
func (s *Service) PatchTarget(ctx context.Context, name string, patch map[string]any, expect int64) (api.BackupTarget, error) {
	cur, err := s.GetTarget(ctx, name)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return cur, api.Errorf(api.CodeConflict, "backup-target %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	var out api.BackupTarget
	if err := MergePatch(cur, patch, &out); err != nil {
		return out, err
	}
	return s.UpdateTarget(ctx, name, out, cur.Metadata.Generation)
}

// DeleteTarget removes a target no policy uses.
func (s *Service) DeleteTarget(ctx context.Context, name string, expect int64) error {
	if err := requireGlobal(ctx, "backup targets"); err != nil {
		return err
	}

	pols, _ := s.bpolKind.listAll()
	for _, p := range pols {
		for _, t := range p.Spec.Targets {
			if t == name {
				return api.Errorf(api.CodeBusy, "backup target %q is used by policy %q of project %q", name, p.Meta.Name, p.Meta.Project)
			}
		}
	}
	return s.tgtKind.delete(ctx, name, expect)
}

func (s *Service) checkBackupPolicy(name string, p api.BackupPolicySpec) error {
	if err := ValidObjectName(name); err != nil {
		return err
	}
	if len(p.Targets) == 0 {
		return invalid("a backup policy needs at least one target")
	}
	for _, t := range p.Targets {
		if !s.tgtKind.exists(t) {
			return notFound("backup-target", t)
		}
	}
	if _, err := schedule.Parse(p.Schedule); err != nil {
		return invalid("schedule: %v", err)
	}
	if p.VerifySchedule != "" {
		if _, err := schedule.Parse(p.VerifySchedule); err != nil {
			return invalid("verify_schedule: %v", err)
		}
	}
	switch p.VerifyMode {
	case "", "deep", "extract", "full":
	default:
		return invalid("verify_mode must be deep, extract or full")
	}
	return nil
}

func bpolToAPI(o object[api.BackupPolicySpec]) api.BackupPolicy {
	return api.BackupPolicy{Metadata: o.Meta, Spec: o.Spec}
}

// ListBackupPolicies lists the backup policies of the request's project.
func (s *Service) ListBackupPolicies(ctx context.Context, labels map[string]string) ([]api.BackupPolicy, error) {
	p, err := s.access(ctx)
	if err != nil {
		return nil, err
	}
	objs, err := s.bpolKind.p(p.Meta.Name).list()
	if err != nil {
		return nil, err
	}
	out := []api.BackupPolicy{}
	for _, o := range objs {
		if MatchLabels(o.Meta.Labels, labels) {
			out = append(out, bpolToAPI(o))
		}
	}
	return out, nil
}

// GetBackupPolicy returns a policy.
func (s *Service) GetBackupPolicy(ctx context.Context, name string) (api.BackupPolicy, error) {
	p, err := s.access(ctx)
	if err != nil {
		return api.BackupPolicy{}, err
	}
	o, err := s.bpolKind.p(p.Meta.Name).get(name)
	return bpolToAPI(o), err
}

// CreateBackupPolicy stores a policy in the request's project.
func (s *Service) CreateBackupPolicy(ctx context.Context, in api.BackupPolicy) (api.BackupPolicy, error) {
	p, err := s.access(ctx)
	if err != nil {
		return api.BackupPolicy{}, err
	}
	if err := bodyProject(p.Meta.Name, in.Metadata.Project); err != nil {
		return api.BackupPolicy{}, err
	}
	ks := s.bpolKind.p(p.Meta.Name)
	if err := ks.notTaken(in.Metadata.Name); err != nil {
		return api.BackupPolicy{}, err
	}
	if err := s.checkBackupPolicy(in.Metadata.Name, in.Spec); err != nil {
		return api.BackupPolicy{}, err
	}
	o, err := ks.create(ctx, in.Metadata, in.Spec)
	return bpolToAPI(o), err
}

// UpdateBackupPolicy replaces a policy.
func (s *Service) UpdateBackupPolicy(ctx context.Context, name string, in api.BackupPolicy, expect int64) (api.BackupPolicy, error) {
	p, err := s.access(ctx)
	if err != nil {
		return api.BackupPolicy{}, err
	}
	if in.Metadata.Name != "" && in.Metadata.Name != name {
		return api.BackupPolicy{}, invalid("renaming is not supported")
	}
	if err := bodyProject(p.Meta.Name, in.Metadata.Project); err != nil {
		return api.BackupPolicy{}, err
	}
	ks := s.bpolKind.p(p.Meta.Name)
	if !ks.exists(name) {
		return api.BackupPolicy{}, notFound("backup-policy", name)
	}
	if err := s.checkBackupPolicy(name, in.Spec); err != nil {
		return api.BackupPolicy{}, err
	}
	o, err := ks.update(ctx, name, expect, in.Metadata.Labels, &in.Metadata.ManagedBy, in.Spec)
	return bpolToAPI(o), err
}

// PatchBackupPolicy applies a merge patch.
func (s *Service) PatchBackupPolicy(ctx context.Context, name string, patch map[string]any, expect int64) (api.BackupPolicy, error) {
	cur, err := s.GetBackupPolicy(ctx, name)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return cur, api.Errorf(api.CodeConflict, "backup-policy %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	var out api.BackupPolicy
	if err := MergePatch(cur, patch, &out); err != nil {
		return out, err
	}
	return s.UpdateBackupPolicy(ctx, name, out, cur.Metadata.Generation)
}

// DeleteBackupPolicy removes a policy.
func (s *Service) DeleteBackupPolicy(ctx context.Context, name string, expect int64) error {
	p, err := s.access(ctx)
	if err != nil {
		return err
	}
	return s.bpolKind.p(p.Meta.Name).delete(ctx, name, expect)
}

// ---- backups and restores ----

// Backups is the host-side backup backend (the repository engine client).
// While none is wired every backup and restore call answers api.CodeUnsupported.
type Backups interface {
	List(ctx context.Context) ([]api.Backup, error)
	Get(ctx context.Context, id string) (api.Backup, error)
	Delete(ctx context.Context, id string) error
	Preflight(ctx context.Context, req api.RestoreRequest) (api.RestorePreflight, error)
	Restore(ctx context.Context, req api.RestoreRequest) (api.Jail, error)
	// RestoreVolume restores a volume backup as a new volume of the project.
	RestoreVolume(ctx context.Context, req api.RestoreRequest) (api.Volume, error)
}

// backupRunning refuses an operation that destroys what a backup is reading: a delete of a jail or a volume while a
// backup of it runs would fail half way (the capture has its datasets mounted) or fail the backup. Backends that do not
// say whether a run is on its way are not asked.
func (s *Service) backupRunning(kind, name, uuid string) error {
	if b, ok := s.d.Backups.(interface{ Busy(uuid string) bool }); ok && uuid != "" && b.Busy(uuid) {
		return api.Errorf(api.CodeBusy, "a backup of %s %q is running", kind, name).WithHint("wait for it to finish (jailops backup list), then delete")
	}
	return nil
}

func (s *Service) backupsUnsupported() error {
	return api.Errorf(api.CodeUnsupported, "this daemon has no backup repository client configured").
		WithHint("backup capture and restore need the repository engine")
}

// backupProject is the project a backup belongs to.
func backupProject(b api.Backup) string { return b.Metadata.Project }

// ListBackups lists the backups the caller may see, narrowed by ?project=.
func (s *Service) ListBackups(ctx context.Context, labels map[string]string) ([]api.Backup, error) {
	all, projects, err := s.visibleProjects(ctx)
	if err != nil {
		return nil, err
	}
	if s.d.Backups == nil {
		return []api.Backup{}, nil
	}
	l, err := s.d.Backups.List(ctx)
	out := []api.Backup{}
	for _, b := range l {
		if (all || slices.Contains(projects, backupProject(b))) && MatchLabels(b.Metadata.Labels, labels) {
			out = append(out, b)
		}
	}
	return out, err
}

// GetBackup returns one backup, or not_found when it belongs to a project the
// caller may not use.
func (s *Service) GetBackup(ctx context.Context, id string) (api.Backup, error) {
	a := ActorFrom(ctx)
	if !a.HasScope() {
		return api.Backup{}, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	if s.d.Backups == nil {
		return api.Backup{}, notFound("backup", id)
	}
	b, err := s.d.Backups.Get(ctx, id)
	if err != nil || !a.CanProject(backupProject(b)) {
		return api.Backup{}, notFound("backup", id)
	}
	return b, nil
}

// DeleteBackup requests deletion as an operation.
func (s *Service) DeleteBackup(ctx context.Context, id string) (api.Operation, error) {
	if s.d.Backups == nil {
		if !ActorFrom(ctx).HasScope() {
			return api.Operation{}, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
		}
		return api.Operation{}, s.backupsUnsupported()
	}
	b, err := s.GetBackup(ctx, id)
	if err != nil {
		return api.Operation{}, err
	}
	return s.Submit(ctx, OpSpec{Description: "Delete backup " + id, Project: backupProject(b),
		Resources: map[string][]string{"backups": {"/api/v1/backups/" + id}},
		Run:       func(ctx context.Context, h *OpHandle) (any, error) { return nil, s.d.Backups.Delete(ctx, id) }})
}

// Restore runs a preflight (dry run, synchronous result) or a restore
// operation. The jail goes into the project the request names (body field
// project), else the one the call selected (?project=): there is no default.
// The caller needs access to it, and the project's grants and quotas apply
// like for a new jail.
func (s *Service) Restore(ctx context.Context, req api.RestoreRequest) (*api.RestorePreflight, *api.Operation, error) {
	a := ActorFrom(ctx)
	if !a.HasScope() {
		return nil, nil, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	if req.Backup == "" {
		return nil, nil, invalid("backup is required")
	}
	if s.d.Backups == nil {
		return nil, nil, s.backupsUnsupported()
	}
	b, err := s.GetBackup(ctx, req.Backup)
	if err != nil {
		return nil, nil, err
	}
	// a restore goes into the project it names: the request's, else the one the call selected; there is no default
	target := req.Project
	if target == "" {
		target = ProjectFrom(ctx)
	}
	if target == "" {
		return nil, nil, ErrProjectRequired().WithHint("name the project the jail is restored into with --project NAME")
	}
	if !a.CanProject(target) {
		return nil, nil, notFound("project", target)
	}
	p, err := s.projKind.get(target)
	if err != nil {
		return nil, nil, notFound("project", target)
	}
	req.Project = target
	pf, err := s.d.Backups.Preflight(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	if req.DryRun {
		return &pf, nil, nil
	}
	if !pf.OK {
		return nil, nil, invalid("restore preflight failed: %s", strings.TrimSpace("missing: "+join(pf.Missing)+" errors: "+join(pf.Errors))).
			WithDetail("missing", join(pf.Missing)).WithDetail("errors", join(pf.Errors))
	}
	if b.Spec.Kind == "volume" {
		return s.restoreVolumeBackup(ctx, p, b, req)
	}
	name := req.As
	if name == "" {
		name = b.Spec.Jail
	}
	key, err := validate.QualifiedName(target, name)
	if err != nil {
		return nil, nil, err
	}
	// Admission: the restored jail is checked like a new one (grants,
	// defaults, quotas) with its network map applied.
	// a deep copy: the network map is applied to the copy, never to the backup's own bundle
	var spec api.JailSpec
	raw, _ := json.Marshal(b.Spec.Bundle.Spec)
	_ = json.Unmarshal(raw, &spec)
	for i := range spec.Network {
		if m, ok := req.NetworkMap[spec.Network[i].Network]; ok {
			spec.Network[i].Network = m
		}
	}
	if req.NoVolumes {
		spec.Volumes = nil // the jail is restored with no attachments
	}
	var old *api.JailSpec
	s.mu.RLock()
	if e, ok := s.jails[key]; ok && req.Replace {
		o := e.jail.Spec
		old = &o
	}
	s.mu.RUnlock()
	release, err := s.admit(ctx, p, key, &spec, old)
	if err != nil {
		return nil, nil, err
	}
	locks := []string{jailLock(key)}
	if !req.NoVolumes {
		// the volumes of the jail that the project lacks are made by this restore
		for _, v := range b.Spec.Bundle.Volumes {
			if _, err := s.volKind.p(target).get(v); err != nil {
				locks = append(locks, volumeLock(target, v))
			}
		}
	}
	op, err := s.Submit(ctx, OpSpec{Description: "Restore backup " + req.Backup, Locks: locks, Project: target,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			defer release()
			return s.d.Backups.Restore(ctx, req)
		}})
	if err != nil {
		release()
	}
	return nil, &op, err
}

func join(l []string) string {
	out := ""
	for i, x := range l {
		if i > 0 {
			out += "; "
		}
		out += x
	}
	return out
}

// ---- resources ----

// Resources reports the capacity of the JailOps pool.
func (s *Service) Resources(ctx context.Context) (api.PoolUsage, error) {
	if err := requireGlobal(ctx, "reading pool usage"); err != nil {
		return api.PoolUsage{}, err
	}
	if s.d.ZClient == nil {
		return api.PoolUsage{}, api.Errorf(api.CodeUnsupported, "pool usage is not available")
	}
	pools, err := s.d.ZClient.ListPools(ctx)
	if err != nil {
		return api.PoolUsage{}, err
	}
	for _, p := range pools {
		if p.Name == s.d.Pool {
			return api.PoolUsage{Name: p.Name, Size: p.Size, Allocated: p.Allocated, Free: p.Free, Health: p.Health}, nil
		}
	}
	return api.PoolUsage{}, notFound("pool", s.d.Pool)
}
