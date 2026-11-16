package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"

	"jailops.net/jailops/internal/backup"
	"jailops.net/jailops/internal/fsagent"
	"jailops.net/jailops/internal/hostbackup"
	"jailops.net/jailops/internal/imagegen"
	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/internal/repo/catalog"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// lateSvc lets the backup service be built before the service layer it reads
// from: the service layer needs the backup backend in its Deps, the backend
// reads the service layer. set is called right after service.New.
type lateSvc struct{ s *service.Service }

func (l *lateSvc) get() (*service.Service, error) {
	if l.s == nil {
		return nil, api.Errorf(api.CodeBusy, "the daemon is still starting")
	}
	return l.s, nil
}

// hostBackups is the wiring of internal/hostbackup into the daemon: the
// service itself (it satisfies service.Backups) and the adapters it needs.
type hostBackups struct {
	svc  *hostbackup.Service
	late *lateSvc
}

// buildHostBackups builds the host-side backup service from the configuration.
// It is nil when the configuration has no backup section.
func buildHostBackups(cfg Config, hostUUID string, z zfs.Client, log *slog.Logger, opts Options, agents hostbackup.Agents, mounts hostbackup.DatasetMounter) (*hostBackups, error) {
	b := cfg.Backup
	if b == nil {
		return nil, nil
	}
	if z == nil {
		return nil, fmt.Errorf("backup: no ZFS client")
	}
	late := &lateSvc{}
	hc := hostbackup.Config{
		KeyPath: b.KeyPath, PassphraseFile: b.PassphraseFile, RecoveryRecipients: b.RecoveryRecipients, AllowUnescrowed: b.AllowUnescrowed,
		HostUUID: hostUUID, Concurrency: b.Concurrency, ScratchDir: b.ScratchDir, ScratchDataset: b.ScratchDataset, Log: log,
		Node: hostbackup.NodeConfig{Name: b.Node.Name, Address: b.Node.Address, Fingerprint: b.Node.Fingerprint, CertFile: b.Node.CertFile, KeyFile: b.Node.KeyFile},
	}
	if opts.BackupTLS != nil {
		hc.Node.TLS = opts.BackupTLS
	}
	cat, err := hostbackup.OpenFileCatalog(filepath.Join(cfg.StateDir, "backup-catalog.json"))
	if err != nil {
		return nil, fmt.Errorf("backup catalog: %w", err)
	}
	ad := &backupAdapters{late: late, defaultStorage: service.DefaultStorage}
	deps := hostbackup.Deps{
		ZFS: z, Jails: ad, Volumes: ad, Objects: ad, Policies: ad, Host: ad, Catalog: cat,
		Images: hostbackup.ImagegenImages{Manager: ad.imageManager}, Mounter: opts.BackupMounter, Agents: agents, Datasets: mounts,
	}
	svc, err := hostbackup.New(hc, deps)
	if err != nil {
		return nil, err
	}
	return &hostBackups{svc: svc, late: late}, nil
}

// backupAdmin adapts the host-side service to service.BackupAdmin.
type backupAdmin struct{ s *hostbackup.Service }

func (b backupAdmin) CreateKey(ctx context.Context, recipients []string) (api.BackupKeyCreated, error) {
	r, err := b.s.CreateKey(ctx, hostbackup.CreateKeyOptions{Recipients: recipients})
	if err != nil {
		return api.BackupKeyCreated{}, err
	}
	out := api.BackupKeyCreated{Domain: r.Domain, RecoveryKey: r.RecoveryKey, Escrowed: r.Escrowed}
	if r.EscrowErr != nil {
		out.EscrowError = r.EscrowErr.Error()
	}
	return out, nil
}

func (b backupAdmin) EscrowKey(ctx context.Context, recipients []string) error {
	return b.s.EscrowKey(ctx, recipients)
}

func (b backupAdmin) KeyStatus(ctx context.Context) (api.BackupKeyStatus, error) {
	st, err := b.s.Status(ctx)
	out := api.BackupKeyStatus{Status: st.Status.String(), Domain: st.Domain, Path: st.Path}
	// An unreachable node leaves the status "present"; that is an answer.
	_ = err
	return out, nil
}

func runToAPI(r hostbackup.Run) api.BackupRun {
	return api.BackupRun{ID: r.ID, Kind: r.Kind, Policy: r.Policy, Target: r.Target, Project: r.Project, Jail: r.Jail, JailUUID: r.JailUUID,
		Scheduled: r.Scheduled, Attempt: r.Attempt, Started: r.Started, Finished: r.Finished, OK: r.OK, Error: r.Error, Code: r.Code,
		Snapshot: r.Snapshot, Full: r.Full, Bytes: r.Bytes, NewBytes: r.NewBytes, Files: r.Files, Warnings: r.Warnings, Depth: r.Depth, Problems: r.Problems}
}

func (b backupAdmin) RunPolicy(ctx context.Context, project, policy string, noVolumes bool) ([]api.BackupRun, error) {
	runs, err := b.s.RunNowWith(ctx, project, policy, hostbackup.RunOptions{NoVolumes: noVolumes})
	out := make([]api.BackupRun, 0, len(runs))
	for _, r := range runs {
		out = append(out, runToAPI(r))
	}
	return out, err
}

func (b backupAdmin) Verify(ctx context.Context, id, depth string) (api.BackupRun, error) {
	d := backup.Depth(depth)
	if d == "" {
		d = backup.DepthDeep
	}
	r, err := b.s.RunDrill(ctx, id, d)
	return runToAPI(r), err
}

// ---- adapters over the service layer ----

type backupAdapters struct {
	late           *lateSvc
	defaultStorage string
}

// Jails implements hostbackup.JailSource.
func (a *backupAdapters) Jails(ctx context.Context) ([]hostbackup.JailRecord, error) {
	s, err := a.late.get()
	if err != nil {
		return nil, err
	}
	js, err := s.BackupJails(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]hostbackup.JailRecord, 0, len(js))
	for _, j := range js {
		rec := hostbackup.JailRecord{Name: j.Name, UUID: j.UUID, Project: j.Project, Labels: j.Labels, Spec: j.Spec,
			Container: j.Layout.Container, Image: j.Image, VolumeIDs: j.VolumeIDs}
		for _, d := range j.Layout.Datasets {
			hd := hostbackup.Dataset{Name: d.Name, Kind: d.Kind, Mountpoint: d.Mountpoint, Props: d.Props}
			if d.Delegated {
				hd.Skip = hostbackup.SkipDelegated
			}
			rec.Datasets = append(rec.Datasets, hd)
		}
		out = append(out, rec)
	}
	return out, nil
}

// Volumes implements hostbackup.VolumeSource: every volume of every project is one record, however many jails attach it.
func (a *backupAdapters) Volumes(ctx context.Context) ([]hostbackup.JailRecord, error) {
	s, err := a.late.get()
	if err != nil {
		return nil, err
	}
	vs, err := s.BackupVolumes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]hostbackup.JailRecord, 0, len(vs))
	for _, v := range vs {
		spec := v.Spec
		d := hostbackup.Dataset{Name: v.Dataset, Kind: hostbackup.KindVolume, Mountpoint: v.Mountpoint}
		if v.Locked {
			d.Skip = hostbackup.SkipLocked
		}
		out = append(out, hostbackup.JailRecord{Name: v.Name, UUID: v.UUID, Project: v.Project, Labels: v.Labels, Container: v.Dataset,
			IsVolume: true, Volume: &spec, Datasets: []hostbackup.Dataset{d}})
	}
	return out, nil
}

// RestoreVolume implements hostbackup.VolumeHost.
func (a *backupAdapters) RestoreVolume(ctx context.Context, project, name string, spec api.VolumeSpec, labels map[string]string, passphrase string) (string, func(context.Context) error, error) {
	s, err := a.late.get()
	if err != nil {
		return "", nil, err
	}
	return s.RestoreVolume(ctx, project, name, spec, labels, passphrase)
}

// CompleteVolume implements hostbackup.VolumeHost.
func (a *backupAdapters) CompleteVolume(ctx context.Context, project, name string) error {
	s, err := a.late.get()
	if err != nil {
		return err
	}
	return s.CompleteRestoredVolume(ctx, project, name)
}

// Network, Policy and AddressSet implement backup.ObjectSource without a project. There is no default project, so
// they find nothing; ForProject serves a named one.
func (a *backupAdapters) Network(string) (api.NetworkSpec, bool) { return api.NetworkSpec{}, false }
func (a *backupAdapters) Policy(string) (api.FirewallPolicySpec, bool) {
	return api.FirewallPolicySpec{}, false
}
func (a *backupAdapters) AddressSet(string) (api.AddressSetSpec, bool) {
	return api.AddressSetSpec{}, false
}
func (a *backupAdapters) ForProject(project string) backup.ObjectSource {
	s, err := a.late.get()
	if err != nil || project == "" {
		return emptyObjects{}
	}
	return s.BackupObjects(project)
}

type emptyObjects struct{}

func (emptyObjects) Network(string) (api.NetworkSpec, bool) { return api.NetworkSpec{}, false }
func (emptyObjects) Policy(string) (api.FirewallPolicySpec, bool) {
	return api.FirewallPolicySpec{}, false
}
func (emptyObjects) AddressSet(string) (api.AddressSetSpec, bool) { return api.AddressSetSpec{}, false }

// BackupPolicies and BackupTargets implement hostbackup.PolicySource.
func (a *backupAdapters) BackupPolicies(ctx context.Context) ([]api.BackupPolicy, error) {
	s, err := a.late.get()
	if err != nil {
		return nil, err
	}
	return s.BackupPolicies()
}

func (a *backupAdapters) BackupTargets(ctx context.Context) ([]api.BackupTarget, error) {
	s, err := a.late.get()
	if err != nil {
		return nil, err
	}
	return s.BackupTargets()
}

func (a *backupAdapters) imageManager(storage string) (*imagegen.Manager, error) {
	s, err := a.late.get()
	if err != nil {
		return nil, err
	}
	return s.ImageManagerOf(storage)
}

// Host implements hostbackup.Host and hostbackup.ProjectHost.
func (a *backupAdapters) State(ctx context.Context, storage string) (backup.HostState, error) {
	return backup.HostState{}, service.ErrProjectRequired()
}

func (a *backupAdapters) StateIn(ctx context.Context, project, storage string) (backup.HostState, error) {
	s, err := a.late.get()
	if err != nil {
		return backup.HostState{}, err
	}
	return s.RestoreState(ctx, project)
}

func (a *backupAdapters) Place(ctx context.Context, project, name, storage string) (hostbackup.Placement, error) {
	s, err := a.late.get()
	if err != nil {
		return hostbackup.Placement{}, err
	}
	p, err := s.RestorePlace(ctx, project, name, storage)
	if err != nil {
		return hostbackup.Placement{}, err
	}
	return hostbackup.Placement{Container: p.Container, Mountpoint: p.Mountpoint, Root: p.Root, RootMountpoint: p.RootMountpoint}, nil
}

func (a *backupAdapters) EnsureObjects(ctx context.Context, b api.RestoreBundle, nm map[string]string) (func(context.Context) error, error) {
	return nil, service.ErrProjectRequired()
}

func (a *backupAdapters) EnsureObjectsIn(ctx context.Context, project string, b api.RestoreBundle, nm map[string]string) (func(context.Context) error, error) {
	s, err := a.late.get()
	if err != nil {
		return nil, err
	}
	return s.RestoreEnsureObjects(ctx, project, b, nm)
}

// Adopt writes spec.json and bundle.json and registers the jail.
func keyOf(j api.Jail) (string, error) {
	return validate.QualifiedName(j.Metadata.Project, j.Metadata.Name)
}

func (a *backupAdapters) Adopt(ctx context.Context, in hostbackup.AdoptInput) (func(context.Context) error, error) {
	s, err := a.late.get()
	if err != nil {
		return nil, err
	}
	key, err := keyOf(in.Jail)
	if err != nil {
		return nil, err
	}
	return s.RestoreAdopt(ctx, key, in.Jail, in.Generation)
}

func (a *backupAdapters) Running(ctx context.Context, project, name string) (bool, error) {
	s, err := a.late.get()
	if err != nil {
		return false, err
	}
	return s.RestoreRunning(ctx, project, name)
}

func (a *backupAdapters) Start(ctx context.Context, project, name string) error {
	s, err := a.late.get()
	if err != nil {
		return err
	}
	return s.RestoreStart(ctx, project, name)
}

// privAgents gives the backup service file agents through the privileged helper: the daemon is not root, the
// agent is (confined to the one directory the helper checked).
type privAgents struct{ h priv.Host }

func (a privAgents) open(ctx context.Context, mode, dir string) (*fsagent.Client, error) {
	f, err := a.h.FSAgent(ctx, mode, dir)
	if err != nil {
		return nil, err
	}
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("the file agent's connection: %w", err)
	}
	return fsagent.NewClient(conn), nil
}

// ReadSnapshot implements hostbackup.Agents.
func (a privAgents) ReadSnapshot(ctx context.Context, dir string) (catalog.ScanFS, func(), error) {
	c, err := a.open(ctx, priv.AgentRead, dir)
	if err != nil {
		return nil, nil, err
	}
	return c, func() { c.Close() }, nil
}

// WriteTree implements hostbackup.Agents.
func (a privAgents) WriteTree(ctx context.Context, dir string) (catalog.Sink, func(), error) {
	c, err := a.open(ctx, priv.AgentWrite, dir)
	if err != nil {
		return nil, nil, err
	}
	return c, func() { c.Close() }, nil
}

// Stop, Delete and Exec make the adapter a hostbackup.DrillHost: a full restore test restores the backup as a jail
// of its own, boots it without a network, checks it and removes it, through the daemon's own jail operations.

// Stop implements hostbackup.DrillHost.
func (a *backupAdapters) Stop(ctx context.Context, project, name string) error {
	s, err := a.late.get()
	if err != nil {
		return err
	}
	return s.RestoreStop(ctx, project, name)
}

// Delete implements hostbackup.DrillHost.
func (a *backupAdapters) Delete(ctx context.Context, project, name string) error {
	s, err := a.late.get()
	if err != nil {
		return err
	}
	return s.RestoreDelete(ctx, project, name)
}

// Exec implements hostbackup.DrillHost.
func (a *backupAdapters) Exec(ctx context.Context, project, name string, argv []string) (string, int, error) {
	s, err := a.late.get()
	if err != nil {
		return "", 0, err
	}
	return s.RestoreExec(ctx, project, name, argv)
}

var _ hostbackup.DrillHost = (*backupAdapters)(nil)
