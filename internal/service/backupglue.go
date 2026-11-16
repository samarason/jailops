package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"jailops.net/jailops/internal/backup"
	"jailops.net/jailops/internal/imagegen"
	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// BackupAdmin is the key and run side of the host-side backup service
// (internal/hostbackup, adapted by the daemon). While none is wired the key
// and run routes answer api.CodeUnsupported.
type BackupAdmin interface {
	CreateKey(ctx context.Context, recipients []string) (api.BackupKeyCreated, error)
	EscrowKey(ctx context.Context, recipients []string) error
	KeyStatus(ctx context.Context) (api.BackupKeyStatus, error)
	RunPolicy(ctx context.Context, project, policy string, noVolumes bool) ([]api.BackupRun, error)
	Verify(ctx context.Context, backupID, depth string) (api.BackupRun, error)
}

func (s *Service) backupAdmin() (BackupAdmin, error) {
	if s.d.BackupAdmin == nil {
		return nil, s.backupsUnsupported()
	}
	return s.d.BackupAdmin, nil
}

// CreateBackupKey creates the host's backup key. The recovery key is in the
// reply and nowhere else: it is not an operation result, not in the audit
// detail, not in a log line.
func (s *Service) CreateBackupKey(ctx context.Context, in api.BackupKeyCreate) (api.BackupKeyCreated, error) {
	if err := requireGlobal(ctx, "creating the backup key"); err != nil {
		return api.BackupKeyCreated{}, err
	}
	a, err := s.backupAdmin()
	if err != nil {
		return api.BackupKeyCreated{}, err
	}
	return a.CreateKey(ctx, in.Recipients)
}

// EscrowBackupKey wraps the key to the recovery recipients and uploads it.
func (s *Service) EscrowBackupKey(ctx context.Context, in api.BackupKeyEscrow) (api.BackupKeyStatus, error) {
	if err := requireGlobal(ctx, "escrowing the backup key"); err != nil {
		return api.BackupKeyStatus{}, err
	}
	a, err := s.backupAdmin()
	if err != nil {
		return api.BackupKeyStatus{}, err
	}
	if err := a.EscrowKey(ctx, in.Recipients); err != nil {
		return api.BackupKeyStatus{}, err
	}
	return a.KeyStatus(ctx)
}

// BackupKeyStatus reports none, present or escrowed.
func (s *Service) BackupKeyStatus(ctx context.Context) (api.BackupKeyStatus, error) {
	if err := requireGlobal(ctx, "reading the backup key status"); err != nil {
		return api.BackupKeyStatus{}, err
	}
	a, err := s.backupAdmin()
	if err != nil {
		return api.BackupKeyStatus{}, err
	}
	return a.KeyStatus(ctx)
}

// RunBackups runs a backup policy now, as an operation.
func (s *Service) RunBackups(ctx context.Context, req api.BackupRunRequest) (api.Operation, error) {
	if err := requireGlobal(ctx, "running backups"); err != nil {
		return api.Operation{}, err
	}
	a, err := s.backupAdmin()
	if err != nil {
		return api.Operation{}, err
	}
	if req.Policy == "" {
		return api.Operation{}, invalid("policy is required")
	}
	project, err := requestProject(ctx)
	if err != nil {
		return api.Operation{}, err
	}
	return s.Submit(ctx, OpSpec{Description: "Run backup policy " + req.Policy,
		Resources: map[string][]string{"backup-policies": {"/api/v1/backup-policies/" + req.Policy}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			runs, err := a.RunPolicy(ctx, project, req.Policy, req.NoVolumes)
			return runs, err
		}})
}

// VerifyBackup runs a restore test of one backup, as an operation.
func (s *Service) VerifyBackup(ctx context.Context, id string, req api.BackupVerifyRequest) (api.Operation, error) {
	a, err := s.backupAdmin()
	if err != nil {
		if !ActorFrom(ctx).HasScope() {
			return api.Operation{}, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
		}
		return api.Operation{}, err
	}
	b, err := s.GetBackup(ctx, id)
	if err != nil {
		return api.Operation{}, err
	}
	switch req.Depth {
	case "", "deep", "extract", "full":
	default:
		return api.Operation{}, invalid("depth must be deep, extract or full")
	}
	return s.Submit(ctx, OpSpec{Description: "Verify backup " + id, Project: backupProject(b),
		Resources: map[string][]string{"backups": {"/api/v1/backups/" + id}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			return a.Verify(ctx, id, req.Depth)
		}})
}

// ---- what the backup service reads ----

// BackupJail is one jail as capture needs it.
type BackupJail struct {
	Key     string
	Name    string
	UUID    string
	Project string
	Labels  map[string]string
	Spec    api.JailSpec
	Layout  lifecycle.JailLayout
	Image   api.ImageGeneration
	// VolumeIDs maps the name of each volume of the jail (its profiles' included) that has a dataset to its UUID.
	VolumeIDs map[string]string
}

// BackupJails lists the jails of this host with their dataset layout.
func (s *Service) BackupJails(ctx context.Context) ([]BackupJail, error) {
	s.mu.RLock()
	keys := sortedKeys(s.jails)
	jails := make([]api.Jail, len(keys))
	for i, k := range keys {
		jails[i] = cloneJail(s.jails[k].jail)
	}
	s.mu.RUnlock()
	out := make([]BackupJail, 0, len(keys))
	for i, k := range keys {
		j := jails[i]
		lay, err := s.life.Layout(ctx, k)
		if err != nil {
			s.log.Warn("backup: a jail's datasets cannot be read; it is skipped", "jail", k, "err", err)
			continue
		}
		bj := BackupJail{Key: k, Name: j.Metadata.Name, UUID: j.Metadata.UUID, Project: j.Metadata.Project, Labels: j.Metadata.Labels, Spec: j.Spec, Layout: lay}
		for _, v := range s.effective(j).Volumes {
			if o, err := s.volKind.p(j.Metadata.Project).get(v.Name); err == nil && !o.Spec.IsHostDir() {
				if bj.VolumeIDs == nil {
					bj.VolumeIDs = map[string]string{}
				}
				bj.VolumeIDs[v.Name] = o.Meta.UUID
			}
		}
		if lay.Image != "" && lay.Generation > 0 {
			if si, ok := s.storageOfJail(k); ok {
				if g, err := s.life.Images.Resolve(ctx, si.Root, genRef(lay.Image, lay.Generation)); err == nil {
					bj.Image = g
				}
			}
		}
		out = append(out, bj)
	}
	return out, nil
}

// BackupVolume is one volume as the backup service sees it.
type BackupVolume struct {
	Name, UUID, Project string
	Labels              map[string]string
	Spec                api.VolumeSpec
	Dataset, Mountpoint string
	// Locked is true for an encrypted volume whose key is not loaded: its files cannot be read.
	Locked bool
}

// BackupVolumes lists the volumes of every project for the backup service.
func (s *Service) BackupVolumes(ctx context.Context) ([]BackupVolume, error) {
	projs, err := s.projKind.list()
	if err != nil {
		return nil, err
	}
	var out []BackupVolume
	for _, p := range projs {
		objs, err := s.volKind.p(p.Meta.Name).list()
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			if o.Spec.IsHostDir() {
				s.log.Info("backup: a volume of a host directory is not backed up: its files are the host's", "project", p.Meta.Name, "volume", o.Meta.Name, "path", o.Spec.Path)
				continue
			}
			si, ok := s.storage(o.Spec.Storage)
			if !ok || s.life == nil {
				s.log.Warn("backup: the storage of a volume is not there; it is skipped", "project", p.Meta.Name, "volume", o.Meta.Name, "storage", o.Spec.Storage)
				continue
			}
			st := si.lifecycle()
			bv := BackupVolume{Name: o.Meta.Name, UUID: o.Meta.UUID, Project: p.Meta.Name, Labels: o.Meta.Labels, Spec: o.Spec,
				Dataset: lifecycle.VolumeDS(st, p.Meta.Name, o.Meta.Name), Mountpoint: lifecycle.VolumeMP(st, p.Meta.Name, o.Meta.Name)}
			if o.Spec.Encrypted {
				if info, err := s.life.VolumeInfo(ctx, st, p.Meta.Name, o.Meta.Name); err == nil {
					bv.Locked = info.Locked
				}
			}
			out = append(out, bv)
		}
	}
	return out, nil
}

// RestoreVolume makes an empty volume of the project from the spec of a volume backup, the way volume create does,
// and registers it. The caller holds the lock of the volume. The returned undo removes it again. A storage the
// backup names that this host does not grant to the project is replaced by the project's only storage.
func (s *Service) RestoreVolume(ctx context.Context, projectName, name string, spec api.VolumeSpec, labels map[string]string, passphrase string) (string, func(context.Context) error, error) {
	p, err := s.projKind.get(projectName)
	if err != nil {
		return "", nil, notFound("project", projectName)
	}
	if _, ok := s.storage(spec.Storage); !ok || !specGrantsStorage(p.Spec, spec.Storage) {
		spec.Storage = ""
	}
	spec, si, mode, err := s.checkVolumeSpec(p, name, spec)
	if err != nil {
		return "", nil, err
	}
	if spec.Encrypted && (s.d.Keys == nil || passphrase == "") {
		return "", nil, invalid("an encrypted volume needs its passphrase and the helper's key operations")
	}
	ks := s.volKind.p(projectName)
	if err := ks.notTaken(name); err != nil {
		return "", nil, err
	}
	var pass []byte
	if spec.Encrypted {
		pass = []byte(passphrase)
		defer wipe(pass)
	}
	meta := api.ObjectMeta{Name: name, Project: projectName, Labels: labels}
	if _, err := s.makeVolume(ctx, p, si, meta, spec, mode, pass, true); err != nil {
		return "", nil, err
	}
	st := si.lifecycle()
	return lifecycle.VolumeDS(st, projectName, name), func(ctx context.Context) error { return s.dropVolume(ctx, projectName, name) }, nil
}

// CompleteRestoredVolume ends the restore of a volume made by RestoreVolume: no file agent writes it from now on.
func (s *Service) CompleteRestoredVolume(ctx context.Context, projectName, name string) error {
	o, err := s.volKind.p(projectName).get(name)
	if err != nil {
		return err
	}
	si, ok := s.storage(o.Spec.Storage)
	if !ok {
		return notFound("storage", o.Spec.Storage)
	}
	return s.life.CompleteVolume(ctx, si.lifecycle(), projectName, name)
}

// restoreVolumeBackup is the restore of a volume backup, as an operation: the volume is made in the project with the
// grants and the checks of volume create, then the backup is extracted into it.
func (s *Service) restoreVolumeBackup(ctx context.Context, p project, b api.Backup, req api.RestoreRequest) (*api.RestorePreflight, *api.Operation, error) {
	name := req.As
	if name == "" {
		name = b.Spec.Jail
	}
	if b.Spec.Volume == nil {
		return nil, nil, invalid("backup %s holds no volume spec", req.Backup)
	}
	target := p.Meta.Name
	if b.Spec.Volume.Encrypted {
		if err := api.CheckPassphrase(req.Passphrase); err != nil {
			return nil, nil, err
		}
	}
	spec := *b.Spec.Volume
	if _, ok := s.storage(spec.Storage); !ok || !specGrantsStorage(p.Spec, spec.Storage) {
		spec.Storage = ""
	}
	if _, _, _, err := s.checkVolumeSpec(p, name, spec); err != nil {
		return nil, nil, err
	}
	if err := s.volKind.p(target).notTaken(name); err != nil {
		return nil, nil, err
	}
	op, err := s.Submit(ctx, OpSpec{Description: "Restore backup " + req.Backup + " as volume " + name, Locks: []string{volumeLock(target, name)}, Project: target,
		Resources: map[string][]string{"volumes": {"/api/v1/volumes/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			return s.d.Backups.RestoreVolume(ctx, req)
		}})
	return nil, &op, err
}

func genRef(image string, n int) string { return image + "#g" + itoa(n) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// BackupObjects resolves networks, policies and address sets for a bundle.
// Networks are host-wide; policies and address sets belong to a project.
func (s *Service) BackupObjects(project string) backup.ObjectSource {
	return &backupObjects{s: s, project: project}
}

type backupObjects struct {
	s       *Service
	project string
}

func (o *backupObjects) Network(name string) (api.NetworkSpec, bool) {
	n, err := o.s.netKind.get(name)
	if err != nil {
		return api.NetworkSpec{}, false
	}
	return n.Spec, true
}

func (o *backupObjects) Policy(name string) (api.FirewallPolicySpec, bool) {
	n, err := o.s.polKind.p(o.project).get(name)
	if err != nil {
		return api.FirewallPolicySpec{}, false
	}
	return n.Spec, true
}

func (o *backupObjects) AddressSet(name string) (api.AddressSetSpec, bool) {
	n, err := o.s.setKind.p(o.project).get(name)
	if err != nil {
		return api.AddressSetSpec{}, false
	}
	return n.Spec, true
}

// BackupPolicies lists the backup policies of every project.
func (s *Service) BackupPolicies() ([]api.BackupPolicy, error) {
	projs, err := s.projKind.list()
	if err != nil {
		return nil, err
	}
	var out []api.BackupPolicy
	for _, p := range projs {
		objs, err := s.bpolKind.p(p.Meta.Name).list()
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			out = append(out, bpolToAPI(o))
		}
	}
	return out, nil
}

// BackupTargets lists the backup targets.
func (s *Service) BackupTargets() ([]api.BackupTarget, error) {
	objs, err := s.tgtKind.list()
	if err != nil {
		return nil, err
	}
	out := make([]api.BackupTarget, 0, len(objs))
	for _, o := range objs {
		out = append(out, api.BackupTarget{Metadata: o.Meta, Spec: o.Spec})
	}
	return out, nil
}

// ---- restore ----

// RestoreState gathers the facts of this host for a restore into a project.
func (s *Service) RestoreState(ctx context.Context, project string) (backup.HostState, error) {
	st := backup.HostState{Generations: map[string]string{}, Networks: map[string]api.NetworkSpec{}, Policies: map[string]api.FirewallPolicySpec{},
		AddressSets: map[string]api.AddressSetSpec{}, Jails: map[string]backup.JailRef{}, Secrets: map[string]bool{}}
	nets, err := s.netKind.list()
	if err != nil {
		return st, err
	}
	for _, n := range nets {
		st.Networks[n.Meta.Name] = n.Spec
	}
	pols, err := s.polKind.p(project).list()
	if err != nil {
		return st, err
	}
	for _, p := range pols {
		st.Policies[p.Meta.Name] = p.Spec
	}
	sets, err := s.setKind.p(project).list()
	if err != nil {
		return st, err
	}
	for _, x := range sets {
		st.AddressSets[x.Meta.Name] = x.Spec
	}
	vols, err := s.volKind.p(project).list()
	if err != nil {
		return st, err
	}
	st.Volumes = map[string]bool{}
	for _, v := range vols {
		st.Volumes[v.Meta.Name] = true
	}
	s.mu.RLock()
	for _, k := range sortedKeys(s.jails) {
		j := s.jails[k].jail
		if j.Metadata.Project == project {
			st.Jails[j.Metadata.Name] = backup.JailRef{Name: j.Metadata.Name, UUID: j.Metadata.UUID}
		}
		for _, at := range j.Spec.Network {
			for _, v := range []string{at.IPv4, at.IPv6} {
				if _, ok := parseAddr(v); ok {
					st.Leases = append(st.Leases, api.Lease{Address: v, Jail: jailDisplay(j.Metadata.Project, j.Metadata.Name), Network: at.Network})
				}
			}
		}
	}
	s.mu.RUnlock()
	return st, nil
}

// RestorePlacement is where a restored jail goes.
type RestorePlacement struct {
	Container, Mountpoint, Root, RootMountpoint string
	Key                                         string
}

// RestorePlace decides the datasets of a jail restored into project. The
// jail is placed on the storage the backup's bundle names (the default
// storage when it names none) until the registry knows it.
func (s *Service) RestorePlace(ctx context.Context, project, name, storage string) (RestorePlacement, error) {
	key, err := validate.QualifiedName(project, name)
	if err != nil {
		return RestorePlacement{}, err
	}
	if storage == "" {
		storage = DefaultStorage
	}
	if _, ok := s.storage(storage); !ok {
		return RestorePlacement{}, api.Errorf(api.CodeNotFound, "storage %q does not exist on this host", storage)
	}
	s.place(key, storage)
	return RestorePlacement{Key: key, Container: s.lcfg.ContainerDS(key), Mountpoint: s.lcfg.ContainerMP(key), Root: s.lcfg.RootDS(key), RootMountpoint: s.lcfg.RootMP(key)}, nil
}

// RestoreEnsureObjects creates the networks, policies and address sets of a
// bundle that this host lacks, with the rights of the caller: a network is a
// host-level object, so an identity that is not global gets forbidden and the
// hint to map the network onto an existing one. The returned undo removes
// what was created.
func (s *Service) RestoreEnsureObjects(ctx context.Context, project string, b api.RestoreBundle, networkMap map[string]string) (func(context.Context) error, error) {
	var undos []func(context.Context) error
	undo := func(ctx context.Context) error {
		var first error
		for i := len(undos) - 1; i >= 0; i-- {
			if err := undos[i](ctx); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	pctx := WithProject(ctx, project)
	for i, n := range b.NetworkNames {
		if _, mapped := networkMap[n]; mapped || s.netKind.exists(n) {
			continue
		}
		if i >= len(b.Networks) {
			break
		}
		if _, err := s.CreateNetwork(ctx, api.Network{Metadata: api.ObjectMeta{Name: n}, Spec: b.Networks[i]}); err != nil {
			return undo, api.Errorf(api.CodeForbidden, "network %q of the backup does not exist here and cannot be created: %v", n, err).
				WithHint("restore with network_map onto an existing network")
		}
		n := n
		undos = append(undos, func(ctx context.Context) error { return s.DeleteNetwork(ctx, n, 0) })
	}
	for i, n := range b.AddressSetNames {
		if s.setKind.p(project).exists(n) || i >= len(b.AddressSets) {
			continue
		}
		if _, err := s.CreateAddressSet(pctx, api.AddressSet{Metadata: api.ObjectMeta{Name: n, Project: project}, Spec: b.AddressSets[i]}); err != nil {
			return undo, err
		}
		n := n
		undos = append(undos, func(ctx context.Context) error { return s.DeleteAddressSet(WithProject(ctx, project), n, 0) })
	}
	for i, n := range b.PolicyNames {
		if s.polKind.p(project).exists(n) || i >= len(b.Policies) {
			continue
		}
		if _, err := s.CreatePolicy(pctx, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: n, Project: project}, Spec: b.Policies[i]}); err != nil {
			return undo, err
		}
		n := n
		undos = append(undos, func(ctx context.Context) error { return s.DeletePolicy(WithProject(ctx, project), n, 0) })
	}
	return undo, nil
}

// RestoreAdopt writes spec.json and bundle.json of a restored jail and
// registers it. The undo forgets it again (the restore removes the datasets).
func (s *Service) RestoreAdopt(ctx context.Context, key string, j api.Jail, gen api.ImageGeneration) (func(context.Context) error, error) {
	if err := s.life.WriteRecords(ctx, key, j, gen); err != nil {
		return nil, err
	}
	if err := s.refreshJail(ctx, key); err != nil {
		return nil, err
	}
	// A restore asks for fresh addresses unless it keeps the old ones: allocate "auto" now, as a copy does.
	nj, err := s.jailSnapshot(key)
	if err != nil {
		return nil, err
	}
	if err := s.assignOwn(j.Metadata.Project, key, &nj.Spec); err != nil {
		return nil, fmt.Errorf("restored, but allocating addresses failed: %w", err)
	}
	if err := s.writeJailRecord(ctx, nj); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if e := s.jails[key]; e != nil {
		nj.Status.Generation = e.jail.Status.Generation
		e.jail = nj
	}
	s.mu.Unlock()
	s.kick()
	return func(ctx context.Context) error {
		s.mu.Lock()
		delete(s.jails, key)
		s.mu.Unlock()
		s.unplace(key)
		return nil
	}, nil
}

// RestoreRunning reports whether the jail runs.
func (s *Service) RestoreRunning(ctx context.Context, project, name string) (bool, error) {
	key, err := validate.QualifiedName(project, name)
	if err != nil {
		return false, err
	}
	if s.d.Jails == nil {
		return false, nil
	}
	_, up, err := s.d.Jails.Get(ctx, key)
	return up, err
}

// RestoreStart starts a restored jail.
func (s *Service) RestoreStart(ctx context.Context, project, name string) error {
	key, err := validate.QualifiedName(project, name)
	if err != nil {
		return err
	}
	return s.StartJail(ctx, key)
}

var _ = sort.Strings

// ImageManagerOf returns the image pool of a storage ("" is the default).
func (s *Service) ImageManagerOf(storage string) (*imagegen.Manager, error) {
	if storage == "" {
		storage = DefaultStorage
	}
	si, ok := s.storage(storage)
	if !ok {
		return nil, api.Errorf(api.CodeNotFound, "storage %q does not exist", storage)
	}
	return si.Images, nil
}

// ---- what a full restore test does with the jail it restored ----

func (s *Service) waitOp(ctx context.Context, op api.Operation, what string) error {
	done, err := s.WaitOperation(ctx, op.ID, 5*time.Minute)
	if err != nil {
		return err
	}
	switch done.Status {
	case api.OpSuccess:
		return nil
	case api.OpFailure, api.OpCancelled:
		if done.Error != nil {
			return fmt.Errorf("%s: %s", what, done.Error.Message)
		}
		return fmt.Errorf("%s failed", what)
	}
	return fmt.Errorf("%s did not finish in time", what)
}

// RestoreStop stops the jail a restore test started.
func (s *Service) RestoreStop(ctx context.Context, project, name string) error {
	ctx = WithProject(ctx, project)
	op, err := s.JailAction(ctx, name, api.JailAction{Action: "stop", Force: true})
	if err != nil {
		return err
	}
	return s.waitOp(ctx, op, "stopping "+name)
}

// RestoreDelete removes the jail a restore test restored, with its datasets.
func (s *Service) RestoreDelete(ctx context.Context, project, name string) error {
	ctx = WithProject(ctx, project)
	op, err := s.DeleteJail(ctx, name)
	if err != nil {
		if api.IsCode(err, api.CodeNotFound) {
			return nil
		}
		return err
	}
	return s.waitOp(ctx, op, "deleting "+name)
}

// RestoreExec runs a command in the jail of a restore test and returns what it printed (stdout and stderr
// together, at most 16 KiB) and its exit status.
func (s *Service) RestoreExec(ctx context.Context, project, name string, argv []string) (string, int, error) {
	if s.d.Execer == nil {
		return "", 0, api.Errorf(api.CodeUnsupported, "this daemon has no way to run commands in jails")
	}
	key, err := validate.QualifiedName(project, name)
	if err != nil {
		return "", 0, err
	}
	sess, err := s.d.Execer.Exec(ctx, key, argv, ExecOpts{})
	if err != nil {
		return "", 0, err
	}
	_ = sess.Stdin().Close()
	var mu sync.Mutex
	var buf bytes.Buffer
	var wg sync.WaitGroup
	for _, r := range []io.Reader{sess.Stdout(), sess.Stderr()} {
		if r == nil {
			continue
		}
		wg.Add(1)
		go func(r io.Reader) {
			defer wg.Done()
			b := make([]byte, 4096)
			for {
				n, err := r.Read(b)
				mu.Lock()
				if buf.Len() < 16<<10 {
					buf.Write(b[:n])
				}
				mu.Unlock()
				if err != nil {
					return
				}
			}
		}(r)
	}
	code, werr := sess.Wait()
	wg.Wait()
	return buf.String(), code, werr
}
