package service

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"jailops.net/jailops/internal/imagegen"
	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// DefaultStorage is the name of the storage every host has: the dataset the
// daemon is configured with, created at the first start.
const DefaultStorage = "default"

// StorageRegistrar tells the root helper which dataset roots it may touch.
// A storage is usable only after its dataset was registered, so a request to
// the helper for a dataset that no administrator named is refused there too.
type StorageRegistrar interface {
	RegisterStorage(ctx context.Context, dataset string) error
	UnregisterStorage(ctx context.Context, dataset string) error
}

// LocalRegistrar is the in-process implementation: it keeps the set of
// registered dataset roots in memory. It is used when jailopsd runs its own
// helper operations (development) and by tests.
type LocalRegistrar struct {
	mu  sync.Mutex
	set map[string]bool
}

// NewLocalRegistrar returns an empty registrar.
func NewLocalRegistrar() *LocalRegistrar { return &LocalRegistrar{set: map[string]bool{}} }

// RegisterStorage implements StorageRegistrar.
func (r *LocalRegistrar) RegisterStorage(_ context.Context, dataset string) error {
	if err := validate.StorageSpec("registrar", api.StorageSpec{Dataset: dataset}); err != nil {
		return err
	}
	r.mu.Lock()
	r.set[dataset] = true
	r.mu.Unlock()
	return nil
}

// UnregisterStorage implements StorageRegistrar.
func (r *LocalRegistrar) UnregisterStorage(_ context.Context, dataset string) error {
	r.mu.Lock()
	delete(r.set, dataset)
	r.mu.Unlock()
	return nil
}

// Has reports whether the dataset is registered.
func (r *LocalRegistrar) Has(dataset string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.set[dataset]
}

// Registered lists the registered datasets, sorted.
func (r *LocalRegistrar) Registered() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.set))
	for d := range r.set {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

// FakeRegistrar records the calls it receives and can be made to fail.
type FakeRegistrar struct {
	mu    sync.Mutex
	calls []string
	// RegisterErr and UnregisterErr are returned by the matching call.
	RegisterErr, UnregisterErr error
}

// RegisterStorage implements StorageRegistrar.
func (f *FakeRegistrar) RegisterStorage(_ context.Context, dataset string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "register "+dataset)
	return f.RegisterErr
}

// UnregisterStorage implements StorageRegistrar.
func (f *FakeRegistrar) UnregisterStorage(_ context.Context, dataset string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "unregister "+dataset)
	return f.UnregisterErr
}

// Calls returns the recorded calls in order.
func (f *FakeRegistrar) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// storageInfo is a storage as the daemon uses it: its dataset root, the
// directory the root is mounted under and the image pool of that root.
type storageInfo struct {
	Name      string
	Spec      api.StorageSpec
	Root      string
	MountBase string
	Images    *imagegen.Manager
}

func (si *storageInfo) lifecycle() lifecycle.Storage {
	return lifecycle.Storage{Name: si.Name, Root: si.Root, MountBase: si.MountBase}
}

// newImageManager builds the image pool of one storage. Pools are peers of
// each other: a generation a pool lacks is received from another.
func (s *Service) newImageManager(root, mountBase string) *imagegen.Manager {
	return &imagegen.Manager{
		Layout: imagegen.Layout{Root: root, MountBase: mountBase}, Work: s.d.WorkDir,
		ZFS: s.d.ImageZFS, Exec: execAdapter{s.d.Exec}, Files: s.d.Files, Executor: s.planExec,
		Specs: s.imageSpec, Now: s.d.Now, Sources: s.d.ImageSources, Peers: s.imageManagers,
	}
}

// addStorage registers a storage in memory.
func (s *Service) addStorage(name string, spec api.StorageSpec, root, mountBase string) *storageInfo {
	si := &storageInfo{Name: name, Spec: spec, Root: root, MountBase: mountBase}
	if s.life != nil {
		si.Images = s.newImageManager(root, mountBase)
	}
	s.stMu.Lock()
	s.storages[name] = si
	s.stMu.Unlock()
	return si
}

func (s *Service) dropStorage(name string) {
	s.stMu.Lock()
	delete(s.storages, name)
	s.stMu.Unlock()
}

// storage returns the storage of that name.
func (s *Service) storage(name string) (*storageInfo, bool) {
	s.stMu.RLock()
	defer s.stMu.RUnlock()
	si, ok := s.storages[name]
	return si, ok
}

// storageList returns every storage, sorted by name.
func (s *Service) storageList() []*storageInfo {
	s.stMu.RLock()
	defer s.stMu.RUnlock()
	out := make([]*storageInfo, 0, len(s.storages))
	for _, si := range s.storages {
		out = append(out, si)
	}
	slices.SortFunc(out, func(a, b *storageInfo) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// imageManagers lists the image pool of every storage, the default one first.
func (s *Service) imageManagers() []*imagegen.Manager {
	var out []*imagegen.Manager
	for _, si := range s.storageList() {
		if si.Images == nil {
			continue
		}
		if si.Name == DefaultStorage {
			out = append([]*imagegen.Manager{si.Images}, out...)
		} else {
			out = append(out, si.Images)
		}
	}
	return out
}

// defaultImages is the image pool API-level builds use by default.
func (s *Service) defaultImages() *imagegen.Manager {
	if si, ok := s.storage(DefaultStorage); ok {
		return si.Images
	}
	if l := s.imageManagers(); len(l) > 0 {
		return l[0]
	}
	return nil
}

// imagesOfRoot returns the image pool whose dataset root is root.
func (s *Service) imagesOfRoot(root string) *imagegen.Manager {
	for _, si := range s.storageList() {
		if si.Root == root {
			return si.Images
		}
	}
	return nil
}

// storageOfJail is the storage a jail key lives on: its spec says so, a
// jail that is being created is in the placement table, anything else is on
// the default storage.
func (s *Service) storageOfJail(key string) (*storageInfo, bool) {
	name := ""
	s.mu.RLock()
	if e, ok := s.jails[key]; ok {
		name = e.jail.Spec.Storage
	}
	s.mu.RUnlock()
	if name == "" {
		s.stMu.RLock()
		name = s.placed[key]
		s.stMu.RUnlock()
	}
	if name == "" {
		name = DefaultStorage
	}
	return s.storage(name)
}

// locate implements lifecycle.Config.Locate.
func (s *Service) locate(key string) (lifecycle.Storage, bool) {
	si, ok := s.storageOfJail(key)
	if !ok {
		return lifecycle.Storage{}, false
	}
	return si.lifecycle(), true
}

// lifecycleStorages implements lifecycle.Config.Storages.
func (s *Service) lifecycleStorages() []lifecycle.Storage {
	var out []lifecycle.Storage
	for _, si := range s.storageList() {
		out = append(out, si.lifecycle())
	}
	return out
}

// place records where a jail that is about to be created lives.
func (s *Service) place(key, storage string) {
	s.stMu.Lock()
	s.placed[key] = storage
	s.stMu.Unlock()
}

func (s *Service) unplace(key string) {
	s.stMu.Lock()
	delete(s.placed, key)
	s.stMu.Unlock()
}

// mountBaseOf finds the directory a dataset is mounted under.
func (s *Service) mountBaseOf(ctx context.Context, dataset string) string {
	if s.d.ZClient != nil {
		if m, err := s.d.ZClient.Get(ctx, dataset, "mountpoint"); err == nil {
			if v := m["mountpoint"].Value; strings.HasPrefix(v, "/") {
				return v
			}
		}
	}
	return "/" + dataset
}

// ---- API ----

func storageToAPI(o object[api.StorageSpec], st api.StorageStatus) api.Storage {
	return api.Storage{Metadata: o.Meta, Spec: o.Spec, Status: st}
}

func atoi64(v string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// storageStatus reads the pool and dataset state from ZFS.
func (s *Service) storageStatus(ctx context.Context, spec api.StorageSpec) api.StorageStatus {
	st := api.StorageStatus{Pool: poolOf(spec.Dataset)}
	now := s.now().UTC()
	unknown := func(reason, msg string) api.StorageStatus {
		st.Conditions = append(st.Conditions, api.Condition{Type: "Ready", Status: api.ConditionUnknown, Reason: reason, Message: msg, Since: now})
		return st
	}
	if s.d.ZClient == nil {
		return unknown("NoZFS", "no ZFS client is configured")
	}
	pools, err := s.d.ZClient.ListPools(ctx)
	if err != nil {
		return unknown("PoolsUnreadable", err.Error())
	}
	var found bool
	for _, p := range pools {
		if p.Name == st.Pool {
			found = true
			st.Health, st.Size = p.Health, int64(p.Size)
		}
	}
	if !found {
		st.Conditions = append(st.Conditions, api.Condition{Type: "Ready", Status: api.ConditionFalse, Reason: "PoolMissing",
			Message: "pool " + st.Pool + " is not imported", Since: now})
		return st
	}
	props, err := s.d.ZClient.Get(ctx, spec.Dataset, "used", "available")
	if err != nil {
		st.Conditions = append(st.Conditions, api.Condition{Type: "Ready", Status: api.ConditionFalse, Reason: "DatasetMissing",
			Message: err.Error(), Since: now})
		return st
	}
	st.Used, st.Available = atoi64(props["used"].Value), atoi64(props["available"].Value)
	ready := st.Health == "ONLINE" || st.Health == "DEGRADED"
	c := api.Condition{Type: "Ready", Status: api.ConditionTrue, Reason: "Online", Message: "pool " + st.Pool + " is " + st.Health, Since: now}
	if !ready {
		c.Status, c.Reason = api.ConditionFalse, "PoolUnhealthy"
	}
	st.Conditions = append(st.Conditions, c)
	return st
}

func poolOf(dataset string) string {
	p, _, _ := strings.Cut(dataset, "/")
	return p
}

// storageVisible reports whether a project identity may see a storage: some
// project of theirs grants it. Global identities see every storage.
func (s *Service) storageVisible(ctx context.Context, name string) bool {
	a := ActorFrom(ctx)
	if a.Global {
		return true
	}
	if p := ProjectFrom(ctx); p != "" {
		a = Actor{Projects: []string{p}}
		if !ActorFrom(ctx).CanProject(p) {
			return false
		}
	}
	for _, p := range a.Projects {
		if o, err := s.projKind.get(p); err == nil && specGrantsStorage(o.Spec, name) {
			return true
		}
	}
	return false
}

// ListStorage lists the storage the caller may see.
func (s *Service) ListStorage(ctx context.Context, labels map[string]string) ([]api.Storage, error) {
	if !ActorFrom(ctx).HasScope() {
		return nil, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	objs, err := s.stoKind.list()
	if err != nil {
		return nil, err
	}
	out := []api.Storage{}
	for _, o := range objs {
		if MatchLabels(o.Meta.Labels, labels) && s.storageVisible(ctx, o.Meta.Name) {
			out = append(out, storageToAPI(o, s.storageStatus(ctx, o.Spec)))
		}
	}
	return out, nil
}

// GetStorage returns one storage, or not_found when the caller may not see it.
func (s *Service) GetStorage(ctx context.Context, name string) (api.Storage, error) {
	if !ActorFrom(ctx).HasScope() {
		return api.Storage{}, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	o, err := s.stoKind.get(name)
	if err != nil || !s.storageVisible(ctx, name) {
		return api.Storage{}, notFound("storage", name)
	}
	return storageToAPI(o, s.storageStatus(ctx, o.Spec)), nil
}

// overlapsStorage reports a storage whose dataset contains or is contained in dataset.
func (s *Service) overlapsStorage(dataset, except string) (string, bool) {
	objs, _ := s.stoKind.list()
	for _, o := range objs {
		if o.Meta.Name == except {
			continue
		}
		d := o.Spec.Dataset
		if d == dataset || strings.HasPrefix(d, dataset+"/") || strings.HasPrefix(dataset, d+"/") {
			return o.Meta.Name, true
		}
	}
	return "", false
}

// layoutDatasets are created below a storage root.
func layoutDatasets(root string) []struct{ name, kind string } {
	return []struct{ name, kind string }{
		{path.Join(root, "images"), "images"}, {path.Join(root, "projects"), "projects"}, {path.Join(root, "deleted"), "deleted"},
	}
}

// adoptStorage makes a dataset a JailOps storage root: the root is marked
// ours and the layout datasets are created below it. A dataset that is not
// ours is adopted only when it is empty, so nothing foreign is ever mixed in.
func (s *Service) adoptStorage(ctx context.Context, spec api.StorageSpec) (created []string, err error) {
	z := s.d.ZClient
	if z == nil {
		return nil, api.Errorf(api.CodeUnsupported, "storage needs a ZFS client")
	}
	pool := poolOf(spec.Dataset)
	pools, err := z.ListPools(ctx)
	if err != nil {
		return nil, internal(err)
	}
	if !slices.ContainsFunc(pools, func(p zfs.Pool) bool { return p.Name == pool }) {
		return nil, api.Errorf(api.CodeNotFound, "pool %q is not imported", pool).WithHint("import the pool first")
	}
	ok, err := z.Exists(ctx, spec.Dataset)
	if err != nil {
		return nil, internal(err)
	}
	if !ok {
		return nil, api.Errorf(api.CodeNotFound, "dataset %q does not exist", spec.Dataset).
			WithHint("create it first, for example: zfs create " + spec.Dataset)
	}
	props, err := z.Get(ctx, spec.Dataset, "jailops:managed", "jailops:kind")
	if err != nil {
		return nil, internal(err)
	}
	ours := props["jailops:managed"].Value == "on"
	if !ours {
		kids, err := z.List(ctx, zfs.ListOpts{Root: spec.Dataset, Recursive: true})
		if err != nil {
			return nil, internal(err)
		}
		if len(kids) > 1 {
			return nil, api.Errorf(api.CodeInvalid, "dataset %q is not managed by JailOps and is not empty", spec.Dataset).
				WithHint("use an empty dataset, for example: zfs create " + spec.Dataset + "-jails")
		}
		if err := z.Set(ctx, spec.Dataset, map[string]string{"jailops:managed": "on", "jailops:kind": "root"}); err != nil {
			return nil, internal(err)
		}
	}
	for _, d := range layoutDatasets(spec.Dataset) {
		ex, err := z.Exists(ctx, d.name)
		if err != nil {
			return created, internal(err)
		}
		if ex {
			if p, _ := z.Get(ctx, d.name, "jailops:managed"); p["jailops:managed"].Value != "on" {
				return created, api.Errorf(api.CodeInvalid, "dataset %q exists and is not managed by JailOps; refusing to use it", d.name)
			}
			continue
		}
		cp := map[string]string{"jailops:managed": "on", "jailops:kind": d.kind}
		if d.kind == "projects" {
			cp["canmount"], cp["mountpoint"] = "off", "none"
		}
		if err := z.Create(ctx, zfs.CreateOpts{Name: d.name, Props: cp}); err != nil {
			return created, internal(err)
		}
		created = append(created, d.name)
	}
	if spec.Compression != "" {
		if err := z.Set(ctx, spec.Dataset, map[string]string{"compression": spec.Compression}); err != nil {
			return created, internal(err)
		}
	}
	return created, nil
}

func (s *Service) registrar() StorageRegistrar {
	if s.d.Registrar != nil {
		return s.d.Registrar
	}
	return s.localReg
}

// CreateStorage registers a ZFS dataset root as a storage.
func (s *Service) CreateStorage(ctx context.Context, in api.Storage) (api.Storage, error) {
	if err := requireGlobal(ctx, "creating storage"); err != nil {
		return api.Storage{}, err
	}
	name := in.Metadata.Name
	if err := validate.StorageSpec(name, in.Spec); err != nil {
		return api.Storage{}, err
	}
	if err := validate.StorageDataset("dataset", in.Spec.Dataset); err != nil {
		return api.Storage{}, err
	}
	if in.Spec.Encrypted {
		return api.Storage{}, api.Errorf(api.CodeUnsupported, "encrypted storage is not implemented").
			WithHint("make the dataset itself an encryption root ('zfs create -o encryption=on -o keyformat=passphrase ...') and register it; ZFS then encrypts everything below it and you load the key with 'zfs load-key' after a boot")
	}
	unlock, err := s.locks.lockPatient(ctx, "create storage "+name, storageLock(name))
	if err != nil {
		return api.Storage{}, err
	}
	defer unlock()
	if err := s.stoKind.notTaken(name); err != nil {
		return api.Storage{}, err
	}
	if other, clash := s.overlapsStorage(in.Spec.Dataset, ""); clash {
		return api.Storage{}, api.Errorf(api.CodeAlreadyExists, "dataset %q overlaps storage %q", in.Spec.Dataset, other)
	}
	if err := s.registrar().RegisterStorage(ctx, in.Spec.Dataset); err != nil {
		return api.Storage{}, err
	}
	created, err := s.adoptStorage(ctx, in.Spec)
	if err != nil {
		_ = s.registrar().UnregisterStorage(context.WithoutCancel(ctx), in.Spec.Dataset)
		s.undoLayout(ctx, created)
		return api.Storage{}, err
	}
	o, err := s.stoKind.create(ctx, in.Metadata, in.Spec)
	if err != nil {
		_ = s.registrar().UnregisterStorage(context.WithoutCancel(ctx), in.Spec.Dataset)
		s.undoLayout(ctx, created)
		return api.Storage{}, err
	}
	s.addStorage(name, o.Spec, o.Spec.Dataset, s.mountBaseOf(ctx, o.Spec.Dataset))
	return storageToAPI(o, s.storageStatus(ctx, o.Spec)), nil
}

func (s *Service) undoLayout(ctx context.Context, created []string) {
	for i := len(created) - 1; i >= 0; i-- {
		_ = s.d.ZClient.Destroy(context.WithoutCancel(ctx), created[i], zfs.DestroyOpts{})
	}
}

// UpdateStorage changes the description and compression of a storage; the
// dataset of a storage cannot change.
func (s *Service) UpdateStorage(ctx context.Context, name string, in api.Storage, expect int64) (api.Storage, error) {
	if err := requireGlobal(ctx, "changing storage"); err != nil {
		return api.Storage{}, err
	}
	if in.Metadata.Name != "" && in.Metadata.Name != name {
		return api.Storage{}, invalid("a storage cannot be renamed").
			WithHint("its name is what projects grant and what the records of its jails and the image pools on it carry; it stays")
	}
	old, err := s.stoKind.get(name)
	if err != nil {
		return api.Storage{}, err
	}
	if in.Spec.Dataset == "" {
		in.Spec.Dataset = old.Spec.Dataset
	}
	if in.Spec.Dataset != old.Spec.Dataset {
		return api.Storage{}, invalid("the dataset of a storage cannot change").WithHint("create a new storage and move the jails")
	}
	if err := validate.StorageSpec(name, in.Spec); err != nil {
		return api.Storage{}, err
	}
	if in.Spec.Encrypted != old.Spec.Encrypted {
		return api.Storage{}, invalid("encryption cannot change")
	}
	unlock, err := s.locks.lockPatient(ctx, "update storage "+name, storageLock(name))
	if err != nil {
		return api.Storage{}, err
	}
	defer unlock()
	if in.Spec.Compression != old.Spec.Compression && s.d.ZClient != nil {
		if in.Spec.Compression == "" {
			err = s.d.ZClient.Inherit(ctx, in.Spec.Dataset, "compression")
		} else {
			err = s.d.ZClient.Set(ctx, in.Spec.Dataset, map[string]string{"compression": in.Spec.Compression})
		}
		if err != nil {
			return api.Storage{}, internal(err)
		}
	}
	o, err := s.stoKind.update(ctx, name, expect, in.Metadata.Labels, &in.Metadata.ManagedBy, in.Spec)
	if err != nil {
		return api.Storage{}, err
	}
	if si, ok := s.storage(name); ok {
		s.stMu.Lock()
		si.Spec = o.Spec
		s.stMu.Unlock()
	}
	return storageToAPI(o, s.storageStatus(ctx, o.Spec)), nil
}

// PatchStorage applies a merge patch.
func (s *Service) PatchStorage(ctx context.Context, name string, patch map[string]any, expect int64) (api.Storage, error) {
	cur, err := s.GetStorage(ctx, name)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return cur, api.Errorf(api.CodeConflict, "storage %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	var out api.Storage
	if err := MergePatch(cur, patch, &out); err != nil {
		return out, err
	}
	return s.UpdateStorage(ctx, name, out, cur.Metadata.Generation)
}

// DeleteStorage forgets a storage that no project grants and no jail uses.
// The datasets stay: JailOps never destroys a storage root.
func (s *Service) DeleteStorage(ctx context.Context, name string, expect int64) error {
	if err := requireGlobal(ctx, "deleting storage"); err != nil {
		return err
	}
	unlock, err := s.locks.lockPatient(ctx, "delete storage "+name, storageLock(name))
	if err != nil {
		return err
	}
	defer unlock()
	o, err := s.stoKind.get(name)
	if err != nil {
		return err
	}
	if projs, _ := s.projKind.list(); true {
		for _, p := range projs {
			for _, g := range p.Spec.Storage {
				if g.Storage == name {
					return api.Errorf(api.CodeBusy, "storage %q is granted to project %q", name, p.Meta.Name).WithHint("remove the grant first")
				}
			}
		}
	}
	s.mu.RLock()
	for _, e := range s.jails {
		if e.jail.Spec.Storage == name {
			s.mu.RUnlock()
			return api.Errorf(api.CodeBusy, "storage %q holds jail %q", name, jailDisplay(e.jail.Metadata.Project, e.jail.Metadata.Name)).
				WithHint("delete the jails first")
		}
	}
	s.mu.RUnlock()
	if name == DefaultStorage {
		return api.Errorf(api.CodeBusy, "the default storage cannot be deleted")
	}
	if err := s.stoKind.delete(ctx, name, expect); err != nil {
		return err
	}
	if err := s.registrar().UnregisterStorage(ctx, o.Spec.Dataset); err != nil {
		s.log.Warn("unregistering a storage with the helper failed", "storage", name, "err", err)
	}
	s.dropStorage(name)
	return nil
}

// loadStorages reads the storage objects at start and registers the
// storage the configuration names. The default storage is created here at the
// first start.
func (s *Service) loadStorages(ctx context.Context) error {
	if _, err := s.stoKind.get(DefaultStorage); err != nil && s.d.Root != "" {
		spec := api.StorageSpec{Dataset: s.d.Root, Comment: "created at the first start"}
		if _, err := s.stoKind.create(ctx, api.ObjectMeta{Name: DefaultStorage}, spec); err != nil {
			return err
		}
	}
	objs, err := s.stoKind.list()
	if err != nil {
		return err
	}
	for _, o := range objs {
		mb := s.d.MountBase
		root := o.Spec.Dataset
		if o.Meta.Name != DefaultStorage || root != s.d.Root {
			mb = s.mountBaseOf(ctx, root)
		}
		s.addStorage(o.Meta.Name, o.Spec, root, mb)
		if err := s.registrar().RegisterStorage(ctx, root); err != nil && !api.IsCode(err, api.CodeAlreadyExists) {
			s.log.Warn("registering a storage with the helper failed", "storage", o.Meta.Name, "err", err)
		}
	}
	return nil
}

var _ = errors.New
var _ = fmt.Sprint
