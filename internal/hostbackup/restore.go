package hostbackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"jailops.net/jailops/internal/repo/catalog"
	"os"
	"path"
	"strings"
	"time"

	"jailops.net/jailops/internal/backup"
	"jailops.net/jailops/internal/repo/engine"
	"jailops.net/jailops/internal/repo/keys"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// Dataset properties of a restored jail. The strings are the JailOps dataset
// properties the lifecycle package defines; they are copied here so this
// package does not import it.
const (
	pManaged  = "jailops:managed"
	pID       = "jailops:id"
	pKind     = "jailops:kind"
	pName     = "jailops:name"
	pImage    = "jailops:image"
	pGen      = "jailops:gen"
	pManifest = "jailops:manifest"
	pComplete = "jailops:complete"
	roSnap    = "ro"
)

// nativeProps are the ZFS properties that a stream's recorded properties may
// set on a restored dataset. mountpoint is computed from the placement.
var nativeProps = map[string]bool{"quota": true, "refquota": true, "reservation": true, "readonly": true, "compression": true,
	"recordsize": true, "atime": true, "canmount": true}

// RestoreOptions control a restore.
type RestoreOptions struct {
	// Start starts the jail when the restore succeeded. By default the
	// restored jail is left stopped.
	Start bool
	// NoNetwork restores the jail without network interfaces and without creating the networks and policies of
	// its bundle: a restore test boots it with a loopback only.
	NoNetwork bool
	// DropVolumes restores the jail without any of the volumes it attaches: a restore test must never touch the
	// live data.
	DropVolumes bool
}

// RestoreResult is what a restore did.
type RestoreResult struct {
	Jail      api.Jail
	Placement Placement
	Backup    api.Backup
	// Parked lists datasets of a replaced jail that were kept (renamed, not
	// mounted) so a replace never destroys data.
	Parked []string
	Notes  []string
}

func (s *Service) host() (Host, error) {
	if s.deps.Host == nil {
		return nil, api.Errorf(api.CodeUnsupported, "this daemon wires no host registry for restores")
	}
	return s.deps.Host, nil
}

// findBackup finds a backup in the catalog, rebuilding the catalog from the
// repository once when it is not there (a new host with a recovery key).
func (s *Service) findBackup(ctx context.Context, id string) (api.Backup, error) {
	b, ok, err := s.deps.Catalog.GetBackup(ctx, id)
	if err != nil {
		return b, err
	}
	if ok {
		return b, nil
	}
	if s.currentKey() != nil {
		if _, err := s.Reindex(ctx, ""); err == nil {
			if b, ok, err = s.deps.Catalog.GetBackup(ctx, id); err == nil && ok {
				return b, nil
			}
		}
	}
	return b, api.Errorf(api.CodeNotFound, "backup %q does not exist", id)
}

// Preflight reports what a restore needs and would do, using the real state of
// this host: generations on the target storage, networks, policies, address
// sets, used addresses, sealed secrets and the key. It changes nothing.
func (s *Service) Preflight(ctx context.Context, req api.RestoreRequest) (api.RestorePreflight, error) {
	pf, _, err := s.preflight(ctx, req)
	return pf, err
}

type restorePlan struct {
	b         api.Backup
	target    string
	project   string
	storage   string
	placement Placement
	existing  bool
	// volumes are the volumes of the jail that this restore brings back first (from their newest backup), and
	// dropped the attachments left out with NoVolumes.
	volumes []volumeRestore
	dropped map[string]bool
}

// volumeRestore is one volume a jail restore brings back.
type volumeRestore struct {
	name string
	b    api.Backup
}

func (s *Service) preflight(ctx context.Context, req api.RestoreRequest) (api.RestorePreflight, *restorePlan, error) {
	h, err := s.host()
	if err != nil {
		return api.RestorePreflight{}, nil, err
	}
	if req.Host != "" && req.Host != s.cfg.HostUUID {
		return api.RestorePreflight{}, nil, api.Errorf(api.CodeInvalid, "this restore is for host %s, this host is %s", req.Host, s.cfg.HostUUID)
	}
	b, err := s.findBackup(ctx, req.Backup)
	if err != nil {
		return api.RestorePreflight{}, nil, err
	}
	rp := &restorePlan{b: b, target: b.Spec.Jail, project: b.Metadata.Project, storage: b.Spec.Bundle.Spec.Storage}
	if req.As != "" {
		rp.target = req.As
	}
	// A restore goes into the project it names, else the project of the backup.
	if req.Project != "" {
		rp.project = req.Project
	}
	if rp.project == "" {
		return api.RestorePreflight{}, nil, api.Errorf(api.CodeInvalid, "a project is required").
			WithHint("this backup names no project; give the project to restore into")
	}
	var st backup.HostState
	if ph, ok := h.(ProjectHost); ok {
		st, err = ph.StateIn(ctx, rp.project, rp.storage)
	} else {
		st, err = h.State(ctx, rp.storage)
	}
	if err != nil {
		return api.RestorePreflight{}, nil, err
	}
	if st.Generations == nil {
		st.Generations = map[string]string{}
	}
	if b.Spec.Kind == "volume" {
		pf, err := s.preflightVolume(h, req, rp, st)
		return pf, rp, err
	}
	bundle := b.Spec.Bundle
	thick := bundle.Spec.Layout == api.LayoutThick
	var genErr string
	if bundle.ImageGeneration != "" && !thick {
		if s.deps.Images == nil {
			genErr = "this host cannot look up image generations (no image manager is wired)"
		} else if g, gerr := s.deps.Images.Resolve(ctx, rp.storage, bundle.ImageGeneration); gerr == nil {
			st.Generations[bundle.ImageGeneration] = g.Manifest
		} else if api.IsCode(gerr, api.CodeNotFound) {
			delete(st.Generations, bundle.ImageGeneration)
		} else {
			return api.RestorePreflight{}, nil, gerr
		}
	}
	st.KeyDomains = map[string]bool{}
	if k := s.currentKey(); k != nil {
		st.KeyDomains[k.DomainID()] = true
	}
	var volNotes []string
	var volErrs []string
	if len(bundle.Volumes) > 0 {
		volNotes, volErrs = s.planVolumes(ctx, req, rp, &st)
	}
	pf := backup.Preflight(b, req, st)
	pf.Changes = append(pf.Changes, volNotes...)
	if len(volErrs) > 0 {
		pf.OK = false
		pf.Errors = append(pf.Errors, volErrs...)
	}
	if genErr != "" {
		pf.OK = false
		pf.Errors = append(pf.Errors, genErr)
	}
	// A generation that is missing from the target pool is refused: the thin
	// root is rebuilt from it, so it must be built or imported first.
	if !thick && bundle.ImageGeneration != "" {
		if _, ok := st.Generations[bundle.ImageGeneration]; !ok && genErr == "" {
			pf.OK = false
			pf.Errors = append(pf.Errors, fmt.Sprintf("image generation %s is not present on the target storage %q; build or import it first", bundle.ImageGeneration, rp.storage))
		}
	}
	pl, err := h.Place(ctx, rp.project, rp.target, rp.storage)
	if err != nil {
		return pf, nil, err
	}
	rp.placement = pl
	if ok, err := s.zfs.Exists(ctx, pl.Container); err != nil {
		return pf, nil, err
	} else if ok {
		rp.existing = true
		if !req.Replace {
			pf.OK = false
			pf.Errors = append(pf.Errors, fmt.Sprintf("dataset %s already exists; use as=<new name> or replace", pl.Container))
		}
	}
	return pf, rp, nil
}

// Restore restores a backup as the daemon's Backups interface needs it: the
// jail is left stopped.
func (s *Service) Restore(ctx context.Context, req api.RestoreRequest) (api.Jail, error) {
	r, err := s.RestoreWith(ctx, req, RestoreOptions{})
	if r == nil {
		return api.Jail{}, err
	}
	return r.Jail, err
}

func newUUID() string {
	var b [16]byte
	copy(b[:], mustRand(16))
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// RestoreWith restores a whole jail: it creates the datasets from the
// manifest, extracts the data, rebuilds the thin root from the image
// generation, applies the network map and keep_ip, registers the jail with a
// new UUID (unless replace) and leaves it stopped unless asked. Any failure
// undoes everything it created. It needs the key of the backup's key domain.
func (s *Service) RestoreWith(ctx context.Context, req api.RestoreRequest, opts RestoreOptions) (res *RestoreResult, err error) {
	pf, rp, err := s.preflight(ctx, req)
	if err != nil {
		return nil, err
	}
	if rp.b.Spec.Kind == "volume" {
		return nil, api.Errorf(api.CodeInvalid, "backup %s is a volume backup, not a jail backup", req.Backup).WithHint("restore it as a volume")
	}
	if !pf.OK {
		code := api.CodeInvalid
		for _, e := range pf.Errors {
			if strings.Contains(e, "key domain") {
				code = api.CodeForbidden
			}
		}
		return nil, api.Errorf(code, "restore preflight failed").WithDetail("missing", strings.Join(pf.Missing, "; ")).WithDetail("errors", strings.Join(pf.Errors, "; "))
	}
	key := s.currentKey()
	if key == nil || key.DomainID() != rp.b.Spec.KeyDomain {
		return nil, api.Errorf(api.CodeForbidden, "this host does not hold the key of backup %s (key domain %s)", rp.b.Spec.Snapshot, rp.b.Spec.KeyDomain).
			WithHint("restore on a host that holds the key, or import it from the recovery key")
	}
	h, _ := s.host()
	remote, err := s.remoteFor(ctx, rp.b.Spec.Target)
	if err != nil {
		return nil, err
	}
	if err := remote.Refresh(ctx); err != nil {
		return nil, err
	}
	b := rp.b
	group := key.Keys.GroupID(b.Spec.HostUUID, b.Spec.JailUUID)
	snap, err := engine.OpenSnapshot(ctx, remote, key.Keys, group, b.Spec.Snapshot)
	if err != nil {
		return nil, mapEngineErr(err)
	}
	pl := rp.placement
	bundle := b.Spec.Bundle
	uuid := newUUID()
	if req.Replace {
		uuid = b.Spec.JailUUID
	}
	res = &RestoreResult{Placement: pl, Backup: b}
	var rev reverter
	defer func() {
		if err != nil {
			if rerr := rev.revert(ctx); rerr != nil {
				s.cfg.Log.Error("restore: cleanup failed", "jail", rp.target, "err", rerr)
				err = errors.Join(err, fmt.Errorf("restore cleanup: %w", rerr))
			}
		}
	}()

	// the volumes the jail attaches that the project lacks come back first, each from its newest backup; a restore
	// test attaches none of them
	if opts.DropVolumes {
		rp.volumes, rp.dropped = nil, map[string]bool{}
		for _, v := range bundle.Volumes {
			rp.dropped[v] = true
		}
	}
	for _, vr := range rp.volumes {
		if _, err := s.restoreVolumeData(ctx, &rev, key, vr.b, rp.project, vr.name, ""); err != nil {
			return nil, fmt.Errorf("restoring volume %s: %w", vr.name, err)
		}
		res.Notes = append(res.Notes, fmt.Sprintf("volume %s was restored from backup %s", vr.name, vr.b.Metadata.Name))
	}

	// replace: park the current datasets, never destroy them
	if rp.existing {
		if running, rerr := h.Running(ctx, rp.project, rp.target); rerr != nil {
			return nil, rerr
		} else if running {
			return nil, api.Errorf(api.CodeBusy, "jail %q is running; stop it before replacing it", rp.target)
		}
		if err := s.fail("restore.park"); err != nil {
			return nil, err
		}
		parked, err := s.park(ctx, &rev, pl.Container)
		if err != nil {
			return nil, err
		}
		res.Parked = append(res.Parked, parked)
		res.Notes = append(res.Notes, fmt.Sprintf("the replaced jail's datasets were kept as %s (mountpoints removed)", parked))
	}

	gen, err := s.materialize(ctx, &rev, materialize{key: key, remote: remote, snap: snap, b: b, pl: pl, uuid: uuid, name: rp.target, storage: rp.storage})
	if err != nil {
		return nil, err
	}

	// networks, policies and address sets, then the registration
	if err := s.fail("restore.objects"); err != nil {
		return nil, err
	}
	var undo func(context.Context) error
	if opts.NoNetwork {
		// nothing to create: the jail has no interfaces
	} else if ph, ok := h.(ProjectHost); ok {
		undo, err = ph.EnsureObjectsIn(ctx, rp.project, bundle, req.NetworkMap)
	} else {
		undo, err = h.EnsureObjects(ctx, bundle, req.NetworkMap)
	}
	if undo != nil {
		rev.add(undo)
	}
	if err != nil {
		return nil, err
	}
	// The datasets are complete before the jail is registered: registering observes them, and an incomplete
	// jail would be reported as degraded. A failure from here on undoes everything.
	if err := s.fail("restore.complete"); err != nil {
		return nil, err
	}
	if err := s.zfs.Set(ctx, pl.Container, map[string]string{pComplete: "on"}); err != nil {
		return nil, err
	}
	jail := restoredJail(b, req, rp, uuid, s.now(), gen.Name)
	if opts.NoNetwork {
		jail.Spec.Network = nil
		jail.Spec.Firewall = api.FirewallAttach{}
	}
	if err := s.fail("restore.adopt"); err != nil {
		return nil, err
	}
	undo, err = h.Adopt(ctx, AdoptInput{Jail: jail, Bundle: bundle, Placement: pl, Backup: b, Replace: req.Replace, Generation: gen})
	if undo != nil {
		rev.add(undo)
	}
	if err != nil {
		return nil, err
	}
	rev.disarm()
	res.Jail = jail
	if opts.Start {
		if serr := h.Start(ctx, rp.project, rp.target); serr != nil {
			res.Notes = append(res.Notes, "the jail was restored but did not start: "+serr.Error())
		} else {
			res.Jail.Status.Power = api.PowerRunning
		}
	}
	return res, nil
}

func safeRel(rel string) bool {
	if rel == rootRel {
		return true
	}
	if rel == "" || strings.HasPrefix(rel, "/") || strings.ContainsAny(rel, "\x00@#\\ ") {
		return false
	}
	for _, c := range strings.Split(rel, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// datasetProps builds the properties of a restored dataset: the recorded
// user properties and the allowed native ones, the ownership marks, and the
// mountpoint below the new container.
func datasetProps(rec map[string]string, pl Placement, rel, mrel string, base map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range rec {
		switch {
		case k == propRel || k == propKind || k == propMountRel || k == pManaged || k == pID || k == pName || k == pComplete:
		case strings.HasPrefix(k, "jailops:"), nativeProps[k]:
			out[k] = v
		}
	}
	for k, v := range base {
		out[k] = v
	}
	switch {
	case rel == rootRel:
		out["mountpoint"] = pl.Mountpoint
	case mrel != "" && mrel != ".":
		out["mountpoint"] = path.Join(pl.Mountpoint, mrel)
	default:
		out["mountpoint"] = path.Join(pl.Mountpoint, rel)
	}
	return out
}

// materialize is the input of the dataset creation and extraction shared by a
// restore and a full restore test.
type materialize struct {
	key     *keys.Key
	remote  Remote
	snap    *engine.Snapshot
	b       api.Backup
	pl      Placement
	uuid    string
	name    string
	storage string
}

// materialize creates the container, the root (cloned from the image
// generation when thin) and the data datasets of a backup below the placement
// and extracts the data into them. Everything it creates is registered with
// the reverter before the step that creates it.
func (s *Service) materialize(ctx context.Context, rev *reverter, m materialize) (gen api.ImageGeneration, err error) {
	bundle := m.b.Spec.Bundle
	thick := bundle.Spec.Layout == api.LayoutThick
	pl := m.pl
	type item struct {
		name, rel, kind, mrel string
		props                 map[string]string
	}
	var items []item
	hasContainer := false
	for _, st := range m.snap.Manifest.Streams {
		rel := st.Props[propRel]
		if rel == "" {
			rel = st.Name
		}
		if !safeRel(rel) || strings.Contains(rel, "/") {
			return gen, api.Errorf(api.CodeInvalid, "backup %s has a dataset with an unsafe name %q", m.b.Spec.Snapshot, rel)
		}
		if mr := st.Props[propMountRel]; mr != "" && mr != "." && !safeRel(mr) {
			return gen, api.Errorf(api.CodeInvalid, "backup %s has a dataset with an unsafe mountpoint %q", m.b.Spec.Snapshot, mr)
		}
		hasContainer = hasContainer || rel == rootRel
		items = append(items, item{name: st.Name, rel: rel, kind: st.Props[propKind], mrel: st.Props[propMountRel], props: st.Props})
	}
	if !hasContainer {
		return gen, api.Errorf(api.CodeInvalid, "backup %s holds no container dataset (spec.json); it is not a jail backup", m.b.Spec.Snapshot)
	}
	baseProps := func(kind string) map[string]string {
		return map[string]string{pManaged: "on", pID: m.uuid, pKind: kind, pName: m.name}
	}
	owned := func(ds string) func(context.Context) error {
		return func(ctx context.Context) error {
			ok, err := s.zfs.Exists(ctx, ds)
			if err != nil || !ok {
				return err
			}
			p, err := s.zfs.Get(ctx, ds, pManaged, pID)
			if err != nil {
				return err
			}
			if p[pManaged].Value != "on" || p[pID].Value != m.uuid {
				return nil // not ours: never touch it
			}
			return s.zfs.Destroy(ctx, ds, zfs.DestroyOpts{Recursive: true})
		}
	}

	if err := s.fail("restore.container"); err != nil {
		return gen, err
	}
	rev.add(owned(pl.Container))
	var cprops map[string]string
	for _, it := range items {
		if it.rel == rootRel {
			cprops = datasetProps(it.props, pl, it.rel, it.mrel, baseProps(KindContainer))
		}
	}
	cprops[pComplete] = "off"
	// the disk limit is the quota of the container, not of the root clone
	delete(cprops, "quota")
	delete(cprops, "reservation")
	if q := bundle.Spec.Resources.Disk; q != "" {
		cprops["quota"] = q
	}
	if r := bundle.Spec.Resources.DiskReservation; r != "" {
		cprops["reservation"] = r
	}
	if err := s.zfs.Create(ctx, zfs.CreateOpts{Name: pl.Container, Parents: true, Props: cprops}); err != nil {
		return gen, fmt.Errorf("creating %s: %w", pl.Container, err)
	}

	if !thick {
		if err := s.fail("restore.root"); err != nil {
			return gen, err
		}
		if s.deps.Images == nil {
			return gen, api.Errorf(api.CodeUnsupported, "this daemon wires no image manager for restores")
		}
		if gen, err = s.deps.Images.Resolve(ctx, m.storage, bundle.ImageGeneration); err != nil {
			return gen, err
		}
		if gen.Manifest != bundle.ImageManifest {
			return gen, api.Errorf(api.CodeInvalid, "image generation %s has manifest %s, the backup needs %s", gen.Name, gen.Manifest, bundle.ImageManifest)
		}
		imageName, _, _ := strings.Cut(gen.Name, "#")
		rprops := baseProps(KindRoot)
		rprops["mountpoint"], rprops["canmount"] = pl.rootMP(), "on"
		rprops[pGen], rprops[pImage], rprops[pManifest] = fmt.Sprint(gen.Number), imageName, gen.Manifest
		if err := s.zfs.Clone(ctx, gen.Dataset+"@"+roSnap, pl.root(), rprops, false); err != nil {
			return gen, fmt.Errorf("cloning the root from %s: %w", gen.Name, err)
		}
	}

	dsOf := map[string]string{} // stream name -> dataset
	for i, it := range items {
		if it.rel == rootRel {
			dsOf[it.name] = pl.Container
			continue
		}
		if it.rel == "root" && !thick {
			continue // never overlay the cloned root
		}
		if err := s.fail(fmt.Sprintf("restore.dataset.%d", i)); err != nil {
			return gen, err
		}
		ds := path.Join(pl.Container, it.rel)
		props := datasetProps(it.props, pl, it.rel, it.mrel, baseProps(firstNonEmpty(it.kind, KindPersistent)))
		if it.rel == "root" {
			props["mountpoint"] = pl.rootMP()
		}
		if err := s.zfs.Create(ctx, zfs.CreateOpts{Name: ds, Props: props}); err != nil {
			return gen, fmt.Errorf("creating %s: %w", ds, err)
		}
		dsOf[it.name] = ds
	}

	// UNVERIFIED: extraction into the container while the root and the
	// persistent datasets are mounted below it, and that the empty mountpoint
	// directories in the container's catalog (root, ...) are accepted as they
	// are by the extractor on FreeBSD.
	if err := s.fail("restore.extract"); err != nil {
		return gen, err
	}
	dests := map[string]string{}
	for name, ds := range dsOf {
		dir, err := s.deps.Mounter.MountDir(ctx, ds)
		if err != nil {
			return gen, err
		}
		dests[name] = dir
	}
	group := m.key.Keys.GroupID(m.b.Spec.HostUUID, m.b.Spec.JailUUID)
	ro := engine.RestoreOptions{Key: m.key, Repo: m.remote, Group: group, Snapshot: m.b.Spec.Snapshot, Dests: dests,
		NoChown: s.cfg.noChown(), Workers: s.cfg.EngineWorkers}
	if s.deps.Agents != nil {
		// The daemon is not root: a file agent writes the jail for it (as the owners the backup recorded).
		ro.NewSink = func(_, dest string) (catalog.Sink, func(), error) { return s.deps.Agents.WriteTree(ctx, dest) }
	}
	if _, err := engine.Restore(ctx, ro); err != nil {
		return gen, mapEngineErr(err)
	}
	return gen, nil
}

// park renames an existing jail's container out of the way after taking a
// recursive safety snapshot and removing every mountpoint (so the name and the
// mountpoints are free). The undo puts everything back.
func (s *Service) park(ctx context.Context, rev *reverter, container string) (string, error) {
	list, err := s.zfs.List(ctx, zfs.ListOpts{Root: container, Recursive: true, Props: []string{"mountpoint"}})
	if err != nil {
		return "", err
	}
	type saved struct {
		name, value, source string
		refres              string // a reservation of its own ("" when it has none)
	}
	var olds []saved
	for _, d := range list {
		p, err := s.zfs.Get(ctx, d.Name, "mountpoint", "refreservation")
		if err != nil {
			return "", err
		}
		o := saved{name: d.Name, value: p["mountpoint"].Value, source: p["mountpoint"].Source}
		if r := p["refreservation"]; r.Source == "local" && r.Value != "none" && r.Value != "0" && r.Value != "" && r.Value != "-" {
			o.refres = r.Value
		}
		olds = append(olds, o)
	}
	id := randHex(3)
	snap := "jailops-prerestore-" + id
	if err := s.zfs.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{container + "@" + snap}, Recursive: true,
		Props: map[string]string{snapManaged: "on"}}); err != nil {
		return "", err
	}
	// UNVERIFIED: zfs set mountpoint=none followed by zfs rename of a mounted
	// tree on FreeBSD 15 (unmount order, busy datasets).
	parked := container + ".replaced-" + id
	restoreMPs := func(ctx context.Context, rename string) error {
		var errs []error
		for _, o := range olds {
			name := o.name
			if rename != "" {
				name = rename + strings.TrimPrefix(o.name, container)
			}
			if o.source == "local" {
				errs = append(errs, s.zfs.Set(ctx, name, map[string]string{"mountpoint": o.value}))
			} else {
				errs = append(errs, s.zfs.Inherit(ctx, name, "mountpoint"))
			}
		}
		return errors.Join(errs...)
	}
	// registered first: a half-done park is put back
	state := 0 // 0 nothing, 1 mountpoints removed, 2 renamed
	rev.add(func(ctx context.Context) error {
		var errs []error
		switch state {
		case 2:
			if err := s.zfs.Rename(ctx, parked, container, zfs.RenameOpts{}); err != nil {
				return err
			}
			errs = append(errs, restoreMPs(ctx, ""))
			for _, o := range olds {
				if o.refres != "" {
					errs = append(errs, s.zfs.Set(ctx, o.name, map[string]string{"refreservation": o.refres}))
				}
			}
		case 1:
			errs = append(errs, restoreMPs(ctx, ""))
		}
		for _, o := range olds {
			if ok, _ := s.zfs.Exists(ctx, o.name+"@"+snap); ok {
				errs = append(errs, s.zfs.Destroy(ctx, o.name+"@"+snap, zfs.DestroyOpts{Defer: true}))
			}
		}
		return errors.Join(errs...)
	})
	state = 1
	for _, o := range olds {
		if err := s.zfs.Set(ctx, o.name, map[string]string{"mountpoint": "none"}); err != nil {
			return "", err
		}
	}
	if err := s.zfs.Rename(ctx, container, parked, zfs.RenameOpts{}); err != nil {
		return "", err
	}
	state = 2
	// a parked jail runs nowhere: its guarantee of space (refreservation) is given back to the pool, so that keeping
	// the old data does not keep that space reserved
	for _, o := range olds {
		if o.refres != "" {
			if err := s.zfs.Set(ctx, parked+strings.TrimPrefix(o.name, container), map[string]string{"refreservation": "none"}); err != nil {
				return "", err
			}
		}
	}
	return parked, nil
}

// restoredJail builds the record of the restored jail: new name and uuid
// (unless replace), the network map, keep_ip and the MAC rule applied.
func restoredJail(b api.Backup, req api.RestoreRequest, rp *restorePlan, uuid string, now time.Time, gen string) api.Jail {
	var spec api.JailSpec
	raw, _ := json.Marshal(b.Spec.Bundle.Spec)
	_ = json.Unmarshal(raw, &spec)
	for i := range spec.Network {
		a := &spec.Network[i]
		if m, ok := req.NetworkMap[a.Network]; ok {
			a.Network = m
		}
		if !req.KeepIP {
			if a.IPv4 != "" && a.IPv4 != "none" {
				a.IPv4 = "auto"
			}
			if a.IPv6 != "" && a.IPv6 != "none" {
				a.IPv6 = "auto"
			}
		}
		if !req.Replace {
			a.MAC = ""
		}
	}
	if spec.Hostname == b.Spec.Jail && rp.target != b.Spec.Jail {
		spec.Hostname = ""
	}
	if len(rp.dropped) > 0 {
		var keep []api.VolumeAttach
		for _, v := range spec.Volumes {
			if !rp.dropped[v.Name] {
				keep = append(keep, v)
			}
		}
		spec.Volumes = keep
	}
	return api.Jail{
		Metadata: api.ObjectMeta{Name: rp.target, UUID: uuid, Project: rp.project, Host: b.Spec.HostUUID, Scope: api.ScopeHost, Generation: 1,
			CreatedAt: now, UpdatedAt: now},
		Spec:   spec,
		Status: api.JailStatus{Power: api.PowerStopped, Generation: gen},
	}
}

// FileRestore restores single files or subtrees of one dataset of a backup
// into a directory. Only the chunks holding the requested bytes are fetched.
type FileRestore struct {
	Backup string
	// Dataset is the dataset's name below the jail's container ("." for the
	// container itself, "etc", "data/db", ...).
	Dataset string
	// Paths are paths inside the dataset, restored with everything below them.
	Paths []string
	// Dest is the directory to restore into; it is created when missing.
	Dest string
}

// RestoreFiles restores single files or subtrees. It needs the key.
func (s *Service) RestoreFiles(ctx context.Context, fr FileRestore) (*engine.RestoreResult, error) {
	if len(fr.Paths) == 0 || fr.Dest == "" || fr.Dataset == "" {
		return nil, api.Errorf(api.CodeInvalid, "a file restore needs a dataset, at least one path and a destination directory")
	}
	b, err := s.findBackup(ctx, fr.Backup)
	if err != nil {
		return nil, err
	}
	key := s.currentKey()
	if key == nil || key.DomainID() != b.Spec.KeyDomain {
		return nil, api.Errorf(api.CodeForbidden, "this host does not hold the key of backup %s (key domain %s)", b.Spec.Snapshot, b.Spec.KeyDomain)
	}
	remote, err := s.remoteFor(ctx, b.Spec.Target)
	if err != nil {
		return nil, err
	}
	if err := remote.Refresh(ctx); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(fr.Dest, 0o700); err != nil {
		return nil, err
	}
	res, err := engine.Restore(ctx, engine.RestoreOptions{Key: key, Repo: remote, Group: key.Keys.GroupID(b.Spec.HostUUID, b.Spec.JailUUID),
		Snapshot: b.Spec.Snapshot, Stream: fr.Dataset, Dest: fr.Dest, Paths: fr.Paths, NoChown: s.cfg.noChown(), Workers: s.cfg.EngineWorkers})
	return res, mapEngineErr(err)
}

// Reindex rebuilds the catalog's backups of a target from the repository. It
// opens every manifest with the key; manifests of other keys are skipped.
// It returns the number of backups of this key found.
func (s *Service) Reindex(ctx context.Context, target string) (int, error) {
	key := s.currentKey()
	if key == nil {
		return 0, noKeyErr()
	}
	r, err := s.remoteFor(ctx, target)
	if err != nil {
		return 0, err
	}
	if err := r.Refresh(ctx); err != nil {
		return 0, err
	}
	groups, err := r.Groups(ctx)
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, g := range groups {
		snaps, err := r.ListSnapshots(ctx, g)
		if err != nil {
			return 0, err
		}
		for _, sm := range snaps {
			mb, err := r.ReadManifest(ctx, g, sm.ID)
			if err != nil {
				continue
			}
			m, err := key.Keys.OpenManifest(mb, g, sm.ID)
			if err != nil {
				continue // another key's backup
			}
			var rb api.RestoreBundle
			if len(m.Bundle) > 0 {
				_ = json.Unmarshal(m.Bundle, &rb)
			}
			zs := ""
			full := false
			for _, st := range m.Streams {
				zs = firstNonEmpty(zs, st.ZFSSnapshot)
				full = full || st.Mode == "full"
			}
			chunks := 0
			if rc, err := r.ReadReceipt(ctx, g, sm.ID); err == nil {
				chunks = rc.ChunkCount
			}
			b := api.Backup{
				Metadata: api.ObjectMeta{Name: sm.ID, UUID: sm.ID, Project: m.Meta[metaProject], Host: m.Host, Scope: api.ScopeHost, Generation: 1,
					CreatedAt: sm.Committed, UpdatedAt: sm.Committed},
				Spec: api.BackupSpec{Kind: kindOfMeta(m.Meta), Volume: volumeOfMeta(m.Meta), Jail: m.JailName, JailUUID: m.Jail, HostUUID: m.Host, Policy: m.Policy, Target: target, Snapshot: sm.ID,
					ZFSSnapshot: zs, KeyDomain: key.DomainID(), Full: full, Bundle: rb},
				Status: api.BackupStatus{Bytes: int64(m.Stats.LogicalBytes), NewBytes: int64(m.Stats.UploadedBytes), Chunks: chunks,
					Files: m.Stats.Files, Failed: sm.Failed},
			}
			if err := s.deps.Catalog.PutBackup(ctx, b); err != nil {
				return 0, err
			}
			seen[sm.ID] = true
		}
	}
	old, err := s.deps.Catalog.Backups(ctx)
	if err != nil {
		return 0, err
	}
	for _, b := range old {
		if b.Spec.Target == target && !seen[b.Metadata.Name] {
			if err := s.deps.Catalog.DeleteBackup(ctx, b.Metadata.Name); err != nil {
				return 0, err
			}
		}
	}
	return len(seen), nil
}

// kindOfMeta is the Kind of a backup object: "volume" for a volume backup, empty for a jail.
func kindOfMeta(meta map[string]string) string {
	if meta[metaKind] == "volume" {
		return "volume"
	}
	return ""
}

// volumeOfMeta reads the volume spec recorded in the manifest of a volume backup.
func volumeOfMeta(meta map[string]string) *api.VolumeSpec {
	raw := meta[metaVolume]
	if raw == "" || meta[metaKind] != "volume" {
		return nil
	}
	var v api.VolumeSpec
	if json.Unmarshal([]byte(raw), &v) != nil {
		return nil
	}
	return &v
}

// planVolumes decides how this restore gets the volumes the backed-up jail attaches: with NoVolumes it leaves every
// attachment out; otherwise, for each volume the target project lacks, it takes the newest backup of the volume. A volume it can
// do neither for is left missing in the state, so the preflight says so. st is changed to say which volumes will be
// there. It returns the notes for the report and the errors it found.
func (s *Service) planVolumes(ctx context.Context, req api.RestoreRequest, rp *restorePlan, st *backup.HostState) (notes, errs []string) {
	vols := map[string]bool{}
	for k, v := range st.Volumes {
		vols[k] = v
	}
	if req.NoVolumes {
		// the jail is restored with no volume attachments at all, those the project has and those it lacks
		rp.dropped = map[string]bool{}
		for _, name := range rp.b.Spec.Bundle.Volumes {
			rp.dropped[name] = true
			vols[name] = true
		}
		st.Volumes = vols
		return []string{fmt.Sprintf("jail %s is restored without its volumes (no_volumes): attach them with jailops volume attach", rp.target)}, nil
	}
	_, canRestore := s.deps.Host.(VolumeHost)
	var all []api.Backup
	for _, name := range rp.b.Spec.Bundle.Volumes {
		if vols[name] {
			continue
		}
		if !canRestore {
			continue
		}
		if all == nil {
			all, _ = s.deps.Catalog.Backups(ctx)
		}
		vb, ok := newestVolumeBackup(all, rp.project, name, rp.b.Spec.Bundle.VolumeIDs[name], s.currentKey())
		if !ok {
			continue // stays missing: the preflight reports it
		}
		if vb.Spec.Volume != nil && vb.Spec.Volume.Encrypted {
			errs = append(errs, fmt.Sprintf("volume %s is encrypted: restore its backup %s first (it needs its passphrase), then restore the jail", name, vb.Metadata.Name))
			vols[name] = true
			continue
		}
		rp.volumes = append(rp.volumes, volumeRestore{name: name, b: vb})
		vols[name] = true
		notes = append(notes, fmt.Sprintf("restores volume %s from backup %s first", name, vb.Metadata.Name))
	}
	st.Volumes = vols
	return notes, errs
}

// newestVolumeBackup finds the newest usable backup of a volume of the project that this host's key opens. The volume is
// the one with this UUID: a volume deleted and made again under the same name is another volume, and its backups are not
// the ones an older jail needs. Without a UUID (the bundle does not know the volume) nothing matches.
func newestVolumeBackup(all []api.Backup, project, name, id string, key *keys.Key) (api.Backup, bool) {
	var best api.Backup
	found := false
	if id == "" {
		return best, false
	}
	for _, b := range all {
		if b.Spec.Kind != "volume" || b.Spec.Jail != name || b.Spec.JailUUID != id || b.Metadata.Project != project || b.Status.Failed {
			continue
		}
		if key == nil || key.DomainID() != b.Spec.KeyDomain {
			continue
		}
		if !found || b.Metadata.CreatedAt.After(best.Metadata.CreatedAt) {
			best, found = b, true
		}
	}
	return best, found
}

// preflightVolume is the preflight of a volume backup: it is restored as a new volume of the project.
func (s *Service) preflightVolume(h Host, req api.RestoreRequest, rp *restorePlan, st backup.HostState) (api.RestorePreflight, error) {
	if _, ok := h.(VolumeHost); !ok {
		return api.RestorePreflight{}, api.Errorf(api.CodeUnsupported, "this daemon wires no volume registry for restores")
	}
	pf := api.RestorePreflight{OK: true}
	fail := func(f string, a ...any) {
		pf.OK = false
		pf.Errors = append(pf.Errors, fmt.Sprintf(f, a...))
	}
	b := rp.b
	switch {
	case b.Spec.Volume == nil:
		fail("backup %s holds no volume spec; it cannot be restored as a volume", b.Spec.Snapshot)
		return pf, nil
	case st.Volumes[rp.target]:
		fail("volume %q already exists in project %q; restore it under another name with as=NAME (a volume is never replaced)", rp.target, rp.project)
	case b.Spec.Volume.Encrypted && req.Passphrase == "":
		fail("the volume is encrypted: give its passphrase; it makes the volume again and is never stored")
	case !b.Spec.Volume.Encrypted && req.Passphrase != "":
		fail("a passphrase was given but the volume is not encrypted")
	}
	if k := s.currentKey(); k == nil || k.DomainID() != b.Spec.KeyDomain {
		fail("backup needs key domain %s, which the target does not hold; unwrap it from the escrow with the recovery key", b.Spec.KeyDomain)
	}
	if b.Status.Failed {
		fail("backup %s failed verification (a chunk is missing or corrupt) and cannot be restored", b.Spec.Snapshot)
	}
	pf.Changes = append(pf.Changes, fmt.Sprintf("creates volume %s in project %s from backup %s", rp.target, rp.project, b.Metadata.Name))
	return pf, nil
}

// restoreVolumeData makes the volume of a volume backup in the project and extracts the backup into it. What it
// creates is registered with rev before the step that creates it.
func (s *Service) restoreVolumeData(ctx context.Context, rev *reverter, key *keys.Key, b api.Backup, project, name, pass string) (api.Volume, error) {
	h, err := s.host()
	if err != nil {
		return api.Volume{}, err
	}
	vh, ok := h.(VolumeHost)
	if !ok {
		return api.Volume{}, api.Errorf(api.CodeUnsupported, "this daemon wires no volume registry for restores")
	}
	if b.Spec.Volume == nil {
		return api.Volume{}, api.Errorf(api.CodeInvalid, "backup %s holds no volume spec", b.Spec.Snapshot)
	}
	remote, err := s.remoteFor(ctx, b.Spec.Target)
	if err != nil {
		return api.Volume{}, err
	}
	if err := remote.Refresh(ctx); err != nil {
		return api.Volume{}, err
	}
	if err := s.fail("restore.volume"); err != nil {
		return api.Volume{}, err
	}
	ds, undo, err := vh.RestoreVolume(ctx, project, name, *b.Spec.Volume, nil, pass)
	if undo != nil {
		rev.add(undo)
	}
	if err != nil {
		return api.Volume{}, err
	}
	dir, err := s.deps.Mounter.MountDir(ctx, ds)
	if err != nil {
		return api.Volume{}, err
	}
	if err := s.fail("restore.volume.extract"); err != nil {
		return api.Volume{}, err
	}
	ro := engine.RestoreOptions{Key: key, Repo: remote, Group: key.Keys.GroupID(b.Spec.HostUUID, b.Spec.JailUUID), Snapshot: b.Spec.Snapshot,
		Dests: map[string]string{rootRel: dir}, NoChown: s.cfg.noChown(), Workers: s.cfg.EngineWorkers}
	if s.deps.Agents != nil {
		ro.NewSink = func(_, dest string) (catalog.Sink, func(), error) { return s.deps.Agents.WriteTree(ctx, dest) }
	}
	if _, err := engine.Restore(ctx, ro); err != nil {
		return api.Volume{}, mapEngineErr(err)
	}
	if err := vh.CompleteVolume(ctx, project, name); err != nil {
		return api.Volume{}, err
	}
	return api.Volume{Metadata: api.ObjectMeta{Name: name, Project: project}, Spec: *b.Spec.Volume}, nil
}

// RestoreVolumeBackup restores a volume backup as a new volume of the project (the daemon's Backups interface).
// Any failure removes the volume again. It needs the key of the backup's key domain.
func (s *Service) RestoreVolumeBackup(ctx context.Context, req api.RestoreRequest) (v api.Volume, err error) {
	pf, rp, err := s.preflight(ctx, req)
	if err != nil {
		return v, err
	}
	if rp.b.Spec.Kind != "volume" {
		return v, api.Errorf(api.CodeInvalid, "backup %s is a jail backup, not a volume backup", req.Backup)
	}
	if !pf.OK {
		code := api.CodeInvalid
		for _, e := range pf.Errors {
			if strings.Contains(e, "key domain") {
				code = api.CodeForbidden
			}
		}
		return v, api.Errorf(code, "restore preflight failed").WithDetail("errors", strings.Join(pf.Errors, "; "))
	}
	key := s.currentKey()
	var rev reverter
	defer func() {
		if err != nil {
			if rerr := rev.revert(ctx); rerr != nil {
				s.cfg.Log.Error("restore: cleanup failed", "volume", rp.target, "err", rerr)
				err = errors.Join(err, fmt.Errorf("restore cleanup: %w", rerr))
			}
		}
	}()
	if v, err = s.restoreVolumeData(ctx, &rev, key, rp.b, rp.project, rp.target, req.Passphrase); err != nil {
		return v, err
	}
	rev.disarm()
	return v, nil
}
