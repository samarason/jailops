package service

import (
	"context"
	"errors"
	"fmt"
	"jailops.net/jailops/internal/supervise"
	"slices"
	"strconv"
	"strings"
	"sync"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Volumes are objects of a project: a dataset, <storage root>/projects/<project>/volumes/<name>, that jails attach by
// name. The attachment is part of the jail's spec (spec.volumes); the volume knows nothing of the jails and is never
// deleted with one (docs/storage.md).

const defaultVolumeMode = 0o755

// parseVolumeMode reads the mode of a volume's root: octal, with or without the leading zero, at most 0777. An empty
// mode is the default, 0755.
func parseVolumeMode(m string) (uint32, error) {
	if m == "" {
		return defaultVolumeMode, nil
	}
	v, err := strconv.ParseUint(m, 8, 32)
	if err != nil || v > 0o777 {
		return 0, invalid("mode %q is not an octal mode up to 0777", m).WithHint("for example 0755 or 0770; setuid, setgid and the sticky bit are not offered")
	}
	return uint32(v), nil
}

func volToAPI(o object[api.VolumeSpec]) api.Volume {
	return api.Volume{Metadata: o.Meta, Spec: o.Spec}
}

// volumeStorage resolves the storage of a new volume: the one named, or the only storage the project is granted.
func (s *Service) volumeStorage(p project, want string) (*storageInfo, error) {
	if want == "" {
		if want = p.Spec.SoleStorage(); want == "" {
			return nil, invalid("a volume needs a storage: name one with --storage NAME").WithHint("jailops project show " + p.Meta.Name + " lists the grants")
		}
	}
	if !specGrantsStorage(p.Spec, want) {
		return nil, api.Errorf(api.CodeForbidden, "storage %q is not granted to project %q", want, p.Meta.Name).
			WithHint(fmt.Sprintf("a global admin grants it: jailops storage grant %s --project %s", want, p.Meta.Name))
	}
	si, ok := s.storage(want)
	if !ok {
		return nil, notFound("storage", want)
	}
	return si, nil
}

// volumeUses lists the jails of a project that attach a volume, by jail name.
func (s *Service) volumeUses(project, name string) []api.VolumeUse {
	s.mu.RLock()
	var jails []api.Jail
	for _, k := range sortedKeys(s.jails) {
		if j := s.jails[k].jail; j.Metadata.Project == project {
			jails = append(jails, j)
		}
	}
	s.mu.RUnlock()
	var out []api.VolumeUse
	for _, j := range jails {
		// a profile may attach volumes too: what counts is what the jail runs with
		for _, v := range s.effective(j).Volumes {
			if v.Name == name {
				out = append(out, api.VolumeUse{Jail: j.Metadata.Name, Mount: v.Mount, ReadOnly: v.ReadOnly})
			}
		}
	}
	return out
}

// attachedVolumes implements lifecycle.Config.Attached: the volumes a jail's spec attaches, with where the host has
// them. A volume that cannot be found is an error, and the jail does not start without it.
func (s *Service) attachedVolumes(key string) ([]lifecycle.Attached, error) {
	project, _ := validate.SplitQualified(key)
	s.mu.RLock()
	var jail api.Jail
	e := s.jails[key]
	if e != nil {
		jail = cloneJail(e.jail)
	}
	s.mu.RUnlock()
	var vs []api.VolumeAttach
	if e != nil {
		vs = s.effective(jail).Volumes
	}
	var out []lifecycle.Attached
	var errs []error
	for _, v := range vs {
		o, err := s.volKind.p(project).get(v.Name)
		if err != nil {
			errs = append(errs, api.Errorf(api.CodeNotFound, "the volume %q of this jail does not exist", v.Name).WithHint("jailops volume create "+v.Name))
			continue
		}
		if o.Spec.IsHostDir() {
			out = append(out, lifecycle.Attached{Name: v.Name, HostDir: true, Mountpoint: o.Spec.Path, Path: v.Mount, ReadOnly: v.ReadOnly,
				WriteProbe: o.Spec.Watch && o.Spec.Probe == api.VolumeProbeWrite})
			continue
		}
		si, ok := s.storage(o.Spec.Storage)
		if !ok {
			errs = append(errs, api.Errorf(api.CodeNotFound, "the storage %q of volume %q is not there", o.Spec.Storage, v.Name))
			continue
		}
		st := si.lifecycle()
		out = append(out, lifecycle.Attached{Dataset: lifecycle.VolumeDS(st, project, v.Name), Mountpoint: lifecycle.VolumeMP(st, project, v.Name),
			Path: v.Mount, ReadOnly: v.ReadOnly, Encrypted: o.Spec.Encrypted})
	}
	return out, errors.Join(errs...)
}

// volumeView is a volume with what the dataset and the jails say about it now.
func (s *Service) volumeView(ctx context.Context, project string, o object[api.VolumeSpec]) api.Volume {
	v := volToAPI(o)
	name := o.Meta.Name
	v.Status.AttachedTo = s.volumeUses(project, name)
	var rw []string
	for _, u := range v.Status.AttachedTo {
		if !u.ReadOnly {
			rw = append(rw, u.Jail)
		}
	}
	if len(rw) > 1 {
		v.Status.Warnings = append(v.Status.Warnings, fmt.Sprintf("writable in more than one jail (%s): the jails share the files and their locking; a mail store, a database or a package cache needs one writer", strings.Join(rw, ", ")))
	}
	if o.Spec.IsHostDir() {
		v.Status.Mountpoint = o.Spec.Path
		v.Status.State, v.Status.Detail = s.hostDirStateRead(ctx, o)
		return v
	}
	si, ok := s.storage(o.Spec.Storage)
	if !ok || s.life == nil {
		return v
	}
	st := si.lifecycle()
	v.Status.Dataset, v.Status.Mountpoint = lifecycle.VolumeDS(st, project, name), lifecycle.VolumeMP(st, project, name)
	info, err := s.life.VolumeInfo(ctx, st, project, name)
	if err != nil {
		v.Status.Warnings = append(v.Status.Warnings, err.Error())
		return v
	}
	v.Status.Used, v.Status.Locked = info.Used, info.Locked
	return v
}

// ListVolumes lists the volumes of the request's project.
func (s *Service) ListVolumes(ctx context.Context, labels map[string]string) ([]api.Volume, error) {
	p, err := s.access(ctx)
	if err != nil {
		return nil, err
	}
	objs, err := s.volKind.p(p.Meta.Name).list()
	if err != nil {
		return nil, err
	}
	var keep []object[api.VolumeSpec]
	for _, o := range objs {
		if MatchLabels(o.Meta.Labels, labels) {
			keep = append(keep, o)
		}
	}
	// the views are made side by side: a directory that does not answer holds its own view for a few seconds, not the list
	out := make([]api.Volume, len(keep))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, o := range keep {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			defer func() { supervise.Report(s.log, "volume-view", recover()) }()
			out[i] = s.volumeView(ctx, p.Meta.Name, o)
		}()
	}
	wg.Wait()
	return out, nil
}

// volumeIn returns a volume of a project; operations use it, for their context names no project.
func (s *Service) volumeIn(ctx context.Context, project, name string) (api.Volume, error) {
	o, err := s.volKind.p(project).get(name)
	if err != nil {
		return api.Volume{}, err
	}
	return s.volumeView(ctx, project, o), nil
}

// GetVolume returns a volume.
func (s *Service) GetVolume(ctx context.Context, name string) (api.Volume, error) {
	p, err := s.access(ctx)
	if err != nil {
		return api.Volume{}, err
	}
	o, err := s.volKind.p(p.Meta.Name).get(name)
	if err != nil {
		return api.Volume{}, err
	}
	return s.volumeView(ctx, p.Meta.Name, o), nil
}

// checkVolumeSpec checks a volume's spec and returns it with the size and the mode in their canonical form.
func (s *Service) checkVolumeSpec(p project, name string, spec api.VolumeSpec) (api.VolumeSpec, *storageInfo, uint32, error) {
	if err := validate.Name("name", name); err != nil {
		return spec, nil, 0, err
	}
	if err := validate.NameLength("volume", "name", name, validate.MaxVolumeName); err != nil {
		return spec, nil, 0, err
	}
	if err := api.ValidFreeText("comment", spec.Comment, false); err != nil {
		return spec, nil, 0, err
	}
	if spec.IsHostDir() || spec.Watch || spec.Probe != "" || spec.OnLoss != "" {
		spec, err := api.CheckHostDirVolume(spec)
		return spec, nil, 0, err
	}
	if spec.UID < 0 || spec.GID < 0 || spec.UID > 0x7fffffff || spec.GID > 0x7fffffff {
		return spec, nil, 0, invalid("uid and gid are numbers from 0")
	}
	mode, err := parseVolumeMode(spec.Mode)
	if err != nil {
		return spec, nil, 0, err
	}
	spec.Mode = fmt.Sprintf("%04o", mode)
	if spec.Size != "" {
		c, err := validate.CanonicalSize("size", spec.Size)
		if err != nil {
			return spec, nil, 0, err
		}
		spec.Size = c
	}
	si, err := s.volumeStorage(p, spec.Storage)
	if err != nil {
		return spec, nil, 0, err
	}
	spec.Storage = si.Name
	ds := lifecycle.VolumeDS(si.lifecycle(), p.Meta.Name, name)
	if err := validate.DatasetBudget("name", "volume "+name, ds, validate.SnapshotReserve); err != nil {
		return spec, nil, 0, err
	}
	return spec, si, mode, nil
}

// CreateVolume creates a volume in the request's project as an operation whose result is the Volume. The passphrase
// of an encrypted volume is handed to the creating step and dropped; the operation, its journal and the volume never
// hold it.
func (s *Service) CreateVolume(ctx context.Context, in api.VolumeCreate) (api.Operation, error) {
	if err := s.requireHost("volumes"); err != nil {
		return api.Operation{}, err
	}
	p, err := s.access(ctx)
	if err != nil {
		return api.Operation{}, err
	}
	if err := bodyProject(p.Meta.Name, in.Metadata.Project); err != nil {
		return api.Operation{}, err
	}
	proj, name := p.Meta.Name, in.Metadata.Name
	spec, si, mode, err := s.checkVolumeSpec(p, name, in.Spec)
	if err != nil {
		return api.Operation{}, err
	}
	if err := api.ValidLabels(in.Metadata.Labels); err != nil {
		return api.Operation{}, err
	}
	if spec.IsHostDir() {
		return s.createHostDirVolume(ctx, p, in, spec)
	}
	var pass []byte
	switch {
	case spec.Encrypted && s.d.Keys == nil:
		return api.Operation{}, api.Errorf(api.CodeUnsupported, "encrypted volumes are not available on this host").
			WithHint("the daemon runs without the privileged helper's key operations")
	case spec.Encrypted && in.Passphrase == "":
		return api.Operation{}, invalid("an encrypted volume needs a passphrase").WithHint("jailops prompts for it; scripts use --passphrase-file")
	case !spec.Encrypted && in.Passphrase != "":
		return api.Operation{}, invalid("a passphrase was given but the volume is not encrypted").WithHint("add --encrypted or leave the passphrase out")
	case spec.Encrypted:
		if err := api.CheckPassphrase(in.Passphrase); err != nil {
			return api.Operation{}, err
		}
		pass = []byte(in.Passphrase)
	}
	ks := s.volKind.p(proj)
	if err := ks.notTaken(name); err != nil {
		wipe(pass)
		return api.Operation{}, err
	}
	meta := api.ObjectMeta{Name: name, Project: proj, Labels: in.Metadata.Labels, ManagedBy: in.Metadata.ManagedBy}
	op, err := s.Submit(ctx, OpSpec{
		Description: "Create volume " + name, Locks: []string{volumeLock(proj, name)}, Project: proj,
		Resources: map[string][]string{"volumes": {"/api/v1/volumes/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			defer wipe(pass)
			o, err := s.makeVolume(ctx, p, si, meta, spec, mode, pass, false)
			if err != nil {
				return nil, err
			}
			return s.volumeView(ctx, proj, o), nil
		},
	})
	if err != nil {
		wipe(pass)
	}
	return op, err
}

// makeVolume creates the dataset of a volume and its object; the caller holds the lock of the volume and has checked
// the spec. The dataset is destroyed again when the object cannot be stored.
func (s *Service) makeVolume(ctx context.Context, p project, si *storageInfo, meta api.ObjectMeta, spec api.VolumeSpec, mode uint32, pass []byte, restoring bool) (object[api.VolumeSpec], error) {
	proj := p.Meta.Name
	g, _ := specStorageGrant(p.Spec, si.Name)
	if err := s.ensureProjectDatasets(ctx, proj, si, g); err != nil {
		return object[api.VolumeSpec]{}, err
	}
	req := lifecycle.VolumeRequest{Storage: si.lifecycle(), Project: proj, Name: meta.Name, UUID: state_uuid(), Size: spec.Size,
		UID: spec.UID, GID: spec.GID, Mode: mode, Encrypted: spec.Encrypted, Restoring: restoring}
	// what a recovery needs to take the dataset away again if the daemon dies in the middle
	runID := "create-volume/" + proj + "_" + meta.Name
	recorded := req
	_ = s.journal.putRequest(runID, opRequest{Kind: "create-volume", Volume: &recorded})
	_, err := s.life.CreateVolume(ctx, req, pass, false)
	s.journal.deleteRequest(runID)
	if err != nil {
		return object[api.VolumeSpec]{}, err
	}
	o, err := s.volKind.p(proj).create(ctx, meta, spec)
	if err != nil {
		_ = s.life.DestroyVolume(ctx, si.lifecycle(), proj, meta.Name)
		return o, err
	}
	return o, nil
}

// dropVolume destroys a volume and its object, for the undo of a plan that made it.
func (s *Service) dropVolume(ctx context.Context, project, name string) error {
	ks := s.volKind.p(project)
	o, err := ks.get(name)
	if err != nil {
		return nil
	}
	if si, ok := s.storage(o.Spec.Storage); ok {
		if err := s.life.DestroyVolume(ctx, si.lifecycle(), project, name); err != nil {
			return err
		}
	}
	return ks.delete(ctx, name, AnyGeneration)
}

// UpdateVolume replaces the labels, the comment and the size of a volume. Everything else is fixed when it is made.
func (s *Service) UpdateVolume(ctx context.Context, name string, in api.Volume, expect int64) (api.Volume, error) {
	if err := s.requireHost("volumes"); err != nil {
		return api.Volume{}, err
	}
	p, err := s.access(ctx)
	if err != nil {
		return api.Volume{}, err
	}
	if in.Metadata.Name != "" && in.Metadata.Name != name {
		return api.Volume{}, renameByAction("volume", "volumes")
	}
	if err := bodyProject(p.Meta.Name, in.Metadata.Project); err != nil {
		return api.Volume{}, err
	}
	proj := p.Meta.Name
	ks := s.volKind.p(proj)
	unlock, err := s.locks.lockPatient(ctx, "update volume "+name, volumeLock(proj, name))
	if err != nil {
		return api.Volume{}, err
	}
	defer unlock()
	old, err := ks.get(name)
	if err != nil {
		return api.Volume{}, err
	}
	spec, si, _, err := s.checkVolumeSpec(p, name, in.Spec)
	if err != nil {
		return api.Volume{}, err
	}
	if old.Spec.IsHostDir() && (spec.Watch != old.Spec.Watch || spec.Probe != old.Spec.Probe || spec.OnLoss != old.Spec.OnLoss) {
		if err := requireGlobalAdminFor(ctx, "watching a directory of the host and what happens when its mount is lost"); err != nil {
			return api.Volume{}, err
		}
	}
	for _, f := range []struct {
		what    string
		changed bool
		hint    string
	}{
		{"path", spec.Path != old.Spec.Path, "a volume keeps its directory: make a new volume for another one"},
		{"storage", spec.Storage != old.Spec.Storage, "a volume stays on its storage: create a new volume there and copy the files"},
		{"uid", spec.UID != old.Spec.UID, "the owner of a volume is set when it is made: change it inside a jail with chown"},
		{"gid", spec.GID != old.Spec.GID, "the owner of a volume is set when it is made: change it inside a jail with chown"},
		{"mode", spec.Mode != old.Spec.Mode, "the mode of a volume is set when it is made: change it inside a jail with chmod"},
		{"encrypted", spec.Encrypted != old.Spec.Encrypted, "a volume is encrypted when it is made: create a new one and copy the files"},
	} {
		if f.changed {
			return api.Volume{}, invalid("the %s of a volume cannot change", f.what).WithHint(f.hint)
		}
	}
	if spec.Size != old.Spec.Size {
		if err := s.life.ResizeVolume(ctx, si.lifecycle(), proj, name, spec.Size); err != nil {
			return api.Volume{}, err
		}
	}
	o, err := ks.update(ctx, name, expect, in.Metadata.Labels, &in.Metadata.ManagedBy, spec)
	if err != nil {
		return api.Volume{}, err
	}
	return s.volumeView(ctx, proj, o), nil
}

// PatchVolume applies a merge patch.
func (s *Service) PatchVolume(ctx context.Context, name string, patch map[string]any, expect int64) (api.Volume, error) {
	cur, err := s.GetVolume(ctx, name)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return cur, api.Errorf(api.CodeConflict, "volume %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	var out api.Volume
	if err := MergePatch(cur, patch, &out); err != nil {
		return out, err
	}
	return s.UpdateVolume(ctx, name, out, cur.Metadata.Generation)
}

// refuseAttached refuses a change that a jail with the volume attached would lose its files to.
func (s *Service) refuseAttached(project, name, what string) error {
	uses := s.volumeUses(project, name)
	if len(uses) == 0 {
		return nil
	}
	jails := make([]string, len(uses))
	for i, u := range uses {
		jails[i] = u.Jail
	}
	return api.Errorf(api.CodeBusy, "volume %q is attached to %s: %s", name, strings.Join(jails, ", "), what).
		WithHint("jailops volume detach "+jails[0]+" "+name).WithDetail("jails", strings.Join(jails, ","))
}

// DeleteVolume destroys a volume, with its snapshots, as an operation. A volume that a jail attaches is not deleted.
func (s *Service) DeleteVolume(ctx context.Context, name string, expect int64) (api.Operation, error) {
	if err := s.requireHost("volumes"); err != nil {
		return api.Operation{}, err
	}
	p, err := s.access(ctx)
	if err != nil {
		return api.Operation{}, err
	}
	proj := p.Meta.Name
	ks := s.volKind.p(proj)
	o, err := ks.get(name)
	if err != nil {
		return api.Operation{}, err
	}
	if expect != AnyGeneration && expect != o.Meta.Generation {
		return api.Operation{}, api.Errorf(api.CodeConflict, "volume %q changed: current generation is %d", name, o.Meta.Generation)
	}
	if err := s.refuseAttached(proj, name, "detach it before it is deleted"); err != nil {
		return api.Operation{}, err
	}
	if !o.Spec.IsHostDir() {
		if err := s.backupRunning("volume", name, o.Meta.UUID); err != nil {
			return api.Operation{}, err
		}
	}
	if o.Spec.IsHostDir() {
		// there is no dataset: the volume is forgotten and the directory is left as it is
		return s.Submit(ctx, OpSpec{
			Description: "Delete volume " + name, Locks: []string{volumeLock(proj, name)}, Project: proj,
			Resources: map[string][]string{"volumes": {"/api/v1/volumes/" + name}},
			Run: func(ctx context.Context, h *OpHandle) (any, error) {
				if err := s.refuseAttached(proj, name, "detach it before it is deleted"); err != nil {
					return nil, err
				}
				return nil, ks.delete(ctx, name, AnyGeneration)
			},
		})
	}
	si, ok := s.storage(o.Spec.Storage)
	if !ok {
		return api.Operation{}, notFound("storage", o.Spec.Storage)
	}
	return s.Submit(ctx, OpSpec{
		Description: "Delete volume " + name, Locks: []string{volumeLock(proj, name)}, Project: proj,
		Resources: map[string][]string{"volumes": {"/api/v1/volumes/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			if err := s.refuseAttached(proj, name, "detach it before it is deleted"); err != nil {
				return nil, err
			}
			if err := s.life.DestroyVolume(ctx, si.lifecycle(), proj, name); err != nil {
				return nil, err
			}
			s.forgetKeys("vol:" + proj + "/" + name)
			return nil, ks.delete(ctx, name, AnyGeneration)
		},
	})
}

// volumeOf resolves a volume of a request: the project, the object and its storage.
func (s *Service) volumeOf(ctx context.Context, name string) (project, object[api.VolumeSpec], lifecycle.Storage, error) {
	if err := s.requireHost("volumes"); err != nil {
		return project{}, object[api.VolumeSpec]{}, lifecycle.Storage{}, err
	}
	p, err := s.access(ctx)
	if err != nil {
		return p, object[api.VolumeSpec]{}, lifecycle.Storage{}, err
	}
	o, err := s.volKind.p(p.Meta.Name).get(name)
	if err != nil {
		return p, o, lifecycle.Storage{}, err
	}
	if o.Spec.IsHostDir() {
		return p, o, lifecycle.Storage{}, refuseHostDir(name, "it has no snapshots, no key and no size of its own")
	}
	si, ok := s.storage(o.Spec.Storage)
	if !ok {
		return p, o, lifecycle.Storage{}, notFound("storage", o.Spec.Storage)
	}
	return p, o, si.lifecycle(), nil
}

// ---- snapshots ----

func volSnapToAPI(project, volume string, sn lifecycle.VolumeSnap) api.VolumeSnapshot {
	return api.VolumeSnapshot{Metadata: api.ObjectMeta{Name: sn.Name, Project: project},
		Spec: api.VolumeSnapshotSpec{Volume: volume, Comment: sn.Comment}, Status: api.VolumeSnapshotStatus{Written: sn.Written}}
}

// ListVolumeSnapshots lists the snapshots of a volume.
func (s *Service) ListVolumeSnapshots(ctx context.Context, name string) ([]api.VolumeSnapshot, error) {
	p, _, st, err := s.volumeOf(ctx, name)
	if err != nil {
		return nil, err
	}
	info, err := s.life.VolumeInfo(ctx, st, p.Meta.Name, name)
	if err != nil {
		return nil, err
	}
	out := []api.VolumeSnapshot{}
	for _, sn := range info.Snapshots {
		out = append(out, volSnapToAPI(p.Meta.Name, name, sn))
	}
	return out, nil
}

// CreateVolumeSnapshot snapshots a volume as an operation. An empty name lets the server choose "snap-<time>".
func (s *Service) CreateVolumeSnapshot(ctx context.Context, name string, req api.VolumeSnapshot) (api.Operation, error) {
	p, _, st, err := s.volumeOf(ctx, name)
	if err != nil {
		return api.Operation{}, err
	}
	if err := api.ValidFreeText("comment", req.Spec.Comment, false); err != nil {
		return api.Operation{}, err
	}
	snap := req.Metadata.Name
	if snap == "" {
		snap = "snap-" + s.now().UTC().Format("20060102T150405Z")
	} else if err := validate.SnapshotName("name", snap); err != nil {
		return api.Operation{}, err
	}
	proj := p.Meta.Name
	return s.Submit(ctx, OpSpec{
		Description: "Snapshot volume " + name, Locks: []string{volumeLock(proj, name)}, Project: proj,
		Resources: map[string][]string{"volumes": {"/api/v1/volumes/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			props := map[string]string{}
			if req.Spec.Comment != "" {
				props[lifecycle.PropComment] = req.Spec.Comment
			}
			if err := s.life.SnapshotVolume(ctx, st, proj, name, snap, props); err != nil {
				return nil, err
			}
			s.emitIn(ctx, proj, "volume-snapshot-created", "/api/v1/volumes/"+name+"/snapshots/"+snap)
			return api.VolumeSnapshot{Metadata: api.ObjectMeta{Name: snap, Project: proj}, Spec: api.VolumeSnapshotSpec{Volume: name, Comment: req.Spec.Comment}}, nil
		},
	})
}

// DeleteVolumeSnapshot deletes a snapshot of a volume as an operation.
func (s *Service) DeleteVolumeSnapshot(ctx context.Context, name, snap string) (api.Operation, error) {
	p, _, st, err := s.volumeOf(ctx, name)
	if err != nil {
		return api.Operation{}, err
	}
	proj := p.Meta.Name
	info, err := s.life.VolumeInfo(ctx, st, proj, name)
	if err != nil {
		return api.Operation{}, err
	}
	if !slices.ContainsFunc(info.Snapshots, func(x lifecycle.VolumeSnap) bool { return x.Name == snap }) {
		return api.Operation{}, notFound("snapshot", snap)
	}
	return s.Submit(ctx, OpSpec{
		Description: "Delete snapshot " + snap + " of volume " + name, Locks: []string{volumeLock(proj, name)}, Project: proj,
		Resources: map[string][]string{"volumes": {"/api/v1/volumes/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			if err := s.life.DeleteVolumeSnapshot(ctx, st, proj, name, snap); err != nil {
				return nil, err
			}
			s.emitIn(ctx, proj, "volume-snapshot-deleted", "/api/v1/volumes/"+name+"/snapshots/"+snap)
			return nil, nil
		},
	})
}

// RollbackVolume returns a volume to a snapshot as an operation: everything written since is gone, and so are the
// snapshots after it. No jail that has the volume attached may run, for the files would change under it.
func (s *Service) RollbackVolume(ctx context.Context, name string, rb api.VolumeRollback) (api.Operation, error) {
	p, _, st, err := s.volumeOf(ctx, name)
	if err != nil {
		return api.Operation{}, err
	}
	if rb.Snapshot == "" {
		return api.Operation{}, invalid("name the snapshot to roll back to")
	}
	if !rb.ConfirmDataLoss {
		return api.Operation{}, invalid("a rollback discards what was written to the volume since the snapshot").WithHint("repeat it with confirm_data_loss (jailops volume snapshot rollback --confirm-data-loss)")
	}
	proj := p.Meta.Name
	info, err := s.life.VolumeInfo(ctx, st, proj, name)
	if err != nil {
		return api.Operation{}, err
	}
	if !slices.ContainsFunc(info.Snapshots, func(x lifecycle.VolumeSnap) bool { return x.Name == rb.Snapshot }) {
		return api.Operation{}, notFound("snapshot", rb.Snapshot)
	}
	locks := []string{volumeLock(proj, name)}
	for _, u := range s.volumeUses(proj, name) {
		k, _ := validate.QualifiedName(proj, u.Jail)
		locks = append(locks, jailLock(k))
	}
	return s.Submit(ctx, OpSpec{
		Description: "Roll volume " + name + " back to " + rb.Snapshot, Locks: locks, Project: proj,
		Resources: map[string][]string{"volumes": {"/api/v1/volumes/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			if err := s.refuseRunningUsers(ctx, proj, name, "stop it before the volume is rolled back"); err != nil {
				return nil, err
			}
			if err := s.life.RollbackVolume(ctx, st, proj, name, rb.Snapshot); err != nil {
				return nil, err
			}
			s.emitIn(ctx, proj, "volume-rolled-back", "/api/v1/volumes/"+name)
			return s.volumeIn(ctx, proj, name)
		},
	})
}

// refuseRunningUsers refuses while a jail that has the volume attached runs.
func (s *Service) refuseRunningUsers(ctx context.Context, project, name, what string) error {
	for _, u := range s.volumeUses(project, name) {
		k, _ := validate.QualifiedName(project, u.Jail)
		if j, err := s.getByKey(ctx, k); err == nil && j.Status.Power == api.PowerRunning {
			return api.Errorf(api.CodeBusy, "jail %q has volume %q attached and is running: %s", u.Jail, name, what).WithHint("jailops stop " + u.Jail)
		}
	}
	return nil
}

// ---- attach and detach ----

// checkAttachments checks the volumes a jail attaches: the volumes exist in its project, an encrypted volume is
// attached to no other jail, and the paths do not collide with the jail's persistent paths or each other.
func (s *Service) checkAttachments(project, key string, vs []api.VolumeAttach) ([]api.VolumeAttach, error) {
	vs, err := s.lcfg.CheckVolumes(vs)
	if err != nil {
		return nil, err
	}
	_, jail := validate.SplitQualified(key)
	for _, v := range vs {
		o, err := s.volKind.p(project).get(v.Name)
		if err != nil {
			return nil, api.Errorf(api.CodeNotFound, "volume %q does not exist in project %q", v.Name, project).WithHint("jailops volume create " + v.Name)
		}
		if !o.Spec.Encrypted {
			continue
		}
		for _, u := range s.volumeUses(project, v.Name) {
			if u.Jail != jail {
				return nil, api.Errorf(api.CodeConflict, "volume %q is encrypted and attached to jail %q already: an encrypted volume is attached to one jail", v.Name, u.Jail).
					WithHint("jailops volume detach " + u.Jail + " " + v.Name)
			}
		}
	}
	return vs, nil
}

// checkEncryptedSharing refuses an encrypted volume that the jail key would attach together with another jail of the
// project, whether the volume comes from the jail's own spec or from a profile, and whether the other jail exists or
// is being created. The caller holds quotaMu (jails being created are registered there).
func (s *Service) checkEncryptedSharing(project, key string, vols []api.VolumeAttach) error {
	for _, v := range vols {
		o, err := s.volKind.p(project).get(v.Name)
		if err != nil || !o.Spec.Encrypted {
			continue
		}
		if other := s.otherUserOfVolume(project, key, v.Name, nil); other != "" {
			return encryptedSharedErr(v.Name, other)
		}
	}
	return nil
}

func encryptedSharedErr(volume, jail string) error {
	return api.Errorf(api.CodeConflict, "volume %q is encrypted and attached to jail %q already: an encrypted volume is attached to one jail", volume, jail).
		WithHint("jailops volume detach " + jail + " " + volume)
}

// otherUserOfVolume names a jail of the project other than key that attaches the volume (its own spec and its profiles
// counted; a jail in override uses the spec given there, for a change that is not stored yet), or "".
func (s *Service) otherUserOfVolume(project, key, volume string, override map[string]api.JailSpec) string {
	has := func(spec api.JailSpec) bool {
		return slices.ContainsFunc(spec.Volumes, func(a api.VolumeAttach) bool { return a.Name == volume })
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, e := range s.jails {
		if k == key || e.jail.Metadata.Project != project {
			continue
		}
		spec, ok := override[k]
		if !ok {
			spec = s.effective(e.jail)
		}
		if has(spec) {
			return e.jail.Metadata.Name
		}
	}
	for k, pj := range s.pending {
		if _, registered := s.jails[k]; k != key && pj.project == project && !registered && has(pj.spec) {
			_, name := validate.SplitQualified(k)
			return name
		}
	}
	return ""
}

// attachmentsChanged runs the checks of a change of a jail's volumes: the jail is stopped and the new ones are valid.
func (s *Service) attachmentsChanged(ctx context.Context, project, key string, spec []api.VolumeAttach) ([]api.VolumeAttach, error) {
	_, jail := validate.SplitQualified(key)
	if j, err := s.getByKey(ctx, key); err == nil && j.Status.Power == api.PowerRunning {
		return nil, api.Errorf(api.CodeBusy, "jail %q is running: volumes are attached and detached while it is stopped", jail).WithHint("jailops stop " + jail)
	}
	return s.checkAttachments(project, key, spec)
}

// ListJailVolumes lists what a jail attaches.
func (s *Service) ListJailVolumes(ctx context.Context, jail string) ([]api.VolumeAttach, error) {
	_, key, err := s.jailRef(ctx, jail)
	if err != nil {
		return nil, err
	}
	j, err := s.getByKey(ctx, key)
	if err != nil {
		return nil, err
	}
	if j.Spec.Volumes == nil {
		return []api.VolumeAttach{}, nil
	}
	return j.Spec.Volumes, nil
}

// AttachVolume attaches a volume of the project to a stopped jail at a path in it, as an operation whose result is
// the jail. With CopyExisting the files the jail has at the path are copied into the volume first.
func (s *Service) AttachVolume(ctx context.Context, jail string, req api.VolumeAttachRequest) (api.Operation, error) {
	if err := s.requireHost("volumes"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, jail)
	if err != nil {
		return api.Operation{}, err
	}
	proj := p.Meta.Name
	if req.Volume == "" || req.Mount == "" {
		return api.Operation{}, invalid("name the volume and the path it has in the jail")
	}
	old, err := s.jailSnapshot(key)
	if err != nil {
		return api.Operation{}, notFound("jail", jail)
	}
	vo, err := s.volKind.p(proj).get(req.Volume)
	if err != nil {
		return api.Operation{}, api.Errorf(api.CodeNotFound, "volume %q does not exist in project %q", req.Volume, proj).WithHint("jailops volume create " + req.Volume)
	}
	if slices.ContainsFunc(old.Spec.Volumes, func(v api.VolumeAttach) bool { return v.Name == req.Volume }) {
		return api.Operation{}, api.Errorf(api.CodeAlreadyExists, "volume %q is attached to jail %q already", req.Volume, jail).
			WithHint("jailops volume detach " + jail + " " + req.Volume + " to attach it elsewhere in the jail")
	}
	var si *storageInfo
	if vo.Spec.IsHostDir() {
		if err := requireGlobalAdminFor(ctx, "attaching a directory of the host to a jail"); err != nil {
			return api.Operation{}, err
		}
		if req.CopyExisting {
			return api.Operation{}, refuseHostDir(req.Volume, "the files a jail has at the path are not copied into the host's directory")
		}
	} else {
		var ok bool
		if si, ok = s.storage(vo.Spec.Storage); !ok {
			return api.Operation{}, notFound("storage", vo.Spec.Storage)
		}
	}
	if req.CopyExisting && vo.Spec.Encrypted && s.d.Keys == nil {
		return api.Operation{}, api.Errorf(api.CodeUnsupported, "encrypted volumes are not available on this host")
	}
	return s.Submit(ctx, OpSpec{
		Description: "Attach volume " + req.Volume + " to jail " + jail, Locks: []string{jailLock(key), anchorLock(key), volumeLock(proj, req.Volume)}, Project: proj,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + jail}, "volumes": {"/api/v1/volumes/" + req.Volume}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			cur, err := s.jailSnapshot(key)
			if err != nil {
				return nil, notFound("jail", jail)
			}
			if j, err := s.getByKey(ctx, key); err == nil && j.Status.Power == api.PowerRunning {
				return nil, api.Errorf(api.CodeBusy, "jail %q is running: volumes are attached and detached while it is stopped", jail).WithHint("jailops stop " + jail)
			}
			in := cur
			in.Spec.Volumes = append(slices.Clone(cur.Spec.Volumes), api.VolumeAttach{Name: req.Volume, Mount: req.Mount, ReadOnly: req.ReadOnly})
			// Everything is checked before the files are copied: a refused attachment copies nothing.
			vols, err := s.attachmentsChanged(ctx, proj, key, in.Spec.Volumes)
			if err != nil {
				return nil, err
			}
			in.Spec.Volumes = vols
			if req.CopyExisting {
				mount := vols[len(vols)-1].Mount
				if err := s.life.CopyIntoVolume(ctx, key, mount, si.lifecycle(), proj, req.Volume); err != nil {
					return nil, err
				}
			}
			return s.updateAttachments(ctx, p, key, jail, in)
		},
	})
}

// DetachVolume detaches a volume from a stopped jail as an operation whose result is the jail. The volume and its
// files stay.
func (s *Service) DetachVolume(ctx context.Context, jail, volume string) (api.Operation, error) {
	if err := s.requireHost("volumes"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, jail)
	if err != nil {
		return api.Operation{}, err
	}
	proj := p.Meta.Name
	old, err := s.jailSnapshot(key)
	if err != nil {
		return api.Operation{}, notFound("jail", jail)
	}
	if !slices.ContainsFunc(old.Spec.Volumes, func(v api.VolumeAttach) bool { return v.Name == volume }) {
		return api.Operation{}, notFound("volume attachment", volume)
	}
	return s.Submit(ctx, OpSpec{
		Description: "Detach volume " + volume + " from jail " + jail, Locks: []string{jailLock(key), anchorLock(key), volumeLock(proj, volume)}, Project: proj,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + jail}, "volumes": {"/api/v1/volumes/" + volume}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			cur, err := s.jailSnapshot(key)
			if err != nil {
				return nil, notFound("jail", jail)
			}
			i := slices.IndexFunc(cur.Spec.Volumes, func(v api.VolumeAttach) bool { return v.Name == volume })
			if i < 0 {
				return nil, notFound("volume attachment", volume)
			}
			if j, err := s.getByKey(ctx, key); err == nil && j.Status.Power == api.PowerRunning {
				return nil, api.Errorf(api.CodeBusy, "jail %q is running: volumes are attached and detached while it is stopped", jail).WithHint("jailops stop " + jail)
			}
			in := cur
			in.Spec.Volumes = slices.Delete(slices.Clone(cur.Spec.Volumes), i, i+1)
			if len(in.Spec.Volumes) == 0 {
				in.Spec.Volumes = nil
			}
			return s.updateAttachments(ctx, p, key, jail, in)
		},
	})
}

// updateAttachments stores a jail with its new attachments; the caller holds the jail's locks.
func (s *Service) updateAttachments(ctx context.Context, p project, key, jail string, in api.Jail) (api.Jail, error) {
	unlockNets, err := s.locks.lockPatient(ctx, "attach volumes of "+jail, s.netLocksEff(p.Meta.Name, in.Spec)...)
	if err != nil {
		return api.Jail{}, err
	}
	defer unlockNets()
	return s.updateLocked(ctx, p, key, jail, in, AnyGeneration)
}
