package service

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// The renames of the objects that stand on their own in the state store: a backup target, a backup policy, a
// certificate, a storage and a volume. Each follows the planners of rename_config.go: the object and everything
// that names it change in one operation, or none of it does.

// RenameBackupTarget renames a backup target and rewrites the targets lists of the policies that name it. The
// backups that were made keep the name the target had in their records: a backup is written once.
func (s *Service) RenameBackupTarget(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := requireGlobal(ctx, "renaming a backup target"); err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindBackupTarget, noun: "backup-target", path: "/api/v1/backup-targets", from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		obj, err := s.tgtKind.getObj(name)
		if err != nil {
			return nil, notFound("backup-target", name)
		}
		if err := checkGeneration("backup target", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("backup target", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := s.tgtKind.notTaken(to); err != nil {
			return nil, err
		}
		p := newRenamePlan()
		p.lock("backup-target/"+name, "backup-target/"+to)
		p.resources["backup-targets"] = []string{"/api/v1/backup-targets/" + name, "/api/v1/backup-targets/" + to}
		st, err := stateStep(api.KindBackupTarget, obj, to, "", nil, objectChange("backup target", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		pols, err := s.bpolKind.listAll()
		if err != nil {
			return nil, err
		}
		for _, pol := range pols {
			if !slices.Contains(pol.Spec.Targets, name) {
				continue
			}
			if err := refuseManagedRef("backup policy", pol.Meta.Name, pol.Meta.ManagedBy); err != nil {
				return nil, err
			}
			spec := pol.Spec
			spec.Targets = replaceAll(spec.Targets, name, to)
			po, err := s.bpolKind.p(pol.Meta.Project).getObj(pol.Meta.Name)
			if err != nil {
				return nil, internal(err)
			}
			ps, err := stateStep(api.KindBackupPolicy, po, pol.Meta.Name, pol.Meta.Project, spec,
				api.RenameChange{Kind: api.RenameReference, Object: fmt.Sprintf("backup policy %s (project %s)", pol.Meta.Name, pol.Meta.Project),
					Detail: "spec.targets: " + name + " -> " + to})
			if err != nil {
				return nil, err
			}
			p.add(ps)
			p.lock(projectLock(pol.Meta.Project))
		}
		p.warnings = append(p.warnings, "the backups that were made keep the name "+name+" in their records")
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// RenameBackupPolicy renames a backup policy of the project. Its schedule starts again under the new name, and the
// backups that were made keep the old name in their records.
func (s *Service) RenameBackupPolicy(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	pr, err := s.access(ctx)
	if err != nil {
		return api.Operation{}, nil, err
	}
	proj, to := pr.Meta.Name, o.NewName
	j := renameJob{kind: api.KindBackupPolicy, noun: "backup-policy", path: "/api/v1/backup-policies", project: proj, from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		ks := s.bpolKind.p(proj)
		obj, err := ks.getObj(name)
		if err != nil {
			return nil, notFound("backup-policy", name)
		}
		if err := checkGeneration("backup policy", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("backup policy", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := ks.notTaken(to); err != nil {
			return nil, err
		}
		p := newRenamePlan()
		p.lock(projectLock(proj))
		p.resources["backup-policies"] = []string{"/api/v1/backup-policies/" + name, "/api/v1/backup-policies/" + to}
		st, err := stateStep(api.KindBackupPolicy, obj, to, proj, nil, objectChange("backup policy", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		p.warnings = append(p.warnings, "the schedule of the policy starts again under the new name, and the backups that were made keep the name "+name+" in their records")
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// RenameCertificate renames a certificate: its fingerprint, permissions and projects stay. The audit log keeps the
// name the certificate had when it acted.
func (s *Service) RenameCertificate(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := requireGlobal(ctx, "renaming a certificate"); err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindCertificate, noun: "certificate", path: "/api/v1/certificates", from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		obj, err := s.certKind.getObj(name)
		if err != nil {
			return nil, notFound("certificate", name)
		}
		if err := checkGeneration("certificate", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("certificate", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := s.certKind.notTaken(to); err != nil {
			return nil, err
		}
		p := newRenamePlan()
		p.lock("certificate/"+name, "certificate/"+to)
		p.resources["certificates"] = []string{"/api/v1/certificates/" + name, "/api/v1/certificates/" + to}
		st, err := stateStep(api.KindCertificate, obj, to, "", nil, objectChange("certificate", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		p.warnings = append(p.warnings, "the audit log keeps the name "+name+" for what the certificate did before")
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// RenameStorage renames a storage: the projects it is granted to, the jails and volumes on it and the registry the
// daemon keeps. The datasets stay where they are; the name is the only thing that changes. The default storage keeps
// its name, and a storage that jails or volumes use is renamed while they run (nothing about them moves).
func (s *Service) RenameStorage(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := requireGlobal(ctx, "renaming a storage"); err != nil {
		return api.Operation{}, nil, err
	}
	if err := s.requireHost("storage"); err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindStorage, noun: "storage", path: "/api/v1/storage", from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		obj, err := s.stoKind.getObj(name)
		if err != nil {
			return nil, notFound("storage", name)
		}
		if name == DefaultStorage {
			return nil, api.Errorf(api.CodeBusy, "the default storage keeps its name").WithHint("create a storage with the name you want and move to it")
		}
		if err := checkGeneration("storage", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("storage", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := s.stoKind.notTaken(to); err != nil {
			return nil, err
		}
		si, ok := s.storage(name)
		if !ok {
			return nil, notFound("storage", name)
		}
		p := newRenamePlan()
		p.lock(storageLock(name), storageLock(to))
		p.resources["storage"] = []string{"/api/v1/storage/" + name, "/api/v1/storage/" + to}
		st, err := stateStep(api.KindStorage, obj, to, "", nil, objectChange("storage", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		// the projects it is granted to
		projs, err := s.projKind.list()
		if err != nil {
			return nil, err
		}
		for _, pr := range projs {
			spec := pr.Spec
			spec.Storage = slices.Clone(spec.Storage)
			hit := false
			for i := range spec.Storage {
				if spec.Storage[i].Storage == name {
					spec.Storage[i].Storage, hit = to, true
				}
			}
			if !hit {
				continue
			}
			if err := refuseManagedRef("project", pr.Meta.Name, pr.Meta.ManagedBy); err != nil {
				return nil, err
			}
			po, err := s.projKind.getObj(pr.Meta.Name)
			if err != nil {
				return nil, internal(err)
			}
			ps, err := stateStep(api.KindProject, po, pr.Meta.Name, "", spec,
				api.RenameChange{Kind: api.RenameReference, Object: "project " + pr.Meta.Name, Detail: "spec.storage: " + name + " -> " + to})
			if err != nil {
				return nil, err
			}
			p.add(ps)
			p.lock(projectLock(pr.Meta.Name))
		}
		// the volumes on it
		vols, err := s.volKind.listAll()
		if err != nil {
			return nil, err
		}
		for _, v := range vols {
			if v.Spec.Storage != name {
				continue
			}
			if err := refuseManagedRef("volume", v.Meta.Name, v.Meta.ManagedBy); err != nil {
				return nil, err
			}
			spec := v.Spec
			spec.Storage = to
			vo, err := s.volKind.p(v.Meta.Project).getObj(v.Meta.Name)
			if err != nil {
				return nil, internal(err)
			}
			vs, err := stateStep(api.KindVolume, vo, v.Meta.Name, v.Meta.Project, spec,
				api.RenameChange{Kind: api.RenameReference, Object: fmt.Sprintf("volume %s (project %s)", v.Meta.Name, v.Meta.Project),
					Detail: "spec.storage: " + name + " -> " + to})
			if err != nil {
				return nil, err
			}
			p.add(vs)
			p.lock(volumeLock(v.Meta.Project, v.Meta.Name))
		}
		// the jails on it, running or not
		if err := s.rewriteJails(ctx, p, nil, func(j *api.Jail) []string {
			if j.Spec.Storage != name {
				return nil
			}
			j.Spec.Storage = to
			return []string{"spec.storage: " + name + " -> " + to}
		}); err != nil {
			return nil, err
		}
		// profiles that name it
		if err := s.rewriteProfiles(p, func(k, v string) (string, bool) {
			if k == "storage" && v == name {
				return to, true
			}
			return v, false
		}); err != nil {
			return nil, err
		}
		// the registry of the daemon goes last: the jails above are read through the old name until then
		p.add(renameStep{Op: "storage-registry", From: name, To: to, OldValue: si.Root, NewValue: si.MountBase,
			Change: api.RenameChange{Kind: api.RenameReference, Object: "the storage registry of the daemon", Detail: name + " -> " + to}})
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// renameStorageRegistry moves the in-memory storage from one name to the other.
func (s *Service) renameStorageRegistry(from, to string) error {
	si, ok := s.storage(from)
	if !ok {
		if _, done := s.storage(to); done {
			return nil
		}
		return notFound("storage", from)
	}
	s.addStorage(to, si.Spec, si.Root, si.MountBase)
	s.dropStorage(from)
	return nil
}

// RenameVolume renames a volume of the project: the dataset, its mount point and name property, the attachments of
// the jails and the keys of the profiles that name it. A jail that attaches it must be stopped; a host directory has
// no dataset and only the object and the references change.
func (s *Service) RenameVolume(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := s.requireHost("volumes"); err != nil {
		return api.Operation{}, nil, err
	}
	pr, err := s.access(ctx)
	if err != nil {
		return api.Operation{}, nil, err
	}
	proj, to := pr.Meta.Name, o.NewName
	j := renameJob{kind: api.KindVolume, noun: "volume", path: "/api/v1/volumes", project: proj, from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		ks := s.volKind.p(proj)
		obj, err := ks.getObj(name)
		if err != nil {
			return nil, notFound("volume", name)
		}
		if err := checkGeneration("volume", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("volume", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := ks.notTaken(to); err != nil {
			return nil, err
		}
		v, err := decodeObject[api.VolumeSpec](obj)
		if err != nil {
			return nil, err
		}
		if err := s.refuseRunningUsers(ctx, proj, name, "stop it before the volume is renamed"); err != nil {
			return nil, err
		}
		// a host profile attaches volumes by name to the jails of every project: one project's rename cannot rewrite it
		if hp, err := s.profKind.p(api.HostProfileProject).list(); err == nil {
			for _, x := range hp {
				if profileNamesDisk(x.Spec.Config, name) {
					return nil, api.Errorf(api.CodeConflict, "host profile %q attaches a volume named %q to the jails of every project", x.Meta.Name, name).
						WithHint("change the profile first")
				}
			}
		}
		p := newRenamePlan()
		p.lock(projectLock(proj), volumeLock(proj, name), volumeLock(proj, to))
		p.resources["volumes"] = []string{"/api/v1/volumes/" + name, "/api/v1/volumes/" + to}
		if !v.Spec.IsHostDir() {
			si, ok := s.storage(v.Spec.Storage)
			if !ok {
				return nil, notFound("storage", v.Spec.Storage)
			}
			st := si.lifecycle()
			from, dst := lifecycle.VolumeDS(st, proj, name), lifecycle.VolumeDS(st, proj, to)
			oldMP, newMP := lifecycle.VolumeMP(st, proj, name), lifecycle.VolumeMP(st, proj, to)
			p.add(renameStep{Op: "zfs-rename", From: from, To: dst,
				Change: api.RenameChange{Kind: api.RenameDataset, Object: "dataset " + from, Detail: "renamed to " + dst}})
			p.add(renameStep{Op: "zfs-set", From: dst, Prop: "mountpoint", OldValue: oldMP, NewValue: newMP})
			p.add(renameStep{Op: "zfs-set", From: dst, Prop: lifecycle.PropName, OldValue: name, NewValue: to})
		}
		st, err := stateStep(api.KindVolume, obj, to, proj, nil, objectChange("volume", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		if err := s.rewriteJails(ctx, p, func(x string) bool { return x == proj }, func(j *api.Jail) []string {
			var d []string
			for i := range j.Spec.Volumes {
				if j.Spec.Volumes[i].Name == name {
					j.Spec.Volumes[i].Name = to
					d = append(d, fmt.Sprintf("spec.volumes[%d].volume: %s -> %s", i, name, to))
				}
			}
			return d
		}); err != nil {
			return nil, err
		}
		if err := s.rewriteProfileKeysIn(p, func(x string) bool { return x == proj }, func(k string) (string, bool) {
			return renameDiskKey(k, name, to)
		}); err != nil {
			return nil, err
		}
		p.after = func(ctx context.Context) { s.forgetKeys("vol:" + proj + "/" + name) }
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// renameDiskKey renames the device of a disk.<volume> key of a profile.
func renameDiskKey(key, from, to string) (string, bool) {
	rest, ok := strings.CutPrefix(key, "disk."+from)
	if !ok || (rest != "" && !strings.HasPrefix(rest, ".")) {
		return key, false
	}
	return "disk." + to + rest, true
}

// profileNamesDisk reports whether a profile config attaches the volume.
func profileNamesDisk(cfg map[string]string, volume string) bool {
	for k := range cfg {
		if _, ok := renameDiskKey(k, volume, "x"); ok {
			return true
		}
	}
	return false
}

// rewriteProfileKeysIn renames the keys of the profiles of the projects keep accepts.
func (s *Service) rewriteProfileKeysIn(p *renamePlan, keep func(project string) bool, rename func(key string) (string, bool)) error {
	profs, err := s.profKind.listAll()
	if err != nil {
		return err
	}
	for _, pr := range profs {
		if keep != nil && !keep(pr.Meta.Project) {
			continue
		}
		spec := pr.Spec
		cfg := map[string]string{}
		var d []string
		for _, k := range sortedKeys(spec.Config) {
			nk, ok := rename(k)
			if ok {
				d = append(d, fmt.Sprintf("config %s -> %s", k, nk))
			}
			cfg[nk] = spec.Config[k]
		}
		if len(d) == 0 {
			continue
		}
		if err := refuseManagedRef("profile", pr.Meta.Name, pr.Meta.ManagedBy); err != nil {
			return err
		}
		spec.Config = cfg
		o, err := s.profKind.p(pr.Meta.Project).getObj(pr.Meta.Name)
		if err != nil {
			return internal(err)
		}
		st, err := stateStep(api.KindProfile, o, pr.Meta.Name, pr.Meta.Project, spec,
			api.RenameChange{Kind: api.RenameReference, Object: profileObject(pr.Meta.Project, pr.Meta.Name), Detail: strings.Join(d, "; ")})
		if err != nil {
			return err
		}
		p.add(st)
	}
	return nil
}

// RenameUser renames a user. The id stays, so the password, the second factor and the sessions stay with it; the
// audit log keeps the name the user had when they acted.
func (s *Service) RenameUser(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := requireGlobal(ctx, "renaming a user"); err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindUser, noun: "user", path: "/api/v1/users", from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		u, err := s.d.DB.Users.GetByName(ctx, name)
		if err != nil {
			return nil, notFound("user", name)
		}
		if err := checkGeneration("user", name, o.Expect, userToAPI(u).Metadata.Generation); err != nil {
			return nil, err
		}
		if err := ValidObjectName(to); err != nil {
			return nil, err
		}
		if _, err := s.d.DB.Users.GetByName(ctx, to); err == nil {
			return nil, api.Errorf(api.CodeAlreadyExists, "user %q already exists", to)
		}
		p := newRenamePlan()
		p.lock("user/"+name, "user/"+to)
		p.resources["users"] = []string{"/api/v1/users/" + name, "/api/v1/users/" + to}
		p.add(renameStep{Op: "user-name", From: name, To: to, Prop: u.ID, Change: objectChange("user", name, to)})
		p.warnings = append(p.warnings, "the audit log keeps the name "+name+" for what the user did before")
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// renameUserName sets the name of the user with the id; a user that already has it is left alone.
func (s *Service) renameUserName(ctx context.Context, id, from, to string) error {
	u, err := s.d.DB.Users.GetByID(ctx, id)
	if err != nil {
		return notFound("user", from)
	}
	if u.Name == to {
		return nil
	}
	return s.d.DB.Users.SetName(ctx, id, to)
}

// RenameWireGuard renames a tunnel: the object, the directory of its keys inside the helper's own WireGuard
// directory and the PF anchor, which the reconcile loop loads again under the new name. The interface keeps its
// name and stays up; its description follows with the next apply.
func (s *Service) RenameWireGuard(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := requireGlobal(ctx, "renaming a WireGuard tunnel"); err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindWireGuard, noun: "wireguard", path: "/api/v1/wireguard", from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		obj, err := s.wgKind.getObj(name)
		if err != nil {
			return nil, notFound("wireguard", name)
		}
		if err := checkGeneration("wireguard", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("WireGuard tunnel", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := wireguard.ValidName("name", to); err != nil {
			return nil, err
		}
		if err := s.wgKind.notTaken(to); err != nil {
			return nil, err
		}
		p := newRenamePlan()
		p.lock(wgLock(name), wgLock(to))
		p.resources["wireguard"] = []string{"/api/v1/wireguard/" + name, "/api/v1/wireguard/" + to}
		st, err := stateStep(api.KindWireGuard, obj, to, "", nil, objectChange("WireGuard tunnel", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		if s.d.WG != nil {
			p.add(renameStep{Op: "wg-keys", From: name, To: to,
				Change: api.RenameChange{Kind: api.RenameFile, Object: "the keys of tunnel " + name, Detail: "moved to the directory of " + to}})
		}
		if s.d.PF != nil {
			if cur, err := s.d.PF.Read(ctx, wireguard.Anchor(name)); err == nil && strings.TrimSpace(cur) != "" {
				p.add(renameStep{Op: "anchor", From: wireguard.Anchor(name), To: wireguard.Anchor(to), OldRules: cur,
					Change: api.RenameChange{Kind: api.RenameAnchor, Object: "PF anchor " + wireguard.Anchor(name), Detail: "loaded again as " + wireguard.Anchor(to)}})
			}
		}
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}
