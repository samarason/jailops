package service

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"jailops.net/jailops/internal/imagegen"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// RenameImage renames an image: its datasets on every pool (the generations go with them, and the roots of thin
// jails, which are clones of a generation, follow by themselves), the image name ZFS properties hold, the references
// of the jails (spec.image, bundle.json and their container's property), the projects' image allow-lists and the
// records of its nightly upgrade. Jails on it may run.
func (s *Service) RenameImage(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := requireGlobal(ctx, "renaming an image"); err != nil {
		return api.Operation{}, nil, err
	}
	if err := s.requireHost("images"); err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindImage, noun: "image", path: "/api/v1/images", from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		obj, err := s.imgKind.getObj(name)
		if err != nil {
			return nil, notFound("image", name)
		}
		if err := checkGeneration("image", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("image", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := s.imgKind.notTaken(to); err != nil {
			return nil, err
		}
		s.imgAuto.mu.Lock()
		running := s.imgAuto.running[name]
		s.imgAuto.mu.Unlock()
		if running {
			return nil, api.Errorf(api.CodeBusy, "the nightly upgrade of image %q runs", name).WithHint("rename it when the upgrade finished")
		}
		recs, err := s.journal.List(ctx)
		if err != nil {
			return nil, internal(err)
		}
		for _, r := range recs {
			if _, rest, _ := strings.Cut(r.ID, "/"); strings.HasPrefix(r.ID, "image-") && (rest == name || strings.HasPrefix(rest, name+"/")) {
				return nil, api.Errorf(api.CodeBusy, "image %q has an interrupted run (%s)", name, r.ID).WithHint("run `jailops doctor`")
			}
		}
		p := newRenamePlan()
		p.lock(imageLock(name), imageLock(to))
		p.resources["images"] = []string{"/api/v1/images/" + name, "/api/v1/images/" + to}
		st, err := stateStep(api.KindImage, obj, to, "", nil, objectChange("image", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		for _, m := range s.imageManagers() {
			steps, err := s.imagePoolSteps(ctx, m.Layout, name, to)
			if err != nil {
				return nil, err
			}
			p.add(steps...)
		}
		// the projects whose allow-list names it
		projs, err := s.projKind.list()
		if err != nil {
			return nil, err
		}
		for _, pr := range projs {
			if !slices.Contains(pr.Spec.Images, name) {
				continue
			}
			if err := refuseManagedRef("project", pr.Meta.Name, pr.Meta.ManagedBy); err != nil {
				return nil, err
			}
			spec := pr.Spec
			spec.Images = replaceAll(spec.Images, name, to)
			po, err := s.projKind.getObj(pr.Meta.Name)
			if err != nil {
				return nil, internal(err)
			}
			st, err := stateStep(api.KindProject, po, pr.Meta.Name, "", spec,
				api.RenameChange{Kind: api.RenameReference, Object: "project " + pr.Meta.Name, Detail: "spec.images: " + name + " -> " + to})
			if err != nil {
				return nil, err
			}
			p.add(st)
			p.lock(projectLock(pr.Meta.Name))
		}
		// the jails on it: their records, and the property of their datasets
		s.mu.RLock()
		keys := sortedKeys(s.jails)
		jails := make([]api.Jail, len(keys))
		for i, k := range keys {
			jails[i] = cloneJail(s.jails[k].jail)
		}
		s.mu.RUnlock()
		users := 0
		for i, k := range keys {
			jl := jails[i]
			ref, ok := renameImageRef(jl.Spec.Image, name, to)
			if !ok {
				continue
			}
			users++
			if err := refuseManagedRef("jail", jailDisplay(jl.Metadata.Project, jl.Metadata.Name), jl.Metadata.ManagedBy); err != nil {
				return nil, err
			}
			if slices.ContainsFunc(recs, func(r plan.Record) bool { return strings.HasSuffix(r.ID, "/"+k) }) {
				return nil, api.Errorf(api.CodeBusy, "jail %s has an interrupted run", jailDisplay(jl.Metadata.Project, jl.Metadata.Name)).WithHint("run `jailops doctor`")
			}
			nj := cloneJail(jl)
			nj.Spec.Image = ref
			ch := api.RenameChange{Kind: api.RenameReference, Object: jailObject(jl.Metadata.Project, jl.Metadata.Name), Detail: "spec.image: " + jl.Spec.Image + " -> " + ref}
			steps, err := s.jailRecordSteps(ctx, k, jl, nj, ch, func(b map[string]any) {
				im, _ := b["image"].(map[string]any)
				if im == nil {
					return
				}
				for _, f := range []string{"ref", "name"} {
					if v, ok := im[f].(string); ok {
						if r, ok := renameImageRef(v, name, to); ok {
							im[f] = r
						}
					}
				}
				if v, ok := im["dataset"].(string); ok {
					im["dataset"] = strings.Replace(v, "/images/"+name+"/", "/images/"+to+"/", 1)
				}
			})
			if err != nil {
				return nil, err
			}
			p.add(steps...)
			c := s.lcfg.ContainerDS(k)
			props, err := s.propSteps(ctx, c, imagegen.PropImage, name, to)
			if err != nil {
				return nil, err
			}
			p.add(props...)
			p.lock(jailLock(k), anchorLock(k))
			p.resources["jails"] = append(p.resources["jails"], "/api/v1/jails/"+jl.Metadata.Name)
		}
		if st, ok := s.stateFileStep(s.imageRunsPath(name), s.imageRunsPath(to), nil,
			api.RenameChange{Kind: api.RenameState, Object: "nightly upgrade runs of image " + name, Detail: path.Base(s.imageRunsPath(name)) + " -> " + path.Base(s.imageRunsPath(to))}); ok {
			p.add(st)
		}
		if users > 0 {
			p.warnings = append(p.warnings, fmt.Sprintf("backups taken before the rename name the image %q: a restore of one asks for an image of that name", name))
		}
		p.after = func(context.Context) {
			s.imgAuto.mu.Lock()
			if v, ok := s.imgAuto.mem[name]; ok {
				s.imgAuto.mem[to] = v
				delete(s.imgAuto.mem, name)
			}
			s.imgAuto.mu.Unlock()
		}
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// imagePoolSteps rename the image tree of one pool and the image property of its datasets and of the deleted
// generations parked for collection.
func (s *Service) imagePoolSteps(ctx context.Context, l imagegen.Layout, from, to string) ([]renameStep, error) {
	ds, nds := l.ImageDS(from), l.ImageDS(to)
	ok, err := s.d.ZFS.Exists(ctx, ds)
	if err != nil || !ok {
		return nil, err
	}
	if ok, _ := s.d.ZFS.Exists(ctx, nds); ok {
		return nil, api.Errorf(api.CodeAlreadyExists, "dataset %s exists", nds).WithHint("it belongs to no image JailOps knows; remove it or choose another name")
	}
	kids, err := s.d.ZFS.Descendants(ctx, ds)
	if err != nil {
		return nil, err
	}
	for _, k := range kids {
		if strings.HasPrefix(path.Base(k), "staging-") {
			return nil, api.Errorf(api.CodeBusy, "image %q is being built or received (%s)", from, k).WithHint("rename it when that finished")
		}
	}
	mb := l.MountBase + "/images/"
	out, err := s.datasetMoveSteps(ctx, ds, nds, mb+from, mb+to)
	if err != nil {
		return nil, err
	}
	props, err := s.propStepsMoved(ctx, ds, nds, imagegen.PropImage, from, to)
	if err != nil {
		return nil, err
	}
	out = append(out, props...)
	if ok, _ := s.d.ZFS.Exists(ctx, l.DeletedParent()); ok {
		parked, err := s.d.ZFS.Descendants(ctx, l.DeletedParent())
		if err != nil {
			return nil, err
		}
		for _, d := range parked {
			if v, _ := s.d.ZFS.Get(ctx, d, imagegen.PropImage); v == from {
				out = append(out, renameStep{Op: "zfs-set", From: d, Prop: imagegen.PropImage, OldValue: from, NewValue: to})
			}
		}
	}
	return out, nil
}

// propSteps set a property of a dataset and its descendants that holds from to to.
func (s *Service) propSteps(ctx context.Context, ds, prop, from, to string) ([]renameStep, error) {
	return s.propStepsMoved(ctx, ds, ds, prop, from, to)
}

// propStepsMoved is propSteps for a tree that is renamed from ds to nds before the steps run.
func (s *Service) propStepsMoved(ctx context.Context, ds, nds, prop, from, to string) ([]renameStep, error) {
	kids, err := s.d.ZFS.Descendants(ctx, ds)
	if err != nil {
		return nil, err
	}
	var out []renameStep
	for _, d := range append([]string{ds}, kids...) {
		v, err := s.d.ZFS.Get(ctx, d, prop)
		if err != nil {
			return nil, err
		}
		if v == from {
			out = append(out, renameStep{Op: "zfs-set", From: nds + strings.TrimPrefix(d, ds), Prop: prop, OldValue: from, NewValue: to})
		}
	}
	return out, nil
}

// renameImageRef rewrites an image reference (NAME, NAME@alias, NAME#gN) of the image from; ok is false for a
// reference to another image.
func renameImageRef(ref, from, to string) (string, bool) {
	r, err := validate.ParseImageRef(ref)
	if err != nil || r.Name != from {
		return ref, false
	}
	return to + strings.TrimPrefix(ref, from), true
}
