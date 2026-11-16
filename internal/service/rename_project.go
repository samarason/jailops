package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// RenameProject renames a project whose jails are stopped: the project and every object of it (firewall policies,
// address sets, backup policies, profiles, app access), its datasets on every storage with the mountpoints of its
// jails, the records and state files of its jails, its PF anchor, its provisioning files, the project lists of
// users, tokens, trust tokens and certificates, and the log sinks that select it.
func (s *Service) RenameProject(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := requireGlobal(ctx, "renaming a project"); err != nil {
		return api.Operation{}, nil, err
	}
	if err := s.requireHost("projects"); err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindProject, noun: "project", path: "/api/v1/projects", from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		obj, err := s.projKind.getObj(name)
		if err != nil {
			return nil, notFound("project", name)
		}
		pr, err := decodeObject[api.ProjectSpec](obj)
		if err != nil {
			return nil, err
		}
		if err := checkGeneration("project", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("project", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if len(pr.Spec.Hosts) > 0 {
			return nil, api.Errorf(api.CodeUnsupported, "project %q is a fleet project spanning hosts %s", name, strings.Join(pr.Spec.Hosts, ", ")).
				WithHint("a fleet project keeps its name on every host; create a new one and move the jails")
		}
		if err := validate.ProjectName(to); err != nil {
			return nil, err
		}
		if to == api.HostProfileProject {
			return nil, invalid("%q is reserved", to)
		}
		if err := s.projKind.notTaken(to); err != nil {
			return nil, err
		}
		s.quotaMu.Lock()
		creating := false
		for _, pj := range s.pending {
			creating = creating || pj.project == name
		}
		s.quotaMu.Unlock()
		if creating {
			return nil, api.Errorf(api.CodeBusy, "project %q has a jail being created", name)
		}
		p := newRenamePlan()
		p.lock(projectLock(name), projectLock(to))
		p.resources["projects"] = []string{"/api/v1/projects/" + name, "/api/v1/projects/" + to}
		st, err := stateStep(api.KindProject, obj, to, "", nil, objectChange("project", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		if err := s.projectObjectSteps(p, name, to); err != nil {
			return nil, err
		}
		jails := s.projectJails(name)
		for _, jl := range jails {
			key := jailKey(jl)
			newKey, err := validate.QualifiedName(to, jl.Metadata.Name)
			if err != nil {
				return nil, invalid("jail %q would get the key %s_%s: %v", jl.Metadata.Name, to, jl.Metadata.Name, err).WithHint("choose a shorter name")
			}
			if err := refuseManagedRef("jail", jl.Metadata.Name, jl.Metadata.ManagedBy); err != nil {
				return nil, err
			}
			if err := s.jailIdle(ctx, key, jl.Metadata.Name); err != nil {
				return nil, err
			}
			p.lock(jailLock(key), jailLock(newKey), anchorLock(key), anchorLock(newKey))
		}
		// the datasets, storage by storage: the project dataset holds the jails of the project there
		for _, si := range s.storageList() {
			ls := si.lifecycle()
			fromDS, toDS := lifecycle.ProjectDS(ls, name), lifecycle.ProjectDS(ls, to)
			ok, err := s.d.ZFS.Exists(ctx, fromDS)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if ok, _ := s.d.ZFS.Exists(ctx, toDS); ok {
				return nil, api.Errorf(api.CodeAlreadyExists, "dataset %s exists", toDS).WithHint("it belongs to no project JailOps knows; remove it or choose another name")
			}
			mb := path.Join(ls.MountBase, "projects")
			moves, err := s.datasetMoveSteps(ctx, fromDS, toDS, mb+"/"+name, mb+"/"+to)
			if err != nil {
				return nil, err
			}
			p.add(moves...)
			props, err := s.propStepsMoved(ctx, fromDS, toDS, lifecycle.PropProject, name, to)
			if err != nil {
				return nil, err
			}
			p.add(props...)
		}
		for _, jl := range jails {
			key := jailKey(jl)
			newKey, _ := validate.QualifiedName(to, jl.Metadata.Name)
			ls := s.lcfg.StorageOf(key)
			_, fromMP := lifecycle.ContainerOn(ls, name, jl.Metadata.Name)
			_, toMP := lifecycle.ContainerOn(ls, to, jl.Metadata.Name)
			nj := cloneJail(jl)
			nj.Metadata.Project = to
			recs, err := s.jailRecordStepsAt(ctx, fromMP, toMP, jl, nj,
				api.RenameChange{Kind: api.RenameReference, Object: jailObject(name, jl.Metadata.Name), Detail: "metadata.project: " + name + " -> " + to}, nil)
			if err != nil {
				return nil, err
			}
			p.add(recs...)
			p.add(s.jailStateFileSteps(key, newKey, name, jl.Metadata.Name, jl.Metadata.Name)...)
			p.resources["jails"] = append(p.resources["jails"], "/api/v1/jails/"+jl.Metadata.Name)
		}
		// histories: the records of the project's jails name the project too
		for i := range p.steps {
			if p.steps[i].Op == "state-file" && strings.Contains(p.steps[i].From, "/updates/") {
				p.steps[i].New = renameHistoryProject(p.steps[i].New, name, to)
			}
		}
		if s.d.PF != nil {
			if cur, err := s.d.PF.Read(ctx, render.ProjectAnchor(name)); err == nil && strings.TrimSpace(cur) != "" {
				p.add(renameStep{Op: "anchor", From: render.ProjectAnchor(name), To: render.ProjectAnchor(to), OldRules: cur, NewRules: render.ProjectAnchorRules(),
					Change: api.RenameChange{Kind: api.RenameAnchor, Object: "PF anchor " + render.ProjectAnchor(name), Detail: "loaded as " + render.ProjectAnchor(to)}})
			}
		}
		if s.d.StateDir != "" || s.d.ProjectFilesDir != "" {
			from, dst := s.projectFilesDir(name), s.projectFilesDir(to)
			if _, err := os.Stat(from); err == nil {
				if _, err := os.Stat(dst); err == nil {
					return nil, api.Errorf(api.CodeAlreadyExists, "%s exists", dst).WithHint("remove the provisioning files left by an earlier project of that name")
				}
				p.add(renameStep{Op: "dir", From: from, To: dst,
					Change: api.RenameChange{Kind: api.RenameFile, Object: "provisioning files of project " + name, Detail: from + " -> " + dst}})
			}
		}
		refs, err := s.d.DB.FindProjectRefs(ctx, name)
		if err != nil {
			return nil, internal(err)
		}
		if refs.Count() > 0 {
			p.add(renameStep{Op: "identities", From: name, To: to, Refs: &refs,
				Change: api.RenameChange{Kind: api.RenameReference, Object: "identities", Detail: fmt.Sprintf("%d users, %d tokens and %d trust tokens: projects %s -> %s", len(refs.Users), len(refs.Tokens), len(refs.TrustTokens), name, to)}})
		}
		if err := s.projectRefSteps(p, name, to); err != nil {
			return nil, err
		}
		p.warnings = append(p.warnings, "the audit log, the operations and the backups made so far keep the old project name")
		for _, k := range s.d.LogForward {
			if slices.Contains(k.Sources.Projects, name) {
				p.warnings = append(p.warnings, fmt.Sprintf("log sink %q of jailopsd.yaml selects project %q; change the file", k.Name, name))
			}
		}
		p.after = func(ctx context.Context) {
			for _, jl := range jails {
				key := jailKey(jl)
				newKey, _ := validate.QualifiedName(to, jl.Metadata.Name)
				s.moveKeyCaches(key, newKey)
				_ = (&hooks{s: s}).Remove(ctx, key)
			}
			s.credGen.Add(1) // the scopes of identities changed
			s.FleetKick()
		}
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// projectObjectSteps move the objects that live in a project to its new name.
func (s *Service) projectObjectSteps(p *renamePlan, from, to string) error {
	for _, k := range []struct {
		kind api.Kind
		noun string
	}{{api.KindFirewallPolicy, "firewall policy"}, {api.KindAddressSet, "address set"}, {api.KindBackupPolicy, "backup policy"},
		{api.KindProfile, "profile"}, {api.KindVolume, "volume"}, {api.KindAppAccess, "app access of jail"}} {
		objs, err := s.d.State.ListIn(k.kind, from, "")
		if err != nil {
			return internal(err)
		}
		for _, o := range objs {
			if err := refuseManagedRef(k.noun, o.Metadata.Name, o.Metadata.ManagedBy); err != nil {
				return err
			}
			st, err := stateStep(k.kind, o, o.Metadata.Name, to, nil,
				api.RenameChange{Kind: api.RenameReference, Object: k.noun + " " + o.Metadata.Name, Detail: "moved to project " + to})
			if err != nil {
				return err
			}
			p.add(st)
		}
	}
	return nil
}

// projectRefSteps rewrite the host-level objects that name the project: certificates, the stored log sinks and the
// label of the networks made for it.
func (s *Service) projectRefSteps(p *renamePlan, from, to string) error {
	certs, err := s.d.State.List(api.KindCertificate, "")
	if err != nil {
		return internal(err)
	}
	for _, o := range certs {
		var spec api.CertificateSpec
		if json.Unmarshal(o.Spec, &spec) != nil || !slices.Contains(spec.Projects, from) {
			continue
		}
		spec.Projects = replaceAll(spec.Projects, from, to)
		st, err := stateStep(api.KindCertificate, o, o.Metadata.Name, o.Metadata.Project, spec,
			api.RenameChange{Kind: api.RenameReference, Object: "certificate " + o.Metadata.Name, Detail: "projects: " + from + " -> " + to})
		if err != nil {
			return err
		}
		p.add(st)
	}
	if fo, err := s.fwdKind.getObj(logForwardName); err == nil {
		var spec api.LogForwardSpec
		if err := json.Unmarshal(fo.Spec, &spec); err == nil {
			hit := false
			for i := range spec.Sinks {
				if slices.Contains(spec.Sinks[i].Sources.Projects, from) {
					spec.Sinks[i].Sources.Projects, hit = replaceAll(spec.Sinks[i].Sources.Projects, from, to), true
				}
			}
			if hit {
				st, err := stateStep(api.KindLogForward, fo, fo.Metadata.Name, fo.Metadata.Project, spec,
					api.RenameChange{Kind: api.RenameReference, Object: "log forwarding", Detail: "sources.projects: " + from + " -> " + to})
				if err != nil {
					return err
				}
				p.add(st)
				p.after = chainAfter(p.after, func(context.Context) {
					if spec, o, err := s.logForwardSpec(); err == nil && o != nil {
						s.fwd.ApplyFrom(spec.Sinks, true)
					}
				})
			}
		}
	}
	nets, err := s.d.State.List(api.KindNetwork, "")
	if err != nil {
		return internal(err)
	}
	for _, o := range nets {
		if o.Metadata.Labels[labelProject] != from {
			continue
		}
		st, err := stateStep(api.KindNetwork, o, o.Metadata.Name, o.Metadata.Project, nil,
			api.RenameChange{Kind: api.RenameReference, Object: "network " + o.Metadata.Name, Detail: "label " + labelProject + "=" + to})
		if err != nil {
			return err
		}
		labels := map[string]string{}
		for k, v := range o.Metadata.Labels {
			labels[k] = v
		}
		labels[labelProject] = to
		st.Obj.After.Labels = labels
		p.add(st)
	}
	return nil
}

func chainAfter(a, b func(context.Context)) func(context.Context) {
	return func(ctx context.Context) {
		if a != nil {
			a(ctx)
		}
		b(ctx)
	}
}

// renameHistoryProject rewrites the project of the update records of a history file.
func renameHistoryProject(b []byte, from, to string) []byte {
	var recs []map[string]any
	if json.Unmarshal(b, &recs) != nil {
		return b
	}
	for _, r := range recs {
		if r["project"] == from {
			r["project"] = to
		}
	}
	nb, err := json.Marshal(recs)
	if err != nil {
		return b
	}
	return nb
}

// renameDir moves a directory of the state directory, or back.
func renameDir(from, to string) error {
	if _, err := os.Stat(from); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(to); err == nil {
			return nil // done before
		}
		return nil
	}
	if err := os.MkdirAll(path.Dir(to), 0o750); err != nil {
		return err
	}
	return os.Rename(from, to)
}

// replaceProject is the identities step: the project lists of users and tokens.
func (s *Service) replaceProject(ctx context.Context, refs store.ProjectRefs, from, to string) error {
	if err := s.d.DB.ReplaceProject(ctx, refs, from, to); err != nil {
		return internal(err)
	}
	s.credGen.Add(1)
	return nil
}

// labelProject is the label of a network made for a project (new_network).
const labelProject = "jailops.project"
