package service

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// RenameJail renames a stopped jail of the request's project: its datasets (the whole tree, volumes and snapshots
// with it) and their mountpoints, its records, its update history and the marks of its provisioning and shell
// setup, and the boot order of the jails that depend on it. A running jail is refused: the kernel knows a jail by
// its name, and its mounts, interfaces and anchor are set up under it.
func (s *Service) RenameJail(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := s.requireHost("jails"); err != nil {
		return api.Operation{}, nil, err
	}
	pr, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.Operation{}, nil, err
	}
	proj, to := pr.Meta.Name, o.NewName
	j := renameJob{kind: api.KindJail, noun: "jail", path: "/api/v1/jails", project: proj, from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		cur, err := s.jailSnapshot(key)
		if err != nil {
			return nil, notFound("jail", name)
		}
		if err := checkGeneration("jail", name, o.Expect, cur.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("jail", name, cur.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.JailName(to); err != nil {
			return nil, err
		}
		newKey, err := validate.QualifiedName(proj, to)
		if err != nil {
			return nil, err
		}
		if _, err := s.jailSnapshot(newKey); err == nil {
			return nil, api.Errorf(api.CodeAlreadyExists, "jail %q already exists", to)
		}
		s.quotaMu.Lock()
		_, creating := s.pending[newKey]
		s.quotaMu.Unlock()
		if creating {
			return nil, api.Errorf(api.CodeAlreadyExists, "jail %q is being created", to)
		}
		if err := s.jailIdle(ctx, key, name); err != nil {
			return nil, err
		}
		if err := s.noAppAccess(proj, name); err != nil {
			return nil, err
		}
		if err := s.noRuleNamesJail(proj, name, false); err != nil {
			return nil, err
		}
		st := s.lcfg.StorageOf(key)
		fromDS, fromMP := lifecycle.ContainerOn(st, proj, name)
		toDS, toMP := lifecycle.ContainerOn(st, proj, to)
		if ok, err := s.d.ZFS.Exists(ctx, toDS); err != nil {
			return nil, err
		} else if ok {
			return nil, api.Errorf(api.CodeAlreadyExists, "dataset %s exists", toDS).WithHint("it belongs to no jail JailOps knows; remove it or choose another name")
		}
		p := newRenamePlan()
		p.lock(jailLock(key), jailLock(newKey), anchorLock(key), anchorLock(newKey))
		p.resources["jails"] = []string{"/api/v1/jails/" + name, "/api/v1/jails/" + to}
		moves, err := s.datasetMoveSteps(ctx, fromDS, toDS, fromMP, toMP)
		if err != nil {
			return nil, err
		}
		p.add(moves...)
		// jailops:name on the datasets is informational, but it should not lie
		props, err := s.namePropSteps(ctx, fromDS, toDS, map[string]string{name: to, key: newKey})
		if err != nil {
			return nil, err
		}
		p.add(props...)
		nj := cloneJail(cur)
		nj.Metadata.Name = to
		recs, err := s.jailRecordStepsAt(ctx, fromMP, toMP, cur, nj, objectChange("jail", name, to), nil)
		if err != nil {
			return nil, err
		}
		p.add(recs...)
		// the jails of the project that start after it
		if err := s.rewriteJails(ctx, p, func(x string) bool { return x == proj }, func(j *api.Jail) []string {
			if j.Metadata.Name == name || !slices.Contains(j.Spec.Boot.Depends, name) {
				return nil
			}
			j.Spec.Boot.Depends = replaceAll(j.Spec.Boot.Depends, name, to)
			return []string{"spec.boot.depends: " + name + " -> " + to}
		}); err != nil {
			return nil, err
		}
		p.add(s.jailStateFileSteps(key, newKey, proj, name, to)...)
		switch cur.Spec.Hostname {
		case "":
			p.warnings = append(p.warnings, fmt.Sprintf("the jail has no hostname of its own: it is %q from its next start", to))
		case name:
			p.warnings = append(p.warnings, fmt.Sprintf("the hostname of the jail stays %q; `jailops set %s hostname=%s` changes it", name, to, to))
		}
		p.warnings = append(p.warnings, s.logSelectorWarnings(name)...)
		p.after = func(ctx context.Context) {
			s.moveKeyCaches(key, newKey)
			// what the old name rendered is rendered again under the new one at the next start
			_ = (&hooks{s: s}).Remove(ctx, key)
		}
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// jailIdle refuses to rename a jail that runs, is locked, or has work in progress (an installation, an exec
// session, an interrupted run in the journal).
func (s *Service) jailIdle(ctx context.Context, key, name string) error {
	if s.runningKeys(ctx)[key] {
		return api.Errorf(api.CodeBusy, "jail %q is running", name).
			WithHint("stop it first (jailops stop " + name + "); a jail is renamed while it is stopped")
	}
	s.mu.RLock()
	e := s.jails[key]
	locked := e != nil && len(e.locked) > 0
	s.mu.RUnlock()
	if locked {
		return api.Errorf(api.CodeLocked, "jail %q has locked volumes", name).WithHint("unlock its volumes first (jailops volume list shows them, jailops volume unlock NAME)")
	}
	s.execMu.Lock()
	busy := s.installing[key] || s.execN[key] > 0
	s.execMu.Unlock()
	if busy {
		return api.Errorf(api.CodeBusy, "jail %q has an installation or a session in progress", name)
	}
	recs, err := s.journal.List(ctx)
	if err != nil {
		return internal(err)
	}
	for _, r := range recs {
		if strings.HasSuffix(r.ID, "/"+key) {
			return api.Errorf(api.CodeBusy, "jail %q has an interrupted run (%s)", name, r.ID).WithHint("run `jailops doctor`")
		}
	}
	return nil
}

// noAppAccess refuses a jail that app access knows: an installed app with grants, or the source of a grant. The
// grants, their rule names and the database roles carry the name.
func (s *Service) noAppAccess(project, name string) error {
	hint := "deny the grants (jailops app deny), rename the jail, then allow them again"
	if s.accKind().p(project).exists(name) {
		return api.Errorf(api.CodeConflict, "jail %q has app access grants", name).WithHint(hint)
	}
	if o, err := s.polKind.p(project).get(apps.AccessPolicyName(name)); err == nil && o.Meta.ManagedBy == api.AppAccessManagedBy {
		return api.Errorf(api.CodeConflict, "jail %q has the app access policy %s", name, o.Meta.Name).WithHint(hint)
	}
	recs, err := s.accKind().listAll()
	if err != nil {
		return err
	}
	for _, r := range recs {
		for _, g := range r.Spec.Grants {
			if g.Kind == api.AccessSourceJail && r.Meta.Project == project && g.SourceName == name {
				return api.Errorf(api.CodeConflict, "jail %q may connect to app %s (project %s) through app access", name, r.Meta.Name, r.Meta.Project).WithHint(hint)
			}
		}
	}
	return nil
}

// noRuleNamesJail refuses a jail, to rename or to delete, that a firewall policy or an address set of its project names as
// jail:NAME: the reference would end up naming nothing, and the rule would stop matching.
func (s *Service) noRuleNamesJail(project, name string, deleting bool) error {
	hint := "change the rule or the member to the new name first (jailops firewall policy edit, address-set edit), "
	if deleting {
		hint = "remove that reference first (jailops firewall policy edit, address-set edit): a rule that names a jail that is gone matches nobody, and a jail made later under the name would take its place"
	}
	pols, err := s.polKind.p(project).list()
	if err != nil {
		return err
	}
	for _, o := range pols {
		for i, r := range o.Spec.Rules {
			if slices.Contains(r.From, "jail:"+name) || slices.Contains(r.To, "jail:"+name) {
				e := api.Errorf(api.CodeConflict, "jail %q is named by rule %d of firewall policy %s", name, i+1, o.Meta.Name)
				if o.Meta.ManagedBy == api.AppAccessManagedBy {
					return e.WithHint("it is the source of an app access grant: jailops app deny " + strings.TrimPrefix(o.Meta.Name, "app-") + " --from jail:" + name + " first")
				}
				return e.WithHint(hint)
			}
		}
	}
	sets, err := s.setKind.p(project).list()
	if err != nil {
		return err
	}
	for _, o := range sets {
		if slices.Contains(o.Spec.Members(), "jail:"+name) {
			return api.Errorf(api.CodeConflict, "jail %q is a member of address set %s", name, o.Meta.Name).WithHint(hint)
		}
	}
	return nil
}

// namePropSteps rewrites jailops:name on the datasets of a tree that carry one of the old names.
func (s *Service) namePropSteps(ctx context.Context, fromDS, toDS string, names map[string]string) ([]renameStep, error) {
	kids, err := s.d.ZFS.Descendants(ctx, fromDS)
	if err != nil {
		return nil, err
	}
	var out []renameStep
	for _, d := range append([]string{fromDS}, kids...) {
		v, err := s.d.ZFS.Get(ctx, d, lifecycle.PropName)
		if err != nil {
			return nil, err
		}
		nv, ok := names[v]
		if !ok || v == "" {
			continue
		}
		out = append(out, renameStep{Op: "zfs-set", From: toDS + strings.TrimPrefix(d, fromDS), Prop: lifecycle.PropName, OldValue: v, NewValue: nv})
	}
	return out, nil
}

// jailStateFileSteps move the files of the state directory a jail key names: the update history (whose records
// name the jail), the mark of its provisioning and of its shell setup.
func (s *Service) jailStateFileSteps(key, newKey, project, name, to string) []renameStep {
	var out []renameStep
	editHistory := func(b []byte) []byte {
		var recs []map[string]any
		if json.Unmarshal(b, &recs) != nil {
			return b
		}
		for _, r := range recs {
			if r["jail"] == name && (r["project"] == project || r["project"] == nil) {
				r["jail"] = to
			}
		}
		nb, err := json.Marshal(recs)
		if err != nil {
			return b
		}
		return nb
	}
	for _, f := range []struct {
		from, to, what string
		edit           func([]byte) []byte
	}{
		{s.historyPath(key), s.historyPath(newKey), "update history", editHistory},
		{s.provPath(key), s.provPath(newKey), "provisioning mark", nil},
		{s.shellPath(key), s.shellPath(newKey), "shell setup mark", nil},
	} {
		if st, ok := s.stateFileStep(f.from, f.to, f.edit, api.RenameChange{Kind: api.RenameState, Object: f.what + " of jail " + name,
			Detail: filepath.Base(f.from) + " -> " + filepath.Base(f.to)}); ok {
			out = append(out, st)
		}
	}
	return out
}

// moveKeyCaches moves what the service keeps in memory under a jail key to the new key.
func (s *Service) moveKeyCaches(key, newKey string) {
	s.prov.mu.Lock()
	if v, ok := s.prov.m[key]; ok {
		s.prov.m[newKey] = v
		delete(s.prov.m, key)
	}
	s.prov.mu.Unlock()
	s.shellM.mu.Lock()
	if v, ok := s.shellM.m[key]; ok {
		s.shellM.m[newKey] = v
		delete(s.shellM.m, key)
	}
	s.shellM.mu.Unlock()
	s.histMem.mu.Lock()
	if v, ok := s.histMem.m[key]; ok {
		s.histMem.m[newKey] = v
		delete(s.histMem.m, key)
	}
	s.histMem.mu.Unlock()
	s.upd.mu.Lock()
	if v, ok := s.upd.reports[key]; ok {
		s.upd.reports[newKey] = v
		delete(s.upd.reports, key)
	}
	if v, ok := s.upd.last[key]; ok {
		s.upd.last[newKey] = v
		delete(s.upd.last, key)
	}
	s.upd.mu.Unlock()
	s.mu.Lock()
	delete(s.status, key)
	s.mu.Unlock()
}

// logSelectorWarnings names the log sinks that select jails by the old name: a sink selects a name in every project,
// so a rename in one project does not change it.
func (s *Service) logSelectorWarnings(name string) []string {
	spec, _, err := s.logForwardSpec()
	if err != nil {
		return nil
	}
	var out []string
	for _, k := range spec.Sinks {
		if slices.Contains(k.Sources.Jails, name) || slices.Contains(k.Sources.ExcludeJails, name) {
			out = append(out, fmt.Sprintf("log sink %q selects jails named %q; it does not follow the rename", k.Name, name))
		}
	}
	return out
}
