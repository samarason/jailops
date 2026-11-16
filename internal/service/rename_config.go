package service

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// The renames of configuration objects: networks, address sets, firewall policies and profiles. Their references
// live in other state objects and in the records of jails; a network also names a PF anchor and the descriptions of
// its interfaces. The interfaces themselves keep their names: a live epair is never renamed.

// rewriteJails adds the steps that rewrite the jails edit changes. edit gets a copy of each jail (of the projects
// keep accepts, every project when keep is nil) and returns it changed with the details, or false to leave it.
func (s *Service) rewriteJails(ctx context.Context, p *renamePlan, keep func(project string) bool, edit func(j *api.Jail) []string) error {
	s.mu.RLock()
	keys := sortedKeys(s.jails)
	jails := make([]api.Jail, len(keys))
	for i, k := range keys {
		jails[i] = cloneJail(s.jails[k].jail)
	}
	s.mu.RUnlock()
	for i, k := range keys {
		j := jails[i]
		if keep != nil && !keep(j.Metadata.Project) {
			continue
		}
		nj := cloneJail(j)
		details := edit(&nj)
		if len(details) == 0 {
			continue
		}
		if err := refuseManagedRef("jail", jailDisplay(j.Metadata.Project, j.Metadata.Name), j.Metadata.ManagedBy); err != nil {
			return err
		}
		ch := api.RenameChange{Kind: api.RenameReference, Object: jailObject(j.Metadata.Project, j.Metadata.Name), Detail: strings.Join(details, "; ")}
		steps, err := s.jailRecordSteps(ctx, k, j, nj, ch, nil)
		if err != nil {
			return err
		}
		p.add(steps...)
		p.lock(jailLock(k))
		p.resources["jails"] = append(p.resources["jails"], "/api/v1/jails/"+j.Metadata.Name)
	}
	return nil
}

// refuseManagedRef refuses to rewrite an object that a repository or a hub defines: its next pass would write the
// old name back.
func refuseManagedRef(noun, name, managedBy string) error {
	if managedBy == "" || managedBy == api.AppAccessManagedBy {
		return nil
	}
	return api.Errorf(api.CodeForbidden, "%s %s refers to the name and is managed by %s", noun, name, managedBy).
		WithHint("change the name in the repository or on the hub that defines it")
}

func newRenamePlan() *renamePlan { return &renamePlan{resources: map[string][]string{}} }

// ---- networks ----

// RenameNetwork renames a network and rewrites the jails, projects, profiles and tunnels that name it, its PF
// anchor and the descriptions of its interfaces. A jail on it may run: nothing of the data path changes.
func (s *Service) RenameNetwork(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	if err := requireGlobal(ctx, "renaming a network"); err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindNetwork, noun: "network", path: "/api/v1/networks", from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		obj, err := s.netKind.getObj(name)
		if err != nil {
			return nil, notFound("network", name)
		}
		if err := checkGeneration("network", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("network", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := s.netKind.notTaken(to); err != nil {
			return nil, err
		}
		n, err := decodeObject[api.NetworkSpec](obj)
		if err != nil {
			return nil, err
		}
		p := newRenamePlan()
		p.lock(networkLock(name), networkLock(to))
		p.resources["networks"] = []string{"/api/v1/networks/" + name, "/api/v1/networks/" + to}
		st, err := stateStep(api.KindNetwork, obj, to, "", nil, objectChange("network", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		// the projects the network is granted to
		projs, err := s.projKind.list()
		if err != nil {
			return nil, err
		}
		for _, pr := range projs {
			spec := pr.Spec
			spec.Networks = slices.Clone(spec.Networks)
			hit := false
			for i := range spec.Networks {
				if spec.Networks[i].Network == name {
					spec.Networks[i].Network, hit = to, true
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
			st, err := stateStep(api.KindProject, po, pr.Meta.Name, "", spec,
				api.RenameChange{Kind: api.RenameReference, Object: "project " + pr.Meta.Name, Detail: "spec.networks: " + name + " -> " + to})
			if err != nil {
				return nil, err
			}
			p.add(st)
			p.lock(projectLock(pr.Meta.Name))
		}
		// profiles (of every project and the host) that attach an interface to it
		if err := s.rewriteProfiles(p, func(k, v string) (string, bool) {
			if nicNetworkKey(k) && v == name {
				return to, true
			}
			return v, false
		}); err != nil {
			return nil, err
		}
		// tunnels whose peers may reach it
		wgs, err := s.wgKind.list()
		if err != nil {
			return nil, err
		}
		for _, w := range wgs {
			if !slices.Contains(w.Spec.Networks, name) {
				continue
			}
			if err := refuseManagedRef("WireGuard tunnel", w.Meta.Name, w.Meta.ManagedBy); err != nil {
				return nil, err
			}
			spec := w.Spec
			spec.Networks = replaceAll(spec.Networks, name, to)
			wo, err := s.wgKind.getObj(w.Meta.Name)
			if err != nil {
				return nil, internal(err)
			}
			st, err := stateStep(api.KindWireGuard, wo, w.Meta.Name, "", spec,
				api.RenameChange{Kind: api.RenameReference, Object: "WireGuard tunnel " + w.Meta.Name, Detail: "spec.networks: " + name + " -> " + to})
			if err != nil {
				return nil, err
			}
			p.add(st)
			p.lock(wgLock(w.Meta.Name))
		}
		// the jails attached to it, running or not
		if err := s.rewriteJails(ctx, p, nil, func(j *api.Jail) []string {
			var d []string
			for i := range j.Spec.Network {
				if j.Spec.Network[i].Network == name {
					j.Spec.Network[i].Network = to
					d = append(d, fmt.Sprintf("spec.network[%d].network: %s -> %s", i, name, to))
				}
			}
			return d
		}); err != nil {
			return nil, err
		}
		// the PF anchor of the network: the same rules under the new name
		if s.d.PF != nil {
			if cur, err := s.d.PF.Read(ctx, render.NetAnchor(name)); err == nil && strings.TrimSpace(cur) != "" {
				rules, err := render.PFNet(to, n.Spec)
				if err != nil {
					return nil, err
				}
				p.add(renameStep{Op: "anchor", From: render.NetAnchor(name), To: render.NetAnchor(to), OldRules: cur, NewRules: rules,
					Change: api.RenameChange{Kind: api.RenameAnchor, Object: "PF anchor " + render.NetAnchor(name), Detail: "loaded as " + render.NetAnchor(to)}})
			}
		}
		descs, err := s.networkDescSteps(ctx, n, name, to)
		if err != nil {
			return nil, err
		}
		p.add(descs...)
		p.after = func(context.Context) {
			s.mu.Lock()
			if st, ok := s.netStat[name]; ok {
				s.netStat[to] = st
				delete(s.netStat, name)
			}
			s.mu.Unlock()
		}
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// nicNetworkKey reports whether a profile key holds the network of an interface: nic.<device>,
// nic.<device>.network, or the same in the older network. spelling.
func nicNetworkKey(k string) bool {
	if rest, ok := strings.CutPrefix(k, "network."); ok {
		k = "nic." + rest
	}
	rest, ok := strings.CutPrefix(k, "nic.")
	if !ok {
		return false
	}
	dev, field, has := strings.Cut(rest, ".")
	return dev != "" && (!has || field == "network")
}

// networkDescSteps rewrites the descriptions that carry the network's name: both ends of the epairs of the jails that
// run on it. An interface whose description is not the one JailOps wrote for
// the old name is left alone.
func (s *Service) networkDescSteps(ctx context.Context, n object[api.NetworkSpec], from, to string) ([]renameStep, error) {
	if s.d.Net == nil {
		return nil, nil
	}
	list, err := s.d.Net.List(ctx)
	if err != nil {
		return nil, err
	}
	desc := map[string]string{}
	for _, i := range list {
		desc[i.Name] = i.Description
	}
	var out []renameStep
	add := func(jail, iface, old, nu string) {
		out = append(out, renameStep{Op: "ifdesc", Jail: jail, Iface: iface, OldValue: old, NewValue: nu,
			Change: api.RenameChange{Kind: api.RenameInterface, Object: "interface " + ifaceWhere(jail, iface), Detail: fmt.Sprintf("description %q -> %q", old, nu)}})
	}
	// the epairs of running jails: the steps their start rendered say which interface carries which text
	running := s.runningKeys(ctx)
	s.mu.RLock()
	var jails []api.Jail
	for _, k := range sortedKeys(s.jails) {
		if running[k] {
			jails = append(jails, cloneJail(s.jails[k].jail))
		}
	}
	s.mu.RUnlock()
	for _, j := range jails {
		uses := false
		for _, a := range j.Spec.Network {
			uses = uses || a.Network == from
		}
		if !uses {
			continue
		}
		sets, err := s.allRefs(j.Metadata.Project)
		if err != nil {
			return nil, err
		}
		b, err := s.buildJail(ctx, j, sets)
		if err != nil {
			continue
		}
		key := jailKey(j)
		hostOld := render.JailIfaceDesc(j.Metadata.Project, j.Metadata.Name, from, true)
		jailOld := render.JailIfaceDesc(j.Metadata.Project, j.Metadata.Name, from, false)
		for _, steps := range b.desired.Attach {
			for _, st := range steps {
				if st.Op == render.OpSetDescription && st.Arg == hostOld && desc[st.Iface] == hostOld {
					add("", st.Iface, hostOld, render.JailIfaceDesc(j.Metadata.Project, j.Metadata.Name, to, true))
				}
			}
		}
		for _, st := range b.desired.JailSide {
			if st.Op != render.OpSetDescription || st.Arg != jailOld {
				continue
			}
			if got, ok := s.jailIfaceDesc(ctx, key, st.Iface); ok && got == jailOld {
				add(key, st.Iface, jailOld, render.JailIfaceDesc(j.Metadata.Project, j.Metadata.Name, to, false))
			}
		}
	}
	return out, nil
}

func ifaceWhere(jail, iface string) string {
	if jail == "" {
		return iface
	}
	return iface + " (in jail " + jail + ")"
}

// runningKeys are the keys of the jails that run.
func (s *Service) runningKeys(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	if s.d.Jails == nil {
		return out
	}
	l, err := s.d.Jails.List(ctx)
	if err != nil {
		return out
	}
	for _, x := range l {
		if !x.Dying {
			out[x.Name] = true
		}
	}
	return out
}

func replaceAll(l []string, from, to string) []string {
	out := slices.Clone(l)
	for i := range out {
		if out[i] == from {
			out[i] = to
		}
	}
	return out
}

// rewriteProfiles adds the steps that rewrite the configuration values of profiles (of every project and the
// host) that edit changes.
func (s *Service) rewriteProfiles(p *renamePlan, edit func(key, value string) (string, bool)) error {
	return s.rewriteProfilesIn(p, nil, edit)
}

func (s *Service) rewriteProfilesIn(p *renamePlan, keep func(project string) bool, edit func(key, value string) (string, bool)) error {
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
			v := spec.Config[k]
			if nv, ok := edit(k, v); ok {
				d = append(d, fmt.Sprintf("config %s: %s -> %s", k, v, nv))
				v = nv
			}
			cfg[k] = v
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

func profileObject(project, name string) string {
	if project == api.HostProfileProject {
		return "host profile " + name
	}
	return fmt.Sprintf("profile %s (project %s)", name, project)
}

// ---- address sets ----

// RenameAddressSet renames an address set of the request's project and rewrites the rules that name it (@name),
// the sets that include it and the grants of app access made from it. The set's PF table is renamed with it, so
// the connections that rules using it passed are cut once (their state labels change).
func (s *Service) RenameAddressSet(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	pr, err := s.access(ctx)
	if err != nil {
		return api.Operation{}, nil, err
	}
	proj, to := pr.Meta.Name, o.NewName
	j := renameJob{kind: api.KindAddressSet, noun: "address-set", path: "/api/v1/firewall/address-sets", project: proj, from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		ks := s.setKind.p(proj)
		obj, err := ks.getObj(name)
		if err != nil {
			return nil, notFound("address-set", name)
		}
		if err := checkGeneration("address-set", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("address set", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.SetName("name", to); err != nil {
			return nil, err
		}
		if err := ks.notTaken(to); err != nil {
			return nil, err
		}
		p := newRenamePlan()
		p.lock(projectLock(proj))
		p.resources["address-sets"] = []string{"/api/v1/firewall/address-sets/" + name}
		st, err := stateStep(api.KindAddressSet, obj, to, proj, nil, objectChange("address set", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		sets, err := ks.list()
		if err != nil {
			return nil, err
		}
		for _, x := range sets {
			if x.Meta.Name == name || !slices.Contains(x.Spec.Members(), "set:"+name) {
				continue
			}
			spec := x.Spec
			// a member set:NAME of another set is this set
			spec.Addresses = slices.Clone(spec.Addresses)
			for i := range spec.Addresses {
				if spec.Addresses[i].Address == "set:"+name {
					spec.Addresses[i].Address = "set:" + to
				}
			}
			detail := "spec.addresses: set:" + name + " -> set:" + to
			xo, err := ks.getObj(x.Meta.Name)
			if err != nil {
				return nil, internal(err)
			}
			st, err := stateStep(api.KindAddressSet, xo, x.Meta.Name, proj, spec,
				api.RenameChange{Kind: api.RenameReference, Object: "address set " + x.Meta.Name, Detail: detail})
			if err != nil {
				return nil, err
			}
			p.add(st)
		}
		// app access grants made from the set
		recs, err := s.accKind().p(proj).list()
		if err != nil {
			return nil, err
		}
		granted := map[string]bool{} // the managed policies whose rule names follow the source
		for _, r := range recs {
			spec := r.Spec
			spec.Grants = slices.Clone(spec.Grants)
			hit := false
			for i := range spec.Grants {
				g := &spec.Grants[i]
				if g.Kind != api.AccessSourceSet || g.SourceName != name {
					continue
				}
				hit = true
				g.Source, g.SourceName, g.From = "set:"+to, to, replaceAll(g.From, "set:"+name, "set:"+to)
			}
			if !hit {
				continue
			}
			ro, err := s.accKind().p(proj).getObj(r.Meta.Name)
			if err != nil {
				return nil, internal(err)
			}
			st, err := stateStep(api.KindAppAccess, ro, r.Meta.Name, proj, spec,
				api.RenameChange{Kind: api.RenameReference, Object: "app access of jail " + r.Meta.Name, Detail: "source set:" + name + " -> set:" + to})
			if err != nil {
				return nil, err
			}
			p.add(st)
			granted[apps.AccessPolicyName(r.Meta.Name)] = true
		}
		pols, err := s.polKind.p(proj).list()
		if err != nil {
			return nil, err
		}
		for _, pol := range pols {
			if strings.Contains(pol.Spec.Raw, validate.SetTable(name)) {
				return nil, api.Errorf(api.CodeConflict, "the raw PF fragment of firewall policy %q mentions the table of address set %q", pol.Meta.Name, name).
					WithHint("a raw fragment is not rewritten: change it to the new table name <" + validate.SetTable(to) + "> after the rename, or remove it first")
			}
			spec := pol.Spec
			spec.Rules = slices.Clone(pol.Spec.Rules)
			var d []string
			for i := range spec.Rules {
				r := &spec.Rules[i]
				nf, nt := replaceAll(r.From, "set:"+name, "set:"+to), replaceAll(r.To, "set:"+name, "set:"+to)
				if slices.Equal(nf, r.From) && slices.Equal(nt, r.To) {
					continue
				}
				r.From, r.To = nf, nt
				if granted[pol.Meta.Name] {
					for _, proto := range []string{"tcp", "udp"} {
						if r.Name == apps.AccessRuleName("set:"+name, proto) {
							r.Name = apps.AccessRuleName("set:"+to, proto)
						}
					}
				}
				d = append(d, fmt.Sprintf("rule %d: set:%s -> set:%s", i+1, name, to))
			}
			if len(d) == 0 {
				continue
			}
			po, err := s.polKind.p(proj).getObj(pol.Meta.Name)
			if err != nil {
				return nil, internal(err)
			}
			st, err := stateStep(api.KindFirewallPolicy, po, pol.Meta.Name, proj, spec,
				api.RenameChange{Kind: api.RenameReference, Object: "firewall policy " + pol.Meta.Name, Detail: strings.Join(d, "; ")})
			if err != nil {
				return nil, err
			}
			p.add(st)
		}
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// ---- firewall policies ----

// RenamePolicy renames a firewall policy of the request's project and rewrites the jails, the project's mandatory
// policy and the project's profiles that name it.
func (s *Service) RenamePolicy(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	pr, err := s.access(ctx)
	if err != nil {
		return api.Operation{}, nil, err
	}
	proj, to := pr.Meta.Name, o.NewName
	j := renameJob{kind: api.KindFirewallPolicy, noun: "firewall-policy", path: "/api/v1/firewall/policies", project: proj, from: name, to: to}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		pr, err := s.projKind.get(proj)
		if err != nil {
			return nil, notFound("project", proj)
		}
		ks := s.polKind.p(proj)
		obj, err := ks.getObj(name)
		if err != nil {
			return nil, notFound("firewall-policy", name)
		}
		if err := checkGeneration("firewall-policy", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("firewall policy", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := ks.notTaken(to); err != nil {
			return nil, err
		}
		if j, ok := strings.CutPrefix(to, "app-"); ok {
			if key, err := validate.QualifiedName(proj, j); err == nil {
				if _, err := s.jailSnapshot(key); err == nil {
					return nil, invalid("%q is the name app access gives the policy of jail %s", to, j).WithHint("choose another name")
				}
			}
		}
		// a host profile names a policy of whichever project its jail is in: one project's rename cannot rewrite it
		if hp, err := s.profKind.p(api.HostProfileProject).list(); err == nil {
			for _, x := range hp {
				if slices.Contains(configList(x.Spec.Config["firewall.policies"]), name) {
					return nil, api.Errorf(api.CodeConflict, "host profile %q names firewall policy %q for the jails of every project", x.Meta.Name, name).
						WithHint("a global administrator changes the host profile; then rename the policy")
				}
			}
		}
		p := newRenamePlan()
		p.lock(projectLock(proj))
		p.resources["firewall-policies"] = []string{"/api/v1/firewall/policies/" + name}
		st, err := stateStep(api.KindFirewallPolicy, obj, to, proj, nil, objectChange("firewall policy", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		if slices.Contains(pr.Spec.FirewallPolicies, name) {
			if !ActorFrom(ctx).Global {
				return nil, api.Errorf(api.CodeForbidden, "firewall policy %q is a mandatory policy of project %q; a global administrator renames it", name, proj)
			}
			if err := refuseManagedRef("project", proj, pr.Meta.ManagedBy); err != nil {
				return nil, err
			}
			spec := pr.Spec
			spec.FirewallPolicies = replaceAll(spec.FirewallPolicies, name, to)
			po, err := s.projKind.getObj(proj)
			if err != nil {
				return nil, internal(err)
			}
			st, err := stateStep(api.KindProject, po, proj, "", spec,
				api.RenameChange{Kind: api.RenameReference, Object: "project " + proj, Detail: "spec.firewall_policies (mandatory policy): " + name + " -> " + to})
			if err != nil {
				return nil, err
			}
			p.add(st)
		}
		if err := s.rewriteProfilesIn(p, func(x string) bool { return x == proj }, func(k, v string) (string, bool) {
			if k == "firewall.policies" {
				if l := configList(v); slices.Contains(l, name) {
					return strings.Join(replaceAll(l, name, to), ","), true
				}
			}
			return v, false
		}); err != nil {
			return nil, err
		}
		if err := s.rewriteJails(ctx, p, func(x string) bool { return x == proj }, func(j *api.Jail) []string {
			if !slices.Contains(j.Spec.Firewall.Policies, name) {
				return nil
			}
			j.Spec.Firewall.Policies = replaceAll(j.Spec.Firewall.Policies, name, to)
			return []string{"spec.firewall.policies: " + name + " -> " + to}
		}); err != nil {
			return nil, err
		}
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// ---- profiles ----

// RenameProfile renames a profile of the request's project (or a host profile, with the project "host") and
// rewrites the jails that apply it.
func (s *Service) RenameProfile(ctx context.Context, name string, o RenameOptions) (api.Operation, *api.RenameResult, error) {
	proj, err := s.profileProject(ctx, true)
	if err != nil {
		return api.Operation{}, nil, err
	}
	to := o.NewName
	j := renameJob{kind: api.KindProfile, noun: "profile", path: "/api/v1/profiles", project: proj, from: name, to: to}
	if proj == api.HostProfileProject {
		j.project = "" // the operation of a host profile belongs to no project: only global identities see it
	}
	j.plan = func(ctx context.Context) (*renamePlan, error) {
		ks := s.profKind.p(proj)
		obj, err := ks.getObj(name)
		if err != nil {
			return nil, notFound("profile", name)
		}
		if err := checkGeneration("profile", name, o.Expect, obj.Metadata.Generation); err != nil {
			return nil, err
		}
		if err := refuseManaged("profile", name, obj.Metadata.ManagedBy); err != nil {
			return nil, err
		}
		if err := validate.Name("name", to); err != nil {
			return nil, err
		}
		if err := ks.notTaken(to); err != nil {
			return nil, err
		}
		host := proj == api.HostProfileProject
		if !host {
			if err := s.noShadow(proj, to); err != nil {
				return nil, err
			}
		} else {
			// a project profile of the new name would be resolved first in its project
			all, err := s.profKind.listAll()
			if err != nil {
				return nil, err
			}
			for _, x := range all {
				if x.Meta.Project != api.HostProfileProject && x.Meta.Name == to {
					return nil, api.Errorf(api.CodeAlreadyExists, "project %s has a profile %q, which its jails would apply instead", x.Meta.Project, to).
						WithHint("choose another name")
				}
			}
		}
		p := newRenamePlan()
		p.lock(projectLock(proj))
		p.resources["profiles"] = []string{"/api/v1/profiles/" + name}
		st, err := stateStep(api.KindProfile, obj, to, proj, nil, objectChange("profile", name, to))
		if err != nil {
			return nil, err
		}
		p.add(st)
		keep := func(x string) bool { return x == proj }
		if host {
			// a jail applies the host profile unless its project has a profile of the same name
			keep = func(x string) bool { return !s.profKind.p(x).exists(name) }
		}
		if err := s.rewriteJails(ctx, p, keep, func(j *api.Jail) []string {
			if !slices.Contains(j.Spec.Profiles, name) {
				return nil
			}
			j.Spec.Profiles = replaceAll(j.Spec.Profiles, name, to)
			return []string{"spec.profiles: " + name + " -> " + to}
		}); err != nil {
			return nil, err
		}
		return p, nil
	}
	return s.runRename(ctx, j, o.DryRun)
}

// configList splits the value of a list key of a profile, the way the key registry does: on commas, without blanks.
func configList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
