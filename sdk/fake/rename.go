package fake

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// The renames (extension "rename"): the object and the references the fake holds (projects, jails, policies,
// profiles, tunnels, tokens) change in one operation; a dry run answers the plan at once. The checks are the
// daemon's: the name rule, a name in use, a managed object, a running jail.

// renamer is what one kind adds to the generic rename.
type renamer struct {
	noun string
	// check refuses an object (s.mu held).
	check func(rc *reqInfo, from string) *api.Error
	// refs returns the references of the object and, with apply, rewrites them (s.mu held).
	refs func(rc *reqInfo, from, to string, apply bool) []api.RenameChange
}

func (s *Server) registerRenames(m muxer) {
	m("POST /api/v1/networks/{name}/rename", renameHandler(s, s.networks, renamer{noun: "network", refs: s.networkRefs}))
	m("POST /api/v1/firewall/address-sets/{name}/rename", renameHandler(s, s.addrsets, renamer{noun: "address set", refs: s.setRefs}))
	m("POST /api/v1/firewall/policies/{name}/rename", renameHandler(s, s.policies, renamer{noun: "firewall policy", refs: s.policyRefs}))
	m("POST /api/v1/profiles/{name}/rename", renameHandler(s, s.profiles, renamer{noun: "profile", refs: s.profileRefs}))
	m("POST /api/v1/jails/{name}/rename", renameHandler(s, s.jails, renamer{noun: "jail", check: s.jailStopped, refs: s.jailRefs}))
	m("POST /api/v1/images/{name}/rename", renameHandler(s, s.images, renamer{noun: "image", refs: s.imageRefs}))
	m("POST /api/v1/projects/{name}/rename", renameHandler(s, s.projects, renamer{noun: "project", check: s.projectStopped, refs: s.projectRefs}))
	m("POST /api/v1/backup-targets/{name}/rename", renameHandler(s, s.targets, renamer{noun: "backup target", refs: s.targetRefs}))
	m("POST /api/v1/backup-policies/{name}/rename", renameHandler(s, s.bpolicies, renamer{noun: "backup policy", refs: noRefs}))
	m("POST /api/v1/certificates/{name}/rename", renameHandler(s, s.certs, renamer{noun: "certificate", refs: noRefs}))
	m("POST /api/v1/storage/{name}/rename", renameHandler(s, s.storages, renamer{noun: "storage", check: s.storageRenamable, refs: s.storageRefs}))
	m("POST /api/v1/wireguard/{name}/rename", renameHandler(s, s.wireguard, renamer{noun: "WireGuard tunnel", refs: noRefs}))
	m("POST /api/v1/users/{name}/rename", renameHandler(s, s.users, renamer{noun: "user", refs: noRefs}))
	m("POST /api/v1/volumes/{name}/rename", renameHandler(s, s.volumes, renamer{noun: "volume", check: s.volumeStopped, refs: s.volumeRefs}))
}

func renameHandler[T any](s *Server, k *kind[T], rn renamer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, e := decode[api.Rename](r)
		if e != nil {
			writeErr(w, e)
			return
		}
		from, to := r.PathValue("name"), req.NewName
		rc := s.info(r)
		s.mu.Lock()
		rp := func() reply {
			key, obj := k.find(r, from)
			if obj == nil {
				return reply{err: notFound(k.action, from)}
			}
			m := k.meta(obj)
			if !ifMatchOK(r, m.Generation) {
				return reply{err: api.Errorf(api.CodeConflict, "%s %q changed: current generation is %d", k.action, from, m.Generation).
					WithHint("read it again and repeat the rename")}
			}
			if k.guard != nil {
				if e := k.guard(rc, obj, "update"); e != nil {
					return reply{err: e}
				}
			}
			switch {
			case to == from:
				return reply{err: api.Errorf(api.CodeInvalid, "the new name is the old name")}
			case !renameNameOK(k.action, to):
				return reply{err: api.Errorf(api.CodeInvalid, "invalid name %q", to).WithHint("the name rule of the kind's create applies")}
			case k.items[k.keyIn(m.Project, to)] != nil:
				return reply{err: api.Errorf(api.CodeAlreadyExists, "%s %q already exists", k.action, to)}
			case m.ManagedBy != "":
				return reply{err: api.Errorf(api.CodeForbidden, "%s %q is managed by %s", rn.noun, from, m.ManagedBy).
					WithHint("rename it where it is defined")}
			}
			if rn.check != nil {
				if e := rn.check(rc, from); e != nil {
					return reply{err: e}
				}
			}
			project := ""
			if k.scoped {
				project = m.Project
			}
			res := api.RenameResult{Kind: kindOf(k.action), Project: project, From: from, To: to, Counts: map[string]int{},
				Changes: []api.RenameChange{{Kind: api.RenameObject, Object: rn.noun + " " + from, Detail: "renamed to " + to}}}
			res.Changes = append(res.Changes, rn.refs(rc, from, to, false)...)
			for _, c := range res.Changes {
				res.Counts[c.Kind]++
				res.Steps = append(res.Steps, fmt.Sprintf("%02d %s: %s", len(res.Steps)+1, c.Object, c.Detail))
			}
			if req.DryRun {
				res.DryRun = true
				return reply{status: http.StatusOK, meta: res}
			}
			op := s.startOp(project, k.plural+".rename", fmt.Sprintf("rename %s %s to %s", k.action, from, to),
				map[string][]string{k.plural: {k.base + "/" + from, k.base + "/" + to}}, func() (any, *api.Error) {
					obj := k.items[key]
					if obj == nil {
						return nil, notFound(k.action, from)
					}
					delete(k.items, key)
					m := k.meta(obj)
					m.Name, m.Generation, m.UpdatedAt = to, m.Generation+1, s.now()
					k.items[k.keyIn(m.Project, to)] = obj
					rn.refs(rc, from, to, true)
					s.emitIn(project, k.action+"-renamed", k.base+"/"+to)
					return res, nil
				})
			return reply{op: &op}
		}()
		s.mu.Unlock()
		s.respond(w, rp)
	}
}

// renameNameOK is the name rule of a kind: a set name is a PF table name.
func renameNameOK(action, n string) bool {
	max, extra := 63, byte('-')
	if action == "address-set" {
		max, extra = 24, '_'
	}
	if n == "" || len(n) > max || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == extra) {
			return false
		}
	}
	return true
}

func kindOf(action string) api.Kind {
	return map[string]api.Kind{"network": api.KindNetwork, "address-set": api.KindAddressSet, "firewall-policy": api.KindFirewallPolicy,
		"profile": api.KindProfile, "jail": api.KindJail, "image": api.KindImage, "project": api.KindProject,
		"backup-target": api.KindBackupTarget, "backup-policy": api.KindBackupPolicy, "certificate": api.KindCertificate,
		"storage": api.KindStorage, "volume": api.KindVolume, "user": api.KindUser, "wireguard": api.KindWireGuard}[action]
}

func ref(object, detail string) api.RenameChange {
	return api.RenameChange{Kind: api.RenameReference, Object: object, Detail: detail}
}

func (s *Server) networkRefs(_ *reqInfo, from, to string, apply bool) []api.RenameChange {
	var out []api.RenameChange
	for _, n := range sortedNames(s.projects.items) {
		p := s.projects.items[n]
		for i := range p.Spec.Networks {
			if p.Spec.Networks[i].Network == from {
				out = append(out, ref("project "+p.Metadata.Name, "spec.networks: "+from+" -> "+to))
				if apply {
					p.Spec.Networks[i].Network = to
				}
			}
		}
	}
	for _, k := range sortedNames(s.jails.items) {
		j := s.jails.items[k]
		for i := range j.Spec.Network {
			if j.Spec.Network[i].Network == from {
				out = append(out, ref(jailObj(j), fmt.Sprintf("spec.network[%d].network: %s -> %s", i, from, to)))
				if apply {
					j.Spec.Network[i].Network = to
				}
			}
		}
	}
	for _, n := range sortedNames(s.wireguard.items) {
		w := s.wireguard.items[n]
		if slices.Contains(w.Spec.Networks, from) {
			out = append(out, ref("WireGuard tunnel "+n, "spec.networks: "+from+" -> "+to))
			if apply {
				w.Spec.Networks = replaced(w.Spec.Networks, from, to)
			}
		}
	}
	return out
}

func (s *Server) setRefs(rc *reqInfo, from, to string, apply bool) []api.RenameChange {
	var out []api.RenameChange
	for _, n := range sortedNames(s.policies.items) {
		p := s.policies.items[n]
		if p.Metadata.Project != rc.project {
			continue
		}
		for i := range p.Spec.Rules {
			r := &p.Spec.Rules[i]
			if slices.Contains(r.From, "set:"+from) || slices.Contains(r.To, "set:"+from) {
				out = append(out, ref("firewall policy "+p.Metadata.Name, fmt.Sprintf("rule %d: set:%s -> set:%s", i+1, from, to)))
				if apply {
					r.From, r.To = replaced(r.From, "set:"+from, "set:"+to), replaced(r.To, "set:"+from, "set:"+to)
				}
			}
		}
	}
	for _, n := range sortedNames(s.addrsets.items) {
		x := s.addrsets.items[n]
		if x.Metadata.Project == rc.project && slices.Contains(x.Spec.Members(), "set:"+from) {
			out = append(out, ref("address set "+x.Metadata.Name, "spec.addresses: set:"+from+" -> set:"+to))
			if apply {
				for i := range x.Spec.Addresses {
					if x.Spec.Addresses[i].Address == "set:"+from {
						x.Spec.Addresses[i].Address = "set:" + to
					}
				}
			}
		}
	}
	return out
}

func (s *Server) policyRefs(rc *reqInfo, from, to string, apply bool) []api.RenameChange {
	var out []api.RenameChange
	if p := s.projects.items[rc.project]; p != nil && slices.Contains(p.Spec.FirewallPolicies, from) {
		out = append(out, ref("project "+rc.project, "spec.firewall_policies (mandatory policy): "+from+" -> "+to))
		if apply {
			p.Spec.FirewallPolicies = replaceName(p.Spec.FirewallPolicies, from, to)
		}
	}
	for _, n := range sortedNames(s.profiles.items) {
		p := s.profiles.items[n]
		if l := splitCSV(p.Spec.Config["firewall.policies"]); p.Metadata.Project == rc.project && slices.Contains(l, from) {
			out = append(out, ref("profile "+p.Metadata.Name, "config firewall.policies: "+from+" -> "+to))
			if apply {
				p.Spec.Config["firewall.policies"] = strings.Join(replaceName(l, from, to), ",")
			}
		}
	}
	for _, k := range sortedNames(s.jails.items) {
		j := s.jails.items[k]
		if j.Metadata.Project == rc.project && slices.Contains(j.Spec.Firewall.Policies, from) {
			out = append(out, ref(jailObj(j), "spec.firewall.policies: "+from+" -> "+to))
			if apply {
				j.Spec.Firewall.Policies = replaceName(j.Spec.Firewall.Policies, from, to)
			}
		}
	}
	return out
}

func (s *Server) profileRefs(rc *reqInfo, from, to string, apply bool) []api.RenameChange {
	var out []api.RenameChange
	for _, k := range sortedNames(s.jails.items) {
		j := s.jails.items[k]
		if (rc.project == api.HostProfileProject || j.Metadata.Project == rc.project) && slices.Contains(j.Spec.Profiles, from) {
			out = append(out, ref(jailObj(j), "spec.profiles: "+from+" -> "+to))
			if apply {
				j.Spec.Profiles = replaced(j.Spec.Profiles, from, to)
			}
		}
	}
	return out
}

func (s *Server) jailStopped(rc *reqInfo, name string) *api.Error {
	if j := s.jails.items[s.jails.keyIn(rc.project, name)]; j != nil && j.Status.Power == api.PowerRunning {
		return api.Errorf(api.CodeBusy, "jail %q is running", name).WithHint("stop it first (jailops stop " + name + "); a jail is renamed while it is stopped")
	}
	return nil
}

func (s *Server) jailRefs(rc *reqInfo, from, to string, apply bool) []api.RenameChange {
	if apply {
		o, n := s.jails.keyIn(rc.project, from), s.jails.keyIn(rc.project, to)
		moveKey(s.snapshots, o, n)
		moveKey(s.logs, o, n)
		moveKey(s.updHistory, o, n)
		moveKey(s.usage, o, n)
	}
	out := []api.RenameChange{{Kind: api.RenameDataset, Object: "dataset tank/jailops/projects/" + rc.project + "/jails/" + from,
		Detail: "renamed to tank/jailops/projects/" + rc.project + "/jails/" + to}}
	for _, k := range sortedNames(s.jails.items) {
		j := s.jails.items[k]
		if j.Metadata.Project == rc.project && slices.Contains(j.Spec.Boot.Depends, from) {
			out = append(out, ref(jailObj(j), "spec.boot.depends: "+from+" -> "+to))
			if apply {
				j.Spec.Boot.Depends = replaced(j.Spec.Boot.Depends, from, to)
			}
		}
	}
	return out
}

func (s *Server) imageRefs(_ *reqInfo, from, to string, apply bool) []api.RenameChange {
	out := []api.RenameChange{{Kind: api.RenameDataset, Object: "dataset tank/jailops/images/" + from, Detail: "renamed to tank/jailops/images/" + to}}
	if apply {
		for _, g := range s.gens[from] {
			g.Name = to + strings.TrimPrefix(g.Name, from)
		}
		moveKey(s.gens, from, to)
		moveKey(s.genMax, from, to)
		moveKey(s.aliases, from, to)
		moveKey(s.imgSame, from, to)
	}
	for _, n := range sortedNames(s.projects.items) {
		p := s.projects.items[n]
		if slices.Contains(p.Spec.Images, from) {
			out = append(out, ref("project "+n, "spec.images: "+from+" -> "+to))
			if apply {
				p.Spec.Images = replaced(p.Spec.Images, from, to)
			}
		}
	}
	for _, k := range sortedNames(s.jails.items) {
		j := s.jails.items[k]
		name, rest := j.Spec.Image, ""
		if i := strings.IndexAny(name, "@#"); i >= 0 {
			name, rest = name[:i], name[i:]
		}
		if name == from {
			out = append(out, ref(jailObj(j), "spec.image: "+j.Spec.Image+" -> "+to+rest))
			if apply {
				j.Spec.Image = to + rest
			}
		}
	}
	return out
}

func (s *Server) projectStopped(_ *reqInfo, name string) *api.Error {
	for _, k := range sortedNames(s.jails.items) {
		if j := s.jails.items[k]; j.Metadata.Project == name && j.Status.Power == api.PowerRunning {
			return api.Errorf(api.CodeBusy, "jail %q of project %q is running", j.Metadata.Name, name).WithHint("stop the jails of the project first")
		}
	}
	return nil
}

func (s *Server) projectRefs(_ *reqInfo, from, to string, apply bool) []api.RenameChange {
	out := []api.RenameChange{{Kind: api.RenameDataset, Object: "dataset tank/jailops/projects/" + from, Detail: "renamed to tank/jailops/projects/" + to}}
	moveIn := func(noun string, keys []string, metaOf func(string) *api.ObjectMeta, rekey func(old, nu string)) {
		for _, k := range keys {
			m := metaOf(k)
			if m.Project != from {
				continue
			}
			out = append(out, ref(noun+" "+m.Name, "moved to project "+to))
			if apply {
				m.Project = to
				rekey(k, to+"/"+m.Name)
			}
		}
	}
	moveIn("jail", sortedNames(s.jails.items), func(k string) *api.ObjectMeta { return &s.jails.items[k].Metadata },
		func(o, n string) { s.jails.items[n] = s.jails.items[o]; delete(s.jails.items, o) })
	moveIn("firewall policy", sortedNames(s.policies.items), func(k string) *api.ObjectMeta { return &s.policies.items[k].Metadata },
		func(o, n string) { s.policies.items[n] = s.policies.items[o]; delete(s.policies.items, o) })
	moveIn("address set", sortedNames(s.addrsets.items), func(k string) *api.ObjectMeta { return &s.addrsets.items[k].Metadata },
		func(o, n string) { s.addrsets.items[n] = s.addrsets.items[o]; delete(s.addrsets.items, o) })
	moveIn("backup policy", sortedNames(s.bpolicies.items), func(k string) *api.ObjectMeta { return &s.bpolicies.items[k].Metadata },
		func(o, n string) { s.bpolicies.items[n] = s.bpolicies.items[o]; delete(s.bpolicies.items, o) })
	moveIn("profile", sortedNames(s.profiles.items), func(k string) *api.ObjectMeta { return &s.profiles.items[k].Metadata },
		func(o, n string) { s.profiles.items[n] = s.profiles.items[o]; delete(s.profiles.items, o) })
	for _, n := range sortedNames(s.tokens.items) {
		t := s.tokens.items[n]
		if slices.Contains(t.Spec.Projects, from) {
			out = append(out, ref("token "+n, "projects: "+from+" -> "+to))
			if apply {
				t.Spec.Projects = replaced(t.Spec.Projects, from, to)
			}
		}
	}
	return out
}

func moveKey[V any](m map[string]V, from, to string) {
	if v, ok := m[from]; ok {
		m[to] = v
		delete(m, from)
	}
}

func jailObj(j *api.Jail) string {
	return fmt.Sprintf("jail %s (project %s)", j.Metadata.Name, j.Metadata.Project)
}

func replaced(l []string, from, to string) []string {
	out := slices.Clone(l)
	for i := range out {
		if out[i] == from {
			out[i] = to
		}
	}
	return out
}

func sortedNames[T any](m map[string]*T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// replaceName returns a copy of l with every from replaced by to.
func replaceName(l []string, from, to string) []string {
	out := slices.Clone(l)
	for i := range out {
		if out[i] == from {
			out[i] = to
		}
	}
	return out
}

// splitCSV splits the value of a list key of a profile on commas, without blanks.
func splitCSV(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func noRefs(*reqInfo, string, string, bool) []api.RenameChange { return nil }

func (s *Server) targetRefs(_ *reqInfo, from, to string, apply bool) []api.RenameChange {
	var out []api.RenameChange
	for _, k := range sortedNames(s.bpolicies.items) {
		p := s.bpolicies.items[k]
		if slices.Contains(p.Spec.Targets, from) {
			out = append(out, ref("backup policy "+p.Metadata.Name+" (project "+p.Metadata.Project+")", "spec.targets: "+from+" -> "+to))
			if apply {
				p.Spec.Targets = replaceName(p.Spec.Targets, from, to)
			}
		}
	}
	return out
}

// storageRenamable keeps the name of the default storage.
func (s *Server) storageRenamable(_ *reqInfo, name string) *api.Error {
	if name == "default" {
		return api.Errorf(api.CodeBusy, "the default storage keeps its name")
	}
	return nil
}

func (s *Server) storageRefs(_ *reqInfo, from, to string, apply bool) []api.RenameChange {
	var out []api.RenameChange
	for _, n := range sortedNames(s.projects.items) {
		p := s.projects.items[n]
		for i := range p.Spec.Storage {
			if p.Spec.Storage[i].Storage == from {
				out = append(out, ref("project "+p.Metadata.Name, "spec.storage: "+from+" -> "+to))
				if apply {
					p.Spec.Storage[i].Storage = to
				}
			}
		}
	}
	for _, k := range sortedNames(s.volumes.items) {
		v := s.volumes.items[k]
		if v.Spec.Storage == from {
			out = append(out, ref("volume "+v.Metadata.Name+" (project "+v.Metadata.Project+")", "spec.storage: "+from+" -> "+to))
			if apply {
				v.Spec.Storage = to
			}
		}
	}
	for _, k := range sortedNames(s.jails.items) {
		j := s.jails.items[k]
		if j.Spec.Storage == from {
			out = append(out, ref(jailObj(j), "spec.storage: "+from+" -> "+to))
			if apply {
				j.Spec.Storage = to
			}
		}
	}
	return out
}

// volumeStopped refuses the rename of a volume that a running jail attaches.
func (s *Server) volumeStopped(rc *reqInfo, name string) *api.Error {
	for _, k := range sortedNames(s.jails.items) {
		j := s.jails.items[k]
		if j.Metadata.Project != rc.project || j.Status.Power != api.PowerRunning {
			continue
		}
		for _, v := range j.Spec.Volumes {
			if v.Name == name {
				return api.Errorf(api.CodeBusy, "jail %q has volume %q attached and is running: stop it before the volume is renamed", j.Metadata.Name, name).
					WithHint("jailops stop " + j.Metadata.Name)
			}
		}
	}
	return nil
}

func (s *Server) volumeRefs(rc *reqInfo, from, to string, apply bool) []api.RenameChange {
	var out []api.RenameChange
	if apply {
		o, n := rc.project+"/"+from, rc.project+"/"+to
		moveKey(s.vol.pass, o, n)
		moveKey(s.vol.locked, o, n)
		moveKey(s.vol.fails, o, n)
		moveKey(s.vol.until, o, n)
	}
	for _, k := range sortedNames(s.jails.items) {
		j := s.jails.items[k]
		if j.Metadata.Project != rc.project {
			continue
		}
		for i := range j.Spec.Volumes {
			if j.Spec.Volumes[i].Name == from {
				out = append(out, ref(jailObj(j), fmt.Sprintf("spec.volumes[%d].volume: %s -> %s", i, from, to)))
				if apply {
					j.Spec.Volumes[i].Name = to
				}
			}
		}
	}
	return out
}
