package service

import (
	"context"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"sort"
	"strings"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// A project is a namespace; it is granted networks and storage and bounded by
// quotas (design 8.1). Everything below enforces it in the service layer, so
// the HTTP layer cannot forget a check.

type project = object[api.ProjectSpec]

// ---- grants ----

// specGrantsNetwork returns the grant that lets the project use a network. Networks are granted by name only: a
// network belongs to one project, so there is no wildcard.
func specGrantsNetwork(sp api.ProjectSpec, network string) (api.ProjectNetwork, bool) {
	for _, g := range sp.Networks {
		if g.Network == network {
			return g, true
		}
	}
	return api.ProjectNetwork{}, false
}

func specGrantsStorage(sp api.ProjectSpec, storage string) bool {
	_, ok := specStorageGrant(sp, storage)
	return ok
}

func specStorageGrant(sp api.ProjectSpec, storage string) (api.ProjectStorage, bool) {
	var wild bool
	for _, g := range sp.Storage {
		if g.Storage == storage {
			return g, true
		}
		if g.Storage == "*" {
			wild = true
		}
	}
	if wild {
		return api.ProjectStorage{Storage: storage}, true
	}
	return api.ProjectStorage{}, false
}

// ---- access ----

// access resolves the project a request works in and checks that the caller
// may use it. A project that does not exist and a project the caller may not
// use are both not_found: an identity never learns which projects exist.
func (s *Service) access(ctx context.Context) (project, error) {
	a := ActorFrom(ctx)
	if !a.HasScope() {
		return project{}, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	name, err := requestProject(ctx)
	if err != nil {
		return project{}, err
	}
	if !a.CanProject(name) {
		return project{}, notFound("project", name)
	}
	p, err := s.projKind.get(name)
	if err != nil {
		return project{}, notFound("project", name)
	}
	return p, nil
}

// AccessProject checks that the caller may use the project the request names.
// The server calls it for every project-level route before the handler runs,
// so a route without logic of its own (an unsupported one) answers a project
// the caller may not use with not_found like every other.
func (s *Service) AccessProject(ctx context.Context) error {
	_, err := s.access(ctx)
	return err
}

// canSeeProject is the visibility rule of lists, events and operations.
func canSeeProject(a Actor, p string) bool {
	return a.Global || (p != "" && slices.Contains(a.Projects, p))
}

// visibleProjects returns the projects whose objects the caller sees in a
// stream or a list that is not scoped to one project: all for a global
// identity (all == true), the identity's projects otherwise. A project named
// in the request narrows the result, and an inaccessible one is not_found.
func (s *Service) visibleProjects(ctx context.Context) (all bool, projects []string, err error) {
	a := ActorFrom(ctx)
	if !a.HasScope() {
		return false, nil, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	if p := ProjectFrom(ctx); p != "" {
		if !a.CanProject(p) {
			return false, nil, notFound("project", p)
		}
		if _, err := s.projKind.get(p); err != nil {
			return false, nil, notFound("project", p)
		}
		return false, []string{p}, nil
	}
	return a.Global, slices.Clone(a.Projects), nil
}

// ---- reads ----

func (s *Service) projectToAPI(ctx context.Context, o project) api.Project {
	p := api.Project{Metadata: o.Meta, Spec: o.Spec}
	p.Status = s.projectStatus(ctx, o)
	return p
}

// projectJails returns the registry entries of a project.
func (s *Service) projectJails(name string) []api.Jail {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []api.Jail
	for _, key := range sortedKeys(s.jails) {
		if e := s.jails[key]; e.jail.Metadata.Project == name {
			out = append(out, e.jail)
		}
	}
	return out
}

// usage is the consumption of a project, from the jail specs.
type usage struct {
	jails, cpu, pids, addrs int
	memory                  uint64
	diskByStorage           map[string]uint64
}

func attachedAddresses(spec api.JailSpec) int {
	n := 0
	for _, a := range spec.Network {
		for _, v := range []string{a.IPv4, a.IPv6} {
			if v != "" && v != "none" {
				n++
			}
		}
	}
	return n
}

func memBytes(v string) uint64 {
	if v == "" {
		return 0
	}
	n, err := validate.ParseSize(v)
	if err != nil {
		return 0
	}
	return n
}

func (u *usage) add(spec api.JailSpec) {
	u.jails++
	u.cpu += spec.Resources.CPU
	u.pids += spec.Resources.PIDs
	u.addrs += attachedAddresses(spec)
	u.memory += memBytes(spec.Resources.Memory)
	if d := memBytes(spec.Resources.Disk); d > 0 {
		if u.diskByStorage == nil {
			u.diskByStorage = map[string]uint64{}
		}
		u.diskByStorage[spec.Storage] += d
	}
}

// usageOf sums the jails of a project, those being created included, without
// the jail named except.
func (s *Service) usageOf(name, except string) usage {
	var u usage
	s.mu.RLock()
	for key, e := range s.jails {
		if key != except && e.jail.Metadata.Project == name {
			u.add(s.effective(e.jail))
		}
	}
	s.mu.RUnlock()
	s.quotaMu.Lock()
	for key, pj := range s.pending {
		if key != except && pj.project == name {
			if _, registered := s.jails[key]; !registered {
				u.add(pj.spec)
			}
		}
	}
	s.quotaMu.Unlock()
	return u
}

func (s *Service) projectStatus(ctx context.Context, o project) api.ProjectStatus {
	u := s.usageOf(o.Meta.Name, "")
	st := api.ProjectStatus{Jails: u.jails, CPU: u.cpu, MemoryUsed: int64(u.memory), Addresses: u.addrs}
	st.Conditions = s.FleetConditions(o.Meta.Name)
	if s.d.ZClient != nil {
		for _, si := range s.storageList() {
			if !specGrantsStorage(o.Spec, si.Name) {
				continue
			}
			if m, err := s.d.ZClient.Get(ctx, lifecycle.ProjectDS(si.lifecycle(), o.Meta.Name), "used"); err == nil {
				st.DiskUsed += atoi64(m["used"].Value)
			}
		}
	}
	return st
}

// ListProjects lists the projects the caller may use.
func (s *Service) ListProjects(ctx context.Context, labels map[string]string) ([]api.Project, error) {
	a := ActorFrom(ctx)
	if !a.HasScope() {
		return nil, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	objs, err := s.projKind.list()
	if err != nil {
		return nil, err
	}
	out := []api.Project{}
	for _, o := range objs {
		if a.CanProject(o.Meta.Name) && MatchLabels(o.Meta.Labels, labels) {
			out = append(out, s.projectToAPI(ctx, o))
		}
	}
	return out, nil
}

// GetProject returns one project.
func (s *Service) GetProject(ctx context.Context, name string) (api.Project, error) {
	a := ActorFrom(ctx)
	if !a.HasScope() {
		return api.Project{}, api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	if !a.CanProject(name) {
		return api.Project{}, notFound("project", name)
	}
	o, err := s.projKind.get(name)
	if err != nil {
		return api.Project{}, notFound("project", name)
	}
	return s.projectToAPI(ctx, o), nil
}

// ---- validation against the host ----

// checkProjectRefs checks a project spec against networks, storage and the
// other projects. self is the project's own name (empty on create).
func (s *Service) checkProjectRefs(name string, spec api.ProjectSpec, self string) error {
	// A hub that only defines a fleet project for other hosts does not hold
	// its networks and storage: each host checks its own when it applies it.
	local := len(spec.Hosts) == 0 || slices.ContainsFunc(spec.Hosts, s.isSelfHost)
	for _, g := range spec.Networks {
		if !local {
			continue
		}
		if _, err := s.netKind.get(g.Network); err != nil {
			return api.Errorf(api.CodeNotFound, "network %q does not exist", g.Network).WithDetail("network", g.Network)
		}
	}
	for _, g := range spec.Storage {
		if g.Storage == "*" || !local {
			continue
		}
		if _, ok := s.storage(g.Storage); !ok {
			return api.Errorf(api.CodeNotFound, "storage %q does not exist", g.Storage).WithDetail("storage", g.Storage)
		}
		if g.Quota != "" {
			if _, err := validate.ParseSize(g.Quota); err != nil {
				return invalid("storage %q: quota %q is not a size such as 500G", g.Storage, g.Quota)
			}
		}
	}
	// A network belongs to one project: another project that holds it blocks the grant.
	others, err := s.projKind.list()
	if err != nil {
		return err
	}
	for _, g := range spec.Networks {
		for _, o := range others {
			if o.Meta.Name == name || o.Meta.Name == self {
				continue
			}
			if _, held := specGrantsNetwork(o.Spec, g.Network); held {
				return api.Errorf(api.CodeConflict, "network %s is already granted to project %s", g.Network, o.Meta.Name).
					WithDetail("network", g.Network).WithDetail("project", o.Meta.Name).
					WithHint("networks are not shared between projects: create another network for this project")
			}
		}
	}
	return nil
}

// checkProjectInUse verifies that a new spec does not take away or shrink
// what the project's jails already use.
func (s *Service) checkProjectInUse(name string, old, next api.ProjectSpec) error {
	for _, j := range s.projectJails(name) {
		for _, a := range j.Spec.Network {
			if _, ok := specGrantsNetwork(next, a.Network); !ok {
				return api.Errorf(api.CodeBusy, "network %q is used by jail %q of the project", a.Network, j.Metadata.Name).
					WithHint("detach or delete the jail first")
			}
		}
		if !specGrantsStorage(next, j.Spec.Storage) {
			return api.Errorf(api.CodeBusy, "storage %q holds jail %q of the project", j.Spec.Storage, j.Metadata.Name).
				WithHint("delete the jail first")
		}
	}
	if l, err := s.volKind.p(name).list(); err == nil {
		for _, v := range l {
			if !v.Spec.IsHostDir() && !specGrantsStorage(next, v.Spec.Storage) {
				return api.Errorf(api.CodeBusy, "storage %q holds volume %q of the project", v.Spec.Storage, v.Meta.Name).
					WithHint("delete the volume first")
			}
		}
	}
	u := s.usageOf(name, "")
	q := next.Quotas
	for _, c := range []struct {
		what       string
		limit, use uint64
	}{
		{"jails", uint64(q.Jails), uint64(u.jails)}, {"cpu", uint64(q.CPU), uint64(u.cpu)},
		{"pids", uint64(q.PIDs), uint64(u.pids)}, {"addresses", uint64(q.Addresses), uint64(u.addrs)},
		{"memory", memBytes(q.Memory), u.memory},
	} {
		if c.limit > 0 && c.use > c.limit {
			return quotaErr(c.what, c.limit, c.use, 0).WithHint("the project already uses more than the new quota")
		}
	}
	_ = old
	return nil
}

func quotaErr(what string, limit, used, want uint64) *api.Error {
	e := api.Errorf(api.CodeQuotaExceeded, "the project's %s quota would be exceeded", what).
		WithDetail("resource", what).WithDetail("limit", fmt.Sprint(limit)).WithDetail("used", fmt.Sprint(used))
	if want > 0 {
		e = e.WithDetail("requested", fmt.Sprint(want))
	}
	return e
}

// ---- datasets ----

// ensureProjectDatasets creates the datasets of a project on one storage and
// applies the quota of the grant: <root>/projects/<project> and its jails
// container. The quota covers every jail of the project on that storage.
func (s *Service) ensureProjectDatasets(ctx context.Context, project string, si *storageInfo, g api.ProjectStorage) error {
	z := s.d.ZClient
	if z == nil {
		return nil
	}
	projDS := lifecycle.ProjectDS(si.lifecycle(), project)
	jailsDS := lifecycle.ProjectJailsDS(si.lifecycle(), project)
	if ok, err := z.Exists(ctx, path.Join(si.Root, "projects")); err != nil {
		return internal(err)
	} else if !ok {
		return api.Errorf(api.CodeNotFound, "storage %q has no projects dataset; it is not set up", si.Name)
	}
	for _, d := range []struct{ name, kind string }{{projDS, "project"}, {jailsDS, "jails"}} {
		ok, err := z.Exists(ctx, d.name)
		if err != nil {
			return internal(err)
		}
		if ok {
			if p, _ := z.Get(ctx, d.name, "jailops:managed"); p["jailops:managed"].Value != "on" {
				return api.Errorf(api.CodeConflict, "dataset %s exists and is not managed by JailOps", d.name)
			}
			continue
		}
		props := map[string]string{"jailops:managed": "on", "jailops:kind": d.kind, "canmount": "off", "mountpoint": "none"}
		if d.kind == "project" {
			props["jailops:project"] = project
		}
		if err := z.Create(ctx, zfs.CreateOpts{Name: d.name, Props: props}); err != nil {
			return internal(err)
		}
	}
	cur, _ := z.Get(ctx, projDS, "quota")
	have := cur["quota"].Value
	switch {
	case g.Quota != "" && quotaDiffers(have, g.Quota):
		want, err := validate.CanonicalSize("quota", g.Quota)
		if err != nil {
			return err
		}
		if err := z.Set(ctx, projDS, map[string]string{"quota": want}); err != nil {
			return internal(err)
		}
	case g.Quota == "" && have != "" && have != "-" && have != "none" && have != "0":
		if err := z.Set(ctx, projDS, map[string]string{"quota": "none"}); err != nil {
			return internal(err)
		}
	}
	return nil
}

// applyProjectDatasets creates the datasets of every explicitly granted storage.
func (s *Service) applyProjectDatasets(ctx context.Context, name string, spec api.ProjectSpec) error {
	if len(spec.Hosts) > 0 && !slices.ContainsFunc(spec.Hosts, s.isSelfHost) {
		return nil // the project lives on other hosts
	}
	for _, g := range spec.Storage {
		if g.Storage == "*" {
			continue
		}
		si, ok := s.storage(g.Storage)
		if !ok {
			continue
		}
		if err := s.ensureProjectDatasets(ctx, name, si, g); err != nil {
			return err
		}
	}
	return nil
}

// ---- writes (global only) ----

func (s *Service) newProjectNetwork(ctx context.Context, name string) (string, error) {
	if s.d.NetworkPool == "" {
		return "", api.Errorf(api.CodeUnsupported, "this daemon has no pool of subnets for dedicated project networks").
			WithHint("set projects.network_pool in the configuration, for example 10.64.0.0/12")
	}
	pool, err := netip.ParsePrefix(s.d.NetworkPool)
	if err != nil || !pool.Addr().Is4() {
		return "", api.Errorf(api.CodeInternal, "the configured network pool %q is not an IPv4 prefix", s.d.NetworkPool)
	}
	bits := s.d.NetworkPoolBits
	if bits == 0 {
		bits = 24
	}
	if bits <= pool.Bits() || bits > 29 {
		return "", api.Errorf(api.CodeInternal, "the configured subnet size /%d does not fit the pool %s", bits, pool)
	}
	objs, err := s.netKind.list()
	if err != nil {
		return "", err
	}
	used := s.hostPrefixes(ctx)
	for _, o := range objs {
		if o.Spec.IPv4 != nil {
			if p, err := netip.ParsePrefix(o.Spec.IPv4.Subnet); err == nil {
				used = append(used, p.Masked())
			}
		}
	}
	var sub netip.Prefix
	for cand := netip.PrefixFrom(pool.Masked().Addr(), bits); pool.Contains(cand.Addr()); {
		free := true
		for _, u := range used {
			if u.Overlaps(cand) {
				free = false
				break
			}
		}
		if free {
			sub = cand
			break
		}
		next := nextPrefix(cand)
		if !next.IsValid() {
			break
		}
		cand = next
	}
	if !sub.IsValid() {
		return "", api.Errorf(api.CodePoolExhausted, "the pool of subnets %s has no free /%d", pool, bits)
	}
	base := sub.Addr()
	gw := base.Next()
	first := gw
	for i := 0; i < 9; i++ {
		first = first.Next()
	}
	last := lastAddr(sub).Prev().Prev() // broadcast and one spare
	spec := api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: sub.String(), Gateway: gw.String(), Range: first.String() + "-" + last.String()}}
	if s.d.NetworkUplink != "" {
		spec.Uplink = s.d.NetworkUplink
		spec.IPv4.NAT = s.d.NetworkNAT
	}
	netName := name
	if s.netKind.exists(netName) {
		return "", api.Errorf(api.CodeAlreadyExists, "a network named %q exists already", netName).
			WithHint("create the project without new_network and grant that network")
	}
	n, err := s.CreateNetwork(ctx, api.Network{Metadata: api.ObjectMeta{Name: netName, Labels: map[string]string{labelProject: name}}, Spec: spec})
	if err != nil {
		return "", err
	}
	return n.Metadata.Name, nil
}

func nextPrefix(p netip.Prefix) netip.Prefix {
	last := lastAddr(p)
	n := last.Next()
	if !n.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(n, p.Bits())
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// CreateProject creates a project. Only global identities create projects.
func (s *Service) CreateProject(ctx context.Context, in api.Project) (api.Project, error) {
	if err := requireGlobal(ctx, "creating a project"); err != nil {
		return api.Project{}, err
	}
	name := in.Metadata.Name
	spec := in.Spec
	if err := validate.ProjectSpec(name, spec); err != nil {
		return api.Project{}, err
	}
	if err := validate.NameLength("project", "name", name, validate.MaxProjectName); err != nil {
		return api.Project{}, err
	}
	if err := canonicalProjectSizes(&spec); err != nil {
		return api.Project{}, err
	}
	unlock, err := s.locks.lockPatient(ctx, "create project "+name, projectLock(name))
	if err != nil {
		return api.Project{}, err
	}
	defer unlock()
	if err := s.projKind.notTaken(name); err != nil {
		return api.Project{}, err
	}
	if len(spec.FirewallPolicies) > 0 {
		return api.Project{}, api.Errorf(api.CodeNotFound, "firewall policy %q does not exist in the new project", spec.FirewallPolicies[0]).
			WithHint("create the project, create the policy in it, then set spec.firewall_policies")
	}
	var madeNet string
	if spec.NewNetwork {
		spec.NewNetwork = false
		nn, err := s.newProjectNetwork(ctx, name)
		if err != nil {
			return api.Project{}, err
		}
		madeNet = nn
		spec.Networks = append(spec.Networks, api.ProjectNetwork{Network: nn})
	}
	undoNet := func() {
		if madeNet != "" {
			_ = s.DeleteNetwork(context.WithoutCancel(ctx), madeNet, AnyGeneration)
		}
	}
	if err := s.checkProjectRefs(name, spec, ""); err != nil {
		undoNet()
		return api.Project{}, err
	}
	if err := s.applyProjectDatasets(ctx, name, spec); err != nil {
		undoNet()
		return api.Project{}, err
	}
	o, err := s.projKind.create(ctx, in.Metadata, spec)
	if err != nil {
		undoNet()
		return api.Project{}, err
	}
	s.kick()
	s.FleetKick()
	return s.projectToAPI(ctx, o), nil
}

// UpdateProject replaces a project's definition.
func (s *Service) UpdateProject(ctx context.Context, name string, in api.Project, expect int64) (api.Project, error) {
	if err := requireGlobal(ctx, "changing a project"); err != nil {
		return api.Project{}, err
	}
	if in.Metadata.Name != "" && in.Metadata.Name != name {
		return api.Project{}, renameByAction("project", "projects")
	}
	if in.Spec.NewNetwork {
		return api.Project{}, invalid("new_network applies when a project is created").WithHint("create a network and grant it")
	}
	if err := validate.ProjectSpec(name, in.Spec); err != nil {
		return api.Project{}, err
	}
	if err := canonicalProjectSizes(&in.Spec); err != nil {
		return api.Project{}, err
	}
	unlock, err := s.locks.lockPatient(ctx, "update project "+name, projectLock(name))
	if err != nil {
		return api.Project{}, err
	}
	defer unlock()
	old, err := s.projKind.get(name)
	if err != nil {
		return api.Project{}, err
	}
	for _, pn := range in.Spec.FirewallPolicies {
		if slices.Contains(old.Spec.FirewallPolicies, pn) {
			continue
		}
		o, err := s.polKind.p(name).get(pn)
		if err != nil {
			if api.IsCode(err, api.CodeNotFound) {
				return api.Project{}, api.Errorf(api.CodeNotFound, "firewall policy %q does not exist in project %q", pn, name)
			}
			return api.Project{}, err
		}
		if o.Meta.ManagedBy != "" {
			return api.Project{}, invalid("firewall policy %q is managed by %s: it belongs to its own jail and cannot be a mandatory policy", pn, o.Meta.ManagedBy)
		}
	}
	if err := s.checkProjectRefs(name, in.Spec, name); err != nil {
		return api.Project{}, err
	}
	if err := s.checkProjectInUse(name, old.Spec, in.Spec); err != nil {
		return api.Project{}, err
	}
	if err := s.applyProjectDatasets(ctx, name, in.Spec); err != nil {
		return api.Project{}, err
	}
	o, err := s.projKind.update(ctx, name, expect, in.Metadata.Labels, &in.Metadata.ManagedBy, in.Spec)
	if err != nil {
		return api.Project{}, err
	}
	s.kick()
	s.FleetKick()
	return s.projectToAPI(ctx, o), nil
}

// PatchProject applies a merge patch.
func (s *Service) PatchProject(ctx context.Context, name string, patch map[string]any, expect int64) (api.Project, error) {
	cur, err := s.GetProject(ctx, name)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return cur, api.Errorf(api.CodeConflict, "project %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	var out api.Project
	if err := MergePatch(cur, patch, &out); err != nil {
		return out, err
	}
	return s.UpdateProject(ctx, name, out, cur.Metadata.Generation)
}

// projectObjects counts what a project still holds.
func (s *Service) projectObjects(name string) (map[string]int, int) {
	held := map[string]int{}
	held["jails"] = len(s.projectJails(name))
	if l, err := s.polKind.p(name).list(); err == nil {
		held["firewall policies"] = len(l)
	}
	if l, err := s.setKind.p(name).list(); err == nil {
		held["address sets"] = len(l)
	}
	if l, err := s.bpolKind.p(name).list(); err == nil {
		held["backup policies"] = len(l)
	}
	if l, err := s.volKind.p(name).list(); err == nil {
		held["volumes"] = len(l)
	}
	total := 0
	for _, n := range held {
		total += n
	}
	return held, total
}

// projectLeftovers names the datasets below the datasets of a project on any storage that are not the empty
// containers JailOps keeps for it: what is there belongs to something that is not an object of the project any more.
func (s *Service) projectLeftovers(ctx context.Context, name string) ([]string, error) {
	z := s.d.ZClient
	if z == nil {
		return nil, nil
	}
	var out []string
	for _, si := range s.storageList() {
		pd := lifecycle.ProjectDS(si.lifecycle(), name)
		if ok, _ := z.Exists(ctx, pd); !ok {
			continue
		}
		if p, _ := z.Get(ctx, pd, "jailops:managed"); p["jailops:managed"].Value != "on" {
			continue
		}
		list, err := z.List(ctx, zfs.ListOpts{Root: pd, Recursive: true})
		if err != nil {
			return nil, err
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		keep := map[string]bool{
			pd: true, lifecycle.ProjectJailsDS(si.lifecycle(), name): true, lifecycle.ProjectVolumesDS(si.lifecycle(), name): true,
		}
		var offenders []string
		for _, d := range list {
			if keep[d.Name] {
				continue
			}
			covered := false
			for _, o := range offenders {
				if strings.HasPrefix(d.Name, o+"/") {
					covered = true
					break
				}
			}
			if !covered {
				offenders = append(offenders, d.Name)
			}
		}
		sort.Strings(offenders)
		out = append(out, offenders...)
	}
	return out, nil
}

// DeleteProject deletes an empty project and its datasets.
func (s *Service) DeleteProject(ctx context.Context, name string, expect int64) error {
	if err := requireGlobal(ctx, "deleting a project"); err != nil {
		return err
	}
	unlock, err := s.locks.lockPatient(ctx, "delete project "+name, projectLock(name))
	if err != nil {
		return err
	}
	defer unlock()
	o, err := s.projKind.get(name)
	if err != nil {
		return err
	}
	s.quotaMu.Lock()
	var busy bool
	for _, pj := range s.pending {
		busy = busy || pj.project == name
	}
	s.quotaMu.Unlock()
	if busy {
		return api.Errorf(api.CodeBusy, "project %q has a jail being created", name)
	}
	if held, total := s.projectObjects(name); total > 0 {
		var parts []string
		for k, n := range held {
			if n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, k))
			}
		}
		sort.Strings(parts)
		return api.Errorf(api.CodeBusy, "project %q is not empty: %s", name, strings.Join(parts, ", ")).WithHint("delete them first (volumes with 'jailops volume delete', which asks before it destroys data)")
	}
	// What is left below the project's datasets is data that no object of the project accounts for (a volume dataset
	// whose object is gone, a jail container parked by a replace-restore, a dataset an interrupted operation left):
	// it is named, and nothing is destroyed until the operator has dealt with it.
	if left, err := s.projectLeftovers(ctx, name); err != nil {
		return err
	} else if len(left) > 0 {
		return api.Errorf(api.CodeBusy, "project %q still has datasets: %s", name, strings.Join(left, ", ")).
			WithHint("look at them with 'zfs list -r', keep what you need and destroy the rest with 'zfs destroy -r' (jailops would delete them with the project)")
	}
	if err := s.projKind.delete(ctx, name, expect); err != nil {
		return err
	}
	// The anchors were loaded project first, jails below it; they go in
	// reverse. The project is empty, so its jail anchors are gone already.
	if s.d.PF != nil {
		if err := s.d.PF.Flush(ctx, render.ProjectAnchor(name)); err != nil && !api.IsCode(err, api.CodeNotFound) {
			s.log.Warn("flushing the anchor of a deleted project failed", "project", name, "err", err)
		}
	}
	if z := s.d.ZClient; z != nil {
		for _, si := range s.storageList() {
			pd := lifecycle.ProjectDS(si.lifecycle(), name)
			if ok, _ := z.Exists(ctx, pd); !ok {
				continue
			}
			if p, _ := z.Get(ctx, pd, "jailops:managed"); p["jailops:managed"].Value != "on" {
				continue
			}
			if err := z.Destroy(ctx, pd, zfs.DestroyOpts{Recursive: true}); err != nil {
				s.log.Warn("removing the datasets of a deleted project failed", "project", name, "storage", si.Name, "err", err)
			}
		}
	}
	s.fleetForget(ctx, o)
	s.kick()
	return nil
}

// ---- quotas and jail admission ----

type pendingJail struct {
	project string
	spec    api.JailSpec
}

// admit checks a jail against the project's grants, image allow-list and
// quotas and, for a
// jail that does not exist yet, reserves its share of the quotas until
// release is called. Nothing is created before this passes. A jail names its
// network and storage itself or through its profiles: nothing is filled in.
func (s *Service) admit(ctx context.Context, p project, key string, spec *api.JailSpec, old *api.JailSpec) (release func(), err error) {
	a := ActorFrom(ctx)
	isNew := old == nil
	globalAdmin := a.Global && a.Perm.Satisfies(api.PermAdmin)
	if spec.Delegate && (old == nil || !old.Delegate) && !globalAdmin {
		return nil, api.Errorf(api.CodeForbidden, "ZFS delegation is granted by a global administrator only")
	}
	profs, err := s.resolveProfiles(p.Meta.Name, spec.Profiles)
	if err != nil {
		return nil, err
	}
	api.NormalizeDevices(spec)
	eff, _ := api.ExpandedConfig(*spec, profs)
	if err := s.checkSealedEnv(eff.Env); err != nil {
		return nil, err
	}
	if spec.Delegate && eff.Resources.Disk == "" {
		return nil, invalid("ZFS delegation needs a disk limit: the jail manages the dataset it is handed, and without a quota on its container it can fill the pool").
			WithHint("set limits.disk, for example `jailops config set JAIL limits.disk 20G`")
	}
	if len(eff.Network) == 0 {
		return nil, invalid("a jail needs a network: name one with --network NAME or use a profile that has one")
	}
	for i := range eff.Network {
		if eff.Network[i].Network == "" {
			return nil, invalid("network device %q names no network: name one with --network NAME or set nic.%s.network", eff.Network[i].Name, eff.Network[i].Name)
		}
		if _, ok := specGrantsNetwork(p.Spec, eff.Network[i].Network); !ok {
			return nil, api.Errorf(api.CodeForbidden, "network %q is not granted to project %q", eff.Network[i].Network, p.Meta.Name).
				WithHint(fmt.Sprintf("a global admin grants it: jailops network grant %s --project %s", eff.Network[i].Network, p.Meta.Name))
		}
	}
	if len(eff.Devfs) > 0 && !a.Perm.Satisfies(api.PermAdmin) {
		return nil, api.Errorf(api.CodeForbidden, "exposing device nodes needs the admin role")
	}
	if len(eff.Proxy) > 0 {
		if old == nil || !slices.Equal(eff.Proxy, s.effective(api.Jail{Spec: *old}).Proxy) {
			if err := requireGlobalForForward(ctx, "forwarding a host port into a jail"); err != nil {
				return nil, err
			}
		}
		if err := s.checkProxyDevices(ctx, "jail "+key, eff.Proxy); err != nil {
			return nil, err
		}
	}
	var wasVolumes []api.VolumeAttach
	if old != nil {
		wasVolumes = s.effective(api.Jail{Spec: *old}).Volumes
	}
	if err := s.hostDirAdmission(ctx, p.Meta.Name, eff.Volumes, wasVolumes); err != nil {
		return nil, err
	}
	if len(eff.Proxy) > 0 {
		up := false
		for _, nd := range eff.Network {
			if n, err := s.netKind.get(nd.Network); err == nil && n.Spec.Uplink != "" {
				up = true
			}
		}
		if !up {
			return nil, invalid("proxy devices forward host ports and need a network with an uplink")
		}
	}
	if err := s.checkProxyConflicts(key, eff); err != nil {
		return nil, err
	}
	if spec.Storage == "" {
		spec.Storage = eff.Storage // a profile may carry it
	}
	if spec.Storage == "" {
		return nil, invalid("a jail needs a storage: name one with --storage NAME or use a profile that has one")
	}
	if !specGrantsStorage(p.Spec, spec.Storage) {
		return nil, api.Errorf(api.CodeForbidden, "storage %q is not granted to project %q", spec.Storage, p.Meta.Name).
			WithHint(fmt.Sprintf("a global admin grants it: jailops storage grant %s --project %s", spec.Storage, p.Meta.Name))
	}
	if _, ok := s.storage(spec.Storage); !ok {
		return nil, notFound("storage", spec.Storage)
	}
	if ref, err := validate.ParseImageRef(spec.Image); err == nil && !imageAllowed(p.Spec, ref.Name) {
		return nil, notFound("image", ref.Name)
	}
	eff.Storage = spec.Storage
	if err := s.checkJailRefs(p.Meta.Name, eff); err != nil {
		return nil, err
	}
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	if err := s.checkEncryptedSharing(p.Meta.Name, key, eff.Volumes); err != nil {
		return nil, err
	}
	u := s.usageOfLocked(p.Meta.Name, key)
	if err := s.checkQuota(p, eff, u, isNew); err != nil {
		return nil, err
	}
	if !isNew {
		return func() {}, nil
	}
	s.pending[key] = pendingJail{project: p.Meta.Name, spec: eff}
	return func() {
		s.quotaMu.Lock()
		delete(s.pending, key)
		s.quotaMu.Unlock()
	}, nil
}

// usageWithoutLocked sums the jails of a project (those being created included) except the jails in skip, for a
// caller that holds quotaMu and counts those jails itself with the specs they would have.
func (s *Service) usageWithoutLocked(name string, skip map[string]api.JailSpec) usage {
	var u usage
	s.mu.RLock()
	for key, e := range s.jails {
		if _, skipped := skip[key]; !skipped && e.jail.Metadata.Project == name {
			u.add(s.effective(e.jail))
		}
	}
	for key, pj := range s.pending {
		if _, registered := s.jails[key]; !registered && pj.project == name {
			if _, skipped := skip[key]; !skipped {
				u.add(pj.spec)
			}
		}
	}
	s.mu.RUnlock()
	return u
}

// usageOfLocked is usageOf for a caller that holds quotaMu.
func (s *Service) usageOfLocked(name, except string) usage {
	var u usage
	s.mu.RLock()
	for key, e := range s.jails {
		if key != except && e.jail.Metadata.Project == name {
			u.add(s.effective(e.jail))
		}
	}
	for key, pj := range s.pending {
		if _, registered := s.jails[key]; key != except && pj.project == name && !registered {
			u.add(pj.spec)
		}
	}
	s.mu.RUnlock()
	return u
}

func imageAllowed(sp api.ProjectSpec, image string) bool {
	return len(sp.Images) == 0 || slices.Contains(sp.Images, image)
}

// checkQuota fails with quota_exceeded when adding spec to u would pass a
// quota of the project. A quota on cpu, memory or pids needs the jail to say
// how much it uses, because an unbounded jail would escape the quota.
func (s *Service) checkQuota(p project, spec api.JailSpec, u usage, isNew bool) error {
	q := p.Spec.Quotas
	name := p.Meta.Name
	if q.Jails > 0 && isNew && u.jails+1 > q.Jails {
		return quotaErr("jails", uint64(q.Jails), uint64(u.jails), 1).WithHint("project " + name + " may hold " + fmt.Sprint(q.Jails) + " jails")
	}
	if q.CPU > 0 {
		if spec.Resources.CPU == 0 {
			return invalid("project %q has a CPU quota: give the jail a CPU limit (--cpu N, or limits.cpu)", name)
		}
		if u.cpu+spec.Resources.CPU > q.CPU {
			return quotaErr("cpu", uint64(q.CPU), uint64(u.cpu), uint64(spec.Resources.CPU))
		}
	}
	if q.PIDs > 0 {
		if spec.Resources.PIDs == 0 {
			return invalid("project %q has a process quota: give the jail a process limit (--pids N, or limits.pids)", name)
		}
		if u.pids+spec.Resources.PIDs > q.PIDs {
			return quotaErr("pids", uint64(q.PIDs), uint64(u.pids), uint64(spec.Resources.PIDs))
		}
	}
	if q.Memory != "" {
		limit := memBytes(q.Memory)
		want := memBytes(spec.Resources.Memory)
		if want == 0 {
			return invalid("project %q has a memory quota: give the jail a memory limit (--memory SIZE, or limits.memory)", name)
		}
		if u.memory+want > limit {
			return quotaErr("memory", limit, u.memory, want)
		}
	}
	if q.Addresses > 0 {
		if want := attachedAddresses(spec); u.addrs+want > q.Addresses {
			return quotaErr("addresses", uint64(q.Addresses), uint64(u.addrs), uint64(want))
		}
	}
	if g, ok := specStorageGrant(p.Spec, spec.Storage); ok && g.Quota != "" {
		if want := memBytes(spec.Resources.Disk); want > 0 {
			limit := memBytes(g.Quota)
			if u.diskByStorage[spec.Storage]+want > limit {
				return quotaErr("disk", limit, u.diskByStorage[spec.Storage], want)
			}
		}
	}
	return nil
}

// projectLock serialises changes of one project's definition.
func projectLock(n string) string { return "project/" + n }
func storageLock(n string) string { return "storage/" + n }
