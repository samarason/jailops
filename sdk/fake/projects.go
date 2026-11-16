package fake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// DefaultStorage is the storage every fake starts with.
const DefaultStorage = "default"

func granted(list []string, name string) bool {
	return slices.Contains(list, name) || slices.Contains(list, "*")
}

func (s *Server) project(name string) *api.Project { return s.projects.items[name] }

func (s *Server) netGrants(p *api.Project) []string {
	var out []string
	for _, g := range p.Spec.Networks {
		out = append(out, g.Network)
	}
	return out
}

func (s *Server) storGrants(p *api.Project) []string {
	var out []string
	for _, g := range p.Spec.Storage {
		out = append(out, g.Storage)
	}
	return out
}

// parseSize reads "512M", "2G" or a byte count.
func parseSize(v string) (int64, bool) {
	if v == "" {
		return 0, true
	}
	mult := int64(1)
	t := strings.TrimSuffix(strings.TrimSuffix(v, "B"), "i")
	if t != "" {
		switch t[len(t)-1] {
		case 'K', 'k':
			mult = 1 << 10
		case 'M', 'm':
			mult = 1 << 20
		case 'G', 'g':
			mult = 1 << 30
		case 'T', 't':
			mult = 1 << 40
		}
		if mult != 1 {
			t = t[:len(t)-1]
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n * mult, true
}

func (s *Server) setupProjects() {
	k := s.projects
	k.keep = func(dst, old *api.Project) { dst.Status = old.Status }
	k.visible = func(rc *reqInfo, p *api.Project) bool { return rc.canProject(p.Metadata.Name) }
	k.validate = s.validateProject
	k.assign = func(p, old *api.Project) *api.Error {
		if p.Spec.NewNetwork {
			n, e := s.newNetworkFor(p.Metadata.Name)
			if e != nil {
				return e
			}
			p.Spec.Networks = append(p.Spec.Networks, api.ProjectNetwork{Network: n})
			p.Spec.NewNetwork = false
		}
		return nil
	}
	k.after = func(p *api.Project) { s.applyFleet(p.Metadata.Name) }
	k.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		rc := s.info(r)
		if !rc.aggregate {
			return false
		}
		s.mu.Lock()
		p := s.projects.items[r.PathValue("name")]
		vis := p != nil && k.visible(rc, p)
		s.mu.Unlock()
		if !vis {
			writeErr(w, notFound("project", r.PathValue("name")))
			return true
		}
		s.aggregate(w, r, r.PathValue("name"))
		return true
	}
	k.beforeDelete = func(p *api.Project) *api.Error {
		name := p.Metadata.Name
		if s.projectUsed(name) {
			return api.Errorf(api.CodeBusy, "project %q is not empty", name).WithHint("delete its jails, policies, address sets and backup policies first")
		}
		return nil
	}
	k.onDelete = func(p *api.Project) { s.deleteFleet(p) }
	k.decorate = func(p *api.Project) {
		p.Status = s.projectUsage(p.Metadata.Name)
		p.Status.Conditions = append(p.Status.Conditions, s.fleetConds[p.Metadata.Name]...)
	}
}

func (s *Server) projectUsed(name string) bool {
	for _, m := range []func() []*api.ObjectMeta{
		func() []*api.ObjectMeta { return metas(s.jails) },
		func() []*api.ObjectMeta { return metas(s.policies) },
		func() []*api.ObjectMeta { return metas(s.addrsets) },
		func() []*api.ObjectMeta { return metas(s.bpolicies) },
	} {
		for _, om := range m() {
			if om.Project == name {
				return true
			}
		}
	}
	return false
}

func metas[T any](k *kind[T]) []*api.ObjectMeta {
	var out []*api.ObjectMeta
	for _, o := range k.items {
		out = append(out, k.meta(o))
	}
	return out
}

// projectJails returns the jails of a project.
func (s *Server) projectJails(project string) []*api.Jail {
	var out []*api.Jail
	for _, j := range s.jails.items {
		if j.Metadata.Project == project {
			out = append(out, j)
		}
	}
	return out
}

func countAddrs(j *api.Jail) int {
	n := 0
	for _, a := range j.Spec.Network {
		for _, v := range []string{a.IPv4, a.IPv6} {
			if v != "" && v != "none" {
				n++
			}
		}
	}
	return n
}

func (s *Server) projectUsage(name string) api.ProjectStatus {
	var st api.ProjectStatus
	for _, j := range s.projectJails(name) {
		st.Jails++
		st.CPU += j.Spec.Resources.CPU
		m, _ := parseSize(j.Spec.Resources.Memory)
		st.MemoryUsed += m
		d, _ := parseSize(j.Spec.Resources.Disk)
		st.DiskUsed += d
		st.Addresses += countAddrs(j)
	}
	return st
}

func (s *Server) validateProject(p, old *api.Project) *api.Error {
	name := p.Metadata.Name
	if p.Spec.NewNetwork && old != nil {
		return api.Errorf(api.CodeInvalid, "new_network is a create-time option")
	}
	local := !(s.hub && len(p.Spec.Hosts) > 0)
	for _, g := range p.Spec.Networks {
		if g.Network == "" {
			return api.Errorf(api.CodeInvalid, "a network grant needs a network")
		}
		if g.Network == "*" {
			return api.Errorf(api.CodeInvalid, "a network grant names one network: * is not accepted")
		}
		if local && s.networks.items[g.Network] == nil {
			return notFound("network", g.Network)
		}
		for _, o := range s.projects.items {
			if o.Metadata.Name == name {
				continue
			}
			for _, og := range o.Spec.Networks {
				if og.Network == g.Network {
					return api.Errorf(api.CodeConflict, "network %s is already granted to project %s", g.Network, o.Metadata.Name)
				}
			}
		}
	}
	for _, g := range p.Spec.Storage {
		if g.Storage == "" {
			return api.Errorf(api.CodeInvalid, "a storage grant needs a storage")
		}
		if _, ok := parseSize(g.Quota); !ok {
			return api.Errorf(api.CodeInvalid, "invalid storage quota %q", g.Quota)
		}
		if g.Storage != "*" && local && s.storages.items[g.Storage] == nil {
			return notFound("storage", g.Storage)
		}
	}
	q := p.Spec.Quotas
	if q.Jails < 0 || q.CPU < 0 || q.PIDs < 0 || q.Addresses < 0 {
		return api.Errorf(api.CodeInvalid, "quotas must not be negative")
	}
	if _, ok := parseSize(q.Memory); !ok {
		return api.Errorf(api.CodeInvalid, "invalid memory quota %q", q.Memory)
	}
	for _, pn := range p.Spec.FirewallPolicies {
		if s.policies.items[name+"/"+pn] == nil {
			return api.Errorf(api.CodeInvalid, "firewall policy %q does not exist in project %q", pn, name)
		}
	}
	return nil
}

func parseRangeOrAddr(v string) (netip.Addr, netip.Addr, error) {
	if !strings.Contains(v, "-") {
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		return a, a, err
	}
	return parseRange(v)
}

// newNetworkFor creates the dedicated network of --new-network.
func (s *Server) newNetworkFor(project string) (string, *api.Error) {
	if s.networks.items[project] != nil {
		return "", api.Errorf(api.CodeAlreadyExists, "network %q already exists", project)
	}
	taken := map[string]bool{}
	for _, n := range s.networks.items {
		if n.Spec.IPv4 != nil {
			taken[n.Spec.IPv4.Subnet] = true
		}
	}
	for i := 0; i < 256; i++ {
		sub := fmt.Sprintf("10.64.%d.0/24", i)
		if taken[sub] {
			continue
		}
		n := &api.Network{Metadata: api.ObjectMeta{Name: project}, Spec: api.NetworkSpec{
			IPv4: &api.IPv4Net{Subnet: sub, Gateway: fmt.Sprintf("10.64.%d.1", i), Range: fmt.Sprintf("10.64.%d.10-10.64.%d.250", i, i)}}}
		s.networks.insert(n, false)
		return project, nil
	}
	return "", api.Errorf(api.CodePoolExhausted, "no free subnet in the pool")
}

// ---- jail checks against the project ----

// checkJail applies the project's grants, defaults and quotas to a jail that
// is created (old == nil) or changed. s.mu is held.
func (s *Server) checkJail(j, old *api.Jail) *api.Error {
	p := s.project(j.Metadata.Project)
	if p == nil {
		return notFound("project", j.Metadata.Project)
	}
	spec := &j.Spec
	// What the jail ends up with is its own fields merged with its profiles'. Nothing is defaulted: a jail
	// names its networks and its storage, or a profile does.
	eff, _ := api.ExpandedConfig(*spec, s.profilesFor(j.Metadata.Project, spec.Profiles))
	for i, a := range spec.Network {
		if a.Network == "" {
			return api.Errorf(api.CodeInvalid, "network %d names no network", i)
		}
	}
	if len(eff.Network) == 0 {
		return api.Errorf(api.CodeInvalid, "a jail needs a network: name one with --network NAME or use a profile that has one")
	}
	for _, a := range eff.Network {
		if a.Network == "" {
			return api.Errorf(api.CodeInvalid, "a network device of the jail names no network")
		}
		if !granted(s.netGrants(p), a.Network) {
			return api.Errorf(api.CodeForbidden, "network %q is not granted to project %q", a.Network, p.Metadata.Name)
		}
		if s.networks.items[a.Network] == nil {
			return notFound("network", a.Network)
		}
	}
	// Storage.
	storage := eff.Storage
	if storage == "" {
		return api.Errorf(api.CodeInvalid, "a jail needs a storage: name one with --storage NAME or use a profile that has one")
	}
	if !granted(s.storGrants(p), storage) {
		return api.Errorf(api.CodeForbidden, "storage %q is not granted to project %q", storage, p.Metadata.Name)
	}
	if s.storages.items[storage] == nil {
		return notFound("storage", storage)
	}
	// Images.
	if len(p.Spec.Images) > 0 && !slices.Contains(p.Spec.Images, imageName(spec.Image)) {
		return api.Errorf(api.CodeForbidden, "image %q is not allowed in project %q", imageName(spec.Image), p.Metadata.Name)
	}
	// Quotas.
	q := p.Spec.Quotas
	self := s.jails.keyIn(j.Metadata.Project, j.Metadata.Name)
	var jails, cpu, pids, addrs int
	var mem int64
	disk := map[string]int64{}
	count := func(x *api.Jail) {
		jails++
		cpu += x.Spec.Resources.CPU
		pids += x.Spec.Resources.PIDs
		m, _ := parseSize(x.Spec.Resources.Memory)
		mem += m
		d, _ := parseSize(x.Spec.Resources.Disk)
		disk[s.storageOf(x)] += d
		addrs += countAddrs(x)
	}
	for _, x := range s.projectJails(j.Metadata.Project) {
		if s.jails.keyIn(x.Metadata.Project, x.Metadata.Name) != self {
			count(x)
		}
	}
	count(j)
	exceeded := func(what string, have, limit any) *api.Error {
		return api.Errorf(api.CodeQuotaExceeded, "project %q would exceed its %s quota (%v of %v)", p.Metadata.Name, what, have, limit)
	}
	if q.Jails > 0 && jails > q.Jails {
		return exceeded("jails", jails, q.Jails)
	}
	if q.CPU > 0 {
		if spec.Resources.CPU == 0 {
			return api.Errorf(api.CodeInvalid, "project %q has a cpu quota: set resources.cpu", p.Metadata.Name)
		}
		if cpu > q.CPU {
			return exceeded("cpu", cpu, q.CPU)
		}
	}
	if q.PIDs > 0 {
		if spec.Resources.PIDs == 0 {
			return api.Errorf(api.CodeInvalid, "project %q has a pids quota: set resources.pids", p.Metadata.Name)
		}
		if pids > q.PIDs {
			return exceeded("pids", pids, q.PIDs)
		}
	}
	if ql, _ := parseSize(q.Memory); ql > 0 {
		if spec.Resources.Memory == "" {
			return api.Errorf(api.CodeInvalid, "project %q has a memory quota: set resources.memory", p.Metadata.Name)
		}
		if mem > ql {
			return exceeded("memory", mem, ql)
		}
	}
	if q.Addresses > 0 && addrs > q.Addresses {
		return exceeded("addresses", addrs, q.Addresses)
	}
	for _, g := range p.Spec.Storage {
		if ql, _ := parseSize(g.Quota); ql > 0 && (g.Storage == storage || g.Storage == "*") && disk[storage] > ql {
			return exceeded("disk on "+storage, disk[storage], ql)
		}
	}
	return nil
}

// storageOf is the storage of a jail after its profiles.
func (s *Server) storageOf(j *api.Jail) string {
	eff, _ := api.ExpandedConfig(j.Spec, s.profilesFor(j.Metadata.Project, j.Spec.Profiles))
	return eff.Storage
}

// ---- storage ----

func (s *Server) setupStorage() {
	k := s.storages
	k.keep = func(dst, old *api.Storage) { dst.Status = old.Status }
	k.visible = func(rc *reqInfo, st *api.Storage) bool {
		if rc.id.Global {
			return true
		}
		for _, p := range rc.id.Projects {
			if pr := s.project(p); pr != nil && granted(s.storGrants(pr), st.Metadata.Name) {
				return true
			}
		}
		return false
	}
	k.validate = func(st, old *api.Storage) *api.Error {
		d := st.Spec.Dataset
		pool, rest, ok := strings.Cut(d, "/")
		if !ok || pool == "" || rest == "" || strings.HasPrefix(d, "/") || strings.HasSuffix(d, "/") || strings.Contains(d, "//") ||
			strings.ContainsAny(d, " \t\n@#") {
			return api.Errorf(api.CodeInvalid, "dataset %q must look like pool/dataset", d)
		}
		if old != nil && old.Spec.Dataset != d {
			return api.Errorf(api.CodeInvalid, "the dataset of a storage cannot change")
		}
		for _, o := range s.storages.items {
			if o.Metadata.Name != st.Metadata.Name && (o.Spec.Dataset == d || strings.HasPrefix(o.Spec.Dataset, d+"/") || strings.HasPrefix(d, o.Spec.Dataset+"/")) {
				return api.Errorf(api.CodeAlreadyExists, "dataset %q overlaps storage %q", d, o.Metadata.Name)
			}
		}
		if st.Spec.Encrypted {
			return api.Errorf(api.CodeUnsupported, "encrypted storage is not implemented")
		}
		return nil
	}
	k.beforeDelete = func(st *api.Storage) *api.Error {
		for _, p := range s.projects.items {
			for _, g := range p.Spec.Storage {
				if g.Storage == st.Metadata.Name {
					return api.Errorf(api.CodeBusy, "storage %q is granted to project %q", g.Storage, p.Metadata.Name)
				}
			}
		}
		for _, j := range s.jails.items {
			if j.Spec.Storage == st.Metadata.Name {
				return api.Errorf(api.CodeBusy, "storage %q is used by jail %q", st.Metadata.Name, j.Metadata.Name)
			}
		}
		return nil
	}
	k.onDelete = func(st *api.Storage) { delete(s.storageStat, st.Metadata.Name) }
	k.decorate = func(st *api.Storage) {
		pool, _, _ := strings.Cut(st.Spec.Dataset, "/")
		st.Status = api.StorageStatus{Pool: pool, Health: "ONLINE", Size: 1 << 40, Used: 1 << 30, Available: 1<<40 - 1<<30}
		if o, ok := s.storageStat[st.Metadata.Name]; ok {
			st.Status = o
			st.Status.Conditions = slices.Clone(o.Conditions)
		}
	}
	s.storages.insert(&api.Storage{Metadata: api.ObjectMeta{Name: DefaultStorage}, Spec: api.StorageSpec{Dataset: "tank/jailops"}}, true)
}

// SetStorageStatus sets the status a storage reports.
func (s *Server) SetStorageStatus(name string, st api.StorageStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storageStat[name] = st
}

// ---- access: visibility of host-level kinds, certificates, backups ----

func (s *Server) setupAccess() {
	s.networks.visible = func(rc *reqInfo, n *api.Network) bool {
		if rc.id.Global {
			return true
		}
		for _, p := range rc.id.Projects {
			if pr := s.project(p); pr != nil && granted(s.netGrants(pr), n.Metadata.Name) {
				return true
			}
		}
		return false
	}
	s.images.visible = func(rc *reqInfo, im *api.Image) bool {
		if rc.id.Global {
			return true
		}
		for _, p := range rc.id.Projects {
			if pr := s.project(p); pr != nil && (len(pr.Spec.Images) == 0 || slices.Contains(pr.Spec.Images, im.Metadata.Name)) {
				return true
			}
		}
		return false
	}
	s.backups.visible = func(rc *reqInfo, b *api.Backup) bool { return rc.canProject(projectOr(b.Metadata.Project)) }
	// A project's mandatory firewall policy is for global admins to change.
	s.policies.guard = func(rc *reqInfo, pol *api.FirewallPolicy, verb string) *api.Error {
		if verb == "create" || rc.id.Global {
			return nil
		}
		if p := s.project(pol.Metadata.Project); p != nil && slices.Contains(p.Spec.FirewallPolicies, pol.Metadata.Name) {
			return api.Errorf(api.CodeForbidden, "the mandatory firewall policy of project %q can only be changed by a global admin", p.Metadata.Name)
		}
		return nil
	}
	s.certs.alias = func(key string) string {
		fp := normFP(key)
		for _, c := range s.certs.items {
			if normFP(c.Spec.Fingerprint) == fp {
				return c.Metadata.Name
			}
		}
		return ""
	}
	s.certs.validate = func(c, _ *api.Certificate) *api.Error {
		if e := validIdentityScope(c.Spec.Projects, c.Spec.Global); e != nil {
			return e
		}
		return s.checkProjectsExist(c.Spec.Projects)
	}
	s.users.validate = func(u, _ *api.User) *api.Error {
		if e := validIdentityScope(u.Spec.Projects, u.Spec.Global); e != nil {
			return e
		}
		return s.checkProjectsExist(u.Spec.Projects)
	}
}

func (s *Server) checkProjectsExist(ps []string) *api.Error {
	for _, p := range ps {
		if s.projects.items[p] == nil {
			return api.Errorf(api.CodeInvalid, "project %q does not exist", p)
		}
	}
	return nil
}

// ---- fleet projects (hub) ----

func (s *Server) hostFor(h string) *Server {
	if t := s.hosts[h]; t != nil {
		return t
	}
	for _, t := range s.hosts {
		if t.uuid == h {
			return t
		}
	}
	return nil
}

// SetOffline simulates a host that cannot be reached by this hub.
func (s *Server) SetOffline(host string, off bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if off {
		s.offline[host] = true
	} else {
		delete(s.offline, host)
	}
}

func (s *Server) isOffline(host string, t *Server) bool {
	return s.offline[host] || (t != nil && s.offline[t.uuid])
}

// ReconcileFleet applies every fleet project of this hub to its hosts again;
// hosts that were offline catch up.
func (s *Server) ReconcileFleet() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, p := range s.projects.items {
		if len(p.Spec.Hosts) > 0 {
			s.applyFleet(name)
		}
	}
}

// applyFleet applies one project to its hosts and records a condition per
// host. s.mu is held.
func (s *Server) applyFleet(name string) {
	p := s.projects.items[name]
	if !s.hub || p == nil || len(p.Spec.Hosts) == 0 {
		return
	}
	var conds []api.Condition
	owner := "hub:" + s.uuid
	for _, h := range p.Spec.Hosts {
		c := api.Condition{Type: "Host:" + h, Since: s.now()}
		t := s.hostFor(h)
		switch {
		case t == nil:
			c.Status, c.Reason, c.Message = api.ConditionFalse, "Unknown", "host is not known to this hub"
		case s.isOffline(h, t):
			c.Status, c.Reason, c.Message = api.ConditionFalse, "Offline", "host cannot be reached; it is retried"
		case t == s:
			c.Status, c.Reason, c.Message = api.ConditionTrue, "Applied", "this hub holds the project itself"
		default:
			c.Status, c.Reason, c.Message = t.receiveProject(p, owner)
		}
		conds = append(conds, c)
	}
	s.fleetConds[name] = conds
}

// receiveProject stores a hub's project definition on this host.
func (s *Server) receiveProject(p *api.Project, owner string) (status, reason, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range p.Spec.Networks {
		if g.Network != "*" && s.networks.items[g.Network] == nil {
			return api.ConditionFalse, "MissingNetwork", fmt.Sprintf("network %q does not exist on this host", g.Network)
		}
	}
	for _, g := range p.Spec.Storage {
		if g.Storage != "*" && s.storages.items[g.Storage] == nil {
			return api.ConditionFalse, "MissingStorage", fmt.Sprintf("storage %q does not exist on this host", g.Storage)
		}
	}
	name := p.Metadata.Name
	cp := clone(p)
	cp.Status = api.ProjectStatus{}
	if cur := s.projects.items[name]; cur != nil {
		if cur.Metadata.ManagedBy != owner {
			return api.ConditionFalse, "Conflict", "a project of that name exists and is not managed by this hub"
		}
		a, _ := json.Marshal(cur.Spec)
		b, _ := json.Marshal(cp.Spec)
		if string(a) != string(b) {
			cur.Spec = cp.Spec
			cur.Metadata.Generation++
			cur.Metadata.UpdatedAt = s.now()
			s.emitIn(name, "project-updated", "/api/v1/projects/"+name)
		}
		return api.ConditionTrue, "Applied", "the project is in sync"
	}
	cp.Metadata = api.ObjectMeta{Name: name, UUID: p.Metadata.UUID, ManagedBy: owner}
	s.projects.insert(&cp, false)
	return api.ConditionTrue, "Applied", "the project was created"
}

func (s *Server) deleteFleet(p *api.Project) {
	if !s.hub {
		return
	}
	owner := "hub:" + s.uuid
	for _, h := range p.Spec.Hosts {
		t := s.hostFor(h)
		if t == nil || s.isOffline(h, t) {
			continue
		}
		t.mu.Lock()
		if cur := t.projects.items[p.Metadata.Name]; cur != nil && cur.Metadata.ManagedBy == owner && !t.projectUsed(p.Metadata.Name) {
			delete(t.projects.items, p.Metadata.Name)
		}
		t.mu.Unlock()
	}
	delete(s.fleetConds, p.Metadata.Name)
}

// aggregate builds the host=all reply of a project on a hub. auth is the
// caller's Authorization header, so every host applies its own scoping.
func (s *Server) aggregate(w http.ResponseWriter, r *http.Request, name string) {
	s.mu.Lock()
	p := s.projects.items[name]
	var def api.Project
	if p != nil {
		def = clone(p)
		def.Status = s.projectUsage(name)
	}
	hosts := slices.Clone(def.Spec.Hosts)
	s.mu.Unlock()
	if p == nil {
		writeErr(w, notFound("project", name))
		return
	}
	out := api.ProjectAggregate{Project: def, Hosts: []api.ProjectHostStatus{}}
	for _, h := range hosts {
		hs := api.ProjectHostStatus{Host: h}
		s.mu.Lock()
		t := s.hostFor(h)
		off := s.isOffline(h, t)
		s.mu.Unlock()
		switch {
		case t == nil:
			hs.Error = api.Errorf(api.CodeNotFound, "host %q is not known to this hub", h)
		case off:
			hs.Error = api.Errorf(api.CodeBusy, "host %q is offline", h)
			hs.HostUUID = t.uuid
		default:
			hs.Online, hs.HostUUID = true, t.uuid
			req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+name, nil)
			if a := r.Header.Get("Authorization"); a != "" {
				req.Header.Set("Authorization", a)
			}
			rec := httptest.NewRecorder()
			t.ServeHTTP(rec, req)
			var env api.Response
			_ = json.Unmarshal(rec.Body.Bytes(), &env)
			switch {
			case env.Error != nil && env.Error.Code == api.CodeNotFound:
			case env.Error != nil:
				hs.Error = env.Error
			default:
				var hp api.Project
				_ = json.Unmarshal(env.Metadata, &hp)
				hs.Applied, hs.Generation = true, hp.Metadata.Generation
				st := hp.Status
				hs.Status = &st
				a, _ := json.Marshal(def.Spec)
				b, _ := json.Marshal(hp.Spec)
				hs.InSync = string(a) == string(b)
				out.Total.Jails += st.Jails
				out.Total.CPU += st.CPU
				out.Total.MemoryUsed += st.MemoryUsed
				out.Total.DiskUsed += st.DiskUsed
				out.Total.Addresses += st.Addresses
			}
		}
		s.mu.Lock()
		for _, c := range s.fleetConds[name] {
			if c.Type == "Host:"+h {
				hs.Conditions = append(hs.Conditions, c)
			}
		}
		s.mu.Unlock()
		out.Hosts = append(out.Hosts, hs)
	}
	writeSync(w, 200, out)
}
