package fake

import (
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

func (s *Server) setupJails() {
	k := s.jails
	k.asyncCreate, k.asyncDelete = true, true
	k.keep = func(dst, old *api.Jail) { dst.Status = old.Status }
	k.expand = func(j *api.Jail) any { return s.jailExpanded(j) }
	k.validate = func(j, old *api.Jail) *api.Error {
		if j.Spec.Image == "" {
			return api.Errorf(api.CodeInvalid, "spec.image is required")
		}
		if e := s.checkJail(j, old); e != nil {
			return e
		}
		if e := s.checkAttachments(j, old); e != nil {
			return e
		}
		if s.images.items[imageName(j.Spec.Image)] == nil {
			return notFound("image", imageName(j.Spec.Image)).WithHint(s.imageCreateHint(j.Spec.Image))
		}
		if j.Spec.Delegate && (old == nil || !old.Spec.Delegate) {
			// Only a global admin may delegate ZFS; the check lives in guard.
			return nil
		}
		return nil
	}
	k.guard = func(rc *reqInfo, j *api.Jail, verb string) *api.Error {
		if verb != "delete" && j.Spec.Delegate && !rc.id.Global {
			return api.Errorf(api.CodeForbidden, "only a global admin may delegate ZFS to a jail")
		}
		return nil
	}
	k.assign = func(j, old *api.Jail) *api.Error {
		if e := s.assignJail(j, old); e != nil {
			return e
		}
		if old == nil {
			s.initJailStatus(j)
		}
		return nil
	}
	k.beforeDelete = func(j *api.Jail) *api.Error {
		if j.Status.Power == api.PowerRunning {
			return api.Errorf(api.CodeBusy, "jail %q is running", j.Metadata.Name).WithHint("stop it first")
		}
		return nil
	}
	k.onDelete = func(j *api.Jail) {
		delete(s.snapshots, j.Metadata.Project+"/"+j.Metadata.Name)
		delete(s.access, j.Metadata.Project+"/"+j.Metadata.Name)
	}
}

// assignJail fills defaults and allocates "auto" addresses. s.mu is held.
func (s *Server) assignJail(j, old *api.Jail) *api.Error {
	if j.Spec.Layout == "" {
		j.Spec.Layout = api.LayoutThin
	}
	if j.Spec.Hostname == "" {
		j.Spec.Hostname = j.Metadata.Name
	}
	for i := range j.Spec.Network {
		a := &j.Spec.Network[i]
		// Saying nothing about addresses means one of every family the network has.
		if a.IPv4 == "" && a.IPv6 == "" {
			if n := s.networks.items[a.Network]; n != nil {
				if n.Spec.IPv4 != nil {
					a.IPv4 = "auto"
				}
				if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode != api.IPv6None {
					a.IPv6 = "auto"
				}
			}
		}
		for _, v6 := range []bool{false, true} {
			p := &a.IPv4
			if v6 {
				p = &a.IPv6
			}
			switch *p {
			case "", "none":
			case "auto":
				addr, e := s.allocate(a.Network, v6, j.Metadata.Project, j.Metadata.Name)
				if e != nil {
					return e
				}
				*p = addr
			default:
				if e := s.checkFixed(a.Network, *p, j.Metadata.Project, j.Metadata.Name); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

func (s *Server) initJailStatus(j *api.Jail) {
	j.Status = api.JailStatus{Power: api.PowerStopped, Generation: "g1"}
	if i := strings.IndexByte(j.Spec.Image, '#'); i >= 0 {
		j.Status.Generation = j.Spec.Image[i+1:]
	} else if g := s.gens[imageName(j.Spec.Image)]; len(g) > 0 {
		j.Status.Generation = "g" + strconv.Itoa(g[len(g)-1].Number)
	}
}

func (s *Server) jailState(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	_, j := s.jails.find(r, r.PathValue("name"))
	var st api.JailStatus
	if j != nil {
		st = clone(j).Status
	}
	s.mu.Unlock()
	if j == nil {
		writeErr(w, notFound("jail", r.PathValue("name")))
		return
	}
	writeSync(w, 200, st)
}

// SeedJailUsage sets what GET /api/v1/jails/{name}/usage answers for a jail;
// power and the jail name are filled in from the jail when the reply is
// built. Without it a running jail reports fixed numbers and a stopped jail
// only its disk.
func (s *Server) SeedJailUsage(project, name string, u api.JailUsage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usage == nil {
		s.usage = map[string]api.JailUsage{}
	}
	s.usage[project+"/"+name] = u
}

func (s *Server) jailUsage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	key, j := s.jails.find(r, r.PathValue("name"))
	var u api.JailUsage
	if j != nil {
		seeded, ok := s.usage[key]
		switch {
		case ok:
			u = seeded
		case j.Status.Power == api.PowerRunning:
			u = api.JailUsage{Accounting: &api.JailAccounting{Processes: 23, CPUSeconds: 8013, MemoryBytes: 407048192}}
		}
		if !ok {
			u.Disk = api.JailDiskUsage{RootBytes: 268435456, RootReferencedBytes: 1610612736, DataBytes: 73400320}
		}
		u.Jail, u.Power, u.MeasuredAt = j.Metadata.Name, j.Status.Power, s.now().UTC()
		if u.Power != api.PowerRunning {
			u.Accounting = nil
		}
	}
	s.mu.Unlock()
	if j == nil {
		writeErr(w, notFound("jail", r.PathValue("name")))
		return
	}
	writeSync(w, 200, u)
}

func (s *Server) jailAction(w http.ResponseWriter, r *http.Request) {
	act, e := decode[api.JailAction](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	rc := s.info(r)
	jk := s.jails.key(r, name)
	s.mu.Lock()
	rp := func() reply {
		if s.jails.items[jk] == nil {
			return reply{err: notFound("jail", name)}
		}
		switch act.Action {
		case "start", "stop", "restart":
		default:
			return reply{err: api.Errorf(api.CodeInvalid, "unknown action %q", act.Action)}
		}
		if l := s.jails.items[jk].Status.Locked; act.Action != "stop" && len(l) > 0 {
			return reply{err: api.Errorf(api.CodeLocked, "jail %q is locked: the encrypted volume(s) %s wait for a passphrase", name, strings.Join(l, ", ")).
				WithHint("jailops volume unlock " + l[0])}
		}
		if act.Action != "stop" {
			for _, a := range s.jails.items[jk].Spec.Volumes {
				if v := s.volumes.items[rc.project+"/"+a.Name]; v != nil && v.Spec.IsHostDir() && s.vol.lostDirs[v.Spec.Path] {
					return reply{err: api.Errorf(api.CodeBusy, "volume %q is lost: the directory is not on a mount (%s)", a.Name, v.Spec.Path).
						WithHint("mount it again; the jail starts when it is there")}
				}
			}
		}
		op := s.startOp(rc.project, "jails."+act.Action, act.Action+" jail "+name, map[string][]string{"jails": {"/api/v1/jails/" + name}}, func() (any, *api.Error) {
			j := s.jails.items[jk]
			if j == nil {
				return nil, notFound("jail", name)
			}
			if act.Action != "start" {
				j.Status.Power, j.Status.JID, j.Status.StartedAt, j.Status.Addresses = api.PowerStopped, 0, time.Time{}, nil
			}
			if act.Action != "stop" && j.Status.Power != api.PowerRunning {
				s.nextJID++
				j.Status.Power, j.Status.JID, j.Status.StartedAt = api.PowerRunning, s.nextJID, s.now()
				j.Status.Addresses = nil
				for _, a := range j.Spec.Network {
					for _, ad := range []string{a.IPv4, a.IPv6} {
						if ad != "" && ad != "none" && ad != "auto" {
							j.Status.Addresses = append(j.Status.Addresses, ad)
						}
					}
				}
			}
			s.emitIn(rc.project, "jail-"+map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"}[act.Action], "/api/v1/jails/"+name)
			return clone(j), nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// --- snapshots ---

func (s *Server) snapList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	jk := s.jails.key(r, name)
	s.mu.Lock()
	out := []api.JailSnapshot{}
	for _, sn := range s.snapshots[jk] {
		out = append(out, clone(sn))
	}
	exists := s.jails.items[jk] != nil
	s.mu.Unlock()
	if !exists {
		writeErr(w, notFound("jail", name))
		return
	}
	writeSync(w, 200, out)
}

func (s *Server) findSnap(jail, snap string) *api.JailSnapshot {
	for _, sn := range s.snapshots[jail] {
		if sn.Metadata.Name == snap {
			return sn
		}
	}
	return nil
}

func (s *Server) snapGet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	var out api.JailSnapshot
	sn := s.findSnap(s.jails.key(r, r.PathValue("name")), r.PathValue("snap"))
	if sn != nil {
		out = clone(sn)
	}
	s.mu.Unlock()
	if sn == nil {
		writeErr(w, notFound("snapshot", r.PathValue("snap")))
		return
	}
	writeSync(w, 200, out)
}

func (s *Server) snapCreate(w http.ResponseWriter, r *http.Request) {
	req, e := decode[api.JailSnapshot](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	jail := r.PathValue("name")
	rc := s.info(r)
	jk := s.jails.key(r, jail)
	s.mu.Lock()
	rp := func() reply {
		if s.jails.items[jk] == nil {
			return reply{err: notFound("jail", jail)}
		}
		name := req.Metadata.Name
		if name == "" {
			name = "snap-" + randHex(3)
		}
		if !validName(name) {
			return reply{err: api.Errorf(api.CodeInvalid, "invalid snapshot name %q", name)}
		}
		if s.findSnap(jk, name) != nil {
			return reply{err: api.Errorf(api.CodeAlreadyExists, "snapshot %q already exists", name)}
		}
		op := s.startOp(rc.project, "jails.snapshot", "Snapshot "+jail, map[string][]string{"jails": {"/api/v1/jails/" + jail}}, func() (any, *api.Error) {
			if s.jails.items[jk] == nil {
				return nil, notFound("jail", jail)
			}
			sn := &api.JailSnapshot{
				Metadata: api.ObjectMeta{Name: name, UUID: newUUID(), Project: rc.project, Scope: api.ScopeHost, Host: s.uuid, Generation: 1, CreatedAt: s.now(), UpdatedAt: s.now()},
				Spec:     api.JailSnapshotSpec{Jail: jail, Comment: req.Spec.Comment},
			}
			s.snapshots[jk] = append(s.snapshots[jk], sn)
			s.emitIn(rc.project, "jail-snapshot-created", "/api/v1/jails/"+jail+"/snapshots/"+name)
			return clone(sn), nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) snapDelete(w http.ResponseWriter, r *http.Request) {
	jail, snap := r.PathValue("name"), r.PathValue("snap")
	rc := s.info(r)
	jk := s.jails.key(r, jail)
	s.mu.Lock()
	rp := func() reply {
		if s.findSnap(jk, snap) == nil {
			return reply{err: notFound("snapshot", snap)}
		}
		op := s.startOp(rc.project, "jails.snapshot-delete", "Delete snapshot "+snap, nil, func() (any, *api.Error) {
			l := s.snapshots[jk]
			for i, sn := range l {
				if sn.Metadata.Name == snap {
					s.snapshots[jk] = append(l[:i:i], l[i+1:]...)
					s.emitIn(rc.project, "jail-snapshot-deleted", "/api/v1/jails/"+jail+"/snapshots/"+snap)
					return nil, nil
				}
			}
			return nil, notFound("snapshot", snap)
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// --- rollback and upgrade ---

func (s *Server) jailRollback(w http.ResponseWriter, r *http.Request) {
	rb, e := decode[api.JailRollback](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	rc := s.info(r)
	jk := s.jails.key(r, name)
	s.mu.Lock()
	rp := func() reply {
		j := s.jails.items[jk]
		if j == nil {
			return reply{err: notFound("jail", name)}
		}
		if rb.Scope == "" {
			rb.Scope = api.RollbackRoot
		}
		var target *api.JailSnapshot
		switch rb.Scope {
		case api.RollbackRoot:
			if genNumber(j.Status.Generation) <= 1 {
				return reply{err: api.Errorf(api.CodeInvalid, "jail %q has no previous generation", name)}
			}
		case api.RollbackData, api.RollbackAll:
			if !rb.ConfirmDataLoss {
				return reply{err: api.Errorf(api.CodeDataLoss, "scope %q discards data written since the snapshot", rb.Scope).
					WithHint("set confirm_data_loss after checking what was written")}
			}
			l := s.snapshots[jk]
			if rb.Snapshot == "" && len(l) > 0 {
				target = l[len(l)-1]
			} else if target = s.findSnap(jk, rb.Snapshot); target == nil {
				return reply{err: notFound("snapshot", rb.Snapshot)}
			}
		default:
			return reply{err: api.Errorf(api.CodeInvalid, "unknown rollback scope %q", rb.Scope)}
		}
		op := s.startOp(rc.project, "jails.rollback", "Rollback "+name, map[string][]string{"jails": {"/api/v1/jails/" + name}}, func() (any, *api.Error) {
			j := s.jails.items[jk]
			if j == nil {
				return nil, notFound("jail", name)
			}
			if rb.Scope != api.RollbackData {
				j.Status.Generation = "g" + strconv.Itoa(genNumber(j.Status.Generation)-1)
			}
			if target != nil { // ZFS discards snapshots newer than the target
				l := s.snapshots[jk]
				for i, sn := range l {
					if sn == target {
						s.snapshots[jk] = l[:i+1]
					}
				}
			}
			s.emitIn(rc.project, "jail-rolled-back", "/api/v1/jails/"+name)
			return clone(j), nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) jailUpgrade(w http.ResponseWriter, r *http.Request) {
	up, e := decode[api.JailUpgrade](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	rc := s.info(r)
	jk := s.jails.key(r, name)
	s.mu.Lock()
	rp := func() reply {
		j := s.jails.items[jk]
		if j == nil {
			return reply{err: notFound("jail", name)}
		}
		gens := s.gens[imageName(j.Spec.Image)]
		target := genNumber(up.Generation)
		if up.Generation == "" && len(gens) > 0 {
			target = gens[len(gens)-1].Number
		}
		if target == 0 || target > len(gens) {
			return reply{err: api.Errorf(api.CodeInvalid, "target generation does not exist")}
		}
		if target == genNumber(j.Status.Generation) {
			return reply{err: api.Errorf(api.CodeInvalid, "jail %q is already on generation g%d", name, target)}
		}
		op := s.startOp(rc.project, "jails.upgrade", "Upgrade "+name, map[string][]string{"jails": {"/api/v1/jails/" + name}}, func() (any, *api.Error) {
			j := s.jails.items[jk]
			if j == nil {
				return nil, notFound("jail", name)
			}
			if !up.DryRun {
				j.Status.Generation = "g" + strconv.Itoa(target)
				if i := strings.IndexByte(j.Spec.Image, '#'); i >= 0 {
					j.Spec.Image = j.Spec.Image[:i+1] + j.Status.Generation
					j.Metadata.Generation++
				}
				s.emitIn(rc.project, "jail-upgraded", "/api/v1/jails/"+name)
			}
			return clone(j), nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// --- networks and IPAM ---

func (s *Server) setupNetworks() {
	k := s.networks
	k.keep = func(dst, old *api.Network) { dst.Status = old.Status }
	// The real daemon warns, in the answer of a create, when the host does not answer the off-link neighbor
	// solicitations a shared IPv6 segment's routers send (the sysctl is 0; see WithSysctl).
	k.created = func(n *api.Network) {
		const oid = "net.inet6.icmp6.nd6_onlink_ns_rfc4861"
		if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode == api.IPv6Proxy && s.sysctls[oid] == "0" {
			n.Status.Warnings = append(n.Status.Warnings, oid+" is 0: the routers of a shared IPv6 segment probe the host's address from their global addresses and FreeBSD drops those solicitations as off-link, so the host (and its jails) is unreachable over IPv6 for minutes every few hours; run `sysctl "+oid+"=1` and add `"+oid+"=1` to /etc/sysctl.conf (JailOps never sets it)")
		}
	}
	k.validate = func(n, _ *api.Network) *api.Error {
		if n.Spec.IPv4 == nil && n.Spec.IPv6 == nil {
			return api.Errorf(api.CodeInvalid, "a network needs ipv4 or ipv6")
		}
		for _, v := range []*struct{ sub, rng string }{
			func() *struct{ sub, rng string } {
				if n.Spec.IPv4 != nil {
					return &struct{ sub, rng string }{n.Spec.IPv4.Subnet, n.Spec.IPv4.Range}
				}
				return nil
			}(),
			func() *struct{ sub, rng string } {
				if n.Spec.IPv6 != nil {
					return &struct{ sub, rng string }{n.Spec.IPv6.Subnet, n.Spec.IPv6.Range}
				}
				return nil
			}(),
		} {
			if v == nil {
				continue
			}
			if _, err := netip.ParsePrefix(v.sub); err != nil {
				return api.Errorf(api.CodeInvalid, "invalid subnet %q", v.sub)
			}
			if _, _, err := parseRange(v.rng); err != nil {
				return api.Errorf(api.CodeInvalid, "invalid range %q", v.rng)
			}
		}
		return nil
	}
	k.beforeDelete = func(n *api.Network) *api.Error {
		for _, p := range s.projects.items {
			for _, g := range p.Spec.Networks {
				if g.Network == n.Metadata.Name {
					return api.Errorf(api.CodeBusy, "network %q is granted to project %q", n.Metadata.Name, p.Metadata.Name).WithHint("remove the grant first")
				}
			}
		}
		for _, j := range s.jails.items {
			for _, a := range j.Spec.Network {
				if a.Network == n.Metadata.Name {
					return api.Errorf(api.CodeBusy, "network %q is used by jail %q", n.Metadata.Name, j.Metadata.Name)
				}
			}
		}
		return nil
	}
	k.decorate = func(n *api.Network) {
		n.Status.Allocated = len(s.leasesOf(n.Metadata.Name))
		if n.Spec.IPv4 != nil {
			if a, b, err := parseRange(n.Spec.IPv4.Range); err == nil && a.Is4() {
				total := int(addrNum(b)-addrNum(a)) + 1
				n.Status.Free = max(total-n.Status.Allocated, 0)
			}
		}
	}
}

func addrNum(a netip.Addr) uint64 {
	b := a.As16()
	var n uint64
	for _, x := range b[8:] {
		n = n<<8 | uint64(x)
	}
	return n
}

func parseRange(r string) (netip.Addr, netip.Addr, error) {
	a, b, ok := strings.Cut(r, "-")
	if !ok {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("range must be a-b")
	}
	x, err := netip.ParseAddr(strings.TrimSpace(a))
	if err != nil {
		return x, x, err
	}
	y, err := netip.ParseAddr(strings.TrimSpace(b))
	if err != nil {
		return x, y, err
	}
	if x.Is4() != y.Is4() || y.Less(x) {
		return x, y, fmt.Errorf("bad range")
	}
	return x, y, nil
}

func addrOf(s string) (netip.Addr, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), true
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil
}

type lease struct {
	api.Lease
	project, key string
}

func (s *Server) leasesOf(network string) []lease {
	var out []lease
	keys := make([]string, 0, len(s.jails.items))
	for n := range s.jails.items {
		keys = append(keys, n)
	}
	sort.Strings(keys)
	for _, key := range keys {
		j := s.jails.items[key]
		for _, a := range j.Spec.Network {
			if a.Network != network {
				continue
			}
			for _, ad := range []string{a.IPv4, a.IPv6} {
				if _, ok := addrOf(ad); ok {
					out = append(out, lease{api.Lease{Address: ad, Jail: j.Metadata.Name, Network: network}, j.Metadata.Project, key})
				}
			}
		}
	}
	return out
}

// usedAddrs maps every address in use on a network, across all projects, to
// its owner's key; the jail self is left out.
func (s *Server) usedAddrs(network, self string) map[netip.Addr]string {
	used := map[netip.Addr]string{}
	for _, l := range s.leasesOf(network) {
		if l.key != self {
			a, _ := addrOf(l.Address)
			used[a] = l.Jail
		}
	}
	return used
}

func (s *Server) allocate(network string, v6 bool, project, jail string) (string, *api.Error) {
	self := s.jails.keyIn(project, jail)
	n := s.networks.items[network]
	if n == nil {
		return "", notFound("network", network)
	}
	var rng, gw string
	var excl []string
	if v6 && n.Spec.IPv6 != nil {
		rng, excl = n.Spec.IPv6.Range, n.Spec.IPv6.Exclude
	} else if !v6 && n.Spec.IPv4 != nil {
		rng, gw, excl = n.Spec.IPv4.Range, n.Spec.IPv4.Gateway, n.Spec.IPv4.Exclude
	} else {
		return "", api.Errorf(api.CodeInvalid, "network %q has no such address family", network)
	}
	lo, hi, err := parseRange(rng)
	if err != nil {
		return "", api.Errorf(api.CodeInvalid, "network %q has a bad range", network)
	}
	used := s.usedAddrs(network, self)
	if g, ok := addrOf(gw); ok {
		used[g] = "gateway"
	}
	for a := lo; a.IsValid() && !hi.Less(a); a = a.Next() {
		if _, taken := used[a]; taken || excluded(excl, a) {
			continue
		}
		return a.String(), nil
	}
	return "", api.Errorf(api.CodePoolExhausted, "network %q has no free address for project %q", network, project)
}

func excluded(ex []string, a netip.Addr) bool {
	for _, e := range ex {
		if lo, hi, err := parseRange(e); err == nil {
			if !a.Less(lo) && !hi.Less(a) {
				return true
			}
		} else if x, ok := addrOf(e); ok && x == a {
			return true
		}
	}
	return false
}

func (s *Server) checkFixed(network, addr, project, jail string) *api.Error {
	a, ok := addrOf(addr)
	if !ok {
		return api.Errorf(api.CodeInvalid, "invalid address %q", addr)
	}
	if n := s.networks.items[network]; n != nil {
		sub := ""
		if a.Is6() && n.Spec.IPv6 != nil {
			sub = n.Spec.IPv6.Subnet
		} else if !a.Is6() && n.Spec.IPv4 != nil {
			sub = n.Spec.IPv4.Subnet
		}
		if pf, err := netip.ParsePrefix(sub); err != nil || !pf.Contains(a) {
			return api.Errorf(api.CodeInvalid, "address %s is outside the subnet of network %q", addr, network)
		}
	}
	if owner, taken := s.usedAddrs(network, s.jails.keyIn(project, jail))[a]; taken {
		return api.Errorf(api.CodeIPConflict, "address %s is already used by jail %q", addr, owner).WithDetail("address", addr)
	}
	return nil
}

func (s *Server) leases(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rc := s.info(r)
	s.mu.Lock()
	_, nw := s.networks.find(r, name)
	var out []api.Lease
	if nw != nil {
		for _, l := range s.leasesOf(name) {
			if rc.canProject(l.project) {
				out = append(out, l.Lease)
			}
		}
	}
	s.mu.Unlock()
	if nw == nil {
		writeErr(w, notFound("network", name))
		return
	}
	if out == nil {
		out = []api.Lease{}
	}
	writeSync(w, 200, out)
}

// --- images ---

func (s *Server) setupImages() {
	k := s.images
	k.keep = func(dst, old *api.Image) { dst.Status = old.Status }
	k.validate = func(i, _ *api.Image) *api.Error {
		if i.Spec.OS == "" || i.Spec.Release == "" {
			return api.Errorf(api.CodeInvalid, "spec.os and spec.release are required")
		}
		if au := i.Spec.AutoUpgrade; au != nil && au.At != "" {
			if _, err := time.Parse("15:04", au.At); err != nil || len(au.At) != 5 {
				return api.Errorf(api.CodeInvalid, "spec.auto_upgrade.at %q is not a time of day such as 03:00", au.At)
			}
		}
		return nil
	}
	k.beforeDelete = func(i *api.Image) *api.Error {
		for _, j := range s.jails.items {
			if imageName(j.Spec.Image) == i.Metadata.Name {
				return api.Errorf(api.CodeImageInUse, "image %q is used by jail %q", i.Metadata.Name, j.Metadata.Name)
			}
		}
		return nil
	}
	k.onDelete = func(i *api.Image) {
		delete(s.gens, i.Metadata.Name)
		delete(s.genMax, i.Metadata.Name)
		delete(s.aliases, i.Metadata.Name)
	}
	k.decorate = func(i *api.Image) {
		i.Status.Generations = nil
		for _, g := range s.gens[i.Metadata.Name] {
			c := clone(g)
			c.Refs = s.genRefs(i.Metadata.Name, g.Number)
			i.Status.Generations = append(i.Status.Generations, c)
		}
		i.Status.Aliases = nil
		if len(s.aliases[i.Metadata.Name]) > 0 {
			i.Status.Aliases = maps.Clone(s.aliases[i.Metadata.Name])
		}
		i.Status.AutoUpgrade = nil
		if au := i.Spec.AutoUpgrade; au != nil && au.Enabled {
			i.Status.AutoUpgrade = &api.ImageAutoUpgradeStatus{Next: nextAt(s.now(), au.At)}
		}
	}
}

// nextAt is the next time of day at (HH:MM, empty for the default) after now, in now's zone.
func nextAt(now time.Time, at string) time.Time {
	if at == "" {
		at = api.DefaultAutoUpgradeAt
	}
	t, err := time.Parse("15:04", at)
	if err != nil {
		return time.Time{}
	}
	next := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

func (s *Server) genRefs(image string, n int) []string {
	var refs []string
	for _, j := range s.jails.items {
		if imageName(j.Spec.Image) == image && genNumber(j.Status.Generation) == n {
			refs = append(refs, j.Metadata.Name)
		}
	}
	sort.Strings(refs)
	return refs
}

func (s *Server) genList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	_, im := s.images.find(r, name)
	exists := im != nil
	out := []api.ImageGeneration{}
	for _, g := range s.gens[name] {
		c := clone(g)
		c.Refs = s.genRefs(name, g.Number)
		out = append(out, c)
	}
	s.mu.Unlock()
	if !exists {
		writeErr(w, notFound("image", name))
		return
	}
	writeSync(w, 200, out)
}

func (s *Server) genBuild(w http.ResponseWriter, r *http.Request) {
	b, e := decode[api.ImageBuild](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	s.mu.Lock()
	rp := func() reply {
		if s.images.items[name] == nil {
			return reply{err: notFound("image", name)}
		}
		if b.FromGeneration < 0 || (b.FromGeneration > 0 && s.findGen(name, b.FromGeneration) == nil) {
			return reply{err: api.Errorf(api.CodeInvalid, "generation g%d does not exist", b.FromGeneration)}
		}
		op := s.startOp("", "images.build", "Build "+name, map[string][]string{"images": {"/api/v1/images/" + name}}, func() (any, *api.Error) {
			if s.images.items[name] == nil {
				return nil, notFound("image", name)
			}
			n := s.nextGen(name)
			g := &api.ImageGeneration{
				Number: n, Name: fmt.Sprintf("%s#g%d", name, n), Parent: b.FromGeneration,
				Manifest: "sha256:" + randHex(16), Packages: 120, CreatedAt: s.now(),
				Dataset: fmt.Sprintf("tank/jailops/images/%s/g%d", name, n),
			}
			if !b.DryRun {
				s.gens[name] = append(s.gens[name], g)
				s.genMax[name] = n
				s.followAliases(name, n)
				s.emit("image-generation-created", "/api/v1/images/"+name+"/generations/"+strconv.Itoa(n))
			}
			return clone(g), nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// imageUpgrade implements POST /api/v1/images/{name}/upgrade: the next
// generation from the newest one, then every thin jail of the image through
// the OS update of applyTo, stopping at the first failure. An image seeded
// with SeedImageCurrent has nothing to upgrade: no generation, no moves.
func (s *Server) imageUpgrade(w http.ResponseWriter, r *http.Request) {
	u, e := decodeOptional[api.ImageUpgrade](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	rc := s.info(r)
	s.mu.Lock()
	rp := func() reply {
		if s.images.items[name] == nil {
			return reply{err: notFound("image", name)}
		}
		if u.Project != "" && (s.projects.items[u.Project] == nil || !rc.canProject(u.Project)) {
			return reply{err: notFound("project", u.Project)}
		}
		from := 0
		for _, g := range s.gens[name] {
			from = max(from, g.Number)
		}
		if from == 0 {
			return reply{err: api.Errorf(api.CodeNotFound, "image %q has no generation to upgrade", name).
				WithHint("build the first one with 'jailops image build " + name + "'")}
		}
		var keys []string
		for k, j := range s.jails.items {
			if imageName(j.Spec.Image) == name && rc.canProject(j.Metadata.Project) && (u.Project == "" || j.Metadata.Project == u.Project) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		res := map[string][]string{"images": {"/api/v1/images/" + name}}
		op := s.startOp("", "images.upgrade", "Upgrade image "+name, res, func() (any, *api.Error) {
			if s.images.items[name] == nil {
				return nil, notFound("image", name)
			}
			out := api.ImageUpgradeResult{From: fmt.Sprintf("%s#g%d", name, from), DryRun: u.DryRun, Unchanged: s.imgSame[name], Jails: []api.ImageUpgradeJail{}}
			n := s.nextGen(name)
			out.Plan = []string{fmt.Sprintf("zfs clone tank/jailops/images/%s/g%d@ro tank/jailops/images/%s/staging-g%d", name, from, name, n),
				fmt.Sprintf("pkg -r /jailops/images/%s/staging-g%d upgrade -y -r jailops", name, n)}
			if !u.DryRun && !out.Unchanged {
				g := &api.ImageGeneration{Number: n, Name: fmt.Sprintf("%s#g%d", name, n), Parent: from,
					Manifest: "sha256:" + randHex(16), Packages: 120, CreatedAt: s.now(), Dataset: fmt.Sprintf("tank/jailops/images/%s/g%d", name, n)}
				s.gens[name] = append(s.gens[name], g)
				s.genMax[name] = n
				s.followAliases(name, n)
				s.emit("image-generation-created", "/api/v1/images/"+name+"/generations/"+strconv.Itoa(n))
				c := clone(g)
				out.Generation = &c
			}
			stopped := ""
			for _, k := range keys {
				j := s.jails.items[k]
				if j == nil {
					continue
				}
				o := api.ImageUpgradeJail{Jail: j.Metadata.Name, Project: j.Metadata.Project, From: name + "#" + j.Status.Generation}
				switch {
				case j.Spec.OS == api.OSLinux:
					o.Status, o.Reason = api.ImageUpgradeSkipped, "a Linux jail is thick and is updated in place"
				case j.Spec.Layout == api.LayoutThick:
					o.Status, o.Reason = api.ImageUpgradeSkipped, "a thick jail is updated in place"
				case j.Spec.Update.Strategy == api.UpdateInPlace || j.Spec.Update.Strategy == api.UpdateManual:
					o.Status, o.Reason = api.ImageUpgradeSkipped, "update strategy "+string(j.Spec.Update.Strategy)
				case strings.IndexByte(j.Spec.Image, '#') >= 0:
					o.Status, o.Reason = api.ImageUpgradeSkipped, "pinned to "+j.Spec.Image
				case out.Unchanged:
					o.Status, o.Reason = api.ImageUpgradeSkipped, "the package set did not change"
				case u.DryRun:
					o.Status, o.To = api.ImageUpgradePlanned, fmt.Sprintf("%s#g%d", name, n)
				case u.NoJails:
					o.Status, o.Reason = api.ImageUpgradeNotAttempted, "no_jails was set"
				case stopped != "":
					o.Status, o.Reason = api.ImageUpgradeNotAttempted, "stopped after "+stopped+" failed"
				default:
					recs := s.applyTo(j, api.UpdateApplyRequest{OS: true})
					if len(recs) == 0 {
						o.Status, o.Reason = api.ImageUpgradeSkipped, "already on "+o.From
						break
					}
					rec := recs[0]
					o.From, o.To, o.Record = rec.From, rec.To, rec.ID
					if rec.Result == api.UpdateOK {
						o.Status = api.ImageUpgradeUpgraded
						break
					}
					o.Status, o.Reason = api.ImageUpgradeFailed, rec.Error
					if rec.Note != "" {
						o.Reason += " (" + rec.Note + ")"
					}
					stopped = j.Metadata.Project + "/" + j.Metadata.Name
				}
				out.Jails = append(out.Jails, o)
			}
			if !u.DryRun && !out.Unchanged {
				s.emit("image-upgraded", "/api/v1/images/"+name)
			}
			return out, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) genDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	n, _ := strconv.Atoi(r.PathValue("n"))
	s.mu.Lock()
	rp := func() reply {
		idx := -1
		for i, g := range s.gens[name] {
			if g.Number == n {
				idx = i
			}
		}
		if idx < 0 {
			return reply{err: notFound("generation", r.PathValue("n"))}
		}
		if refs := s.genRefs(name, n); len(refs) > 0 {
			return reply{err: api.Errorf(api.CodeImageInUse, "generation g%d is used by jail %s", n, strings.Join(refs, ", ")).
				WithDetail("jails", strings.Join(refs, ",")).WithHint("upgrade or destroy those jails first")}
		}
		op := s.startOp("", "images.delete-generation", "Delete generation", nil, func() (any, *api.Error) {
			l := s.gens[name]
			for i, g := range l {
				if g.Number == n {
					s.gens[name] = append(l[:i:i], l[i+1:]...)
					s.moveAliasesFrom(name, n)
					return nil, nil
				}
			}
			return nil, notFound("generation", strconv.Itoa(n))
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// nextGen returns the next generation number of an image; numbers are never reused.
func (s *Server) nextGen(image string) int {
	n := s.genMax[image]
	for _, g := range s.gens[image] {
		n = max(n, g.Number)
	}
	return n + 1
}

func (s *Server) findGen(image string, n int) *api.ImageGeneration {
	for _, g := range s.gens[image] {
		if g.Number == n {
			return g
		}
	}
	return nil
}

// followAliases points the aliases named in the image spec at the new generation, as a build does.
func (s *Server) followAliases(image string, n int) {
	im := s.images.items[image]
	if im == nil {
		return
	}
	for _, a := range im.Spec.Aliases {
		if s.aliases[image] == nil {
			s.aliases[image] = map[string]int{}
		}
		s.aliases[image][a] = n
	}
}

// moveAliasesFrom moves the aliases that pointed at a deleted generation to the newest remaining one, or drops them.
func (s *Server) moveAliasesFrom(image string, n int) {
	newest := 0
	for _, g := range s.gens[image] {
		newest = max(newest, g.Number)
	}
	for a, an := range s.aliases[image] {
		if an != n {
			continue
		}
		if newest > 0 {
			s.aliases[image][a] = newest
		} else {
			delete(s.aliases[image], a)
		}
	}
}

func (s *Server) aliasSet(w http.ResponseWriter, r *http.Request) {
	name, alias := r.PathValue("name"), r.PathValue("alias")
	b, e := decode[api.ImageAliasSet](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, im := s.images.find(r, name)
	if im == nil {
		writeErr(w, notFound("image", name))
		return
	}
	n := (*b).Generation
	if n == 0 {
		for _, g := range s.gens[name] {
			n = max(n, g.Number)
		}
		if n == 0 {
			writeErr(w, notFound("generation", "newest").WithHint("build one first"))
			return
		}
	} else if s.findGen(name, n) == nil {
		writeErr(w, notFound("generation", strconv.Itoa(n)))
		return
	}
	if s.aliases[name] == nil {
		s.aliases[name] = map[string]int{}
	}
	s.aliases[name][alias] = n
	if !slices.Contains(im.Spec.Aliases, alias) {
		im.Spec.Aliases = append(im.Spec.Aliases, alias)
		im.Metadata.Generation++
	}
	out := clone(im)
	s.images.decorate(&out)
	writeSync(w, 200, out)
}

func (s *Server) aliasDelete(w http.ResponseWriter, r *http.Request) {
	name, alias := r.PathValue("name"), r.PathValue("alias")
	s.mu.Lock()
	defer s.mu.Unlock()
	_, im := s.images.find(r, name)
	if im == nil {
		writeErr(w, notFound("image", name))
		return
	}
	_, had := s.aliases[name][alias]
	if !had && !slices.Contains(im.Spec.Aliases, alias) {
		writeErr(w, notFound("alias", alias))
		return
	}
	delete(s.aliases[name], alias)
	if slices.Contains(im.Spec.Aliases, alias) {
		im.Spec.Aliases = slices.DeleteFunc(im.Spec.Aliases, func(a string) bool { return a == alias })
		im.Metadata.Generation++
	}
	out := clone(im)
	s.images.decorate(&out)
	writeSync(w, 200, out)
}
