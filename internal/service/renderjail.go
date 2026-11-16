package service

import (
	"context"
	"fmt"
	"jailops.net/jailops/internal/apps"
	"net/netip"
	"path"
	"strings"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// jailBuild is everything rendered for one jail. It is a pure function of the
// jail spec, the networks, the policy and the address sets.
type jailBuild struct {
	desired  reconcile.JailDesired
	jailConf string
	fstab    string
	hasFstab bool
	// guest maps an absolute path under the jail's root to its content.
	guest map[string]string
	// ifaces are the jail-side interface names.
	ifaces []string
	// shapes are the devices with a bandwidth limit and rates the bandwidth of each pipe they use (bits per second,
	// 0 unlimited): the pipes must exist before the jail's anchor is loaded.
	shapes []render.Shape
	rates  map[int]uint64
}

// shapeDev is a device of the jail that has a bandwidth limit, as the loop over its devices sees it.
type shapeDev struct {
	index           int
	host            string
	egress, ingress bool
}

// Where JailOps writes the guest configuration. rc.conf.local is read by the
// stock rc after rc.conf, so the administrator's rc.conf stays untouched.
// UNVERIFIED: on FreeBSD 15 inside a thin jail whose /etc is its own dataset.
const (
	guestRcConf  = "/etc/rc.conf.local"
	guestResolv  = "/etc/resolv.conf"
	guestAlpineI = "/etc/network/interfaces"
	guestAlpineH = "/etc/hostname"
)

// jailKey is the project-qualified key of a jail: its OS-level name, the leaf
// of its dataset path and the handle everything below the API uses.
func jailKey(j api.Jail) string {
	k, err := validate.QualifiedName(j.Metadata.Project, j.Metadata.Name)
	if err != nil {
		return j.Metadata.Name
	}
	return k
}

func (s *Service) buildJail(ctx context.Context, j api.Jail, refs fwRefs) (*jailBuild, error) {
	j.Spec = s.effective(j)
	name, id := jailKey(j), j.Metadata.UUID
	project := j.Metadata.Project
	if project == "" {
		return nil, ErrProjectRequired()
	}
	osf := j.Spec.OS
	if osf == "" {
		osf = api.OSFreeBSD
	}
	b := &jailBuild{guest: map[string]string{}}
	d := &b.desired
	d.Name, d.ID, d.Boot, d.Project = name, id, j.Spec.Boot, project
	d.Boot.Depends = nil
	for _, dep := range j.Spec.Boot.Depends {
		if k, err := validate.QualifiedName(project, dep); err == nil {
			d.Boot.Depends = append(d.Boot.Depends, k)
		}
	}
	var ifs []render.NetIface
	var macs []string
	var linkLocal []netip.Addr     // the kernel forms them from the MACs above
	var netSpecs []api.NetworkSpec // the networks in the order the jail attaches them: its nameservers come from them
	uplink := ""
	var shaped []shapeDev
	var hostAddrs, dnsAddrs []netip.Addr // the host's addresses the jail meets, and the resolver it is pointed at
	for i, a := range j.Spec.Network {
		n, err := s.netKind.get(a.Network)
		if err != nil {
			return nil, fmt.Errorf("network %q: %w", a.Network, err)
		}
		host, jailEnd, err := ipam.EpairNames(id, i)
		if err != nil {
			return nil, err
		}
		in := render.AttachInput{JailID: id, JailUUID: id, Index: i, Project: project, Jail: j.Metadata.Name, Network: a.Network,
			MAC: a.MAC, MTU: attachMTU(a, n.Spec.MTU),
			Uplink: n.Spec.Uplink, HostConfigured: osf == api.OSLinux}
		nif := render.NetIface{Name: jailEnd, MTU: attachMTU(a, n.Spec.MTU)}
		if ad, ok := parseAddr(a.IPv4); ok && n.Spec.IPv4 != nil {
			in.IPv4 = netip.PrefixFrom(ad, ipam.GuestPrefixLen4())
			in.Gateway4, _ = netip.ParseAddr(n.Spec.IPv4.Gateway)
			nif.IPv4, nif.Gateway4 = in.IPv4, in.Gateway4
		}
		if ad, ok := parseAddr(a.IPv6); ok && n.Spec.IPv6 != nil {
			sub, _ := netip.ParsePrefix(n.Spec.IPv6.Subnet)
			in.IPv6 = netip.PrefixFrom(ad, ipam.GuestPrefixLen6(n.Spec.IPv6.Mode, sub.Bits()))
			in.Gateway6 = ipam.GatewayLinkLocal6
			in.IPv6Mode = n.Spec.IPv6.Mode
			nif.IPv6, nif.Gateway6 = in.IPv6, in.Gateway6
			if n.Spec.IPv6.Mode == api.IPv6Proxy {
				d.Proxy = append(d.Proxy, reconcile.ProxyAddr{Addr: ad.String(), Iface: host, Uplink: n.Spec.Uplink})
			}
		}
		steps, err := render.AttachPlan(in)
		if err != nil {
			return nil, err
		}
		var hostSteps []render.Step
		for _, st := range steps {
			switch {
			case st.Phase == render.PhaseHost:
				hostSteps = append(hostSteps, st)
			case st.Op == render.OpSetDescription:
				d.JailSide = append(d.JailSide, st)
			}
		}
		d.Attach = append(d.Attach, hostSteps)
		d.Networks = append(d.Networks, a.Network)
		d.Epairs = append(d.Epairs, host)
		b.ifaces = append(b.ifaces, jailEnd)
		if a.MAC != "" {
			macs = append(macs, a.MAC)
		} else if m, err := ipam.DeriveMACN(id, i, false); err == nil {
			macs = append(macs, m)
		}
		if len(macs) > 0 {
			if l, err := ipam.LinkLocalFromMAC(macs[len(macs)-1]); err == nil {
				linkLocal = append(linkLocal, l)
			}
		}
		if a.Egress != "" || a.Ingress != "" {
			shaped = append(shaped, shapeDev{index: i, host: host, egress: a.Egress != "", ingress: a.Ingress != ""})
		}
		if n.Spec.IPv4 != nil {
			if g, err := netip.ParseAddr(n.Spec.IPv4.Gateway); err == nil {
				hostAddrs = append(hostAddrs, g)
			}
		}
		if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode != api.IPv6None {
			hostAddrs = append(hostAddrs, ipam.GatewayLinkLocal6)
		}
		if d := s.networkDNS(a.Network, n.Spec); d != nil && d.Source == api.DNSFromGateway {
			for _, ns := range d.Nameservers {
				if x, err := netip.ParseAddr(ns); err == nil {
					dnsAddrs = append(dnsAddrs, x)
				}
			}
		}
		ifs = append(ifs, nif)
		netSpecs = append(netSpecs, n.Spec)
		if uplink == "" {
			uplink = n.Spec.Uplink
		}
	}
	if len(shaped) > 0 {
		numbers, wants, err := s.shapingPlan()
		if err != nil {
			return nil, err
		}
		b.rates = map[int]uint64{}
		for _, w := range wants {
			b.rates[w.Number] = w.Rate
		}
		for _, sd := range shaped {
			sh := render.Shape{Iface: sd.host}
			if sd.egress {
				sh.Egress = numbers[render.PipeKey{Jail: id, Device: sd.index}]
			}
			if sd.ingress {
				sh.Ingress = numbers[render.PipeKey{Jail: id, Device: sd.index, Ingress: true}]
			}
			if sh.Egress != 0 || sh.Ingress != 0 {
				b.shapes = append(b.shapes, sh)
			}
		}
	}
	// Firewall anchor: the project's policies first, then the managed access policy, then the jail's own.
	var projectPols, ownPols []object[api.FirewallPolicySpec]
	for _, pn := range j.Spec.Firewall.Policies {
		pol, err := s.polKind.p(project).get(pn)
		if err != nil {
			return nil, fmt.Errorf("firewall policy %q: %w", pn, err)
		}
		ownPols = append(ownPols, pol)
	}
	if pr, err := s.projKind.get(project); err == nil {
		for _, pn := range pr.Spec.FirewallPolicies {
			pol, err := s.polKind.p(project).get(pn)
			if err != nil {
				return nil, fmt.Errorf("the mandatory firewall policy %q of project %q: %w", pn, project, err)
			}
			projectPols = append(projectPols, pol)
		}
	}
	// A policy that was stored without its defaults is not rendered with a guess: the jail keeps the anchor it has.
	for _, p := range append(append([]object[api.FirewallPolicySpec](nil), projectPols...), ownPols...) {
		if err := policyDefaults(p.Meta.Name, p.Spec); err != nil {
			return nil, err
		}
	}
	// Proxy devices are inbound redirects in the jail's anchor.
	var proxyRules []api.FirewallRule
	for _, p := range j.Spec.Proxy {
		host, port, err := validate.ParseListen(p.Listen)
		if err != nil {
			return nil, fmt.Errorf("proxy %q: %w", p.Name, err)
		}
		proto := p.Proto
		if proto == "" {
			proto = "tcp"
		}
		proxyRules = append(proxyRules, api.FirewallRule{Name: "proxy " + p.Name, Action: "allow", Direction: "in", Proto: proto,
			Redirect: &api.Redirect{Listen: host, HostPort: port, JailPort: p.JailPort}})
	}
	// Every jail has an anchor, with or without a policy: the isolation of projects and the anti-spoofing rules do not
	// depend on anyone having written a policy.
	{
		// A jail with a link and no address (a network entry of "none") gets the closed anchor of render.BuildAnchor.
		if addrs := jailAddrs(j.Spec); len(d.Epairs) > 0 {
			in := render.PFInput{Jail: name, Interfaces: d.Epairs, Addresses: addrs, Tags: j.Spec.Firewall.Tags,
				TagMembers: map[string][]netip.Addr{}, Sets: refs.sets, Jails: refs.jails, Uplink: uplink, AllowRaw: true,
				Antispoof: true, LinkLocal: linkLocal, Host: append(s.hostAddrs(ctx), hostAddrs...), DNS: dnsAddrs,
				Foreign: s.foreignPrefixes(project), MaxStates: s.statesLimit(j), Shaping: b.shapes}
			// A jail without any policy is open (apart from the isolation of projects); with policies, the strictest
			// default of them all applies: the project's defaults are a floor that a jail's own policy can open ports
			// through but cannot turn from deny into allow.
			in.DefaultIn, in.DefaultOut = "allow", "allow"
			var specs []api.FirewallPolicySpec
			for _, p := range projectPols {
				in.Policies = append(in.Policies, render.PFPolicy{Name: p.Meta.Name, Project: true, Policy: p.Spec, AllowRaw: true})
				specs = append(specs, p.Spec)
			}
			// The grants of app access (the managed policy app-<jail>) come after the project's policies and before the
			// jail's own; an app's jail it closes stays closed whatever the jail's own policies say.
			accRules, accClosed := s.accessRulesFor(project, j.Metadata.Name)
			if len(accRules) > 0 {
				in.Policies = append(in.Policies, render.PFPolicy{Name: apps.AccessPolicyName(j.Metadata.Name), Managed: true, Policy: api.FirewallPolicySpec{Rules: accRules}})
			}
			for _, p := range ownPols {
				in.Policies = append(in.Policies, render.PFPolicy{Name: p.Meta.Name, Policy: p.Spec, AllowRaw: true})
				specs = append(specs, p.Spec)
			}
			for i, p := range specs {
				if i == 0 {
					in.DefaultIn, in.DefaultOut = p.DefaultIn, p.DefaultOut
					continue
				}
				in.DefaultIn = stricterDefault(in.DefaultIn, p.DefaultIn, "in")
				in.DefaultOut = stricterDefault(in.DefaultOut, p.DefaultOut, "out")
			}
			for _, p := range specs {
				for t, m := range s.tagMembers(project, p) {
					in.TagMembers[t] = append(in.TagMembers[t], m...)
				}
			}
			if accClosed {
				in.DefaultIn = "deny"
			}
			in.Proxy = proxyRules
			an, err := render.BuildAnchor(in)
			if err != nil {
				return nil, err
			}
			d.AnchorName, d.Ruleset, d.Anchor = render.JailAnchor(name), render.FormatAnchor(an), an
			d.ParentAnchors = map[string]string{render.ProjectAnchor(project): render.ProjectAnchorRules()}
		}
	}
	// jail.conf and fstab.
	host := j.Spec.Hostname
	if host == "" {
		host = j.Metadata.Name
	}
	in := render.JailConfInput{Name: name, Path: s.rootMount(name), Hostname: host, OS: osf, Interfaces: b.ifaces, SysVIPC: j.Spec.SysVIPC, Where: s.promptContext(name), StopTimeout: stopTimeoutOf(j.Spec)}
	if j.Spec.Delegate {
		// The jail manages <container>/delegated itself: jail(8) attaches it (zfs.dataset) once the dataset has the
		// jailed property, which a global admin's request set when delegation was turned on.
		ds := s.lcfg.DelegatedDS(name)
		v, err := s.d.ZFS.Get(ctx, ds, "jailed")
		if err != nil || v != "on" {
			return nil, api.Errorf(api.CodeConflict, "the delegated dataset %s of jail %q is not handed over (jailed is not on)", ds, j.Metadata.Name).
				WithHint("turn zfs_delegation off and on again as a global administrator: jailops config set " + j.Metadata.Name + " zfs.delegation false, then true")
		}
		in.ZFSDataset = ds
		in.Allow = []string{"mount", "mount.zfs"}
		one := 1
		in.EnforceStatfs = &one
	}
	devRS := 0
	if osf == api.OSLinux {
		n, _, err := render.LinuxDevfsRuleset(render.SpecDevfsDevices(j.Spec))
		if err != nil {
			return nil, err
		}
		in.DevfsRuleset, devRS = n, n
	} else if devs := render.SpecDevfsDevices(j.Spec); len(devs) > 0 {
		n, _, err := render.DevfsRuleset(devs)
		if err != nil {
			return nil, err
		}
		in.DevfsRuleset = n
	}
	// The volumes the jail attaches are mounted on the host at their own mountpoint and reach the jail through nullfs,
	// like the host directories it is granted.
	var vols []render.FstabVolume
	att, err := s.attachedVolumes(name)
	if err != nil {
		return nil, err
	}
	for _, a := range att {
		vols = append(vols, render.FstabVolume{Source: a.Mountpoint, Target: a.Path, ReadOnly: a.ReadOnly})
	}
	if osf == api.OSLinux || len(vols) > 0 {
		fs, err := render.Fstab(render.FstabInput{OS: osf, Root: s.rootMount(name), Volumes: vols, DevfsRuleset: devRS})
		if err != nil {
			return nil, err
		}
		b.fstab, b.hasFstab = fs, true
		in.FstabPath = s.fstabPath(name)
	}
	jc, err := render.JailConf(in)
	if err != nil {
		return nil, err
	}
	b.jailConf = jc
	// Guest configuration.
	root := s.rootMount(name)
	dnsSrc, dns := s.resolvers(netSpecs)
	search := s.dnsSearch(dnsSrc, project)
	ni := render.NetInput{Hostname: host, Ifaces: ifs, DNS: dns}
	switch osf {
	case api.OSLinux:
		for p, f := range map[string]func() (string, error){
			guestAlpineI: func() (string, error) { return render.AlpineInterfaces(ni) },
			guestAlpineH: func() (string, error) { return render.AlpineHostname(host) },
			guestResolv:  func() (string, error) { return render.AlpineResolvConf(dns, search) },
		} {
			c, err := f()
			if err != nil {
				return nil, err
			}
			b.guest[path.Join(root, p)] = c
		}
	default:
		rc, err := render.RcConfFreeBSD(ni)
		if err != nil {
			return nil, err
		}
		b.guest[path.Join(root, guestRcConf)] = rc
		rv, err := render.ResolvConf(dns, search)
		if err != nil {
			return nil, err
		}
		b.guest[path.Join(root, guestResolv)] = rv
	}
	return b, nil
}

// Desired implements reconcile.Source.
func (s *Service) Desired(ctx context.Context) (reconcile.Desired, error) {
	var out reconcile.Desired
	out.Host = s.hostDesired()
	out.WireGuard = s.wireguardDesired()
	if _, pipes, err := s.shapingPlan(); err == nil {
		out.Pipes = pipes
	}
	nets, err := s.netKind.list()
	if err != nil {
		return out, err
	}
	for _, n := range nets {
		nd := reconcile.NetworkDesired{Name: n.Meta.Name, ID: n.Meta.UUID, Spec: n.Spec}
		steps, err := render.NetworkPlan(render.NetworkInput{ID: n.Meta.UUID, Name: n.Meta.Name, Spec: n.Spec})
		if err != nil {
			nd.Problem = err.Error()
		} else {
			nd.Steps = steps
			net, err := render.PFNet(n.Meta.Name, n.Spec)
			if err != nil {
				nd.Problem = err.Error()
			}
			nd.Anchors = map[string]string{render.NetAnchor(n.Meta.Name): net}
		}
		nd.Allocated, nd.Free, _ = s.networkCounts(n.Spec, n.Meta.Name)
		out.Networks = append(out.Networks, nd)
	}
	s.mu.RLock()
	names := sortedKeys(s.jails)
	jails := make([]api.Jail, 0, len(names))
	for _, n := range names {
		jails = append(jails, s.jails[n].jail)
	}
	s.mu.RUnlock()
	refsOf := map[string]fwRefs{}
	for _, j := range jails {
		p := j.Metadata.Project
		if _, ok := refsOf[p]; !ok {
			refs, err := s.allRefs(p)
			if err != nil {
				return out, err
			}
			refsOf[p] = refs
		}
		b, err := s.buildJail(ctx, j, refsOf[p])
		if err != nil {
			out.Jails = append(out.Jails, reconcile.JailDesired{Name: jailKey(j), ID: j.Metadata.UUID, Project: j.Metadata.Project, Boot: j.Spec.Boot, Problem: err.Error()})
			continue
		}
		out.Jails = append(out.Jails, b.desired)
	}
	return out, nil
}

// ---- hooks (lifecycle.Hooks) ----

type hooks struct{ s *Service }

// PreStart renders the jail's configuration and makes sure its networks exist.
// The epair, jail-phase and firewall work happens in the
// exec hooks of jail.conf, which jail(8) runs through jailops-priv; the
// rendered PF anchor is left where that hook reads it. It is idempotent.
func (h *hooks) PreStart(ctx context.Context, name string) error {
	s := h.s
	j, err := s.jailSnapshot(name)
	if err != nil {
		return err
	}
	refs, err := s.allRefs(j.Metadata.Project)
	if err != nil {
		return err
	}
	b, err := s.buildJail(ctx, j, refs)
	if err != nil {
		return err
	}
	if err := s.ensurePipes(ctx, b.shapes, b.rates); err != nil {
		return err
	}
	obs, err := reconcile.Observe(ctx, s.d.Net, nil)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, a := range j.Spec.Network {
		if seen[a.Network] {
			continue
		}
		seen[a.Network] = true
		if err := s.ensureNetwork(ctx, a.Network, obs); err != nil {
			return err
		}
	}
	f := s.d.Files
	if err := f.MkdirAll(ctx, s.confDir(name)); err != nil {
		return err
	}
	if err := f.WriteAtomic(ctx, s.confPath(name), []byte(b.jailConf)); err != nil {
		return err
	}
	if b.hasFstab {
		if err := f.WriteAtomic(ctx, s.fstabPath(name), []byte(b.fstab)); err != nil {
			return err
		}
	}
	for p, c := range b.guest {
		if p == path.Join(s.rootMount(name), guestResolv) && s.keepsResolv(ctx, p) {
			continue // the jail's own resolver configuration
		}
		if err := f.MkdirAll(ctx, path.Dir(p)); err != nil {
			return err
		}
		if err := f.WriteAtomic(ctx, p, []byte(c)); err != nil {
			return err
		}
	}
	return s.writeAnchorFile(ctx, name, b.desired.Ruleset)
}

// writeAnchorFile leaves the rendered PF anchor for the start hook, or
// removes a stale one when the jail has no firewall.
func (s *Service) writeAnchorFile(ctx context.Context, name, ruleset string) error {
	if s.d.StateDir == "" {
		return nil
	}
	p := s.anchorFile(name)
	if ruleset == "" {
		if ok, _ := s.d.Files.Exists(ctx, p); ok {
			return s.d.Files.RemoveAll(ctx, p)
		}
		return nil
	}
	if err := s.d.Files.MkdirAll(ctx, path.Dir(p)); err != nil {
		return err
	}
	return s.d.Files.WriteAtomic(ctx, p, []byte(ruleset))
}

// ensureNetwork brings one network up (its sysctl preconditions, reject routes and anchor) before a jail attaches.
func (s *Service) ensureNetwork(ctx context.Context, name string, obs *reconcile.Observed) error {
	n, err := s.netKind.get(name)
	if err != nil {
		return err
	}
	steps, err := render.NetworkPlan(render.NetworkInput{ID: n.Meta.UUID, Name: name, Spec: n.Spec})
	if err != nil {
		return err
	}
	unlock, err := s.locks.lockPatient(ctx, "prepare network "+name, networkLock(name))
	if err != nil {
		return err
	}
	defer unlock()
	nat := map[string]string{}
	rs, err := render.PFNet(name, n.Spec)
	if err != nil {
		return err
	}
	nat[render.NetAnchor(name)] = rs
	ex := s.netExec(nat)
	for _, st := range steps {
		if reconcile.Satisfied(st, obs) {
			continue
		}
		if err := ex.Exec(ctx, st, ""); err != nil {
			return fmt.Errorf("network %s: %s: %w", name, st.Describe(), err)
		}
	}
	return nil
}

func (s *Service) netExec(anchors map[string]string) *reconcile.NetExec {
	return &reconcile.NetExec{Net: s.d.Net, PF: s.d.PF, Run: s.d.Run, Jail: s.d.Jails, Sysctl: s.d.Sysctl, Anchors: anchors}
}

// PostStop has nothing to do: the poststop hook of jail.conf flushes the
// anchor and destroys the epairs, and the reconciler removes what is left.
// PostStop cleans up after a jail that does not run: the helper takes the mounts below its root off and runs what the
// poststop hook of jail(8) removes (rctl rules, the pf anchor, the links). jail(8) does not run exec.poststop after a
// failed start or when it died, so this does not depend on it; the helper refuses a jail that runs. It is best effort:
// what cannot be cleaned now is found by the heal of the daemon.
func (h *hooks) PostStop(ctx context.Context, name string) error {
	if h.s.d.Files == nil {
		return nil
	}
	if res, err := h.s.d.Files.HealJail(ctx, name); err != nil {
		h.s.log.Warn("the clean-up after a stopped jail failed", "jail", name, "err", err)
	} else if len(res.Errors) > 0 {
		h.s.log.Warn("the clean-up after a stopped jail was not complete", "jail", name, "errors", strings.Join(res.Errors, "; "))
	}
	return nil
}

// Remove deletes the rendered files of a jail that is being destroyed.
func (h *hooks) Remove(ctx context.Context, name string) error {
	s := h.s
	for _, p := range []string{s.confPath(name), s.fstabPath(name), s.confDir(name)} {
		if ok, _ := s.d.Files.Exists(ctx, p); ok {
			if err := s.d.Files.RemoveAll(ctx, p); err != nil {
				return err
			}
		}
	}
	if s.d.StateDir != "" {
		if ok, _ := s.d.Files.Exists(ctx, s.anchorFile(name)); ok {
			return s.d.Files.RemoveAll(ctx, s.anchorFile(name))
		}
	}
	return nil
}

func attachMTU(a api.NetworkAttach, network int) int {
	if a.MTU > 0 {
		return a.MTU
	}
	return network
}

// stopTimeoutOf is the stop timeout written into the configuration of a jail: its boot.stop_timeout, or the default of
// JailOps. jail.conf always carries one, so that jail(8) bounds the wait after SIGTERM too.
func stopTimeoutOf(spec api.JailSpec) int {
	if spec.Boot.StopTimeout > 0 {
		return spec.Boot.StopTimeout
	}
	return api.DefaultStopTimeout
}
