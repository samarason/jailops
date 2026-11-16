package service

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// WireGuard tunnels (design section 5.3). The objects hold public parts only; the helper keeps the keys
// (wireguard.Host). A change is applied at once and the reconcile loop keeps it applied (it recreates the
// interfaces after a reboot).

// TokenWarning is said with every join token and configuration file.
const TokenWarning = "this token holds the peer's private key and the preshared key: it is shown once, is not stored on this host, and gives whoever holds it access to the tunnel; pass it on over a channel you trust"

func wgLock(name string) string { return "wireguard/" + name }

// placeholderKey stands for a peer's key while its address is checked, before any key is made.
const placeholderKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func (s *Service) wgHost() (wireguard.Host, error) {
	if s.d.WG == nil {
		return nil, api.Errorf(api.CodeUnsupported, "WireGuard is not available on this host (no privileged helper)")
	}
	return s.d.WG, nil
}

// wgToAPI adds the observed status.
func (s *Service) wgToAPI(ctx context.Context, o object[api.WireGuardSpec]) api.WireGuard {
	w := api.WireGuard{Metadata: o.Meta, Spec: o.Spec}
	w.Status.Interface = o.Spec.Interface
	if o.Spec.Mode == api.WireGuardServer {
		w.Status.FirewallRule = wireguard.FirewallRule(o.Spec.ListenPort)
	}
	if s.d.WG != nil {
		if sh, err := s.d.WG.WGShow(ctx, wireguard.ShowReq{Name: o.Meta.Name, Iface: o.Spec.Interface}); err == nil {
			w.Status.Up = sh.Exists && sh.Up
			w.Status.PublicKey, w.Status.ListenPort = sh.PublicKey, sh.ListenPort
			for _, p := range sh.Peers {
				ps := api.WireGuardPeerStatus{PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs,
					RxBytes: p.RxBytes, TxBytes: p.TxBytes, PresharedKey: p.PresharedKey}
				if p.LatestHandshake > 0 {
					ps.LatestHandshake = time.Unix(p.LatestHandshake, 0).UTC()
				}
				for _, sp := range o.Spec.Peers {
					if sp.PublicKey == p.PublicKey {
						ps.Name = sp.Name
					}
				}
				w.Status.Peers = append(w.Status.Peers, ps)
			}
		}
		if w.Status.PublicKey == "" {
			s.mu.RLock()
			w.Status.PublicKey = s.wgPub[o.Meta.Name]
			s.mu.RUnlock()
		}
	}
	now := s.now()
	switch msg := s.wgProblem(o.Meta.Name); {
	case o.Spec.Down:
		w.Status.Conditions = append(w.Status.Conditions, api.Condition{Type: "Ready", Status: api.ConditionFalse, Reason: "Down", Message: "the tunnel is down (jailops wireguard up starts it)", Since: now})
	case msg != "":
		w.Status.Conditions = append(w.Status.Conditions, api.Condition{Type: "Ready", Status: api.ConditionFalse, Reason: "ApplyFailed", Message: msg, Since: now})
	case w.Status.Up:
		w.Status.Conditions = append(w.Status.Conditions, api.Condition{Type: "Ready", Status: api.ConditionTrue, Reason: "Up", Message: "interface " + o.Spec.Interface + " is up", Since: now})
	}
	return w
}

// wgProblem is the latest failure to apply the object, from the service or the reconcile loop.
func (s *Service) wgProblem(name string) string {
	s.mu.RLock()
	msg := s.wgErr[name]
	s.mu.RUnlock()
	if msg != "" {
		return msg
	}
	if s.d.Reconciler != nil {
		return s.d.Reconciler.Last().Failures["wireguard/"+name]
	}
	return ""
}

func (s *Service) setWGErr(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wgErr == nil {
		s.wgErr = map[string]string{}
	}
	if err == nil {
		delete(s.wgErr, name)
		return
	}
	s.wgErr[name] = err.Error()
}

// ListWireGuard lists the tunnels.
func (s *Service) ListWireGuard(ctx context.Context, labels map[string]string) ([]api.WireGuard, error) {
	if err := requireGlobal(ctx, "WireGuard"); err != nil {
		return nil, err
	}
	objs, err := s.wgKind.list()
	if err != nil {
		return nil, err
	}
	out := []api.WireGuard{}
	for _, o := range objs {
		if MatchLabels(o.Meta.Labels, labels) {
			out = append(out, s.wgToAPI(ctx, o))
		}
	}
	return out, nil
}

// GetWireGuard returns one tunnel with its status.
func (s *Service) GetWireGuard(ctx context.Context, name string) (api.WireGuard, error) {
	if err := requireGlobal(ctx, "WireGuard"); err != nil {
		return api.WireGuard{}, err
	}
	o, err := s.wgKind.get(name)
	if err != nil {
		return api.WireGuard{}, err
	}
	return s.wgToAPI(ctx, o), nil
}

// checkWireGuard validates a spec against the other objects: networks exist, no other tunnel has the interface,
// the listen port or an overlapping address.
func (s *Service) checkWireGuard(name string, spec api.WireGuardSpec) error {
	if err := wireguard.ValidateSpec(name, spec); err != nil {
		return err
	}
	for _, n := range spec.Networks {
		if !s.netKind.exists(n) {
			return notFound("network", n)
		}
	}
	mine, _ := wireguard.ParsePrefixes("address", spec.Address, false)
	objs, err := s.wgKind.list()
	if err != nil {
		return err
	}
	for _, o := range objs {
		if o.Meta.Name == name {
			continue
		}
		if o.Spec.Interface == spec.Interface {
			return api.Errorf(api.CodeAlreadyExists, "interface %s is used by wireguard %q", spec.Interface, o.Meta.Name)
		}
		if spec.ListenPort != 0 && o.Spec.ListenPort == spec.ListenPort {
			return api.Errorf(api.CodeAlreadyExists, "listen port %d is used by wireguard %q", spec.ListenPort, o.Meta.Name)
		}
		theirs, _ := wireguard.ParsePrefixes("address", o.Spec.Address, false)
		for _, a := range mine {
			for _, b := range theirs {
				if a.Masked().Overlaps(b.Masked()) {
					return api.Errorf(api.CodeIPConflict, "address %s overlaps %s of wireguard %q", a, b, o.Meta.Name)
				}
			}
		}
	}
	return nil
}

// wgDesired renders what the helper and pf need for one object.
func (s *Service) wgDesired(o object[api.WireGuardSpec]) reconcile.WireGuardDesired {
	d := reconcile.WireGuardDesired{Name: o.Meta.Name, Iface: o.Spec.Interface, Down: o.Spec.Down, Anchor: wireguard.Anchor(o.Meta.Name)}
	req, rs, err := s.wgRender(o)
	if err != nil {
		d.Problem = err.Error()
		return d
	}
	d.Apply, d.Ruleset = req, rs
	return d
}

func (s *Service) wgRender(o object[api.WireGuardSpec]) (wireguard.ApplyReq, string, error) {
	sp := o.Spec
	addrs, err := wireguard.ParsePrefixes("address", sp.Address, false)
	if err != nil {
		return wireguard.ApplyReq{}, "", err
	}
	req := wireguard.ApplyReq{Name: o.Meta.Name, Iface: sp.Interface, Addresses: addrs}
	switch sp.Mode {
	case api.WireGuardServer:
		req.ListenPort = sp.ListenPort
		for _, p := range sp.Peers {
			pa, err := wireguard.ParsePrefixes("allowed_ips", p.AllowedIPs, true)
			if err != nil {
				return req, "", err
			}
			req.Peers = append(req.Peers, wireguard.PeerConf{PublicKey: p.PublicKey, AllowedIPs: pa, Keepalive: p.Keepalive})
		}
	case api.WireGuardClient:
		routes, err := wireguard.ParsePrefixes("allowed_ips", sp.AllowedIPs, false)
		if err != nil {
			return req, "", err
		}
		req.Routes = routes
		req.Peers = []wireguard.PeerConf{{PublicKey: sp.PeerPublicKey, AllowedIPs: routes, Endpoint: sp.Endpoint, Keepalive: sp.Keepalive}}
	}
	var nets []netip.Prefix
	for _, n := range sp.Networks {
		no, err := s.netKind.get(n)
		if err != nil {
			return req, "", err
		}
		if v4 := no.Spec.IPv4; v4 != nil {
			if p, err := netip.ParsePrefix(v4.Subnet); err == nil {
				nets = append(nets, p.Masked())
			}
		}
		if v6 := no.Spec.IPv6; v6 != nil && v6.Mode != api.IPv6None {
			if p, err := netip.ParsePrefix(v6.Subnet); err == nil {
				nets = append(nets, p.Masked())
			}
		}
	}
	rs := ""
	if sp.Mode == api.WireGuardServer {
		if rs, err = render.PFWireGuard(o.Meta.Name, sp.Interface, wireguard.Masked(addrs), nets); err != nil {
			return req, "", err
		}
	}
	return req, rs, nil
}

// wgApply applies one object now: the interface through the helper, the anchor through pf. The caller holds the
// object's lock.
func (s *Service) wgApply(ctx context.Context, o object[api.WireGuardSpec]) error {
	h, err := s.wgHost()
	if err != nil {
		return err
	}
	d := s.wgDesired(o)
	if d.Problem != "" {
		return invalid("%s", d.Problem)
	}
	if o.Spec.Down {
		err = h.WGRemove(ctx, wireguard.RemoveReq{Name: o.Meta.Name, Iface: o.Spec.Interface})
		if err == nil && s.d.PF != nil {
			err = ignoreCode(s.d.PF.Flush(ctx, d.Anchor), api.CodeNotFound)
		}
		s.setWGErr(o.Meta.Name, err)
		return err
	}
	res, err := h.WGApply(ctx, d.Apply)
	if err == nil && s.d.PF != nil {
		if d.Ruleset != "" {
			err = s.d.PF.Load(ctx, d.Anchor, d.Ruleset)
		} else {
			err = ignoreCode(s.d.PF.Flush(ctx, d.Anchor), api.CodeNotFound)
		}
	}
	if err == nil && res.PublicKey != "" {
		s.mu.Lock()
		if s.wgPub == nil {
			s.wgPub = map[string]string{}
		}
		s.wgPub[o.Meta.Name] = res.PublicKey
		s.mu.Unlock()
	}
	s.setWGErr(o.Meta.Name, err)
	return err
}

func ignoreCode(err error, code api.Code) error {
	if err != nil && api.IsCode(err, code) {
		return nil
	}
	return err
}

// CreateWireGuard creates a server tunnel (a client is made with JoinWireGuard, or with a full spec). The keys are
// made on this host; the private key never leaves the helper.
func (s *Service) CreateWireGuard(ctx context.Context, w api.WireGuard) (api.WireGuard, error) {
	if err := requireGlobal(ctx, "creating a WireGuard tunnel"); err != nil {
		return api.WireGuard{}, err
	}
	h, err := s.wgHost()
	if err != nil {
		return api.WireGuard{}, err
	}
	name := w.Metadata.Name
	if err := wireguard.ValidName("name", name); err != nil {
		return api.WireGuard{}, err
	}
	if err := checkWireGuardName(name, w.Spec.Interface); err != nil {
		return api.WireGuard{}, err
	}
	if w.Spec.Mode == api.WireGuardClient && w.Spec.PeerPublicKey != "" {
		return api.WireGuard{}, invalid("a client is made from a join token").WithHint("jailops wireguard join NAME --token-file TOKEN-FILE")
	}
	wireguard.Defaults(name, s.d.Hostname, &w.Spec)
	for i := range w.Spec.Peers {
		if w.Spec.Peers[i].Created.IsZero() {
			w.Spec.Peers[i].Created = s.now().UTC()
		}
	}
	unlock, err := s.locks.lockPatient(ctx, "create wireguard "+name, wgLock(name), "wireguard/_all")
	if err != nil {
		return api.WireGuard{}, err
	}
	defer unlock()
	if err := s.wgKind.notTaken(name); err != nil {
		return api.WireGuard{}, err
	}
	if err := s.checkWireGuard(name, w.Spec); err != nil {
		return api.WireGuard{}, err
	}
	if _, err := h.WGKeys(ctx, wireguard.KeysReq{Name: name}); err != nil {
		return api.WireGuard{}, err
	}
	o, err := s.wgKind.create(ctx, w.Metadata, w.Spec)
	if err != nil {
		return api.WireGuard{}, err
	}
	out := s.wgAfterChange(ctx, o)
	return out, nil
}

// wgAfterChange applies an object and reports a failure as a warning: the object is stored and the reconcile loop
// tries again.
func (s *Service) wgAfterChange(ctx context.Context, o object[api.WireGuardSpec]) api.WireGuard {
	err := s.wgApply(ctx, o)
	s.kick()
	out := s.wgToAPI(ctx, o)
	if err != nil {
		out.Status.Warnings = append(out.Status.Warnings, "not applied yet: "+err.Error())
	}
	out.Status.Warnings = append(out.Status.Warnings, s.wgWarnings(ctx, o)...)
	return out
}

// wgWarnings says what the administrator still has to do.
func (s *Service) wgWarnings(ctx context.Context, o object[api.WireGuardSpec]) []string {
	var out []string
	if o.Spec.Mode == api.WireGuardServer {
		out = append(out, fmt.Sprintf("peers reach UDP port %d only if the host's pf.conf lets them: add `%s` (JailOps never edits pf.conf)", o.Spec.ListenPort, wireguard.FirewallRule(o.Spec.ListenPort)))
		if len(o.Spec.Networks) > 0 {
			if v, err := s.sysctl(ctx, "net.inet.ip.forwarding"); err == nil && v != "1" {
				out = append(out, "net.inet.ip.forwarding is off: peers cannot reach the networks until the administrator turns forwarding on (gateway_enable in rc.conf)")
			}
		}
	}
	if s.d.WG != nil {
		if t, err := s.d.WG.WGTools(ctx); err == nil && t.Path == "" {
			out = append(out, "the wg program is missing: pkg install wireguard-tools")
		}
	}
	return out
}

// UpdateWireGuard replaces a tunnel's spec (fleet sync, edit).
func (s *Service) UpdateWireGuard(ctx context.Context, name string, w api.WireGuard, expect int64) (api.WireGuard, error) {
	if err := requireGlobal(ctx, "changing a WireGuard tunnel"); err != nil {
		return api.WireGuard{}, err
	}
	if w.Metadata.Name != "" && w.Metadata.Name != name {
		return api.WireGuard{}, invalid("renaming is not supported")
	}
	unlock, err := s.locks.lockPatient(ctx, "update wireguard "+name, wgLock(name), "wireguard/_all")
	if err != nil {
		return api.WireGuard{}, err
	}
	defer unlock()
	old, err := s.wgKind.get(name)
	if err != nil {
		return api.WireGuard{}, err
	}
	if w.Spec.Mode == "" {
		w.Spec.Mode = old.Spec.Mode
	}
	if w.Spec.Mode != old.Spec.Mode {
		return api.WireGuard{}, invalid("the mode of a tunnel cannot change")
	}
	wireguard.Defaults(name, s.d.Hostname, &w.Spec)
	for i, p := range w.Spec.Peers {
		if p.Created.IsZero() {
			for _, op := range old.Spec.Peers {
				if op.Name == p.Name {
					w.Spec.Peers[i].Created = op.Created
				}
			}
			if w.Spec.Peers[i].Created.IsZero() {
				w.Spec.Peers[i].Created = s.now().UTC()
			}
		}
	}
	if err := s.checkWireGuard(name, w.Spec); err != nil {
		return api.WireGuard{}, err
	}
	o, err := s.wgKind.update(ctx, name, expect, w.Metadata.Labels, &w.Metadata.ManagedBy, w.Spec)
	if err != nil {
		return api.WireGuard{}, err
	}
	return s.wgAfterChange(ctx, o), nil
}

// PatchWireGuard applies a merge patch.
func (s *Service) PatchWireGuard(ctx context.Context, name string, patch map[string]any, expect int64) (api.WireGuard, error) {
	cur, err := s.GetWireGuard(ctx, name)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return api.WireGuard{}, api.Errorf(api.CodeConflict, "wireguard %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	cur.Status = api.WireGuardStatus{}
	var out api.WireGuard
	if err := MergePatch(cur, patch, &out); err != nil {
		return api.WireGuard{}, err
	}
	return s.UpdateWireGuard(ctx, name, out, cur.Metadata.Generation)
}

// DeleteWireGuard removes the interface, the anchor and the keys, then the object.
func (s *Service) DeleteWireGuard(ctx context.Context, name string, expect int64) error {
	if err := requireGlobal(ctx, "deleting a WireGuard tunnel"); err != nil {
		return err
	}
	unlock, err := s.locks.lockPatient(ctx, "delete wireguard "+name, wgLock(name), "wireguard/_all")
	if err != nil {
		return err
	}
	defer unlock()
	o, err := s.wgKind.get(name)
	if err != nil {
		return err
	}
	if expect != AnyGeneration && expect != o.Meta.Generation {
		return api.Errorf(api.CodeConflict, "wireguard %q changed: current generation is %d", name, o.Meta.Generation)
	}
	if s.d.WG != nil {
		if err := s.d.WG.WGRemove(ctx, wireguard.RemoveReq{Name: name, Iface: o.Spec.Interface, Purge: true}); err != nil {
			return err
		}
	}
	if s.d.PF != nil {
		if err := ignoreCode(s.d.PF.Flush(ctx, wireguard.Anchor(name)), api.CodeNotFound); err != nil {
			s.log.Warn("flushing the anchor of a deleted tunnel failed", "wireguard", name, "err", err)
		}
	}
	if err := s.wgKind.delete(ctx, name, expect); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.wgErr, name)
	delete(s.wgPub, name)
	s.mu.Unlock()
	return nil
}

// AddWireGuardPeer enrolls a peer of a server: a key pair and a preshared key made by the helper, the next free
// address of the pool, the peer applied at once, and a join token returned once.
func (s *Service) AddWireGuardPeer(ctx context.Context, name string, q api.WireGuardPeerAdd) (api.WireGuardPeerCreated, error) {
	if err := requireGlobal(ctx, "enrolling a WireGuard peer"); err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	h, err := s.wgHost()
	if err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	if err := wireguard.ValidName("name", q.Name); err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	if q.Keepalive < 0 || q.Keepalive > wireguard.MaxKeepalive {
		return api.WireGuardPeerCreated{}, invalid("keepalive must be 0 to %d seconds", wireguard.MaxKeepalive)
	}
	unlock, err := s.locks.lockPatient(ctx, "add peer to wireguard "+name, wgLock(name))
	if err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	defer unlock()
	o, err := s.wgKind.get(name)
	if err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	if o.Spec.Mode != api.WireGuardServer {
		return api.WireGuardPeerCreated{}, invalid("wireguard %q is a client; peers are added on the server", name)
	}
	if o.Spec.Endpoint == "" {
		return api.WireGuardPeerCreated{}, invalid("wireguard %q has no endpoint that peers could dial", name).
			WithHint("set it: jailops wireguard edit " + name + " (spec.endpoint: host:port)")
	}
	for _, p := range o.Spec.Peers {
		if p.Name == q.Name {
			return api.WireGuardPeerCreated{}, api.Errorf(api.CodeAlreadyExists, "peer %q of wireguard %q already exists", q.Name, name).
				WithHint("remove it first to issue a new token: jailops wireguard peer remove " + name + " " + q.Name)
		}
	}
	var addrs []netip.Prefix
	if len(q.Address) > 0 {
		if addrs, err = wireguard.ParsePrefixes("address", q.Address, true); err != nil {
			return api.WireGuardPeerCreated{}, err
		}
		for i, a := range addrs {
			addrs[i] = netip.PrefixFrom(a.Addr(), a.Addr().BitLen())
		}
	} else if addrs, err = wireguard.PeerAddresses(o.Spec); err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	peer := api.WireGuardPeer{Name: q.Name, Created: s.now().UTC()}
	for _, a := range addrs {
		peer.AllowedIPs = append(peer.AllowedIPs, a.String())
	}
	// Check the address before any key is made (a placeholder key; the real one replaces it).
	spec := o.Spec
	spec.Peers = append(slices.Clone(o.Spec.Peers), api.WireGuardPeer{Name: peer.Name, PublicKey: placeholderKey, AllowedIPs: peer.AllowedIPs})
	if err := wireguard.ValidateSpec(name, spec); err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	srv, err := h.WGKeys(ctx, wireguard.KeysReq{Name: name})
	if err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	keys, err := h.WGPeerKeys(ctx, wireguard.PeerKeysReq{Name: name})
	if err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	peer.PublicKey = keys.PublicKey
	spec.Peers[len(spec.Peers)-1] = peer
	if err := wireguard.ValidateSpec(name, spec); err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	no, err := s.wgKind.update(ctx, name, o.Meta.Generation, o.Meta.Labels, nil, spec)
	if err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	if err := s.wgApply(ctx, no); err != nil {
		s.log.Warn("applying a new peer failed; the reconcile loop tries again", "wireguard", name, "peer", q.Name, "err", err)
	}
	ka := q.Keepalive
	if ka == 0 {
		ka = api.DefaultWireGuardKeepalive
	}
	tok := wireguard.Token{Name: q.Name, Endpoint: o.Spec.Endpoint, ServerPublicKey: srv.PublicKey, PrivateKey: keys.PrivateKey,
		PresharedKey: keys.PresharedKey, Address: peer.AllowedIPs, AllowedIPs: s.wgClientRoutes(o.Spec), DNS: o.Spec.DNS, Keepalive: ka}
	enc, err := tok.Encode()
	if err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	conf, err := tok.QuickConfig()
	if err != nil {
		return api.WireGuardPeerCreated{}, err
	}
	s.kick()
	return api.WireGuardPeerCreated{Peer: peer, Token: enc, Config: conf, Warning: TokenWarning}, nil
}

// wgClientRoutes is what a peer routes into the tunnel: the server's tunnel subnets and the subnets of the networks
// it serves.
func (s *Service) wgClientRoutes(sp api.WireGuardSpec) []string {
	var out []string
	add := func(p netip.Prefix) {
		if v := p.Masked().String(); !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if addrs, err := wireguard.ParsePrefixes("address", sp.Address, false); err == nil {
		for _, a := range addrs {
			add(a)
		}
	}
	for _, n := range sp.Networks {
		no, err := s.netKind.get(n)
		if err != nil {
			continue
		}
		if v4 := no.Spec.IPv4; v4 != nil {
			if p, err := netip.ParsePrefix(v4.Subnet); err == nil {
				add(p)
			}
		}
		if v6 := no.Spec.IPv6; v6 != nil && v6.Mode != api.IPv6None {
			if p, err := netip.ParsePrefix(v6.Subnet); err == nil {
				add(p)
			}
		}
	}
	return out
}

// RemoveWireGuardPeer removes a peer of a server; its preshared key goes with it.
func (s *Service) RemoveWireGuardPeer(ctx context.Context, name, peer string) (api.WireGuard, error) {
	if err := requireGlobal(ctx, "removing a WireGuard peer"); err != nil {
		return api.WireGuard{}, err
	}
	unlock, err := s.locks.lockPatient(ctx, "remove peer of wireguard "+name, wgLock(name))
	if err != nil {
		return api.WireGuard{}, err
	}
	defer unlock()
	o, err := s.wgKind.get(name)
	if err != nil {
		return api.WireGuard{}, err
	}
	i := slices.IndexFunc(o.Spec.Peers, func(p api.WireGuardPeer) bool { return p.Name == peer })
	if i < 0 {
		return api.WireGuard{}, notFound("peer", peer)
	}
	spec := o.Spec
	spec.Peers = slices.Delete(slices.Clone(o.Spec.Peers), i, i+1)
	no, err := s.wgKind.update(ctx, name, o.Meta.Generation, o.Meta.Labels, nil, spec)
	if err != nil {
		return api.WireGuard{}, err
	}
	return s.wgAfterChange(ctx, no), nil
}

// JoinWireGuard makes a client from a join token and brings it up. The token's secrets go to the helper and
// nowhere else.
func (s *Service) JoinWireGuard(ctx context.Context, q api.WireGuardJoin) (api.WireGuard, error) {
	if err := requireGlobal(ctx, "joining a WireGuard tunnel"); err != nil {
		return api.WireGuard{}, err
	}
	h, err := s.wgHost()
	if err != nil {
		return api.WireGuard{}, err
	}
	t, err := wireguard.DecodeToken(q.Token)
	if err != nil {
		return api.WireGuard{}, err
	}
	name := q.Name
	if name == "" {
		name = t.Name
	}
	spec := api.WireGuardSpec{Mode: api.WireGuardClient, Interface: q.Interface, Address: t.Address, Endpoint: t.Endpoint,
		PeerPublicKey: t.ServerPublicKey, AllowedIPs: t.AllowedIPs, DNS: t.DNS, Keepalive: t.Keepalive}
	if q.Endpoint != "" {
		spec.Endpoint = q.Endpoint
	}
	if len(q.Address) > 0 {
		spec.Address = q.Address
	}
	if len(q.AllowedIPs) > 0 {
		spec.AllowedIPs = q.AllowedIPs
	}
	// A token's addresses are host addresses; the interface takes them as they are.
	if addrs, err := wireguard.ParsePrefixes("address", spec.Address, true); err == nil {
		spec.Address = nil
		for _, a := range addrs {
			spec.Address = append(spec.Address, a.String())
		}
	}
	if err := checkWireGuardName(name, spec.Interface); err != nil {
		return api.WireGuard{}, err
	}
	wireguard.Defaults(name, s.d.Hostname, &spec)
	unlock, err := s.locks.lockPatient(ctx, "join wireguard "+name, wgLock(name), "wireguard/_all")
	if err != nil {
		return api.WireGuard{}, err
	}
	defer unlock()
	if err := s.wgKind.notTaken(name); err != nil {
		return api.WireGuard{}, err
	}
	if err := s.checkWireGuard(name, spec); err != nil {
		return api.WireGuard{}, err
	}
	if _, err := h.WGImport(ctx, wireguard.ImportReq{Name: name, PrivateKey: t.PrivateKey, PeerPublicKey: t.ServerPublicKey, PresharedKey: t.PresharedKey}); err != nil {
		return api.WireGuard{}, err
	}
	o, err := s.wgKind.create(ctx, api.ObjectMeta{Name: name}, spec)
	if err != nil {
		_ = h.WGRemove(ctx, wireguard.RemoveReq{Name: name, Purge: true})
		return api.WireGuard{}, err
	}
	return s.wgAfterChange(ctx, o), nil
}

// SetWireGuardDown takes a tunnel down (the interface goes, the keys stay) or brings it up again.
func (s *Service) SetWireGuardDown(ctx context.Context, name string, down bool) (api.WireGuard, error) {
	if err := requireGlobal(ctx, "starting or stopping a WireGuard tunnel"); err != nil {
		return api.WireGuard{}, err
	}
	unlock, err := s.locks.lockPatient(ctx, "wireguard up/down "+name, wgLock(name))
	if err != nil {
		return api.WireGuard{}, err
	}
	defer unlock()
	o, err := s.wgKind.get(name)
	if err != nil {
		return api.WireGuard{}, err
	}
	spec := o.Spec
	spec.Down = down
	no, err := s.wgKind.update(ctx, name, o.Meta.Generation, o.Meta.Labels, nil, spec)
	if err != nil {
		return api.WireGuard{}, err
	}
	return s.wgAfterChange(ctx, no), nil
}

// RotateWireGuardKeys gives a tunnel a new private key. Every peer of a server, or the server of a client, needs
// the new public key afterwards.
func (s *Service) RotateWireGuardKeys(ctx context.Context, name string) (api.WireGuardKeys, error) {
	if err := requireGlobal(ctx, "rotating WireGuard keys"); err != nil {
		return api.WireGuardKeys{}, err
	}
	h, err := s.wgHost()
	if err != nil {
		return api.WireGuardKeys{}, err
	}
	unlock, err := s.locks.lockPatient(ctx, "rotate wireguard "+name, wgLock(name))
	if err != nil {
		return api.WireGuardKeys{}, err
	}
	defer unlock()
	o, err := s.wgKind.get(name)
	if err != nil {
		return api.WireGuardKeys{}, err
	}
	k, err := h.WGKeys(ctx, wireguard.KeysReq{Name: name, Rotate: true})
	if err != nil {
		return api.WireGuardKeys{}, err
	}
	s.emitIn(ctx, "", "wireguard-keys-rotated", "/api/v1/wireguard/"+name)
	if err := s.wgApply(ctx, o); err != nil {
		s.log.Warn("applying the rotated key failed; the reconcile loop tries again", "wireguard", name, "err", err)
	}
	warn := "the server of this client must be given the new public key: remove the peer there and enroll it again"
	if o.Spec.Mode == api.WireGuardServer {
		warn = "every peer must be given the new public key: issue new tokens (jailops wireguard peer remove, then peer add)"
	}
	return api.WireGuardKeys{PublicKey: k.PublicKey, Warning: warn}, nil
}

// wireguardDesired is the reconcile loop's view of the tunnels.
func (s *Service) wireguardDesired() []reconcile.WireGuardDesired {
	objs, err := s.wgKind.list()
	if err != nil {
		return nil
	}
	out := make([]reconcile.WireGuardDesired, 0, len(objs))
	for _, o := range objs {
		out = append(out, s.wgDesired(o))
	}
	return out
}

func (s *Service) hasWireGuard() bool {
	objs, err := s.wgKind.list()
	return err == nil && len(objs) > 0
}

// wireguardDescChecks lists the interfaces of tunnels whose description is missing or different. The helper
// answers only for an interface it created for the object.
func (s *Service) wireguardDescChecks(ctx context.Context, quote func(string) string) []string {
	objs, err := s.wgKind.list()
	if err != nil || s.d.WG == nil {
		return nil
	}
	var out []string
	for _, o := range objs {
		if o.Spec.Down {
			continue
		}
		sh, err := s.d.WG.WGShow(ctx, wireguard.ShowReq{Name: o.Meta.Name, Iface: o.Spec.Interface})
		if want := render.WireGuardDesc(o.Meta.Name); err == nil && sh.Exists && sh.Description != want {
			out = append(out, o.Spec.Interface+" ("+quote(sh.Description)+")")
		}
	}
	return out
}

// doctorWireGuard checks what tunnels need from the host: the wg program, the module, forwarding for the networks
// they serve, and the pf rule for a server's listen port. Hosts without a tunnel are not bothered.
func (s *Service) doctorWireGuard(ctx context.Context, c *checkSet) {
	objs, err := s.wgKind.list()
	if err != nil || len(objs) == 0 {
		return
	}
	if s.d.WG == nil {
		c.add("wireguard.tools", api.DoctorUnknown, "the privileged helper is not reachable", "")
		return
	}
	t, err := s.d.WG.WGTools(ctx)
	switch {
	case err != nil:
		c.add("wireguard.tools", api.DoctorUnknown, err.Error(), "")
	case t.Path == "":
		c.add("wireguard.tools", api.DoctorWarn, "the wg program is missing ("+strings.Join(wireguard.Binaries, " or ")+"): tunnels cannot be configured",
			"pkg install wireguard-tools")
	case !t.Module:
		c.add("wireguard.tools", api.DoctorWarn, "wg is "+t.Path+" but the kernel module "+wireguard.Module+" is not loaded",
			"the reconcile loop loads it; to load it at boot, add if_wg_load=\"YES\" to /boot/loader.conf")
	default:
		c.add("wireguard.tools", api.DoctorOK, "wg is "+t.Path+" and "+wireguard.Module+" is loaded", "")
	}
	needFwd := false
	var ports []int
	for _, o := range objs {
		if o.Spec.Mode == api.WireGuardServer && !o.Spec.Down {
			ports = append(ports, o.Spec.ListenPort)
			needFwd = needFwd || len(o.Spec.Networks) > 0
		}
	}
	if needFwd {
		v, err := s.sysctl(ctx, "net.inet.ip.forwarding")
		switch {
		case err != nil:
			c.add("wireguard.forwarding", api.DoctorUnknown, err.Error(), "")
		case v != "1":
			c.add("wireguard.forwarding", api.DoctorWarn, "a tunnel serves JailOps networks but net.inet.ip.forwarding is off",
				"sysrc gateway_enable=YES and sysctl net.inet.ip.forwarding=1 (JailOps never sets forwarding)")
		default:
			c.add("wireguard.forwarding", api.DoctorOK, "forwarding is on for the networks the tunnels serve", "")
		}
	}
	if len(ports) > 0 {
		ok, avail, rules := s.runOK(ctx, "pfctl", "-s", "rules")
		var missing []string
		for _, p := range ports {
			if !strings.Contains(rules, fmt.Sprintf("port = %d", p)) {
				missing = append(missing, wireguard.FirewallRule(p))
			}
		}
		switch {
		case !ok || !avail:
			c.add("wireguard.firewall", api.DoctorUnknown, "the loaded pf rules cannot be read", "make sure pf.conf has: "+strings.Join(portsRules(ports), "; "))
		case len(missing) > 0:
			c.add("wireguard.firewall", api.DoctorWarn, "no pf rule of the host mentions the listen port of a tunnel",
				"add to /etc/pf.conf and reload it with pfctl -f /etc/pf.conf: "+strings.Join(missing, "; "))
		default:
			c.add("wireguard.firewall", api.DoctorOK, "the host's pf rules mention the listen ports of the tunnels", "")
		}
	}
}

func portsRules(ports []int) []string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = wireguard.FirewallRule(p)
	}
	return out
}
