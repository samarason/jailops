package fake

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// WireGuard in the fake: tunnels are stored like other objects; keys are made from a counter (never real), a peer
// enrollment returns a join token in the daemon's format, and the status reports a handshake for every peer.
// Nothing the fake hands out is a usable key.

func (s *Server) setupWireGuard() {
	k := s.wireguard
	k.keep = func(dst, old *api.WireGuard) { dst.Status = old.Status }
	k.validate = func(w, old *api.WireGuard) *api.Error {
		if old != nil && w.Spec.Mode != "" && w.Spec.Mode != old.Spec.Mode {
			return api.Errorf(api.CodeInvalid, "the mode of a tunnel cannot change")
		}
		if w.Spec.Mode != api.WireGuardServer && w.Spec.Mode != api.WireGuardClient && (old == nil || w.Spec.Mode != "") {
			return api.Errorf(api.CodeInvalid, "mode must be server or client")
		}
		if len(w.Spec.Address) == 0 {
			return api.Errorf(api.CodeInvalid, "a tunnel needs at least one address with a prefix, for example 10.99.0.1/24")
		}
		for _, a := range w.Spec.Address {
			if _, err := netip.ParsePrefix(a); err != nil {
				return api.Errorf(api.CodeInvalid, "address %q is not an address with a prefix length", a)
			}
		}
		if w.Spec.Mode == api.WireGuardClient && old == nil && w.Spec.PeerPublicKey == "" {
			return api.Errorf(api.CodeInvalid, "a client is made from a join token").WithHint("jailops wireguard join NAME --token-file TOKEN-FILE")
		}
		for _, n := range w.Spec.Networks {
			if s.networks.items[n] == nil {
				return notFound("network", n)
			}
		}
		for n, o := range k.items {
			if n == w.Metadata.Name {
				continue
			}
			if o.Spec.ListenPort != 0 && o.Spec.ListenPort == w.Spec.ListenPort {
				return api.Errorf(api.CodeAlreadyExists, "listen port %d is used by wireguard %q", w.Spec.ListenPort, n)
			}
		}
		return nil
	}
	k.assign = func(w, old *api.WireGuard) *api.Error {
		if old != nil && w.Spec.Mode == "" {
			w.Spec.Mode = old.Spec.Mode
		}
		s.wgDefaults(w)
		if old != nil {
			w.Status = old.Status
		} else {
			w.Status.PublicKey = s.wgKey()
		}
		return nil
	}
	k.decorate = func(w *api.WireGuard) { s.wgStatus(w) }
	k.onDelete = func(w *api.WireGuard) {}
}

func (s *Server) wgDefaults(w *api.WireGuard) {
	sp := &w.Spec
	if sp.Interface == "" {
		sp.Interface = "wg-" + w.Metadata.Name
	}
	switch sp.Mode {
	case api.WireGuardServer:
		if sp.ListenPort == 0 {
			sp.ListenPort = api.DefaultWireGuardPort
		}
		if len(sp.AllowedIPs) == 0 {
			for _, a := range sp.Address {
				if p, err := netip.ParsePrefix(a); err == nil {
					sp.AllowedIPs = append(sp.AllowedIPs, p.Masked().String())
				}
			}
		}
		if sp.Endpoint == "" {
			sp.Endpoint = net.JoinHostPort("host.example.com", strconv.Itoa(sp.ListenPort))
		}
	case api.WireGuardClient:
		if sp.Keepalive == 0 {
			sp.Keepalive = api.DefaultWireGuardKeepalive
		}
	}
}

// wgStatus fills the observed part of a copy: up unless down, a handshake for every peer.
func (s *Server) wgStatus(w *api.WireGuard) {
	st := &w.Status
	st.Interface = w.Spec.Interface
	st.Up = !w.Spec.Down
	st.Peers = nil
	if w.Spec.Mode == api.WireGuardServer {
		st.ListenPort = w.Spec.ListenPort
		st.FirewallRule = "pass in on $ext_if proto udp to port " + strconv.Itoa(w.Spec.ListenPort)
		for i, p := range w.Spec.Peers {
			ps := api.WireGuardPeerStatus{Name: p.Name, PublicKey: p.PublicKey, AllowedIPs: p.AllowedIPs, PresharedKey: true}
			if st.Up && i%2 == 0 {
				ps.LatestHandshake = s.now().Add(-42e9).UTC()
				ps.Endpoint = "198.51.100.7:4" + strconv.Itoa(1000+i)
				ps.RxBytes, ps.TxBytes = int64(1<<20+i), int64(3<<20+i)
			}
			st.Peers = append(st.Peers, ps)
		}
	} else if st.Up {
		st.ListenPort = 40001
		st.Peers = []api.WireGuardPeerStatus{{PublicKey: w.Spec.PeerPublicKey, Endpoint: w.Spec.Endpoint, AllowedIPs: w.Spec.AllowedIPs,
			LatestHandshake: s.now().Add(-12e9).UTC(), RxBytes: 4096, TxBytes: 8192, PresharedKey: true}}
	}
	st.Conditions = []api.Condition{{Type: "Ready", Status: api.ConditionTrue, Reason: "Up", Message: "interface " + w.Spec.Interface + " is up", Since: s.now().UTC()}}
	if w.Spec.Down {
		st.Conditions = []api.Condition{{Type: "Ready", Status: api.ConditionFalse, Reason: "Down", Message: "the tunnel is down (jailops wireguard up starts it)", Since: s.now().UTC()}}
	}
}

// wgKey returns the next fake key. s.mu is held.
func (s *Server) wgKey() string {
	s.wgKeys++
	sum := sha256.Sum256([]byte(fmt.Sprintf("jailops-fake-wireguard-%d", s.wgKeys)))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (s *Server) wgGet(w http.ResponseWriter, r *http.Request) (*api.WireGuard, bool) {
	o := s.wireguard.items[r.PathValue("name")]
	if o == nil {
		s.mu.Unlock()
		writeErr(w, notFound("wireguard", r.PathValue("name")))
		return nil, false
	}
	return o, true
}

func (s *Server) wgReply(w http.ResponseWriter, o *api.WireGuard) {
	c := clone(o)
	s.wgStatus(&c)
	s.mu.Unlock()
	writeSync(w, 200, c)
}

func (s *Server) wgTouch(o *api.WireGuard) {
	o.Metadata.Generation++
	o.Metadata.UpdatedAt = s.now()
	s.emit("wireguard-updated", "/api/v1/wireguard/"+o.Metadata.Name)
}

// wgPeerAdd enrolls a peer: the next free host address of each pool and a token.
func (s *Server) wgPeerAdd(w http.ResponseWriter, r *http.Request) {
	q, e := decode[api.WireGuardPeerAdd](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	s.mu.Lock()
	o, ok := s.wgGet(w, r)
	if !ok {
		return
	}
	fail := func(e *api.Error) { s.mu.Unlock(); writeErr(w, e) }
	if o.Spec.Mode != api.WireGuardServer {
		fail(api.Errorf(api.CodeInvalid, "wireguard %q is a client; peers are added on the server", o.Metadata.Name))
		return
	}
	if !validName(q.Name) || strings.ContainsAny(q.Name, "_.") {
		fail(api.Errorf(api.CodeInvalid, "name %q must match ^[a-z][a-z0-9-]{0,62}$", q.Name))
		return
	}
	for _, p := range o.Spec.Peers {
		if p.Name == q.Name {
			fail(api.Errorf(api.CodeAlreadyExists, "peer %q of wireguard %q already exists", q.Name, o.Metadata.Name))
			return
		}
	}
	used := map[netip.Addr]bool{}
	for _, a := range o.Spec.Address {
		if p, err := netip.ParsePrefix(a); err == nil {
			used[p.Addr()] = true
		}
	}
	for _, p := range o.Spec.Peers {
		for _, a := range p.AllowedIPs {
			if p, err := netip.ParsePrefix(a); err == nil {
				used[p.Addr()] = true
			}
		}
	}
	var addrs []string
	if len(q.Address) > 0 {
		for _, a := range q.Address {
			ad, err := netip.ParseAddr(strings.Split(a, "/")[0])
			if err != nil {
				fail(api.Errorf(api.CodeInvalid, "address %q is not an address", a))
				return
			}
			addrs = append(addrs, netip.PrefixFrom(ad, ad.BitLen()).String())
		}
	} else {
		for _, pool := range o.Spec.AllowedIPs {
			p, err := netip.ParsePrefix(pool)
			if err != nil {
				continue
			}
			for a := p.Masked().Addr().Next(); p.Contains(a); a = a.Next() {
				if !used[a] {
					addrs = append(addrs, netip.PrefixFrom(a, a.BitLen()).String())
					break
				}
			}
		}
	}
	if len(addrs) == 0 {
		fail(api.Errorf(api.CodePoolExhausted, "the address pool of the tunnel is full"))
		return
	}
	priv, psk := s.wgKey(), s.wgKey()
	peer := api.WireGuardPeer{Name: q.Name, PublicKey: s.wgKey(), AllowedIPs: addrs, Keepalive: 0, Created: s.now().UTC()}
	o.Spec.Peers = append(o.Spec.Peers, peer)
	s.wgTouch(o)
	ka := q.Keepalive
	if ka == 0 {
		ka = api.DefaultWireGuardKeepalive
	}
	var routes []string
	for _, a := range o.Spec.Address {
		if p, err := netip.ParsePrefix(a); err == nil {
			routes = append(routes, p.Masked().String())
		}
	}
	tok := map[string]any{"name": q.Name, "endpoint": o.Spec.Endpoint, "server_public_key": o.Status.PublicKey, "private_key": priv,
		"preshared_key": psk, "address": addrs, "allowed_ips": routes, "keepalive": ka}
	if len(o.Spec.DNS) > 0 {
		tok["dns"] = o.Spec.DNS
	}
	raw, _ := json.Marshal(tok)
	conf := "# WireGuard configuration of " + q.Name + ", made by JailOps. It holds a private key: keep it secret.\n[Interface]\nPrivateKey = " + priv +
		"\nAddress = " + strings.Join(addrs, ", ") + "\n\n[Peer]\nPublicKey = " + o.Status.PublicKey + "\nPresharedKey = " + psk +
		"\nEndpoint = " + o.Spec.Endpoint + "\nAllowedIPs = " + strings.Join(routes, ", ") + "\nPersistentKeepalive = " + strconv.Itoa(ka) + "\n"
	out := api.WireGuardPeerCreated{Peer: peer, Token: "jwg1." + base64.RawURLEncoding.EncodeToString(raw), Config: conf,
		Warning: "this token holds the peer's private key and the preshared key: it is shown once, is not stored on this host, and gives whoever holds it access to the tunnel; pass it on over a channel you trust"}
	s.mu.Unlock()
	writeSync(w, 201, out)
}

func (s *Server) wgPeerRemove(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	o, ok := s.wgGet(w, r)
	if !ok {
		return
	}
	peer := r.PathValue("peer")
	i := slices.IndexFunc(o.Spec.Peers, func(p api.WireGuardPeer) bool { return p.Name == peer })
	if i < 0 {
		s.mu.Unlock()
		writeErr(w, notFound("peer", peer))
		return
	}
	o.Spec.Peers = slices.Delete(o.Spec.Peers, i, i+1)
	s.wgTouch(o)
	s.wgReply(w, o)
}

func (s *Server) wgSetDown(down bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		o, ok := s.wgGet(w, r)
		if !ok {
			return
		}
		if o.Spec.Down != down {
			o.Spec.Down = down
			s.wgTouch(o)
		}
		s.wgReply(w, o)
	}
}

func (s *Server) wgRotate(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	o, ok := s.wgGet(w, r)
	if !ok {
		return
	}
	o.Status.PublicKey = s.wgKey()
	warn := "the server of this client must be given the new public key: remove the peer there and enroll it again"
	if o.Spec.Mode == api.WireGuardServer {
		warn = "every peer must be given the new public key: issue new tokens (jailops wireguard peer remove, then peer add)"
	}
	out := api.WireGuardKeys{PublicKey: o.Status.PublicKey, Warning: warn}
	s.mu.Unlock()
	writeSync(w, 200, out)
}

// wgJoin makes a client from a token in the daemon's format.
func (s *Server) wgJoin(w http.ResponseWriter, r *http.Request) {
	q, e := decode[api.WireGuardJoin](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	bad := api.Errorf(api.CodeInvalid, "not a WireGuard join token").WithHint("copy the whole token that `jailops wireguard peer add` printed; it starts with jwg1.")
	if !strings.HasPrefix(q.Token, "jwg1.") {
		writeErr(w, bad)
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(q.Token), "jwg1."))
	var tok struct {
		Name            string   `json:"name"`
		Endpoint        string   `json:"endpoint"`
		ServerPublicKey string   `json:"server_public_key"`
		PrivateKey      string   `json:"private_key"`
		Address         []string `json:"address"`
		AllowedIPs      []string `json:"allowed_ips"`
		DNS             []string `json:"dns"`
		Keepalive       int      `json:"keepalive"`
	}
	if err != nil || json.Unmarshal(raw, &tok) != nil || tok.Name == "" || tok.PrivateKey == "" || tok.ServerPublicKey == "" {
		writeErr(w, bad)
		return
	}
	name := q.Name
	if name == "" {
		name = tok.Name
	}
	obj := &api.WireGuard{Metadata: api.ObjectMeta{Name: name}, Spec: api.WireGuardSpec{Mode: api.WireGuardClient, Interface: q.Interface,
		Address: tok.Address, Endpoint: tok.Endpoint, PeerPublicKey: tok.ServerPublicKey, AllowedIPs: tok.AllowedIPs, DNS: tok.DNS, Keepalive: tok.Keepalive}}
	if q.Endpoint != "" {
		obj.Spec.Endpoint = q.Endpoint
	}
	if len(q.Address) > 0 {
		obj.Spec.Address = q.Address
	}
	if len(q.AllowedIPs) > 0 {
		obj.Spec.AllowedIPs = q.AllowedIPs
	}
	s.respond(w, s.wireguard.doCreate(r, obj))
}

// SeedWireGuard stores a tunnel as if it had been created.
func (s *Server) SeedWireGuard(w api.WireGuard) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wgDefaults(&w)
	if w.Status.PublicKey == "" {
		w.Status.PublicKey = s.wgKey()
	}
	s.wireguard.insert(&w, true)
}
