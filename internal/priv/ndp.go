package priv

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/ndproxy"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/sdk/api"
)

// The IPv6 proxy mode answers neighbor solicitations on the uplink for the addresses of jails, which needs two things
// only root has: a packet capture of the uplink and the right to send frames on it. The helper offers exactly those,
// typed, and nothing wider:
//
//   - ndp.open hands the daemon a read-only, locked BPF descriptor that is attached to the uplink with a filter that
//     passes neighbor discovery messages only. The daemon cannot re-attach it, change the filter or write through it.
//   - ndp.answer makes the helper build and send one Neighbor Advertisement itself, after checking it against the
//     operator's configuration. The daemon never sends a frame of its own.
//
// What may be answered is decided from the networks JailOps has stored: the helper answers only for addresses inside the
// subnet of a network in IPv6 proxy mode on that uplink, and only when it checks out (ndpPrefixes). The daemon cannot
// make it answer for anything else, at more than a bounded rate.

// ndpUplink is an uplink the IPv6 proxy works on, with the prefixes it may answer for.
type ndpUplink struct {
	Uplink   string
	Prefixes []netip.Prefix
}

// NDPDevice is the system side of the two operations. Tests inject a fake; NewSystem uses the BPF implementation.
type NDPDevice interface {
	// Capture returns a read-only, locked descriptor on uplink that delivers neighbor discovery frames.
	Capture(uplink string, promisc bool) (*os.File, error)
	// Send writes one complete Ethernet frame on uplink.
	Send(uplink string, frame []byte) error
	// HardwareAddr is the Ethernet address of uplink.
	HardwareAddr(uplink string) ([6]byte, error)
	// LocalAddrs are the IPv6 addresses assigned to interfaces of this host.
	LocalAddrs() ([]netip.Addr, error)
	// HostRoutes are the /128 host routes of the IPv6 table: address to the interface the route leaves through.
	HostRoutes() (map[netip.Addr]string, error)
}

// NDPAnswerReq is the argument of ndp.answer.
type NDPAnswerReq struct {
	Uplink       string `json:"uplink"`
	Target       string `json:"target"`
	RequesterIP  string `json:"requester_ip"`
	RequesterMAC string `json:"requester_mac"`
	// Announce asks for an unsolicited advertisement of Target to all nodes instead of an answer to a requester.
	Announce bool `json:"announce,omitempty"`
}

type ndpArgs struct {
	Uplink  string `json:"uplink"`
	Promisc bool   `json:"promisc,omitempty"`
}

const (
	// ndpAnswersPerSecond bounds the advertisements the helper sends per uplink; a flood of solicitations cannot
	// turn the helper into a packet source.
	ndpAnswersPerSecond = 200
	ndpMinPrefixBits    = ipam.ProxyApproveMin6
	ndpMaxPrefixBits    = ipam.ProxyApproveMax6
)

type ndpBucket struct {
	tokens float64
	last   time.Time
}

// ndpState is the helper's rate limiter state.
type ndpState struct {
	mu      sync.Mutex
	buckets map[string]*ndpBucket
	now     func() time.Time
	// routes is the last reading of the host routes and when it was taken.
	routes   map[netip.Addr]string
	routesAt time.Time
}

// ndpRoutesMaxAge is how long a reading of the host routes is used: the answers are rate limited, the table is not
// to be read for each one.
const ndpRoutesMaxAge = time.Second

// ndpRoutesMissAge is how old a reading may be when an address is not in it: the table is read again then, because the
// route of a jail that has just started is installed only a moment before the daemon announces it, and an
// announcement refused for a reading that is a second old would wait for the proxy's retry. The bound (four readings a
// second) keeps a stream of requests for unknown addresses from making the helper read the table for each.
const ndpRoutesMissAge = 250 * time.Millisecond

// hostRouteVia returns the interface a /128 host route for addr leaves through.
func (s *ndpState) hostRouteVia(dev NDPDevice, addr netip.Addr) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	if s.routes == nil || now().Sub(s.routesAt) > ndpRoutesMaxAge {
		r, err := dev.HostRoutes()
		if err != nil {
			return "", false, err
		}
		s.routes, s.routesAt = r, now()
	}
	iface, ok := s.routes[addr]
	if !ok && now().Sub(s.routesAt) >= ndpRoutesMissAge {
		r, err := dev.HostRoutes()
		if err != nil {
			return "", false, err
		}
		s.routes, s.routesAt = r, now()
		iface, ok = s.routes[addr]
	}
	return iface, ok, nil
}

func (s *ndpState) allow(uplink string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil {
		s.buckets = map[string]*ndpBucket{}
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	b := s.buckets[uplink]
	t := now()
	if b == nil {
		b = &ndpBucket{tokens: ndpAnswersPerSecond, last: t}
		s.buckets[uplink] = b
	}
	b.tokens += t.Sub(b.last).Seconds() * ndpAnswersPerSecond
	if b.tokens > ndpAnswersPerSecond {
		b.tokens = ndpAnswersPerSecond
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ndpPrefixes are the prefixes the proxy may answer for on an uplink: the subnets of the stored networks in proxy mode that
// use it, each checked here, by the helper itself: between /48 and /120, global or unique-local, no address of the host
// inside it on any interface, no overlap with another stored network, and the uplink a plain interface of the host (not a
// loopback, a bridge, an interface of JailOps or a member of a bridge).
func (l *Local) ndpPrefixes(ctx context.Context, uplink string) (ndpUplink, error) {
	u := ndpUplink{Uplink: uplink}
	nets, err := l.storedNetworks()
	if err != nil {
		return u, err
	}
	var mine []netip.Prefix
	for _, n := range nets {
		if v6 := n.Spec.IPv6; v6 != nil && v6.Mode == api.IPv6Proxy && n.Spec.Uplink == uplink {
			p, err := netip.ParsePrefix(v6.Subnet)
			if err != nil {
				continue
			}
			mine = append(mine, p.Masked())
		}
	}
	if len(mine) == 0 {
		return u, forbidden("no network in IPv6 proxy mode uses %q: the proxy answers for the subnets of such networks only", uplink)
	}
	list, err := l.d.Net.List(ctx)
	if err != nil {
		return u, err
	}
	var up *ifconfig.Iface
	for k := range list {
		if list[k].Name == uplink {
			up = &list[k]
		}
	}
	if up == nil {
		return u, forbidden("%q is not an interface of this host", uplink)
	}
	for _, g := range up.Groups {
		if g == "lo" || g == "bridge" || g == "epair" || g == "wg" || g == "tun" {
			return u, forbidden("%q is a %s interface: the IPv6 proxy needs a plain interface", uplink, g)
		}
	}
	if ifconfig.HasMarker(up.Description) {
		return u, forbidden("%q is an interface of JailOps", uplink)
	}
	for _, i := range list {
		for _, m := range i.Members {
			if m.Name == uplink {
				return u, forbidden("%q is a member of bridge %s: the IPv6 proxy needs a plain interface", uplink, i.Name)
			}
		}
	}
	for _, p := range mine {
		switch {
		case !p.Addr().Is6() || p.Addr().Is4In6():
			return u, forbidden("%s is not an IPv6 prefix", p)
		case p.Bits() < ndpMinPrefixBits || p.Bits() > ndpMaxPrefixBits:
			return u, forbidden("prefix %s must be between /%d and /%d", p, ndpMinPrefixBits, ndpMaxPrefixBits)
		case !p.Addr().IsGlobalUnicast():
			return u, forbidden("prefix %s is not a global or unique-local unicast prefix", p)
		}
		for _, i := range list {
			for _, h := range i.Inet6 {
				if p.Contains(h.Addr()) {
					return u, forbidden("prefix %s holds the host's own address %s on %s", p, h.Addr(), i.Name)
				}
			}
		}
		for _, n := range nets {
			for _, o := range networkPrefixes(n.Spec) {
				if o != p && o.Overlaps(p) {
					return u, forbidden("prefix %s overlaps %s of network %q", p, o, n.Metadata.Name)
				}
			}
		}
		u.Prefixes = append(u.Prefixes, p)
	}
	return u, nil
}

func networkPrefixes(s api.NetworkSpec) []netip.Prefix {
	var out []netip.Prefix
	if s.IPv4 != nil {
		if p, err := netip.ParsePrefix(s.IPv4.Subnet); err == nil {
			out = append(out, p.Masked())
		}
	}
	if s.IPv6 != nil && s.IPv6.Mode != api.IPv6None {
		if p, err := netip.ParsePrefix(s.IPv6.Subnet); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func (u ndpUplink) contains(a netip.Addr) bool {
	for _, p := range u.Prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// NDPOpen implements Host.
func (l *Local) NDPOpen(ctx context.Context, uplink string, promisc bool) (*os.File, error) {
	if err := ifconfig.ValidateIfName(uplink); err != nil {
		return nil, err
	}
	if l.d.NDP == nil {
		return nil, api.Errorf(api.CodeUnsupported, "packet capture is not available here")
	}
	if _, err := l.ndpPrefixes(ctx, uplink); err != nil {
		return nil, err
	}
	return l.d.NDP.Capture(uplink, promisc)
}

// NDPAnswer implements Host: it validates the request against the stored networks and sends one advertisement.
func (l *Local) NDPAnswer(ctx context.Context, q NDPAnswerReq) error {
	if err := ifconfig.ValidateIfName(q.Uplink); err != nil {
		return err
	}
	up, err := l.ndpPrefixes(ctx, q.Uplink)
	if err != nil {
		return err
	}
	target, err := netip.ParseAddr(q.Target)
	if err != nil || !target.Is6() || target.Is4In6() || target.Zone() != "" {
		return invalid("ndp.answer: target %q is not an IPv6 address", q.Target)
	}
	if !up.contains(target) {
		return forbidden("ndp.answer: %s is outside the subnets of the networks in proxy mode on %s", target, q.Uplink)
	}
	if q.Announce {
		return l.ndpAnnounce(q.Uplink, target)
	}
	req, err := netip.ParseAddr(q.RequesterIP)
	if err != nil || !req.Is6() || req.Is4In6() || req.Zone() != "" {
		return invalid("ndp.answer: requester %q is not an IPv6 address", q.RequesterIP)
	}
	// An unspecified source is Duplicate Address Detection, which is never answered. Any unicast requester is
	// answered with one frame to its own link-layer address (a router asks from its link-local or global address,
	// which need not be inside the approved prefix); the advertisement is about an approved target only.
	if req.IsUnspecified() || req.IsMulticast() || req.IsLoopback() {
		return forbidden("ndp.answer: requester %s is not a unicast neighbor on %s", req, q.Uplink)
	}
	hw, err := net.ParseMAC(q.RequesterMAC)
	if err != nil || len(hw) != 6 {
		return invalid("ndp.answer: requester MAC %q is not an Ethernet address", q.RequesterMAC)
	}
	var rmac ndproxy.MAC
	copy(rmac[:], hw)
	if rmac.IsZero() || rmac.IsMulticast() {
		return forbidden("ndp.answer: requester MAC %s is not a unicast address", rmac)
	}
	if l.d.NDP == nil {
		return api.Errorf(api.CodeUnsupported, "packet sending is not available here")
	}
	// Never impersonate this host: its own addresses are answered by its kernel.
	own, err := l.d.NDP.LocalAddrs()
	if err != nil {
		return err
	}
	for _, a := range own {
		if a == target {
			return forbidden("ndp.answer: %s is an address of this host", target)
		}
	}
	if err := l.requireJailRoute(target); err != nil {
		return err
	}
	mac, err := l.d.NDP.HardwareAddr(q.Uplink)
	if err != nil {
		return err
	}
	if ndproxy.MAC(mac) == rmac {
		return forbidden("ndp.answer: the requester is this host")
	}
	if !l.ndp.allow(q.Uplink) {
		return api.Errorf(api.CodeBusy, "ndp.answer: too many advertisements on %s", q.Uplink)
	}
	me := ndproxy.MAC(mac)
	frame := ndproxy.BuildNA(me, rmac, target, req, target, ndproxy.FlagSolicited|ndproxy.FlagOverride, &me)
	return l.d.NDP.Send(q.Uplink, frame)
}

// ndpAnnounce sends one unsolicited advertisement of an approved target to all nodes on the uplink: what a router
// needs to learn that the address is here, with no requester to name.
func (l *Local) ndpAnnounce(uplink string, target netip.Addr) error {
	if l.d.NDP == nil {
		return api.Errorf(api.CodeUnsupported, "packet sending is not available here")
	}
	own, err := l.d.NDP.LocalAddrs()
	if err != nil {
		return err
	}
	for _, a := range own {
		if a == target {
			return forbidden("ndp.answer: %s is an address of this host", target)
		}
	}
	if err := l.requireJailRoute(target); err != nil {
		return err
	}
	mac, err := l.d.NDP.HardwareAddr(uplink)
	if err != nil {
		return err
	}
	if !l.ndp.allow(uplink) {
		return api.Errorf(api.CodeBusy, "ndp.answer: too many advertisements on %s", uplink)
	}
	me := ndproxy.MAC(mac)
	all := netip.MustParseAddr("ff02::1")
	return l.d.NDP.Send(uplink, ndproxy.BuildNA(me, ndproxy.MulticastMAC(all), target, all, target, ndproxy.FlagOverride, &me))
}

// requireJailRoute refuses a target that is not an address of a jail on this host. JailOps installs a /128 host route
// through one of its own interfaces for every address it proxies; anything else inside an approved prefix (the
// upstream router, another machine of the segment) is not ours to speak for, whatever the daemon says.
func (l *Local) requireJailRoute(target netip.Addr) error {
	iface, ok, err := l.ndp.hostRouteVia(l.d.NDP, target)
	if err != nil {
		return err
	}
	if !ok {
		return forbidden("ndp.answer: %s has no host route of a jail on this host", target)
	}
	if err := l.ifOwned(context.Background(), iface); err != nil {
		return forbidden("ndp.answer: the route of %s leaves through %s, which is not an interface of JailOps", target, iface)
	}
	return nil
}
