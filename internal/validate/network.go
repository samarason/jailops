package validate

import (
	"net/netip"
	"strings"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/sdk/api"
)

// NetworkSpec validates a network definition.
func NetworkSpec(s api.NetworkSpec) error {
	if s.Uplink != "" {
		if err := IfName("uplink", s.Uplink); err != nil {
			return err
		}
		if ipam.IsEpairName(s.Uplink) {
			return Invalid("uplink", "uplink %q looks like a jail interface", s.Uplink)
		}
	}
	if s.MTU != 0 && (s.MTU < 576 || s.MTU > 9216) {
		return Invalid("mtu", "mtu must be 0 or between 576 and 9216")
	}
	if len(s.DNS) > 3 {
		return Invalid("dns", "at most 3 DNS servers are used by resolvers")
	}
	for _, d := range s.DNS {
		a, err := addr("dns", d)
		if err != nil {
			return err
		}
		if a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
			return Invalid("dns", "dns %q is not a usable unicast address", d)
		}
	}
	if s.IPv4 == nil && (s.IPv6 == nil || s.IPv6.Mode == api.IPv6None) {
		return Invalid("ipv4", "a network needs at least one address family")
	}
	if s.IPv4 != nil {
		if err := ipv4(s); err != nil {
			return err
		}
	}
	if s.IPv6 != nil {
		if err := ipv6(s); err != nil {
			return err
		}
		if s.IPv6.Mode != api.IPv6None && s.MTU != 0 && s.MTU < 1280 {
			return Invalid("mtu", "IPv6 needs an MTU of at least 1280")
		}
	}
	return nil
}

func ipv4(s api.NetworkSpec) error {
	n := s.IPv4
	p, err := netip.ParsePrefix(n.Subnet)
	if err != nil || !p.Addr().Is4() || p.Addr().Zone() != "" {
		return Invalid("ipv4.subnet", "ipv4.subnet %q is not an IPv4 CIDR", n.Subnet)
	}
	if p != p.Masked() {
		return Invalid("ipv4.subnet", "ipv4.subnet %q has host bits set (want %s)", n.Subnet, p.Masked())
	}
	if p.Bits() < 8 || p.Bits() > 30 {
		return Invalid("ipv4.subnet", "ipv4.subnet prefix length must be between 8 and 30")
	}
	// A network of jails is a unicast network of ordinary addresses: not "this network" (0/8), loopback, link-local,
	// multicast or the reserved class E (224/3): the reject route of the subnet would blackhole traffic that means
	// something else, and the jails would be given addresses that are not theirs to use.
	if a := p.Addr(); a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.As4()[0] == 0 || a.As4()[0] >= 224 {
		return Invalid("ipv4.subnet", "ipv4.subnet %q is not a network for jails: use a private range (10/8, 172.16/12, 192.168/16, 100.64/10) or a range that is routed to this host", n.Subnet)
	}
	gw, err := addr("ipv4.gateway", n.Gateway)
	if err != nil || !gw.Is4() {
		return Invalid("ipv4.gateway", "ipv4.gateway %q is not an IPv4 address", n.Gateway)
	}
	if !p.Contains(gw) {
		return Invalid("ipv4.gateway", "ipv4.gateway %s is outside %s", gw, p)
	}
	if gw == p.Addr() || gw == lastAddr(p) {
		return Invalid("ipv4.gateway", "ipv4.gateway %s is the network or broadcast address", gw)
	}
	r, err := ipam.ParseRange(n.Range)
	if err != nil {
		return Invalid("ipv4.range", "ipv4.range %q must be \"first-last\" with IPv4 addresses", n.Range)
	}
	if !r.First.Is4() || !p.Contains(r.First) || !p.Contains(r.Last) {
		return Invalid("ipv4.range", "ipv4.range %q is outside %s", n.Range, p)
	}
	if r.Contains(gw) {
		return Invalid("ipv4.range", "ipv4.range %q contains the gateway %s", n.Range, gw)
	}
	if err := exclusions("ipv4.exclude", n.Exclude, p); err != nil {
		return err
	}
	if n.NAT && s.Uplink == "" {
		return Invalid("ipv4.nat", "ipv4.nat needs an uplink")
	}
	return nil
}

func exclusions(field string, list []string, p netip.Prefix) error {
	ex, err := ipam.ParseExclusions(list)
	if err != nil {
		return Invalid(field, "%v", err.(*api.Error).Message)
	}
	for _, e := range ex {
		if e.First.BitLen() != p.Addr().BitLen() || !p.Contains(e.First) || !p.Contains(e.Last) {
			return Invalid(field, "exclusion %s-%s is outside %s", e.First, e.Last, p)
		}
	}
	return nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

var (
	globalUnicast6 = netip.MustParsePrefix("2000::/3")
	uniqueLocal6   = netip.MustParsePrefix("fc00::/7")
)

func ipv6(s api.NetworkSpec) error {
	n := s.IPv6
	switch n.Mode {
	case api.IPv6None:
		return nil
	case api.IPv6Routed, api.IPv6Proxy:
	default:
		return Invalid("ipv6.mode", "ipv6.mode %q must be routed, proxy or none", n.Mode)
	}
	p, err := netip.ParsePrefix(n.Subnet)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return Invalid("ipv6.subnet", "ipv6.subnet %q is not an IPv6 CIDR", n.Subnet)
	}
	if p != p.Masked() {
		return Invalid("ipv6.subnet", "ipv6.subnet %q has host bits set (want %s)", n.Subnet, p.Masked())
	}
	// What the proxy cannot serve is refused here, not when the first jail starts: the helper accepts prefixes of
	// /48 to /120.
	lo, hi := ipam.RoutedSubnetMin6, ipam.SubnetMax6
	if n.Mode == api.IPv6Proxy {
		lo, hi = ipam.ProxySubnetMin6, ipam.ProxyApproveMax6
	}
	if p.Bits() < lo || p.Bits() > hi {
		return Invalid("ipv6.subnet", "ipv6.subnet prefix length must be between %d and %d", lo, hi)
	}
	if !globalUnicast6.Contains(p.Addr()) && !uniqueLocal6.Contains(p.Addr()) {
		return Invalid("ipv6.subnet", "ipv6.subnet %q must be a global (2000::/3) or unique-local (fc00::/7) network", n.Subnet)
	}
	r, err := ipam.ParseRange(n.Range)
	if err != nil || r.First.Is4() {
		return Invalid("ipv6.range", "ipv6.range %q must be \"first-last\" with IPv6 addresses", n.Range)
	}
	if !p.Contains(r.First) || !p.Contains(r.Last) {
		return Invalid("ipv6.range", "ipv6.range %q is outside %s", n.Range, p)
	}
	if err := exclusions("ipv6.exclude", n.Exclude, p); err != nil {
		return err
	}
	if n.Mode == api.IPv6Proxy {
		if s.Uplink == "" {
			return Invalid("uplink", "ipv6 proxy mode needs an uplink to answer neighbor solicitations on")
		}
		if ipam.IsEpairName(s.Uplink) || strings.HasPrefix(s.Uplink, "bridge") {
			return Invalid("uplink", "in proxy mode the uplink %q must be a plain interface, not a bridge or an interface of a jail", s.Uplink)
		}
	}
	return nil
}
