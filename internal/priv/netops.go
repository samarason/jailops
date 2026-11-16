package priv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Bounds for an epair MTU. 576 is the IPv4 minimum, 9216 the
// largest jumbo frame common drivers take.
const (
	MinMTU = 576
	MaxMTU = 9216
)

// mtuSetter is implemented by an ifconfig.Client that can change an MTU.
// PROPOSED interface change (internal/sys/ifconfig is not edited here):
//
//	SetMTU(ctx context.Context, iface string, mtu int) error
//
// until ifconfig.Client has it, Local runs ifconfig(8) itself with a fixed
// argument vector after validating the interface and the number.
type mtuSetter interface {
	SetMTU(ctx context.Context, iface string, mtu int) error
}

// SetMTU sets the MTU of an interface JailOps owns. It replaces any use of
// the command Runner for "ifconfig <epair> mtu <n>".
// UNVERIFIED on FreeBSD.
func (l *Local) SetMTU(ctx context.Context, iface string, mtu int) error {
	if mtu < MinMTU || mtu > MaxMTU {
		return invalid("mtu %d is outside %d..%d", mtu, MinMTU, MaxMTU)
	}
	if err := l.ifOwned(ctx, iface); err != nil {
		return err
	}
	if s, ok := l.d.Net.(mtuSetter); ok {
		return s.SetMTU(ctx, iface, mtu)
	}
	return l.ifconfigRun(ctx, iface, "mtu", strconv.Itoa(mtu))
}

// checkNDPRoute accepts only a global unicast IPv6 address (unique-local
// included): a /128 host route for an address JailOps answers neighbor
// discovery for in proxy mode.
func checkNDPRoute(addr netip.Addr) error {
	switch {
	case !addr.IsValid() || !addr.Is6() || addr.Is4In6() || addr.Zone() != "":
		return invalid("%q is not a plain IPv6 address", addr)
	case !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsLoopback() || addr.IsUnspecified():
		return forbidden("%s is not a global unicast address", addr)
	}
	return nil
}

// NDPRouteAdd adds the /128 host route addr through iface (an epair of JailOps; netGuard.RouteAdd reads it in the kernel). Nothing else: no gateway, no prefix, no default.
// UNVERIFIED on FreeBSD.
func (l *Local) NDPRouteAdd(ctx context.Context, addr netip.Addr, iface string) error {
	r, err := l.ndpRoute(addr, iface)
	if err != nil {
		return err
	}
	if err := l.checkNDPAddress(ctx, addr); err != nil {
		return err
	}
	return l.Net().RouteAdd(ctx, r)
}

// NDPRouteDelete removes a route NDPRouteAdd made.
func (l *Local) NDPRouteDelete(ctx context.Context, addr netip.Addr, iface string) error {
	r, err := l.ndpRoute(addr, iface)
	if err != nil {
		return err
	}
	return l.Net().RouteDelete(ctx, r)
}

func (l *Local) ndpRoute(addr netip.Addr, iface string) (ifconfig.Route, error) {
	if err := checkNDPRoute(addr); err != nil {
		return ifconfig.Route{}, err
	}
	if err := ifconfig.ValidateIfName(iface); err != nil {
		return ifconfig.Route{}, err
	}
	return ifconfig.Route{Dest: netip.PrefixFrom(addr, 128).String(), Interface: iface}, nil
}

// checkRejectRoute accepts a reject route only for the subnet of a network JailOps has stored (its IPv4 subnet, or the
// IPv6 prefix of a network in routed mode): the helper never makes a route that answers with an error for any other
// prefix, which would cut the host off from it.
func (l *Local) checkRejectRoute(ctx context.Context, r ifconfig.Route) error {
	p, err := netip.ParsePrefix(r.Dest)
	if err != nil || r.Gateway != "" || r.Interface != "" {
		return invalid("invalid reject route %q", r.Dest)
	}
	dir := filepath.Join(l.cfg.StateDir, "objects", string(api.KindNetwork))
	names, err := l.listState(dir)
	if err != nil {
		return fmt.Errorf("network objects: %w", err)
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		b, err := l.readState(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		var d networkDoc
		if json.Unmarshal(b, &d) != nil {
			continue
		}
		if v4 := d.Spec.IPv4; v4 != nil {
			if q, err := netip.ParsePrefix(v4.Subnet); err == nil && q.Masked() == p.Masked() {
				return nil
			}
		}
		if v6 := d.Spec.IPv6; v6 != nil && v6.Mode == api.IPv6Routed {
			if q, err := netip.ParsePrefix(v6.Subnet); err == nil && q.Masked() == p.Masked() {
				return nil
			}
		}
	}
	return forbidden("%s is not the subnet of a network of JailOps", p)
}

// storedNetworks are the networks JailOps has stored.
func (l *Local) storedNetworks() ([]networkDoc, error) {
	dir := filepath.Join(l.cfg.StateDir, "objects", string(api.KindNetwork))
	names, err := l.listState(dir)
	if err != nil {
		return nil, fmt.Errorf("network objects: %w", err)
	}
	var out []networkDoc
	for _, n := range names {
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		b, err := l.readState(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		var d networkDoc
		if json.Unmarshal(b, &d) == nil {
			out = append(out, d)
		}
	}
	return out, nil
}

// checkStoredNetworkAddr accepts an address (or the destination of a host route) on an interface of JailOps only when it
// lies in the subnet of a network JailOps has stored: its IPv4 subnet or its IPv6 prefix. The link-local addresses of
// an epair's host end (fe80::1, the gateway of every jail) are always fine. Without it the daemon could have the host
// put any address on a jail's link or send the host's traffic for any address into a jail (8.8.8.8/32, a resolver, a
// mirror). what names the thing in the refusal.
func (l *Local) checkStoredNetworkAddr(a netip.Addr, what string) error {
	if a.Is6() && a.IsLinkLocalUnicast() {
		return nil
	}
	nets, err := l.storedNetworks()
	if err != nil {
		return err
	}
	for _, n := range nets {
		for _, p := range networkPrefixes(n.Spec) {
			if p.Contains(a) {
				return nil
			}
		}
	}
	return forbidden("%s: %s is not inside the subnet of a network of JailOps", what, a)
}

// checkNDPAddress accepts the /128 route of the NDP proxy only for the address of a jail: inside the prefix of a stored
// network in proxy mode that the proxy approves (ndpPrefixes), not the prefix's own subnet-router anycast address, not
// the address of the uplink's IPv6 default router and not one that the uplink's neighbor cache holds: the proxy
// answers neighbor discovery for what it has a route for, so a route for the router's address would put the host
// between the router and every host on the segment.
func (l *Local) checkNDPAddress(ctx context.Context, addr netip.Addr) error {
	nets, err := l.storedNetworks()
	if err != nil {
		return err
	}
	for _, n := range nets {
		v6 := n.Spec.IPv6
		if v6 == nil || v6.Mode != api.IPv6Proxy {
			continue
		}
		p, err := netip.ParsePrefix(v6.Subnet)
		if err != nil || !p.Masked().Contains(addr) {
			continue
		}
		if addr == p.Masked().Addr() {
			return forbidden("%s is the subnet-router anycast address of %s", addr, p)
		}
		up, err := l.ndpPrefixes(ctx, n.Spec.Uplink)
		if err != nil {
			return err
		}
		if !up.contains(addr) {
			continue
		}
		if l.neighborOnUplink(ctx, n.Spec.Uplink, addr) {
			return forbidden("%s is the address of a router or host on %s, not of a jail", addr, n.Spec.Uplink)
		}
		return nil
	}
	return forbidden("%s is not inside the prefix of a network in IPv6 proxy mode", addr)
}

// neighborOnUplink reports whether addr is the IPv6 default router of the host or an entry of the neighbor cache on the
// uplink. A lookup that fails says no: the checks above already bind the address to a proxy prefix.
func (l *Local) neighborOnUplink(ctx context.Context, uplink string, addr netip.Addr) bool {
	if res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "route", Args: []string{"-n", "get", "-inet6", "default"}, Timeout: 10 * time.Second}); err == nil {
		for _, line := range strings.Split(string(res.Stdout), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "gateway:" {
				if g, err := netip.ParseAddr(strings.SplitN(f[1], "%", 2)[0]); err == nil && g == addr {
					return true
				}
			}
		}
	}
	if res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "ndp", Args: []string{"-an"}, Timeout: 10 * time.Second}); err == nil {
		for _, line := range strings.Split(string(res.Stdout), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[2] == uplink {
				if g, err := netip.ParseAddr(strings.SplitN(f[0], "%", 2)[0]); err == nil && g == addr {
					return true
				}
			}
		}
	}
	return false
}
