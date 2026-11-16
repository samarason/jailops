package priv

import (
	"context"
	"net/netip"
	"testing"

	"jailops.net/jailops/internal/sys/ifconfig"
)

// The daemon cannot have the host put an address on a jail's link, or send the host's traffic for an address into a
// jail, unless the address lies in the subnet of a network JailOps has stored.
func TestEpairAddressesAndRoutesAreOnlyOfStoredNetworks(t *testing.T) {
	e := newEnv(t)
	e.storeLan(t, "10.0.0.0/24")
	ctx := context.Background()
	n := e.local.Net()
	if _, _, err := e.net.EpairCreate(ctx, "jo0"); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"1.1.1.1/32", "8.8.8.8/32", "192.0.2.1/32", "2001:4860:4860::8888/128"} {
		if err := n.AddrAdd(ctx, "jo0a", netip.MustParsePrefix(a)); err == nil {
			t.Errorf("address %s was accepted", a)
		}
	}
	for _, d := range []string{"8.8.8.8/32", "1.1.1.1", "192.0.2.53/32", "2001:4860:4860::8888/128"} {
		if err := n.RouteAdd(ctx, ifconfig.Route{Dest: d, Interface: "jo0a"}); err == nil {
			t.Errorf("route %s was accepted", d)
		}
	}
	for _, a := range []string{"10.0.0.1/32", "fe80::1/64"} {
		if err := n.AddrAdd(ctx, "jo0a", netip.MustParsePrefix(a)); err != nil {
			t.Errorf("address %s refused: %v", a, err)
		}
	}
	if err := n.RouteAdd(ctx, ifconfig.Route{Dest: "10.0.0.7/32", Interface: "jo0a"}); err != nil {
		t.Errorf("a route of a stored network: %v", err)
	}
}

// The NDP proxy's /128 route is for a jail's address inside the prefix of a network in proxy mode: not the prefix's
// anycast address, not an address outside, not the router of the segment.
func TestNDPRouteIsForAddressesOfTheProxyPrefixOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, _, err := e.net.EpairCreate(ctx, "jo1"); err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]string{
		"an address outside any prefix": "2001:db8:ffff::1",
		"the anycast address":           "2001:db8:1:2:100::",
		"a global address of someone":   "2a00:1450:4001::1",
	} {
		if err := e.local.NDPRouteAdd(ctx, netip.MustParseAddr(a), "jo1a"); err == nil {
			t.Errorf("%s (%s) was accepted", name, a)
		}
	}
	// the router of the segment: the host's IPv6 default route names it
	e.runner.On("route", []string{"-n", "get", "-inet6", "default"}, "   route to: default\n    gateway: 2001:db8:1:2:100::1%em0\n")
	if err := e.local.NDPRouteAdd(ctx, netip.MustParseAddr("2001:db8:1:2:100::1"), "jo1a"); err == nil {
		t.Error("the default router's address was accepted")
	}
	if err := e.local.NDPRouteAdd(ctx, netip.MustParseAddr("2001:db8:1:2:100::2"), "jo1a"); err != nil {
		t.Errorf("a jail's address inside the proxy prefix: %v", err)
	}
}

// A forward leads to a jail of a stored network, and takes over a privileged port or one a host process listens on only
// when the request carries the admin assertion.
func TestForwardsLeaveTheHostsPortsAlone(t *testing.T) {
	e := newEnv(t)
	e.storeLan(t, "10.20.0.0/24")
	e.runner.On("sockstat", []string{"-46l"}, "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\nroot sshd 1 5 tcp4 *:2222 *:*\nroot jailopsd 2 6 tcp4 *:39110 *:*\n")
	rule := func(hostPort int, target string) string {
		return "match in on em0 inet proto tcp from any to (em0) port " + itoa(hostPort) + " rdr-to " + target + " port 80\n"
	}
	user := context.Background()
	admin := WithAdmin(context.Background(), "a")
	pf := e.local.PF()
	for name, tc := range map[string]struct {
		ctx    context.Context
		rs     string
		accept bool
	}{
		"a high free port to a jail":           {user, rule(8080, "10.20.0.5"), true},
		"the host's ssh port":                  {user, rule(2222, "10.20.0.5"), false},
		"the console port":                     {user, rule(39110, "10.20.0.5"), false},
		"a privileged port":                    {user, rule(443, "10.20.0.5"), false},
		"a privileged port with the assertion": {admin, rule(443, "10.20.0.5"), true},
		"a target that is no jail's address":   {admin, rule(8080, "198.51.100.77"), false},
		"the host's own address as target":     {admin, rule(8080, "127.0.0.1"), false},
	} {
		err := pf.Load(tc.ctx, "jailops/web/db", tc.rs)
		if tc.accept && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if !tc.accept && err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
