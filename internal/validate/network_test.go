package validate

import (
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func proxySpec(subnet string) api.NetworkSpec {
	return api.NetworkSpec{Uplink: "vtnet0", IPv6: &api.IPv6Net{Mode: api.IPv6Proxy, Subnet: subnet,
		Range: "2001:db8:1:2:100::10-2001:db8:1:2:100::20"}}
}

// What the proxy cannot serve is refused when the network is created: the helper accepts /48 to /120.
func TestProxySubnetsMustBeServableByTheHelper(t *testing.T) {
	if err := NetworkSpec(proxySpec("2001:db8:1:2:100::/80")); err != nil {
		t.Fatal(err)
	}
	small := proxySpec("2001:db8:1:2:100::/120")
	small.IPv6.Range = "2001:db8:1:2:100::2-2001:db8:1:2:100::20"
	if err := NetworkSpec(small); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"2001:db8::/32", "2001:db8::/47"} {
		s := proxySpec(p)
		s.IPv6.Range = "2001:db8::10-2001:db8::20"
		err := NetworkSpec(s)
		if err == nil || !strings.Contains(err.Error(), "48") {
			t.Errorf("%s: %v", p, err)
		}
	}
	if err := NetworkSpec(proxySpec("2001:db8:1:2:100::/121")); err == nil {
		t.Error("a /121 was accepted")
	}
}

func TestRoutedSubnetsAreBetween32And126(t *testing.T) {
	r := func(subnet, rng string) api.NetworkSpec {
		return api.NetworkSpec{IPv6: &api.IPv6Net{Mode: api.IPv6Routed, Subnet: subnet, Range: rng}}
	}
	if err := NetworkSpec(r("2001:db8::/32", "2001:db8::10-2001:db8::20")); err != nil {
		t.Fatal(err)
	}
	s := r("2000::/16", "2000::10-2000::20")
	if err := NetworkSpec(s); err == nil {
		t.Fatal("a routed /16 was accepted")
	}
}

// A network of jails is a network of ordinary addresses: not 0/8, link-local, multicast or class E for IPv4, and for IPv6
// a global (2000::/3) or unique-local (fc00::/7) one (the reject route of the subnet would blackhole what those mean).
func TestNetworksAreOrdinaryUnicastRanges(t *testing.T) {
	v4 := func(subnet, gw, rng string) api.NetworkSpec {
		return api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: subnet, Gateway: gw, Range: rng}}
	}
	for _, ok := range []api.NetworkSpec{
		v4("10.20.0.0/24", "10.20.0.1", "10.20.0.10-10.20.0.20"),
		v4("100.64.0.0/24", "100.64.0.1", "100.64.0.10-100.64.0.20"),
		v4("203.0.113.0/28", "203.0.113.1", "203.0.113.2-203.0.113.9"),
	} {
		if err := NetworkSpec(ok); err != nil {
			t.Errorf("%s: %v", ok.IPv4.Subnet, err)
		}
	}
	for _, bad := range []api.NetworkSpec{
		v4("0.0.0.0/8", "0.0.0.1", "0.0.0.10-0.0.0.20"),
		v4("127.0.0.0/8", "127.0.0.1", "127.0.0.10-127.0.0.20"),
		v4("169.254.0.0/16", "169.254.0.1", "169.254.0.10-169.254.0.20"),
		v4("224.0.0.0/8", "224.0.0.1", "224.0.0.10-224.0.0.20"),
		v4("240.0.0.0/8", "240.0.0.1", "240.0.0.10-240.0.0.20"),
	} {
		if err := NetworkSpec(bad); err == nil {
			t.Errorf("%s was accepted", bad.IPv4.Subnet)
		}
	}
	v6 := func(subnet, rng string) api.NetworkSpec {
		return api.NetworkSpec{IPv6: &api.IPv6Net{Mode: api.IPv6Routed, Subnet: subnet, Range: rng}}
	}
	if err := NetworkSpec(v6("fd30::/64", "fd30::10-fd30::20")); err != nil {
		t.Errorf("a unique-local network: %v", err)
	}
	for _, bad := range []api.NetworkSpec{
		v6("::/48", "::10-::20"),
		v6("fe80:1::/64", "fe80:1::10-fe80:1::20"),
		v6("ff00::/64", "ff00::10-ff00::20"),
		v6("4000::/64", "4000::10-4000::20"),
	} {
		if err := NetworkSpec(bad); err == nil {
			t.Errorf("%s was accepted", bad.IPv6.Subnet)
		}
	}
}
