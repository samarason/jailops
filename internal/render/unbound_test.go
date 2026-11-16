package render

import (
	"net/netip"
	"testing"
)

func TestUnboundConf(t *testing.T) {
	a := netip.MustParseAddr
	p := netip.MustParsePrefix
	got := UnboundConf("corp.example",
		[]DNSJail{
			{Project: "verkis", Name: "web", Addrs: []netip.Addr{a("172.17.28.4")}},
			{Project: "verkis", Name: "postgres", Addrs: []netip.Addr{a("2001:db8:1::2"), a("172.17.28.2")}},
			{Project: "shop", Name: "db", Addrs: []netip.Addr{a("10.20.0.10")}},
			{Project: "shop", Name: "cache", Addrs: []netip.Addr{a("2001:db8:2::5")}}, // IPv6 only
		},
		[]DNSNet{
			{Project: "verkis", Subnets: []netip.Prefix{p("172.17.28.0/24"), p("2001:db8:1::/64")}, Gateway: a("172.17.28.1")},
			{Project: "shop", Subnets: []netip.Prefix{p("10.20.0.0/24")}, Gateway: a("10.20.0.1")},
			{Project: "idle", Subnets: []netip.Prefix{p("10.30.0.0/24")}, Gateway: a("10.30.0.1")}, // no jail runs: no view, but the resolver listens and admits the subnet
		},
		[]string{"127.0.0.1", "::1", "10.20.0.1"}) // the administrator's own interface lines: not written twice
	want := Header + `
# The names of the running jails inside their project, for the unbound of the host (docs/dns.md).
view:
	name: "jailops-shop"
	view-first: yes
	local-zone: "shop.corp.example." static
	local-data: "cache.shop.corp.example. AAAA 2001:db8:2::5"
	local-data: "cache.v6.shop.corp.example. AAAA 2001:db8:2::5"
	local-data: "db.shop.corp.example. A 10.20.0.10"
	local-data: "db.v4.shop.corp.example. A 10.20.0.10"
	local-data: "host.shop.corp.example. A 10.20.0.1"
	local-data: "host.v4.shop.corp.example. A 10.20.0.1"
view:
	name: "jailops-verkis"
	view-first: yes
	local-zone: "verkis.corp.example." static
	local-data: "host.v4.verkis.corp.example. A 172.17.28.1"
	local-data: "host.verkis.corp.example. A 172.17.28.1"
	local-data: "postgres.v4.verkis.corp.example. A 172.17.28.2"
	local-data: "postgres.v6.verkis.corp.example. AAAA 2001:db8:1::2"
	local-data: "postgres.verkis.corp.example. A 172.17.28.2"
	local-data: "postgres.verkis.corp.example. AAAA 2001:db8:1::2"
	local-data: "web.v4.verkis.corp.example. A 172.17.28.4"
	local-data: "web.verkis.corp.example. A 172.17.28.4"
server:
	interface: 10.30.0.1
	interface: 172.17.28.1
	ip-transparent: yes
	access-control: 10.20.0.0/24 allow
	access-control-view: 10.20.0.0/24 "jailops-shop"
	access-control: 172.17.28.0/24 allow
	access-control-view: 172.17.28.0/24 "jailops-verkis"
	access-control: 2001:db8:1::/64 allow
	access-control-view: 2001:db8:1::/64 "jailops-verkis"
	access-control: 10.30.0.0/24 allow
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}
