package validate

import (
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func wantInvalid(t *testing.T, err error, field string) {
	t.Helper()
	if !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("want invalid(%s), got %v", field, err)
	}
	if got := err.(*api.Error).Detail["field"]; field != "" && got != field {
		t.Fatalf("field = %q, want %q (%v)", got, field, err)
	}
}

func TestNames(t *testing.T) {
	good := []string{"a", "web", "web-1", "a" + strings.Repeat("b", 62)}
	bad := []string{"", "1web", "Web", "web_1", "-web", "we b", "web\n", "a" + strings.Repeat("b", 63), "web.example", "é"}
	for _, s := range good {
		if err := JailName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range bad {
		wantInvalid(t, JailName(s), "name")
	}
}

func TestParseSize(t *testing.T) {
	ok := map[string]uint64{"512M": 512 << 20, "2G": 2 << 30, "100": 100, "1k": 1024, "4GiB": 4 << 30, "7B": 7, "1T": 1 << 40, "1P": 1 << 50}
	for s, want := range ok {
		got, err := ParseSize(s)
		if err != nil || got != want {
			t.Errorf("%q: %d %v", s, got, err)
		}
	}
	for _, s := range []string{"", "G", "0", "0G", "-1G", "1.5G", "1 G", "5i", "iB", "1X", "99999999999999999P", "1e3", "+5", "1GG", "12345678901234567890"} {
		wantInvalid(t, func() error { _, e := ParseSize(s); return e }(), "size")
	}
}

func TestImageRef(t *testing.T) {
	ok := map[string]ImageRef{
		"freebsd-15-0@stable": {Name: "freebsd-15-0", Alias: "stable"},
		"freebsd-15-0#g3":     {Name: "freebsd-15-0", Generation: 3, Pinned: true},
		"alpine-3-22":         {Name: "alpine-3-22"},
	}
	for s, want := range ok {
		got, err := ParseImageRef(s)
		if err != nil || got != want || got.String() != s {
			t.Errorf("%q: %+v %v", s, got, err)
		}
	}
	for _, s := range []string{"", "@stable", "freebsd-15.0@stable", "x@", "x#", "x#g", "x#g0", "x#3", "x#g03", "x#g-1", "x#g+1", "X@a", "x@A", "x y", "x#g1@a", "a/b", "x@a\n"} {
		if _, err := ParseImageRef(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func okJail() api.JailSpec {
	return api.JailSpec{
		Image:     "freebsd-15-0@stable",
		Hostname:  "web.example.org",
		Resources: api.Resources{CPU: 2, Memory: "2G", Disk: "20G"},
		Network:   []api.NetworkAttach{{Network: "lan", IPv4: "auto", IPv6: "2001:db8::5", MAC: "02:00:00:00:00:01"}},
		Firewall:  api.FirewallAttach{Policies: []string{"web"}, Tags: []string{"web", "tier-1"}},
		Volumes:   []api.VolumeAttach{{Name: "data", Mount: "/srv/data"}},
		Boot:      api.BootPolicy{Depends: []string{"db"}},
		Packages:  []string{"nginx", "py311-foo+bar"},
		Env:       map[string]string{"A": "b"},
	}
}

func TestJailSpec(t *testing.T) {
	if err := JailSpec("web", okJail()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		mut   func(*api.JailSpec)
		field string
	}{
		{"image", func(s *api.JailSpec) { s.Image = "bad ref" }, "image"},
		{"layout", func(s *api.JailSpec) { s.Layout = "nullfs" }, "layout"},
		{"hostname", func(s *api.JailSpec) { s.Hostname = "a b" }, "hostname"},
		{"hostname dot", func(s *api.JailSpec) { s.Hostname = "a..b" }, "hostname"},
		{"strategy", func(s *api.JailSpec) { s.Update.Strategy = "x" }, "update.strategy"},
		{"memory", func(s *api.JailSpec) { s.Resources.Memory = "lots" }, "resources.memory"},
		{"cpu", func(s *api.JailSpec) { s.Resources.CPU = -1 }, "resources.cpu"},
		{"net name", func(s *api.JailSpec) { s.Network[0].Network = "LAN" }, "network[0].network"},
		{"v4 junk", func(s *api.JailSpec) { s.Network[0].IPv4 = "10.0.0" }, "network[0].ipv4"},
		{"v4 family", func(s *api.JailSpec) { s.Network[0].IPv4 = "fd00::1" }, "network[0].ipv4"},
		{"v6 family", func(s *api.JailSpec) { s.Network[0].IPv6 = "10.0.0.1" }, "network[0].ipv6"},
		{"v6 multicast", func(s *api.JailSpec) { s.Network[0].IPv6 = "ff02::1" }, "network[0].ipv6"},
		{"mac upper", func(s *api.JailSpec) { s.Network[0].MAC = "02:00:00:00:00:AA" }, "network[0].mac"},
		{"mac mcast", func(s *api.JailSpec) { s.Network[0].MAC = "01:00:00:00:00:01" }, "network[0].mac"},
		{"policy", func(s *api.JailSpec) { s.Firewall.Policies = []string{"x y"} }, "firewall.policies[0]"},
		{"policy twice", func(s *api.JailSpec) { s.Firewall.Policies = []string{"x", "x"} }, "firewall.policies[1]"},
		{"tag", func(s *api.JailSpec) { s.Firewall.Tags = []string{"a b"} }, "firewall.tags[0]"},
		{"dup tag", func(s *api.JailSpec) { s.Firewall.Tags = []string{"a", "a"} }, "firewall.tags[1]"},
		{"vol mount", func(s *api.JailSpec) { s.Volumes[0].Mount = "srv/data" }, "volumes[0].mount"},
		{"vol dotdot", func(s *api.JailSpec) { s.Volumes[0].Mount = "/srv/../etc" }, "volumes[0].mount"},
		{"vol quote", func(s *api.JailSpec) { s.Volumes[0].Mount = "/srv/\"x" }, "volumes[0].mount"},
		{"vol root", func(s *api.JailSpec) { s.Volumes[0].Mount = "/" }, "volumes[0].mount"},
		{"vol dup", func(s *api.JailSpec) { s.Volumes = append(s.Volumes, s.Volumes[0]) }, "volumes[1].volume"},
		{"depends self", func(s *api.JailSpec) { s.Boot.Depends = []string{"web"} }, "boot.depends[0]"},
		{"package", func(s *api.JailSpec) { s.Packages = []string{"x;rm"} }, "packages[0]"},
		{"env key", func(s *api.JailSpec) { s.Env = map[string]string{"1A": "x"} }, "env"},
		{"env nul", func(s *api.JailSpec) { s.Env = map[string]string{"A": "x\x00"} }, "env.A"},
		{"too many nics", func(s *api.JailSpec) { s.Network = make([]api.NetworkAttach, 17) }, "network"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := okJail()
			tc.mut(&s)
			wantInvalid(t, JailSpec("web", s), tc.field)
		})
	}
	wantInvalid(t, JailSpec("Bad", okJail()), "name")
}

func okNet() api.NetworkSpec {
	return api.NetworkSpec{
		Uplink: "em0", DNS: []string{"9.9.9.9", "2620:fe::fe"},
		IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.200", Exclude: []string{"10.20.0.50-10.20.0.60"}, NAT: true},
		IPv6: &api.IPv6Net{Mode: api.IPv6Routed, Subnet: "2001:db8:1::/64", Range: "2001:db8:1::100-2001:db8:1::ffff"},
	}
}

func TestNetworkSpec(t *testing.T) {
	if err := NetworkSpec(okNet()); err != nil {
		t.Fatal(err)
	}
	proxy := func(s *api.NetworkSpec) {
		s.IPv6 = &api.IPv6Net{Mode: api.IPv6Proxy, Subnet: "2001:db8:2::/64", Range: "2001:db8:2::100-2001:db8:2::200"}
	}
	p := okNet()
	proxy(&p)
	if err := NetworkSpec(p); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		mut   func(*api.NetworkSpec)
		field string
	}{
		{"uplink epair", func(s *api.NetworkSpec) { s.Uplink = "jo0123456789a0a" }, "uplink"},
		{"mtu", func(s *api.NetworkSpec) { s.MTU = 100 }, "mtu"},
		{"mtu v6", func(s *api.NetworkSpec) { s.MTU = 1000 }, "mtu"},
		{"dns", func(s *api.NetworkSpec) { s.DNS = []string{"x"} }, "dns"},
		{"dns count", func(s *api.NetworkSpec) { s.DNS = []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"} }, "dns"},
		{"no family", func(s *api.NetworkSpec) { s.IPv4, s.IPv6 = nil, nil }, "ipv4"},
		{"v4 subnet", func(s *api.NetworkSpec) { s.IPv4.Subnet = "10.20.0.0/33" }, "ipv4.subnet"},
		{"v4 host bits", func(s *api.NetworkSpec) { s.IPv4.Subnet = "10.20.0.5/24" }, "ipv4.subnet"},
		{"v4 /31", func(s *api.NetworkSpec) { s.IPv4.Subnet = "10.20.0.0/31" }, "ipv4.subnet"},
		{"v4 gw outside", func(s *api.NetworkSpec) { s.IPv4.Gateway = "10.21.0.1" }, "ipv4.gateway"},
		{"v4 gw broadcast", func(s *api.NetworkSpec) { s.IPv4.Gateway = "10.20.0.255" }, "ipv4.gateway"},
		{"v4 gw v6", func(s *api.NetworkSpec) { s.IPv4.Gateway = "fd00::1" }, "ipv4.gateway"},
		{"v4 range outside", func(s *api.NetworkSpec) { s.IPv4.Range = "10.20.0.10-10.20.1.5" }, "ipv4.range"},
		{"v4 range gw", func(s *api.NetworkSpec) { s.IPv4.Range = "10.20.0.1-10.20.0.20" }, "ipv4.range"},
		{"v4 range empty", func(s *api.NetworkSpec) { s.IPv4.Range = "" }, "ipv4.range"},
		{"v4 range reversed", func(s *api.NetworkSpec) { s.IPv4.Range = "10.20.0.20-10.20.0.10" }, "ipv4.range"},
		{"v4 exclude outside", func(s *api.NetworkSpec) { s.IPv4.Exclude = []string{"10.30.0.1"} }, "ipv4.exclude"},
		{"v4 exclude junk", func(s *api.NetworkSpec) { s.IPv4.Exclude = []string{"zz"} }, "ipv4.exclude"},
		{"nat no uplink", func(s *api.NetworkSpec) { s.Uplink = "" }, "ipv4.nat"},
		{"v6 mode", func(s *api.NetworkSpec) { s.IPv6.Mode = "weird" }, "ipv6.mode"},
		{"v6 subnet v4", func(s *api.NetworkSpec) { s.IPv6.Subnet = "10.0.0.0/8" }, "ipv6.subnet"},
		{"v6 range outside", func(s *api.NetworkSpec) { s.IPv6.Range = "2001:db8:2::1-2001:db8:2::ff" }, "ipv6.range"},
		{"proxy no uplink", func(s *api.NetworkSpec) { proxy(s); s.Uplink = ""; s.IPv4.NAT = false }, "uplink"},
		{"proxy uplink bridge", func(s *api.NetworkSpec) { proxy(s); s.Uplink = "bridge0" }, "uplink"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := okNet()
			tc.mut(&s)
			wantInvalid(t, NetworkSpec(s), tc.field)
		})
	}
	// none disables the v6 checks
	s := okNet()
	s.IPv6 = &api.IPv6Net{Mode: api.IPv6None}
	if err := NetworkSpec(s); err != nil {
		t.Fatal(err)
	}
}

func TestFirewall(t *testing.T) {
	ok := api.FirewallPolicySpec{
		DefaultIn: "deny", DefaultOut: "allow",
		Rules: []api.FirewallRule{
			{Name: "ssh", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office", "jail:web", "10.0.0.0/8", "tag:admin"}, Ports: []string{"22", "8000-8100"}},
			{Action: "allow", Direction: "in", Proto: "tcp", Redirect: &api.Redirect{HostPort: 8080, JailPort: 80}},
			{Action: "allow", Direction: "out", Proto: "icmp6", To: []string{"any"}},
		},
	}
	rep, err := FirewallPolicySpec(ok)
	if err != nil || rep.RequiresAdmin {
		t.Fatal(rep, err)
	}
	ok.Raw = "pass quick all"
	if rep, err = FirewallPolicySpec(ok); err != nil || !rep.RequiresAdmin {
		t.Fatal(rep, err)
	}
	r := func(mut func(*api.FirewallRule)) api.FirewallPolicySpec {
		x := api.FirewallRule{Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"80"}}
		mut(&x)
		return api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{x}}
	}
	tests := []struct {
		name  string
		spec  api.FirewallPolicySpec
		field string
	}{
		{"default", api.FirewallPolicySpec{DefaultIn: "maybe", DefaultOut: "allow"}, "default_in"},
		{"default in missing", api.FirewallPolicySpec{DefaultOut: "allow"}, "default_in"},
		{"default out missing", api.FirewallPolicySpec{DefaultIn: "deny"}, "default_out"},
		{"action", r(func(x *api.FirewallRule) { x.Action = "pass" }), "rules[0].action"},
		{"direction", r(func(x *api.FirewallRule) { x.Direction = "both" }), "rules[0].direction"},
		{"proto", r(func(x *api.FirewallRule) { x.Proto = "sctp" }), "rules[0].proto"},
		{"icmp ports", r(func(x *api.FirewallRule) { x.Proto = "icmp" }), "rules[0].ports"},
		{"port 0", r(func(x *api.FirewallRule) { x.Ports = []string{"0"} }), "rules[0].ports"},
		{"port range", r(func(x *api.FirewallRule) { x.Ports = []string{"90-80"} }), "rules[0].ports"},
		{"port junk", r(func(x *api.FirewallRule) { x.Ports = []string{"80 or any"} }), "rules[0].ports"},
		{"at sign", r(func(x *api.FirewallRule) { x.From = []string{"@office"} }), "rules[0].from"},
		{"set syntax", r(func(x *api.FirewallRule) { x.From = []string{"set:Bad Name"} }), "rules[0].from"},
		{"set with an underscore", r(func(x *api.FirewallRule) { x.From = []string{"set:a_b"} }), "rules[0].from"},
		{"jail dash at the end", r(func(x *api.FirewallRule) { x.From = []string{"jail:a-"} }), "rules[0].from"},
		{"jail too long", r(func(x *api.FirewallRule) { x.From = []string{"jail:" + strings.Repeat("a", 30)} }), "rules[0].from"},
		{"unknown kind", r(func(x *api.FirewallRule) { x.From = []string{"group:office"} }), "rules[0].from"},
		{"tag syntax", r(func(x *api.FirewallRule) { x.To = []string{"tag:a b"} }), "rules[0].to"},
		{"addr", r(func(x *api.FirewallRule) { x.To = []string{"10.0.0.1; pass all"} }), "rules[0].to"},
		{"rdr out", r(func(x *api.FirewallRule) {
			x.Direction = "out"
			x.Ports = nil
			x.Redirect = &api.Redirect{HostPort: 1, JailPort: 2}
		}), "rules[0].redirect"},
		{"rdr deny", r(func(x *api.FirewallRule) {
			x.Action = "deny"
			x.Ports = nil
			x.Redirect = &api.Redirect{HostPort: 1, JailPort: 2}
		}), "rules[0].redirect"},
		{"rdr ports", r(func(x *api.FirewallRule) { x.Redirect = &api.Redirect{HostPort: 1, JailPort: 2} }), "rules[0].ports"},
		{"rdr range", r(func(x *api.FirewallRule) { x.Ports = nil; x.Redirect = &api.Redirect{HostPort: 0, JailPort: 2} }), "rules[0].redirect"},
		{"rdr proto", r(func(x *api.FirewallRule) {
			x.Proto = "icmp"
			x.Ports = nil
			x.Redirect = &api.Redirect{HostPort: 1, JailPort: 2}
		}), "rules[0].redirect"},
		{"rule name", r(func(x *api.FirewallRule) { x.Name = "x\npass all" }), "rules[0].name"},
		{"raw ctrl", api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Raw: "pass\x00"}, "raw"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FirewallPolicySpec(tc.spec)
			wantInvalid(t, err, tc.field)
		})
	}
}

func TestAddressSet(t *testing.T) {
	if err := AddressSetSpec(api.AddressSetSpec{Addresses: api.Entries("10.0.0.1", "10.0.0.0/8", "2001:db8::/32", "jail:web", "jail:web-2", "set:office")}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []api.AddressSetSpec{
		{Addresses: api.Entries("@web")}, {Addresses: api.Entries("jail:Bad Name")}, {Addresses: api.Entries("any")}, {Addresses: api.Entries("tag:x")}, {Addresses: api.Entries("1.2.3")}, {Addresses: api.Entries("set:Bad")},
		{Addresses: []api.AddressEntry{{Address: "10.0.0.1", Comment: "two\nlines"}}},
		{Addresses: []api.AddressEntry{{Address: "10.0.0.1", Comment: strings.Repeat("x", CommentMax+1)}}},
	} {
		wantInvalid(t, AddressSetSpec(s), "")
	}
}

// A member set:NAME is another set and jail:NAME a jail, flattened like an include; a set that reaches itself through
// its members is a cycle, and a jail that is not there has no addresses.
func TestFlattenSetWithJailMembers(t *testing.T) {
	sets := map[string]api.AddressSetSpec{
		"git-allow": {Addresses: api.Entries("192.0.2.7", "jail:web", "jail:web-2", "set:office", "jail:gone")},
		"office":    {Addresses: api.Entries("198.51.100.0/24")},
		"loop":      {Addresses: api.Entries("set:loop2")},
		"loop2":     {Addresses: api.Entries("set:loop")},
	}
	jails := map[string][]string{"web": {"10.0.0.5", "fd00::5"}, "web-2": {"10.0.0.6"}}
	got, err := FlattenSet("git-allow", sets, jails)
	if err != nil || strings.Join(got, " ") != "10.0.0.5 10.0.0.6 192.0.2.7 198.51.100.0/24 fd00::5" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := FlattenSet("loop", sets, jails); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("a cycle through members: %v", err)
	}
	sets["git-allow"] = api.AddressSetSpec{Addresses: api.Entries("set:nosuch")}
	if _, err := FlattenSet("git-allow", sets, jails); err == nil || !strings.Contains(err.Error(), "nosuch") {
		t.Fatalf("a set that does not exist: %v", err)
	}
}

// A reference is kind:name; @ is not used, and an unknown kind names the kinds.
func TestParseEndpointKinds(t *testing.T) {
	for s, want := range map[string]EndpointKind{"any": EndpointAny, "jail:web": EndpointJail, "jail:web-2": EndpointJail, "set:office": EndpointSet,
		"set:git-allow": EndpointSet, "tag:backend": EndpointTag, "192.0.2.7": EndpointAddr, "10.0.0.0/8": EndpointAddr, "2001:db8::1": EndpointAddr} {
		if k, _, err := ParseEndpoint(s); err != nil || k != want {
			t.Errorf("%s: kind %v, %v", s, k, err)
		}
	}
	for s, want := range map[string]string{
		"@web":                            "@ is not used: write jail:web, set:web or tag:web",
		"host:web":                        "unknown kind",
		"jail:":                           "invalid",
		"jail:Web":                        "invalid",
		"jail:web-":                       "invalid",
		"jail:" + strings.Repeat("a", 30): "invalid",
		"set:web_1":                       "invalid",
		"set:":                            "invalid",
		"tag:":                            "invalid",
		"web":                             "not a valid address",
		"999.1.1.1":                       "not a valid address",
	} {
		if _, _, err := ParseEndpoint(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want an error with %q, got %v", s, want, err)
		}
	}
}

func TestAbsPath(t *testing.T) {
	for _, s := range []string{"/", "/a", "/a/b-c_d.e+f@g:h=i,j"} {
		if err := AbsPath("p", s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "a", "//a", "/a//b", "/a/", "/./a", "/..", "/a b", "/a\"", "/a$", "/a\\", "/a\n", "/a;b", "/é", "/a`b`"} {
		if err := AbsPath("p", s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func FuzzParseSize(f *testing.F) {
	for _, s := range []string{"2G", "512M", "", "99999999999999999999", "iB"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseSize(s)
		if err == nil && n == 0 {
			t.Fatal("zero accepted")
		}
	})
}

func FuzzEndpointAndImage(f *testing.F) {
	for _, s := range []string{"jail:a", "set:a", "tag:x", "10.0.0.0/8", "any", "x#g1", "x@y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if k, v, err := ParseEndpoint(s); err == nil && k == EndpointAddr {
			if strings.ContainsAny(v, " \t\n;{},\"'#<>") {
				t.Fatalf("unsafe canonical %q", v)
			}
		}
		if r, err := ParseImageRef(s); err == nil && r.String() != s {
			t.Fatalf("round trip %q -> %q", s, r.String())
		}
	})
}

func TestQualifiedNames(t *testing.T) {
	for _, c := range []struct{ p, n, want string }{
		{"default", "nginx", "default_nginx"}, {"web", "nginx", "web_nginx"}, {"a-b", "c-d", "a-b_c-d"},
	} {
		k, err := QualifiedName(c.p, c.n)
		if err != nil || k != c.want {
			t.Fatalf("%v: %q %v", c, k, err)
		}
		if err := JailKey("name", k); err != nil {
			t.Fatalf("%q: %v", k, err)
		}
	}
	for _, c := range [][2]string{{"web", "Nginx"}, {"we_b", "x"}, {"web", "n_x"}, {"web", ""}, {"1web", "x"}, {"", "nginx"},
		{strings.Repeat("a", 40), strings.Repeat("b", 30)}} {
		if _, err := QualifiedName(c[0], c[1]); err == nil {
			t.Errorf("accepted %v", c)
		}
	}
	_, err := QualifiedName(strings.Repeat("a", 40), strings.Repeat("b", 30))
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Detail["field"] != "name" || ae.Hint == "" {
		t.Fatalf("%v", err)
	}
	for _, k := range []string{"", "nginx", "a_b_c", "_x", "x_", "A_b", "a b", "a_b\n", "a_b;", "-a", strings.Repeat("a", 65)} {
		if JailKey("name", k) == nil {
			t.Errorf("JailKey accepted %q", k)
		}
	}
	for _, n := range []string{"all", "host", "_*", "Web", ""} {
		if ProjectName(n) == nil {
			t.Errorf("ProjectName accepted %q", n)
		}
	}
}

// Injective and invertible: distinct (project, name) pairs give distinct keys.
func TestQualifiedNameInjective(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789-"
	gen := func() string {
		b := []byte{"abcdefghijklmnopqrstuvwxyz"[r.IntN(26)]}
		for i, n := 0, r.IntN(6); i < n; i++ {
			b = append(b, alpha[r.IntN(len(alpha))])
		}
		if b[len(b)-1] == '-' { // a name does not end in a hyphen
			b = append(b, 'x')
		}
		return string(b)
	}
	seen := map[string][2]string{}
	for i := 0; i < 20000; i++ {
		p, n := gen(), gen()
		k, err := QualifiedName(p, n)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[k]; dup && prev != [2]string{p, n} {
			t.Fatalf("%v and %v both give %q", prev, [2]string{p, n}, k)
		}
		seen[k] = [2]string{p, n}
		gp, gn := SplitQualified(k)
		if gp != p || gn != n {
			t.Fatalf("%q splits to %q %q, want %q %q", k, gp, gn, p, n)
		}
	}
}

func TestProjectSpecShape(t *testing.T) {
	ok := api.ProjectSpec{
		Hosts:    []string{"h1", "h2"},
		Networks: []api.ProjectNetwork{{Network: "lan"}, {Network: "dmz"}},
		Storage:  []api.ProjectStorage{{Storage: "*", Quota: "10G"}},
		Quotas:   api.ProjectQuotas{Jails: 3, Memory: "4G"}, FirewallPolicies: []string{"base"}, Images: []string{"freebsd-15-0"}, NewNetwork: true,
	}
	if err := ProjectSpec("web", ok); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(*api.ProjectSpec){
		"dup network":     func(s *api.ProjectSpec) { s.Networks = append(s.Networks, api.ProjectNetwork{Network: "dmz"}) },
		"star network":    func(s *api.ProjectSpec) { s.Networks = []api.ProjectNetwork{{Network: "*"}} },
		"bad net name":    func(s *api.ProjectSpec) { s.Networks[1].Network = "Dmz\n" },
		"bad quota":       func(s *api.ProjectSpec) { s.Storage[0].Quota = "lots" },
		"neg jails":       func(s *api.ProjectSpec) { s.Quotas.Jails = -1 },
		"bad memory":      func(s *api.ProjectSpec) { s.Quotas.Memory = "1x" },
		"bad image":       func(s *api.ProjectSpec) { s.Images = []string{"a b"} },
		"dup image":       func(s *api.ProjectSpec) { s.Images = []string{"a", "a"} },
		"host slash":      func(s *api.ProjectSpec) { s.Hosts = []string{"a/b"} },
		"host empty":      func(s *api.ProjectSpec) { s.Hosts = []string{""} },
		"dup host":        func(s *api.ProjectSpec) { s.Hosts = []string{"a", "a"} },
		"firewall inject": func(s *api.ProjectSpec) { s.FirewallPolicies = []string{"x; pass"} },
		"firewall twice":  func(s *api.ProjectSpec) { s.FirewallPolicies = []string{"x", "x"} },
	}
	for name, m := range mut {
		s := ok
		s.Networks = append([]api.ProjectNetwork(nil), ok.Networks...)
		s.Storage = append([]api.ProjectStorage(nil), ok.Storage...)
		m(&s)
		if ProjectSpec("web", s) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if ProjectSpec("all", ok) == nil {
		t.Error("reserved name accepted")
	}
}

func TestStorageSpecShape(t *testing.T) {
	for _, d := range []string{"tank/jailops", "tank/a.b_c:d-e/f", "tank/x"} {
		if err := StorageSpec("fast", api.StorageSpec{Dataset: d, Compression: "zstd-3"}); err != nil {
			t.Errorf("%q: %v", d, err)
		}
	}
	for _, d := range []string{"", "tank", "/tank/x", "tank//x", "tank/x/", "tank/x@snap", "tank/x#b", "tank/a b", "tank/a;b", "tank/$(x)", "tank/a\nb", "tank/" + strings.Repeat("a", 200)} {
		if StorageSpec("fast", api.StorageSpec{Dataset: d}) == nil {
			t.Errorf("accepted %q", d)
		}
	}
	for _, c := range []string{"off", "on", "lz4", "zle", "zstd", "zstd-19", "gzip", "gzip-9"} {
		if err := StorageSpec("s", api.StorageSpec{Dataset: "t/x", Compression: c}); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	for _, c := range []string{"zstd-0", "zstd-20", "gzip-0", "gzip-10", "lz5", "on;off"} {
		if StorageSpec("s", api.StorageSpec{Dataset: "t/x", Compression: c}) == nil {
			t.Errorf("accepted %s", c)
		}
	}
	if StorageSpec("Bad", api.StorageSpec{Dataset: "t/x"}) == nil {
		t.Error("bad name")
	}
}

func TestJailSpecProjectFields(t *testing.T) {
	s := api.JailSpec{Image: "fb", Storage: "fast", Delegate: true, Resources: api.Resources{DiskReservation: "1G"}}
	if err := JailSpec("web", s); err != nil {
		t.Fatal(err)
	}
	s.Storage = "Fast;"
	if JailSpec("web", s) == nil {
		t.Error("bad storage")
	}
	s.Storage, s.Resources.DiskReservation = "", "lots"
	if JailSpec("web", s) == nil {
		t.Error("bad reservation")
	}
}

func TestJailDevicesAreValidated(t *testing.T) {
	ok := api.JailSpec{Image: "fb", Network: []api.NetworkAttach{{Network: "lan", MTU: 1400, Egress: "10M"}, {Name: "mgmt", Network: "m"}},
		Devfs: []api.DevfsDevice{{Name: "t", Device: "tun"}}, Proxy: []api.ProxyDevice{{Name: "p", Listen: ":8080", JailPort: 80}, {Name: "q", Listen: "192.0.2.1:53", JailPort: 53, Proto: "udp"}},
		Profiles: []string{"base"}}
	if err := JailSpec("web", ok); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*api.JailSpec){
		"dup nic":      func(s *api.JailSpec) { s.Network[1].Name = "eth0" },
		"nic name":     func(s *api.JailSpec) { s.Network[1].Name = "Bad Name" },
		"mtu":          func(s *api.JailSpec) { s.Network[0].MTU = 20 },
		"rate":         func(s *api.JailSpec) { s.Network[0].Egress = "fast" },
		"devfs":        func(s *api.JailSpec) { s.Devfs[0].Device = "mem" },
		"devfs path":   func(s *api.JailSpec) { s.Devfs[0].Device = "../mem" },
		"devfs dup":    func(s *api.JailSpec) { s.Devfs = append(s.Devfs, s.Devfs[0]) },
		"proxy listen": func(s *api.JailSpec) { s.Proxy[0].Listen = "8080" },
		"proxy host":   func(s *api.JailSpec) { s.Proxy[0].Listen = "web.example:80" },
		"proxy port":   func(s *api.JailSpec) { s.Proxy[0].JailPort = 0 },
		"proxy proto":  func(s *api.JailSpec) { s.Proxy[0].Proto = "sctp" },
		"profile name": func(s *api.JailSpec) { s.Profiles = []string{"Bad"} },
	} {
		s := ok
		s.Network = append([]api.NetworkAttach(nil), ok.Network...)
		s.Devfs = append([]api.DevfsDevice(nil), ok.Devfs...)
		s.Proxy = append([]api.ProxyDevice(nil), ok.Proxy...)
		mut(&s)
		if err := JailSpec("web", s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A comment on a rule, a policy or a set is one line of at most CommentMax characters.
func TestFirewallComments(t *testing.T) {
	rule := api.FirewallRule{Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"22"}}
	ok := api.FirewallPolicySpec{Comment: "ssh", DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{{Action: rule.Action, Direction: rule.Direction, Proto: rule.Proto, Ports: rule.Ports, Comment: "from the office"}}}
	if _, err := FirewallPolicySpec(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(p *api.FirewallPolicySpec){
		"policy two lines": func(p *api.FirewallPolicySpec) { p.Comment = "a\nb" },
		"policy too long":  func(p *api.FirewallPolicySpec) { p.Comment = strings.Repeat("x", CommentMax+1) },
		"rule two lines":   func(p *api.FirewallPolicySpec) { p.Rules[0].Comment = "a\rb" },
		"rule too long":    func(p *api.FirewallPolicySpec) { p.Rules[0].Comment = strings.Repeat("é", CommentMax+1) },
		// the comment is a comment line of the ruleset: a backslash would continue it onto the next line (the next rule is gone)
		"policy backslash":    func(p *api.FirewallPolicySpec) { p.Comment = `ends with a backslash\` },
		"rule quote":          func(p *api.FirewallPolicySpec) { p.Rules[0].Comment = `read file "x"` },
		"rule bidi override":  func(p *api.FirewallPolicySpec) { p.Rules[0].Comment = "ssh \u202eadmin" },
		"rule zero width":     func(p *api.FirewallPolicySpec) { p.Rules[0].Comment = "ss\u200bh" },
		"rule line separator": func(p *api.FirewallPolicySpec) { p.Rules[0].Comment = "a\u2028b" },
		"rule not UTF-8":      func(p *api.FirewallPolicySpec) { p.Rules[0].Comment = "a\xffb" },
	} {
		p := ok
		p.Rules = append([]api.FirewallRule(nil), ok.Rules...)
		mod(&p)
		if _, err := FirewallPolicySpec(p); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := AddressSetSpec(api.AddressSetSpec{Comment: "x\ny", Addresses: api.Entries("10.0.0.1")}); err == nil {
		t.Error("a set comment of two lines was accepted")
	}
	if err := AddressSetSpec(api.AddressSetSpec{Comment: strings.Repeat("x", CommentMax), Addresses: []api.AddressEntry{{Address: "10.0.0.1", Comment: strings.Repeat("y", CommentMax)}}}); err != nil {
		t.Errorf("comments of exactly %d characters: %v", CommentMax, err)
	}
}

// A rule belongs to the jail that has the policy: an inbound rule is to the jail itself and an outbound rule from it, so
// the other end is the only one a rule names.
func TestRuleNamesOnlyTheOtherEnd(t *testing.T) {
	spec := func(r api.FirewallRule) api.FirewallPolicySpec {
		return api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{r}}
	}
	for name, tc := range map[string]struct {
		rule api.FirewallRule
		bad  string
	}{
		"inbound from":  {api.FirewallRule{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"192.0.2.7"}, Ports: []string{"5432"}}, ""},
		"outbound to":   {api.FirewallRule{Action: "allow", Direction: "out", Proto: "tcp", To: []string{"192.0.2.7"}, Ports: []string{"5432"}}, ""},
		"inbound to":    {api.FirewallRule{Action: "allow", Direction: "in", Proto: "tcp", To: []string{"any"}, Ports: []string{"22"}}, "inbound rule is always to the jail itself"},
		"outbound from": {api.FirewallRule{Action: "allow", Direction: "out", Proto: "tcp", From: []string{"192.0.2.7"}}, "outbound rule is always from the jail itself"},
	} {
		_, err := FirewallPolicySpec(spec(tc.rule))
		switch {
		case tc.bad == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.bad != "" && (err == nil || !strings.Contains(err.Error(), tc.bad)):
			t.Errorf("%s: want an error saying %q, got %v", name, tc.bad, err)
		}
	}
}

func TestParseRate(t *testing.T) {
	for in, want := range map[string]uint64{"64000": 64000, "500K": 500000, "10M": 10000000, "1G": 1000000000, "10m": 10000000} {
		got, err := ParseRate(in)
		if err != nil || got != want {
			t.Errorf("%q: %d %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "0M", "M", "10 M", "10MB", "10Mbit/s", "-5M", "1.5M", "fast", "1234567890", "10T"} {
		if _, err := ParseRate(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
