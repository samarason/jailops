package ifconfig

import (
	"context"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

var ctx = context.Background()

func TestParseIfconfigGolden(t *testing.T) {
	b, err := os.ReadFile("testdata/ifconfig_a.txt")
	if err != nil {
		t.Fatal(err)
	}
	ifs := ParseIfconfig(string(b))
	byName := map[string]Iface{}
	for _, i := range ifs {
		byName[i.Name] = i
	}
	for _, n := range []string{"em0", "lo0", "mybr", "joweba"} {
		if _, ok := byName[n]; !ok {
			t.Fatalf("missing %s in %v", n, ifs)
		}
	}
	if len(ifs) != 4 {
		t.Errorf("want 4 interfaces, got %d (the bad header must be dropped)", len(ifs))
	}
	em := byName["em0"]
	if em.MTU != 1500 || !em.Up() || em.MAC != "52:54:00:12:34:56" || em.Status != "active" {
		t.Errorf("em0: %+v", em)
	}
	if !reflect.DeepEqual(em.Inet, []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}) {
		t.Errorf("inet %v", em.Inet)
	}
	if !reflect.DeepEqual(em.Inet6, []netip.Prefix{netip.MustParsePrefix("fe80::5054:ff:fe12:3456/64"), netip.MustParsePrefix("2001:db8:1::10/64")}) {
		t.Errorf("inet6 %v", em.Inet6)
	}
	if lo := byName["lo0"]; lo.MTU != 16384 || lo.Inet[0] != netip.MustParsePrefix("127.0.0.1/8") || lo.Inet6[0].Bits() != 128 {
		t.Errorf("lo0: %+v", lo)
	}
	jo := byName["mybr"]
	if jo.Description != "an administrator's bridge" || !reflect.DeepEqual(jo.Groups, []string{"bridge"}) {
		t.Errorf("mybr: %+v", jo)
	}
	if len(jo.Members) != 2 || jo.Members[0].Name != "joweba" || !jo.Members[0].Private || jo.Members[1].Private {
		t.Errorf("members: %+v", jo.Members)
	}
}

func FuzzParseIfconfig(f *testing.F) {
	b, _ := os.ReadFile("testdata/ifconfig_a.txt")
	f.Add(string(b))
	f.Add("x: flags=<\n\tinet 1.2.3.4 netmask\n\tmember:\n")
	f.Fuzz(func(t *testing.T, s string) {
		for _, i := range ParseIfconfig(s) {
			if ValidateIfName(i.Name) != nil {
				t.Fatalf("bad name %q", i.Name)
			}
		}
	})
}

func TestMaskBits(t *testing.T) {
	for in, want := range map[string]int{"0xffffff00": 24, "0xffffffff": 32, "0x0": 0, "255.255.0.0": 16, "0xff00ff00": -1, "zz": -1, "0x1ffffffff": -1} {
		got, ok := maskBits(in)
		if want < 0 && ok || want >= 0 && (!ok || got != want) {
			t.Errorf("%s: %d %v", in, got, ok)
		}
	}
}

func TestValidateNames(t *testing.T) {
	for in, ok := range map[string]bool{"jo0": true, "em0": true, "epair0a": true, "vlan.10": true, "": false, "0jb": false,
		"-jo": false, "jo 0": false, "jo;0": false, strings.Repeat("a", 16): false, strings.Repeat("a", 15): true} {
		if err := ValidateIfName(in); (err == nil) != ok {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func newCmd() (*Command, *run.Fake) {
	f := run.NewFake()
	return NewCommand(f, Options{}), f
}

// show is what `ifconfig <name>` prints for an interface of kind ("bridge", "epair", "vmx", "lo") with desc.
func show(name, kind, desc string) string {
	out := name + ": flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n"
	if desc != "" {
		out += "\tdescription: " + desc + "\n"
	}
	return out + "\tether 58:9c:fc:10:ff:01\n\tgroups: " + kind + "\n"
}

// mine answers `ifconfig <name>` with an interface of JailOps (the marker) for every name.
func mine(f *run.Fake, kind string, names ...string) {
	for _, n := range names {
		f.On("ifconfig", []string{n}, show(n, kind, Marker))
	}
}

// writes returns the calls that are not reads of one interface (ifconfig NAME, ifconfig -j JAIL NAME).
func writes(argv []string) []string {
	var out []string
	for _, a := range argv {
		f := strings.Fields(a)
		if len(f) == 4 && f[1] == "-j" {
			continue
		}
		if len(f) > 2 || a == "ifconfig -a" {
			out = append(out, a)
		}
	}
	return out
}

func TestCommandAddressesAndLinks(t *testing.T) {
	c, f := newCmd()
	mine(f, "epair", "joweba")
	f.Add(run.Rule{Name: "ifconfig", Args: []string{run.RestArgs}})
	if err := c.SetDescription(ctx, "joweba", "jailops jail=p/web net=lan (host side)"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDescription(ctx, "joweba", ""); err != nil { // clearing keeps the marker
		t.Fatal(err)
	}
	if err := c.AddrAdd(ctx, "joweba", netip.MustParsePrefix("10.77.0.1/32")); err != nil {
		t.Fatal(err)
	}
	if err := c.AddrAdd(ctx, "joweba", netip.MustParsePrefix("fe80::1/64")); err != nil {
		t.Fatal(err)
	}
	if err := c.AddrRemove(ctx, "joweba", netip.MustParsePrefix("fd00::1/64")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetLink(ctx, "joweba", true); err != nil {
		t.Fatal(err)
	}
	if err := c.SetLink(ctx, "joweba", false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ifconfig joweba", "ifconfig joweba description jailops jail=p/web net=lan (host side)",
		"ifconfig joweba", "ifconfig joweba description " + Marker,
		"ifconfig joweba", "ifconfig joweba inet 10.77.0.1/32 alias",
		"ifconfig joweba", "ifconfig joweba inet6 fe80::1 prefixlen 64 alias",
		"ifconfig joweba", "ifconfig joweba inet6 fd00::1 prefixlen 64 -alias",
		"ifconfig joweba", "ifconfig joweba up",
		"ifconfig joweba", "ifconfig joweba down",
	}
	if !reflect.DeepEqual(f.Argv(), want) {
		t.Errorf("got  %q\nwant %q", f.Argv(), want)
	}
}

func TestCommandEpair(t *testing.T) {
	c, f := newCmd()
	f.On("ifconfig", []string{"epair", "create"}, "epair3a\n")
	mine(f, "epair", "joweba")
	f.On("ifconfig", []string{"-j", "web", "joweba"}, show("joweba", "epair", "jailops jail=p/web net=lan (jail side)"))
	f.Add(run.Rule{Name: "ifconfig", Args: []string{run.RestArgs}})
	a, b, err := c.EpairCreate(ctx, "joweb")
	if err != nil || a != "joweba" || b != "jowebb" {
		t.Fatal(a, b, err)
	}
	if err := c.MoveToJail(ctx, a, "web"); err != nil {
		t.Fatal(err)
	}
	if err := c.MoveFromJail(ctx, a, "web"); err != nil {
		t.Fatal(err)
	}
	if err := c.EpairDestroy(ctx, a); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ifconfig epair create", "ifconfig epair3a description " + Marker, "ifconfig epair3b description " + Marker,
		"ifconfig epair3b name jowebb", "ifconfig epair3a name joweba",
		"ifconfig joweba", "ifconfig joweba vnet web",
		"ifconfig -j web joweba", "ifconfig joweba -vnet web",
		"ifconfig joweba", "ifconfig joweba destroy",
	}
	if !reflect.DeepEqual(f.Argv(), want) {
		t.Errorf("%q", f.Argv())
	}
}

func TestEpairRenameFailureCleansUp(t *testing.T) {
	c, f := newCmd()
	f.On("ifconfig", []string{"epair", "create"}, "epair3a\n")
	f.Add(run.Rule{Name: "ifconfig", Args: []string{"epair3a", "description", Marker}})
	f.Add(run.Rule{Name: "ifconfig", Args: []string{"epair3b", "description", Marker}})
	f.OnFail("ifconfig", []string{"epair3b", "name", "jowebb"}, 1, "ifconfig: SIOCSIFNAME: File exists")
	f.Add(run.Rule{Name: "ifconfig", Args: []string{"epair3a", "destroy"}})
	if _, _, err := c.EpairCreate(ctx, "joweb"); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatal(err)
	}
	if last := f.Argv()[len(f.Argv())-1]; last != "ifconfig epair3a destroy" {
		t.Errorf("no cleanup: %q", f.Argv())
	}
}

// Ownership is the kernel's description and kind, never the name: every refusal, and what is accepted.
func TestOwnership(t *testing.T) {
	type cas struct {
		name, kind, desc string
		owned            bool
		msg              string
	}
	for _, k := range []cas{
		{"joweba", "epair", Marker, true, ""},
		{"joweba", "epair", "jailops jail=p/web net=lan (host side)", true, ""},
		{"epair0a", "epair", "", false, "has no JailOps description"},               // an epair made by hand
		{"jo7", "epair", "", false, "has no JailOps description"},                   // a name that looks like JailOps's is not a reason
		{"jo1234567890aab", "epair", "", false, "has no JailOps description"},       // the same for an epair end
		{"joweba", "epair", "jailops:0b0e7f3e", false, "is not one JailOps writes"}, // a description of another form
		{"jo7", "epair", "customer vnet link", false, "is not one JailOps writes"},  // someone's description
		{"epair1a", "epair", "jailopsx", false, "is not one JailOps writes"},
		{"epair1a", "epair", "Jailops managed", false, "is not one JailOps writes"},
		{"mybr", "bridge", Marker, false, "only epairs"}, // a bridge is never owned, whatever it says
		{"vmx0", "vmx", "", false, "only epairs"},
		{"vmx0", "vmx", Marker, false, "only epairs"}, // a forged description on the uplink
		{"jo7", "vmx", "", false, "only epairs"},      // a renamed uplink with a JailOps-like name
		{"lo0", "lo", Marker, false, "only epairs"},
		{"wg0", "wg", "jailops wireguard=office", false, "only epairs"},
		{"tap0", "tap", Marker, false, "only epairs"},
	} {
		i := ParseIfconfig(show(k.name, k.kind, k.desc))[0]
		err := Options{}.Owns(i)
		if (err == nil) != k.owned || (err == nil) != (k.msg == "") || err != nil && (!strings.Contains(err.Error(), k.msg) || !api.IsCode(err, api.CodeForbidden)) {
			t.Errorf("%s/%s/%q: %v", k.name, k.kind, k.desc, err)
		}
	}
}

// Every mutating call reads the interface from the kernel first and touches nothing that is not JailOps's.
func TestCommandRefusesForeign(t *testing.T) {
	c, f := newCmd()
	f.On("ifconfig", []string{"vmx0"}, show("vmx0", "vmx", ""))
	f.On("ifconfig", []string{"lo0"}, show("lo0", "lo", ""))
	f.On("ifconfig", []string{"mybr"}, show("mybr", "bridge", Marker))  // a bridge is never JailOps's
	f.On("ifconfig", []string{"epair0a"}, show("epair0a", "epair", "")) // made by hand
	f.On("ifconfig", []string{"forged"}, show("forged", "epair", "my jailops link"))
	f.On("ifconfig", []string{"-j", "web", "lo0"}, show("lo0", "lo", ""))
	f.OnFail("ifconfig", []string{"ghost"}, 1, "ifconfig: interface ghost does not exist")
	for _, name := range []string{"vmx0", "lo0", "mybr", "epair0a", "forged"} {
		for i, err := range []error{
			c.SetDescription(ctx, name, Marker), // the daemon cannot have the marker written on a foreign interface
			c.SetLink(ctx, name, false),
			c.AddrAdd(ctx, name, netip.MustParsePrefix("10.0.0.1/24")),
			c.AddrRemove(ctx, name, netip.MustParsePrefix("10.0.0.1/24")),
			c.EpairDestroy(ctx, name),
			c.MoveToJail(ctx, name, "web"),
			c.RouteAdd(ctx, Route{Dest: "2001:db8::5/128", Interface: name}),
		} {
			if !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), "not managed by JailOps") {
				t.Errorf("%s case %d: %v", name, i, err)
			}
		}
	}
	if !api.IsCode(c.MoveFromJail(ctx, "lo0", "web"), api.CodeForbidden) {
		t.Error("the loopback of a jail was moved")
	}
	if !api.IsCode(c.SetLink(ctx, "ghost", true), api.CodeNotFound) {
		t.Error("a missing interface is not_found")
	}
	if w := writes(f.Argv()); len(w) != 0 {
		t.Errorf("foreign interface touched: %q", w)
	}
	// a create under a driver's name runs nothing at all
	f.Reset()
	for _, n := range []string{"epair0"} {
		if _, _, err := c.EpairCreate(ctx, n); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", n, err)
		}
	}
	if err := c.SetDescription(ctx, "joweba", "my text"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("the marker was removable: %v", err)
	}
	if len(f.Calls()) != 0 {
		t.Errorf("ran %q", f.Argv())
	}
}

func TestInvalidArguments(t *testing.T) {
	c, f := newCmd()
	for i, err := range []error{
		c.SetLink(ctx, "jo0;reboot", true),
		c.MoveToJail(ctx, "joweba", "-j"),
		c.MoveToJail(ctx, "joweba", "a b"),
		c.SetDescription(ctx, "jo0", "line\nbreak"),
		c.AddrAdd(ctx, "jo0", netip.Prefix{}),
		c.RouteAdd(ctx, Route{Dest: "10.0.0.0/8; reboot", Gateway: "10.0.0.1"}),
		c.RouteAdd(ctx, Route{Dest: "10.0.0.0/8", Gateway: "fe80::1"}),
		c.RouteAdd(ctx, Route{Dest: "10.0.0.0/8"}),
		c.RouteAdd(ctx, Route{Dest: "default", Interface: "jo0"}),
	} {
		if !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if len(f.Calls()) != 0 {
		t.Errorf("ran %q", f.Argv())
	}
}

func TestRoutes(t *testing.T) {
	c, f := newCmd()
	mine(f, "epair", "jo0")
	f.Add(run.Rule{Name: "route", Args: []string{run.RestArgs}})
	for _, err := range []error{
		c.RouteAdd(ctx, Route{Dest: "10.1.2.3/24", Gateway: "10.0.0.1"}),
		c.RouteAdd(ctx, Route{Dest: "default", Gateway: "fe80::1"}),
		c.RouteAdd(ctx, Route{Dest: "2001:db8::5", Interface: "jo0"}),
		c.RouteDelete(ctx, Route{Dest: "2001:db8:1::/64", Gateway: "fd00::1"}),
		c.RouteAdd(ctx, Route{Dest: "10.77.0.0/24", Reject: true}),
		c.RouteDelete(ctx, Route{Dest: "10.77.0.0/24", Reject: true}),
		c.RouteAdd(ctx, Route{Dest: "2001:db8:5::/64", Reject: true}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"route -n add -inet 10.1.2.0/24 10.0.0.1",
		"route -n add -inet6 default fe80::1",
		"ifconfig jo0",
		"route -n add -inet6 2001:db8::5 -interface jo0",
		"route -n delete -inet6 2001:db8:1::/64 fd00::1",
		"route -n add -inet 10.77.0.0/24 127.0.0.1 -reject",
		"route -n delete -inet 10.77.0.0/24",
		"route -n add -inet6 2001:db8:5::/64 ::1 -reject",
	}
	if !reflect.DeepEqual(f.Argv(), want) {
		t.Errorf("%q", f.Argv())
	}
}

func TestForwardingAndList(t *testing.T) {
	c, f := newCmd()
	f.On("sysctl", []string{"-n", "net.inet6.ip6.forwarding"}, "1\n")
	if on, err := c.IPv6Forwarding(ctx); err != nil || !on {
		t.Fatal(on, err)
	}
	f.Reset()
	f2 := run.NewFake()
	f2.On("sysctl", []string{run.RestArgs}, "banana\n")
	if _, err := NewCommand(f2, Options{}).IPv6Forwarding(ctx); err == nil {
		t.Fatal("garbage accepted")
	}
	b, _ := os.ReadFile("testdata/ifconfig_a.txt")
	f.On("ifconfig", []string{"-a"}, string(b))
	ifs, err := c.List(ctx)
	if err != nil || len(ifs) != 4 {
		t.Fatal(len(ifs), err)
	}
}

func TestFake(t *testing.T) {
	f := NewFake(Options{})
	f.AddForeign("em0", true)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	a, b, err := f.EpairCreate(ctx, "joweb")
	must(err)
	if _, _, err := f.EpairCreate(ctx, "joweb"); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("dup epair: %v", err)
	}
	must(f.AddrAdd(ctx, a, netip.MustParsePrefix("10.0.0.1/32")))
	must(f.SetLink(ctx, a, true))
	must(f.MoveToJail(ctx, b, "web"))
	ifs, _ := f.List(ctx)
	names := []string{}
	for _, i := range ifs {
		names = append(names, i.Name)
	}
	if !reflect.DeepEqual(names, []string{"em0", "joweba", "lo0"}) {
		t.Fatalf("%v", names)
	}
	if !ifs[1].Up() || len(ifs[1].Inet) != 1 {
		t.Fatalf("%+v", ifs[1])
	}
	if !api.IsCode(f.SetLink(ctx, "em0", false), api.CodeForbidden) {
		t.Fatal("foreign")
	}
	must(f.RouteAdd(ctx, Route{Dest: "default", Gateway: "10.0.0.254"}))
	if !api.IsCode(f.RouteAdd(ctx, Route{Dest: "default", Gateway: "10.0.0.254"}), api.CodeAlreadyExists) {
		t.Fatal("dup route")
	}
	must(f.RouteDelete(ctx, Route{Dest: "default", Gateway: "10.0.0.254"}))
	must(f.RouteAdd(ctx, Route{Dest: "10.0.0.0/24", Reject: true}))
	must(f.RouteDelete(ctx, Route{Dest: "10.0.0.0/24", Reject: true}))
	must(f.EpairDestroy(ctx, a))
	ifs, _ = f.List(ctx)
	if len(ifs) != 2 {
		t.Fatalf("%+v", ifs)
	}
	f.Forwarding = true
	if on, _ := f.IPv6Forwarding(ctx); !on {
		t.Fatal("forwarding")
	}
}

// A proxied jail address is reused by the next jail with another hardware address; the kernel's cached entry of the
// old one must go when the host route does, and before the route of the next jail is made.
func TestHostRoutesForgetTheNeighborEntry(t *testing.T) {
	c, f := newCmd()
	mine(f, "epair", "jo0")
	f.Add(run.Rule{Name: "route", Args: []string{run.RestArgs}})
	f.Add(run.Rule{Name: "ndp", Args: []string{run.RestArgs}})
	r := Route{Dest: "2001:db8:1:2:100::10/128", Interface: "jo0"}
	if err := c.RouteDelete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := c.RouteAdd(ctx, r); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ifconfig jo0",
		"route -n delete -inet6 2001:db8:1:2:100::10/128 -interface jo0",
		"ndp -d 2001:db8:1:2:100::10",
		"ifconfig jo0",
		"ndp -d 2001:db8:1:2:100::10",
		"route -n add -inet6 2001:db8:1:2:100::10/128 -interface jo0",
	}
	got := f.Argv()
	if len(got) != len(want) {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
	// IPv4 and prefixes are not neighbors of this kind
	c2, f2 := newCmd()
	f2.Add(run.Rule{Name: "route", Args: []string{run.RestArgs}})
	if err := c2.RouteAdd(ctx, Route{Dest: "10.9.0.0/24", Gateway: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	for _, a := range f2.Argv() {
		if len(a) >= 3 && a[:3] == "ndp" {
			t.Errorf("ndp ran for an IPv4 route: %q", a)
		}
	}
}

// The line is copied from FreeBSD 15.1 (ifconfig vlan77 create vlan 77 vlandev epair5a).
func TestParseVlan(t *testing.T) {
	out := "vlan77: flags=1008842<BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n" +
		"\toptions=0\n\tether 58:9c:fc:10:1f:35\n\tgroups: vlan\n" +
		"\tvlan: 77 vlanproto: 802.1q vlanpcp: 0 parent interface: epair5a\n\tstatus: active\n"
	ifs := ParseIfconfig(out)
	if len(ifs) != 1 || ifs[0].VlanTag != 77 || ifs[0].VlanParent != "epair5a" || ifs[0].Status != "active" {
		t.Fatalf("%+v", ifs)
	}
}

// The fake stores descriptions and reads them back as the kernel does, with the same ownership rule as Command.
func TestFakeOwnership(t *testing.T) {
	f := NewFake(Options{})
	f.AddForeign("vmx0", true)
	f.AddIface(Iface{Name: "mybr", Groups: []string{"bridge"}, Description: Marker})
	f.AddIface(Iface{Name: "epair7a", Groups: []string{"epair"}})
	a, _, err := f.EpairCreate(ctx, "joweb")
	if err != nil {
		t.Fatal(err)
	}
	if i, _ := f.Show(ctx, a); i.Description != Marker {
		t.Fatalf("created without the marker: %+v", i)
	}
	if err := f.SetDescription(ctx, a, "jailops jail=p/web net=lan (host side)"); err != nil {
		t.Fatal(err)
	}
	if i, _ := f.Show(ctx, a); i.Description != "jailops jail=p/web net=lan (host side)" {
		t.Fatalf("%+v", i)
	}
	for _, err := range []error{f.SetLink(ctx, "vmx0", false), f.SetLink(ctx, "mybr", true), f.SetDescription(ctx, "mybr", Marker),
		f.SetLink(ctx, "epair7a", true)} {
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("foreign: %v", err)
		}
	}
	// a marker travels into the jail's vnet and back
	_, b, err := f.EpairCreate(ctx, "jox")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MoveToJail(ctx, b, "web"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Show(ctx, b); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("a jail's interface is visible on the host: %v", err)
	}
	if i, err := f.ShowInJail(ctx, "web", b); err != nil || i.Description != Marker {
		t.Errorf("%+v %v", i, err)
	}
	f.AddToJail("web", Iface{Name: "mine", Groups: []string{"epair"}, Description: "the jail's"})
	if err := f.MoveFromJail(ctx, "mine", "web"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("an interface the jail made: %v", err)
	}
	if err := f.MoveFromJail(ctx, b, "web"); err != nil {
		t.Fatal(err)
	}
}

// Removing an address that is not on the interface is "not found", whatever the kernel calls it: `ifconfig X inet A
// -alias` answers "Can't assign requested address" (EADDRNOTAVAIL), which is what a jail started by an earlier version
// gives a stop that removes the gateway alias of the routed link.
func TestAddrRemoveOfAnAddressThatIsNotThereIsNotFound(t *testing.T) {
	c, f := newCmd()
	mine(f, "epair", "joweba")
	f.OnFail("ifconfig", []string{"joweba", "inet", "10.77.0.1/32", "-alias"}, 1, "ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address\n")
	err := c.AddrRemove(ctx, "joweba", netip.MustParsePrefix("10.77.0.1/32"))
	if !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("got %v, want not found", err)
	}
}
