package priv

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/sdk/api"
)

// The interfaces of a host as the kernel shows them, for the ownership matrix: what JailOps made, and everything that
// is someone else's.
func ownershipHost(t *testing.T, e *env) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := e.net.EpairCreate(ctx, "joweb"); err != nil { // an epair of a jail
		t.Fatal(err)
	}
	for _, i := range []ifconfig.Iface{
		{Name: "jo7", Groups: []string{"epair"}},                                    // an epair with no description
		{Name: "jo8", Groups: []string{"epair"}, Description: "customer link"},      // a jo name with someone's description
		{Name: "jo9", Groups: []string{"vmx"}},                                      // a physical interface renamed to a jo name
		{Name: "vmx0", Groups: []string{"vmx"}, Description: "uplink"},              // the uplink
		{Name: "vmx1", Groups: []string{"vmx"}, Description: ifconfig.Marker},       // an uplink an administrator marked by hand
		{Name: "bridge0", Groups: []string{"bridge"}},                               // a bridge of the kernel's name
		{Name: "mybr", Groups: []string{"bridge"}, Description: ifconfig.Marker},    // a bridge is never owned, whatever it says
		{Name: "tap0", Groups: []string{"tap"}, Description: "jailops wireguard=x"}, // another kind, whatever the description
		{Name: "jotakena", Groups: []string{"epair"}},                               // a name JailOps would give an epair, taken
	} {
		e.net.AddIface(i)
	}
}

// Every refusal of the helper's ownership rule, through the guard and over the socket: the matrix of the threat model
// in docs/security-model.md ("Interfaces").
func TestInterfaceOwnershipMatrix(t *testing.T) {
	f := newFixtureWith(t, func(e *env) { ownershipHost(t, e); e.conf(t, "shop_web") })
	ctx := context.Background()
	for _, via := range []struct {
		name string
		n    ifconfig.Client
	}{{"guard", f.env.local.Net()}, {"socket", f.client.Net()}} {
		n := via.n
		foreign := []string{"mybr", "em0", "vmx0", "vmx1", "jo7", "jo8", "jo9", "bridge0", "tap0", "lo0"}
		for _, name := range foreign {
			for k, err := range []error{
				n.SetDescription(ctx, name, ifconfig.Marker), // the marker is never written on what exists
				n.SetDescription(ctx, name, ""),
				n.EpairDestroy(ctx, name),
				n.SetLink(ctx, name, false),
				n.AddrAdd(ctx, name, netip.MustParsePrefix("10.9.0.1/24")),
				n.AddrRemove(ctx, name, netip.MustParsePrefix("10.9.0.1/24")),
				n.RouteAdd(ctx, ifconfig.Route{Dest: "2001:db8:1:2:100::7/128", Interface: name}),
				n.MoveToJail(ctx, name, "shop_web"),
				f.client.SetMTU(ctx, name, 1400),
			} {
				if err == nil || !(api.IsCode(err, api.CodeForbidden) || api.IsCode(err, api.CodeInvalid)) {
					t.Errorf("%s %s case %d: %v", via.name, name, k, err)
				}
			}
		}
		// a name that is taken is never adopted
		if _, _, err := n.EpairCreate(ctx, "jotaken"); !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), "never takes over an interface by its name") {
			t.Errorf("%s: create over a name that is taken: %v", via.name, err)
		}
		// names of drivers
		for _, name := range []string{"epair5", "epair0"} {
			if _, _, err := n.EpairCreate(ctx, name); !api.IsCode(err, api.CodeInvalid) {
				t.Errorf("%s: epair under the kernel's names (%s): %v", via.name, name, err)
			}
		}
		// a description that would take the marker off is refused; clearing keeps it
		if err := n.SetDescription(ctx, "joweba", "my text"); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: marker removable: %v", via.name, err)
		}
		if err := n.SetDescription(ctx, "joweba", ""); err != nil {
			t.Fatal(err)
		}
		if d := desc(t, f.env, "joweba"); d != ifconfig.Marker {
			t.Errorf("%s: cleared to %q", via.name, d)
		}
		// creating what JailOps already owns is idempotent for the caller
		if _, _, err := n.EpairCreate(ctx, "joweb"); !api.IsCode(err, api.CodeAlreadyExists) {
			t.Errorf("%s: create of an owned epair: %v", via.name, err)
		}
	}
	// reading stays open: the uplink and the rest are listed
	ifs, err := f.client.Net().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, i := range ifs {
		seen[i.Name] = true
	}
	for _, n := range []string{"vmx0", "em0", "mybr", "lo0", "joweba"} {
		if !seen[n] {
			t.Errorf("%s not listed", n)
		}
	}
	// nothing foreign changed
	for name, want := range map[string]string{"vmx0": "uplink", "jo8": "customer link", "mybr": ifconfig.Marker, "bridge0": "", "jo9": ""} {
		if d := desc(t, f.env, name); d != want {
			t.Errorf("%s: description %q, want %q", name, d, want)
		}
	}
}

func desc(t *testing.T, e *env, name string) string {
	t.Helper()
	i, err := e.net.Show(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return i.Description
}

// Everything a jail's epair needs works through the helper: its description, its addresses, its link and its routes,
// and its jail end keeps the marker in the jail's vnet.
func TestInterfaceOwnershipOfAJailsEpair(t *testing.T) {
	f := newFixtureWith(t, func(e *env) {
		e.conf(t, "shop_web")
		e.storeLan(t, "10.66.0.0/24")
		e.runner.On("ifconfig", []string{"jo0123456789a0a", "mtu", "1400"}, "")
	})
	ctx := context.Background()
	n := f.client.Net()
	a, b, err := n.EpairCreate(ctx, "jo0123456789a0")
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{
		n.SetDescription(ctx, a, "jailops jail=shop/web net=lan (host side)"),
		n.AddrAdd(ctx, a, netip.MustParsePrefix("10.66.0.1/32")),
		n.SetLink(ctx, a, true),
		n.RouteAdd(ctx, ifconfig.Route{Dest: "2001:db8:1:2:100::7/128", Interface: a}),
		f.client.SetMTU(ctx, a, 1400),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	// the jail end keeps its marker in the jail's vnet, and comes back
	if err := n.MoveToJail(ctx, b, "shop_web"); err != nil {
		t.Fatal(err)
	}
	if i, err := f.env.net.ShowInJail(ctx, "shop_web", b); err != nil || i.Description != ifconfig.Marker {
		t.Fatalf("%+v %v", i, err)
	}
	if err := n.MoveFromJail(ctx, b, "shop_web"); err != nil {
		t.Fatal(err)
	}
	if err := n.EpairDestroy(ctx, a); err != nil {
		t.Fatal(err)
	}
}

// A reject route is accepted for the subnet of a network JailOps has stored, and for no other prefix.
func TestRejectRoutesAreForTheSubnetsOfNetworksOnly(t *testing.T) {
	f := newFixtureWith(t, func(e *env) {
		e.conf(t, "shop_web")
		nw, _ := json.Marshal(map[string]any{"kind": "Network", "metadata": api.ObjectMeta{Name: "lan", UUID: "aaaa-1111-2222"},
			"spec": api.NetworkSpec{Uplink: "em0", IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.200"},
				IPv6: &api.IPv6Net{Mode: api.IPv6Routed, Subnet: "2001:db8:1::/64", Range: "2001:db8:1::10-2001:db8:1::ff"}}})
		mustWrite(t, filepath.Join(e.cfg.StateDir, "objects", "Network", "aaaa-1111-2222.json"), string(nw))
	})
	ctx := context.Background()
	for _, via := range []struct {
		name string
		n    ifconfig.Client
	}{{"guard", f.env.local.Net()}, {"socket", f.client.Net()}} {
		for _, d := range []string{"10.20.0.0/24", "2001:db8:1::/64"} {
			if err := via.n.RouteAdd(ctx, ifconfig.Route{Dest: d, Reject: true}); err != nil {
				t.Errorf("%s: reject %s: %v", via.name, d, err)
			}
			if err := via.n.RouteDelete(ctx, ifconfig.Route{Dest: d, Reject: true}); err != nil {
				t.Errorf("%s: delete reject %s: %v", via.name, d, err)
			}
		}
		for _, d := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.20.0.0/25", "192.0.2.0/24", "::/0", "2001:db8::/32"} {
			if err := via.n.RouteAdd(ctx, ifconfig.Route{Dest: d, Reject: true}); !api.IsCode(err, api.CodeForbidden) {
				t.Errorf("%s: reject %s: %v", via.name, d, err)
			}
		}
		if err := via.n.RouteAdd(ctx, ifconfig.Route{Dest: "10.20.0.0/24", Reject: true, Gateway: "10.0.0.1"}); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: a reject route with a gateway: %v", via.name, err)
		}
	}
}

// An interface is JailOps's by its description, never by its name: a name that looks like JailOps's, without a
// description, with someone else's, or on another kind of interface, is not changed.
func TestInterfaceOwnershipIsTheDescriptionNotTheName(t *testing.T) {
	f := newFixtureWith(t, func(e *env) { ownershipHost(t, e) })
	ctx := context.Background()
	n := f.client.Net()
	if err := n.SetLink(ctx, "jo7", true); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a jo name without a description: %v", err)
	}
	if d := desc(t, f.env, "jo7"); d != "" {
		t.Errorf("jo7 was given a description: %q", d)
	}
	if err := n.SetLink(ctx, "jo8", true); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a jo name with a foreign description: %v", err)
	}
	if err := n.SetLink(ctx, "jo9", true); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a jo name on a physical interface: %v", err)
	}
}

// jail(8) moves vnet.interface into the jail itself: one that exists and is not JailOps's stops the jail's creation.
func TestJailCreateRefusesAForeignVnetInterface(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	conf := filepath.Join(e.cfg.ConfDir, "alpha_web.conf")
	e.conf(t, "alpha_web")
	e.net.AddIface(ifconfig.Iface{Name: "jo0123456789a0b", Groups: []string{"epair"}, Description: "someone's"})
	if err := e.local.Jails().Create(ctx, conf, "alpha_web"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("foreign vnet.interface: %v", err)
	}
	// a JailOps epair, or none yet (the prestart hook makes it), is fine
	for _, made := range []bool{false, true} {
		e := newEnv(t)
		e.conf(t, "alpha_web")
		if made {
			if _, _, err := e.net.EpairCreate(ctx, "jo0123456789a0"); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.local.Jails().Create(ctx, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
			t.Errorf("made %v: %v", made, err)
		}
	}
}

// twinNet shows a host interface of every name, as the host does when a name is taken (test helper).
type twinNet struct{ *ifconfig.Fake }

func (t twinNet) Show(_ context.Context, name string) (ifconfig.Iface, error) {
	return ifconfig.Iface{Name: name, Groups: []string{"vmx"}}, nil
}

// The kernel brings an interface back from a jail's vnet although the host has one of that name; the helper does not.
func TestMoveFromJailNeverDoublesAHostName(t *testing.T) {
	e := newEnv(t)
	e.conf(t, "shop_web")
	e.net.AddToJail("shop_web", ifconfig.Iface{Name: "vtnet0", Groups: []string{"epair"}, Description: ifconfig.Marker}) // forged in the jail
	l, err := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: twinNet{e.net}, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Net().MoveFromJail(context.Background(), "vtnet0", "shop_web"); !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), "exists on the host") {
		t.Fatalf("%v", err)
	}
}
