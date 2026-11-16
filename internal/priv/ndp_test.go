package priv

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/ndproxy"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/sdk/api"
)

func ndpReq() NDPAnswerReq {
	return NDPAnswerReq{Uplink: "em0", Target: "2001:db8:1:2:100::10", RequesterIP: "fe80::1", RequesterMAC: "00:00:5e:00:02:96"}
}

func TestNDPAnswerSendsExactlyTheAdvertisementItIsAskedFor(t *testing.T) {
	e := newEnv(t)
	dev := e.local.d.NDP.(*fakeNDP)
	if err := e.local.NDPAnswer(context.Background(), ndpReq()); err != nil {
		t.Fatal(err)
	}
	if dev.frames() != 1 {
		t.Fatalf("frames sent: %d", dev.frames())
	}
	p, err := ndproxy.Parse(dev.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	me := ndproxy.MAC(dev.hw)
	want := p.Type == ndproxy.TypeNeighborAdvertisement && p.Target == netip.MustParseAddr("2001:db8:1:2:100::10") &&
		p.Src == p.Target && p.Dst == netip.MustParseAddr("fe80::1") && p.EthSrc == me && p.EthDst.String() == "00:00:5e:00:02:96" &&
		p.TargetLLA != nil && *p.TargetLLA == me && p.Flags == ndproxy.FlagSolicited|ndproxy.FlagOverride
	if !want {
		t.Fatalf("the advertisement is not the one that was asked for: %+v", p)
	}
}

func TestNDPAnswerRefusals(t *testing.T) {
	cases := []struct {
		name string
		mod  func(q *NDPAnswerReq, dev *fakeNDP)
		code api.Code
		text string
	}{
		{"an uplink that is not approved", func(q *NDPAnswerReq, _ *fakeNDP) { q.Uplink = "igb0" }, api.CodeForbidden, "no network in IPv6 proxy mode uses"},
		{"a bad interface name", func(q *NDPAnswerReq, _ *fakeNDP) { q.Uplink = "-x" }, api.CodeInvalid, ""},
		{"a target outside the approved prefix", func(q *NDPAnswerReq, _ *fakeNDP) { q.Target = "2001:db8:1:2:200::10" }, api.CodeForbidden, "outside the subnets"},
		{"a target that is the upstream router", func(q *NDPAnswerReq, _ *fakeNDP) { q.Target = "fe80::1" }, api.CodeForbidden, "outside the subnets"},
		{"a target that is not an address", func(q *NDPAnswerReq, _ *fakeNDP) { q.Target = "nonsense" }, api.CodeInvalid, ""},
		{"an IPv4 target", func(q *NDPAnswerReq, _ *fakeNDP) { q.Target = "10.0.0.1" }, api.CodeInvalid, ""},
		{"a target with a zone", func(q *NDPAnswerReq, _ *fakeNDP) { q.Target = "2001:db8:1:2:100::10%em0" }, api.CodeInvalid, ""},
		{"an address of this host", func(_ *NDPAnswerReq, dev *fakeNDP) { dev.local = []string{"2001:db8:1:2:100::10"} }, api.CodeForbidden, "address of this host"},
		{"duplicate address detection", func(q *NDPAnswerReq, _ *fakeNDP) { q.RequesterIP = "::" }, api.CodeForbidden, "not a unicast neighbor"},
		{"a multicast requester", func(q *NDPAnswerReq, _ *fakeNDP) { q.RequesterIP = "ff02::1" }, api.CodeForbidden, "not a unicast neighbor"},
		{"an IPv4 requester", func(q *NDPAnswerReq, _ *fakeNDP) { q.RequesterIP = "10.0.0.1" }, api.CodeInvalid, ""},
		{"a multicast MAC", func(q *NDPAnswerReq, _ *fakeNDP) { q.RequesterMAC = "33:33:00:00:00:01" }, api.CodeForbidden, "not a unicast"},
		{"a zero MAC", func(q *NDPAnswerReq, _ *fakeNDP) { q.RequesterMAC = "00:00:00:00:00:00" }, api.CodeForbidden, "not a unicast"},
		{"a MAC that is not Ethernet", func(q *NDPAnswerReq, _ *fakeNDP) { q.RequesterMAC = "00:00:5e:00:02:96:01:02" }, api.CodeInvalid, ""},
		{"the host itself as the requester", func(q *NDPAnswerReq, dev *fakeNDP) { q.RequesterMAC = ndproxy.MAC(dev.hw).String() }, api.CodeForbidden, "this host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			dev := e.local.d.NDP.(*fakeNDP)
			q := ndpReq()
			tc.mod(&q, dev)
			err := e.local.NDPAnswer(context.Background(), q)
			if err == nil || !api.IsCode(err, tc.code) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("want %s %q, got %v", tc.code, tc.text, err)
			}
			if dev.frames() != 0 {
				t.Fatal("a frame was sent for a refused request")
			}
		})
	}
}

// The helper approves a prefix itself, from the stored networks in proxy mode, and checks it.
func TestNDPPrefixChecks(t *testing.T) {
	proxy := func(uplink, subnet string) api.NetworkSpec {
		return api.NetworkSpec{Uplink: uplink, IPv6: &api.IPv6Net{Mode: api.IPv6Proxy, Subnet: subnet}}
	}
	store := func(e *env, name string, spec api.NetworkSpec) {
		b, _ := json.Marshal(map[string]any{"kind": "Network", "metadata": api.ObjectMeta{Name: name, UUID: name + "-uuid"}, "spec": spec})
		mustWrite(t, filepath.Join(e.cfg.StateDir, "objects", "Network", name+"-uuid.json"), string(b))
	}
	alone := func(e *env) { // the network of the fixture is not there: the one under test is the only one on em0
		if err := os.Remove(filepath.Join(e.cfg.StateDir, "objects", "Network", "bbbb-1111-2222.json")); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		mod  func(e *env)
		text string
	}{
		{"a prefix wider than /48", func(e *env) { alone(e); store(e, "wide", proxy("em0", "2001:db8::/32")) }, "must be between"},
		{"a single address", func(e *env) { alone(e); store(e, "one", proxy("em0", "2001:db8:9::1/128")) }, "must be between"},
		{"a link-local prefix", func(e *env) { alone(e); store(e, "ll", proxy("em0", "fe80::/64")) }, "not a global"},
		{"an address of the host inside the prefix", func(e *env) {
			e.net.AddIface(ifconfig.Iface{Name: "em1", Flags: []string{"UP"}, Inet6: []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2:100::5/64")}})
		}, "own address"},
		{"an overlapping network", func(e *env) {
			store(e, "other", api.NetworkSpec{Uplink: "em1", IPv6: &api.IPv6Net{Mode: api.IPv6Routed, Subnet: "2001:db8:1:2:100::/96"}})
		}, "overlaps"},
		{"an uplink that is a bridge", func(e *env) {
			store(e, "onbr", proxy("mybr", "2001:db8:7::/64"))
			e.net.AddIface(ifconfig.Iface{Name: "mybr", Groups: []string{"bridge"}, Flags: []string{"UP"}})
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.mod(e)
			q := ndpReq()
			if tc.name == "an uplink that is a bridge" {
				q.Uplink = "mybr"
			}
			err := e.local.NDPAnswer(context.Background(), q)
			if !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("want forbidden %q, got %v", tc.text, err)
			}
			if e.local.d.NDP.(*fakeNDP).frames() != 0 {
				t.Fatal("a frame was sent")
			}
		})
	}
}

func TestNDPAnswersAreRateLimited(t *testing.T) {
	e := newEnv(t)
	now := time.Unix(1000, 0)
	e.local.ndp.now = func() time.Time { return now }
	dev := e.local.d.NDP.(*fakeNDP)
	ok, refused := 0, 0
	for i := 0; i < ndpAnswersPerSecond*2; i++ {
		switch err := e.local.NDPAnswer(context.Background(), ndpReq()); {
		case err == nil:
			ok++
		case api.IsCode(err, api.CodeBusy):
			refused++
		default:
			t.Fatal(err)
		}
	}
	if ok != ndpAnswersPerSecond || refused != ndpAnswersPerSecond || dev.frames() != ndpAnswersPerSecond {
		t.Fatalf("ok=%d refused=%d sent=%d", ok, refused, dev.frames())
	}
	now = now.Add(time.Second) // a second later the bucket is full again
	if err := e.local.NDPAnswer(context.Background(), ndpReq()); err != nil {
		t.Fatalf("after a second: %v", err)
	}
}

func TestNDPAnnounceIsOneUnsolicitedAdvertisementToAllNodes(t *testing.T) {
	e := newEnv(t)
	dev := e.local.d.NDP.(*fakeNDP)
	q := NDPAnswerReq{Uplink: "em0", Target: "2001:db8:1:2:100::10", Announce: true}
	if err := e.local.NDPAnswer(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if dev.frames() != 1 {
		t.Fatalf("frames sent: %d", dev.frames())
	}
	p, err := ndproxy.Parse(dev.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	me := ndproxy.MAC(dev.hw)
	ok := p.Type == ndproxy.TypeNeighborAdvertisement && p.Target == netip.MustParseAddr(q.Target) && p.Src == p.Target &&
		p.Dst == netip.MustParseAddr("ff02::1") && p.EthSrc == me && p.EthDst.String() == "33:33:00:00:00:01" &&
		p.TargetLLA != nil && *p.TargetLLA == me && p.Flags == ndproxy.FlagOverride
	if !ok {
		t.Fatalf("not an unsolicited advertisement of the target to all nodes: %+v", p)
	}
	// the same limits as an answer: approved prefix only, never the host's own address
	for name, mod := range map[string]func(*NDPAnswerReq, *fakeNDP){
		"outside the prefix": func(q *NDPAnswerReq, _ *fakeNDP) { q.Target = "2001:db8:1:2:200::10" },
		"the host itself":    func(_ *NDPAnswerReq, d *fakeNDP) { d.local = []string{"2001:db8:1:2:100::10"} },
		"an unapproved link": func(q *NDPAnswerReq, _ *fakeNDP) { q.Uplink = "igb0" },
	} {
		e := newEnv(t)
		d := e.local.d.NDP.(*fakeNDP)
		q := NDPAnswerReq{Uplink: "em0", Target: "2001:db8:1:2:100::10", Announce: true}
		mod(&q, d)
		if err := e.local.NDPAnswer(context.Background(), q); !api.IsCode(err, api.CodeForbidden) || d.frames() != 0 {
			t.Errorf("%s: %v (frames %d)", name, err, d.frames())
		}
	}
}

// The helper speaks only for addresses that have a host route of a jail on this host: not for the upstream router, not
// for another machine of the segment, even though they lie inside the approved prefix.
func TestNDPOnlyForAddressesThatRouteToAJail(t *testing.T) {
	for name, routes := range map[string]map[string]string{
		"no route at all":         {},
		"a route out the uplink":  {"2001:db8:1:2:100::10": "em0"},
		"a route of someone else": {"2001:db8:1:2:100::10": "tun0"},
		"a bridge made by hand":   {"2001:db8:1:2:100::10": "mybr"},
	} {
		e := newEnv(t)
		dev := e.local.d.NDP.(*fakeNDP)
		dev.routes = routes
		if err := e.local.NDPAnswer(context.Background(), ndpReq()); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s (answer): %v", name, err)
		}
		a := NDPAnswerReq{Uplink: "em0", Target: "2001:db8:1:2:100::10", Announce: true}
		if err := e.local.NDPAnswer(context.Background(), a); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s (announce): %v", name, err)
		}
		if dev.frames() != 0 {
			t.Errorf("%s: a frame was sent", name)
		}
	}
	// a route that appears is noticed within the cache's age
	e := newEnv(t)
	dev := e.local.d.NDP.(*fakeNDP)
	now := time.Unix(5000, 0)
	e.local.ndp.now = func() time.Time { return now }
	dev.routes = map[string]string{}
	if err := e.local.NDPAnswer(context.Background(), ndpReq()); err == nil {
		t.Fatal("answered without a route")
	}
	dev.routes = map[string]string{"2001:db8:1:2:100::10": "jo30gb"}
	now = now.Add(2 * ndpRoutesMaxAge)
	if err := e.local.NDPAnswer(context.Background(), ndpReq()); err != nil {
		t.Fatalf("after the route appeared: %v", err)
	}
}

// A route installed a moment ago is found at once when the reading that lacks it is older than the miss age, and the
// table is not read again for each request within it.
func TestNDPRereadsTheRoutesOnAMissAfterTheMissAge(t *testing.T) {
	e := newEnv(t)
	dev := e.local.d.NDP.(*fakeNDP)
	now := time.Unix(7000, 0)
	e.local.ndp.now = func() time.Time { return now }
	dev.routes = map[string]string{}
	a := NDPAnswerReq{Uplink: "em0", Target: "2001:db8:1:2:100::10", Announce: true}
	if err := e.local.NDPAnswer(context.Background(), a); err == nil {
		t.Fatal("announced without a route")
	}
	dev.routes = map[string]string{"2001:db8:1:2:100::10": "jo30gb"}
	now = now.Add(ndpRoutesMissAge / 2)
	if err := e.local.NDPAnswer(context.Background(), a); err == nil {
		t.Fatal("the table was read again inside the miss age")
	}
	now = now.Add(ndpRoutesMissAge)
	if err := e.local.NDPAnswer(context.Background(), a); err != nil {
		t.Fatalf("a route younger than the cache's age was refused: %v", err)
	}
}

func TestParseHostRoutes(t *testing.T) {
	text := `Routing tables

Internet6:
Destination                       Gateway                       Flags         Netif Expire
default                           fe80::1%vtnet0                UGS          vtnet0
2001:db8:c1:3bb8::1              link#2                        UHS             lo0
2001:db8:c1:3bb8:100::10         link#8                        UHS          jo30gb
fe80::%vtnet0/64                  link#1                        U            vtnet0
fe80::1%lo0                       link#11                       UHS             lo0
`
	r := parseHostRoutes(text)
	if r[netip.MustParseAddr("2001:db8:c1:3bb8:100::10")] != "jo30gb" || len(r) != 2 {
		t.Fatalf("%v", r)
	}
}
