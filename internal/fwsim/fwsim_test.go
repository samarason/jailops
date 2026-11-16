package fwsim

import (
	"net/netip"
	"strings"
	"testing"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

var (
	jail4 = netip.MustParseAddr("10.20.0.10")
	jail6 = netip.MustParseAddr("2001:db8:1::10")
	peer4 = netip.MustParseAddr("10.20.0.20")
	peer6 = netip.MustParseAddr("2001:db8:1::20")
	far4  = netip.MustParseAddr("192.0.2.7")
)

func allow(name, proto string, ports ...string) api.FirewallRule {
	return api.FirewallRule{Name: name, Action: "allow", Direction: "in", Proto: proto, Ports: ports, Comment: "why " + name}
}

func anchor(t *testing.T, mut func(*render.PFInput)) *render.Anchor {
	t.Helper()
	in := render.PFInput{Jail: "alpha_db", Interfaces: []string{"jo0123456789a0a"},
		Addresses: []netip.Addr{jail4, jail6}, Antispoof: true,
		DefaultIn: "deny", DefaultOut: "allow", Sets: map[string]api.AddressSetSpec{}, TagMembers: map[string][]netip.Addr{}}
	if mut != nil {
		mut(&in)
	}
	a, err := render.BuildAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var (
	intoJail = Hook{Dir: "out"} // what reaches the jail
	fromJail = Hook{Dir: "in"}  // what the jail sends
)

func tcp(src, dst netip.Addr, port int) Packet {
	fam := "inet"
	if dst.Is6() {
		fam = "inet6"
	}
	return Packet{Family: fam, Proto: "tcp", Src: src, Dst: dst, DstPort: port}
}

func check(t *testing.T, what string, got HopResult, want Verdict, stage string) {
	t.Helper()
	if got.Verdict != want {
		t.Errorf("%s: %s (%s), want %s", what, got.Verdict, got.Why, want)
		return
	}
	if stage != "" && (got.Rule == nil || got.Rule.Origin.Stage != stage) {
		t.Errorf("%s: decided by %+v, want stage %s", what, got.Rule, stage)
	}
}

func TestDefaultsAndFirstMatchingRule(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.Policies = []render.PFPolicy{{Name: "postgres", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Name: "from peer", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"10.20.0.20"}, Ports: []string{"5432"}, Comment: "who"},
		}}}}
	})
	got := Evaluate(a, tcp(peer4, jail4, 5432), intoJail)
	check(t, "peer to the port", got, Pass, "policy")
	if got.Rule.Origin.Policy != "postgres" || got.Rule.Origin.RuleNo != 1 || got.Rule.Origin.Comment != "who" || !strings.Contains(got.Text, "5432") {
		t.Errorf("the deciding rule: %+v %q", got.Rule.Origin, got.Text)
	}
	check(t, "another port", Evaluate(a, tcp(peer4, jail4, 5433), intoJail), Block, "default")
	check(t, "another source", Evaluate(a, tcp(far4, jail4, 5432), intoJail), Block, "default")
	// what the jail sends is allowed by default
	check(t, "outbound default", Evaluate(a, tcp(jail4, far4, 443), fromJail), Pass, "default")
}

// A deny rule wins over every allow rule, whatever the order of the policies and of the rules.
func TestDenyBeatsAllowWhateverTheOrder(t *testing.T) {
	deny22 := api.FirewallRule{Name: "no ssh", Action: "deny", Direction: "in", Proto: "tcp", Ports: []string{"22"}, Comment: "closed"}
	allow22 := allow("ssh", "tcp", "22")
	for name, policies := range map[string][]render.PFPolicy{
		"project deny, jail allow": {
			{Name: "floor", Project: true, Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{deny22}}},
			{Name: "own", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{allow22}}},
		},
		"jail allow listed before the deny": {
			{Name: "own", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{allow22}}},
			{Name: "late", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{deny22}}},
		},
		"allow before deny in one policy": {
			{Name: "one", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{allow22, deny22}}},
		},
		"deny before allow in one policy": {
			{Name: "one", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{deny22, allow22}}},
		},
	} {
		a := anchor(t, func(in *render.PFInput) { in.Policies = policies })
		got := Evaluate(a, tcp(peer4, jail4, 22), intoJail)
		check(t, name, got, Block, "policy")
		if got.Rule.Origin.RuleName != "no ssh" {
			t.Errorf("%s: decided by %+v", name, got.Rule.Origin)
		}
		var won bool
		for _, s := range got.Skipped {
			if s.Rule.Origin.RuleName == "ssh" && strings.Contains(s.Why, "deny rule wins") {
				won = true
			}
		}
		if !won {
			t.Errorf("%s: the allow rule that lost is not named: %+v", name, got.Skipped)
		}
	}
}

// The allow rules still decide where no deny rule matches, and the project's policy comes before the jail's in each group.
func TestAllowOnlyWhereNoDenyMatches(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.Policies = []render.PFPolicy{
			{Name: "floor", Project: true, Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
				{Name: "no ssh", Action: "deny", Direction: "in", Proto: "tcp", Ports: []string{"22"}},
				allow("web", "tcp", "80"),
			}}},
			{Name: "own", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{allow("ssh", "tcp", "22"), allow("pg", "tcp", "5432")}}},
		}
	})
	check(t, "ssh", Evaluate(a, tcp(peer4, jail4, 22), intoJail), Block, "policy")
	got := Evaluate(a, tcp(peer4, jail4, 80), intoJail)
	check(t, "web from the project policy", got, Pass, "policy")
	if got.Rule.Origin.Policy != "floor" || !got.Rule.Origin.ProjectPolicy || len(got.Skipped) != 0 {
		t.Errorf("web: %+v %+v", got.Rule.Origin, got.Skipped)
	}
	got = Evaluate(a, tcp(peer4, jail4, 5432), intoJail)
	check(t, "pg from the jail's policy", got, Pass, "policy")
	if got.Rule.Origin.Policy != "own" || got.Rule.Origin.RuleName != "pg" {
		t.Errorf("pg: %+v", got.Rule.Origin)
	}
	check(t, "nothing allows 8080", Evaluate(a, tcp(peer4, jail4, 8080), intoJail), Block, "default")
}

// A disabled rule is not loaded: it lets nothing through and stops nothing, and a walk says that it would have been met.
func TestDisabledRuleIsNotLoadedAndIsSaid(t *testing.T) {
	off := allow("ssh", "tcp", "22")
	off.Disabled = true
	offDeny := api.FirewallRule{Name: "no pg", Action: "deny", Direction: "in", Proto: "tcp", Ports: []string{"5432"}, Disabled: true}
	a := anchor(t, func(in *render.PFInput) {
		in.Policies = []render.PFPolicy{{Name: "own", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{off, offDeny, allow("pg", "tcp", "5432")}}}}
	})
	got := Evaluate(a, tcp(peer4, jail4, 22), intoJail)
	check(t, "a disabled allow lets nothing through", got, Block, "default")
	if len(got.Skipped) != 1 || got.Skipped[0].Why != "disabled" || got.Skipped[0].Rule.Origin.RuleName != "ssh" || got.Skipped[0].Rule.Origin.RuleNo != 1 {
		t.Errorf("skipped: %+v", got.Skipped)
	}
	got = Evaluate(a, tcp(peer4, jail4, 5432), intoJail)
	check(t, "a disabled deny stops nothing", got, Pass, "policy")
	if len(got.Skipped) != 1 || got.Skipped[0].Rule.Origin.RuleName != "no pg" || got.Skipped[0].Rule.Origin.RuleNo != 2 {
		t.Errorf("skipped: %+v", got.Skipped)
	}
	// a disabled rule does not turn the anchor into the grouped form
	if strings.Contains(a.Text(), "deny rules of all policies") {
		t.Errorf("a disabled deny rule grouped the anchor:\n%s", a.Text())
	}
	if !strings.Contains(a.Text(), "# rule 1 (disabled): ssh") || !strings.Contains(a.Text(), "# rule 2 (disabled): no pg") {
		t.Errorf("the disabled rules are not shown:\n%s", a.Text())
	}
}

func TestPortRangesAreInclusive(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.Policies = []render.PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{allow("range", "tcp", "8000-8100", "80")}}}}
	})
	for port, want := range map[int]Verdict{79: Block, 80: Pass, 81: Block, 7999: Block, 8000: Pass, 8050: Pass, 8100: Pass, 8101: Block} {
		check(t, "port", Evaluate(a, tcp(peer4, jail4, port), intoJail), want, "")
	}
	// a rule with ports is not for udp, nor for icmp
	if r := Evaluate(a, Packet{Family: "inet", Proto: "udp", Src: peer4, Dst: jail4, DstPort: 80}, intoJail); r.Verdict != Block {
		t.Errorf("udp matched a tcp rule: %+v", r)
	}
}

func TestSetsTagsAndAnyAndTheEmptySet(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.Sets = map[string]api.AddressSetSpec{
			"office": {Addresses: api.Entries("203.0.113.0/24", "2001:db8:ffff::/48", "set:vpn")},
			"vpn":    {Addresses: api.Entries("198.51.100.7")},
			"empty":  {},
		}
		in.TagMembers = map[string][]netip.Addr{"admin": {peer4}}
		in.Policies = []render.PFPolicy{{Name: "p", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Name: "office", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office"}, Ports: []string{"22"}},
			{Name: "admin", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"tag:admin"}, Ports: []string{"2222"}},
			{Name: "nobody", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:empty"}, Ports: []string{"3333"}},
			{Name: "all", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"any", "10.0.0.1"}, Ports: []string{"80"}},
		}}}}
	})
	check(t, "office prefix", Evaluate(a, tcp(netip.MustParseAddr("203.0.113.9"), jail4, 22), intoJail), Pass, "policy")
	check(t, "nested set", Evaluate(a, tcp(netip.MustParseAddr("198.51.100.7"), jail4, 22), intoJail), Pass, "policy")
	check(t, "office v6", Evaluate(a, tcp(netip.MustParseAddr("2001:db8:ffff::5"), jail6, 22), intoJail), Pass, "policy")
	check(t, "outside the set", Evaluate(a, tcp(far4, jail4, 22), intoJail), Block, "default")
	check(t, "tag member", Evaluate(a, tcp(peer4, jail4, 2222), intoJail), Pass, "policy")
	check(t, "not a tag member", Evaluate(a, tcp(far4, jail4, 2222), intoJail), Block, "default")
	check(t, "an empty set matches nobody", Evaluate(a, tcp(peer4, jail4, 3333), intoJail), Block, "default")
	check(t, "any in a list is any", Evaluate(a, tcp(far4, jail4, 80), intoJail), Pass, "policy")
}

func TestOtherFamilyRulesAreNotForThisFamily(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.Policies = []render.PFPolicy{{Name: "p", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Name: "v6 only", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"2001:db8::/32"}, Ports: []string{"22"}},
		}}}}
	})
	check(t, "v6", Evaluate(a, tcp(peer6, jail6, 22), intoJail), Pass, "policy")
	check(t, "v4 to the same port", Evaluate(a, tcp(peer4, jail4, 22), intoJail), Block, "default")
}

func TestAnEmptyToOnInboundMeansTheJailsAddresses(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.Policies = []render.PFPolicy{{Name: "p", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{allow("web", "tcp", "80")}}}}
	})
	check(t, "to the jail", Evaluate(a, tcp(peer4, jail4, 80), intoJail), Pass, "policy")
	// on the jail's own link nothing but its own addresses reaches it
	r := Evaluate(a, tcp(peer4, netip.MustParseAddr("10.20.0.99"), 80), intoJail)
	check(t, "an address the jail does not own", r, Block, render.StageOwnAddrs)
}

func TestAntispoofAndIsolation(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.Foreign = []netip.Prefix{netip.MustParsePrefix("10.31.0.0/24")}
		in.Policies = []render.PFPolicy{{Name: "p", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Name: "to beta", Action: "allow", Direction: "out", Proto: "tcp", To: []string{"10.31.0.5"}, Ports: []string{"443"}},
		}}}}
	})
	// a jail sending with another source address
	check(t, "spoofed source", Evaluate(a, tcp(peer4, far4, 443), fromJail), Block, render.StageAntispoof)
	// a rule of a policy opens one flow into another project, and nothing else
	check(t, "opened by a rule", Evaluate(a, tcp(jail4, netip.MustParseAddr("10.31.0.5"), 443), fromJail), Pass, "policy")
	check(t, "closed by isolation", Evaluate(a, tcp(jail4, netip.MustParseAddr("10.31.0.6"), 443), fromJail), Block, render.StageIsolation)
	check(t, "other project into the jail", Evaluate(a, tcp(netip.MustParseAddr("10.31.0.9"), jail4, 80), intoJail), Block, render.StageIsolation)
}

func TestARawFragmentIsUnknownBeforeTheDecision(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.AllowRaw = true
		in.Policies = []render.PFPolicy{
			{Name: "typed", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{allow("ssh", "tcp", "22")}}},
			{Name: "admin", Policy: api.FirewallPolicySpec{Raw: "block drop in quick proto tcp to port 9"}},
		}
	})
	// a typed rule before the fragment decides
	check(t, "before the fragment", Evaluate(a, tcp(peer4, jail4, 22), intoJail), Pass, "policy")
	// what the fragment sits in front of is unknown on the jail's port
	r := Evaluate(a, tcp(jail4, far4, 443), fromJail)
	if r.Verdict != Unknown || !strings.Contains(r.Why, "admin") {
		t.Errorf("the raw fragment of policy admin: %+v", r)
	}
}

func TestICMP(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) {
		in.Policies = []render.PFPolicy{{Name: "p", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Name: "ping", Action: "allow", Direction: "in", Proto: "icmp"},
			{Name: "ping6", Action: "allow", Direction: "in", Proto: "icmp6", Comment: "ping6"},
		}}}}
	})
	echo4 := Packet{Family: "inet", Proto: "icmp", Src: peer4, Dst: jail4, ICMPType: "echoreq"}
	echo6 := Packet{Family: "inet6", Proto: "icmp6", Src: peer6, Dst: jail6, ICMPType: "echoreq"}
	check(t, "ping", Evaluate(a, echo4, intoJail), Pass, "policy")
	check(t, "ping6", Evaluate(a, echo6, intoJail), Pass, "policy")
	// the ICMPv6 errors pass whatever the policy says: path MTU discovery depends on them
	none := anchor(t, nil)
	toobig := Packet{Family: "inet6", Proto: "icmp6", Src: peer6, Dst: jail6, ICMPType: "toobig"}
	check(t, "packet too big, no policy", Evaluate(none, toobig, intoJail), Pass, render.StageNeighbour)
	check(t, "ping6, no policy", Evaluate(none, echo6, intoJail), Block, "default")
	// from the jail: typed rules come first, so without a type the test cannot say
	r := Evaluate(a, Packet{Family: "inet6", Proto: "icmp6", Src: jail6, Dst: peer6}, fromJail)
	if r.Verdict != Unknown || !strings.Contains(r.Why, "ICMP type") {
		t.Errorf("icmp6 without a type: %+v", r)
	}
	check(t, "echo from the jail", Evaluate(a, Packet{Family: "inet6", Proto: "icmp6", Src: jail6, Dst: peer6, ICMPType: "echoreq"}, fromJail), Pass, "default")
	// neighbour discovery from the jail uses its own addresses
	check(t, "neighbour solicitation", Evaluate(a, Packet{Family: "inet6", Proto: "icmp6", Src: jail6, Dst: peer6, ICMPType: "neighbrsol"}, fromJail), Pass, render.StageNeighbour)
	check(t, "router advertisement from the jail", Evaluate(a, Packet{Family: "inet6", Proto: "icmp6", Src: jail6, Dst: peer6, ICMPType: "routeradv"}, fromJail), Block, render.StageIPv6Control)
}

func TestADefaultAllowAnchor(t *testing.T) {
	a := anchor(t, func(in *render.PFInput) { in.DefaultIn = "allow" })
	check(t, "open anchor", Evaluate(a, tcp(far4, jail4, 12345), intoJail), Pass, "default")
}

// "any" as the destination of an allow rule is every address but the host's and those of the other projects: a jail that
// may reach the internet on port 22 does not reach the host's sshd or the jails of another project. The host is opened
// by naming it, and a deny rule to "any" still denies the host.
func TestAnyDestinationDoesNotReachTheHostOrOtherProjects(t *testing.T) {
	hostAddr := netip.MustParseAddr("10.20.0.1")
	foreign4 := netip.MustParseAddr("10.30.0.5")
	build := func(rules ...api.FirewallRule) *render.Anchor {
		return anchor(t, func(in *render.PFInput) {
			in.DefaultOut = "deny"
			in.Host = []netip.Addr{hostAddr}
			in.Foreign = []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
			in.Policies = []render.PFPolicy{{Name: "egress", Policy: api.FirewallPolicySpec{Rules: rules}}}
		})
	}
	out := func(name, action string, to ...string) api.FirewallRule {
		return api.FirewallRule{Name: name, Action: action, Direction: "out", Proto: "tcp", To: to, Ports: []string{"22"}, Comment: "why " + name}
	}
	for _, tc := range []struct {
		name  string
		rules []api.FirewallRule
		dst   netip.Addr
		want  Verdict
		stage string
	}{
		{"the internet", []api.FirewallRule{out("ssh", "allow")}, far4, Pass, "policy"},
		{"another jail of the project", []api.FirewallRule{out("ssh", "allow")}, peer4, Pass, "policy"},
		{"the host", []api.FirewallRule{out("ssh", "allow")}, hostAddr, Block, "host"},
		{"another project", []api.FirewallRule{out("ssh", "allow")}, foreign4, Block, "isolation"},
		{"the host, named", []api.FirewallRule{out("ssh", "allow", "host")}, hostAddr, Pass, "policy"},
		{"another project, named", []api.FirewallRule{out("ssh", "allow", "10.30.0.0/24")}, foreign4, Pass, "policy"},
		{"explicit any", []api.FirewallRule{out("ssh", "allow", "any")}, hostAddr, Block, "host"},
		{"a deny to any denies the host", []api.FirewallRule{out("no ssh", "deny"), out("ssh", "allow", "host")}, hostAddr, Block, "policy"},
	} {
		a := build(tc.rules...)
		check(t, tc.name, Evaluate(a, tcp(jail4, tc.dst, 22), fromJail), tc.want, tc.stage)
	}
}
