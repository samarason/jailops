package server_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// The firewall test walks the anchors that are rendered: a database jail that only an allow-list reaches, under a
// project policy that denies inbound and lets ping through.
func TestFirewallTestWalksTheRenderedAnchors(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	fw := e.Admin.Firewall()
	mk := func(name string, spec api.FirewallPolicySpec) {
		t.Helper()
		if _, err := fw.Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: name}, Spec: spec}); err != nil {
			t.Fatal(err)
		}
	}
	mk("default", api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{
		{Action: "allow", Direction: "in", Proto: "icmp", Comment: "ping and ICMP errors"}}})
	startJailIn(t, e.Admin, dtest.WebJailOn("web", "lan"))
	startJailIn(t, e.Admin, dtest.WebJailOn("other", "lan"))
	if _, err := fw.AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "postgresql-allow"},
		Spec: api.AddressSetSpec{Addresses: []api.AddressEntry{{Address: "jail:web", Comment: "the web jail"}}}}); err != nil {
		t.Fatal(err)
	}
	mk("postgres", api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{
		{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:postgresql-allow"}, Ports: []string{"5432"}, Comment: "who may reach PostgreSQL"}}})
	p, err := e.Admin.Projects().Get(c, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	p.Spec.FirewallPolicies = []string{"default"}
	if _, err := e.Admin.Projects().Update(c, "alpha", p, ""); err != nil {
		t.Fatal(err)
	}
	db := dtest.WebJailOn("db", "lan")
	db.Spec.Firewall.Policies = []string{"postgres"}
	startJailIn(t, e.Admin, db)

	test := func(from, to, proto string, port int) api.FirewallTestResult {
		t.Helper()
		res, err := fw.Test(c, api.FirewallTestRequest{From: from, To: to, Proto: proto, Port: port})
		if err != nil {
			t.Fatalf("%s -> %s: %v", from, to, err)
		}
		return res
	}
	last := func(res api.FirewallTestResult) api.FirewallTestHop {
		cs := res.Cases[0]
		return cs.Hops[len(cs.Hops)-1]
	}

	// the allow-list reaches the database port; both hops pass, and the rule that let it in is named
	res := test("jail:web", "jail:db", "tcp", 5432)
	if res.Verdict != api.TestPass || len(res.Cases) != 1 || len(res.Cases[0].Hops) != 2 {
		t.Fatalf("web -> db:5432: %+v", res)
	}
	by := last(res).DecidedBy
	if by == nil || by.Stage != "policy" || by.Policy != "postgres" || by.Rule != 1 || by.Comment != "who may reach PostgreSQL" || !strings.Contains(by.PF, "5432") {
		t.Fatalf("the rule that let web in: %+v", by)
	}
	if h := res.Cases[0].Hops[0]; h.Side != "source" || h.Direction != "in" || h.Jail != "web" {
		t.Fatalf("the first hop is the source jail's own link: %+v", h)
	}
	if h := last(res); h.Side != "destination" || h.Direction != "out" || h.Anchor != "jailops/alpha/db" {
		t.Fatalf("the last hop is the destination's own link: %+v", h)
	}
	// another port, and another jail, are blocked by the default of the destination
	for _, c := range []struct {
		from string
		port int
	}{{"jail:web", 5433}, {"jail:other", 5432}, {"host", 5432}} {
		res := test(c.from, "jail:db", "tcp", c.port)
		if res.Verdict != api.TestBlock {
			t.Fatalf("%s -> db:%d should be blocked: %+v", c.from, c.port, res)
		}
		if by := last(res).DecidedBy; by == nil || by.Stage != "default" {
			t.Fatalf("%s -> db:%d is blocked by the default of the anchor: %+v", c.from, c.port, by)
		}
	}
	// ping comes from the project's policy
	res = test("jail:other", "jail:db", "icmp", 0)
	if by := last(res).DecidedBy; res.Verdict != api.TestPass || by == nil || by.Policy != "default" || !by.ProjectPolicy {
		t.Fatalf("ping other -> db: %+v", res)
	}
	if len(res.Caveats) == 0 || !strings.Contains(strings.Join(res.Caveats, " "), "echo request") {
		t.Fatalf("the ICMP type that was assumed is said: %v", res.Caveats)
	}
	// an address that belongs to a jail is that jail; an address that does not is an external host
	web, err := e.Admin.Jails().Get(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	if res := test(strings.SplitN(web.Spec.Network[0].IPv4, "/", 2)[0], "jail:db", "tcp", 5432); res.Verdict != api.TestPass || res.Cases[0].Hops[0].Jail != "web" {
		t.Fatalf("a jail's address is the jail: %+v", res)
	}
	res = test("192.0.2.7", "jail:db", "tcp", 5432)
	if res.Verdict != api.TestBlock || len(res.Cases[0].Hops) != 1 {
		t.Fatalf("an external address meets only the destination's anchor: %+v", res)
	}
	// refusals say why
	for _, bad := range []struct{ from, to, proto string }{
		{"set:postgresql-allow", "jail:db", "tcp"}, {"jail:nosuch", "jail:db", "tcp"}, {"jail:web", "jail:db", "sctp"}, {"10.0.0.0/8", "jail:db", "tcp"}, {"host", "host", "tcp"},
	} {
		if _, err := fw.Test(c, api.FirewallTestRequest{From: bad.from, To: bad.to, Proto: bad.proto, Port: 1}); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	if _, err := fw.Test(c, api.FirewallTestRequest{From: "jail:web", To: "jail:db"}); err == nil {
		t.Error("a tcp test without a port was accepted")
	}
	// icmp is the IPv4 protocol and icmp6 the IPv6 one, as in a rule: the other family has no test with it
	for _, req := range []api.FirewallTestRequest{
		{From: "jail:web", To: "jail:db", Proto: "icmp", Family: "6"}, {From: "jail:web", To: "jail:db", Proto: "icmp6", Family: "4"}, {From: "jail:web", To: "jail:db", Proto: "icmp6"}} {
		if _, err := fw.Test(c, req); err == nil {
			t.Errorf("%+v was accepted", req)
		}
	}
}

// A deny rule wins over an allow rule of another policy of the jail, in whatever order they are listed, and the test
// names the allow rule that lost; a disabled rule decides nothing and is named.
func TestFirewallTestDenyWinsAndDisabledRulesDecideNothing(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	fw := e.Admin.Firewall()
	mk := func(name string, rules ...api.FirewallRule) {
		t.Helper()
		if _, err := fw.Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: name},
			Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: rules}}); err != nil {
			t.Fatal(err)
		}
	}
	startJailIn(t, e.Admin, dtest.WebJailOn("web", "lan"))
	mk("postgres", api.FirewallRule{Name: "pg from web", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"jail:web"}, Ports: []string{"5432"}})
	mk("quiet", api.FirewallRule{Name: "no web", Action: "deny", Direction: "in", Proto: "tcp", From: []string{"jail:web"}, Ports: []string{"5432"}, Comment: "keep web out"})
	// the deny rule is in the policy that is listed LAST
	db := dtest.WebJailOn("db", "lan")
	db.Spec.Firewall.Policies = []string{"postgres", "quiet"}
	startJailIn(t, e.Admin, db)
	test := func() api.FirewallTestHop {
		t.Helper()
		res, err := fw.Test(c, api.FirewallTestRequest{From: "jail:web", To: "jail:db", Proto: "tcp", Port: 5432})
		if err != nil {
			t.Fatal(err)
		}
		hops := res.Cases[0].Hops
		if res.Verdict != api.TestBlock && res.Verdict != api.TestPass {
			t.Fatalf("%+v", res)
		}
		return hops[len(hops)-1]
	}
	h := test()
	if h.Verdict != api.TestBlock || h.DecidedBy == nil || h.DecidedBy.Policy != "quiet" || h.DecidedBy.Name != "no web" {
		t.Fatalf("the deny rule of the later policy wins: %+v", h)
	}
	if len(h.Skipped) != 1 || h.Skipped[0].Rule.Policy != "postgres" || h.Skipped[0].Rule.Name != "pg from web" || !strings.Contains(h.Skipped[0].Why, "deny rule wins") {
		t.Fatalf("the allow rule that lost is named: %+v", h.Skipped)
	}
	// switch the deny rule off: the allow rule decides, and the disabled rule is named
	q, err := fw.Policies().Get(c, "quiet")
	if err != nil {
		t.Fatal(err)
	}
	q.Spec.Rules[0].Disabled = true
	if _, err := fw.Policies().Update(c, "quiet", q, ""); err != nil {
		t.Fatal(err)
	}
	h = test()
	if h.Verdict != api.TestPass || h.DecidedBy == nil || h.DecidedBy.Policy != "postgres" {
		t.Fatalf("a disabled deny rule stops nothing: %+v", h)
	}
	if len(h.Skipped) != 1 || h.Skipped[0].Why != "disabled" || h.Skipped[0].Rule.Policy != "quiet" || h.Skipped[0].Rule.Rule != 1 {
		t.Fatalf("the disabled rule is named: %+v", h.Skipped)
	}
}

// A raw PF fragment is the administrator's text, which the test does not evaluate: the answer is unknown and names
// the policy, not a guess.
func TestFirewallTestSaysUnknownForARawFragment(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	fw := e.Admin.Firewall()
	if _, err := fw.Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "rawpol"},
		Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Raw: "block drop in quick proto tcp to port 9"}}); err != nil {
		t.Fatal(err)
	}
	j := dtest.WebJailOn("rawjail", "lan")
	j.Spec.Firewall.Policies = []string{"rawpol"}
	startJailIn(t, e.Admin, j)
	startJailIn(t, e.Admin, dtest.WebJailOn("peer", "lan"))
	res, err := fw.Test(c, api.FirewallTestRequest{From: "jail:rawjail", To: "jail:peer", Proto: "tcp", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	h := res.Cases[0].Hops[0]
	if res.Verdict != api.TestUnknown || h.Verdict != api.TestUnknown || !strings.Contains(h.Why, "rawpol") || h.DecidedBy != nil {
		t.Fatalf("a raw fragment: %+v", res)
	}
}

// The test changes nothing but reveals the rules of the project, so it is for operators and up, in the project.
func TestFirewallTestNeedsAnOperator(t *testing.T) {
	e := seeded(t)
	startJailIn(t, e.Admin, dtest.WebJailOn("web", "lan"))
	startJailIn(t, e.Admin, dtest.WebJailOn("db", "lan"))
	req := api.FirewallTestRequest{From: "jail:web", To: "jail:db", Proto: "tcp", Port: 5432}
	if _, err := e.Scoped(api.PermReadonly, "alpha").Firewall().Test(ctxT(t), req); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("readonly: %v", err)
	}
	if _, err := e.Scoped(api.PermOperator, "alpha").Firewall().Test(ctxT(t), req); err != nil {
		t.Fatalf("operator: %v", err)
	}
	net := e.MakeNetwork("b")
	if _, err := e.Admin.Projects().Create(ctxT(t), api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: net}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Scoped(api.PermOperator, "beta").Project("alpha").Firewall().Test(ctxT(t), req); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("an operator of another project may not test in alpha: %v", err)
	}
}

// A rule that names a jail that does not exist matches nobody, and the test says so: the table is empty.
func TestFirewallTestSaysWhenARuleNamesAJailThatIsNotThere(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	fw := e.Admin.Firewall()
	if _, err := fw.Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "pg"}, Spec: api.FirewallPolicySpec{
		DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{
			{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"jail:ghost"}, Ports: []string{"5432"}}}}}); err != nil {
		t.Fatal(err)
	}
	startJailIn(t, e.Admin, dtest.WebJailOn("web", "lan"))
	db := dtest.WebJailOn("db", "lan")
	db.Spec.Firewall.Policies = []string{"pg"}
	startJailIn(t, e.Admin, db)
	res, err := fw.Test(c, api.FirewallTestRequest{From: "jail:web", To: "jail:db", Proto: "tcp", Port: 5432})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != api.TestBlock || !strings.Contains(strings.Join(res.Caveats, "\n"), "policy pg rule 1 names jail:ghost, which does not exist") {
		t.Fatalf("%s: %v", res.Verdict, res.Caveats)
	}
	// the old syntax and a set are refused as ends
	for _, end := range []string{"@web", "set:office", "tag:x"} {
		if _, err := fw.Test(c, api.FirewallTestRequest{From: end, To: "jail:db", Proto: "tcp", Port: 5432}); err == nil {
			t.Errorf("%q was accepted as an end", end)
		}
	}
}
