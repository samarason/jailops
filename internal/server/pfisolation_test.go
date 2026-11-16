package server_test

import (
	"jailops.net/jailops/internal/render"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func startJailIn(t *testing.T, c *sdk.Client, j api.Jail) {
	t.Helper()
	ctx := ctxT(t)
	op, err := c.Jails().Create(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	so, err := c.Jails().Start(ctx, j.Metadata.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := so.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

// Projects are isolated from each other without anyone writing a policy, and every jail has an anchor.
func TestProjectsAreIsolatedWithoutAnyPolicy(t *testing.T) {
	e := seeded(t) // project alpha on lan 10.20.0.0/24
	net := e.MakeNetwork("b")
	if _, err := e.Admin.Projects().Create(ctxT(t), api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: net}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	beta := e.Scoped(api.PermAdmin, "beta")
	startJailIn(t, e.Admin, dtest.WebJailOn("a1", "lan"))
	startJailIn(t, beta, dtest.WebJailOn("b1", net))

	ra := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_a1.conf")
	rb := e.File(e.Cfg.StateDir + "/rendered/pf/beta_b1.conf")
	if ra == "" || rb == "" {
		t.Fatalf("a jail without a policy has no anchor:\nalpha=%q\nbeta=%q", ra, rb)
	}
	if !strings.Contains(ra, "table <foreign> persist { 10.31.0.0/24 }") || strings.Contains(ra, "10.20.0.0/24") {
		t.Errorf("alpha's jail must treat beta's network, and only that, as foreign:\n%s", ra)
	}
	if !strings.Contains(rb, "table <foreign> persist { 10.20.0.0/24 }") || strings.Contains(rb, "10.31.0.0/24") {
		t.Errorf("beta's jail must treat alpha's network, and only that, as foreign:\n%s", rb)
	}
	for _, rs := range []string{ra, rb} {
		if !strings.Contains(rs, "pass in quick on") || strings.Contains(rs, "block drop out quick on jo") && !strings.Contains(rs, "pass out quick on") {
			t.Errorf("a jail without a policy must be open apart from the isolation:\n%s", rs)
		}
	}
}

// The project's mandatory defaults are a floor: a jail's own policy cannot turn a default deny into an allow.
func TestAProjectsDefaultDenyIsAFloor(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	if _, err := e.Admin.Firewall().Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "base"},
		Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Firewall().Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "open"},
		Spec: api.FirewallPolicySpec{DefaultIn: "allow", DefaultOut: "allow"}}); err != nil {
		t.Fatal(err)
	}
	p, err := e.Admin.Projects().Get(c, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	p.Spec.FirewallPolicies = []string{"base"}
	if _, err := e.Admin.Projects().Update(c, "alpha", p, ""); err != nil {
		t.Fatal(err)
	}
	j := dtest.WebJailOn("w1", "lan")
	j.Spec.Firewall.Policies = []string{"open"}
	startJailIn(t, e.Admin, j)
	rs := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_w1.conf")
	i := strings.Index(rs, "# defaults")
	if i < 0 || !strings.Contains(rs[i:], "block drop out quick on") || strings.Contains(rs[i:], "pass out quick on") && strings.Index(rs[i:], "pass out quick on") < strings.Index(rs[i:], "block drop out quick on") {
		t.Fatalf("the jail's own default allow overrode the project's default deny:\n%s", rs)
	}
}

// A rule says `from jail:NAME` and means the jail (its addresses, a table of its own), also for a name with a hyphen; a
// jail that does not exist is allowed and matches nobody (an empty table); a jail and an address set of one project may
// have the same name, because a reference says which of them it means.
func TestARuleNamesAJail(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	startJailIn(t, e.Admin, dtest.WebJailOn("w1", "lan"))
	startJailIn(t, e.Admin, dtest.WebJailOn("web-2", "lan"))
	w1, err := e.Admin.Jails().Get(c, "w1")
	if err != nil {
		t.Fatal(err)
	}
	addr := w1.Spec.Network[0].IPv4
	if addr == "" {
		t.Fatalf("the jail has no address: %+v", w1.Spec.Network)
	}
	rule := func(from string) api.FirewallPolicy {
		return api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "pg"},
			Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{from}, Ports: []string{"5432"}}}}}
	}
	if _, err := e.Admin.Firewall().Policies().Create(c, rule("set:nosuch")); err == nil || !strings.Contains(err.Error(), "nosuch") {
		t.Fatalf("a set that does not exist was accepted: %v", err)
	}
	if _, err := e.Admin.Firewall().Policies().Create(c, rule("@w1")); err == nil || !strings.Contains(err.Error(), "jail:w1") {
		t.Fatalf("@ was accepted, or the error does not say what to write: %v", err)
	}
	if _, err := e.Admin.Firewall().Policies().Create(c, rule("jail:w1")); err != nil {
		t.Fatal(err)
	}
	db := dtest.WebJailOn("db1", "lan")
	db.Spec.Firewall.Policies = []string{"pg"}
	startJailIn(t, e.Admin, db)
	rs := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_db1.conf")
	if !strings.Contains(rs, "<j_w1>") || !strings.Contains(rs, addr) {
		t.Fatalf("the rule does not hold the addresses of the jail w1 (%s):\n%s", addr, rs)
	}
	// a hyphen in the jail's name: the table of it has an underscore
	pol, err := e.Admin.Firewall().Policies().Get(c, "pg")
	if err != nil {
		t.Fatal(err)
	}
	pol.Spec.Rules[0].From = []string{"jail:web-2"}
	if _, err := e.Admin.Firewall().Policies().Update(c, "pg", pol, ""); err != nil {
		t.Fatal(err)
	}
	e.D.Reconciler().Pass(c)
	rs, _ = e.PF.Read(c, render.JailAnchorFor("alpha", "db1"))
	if !strings.Contains(rs, "<j_web_2>") {
		t.Fatalf("a jail with a hyphen in its name is not a table:\n%s", rs)
	}
	// a jail that does not exist is an empty table: the policy is made, the anchor renders, the rule matches nobody
	pol.Spec.Rules[0].From = []string{"jail:later"}
	if _, err := e.Admin.Firewall().Policies().Update(c, "pg", pol, ""); err != nil {
		t.Fatalf("a jail that is not there yet was refused: %v", err)
	}
	e.D.Reconciler().Pass(c)
	rs, _ = e.PF.Read(c, render.JailAnchorFor("alpha", "db1"))
	if !strings.Contains(rs, "table <j_later> persist\n") {
		t.Fatalf("a jail that does not exist is not an empty table:\n%s", rs)
	}
	// a jail and an address set may have the same name: jail:w1 and set:w1 are two tables
	if _, err := e.Admin.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "w1"}, Spec: api.AddressSetSpec{Addresses: api.Entries("192.0.2.77")}}); err != nil {
		t.Fatalf("a set named like a jail was refused: %v", err)
	}
	if _, err := e.Admin.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "lab-1"}, Spec: api.AddressSetSpec{Addresses: api.Entries("192.0.2.79")}}); err != nil {
		t.Fatal(err)
	}
	if op, err := e.Admin.Jails().Create(c, dtest.WebJailOn("lab-1", "lan")); err != nil {
		t.Fatalf("a jail named like a set was refused: %v", err)
	} else if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
}

// An address set can hold jails as members ("jail:w1"), a rule that names it follows them, a jail named by a rule or a member
// is not renamed behind its back, a set renamed is renamed in the members of other sets, and a rule whose jail was
// deleted matches nobody (the anchors of the jails that use the policy are still rendered).
func TestAnAddressSetHoldsJails(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	startJailIn(t, e.Admin, dtest.WebJailOn("w1", "lan"))
	w1, err := e.Admin.Jails().Get(c, "w1")
	if err != nil {
		t.Fatal(err)
	}
	addr := w1.Spec.Network[0].IPv4
	if _, err := e.Admin.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "git-allow"},
		Spec: api.AddressSetSpec{Addresses: []api.AddressEntry{{Address: "192.0.2.7", Comment: "the office"}, {Address: "jail:w1"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "bad"}, Spec: api.AddressSetSpec{Addresses: api.Entries("set:nosuch")}}); err == nil {
		t.Fatal("a member that is a set that does not exist was accepted")
	}
	if _, err := e.Admin.Firewall().Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "git"},
		Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:git-allow"}, Ports: []string{"22"}}}}}); err != nil {
		t.Fatal(err)
	}
	db := dtest.WebJailOn("g1", "lan")
	db.Spec.Firewall.Policies = []string{"git"}
	startJailIn(t, e.Admin, db)
	e.D.Reconciler().Pass(c)
	rs, _ := e.PF.Read(c, render.JailAnchorFor("alpha", "g1"))
	if !strings.Contains(rs, "192.0.2.7") || !strings.Contains(rs, addr) {
		t.Fatalf("the set holds neither its address nor the jail's (%s):\n%s", addr, rs)
	}
	// the jail is named by a member of a set: it is not renamed behind the set's back
	stop, err := e.Admin.Jails().Stop(c, "w1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stop.Wait(c); err != nil {
		t.Fatal(err)
	}
	rop, err := e.Admin.Jails().Rename(c, "w1", api.Rename{NewName: "w9"}, "")
	if err == nil {
		_, err = rop.Wait(c)
	}
	if err == nil || !strings.Contains(err.Error(), "git-allow") {
		t.Fatalf("a jail that a set names was renamed, or refused without naming the set: %v", err)
	}
	// a jail that a set names is not deleted behind the set's back either
	if _, err := e.Admin.Jails().Delete(c, "w1"); err == nil || !strings.Contains(err.Error(), "git-allow") {
		t.Fatalf("a jail that a set names was deleted, or the refusal does not name the set: %v", err)
	}
	// the reference is removed, the jail goes: the rule of the policy still renders and now matches only the office
	gs, err := e.Admin.Firewall().AddressSets().Get(c, "git-allow")
	if err != nil {
		t.Fatal(err)
	}
	gs.Spec.Addresses = api.Entries("192.0.2.7")
	if _, err := e.Admin.Firewall().AddressSets().Update(c, "git-allow", gs, ""); err != nil {
		t.Fatal(err)
	}
	dop, err := e.Admin.Jails().Delete(c, "w1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dop.Wait(c); err != nil {
		t.Fatal(err)
	}
	e.D.Reconciler().Pass(c)
	rs, err = e.PF.Read(c, render.JailAnchorFor("alpha", "g1"))
	if err != nil || !strings.Contains(rs, "192.0.2.7") || strings.Contains(rs, addr+",") {
		t.Fatalf("after the jail was deleted (%v):\n%s", err, rs)
	}
}

// A policy and an address set may name a jail that is made later (the order of a fleet apply is sets, policies, jails):
// the reference is an empty table until the jail exists, and then it holds the jail's addresses.
func TestAPolicyAndASetMayNameAJailMadeLater(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	if _, err := e.Admin.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "clients"},
		Spec: api.AddressSetSpec{Addresses: []api.AddressEntry{{Address: "jail:later", Comment: "made after the set"}}}}); err != nil {
		t.Fatalf("a set that names a jail made later was refused: %v", err)
	}
	if _, err := e.Admin.Firewall().Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "pg"},
		Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{
			{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"jail:later"}, Ports: []string{"5432"}},
			{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:clients"}, Ports: []string{"5433"}}}}}); err != nil {
		t.Fatalf("a policy that names a jail made later was refused: %v", err)
	}
	db := dtest.WebJailOn("db2", "lan")
	db.Spec.Firewall.Policies = []string{"pg"}
	startJailIn(t, e.Admin, db)
	e.D.Reconciler().Pass(c)
	rs, _ := e.PF.Read(c, render.JailAnchorFor("alpha", "db2"))
	if !strings.Contains(rs, "table <j_later> persist\n") || !strings.Contains(rs, "table <s_clients> persist\n") {
		t.Fatalf("before the jail exists both references are empty tables:\n%s", rs)
	}
	startJailIn(t, e.Admin, dtest.WebJailOn("later", "lan"))
	later, err := e.Admin.Jails().Get(c, "later")
	if err != nil {
		t.Fatal(err)
	}
	e.D.Reconciler().Pass(c)
	rs, _ = e.PF.Read(c, render.JailAnchorFor("alpha", "db2"))
	if !strings.Contains(rs, "table <j_later> persist { "+later.Spec.Network[0].IPv4) || !strings.Contains(rs, "table <s_clients> persist { "+later.Spec.Network[0].IPv4) {
		t.Fatalf("after the jail exists the references hold its address %s:\n%s", later.Spec.Network[0].IPv4, rs)
	}
}
