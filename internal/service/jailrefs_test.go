package service_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// A jail:NAME that names a jail that does not exist is allowed, renders as an empty table, and doctor warns for each rule
// and each set member that names one; naming it for real clears the warning.
func TestDoctorWarnsForAJailThatDoesNotExist(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	if _, err := s.CreateAddressSet(ctx, api.AddressSet{Metadata: api.ObjectMeta{Name: "clients"},
		Spec: api.AddressSetSpec{Addresses: api.Entries("192.0.2.7", "jail:app")}}); err != nil {
		t.Fatalf("a set that names a jail that is not there: %v", err)
	}
	if _, err := s.CreatePolicy(ctx, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "pg"},
		Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{
			{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"jail:app"}, Ports: []string{"5432"}},
			{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:clients"}, Ports: []string{"5433"}}}}}); err != nil {
		t.Fatalf("a policy that names a jail that is not there: %v", err)
	}
	if _, err := s.CreatePolicy(ctx, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "bad"},
		Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{
			{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:nosuch"}}}}}); err == nil {
		t.Fatal("a set that does not exist was accepted")
	}
	check := func() api.DoctorCheck {
		t.Helper()
		for _, c := range s.Doctor(as(globalAdmin, "")).Checks {
			if c.Name == "firewall.refs" {
				return c
			}
		}
		t.Fatal("no firewall.refs check")
		return api.DoctorCheck{}
	}
	c := check()
	if c.Status != api.DoctorWarn || !strings.Contains(c.Message, dtest.SeedProject+"/policy pg rule 1 names jail:app") ||
		!strings.Contains(c.Message, dtest.SeedProject+"/address set clients has the member jail:app") || strings.Contains(c.Message, "rule 2") {
		t.Fatalf("%+v", c)
	}
	j := dtest.WebJail("app")
	op, err := s.CreateJail(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("%+v\n%s", got, e.Log())
	}
	if c := check(); c.Status != api.DoctorOK {
		t.Fatalf("the jail exists now: %+v", c)
	}
}
