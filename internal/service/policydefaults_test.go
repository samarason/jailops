package service_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// A policy stored without default_in or default_out is not rendered with a default of ours: the jail that uses it is
// refused with the policy and the field named and the command that fixes it, and doctor fails for the policy.
func TestPolicyStoredWithoutDefaultsIsRefusedAtRenderAndByDoctor(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	if _, err := s.CreatePolicy(ctx, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "tight"},
		Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}}); err != nil {
		t.Fatal(err)
	}
	j := dtest.WebJail("web")
	j.Spec.Firewall.Policies = []string{"tight"}
	op, err := s.CreateJail(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("%+v\n%s", got, e.Log())
	}
	if err := service.RenderJail(s, dtest.SeedProject, "web"); err != nil {
		t.Fatal(err)
	}
	doctor := func() api.DoctorCheck {
		t.Helper()
		for _, c := range s.Doctor(as(globalAdmin, "")).Checks {
			if c.Name == "firewall.defaults" {
				return c
			}
		}
		return api.DoctorCheck{}
	}
	if c := doctor(); c.Name != "" {
		t.Fatalf("a policy with both defaults is reported: %+v", c)
	}
	for _, tc := range []struct {
		name    string
		spec    api.FirewallPolicySpec
		missing string
	}{
		{"no default_in", api.FirewallPolicySpec{DefaultOut: "allow"}, "default_in"},
		{"no default_out", api.FirewallPolicySpec{DefaultIn: "deny"}, "default_out"},
	} {
		if err := service.SetPolicyRaw(s, dtest.SeedProject, "tight", tc.spec); err != nil {
			t.Fatal(err)
		}
		err := service.RenderJail(s, dtest.SeedProject, "web")
		if err == nil || !strings.Contains(err.Error(), `firewall policy "tight" has no `+tc.missing) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ae, ok := err.(*api.Error); !ok || !strings.Contains(ae.Hint, "jailops firewall policy edit tight") {
			t.Fatalf("%s: no hint: %v", tc.name, err)
		}
		c := doctor()
		if c.Status != api.DoctorFail || !strings.Contains(c.Message, dtest.SeedProject+"/tight lacks "+tc.missing) || !strings.Contains(c.Hint, "policy edit") {
			t.Fatalf("%s: %+v", tc.name, c)
		}
	}
}

// A jail's own policy is neither a policy that something else manages (app-JAIL) nor the project's mandatory policy,
// which is rendered for every jail already.
func TestJailMayNotNameAManagedPolicyOrTheProjectFloor(t *testing.T) {
	_, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	spec := api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}
	if err := service.SetManagedPolicy(s, dtest.SeedProject, "app-db", api.AppAccessManagedBy, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePolicy(ctx, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "floor"}, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	pr, err := s.GetProject(as(globalAdmin, ""), dtest.SeedProject)
	if err != nil {
		t.Fatal(err)
	}
	pr.Spec.FirewallPolicies = []string{"floor"}
	if _, err := s.UpdateProject(as(globalAdmin, ""), dtest.SeedProject, pr, pr.Metadata.Generation); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"app-db": "is managed by " + api.AppAccessManagedBy, "floor": "is a mandatory policy of project"} {
		j := dtest.WebJail("web")
		j.Spec.Firewall.Policies = []string{name}
		_, err := s.CreateJail(ctx, j)
		wantCode(t, err, api.CodeInvalid)
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
