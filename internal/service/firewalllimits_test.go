package service_test

import (
	"fmt"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

func bigSet(name string, from, n int) api.AddressSet {
	set := api.AddressSet{Metadata: api.ObjectMeta{Name: name}}
	for i := from; i < from+n; i++ {
		set.Spec.Addresses = append(set.Spec.Addresses, api.AddressEntry{Address: fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)})
	}
	return set
}

// The address sets of one project share a budget, so that one project cannot fill the table space pf has for every project.
func TestAddressSetsOfAProjectShareABudget(t *testing.T) {
	_, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	per := api.MaxAddressSetMembers
	for i := 0; i < api.MaxSetMembersPerProject/per; i++ {
		if _, err := s.CreateAddressSet(ctx, bigSet(fmt.Sprintf("s%d", i), i*per, per)); err != nil {
			t.Fatalf("set %d: %v", i, err)
		}
	}
	_, err := s.CreateAddressSet(ctx, bigSet("over", 0, 1))
	wantCode(t, err, api.CodeQuotaExceeded)
	// a set larger than the limit of one set is invalid, whatever the rest
	_, err = s.CreateAddressSet(ctx, bigSet("huge", 0, api.MaxAddressSetMembers+1))
	wantCode(t, err, api.CodeInvalid)
	// growing a set past the budget is refused as well
	grown := bigSet("s0", 0, per)
	grown.Spec.Addresses = append(grown.Spec.Addresses, api.AddressEntry{Address: "192.0.2.1"})
	_, err = s.UpdateAddressSet(ctx, "s0", grown, service.AnyGeneration)
	wantCode(t, err, api.CodeInvalid)
}

func TestPoliciesOfAProjectAreLimited(t *testing.T) {
	_, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	for i := 0; i < api.MaxPoliciesPerProject; i++ {
		if _, err := s.CreatePolicy(ctx, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: fmt.Sprintf("p%d", i)},
			Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}}); err != nil {
			t.Fatalf("policy %d: %v", i, err)
		}
	}
	_, err := s.CreatePolicy(ctx, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "over"},
		Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}})
	wantCode(t, err, api.CodeQuotaExceeded)
}
