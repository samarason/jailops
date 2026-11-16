package validate

import (
	"fmt"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestFirewallObjectsHaveSizeLimits(t *testing.T) {
	rule := api.FirewallRule{Name: "r", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"22"}, Comment: "ssh"}
	spec := api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}
	for i := 0; i < api.MaxPolicyRules; i++ {
		spec.Rules = append(spec.Rules, rule)
	}
	spec.Rules = append(spec.Rules, rule)
	if _, err := FirewallPolicySpec(spec); err == nil || fieldOf(err) != "rules" {
		t.Fatalf("%d rules: %v", len(spec.Rules), err)
	}
	var set api.AddressSetSpec
	for i := 0; i <= api.MaxAddressSetMembers; i++ {
		set.Addresses = append(set.Addresses, api.AddressEntry{Address: fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)})
	}
	if err := AddressSetSpec(set); err == nil || fieldOf(err) != "addresses" {
		t.Fatalf("%d members: %v", len(set.Addresses), err)
	}
	set.Addresses = set.Addresses[:api.MaxAddressSetMembers]
	if err := AddressSetSpec(set); err != nil {
		t.Fatalf("%d members: %v", len(set.Addresses), err)
	}
}

func fieldOf(err error) string {
	if e, ok := err.(*api.Error); ok {
		return e.Detail["field"]
	}
	return ""
}
