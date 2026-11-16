package cli_test

import (
	"testing"

	"jailops.net/jailops/sdk/api"
)

// The rules of a policy are added, listed, changed, moved, switched and removed one at a time, by number or by name.
func TestFirewallRuleCommands(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("firewall", "address-set", "create", "office", "--address", "192.0.2.0/24", "--comment", "the office")
	tr.ok("firewall", "policy", "create", "web", "--comment", "the public web server")
	tr.ok("firewall", "rule", "add", "web", "in", "--action", "allow", "--proto", "tcp", "--port", "80,443", "--name", "site", "--comment", "the site")
	tr.ok("firewall", "rule", "add", "web", "in", "--action", "allow", "--proto", "tcp", "--from", "set:office", "--port", "22", "--comment", "ssh from the office")
	tr.ok("firewall", "rule", "add", "web", "out", "--action", "allow", "--proto", "tcp", "--to", "192.0.2.50", "--port", "5432", "--comment", "the database")
	tr.ok("firewall", "rule", "add", "web", "in", "--action", "deny", "--at", "1", "--from", "198.51.100.0/24", "--comment", "a network that is not welcome")
	tr.ok("firewall", "rule", "list", "web")
	tr.ok("firewall", "rule", "list", "web", "-o", "json")
	// the number is the one policy show prints
	tr.ok("firewall", "policy", "show", "web")
	tr.ok("firewall", "rule", "edit", "web", "site", "--port", "80,443,8080", "--comment", "the site and the test site")
	tr.ok("firewall", "rule", "edit", "web", "3", "--from", "set:office,203.0.113.7")
	tr.ok("firewall", "rule", "edit", "web", "3", "--from", "")
	tr.ok("firewall", "rule", "disable", "web", "2", "site")
	tr.ok("firewall", "rule", "enable", "web", "site")
	tr.ok("firewall", "rule", "move", "web", "4", "--to", "1")
	tr.ok("firewall", "rule", "move", "web", "site", "--after", "4")
	tr.ok("firewall", "rule", "move", "web", "2", "--before", "1")
	tr.ok("firewall", "rule", "move", "web", "1", "--to", "1")
	tr.ok("firewall", "rule", "list", "web")
	tr.ok("firewall", "rule", "remove", "web", "--name", "site")
	tr.ok("firewall", "rule", "remove", "web", "1")
	tr.ok("firewall", "rule", "list", "web")
	tr.ok("firewall", "--dry-run", "rule", "remove", "web", "1")
	tr.ok("firewall", "rule", "list", "web", "-o", "name")
	tr.golden("firewall_rules")
}

// What a rule command refuses, and says.
func TestFirewallRuleRefusals(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedFirewallPolicy(api.FirewallPolicy{
		Metadata: api.ObjectMeta{Name: "app-db", Project: "main", ManagedBy: api.AppAccessManagedBy},
		Spec:     api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}})
	tr := h.transcript()
	tr.ok("firewall", "policy", "create", "web")
	tr.ok("firewall", "rule", "add", "web", "in", "--action", "allow", "--proto", "tcp", "--port", "80", "--name", "site", "--comment", "the site")
	for _, args := range [][]string{
		{"rule", "add", "web", "in"},                                                                               // no action
		{"rule", "add", "web", "sideways", "--action", "allow"},                                                    // not a direction
		{"rule", "add", "web", "in", "--action", "allow", "--to", "192.0.2.5"},                                     // an inbound rule names its source
		{"rule", "add", "web", "out", "--action", "allow", "--from", "192.0.2.5"},                                  // an outbound rule names its destination
		{"rule", "add", "web", "in", "--action", "allow", "--name", "site", "--port", "81", "--proto", "tcp"},      // a name is used once
		{"rule", "add", "nothing", "in", "--action", "allow"},                                                      // no such policy
		{"rule", "add", "web", "in", "--action", "allow", "--at", "9"},                                             // no such position
		{"rule", "add", "web", "in", "--action", "allow", "--from", "@office"},                                     // @ is gone
		{"rule", "add", "web", "in", "--action", "allow", "--redirect", "eighty"},                                  // not HOSTPORT:JAILPORT
		{"rule", "remove", "web", "7"},                                                                             // no such rule
		{"rule", "remove", "web", "ghost"},                                                                         // no such name
		{"rule", "remove", "web"},                                                                                  // which one
		{"rule", "edit", "web", "1"},                                                                               // nothing to change
		{"rule", "move", "web", "1"},                                                                               // where
		{"rule", "move", "web", "1", "--to", "1", "--after", "1"},                                                  // one place only
		{"rule", "add", "app-db", "in", "--action", "allow", "--proto", "tcp", "--port", "5432", "--comment", "x"}, // managed by app access
		{"rule", "remove", "app-db", "1"},
	} {
		tr.do("", append([]string{"firewall"}, args...)...)
	}
	tr.golden("firewall_rule_refusals")
}
