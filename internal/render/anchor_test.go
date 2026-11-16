package render

import (
	"net/netip"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// The structured rules of an anchor are the filter lines of its text, one for one and in the same order: whoever
// walks Anchor.Rules walks what is loaded, and FormatAnchor is exactly what PFAnchor returns.
func TestAnchorRulesAreTheFilterLinesOfTheText(t *testing.T) {
	rule := func(name, port string) api.FirewallRule {
		return api.FirewallRule{Name: name, Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{port}, Comment: "why " + name}
	}
	full := pfBase()
	full.Foreign = []netip.Prefix{netip.MustParsePrefix("10.31.0.0/24")}
	full.LinkLocal = []netip.Addr{ip("fe80::1")}
	full.Proxy = []api.FirewallRule{{Name: "proxy web", Action: "allow", Direction: "in", Proto: "tcp", Redirect: &api.Redirect{HostPort: 8080, JailPort: 80}}}
	raw := pfBase()
	raw.Policies = append(raw.Policies, PFPolicy{Name: "admin", AllowRaw: true, Policy: api.FirewallPolicySpec{Raw: "block drop in quick proto tcp to port 9"}})
	several := pfBase()
	several.Policies = []PFPolicy{
		{Name: "floor", Project: true, Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{rule("ssh", "22")}}},
		{Name: "app-web", Managed: true, Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{rule("access", "5432")}}},
		{Name: "postgres", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{rule("from the set", "5432")}}},
	}
	for name, in := range map[string]PFInput{"base": pfBase(), "full": full, "raw": raw, "several": several} {
		an, err := BuildAnchor(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		text, err := PFAnchor(in)
		if err != nil {
			t.Fatal(err)
		}
		if FormatAnchor(an) != text || an.Text() != text {
			t.Errorf("%s: FormatAnchor is not the text PFAnchor returns", name)
		}
		// the filter lines of the text, outside the administrator's raw fragment
		var want []int
		inRaw := false
		for i, ln := range an.Lines {
			switch ln {
			case rawBegin:
				inRaw = true
			case rawEnd:
				inRaw = false
			}
			// the pass rule after a port forward's translation stands on the uplink, which is neither the jail's own port
			// nor its gateway: the test of a connection does not walk it
			afterForward := i > 0 && strings.HasPrefix(an.Lines[i-1], "match in on ") && strings.Contains(an.Lines[i-1], " rdr-to ")
			if !inRaw && !afterForward && (strings.HasPrefix(ln, "pass ") || strings.HasPrefix(ln, "block ")) {
				want = append(want, i)
			}
		}
		var got []int
		for _, r := range an.Rules {
			switch r.Kind {
			case RuleFilter:
				ln := an.Lines[r.Line]
				if !strings.HasPrefix(ln, "pass ") && !strings.HasPrefix(ln, "block ") {
					t.Errorf("%s: rule at line %d is not a filter line: %q", name, r.Line, ln)
				}
				if !strings.Contains(ln, " quick ") {
					t.Errorf("%s: a rule that is not quick: %q", name, ln)
				}
				got = append(got, r.Line)
			case RuleRaw:
				if an.Lines[r.Line] != rawBegin {
					t.Errorf("%s: the raw marker is at %q", name, an.Lines[r.Line])
				}
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s: %d structured rules, %d filter lines\n%s", name, len(got), len(want), text)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: rule %d is at line %d, the filter line is at %d", name, i, got[i], want[i])
			}
		}
	}
}

// Every rule of a policy says where it comes from: the policy, its number in the policy, its name and comment.
func TestAnchorRulesKnowTheirOrigin(t *testing.T) {
	in := pfBase()
	in.Policies = []PFPolicy{
		{Name: "floor", Project: true, Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{{Name: "ssh", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"22"}, Comment: "ssh for all"}}}},
		{Name: "app-web", Managed: true, Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"5432"}}, {Name: "second", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"5433"}}}}},
	}
	an, err := BuildAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	var seen []Origin
	for _, r := range an.Rules {
		if r.Origin.Stage == StagePolicy {
			seen = append(seen, r.Origin)
		}
	}
	want := []Origin{
		{Stage: StagePolicy, Policy: "floor", ProjectPolicy: true, RuleNo: 1, RuleName: "ssh", Comment: "ssh for all"},
		{Stage: StagePolicy, Policy: "app-web", Managed: true, RuleNo: 1},
		{Stage: StagePolicy, Policy: "app-web", Managed: true, RuleNo: 2, RuleName: "second"},
	}
	// a policy rule renders once for every family the jail has (the base jail has both)
	var uniq []Origin
	for _, o := range seen {
		if len(uniq) == 0 || uniq[len(uniq)-1] != o {
			uniq = append(uniq, o)
		}
	}
	if len(uniq) != len(want) {
		t.Fatalf("origins %+v", uniq)
	}
	for i := range want {
		if uniq[i] != want[i] {
			t.Errorf("origin %d: %+v, want %+v", i, uniq[i], want[i])
		}
	}
}
