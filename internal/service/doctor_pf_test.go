package service

import (
	"strings"
	"testing"
)

func TestQuickPassesBeforeTheAnchorAreFound(t *testing.T) {
	rules := strings.Join([]string{
		"block drop log all",
		"pass in quick on vtnet0 proto tcp from any to (vtnet0) port = 22 flags S/SA keep state",
		"pass out quick on vtnet0 all flags S/SA keep state",
		"pass quick inet proto icmp all keep state",
		"pass quick inet6 proto ipv6-icmp all keep state",
		`anchor "jailops/*" all`,
		"pass quick all",
	}, "\n")
	got := quickPassesBeforeAnchor(rules)
	if len(got) != 2 || !strings.Contains(got[0], "icmp") || !strings.Contains(got[1], "ipv6-icmp") {
		t.Fatalf("%q", got)
	}
	if got := quickPassesBeforeAnchor("pass all\n" + `anchor "jailops/*" all`); len(got) != 0 {
		t.Fatalf("a rule that is not quick was reported: %q", got)
	}
}

func TestDefaultBlockAndStatePolicyLine(t *testing.T) {
	for rules, want := range map[string]bool{
		"block drop log all\npass out all flags S/SA keep state": true,
		"block drop in on vtnet0 all":                            true,
		"block drop in quick on vtnet0 all":                      false,
		"block drop in log quick inet6 from fe80::/10 to any":    false,
		"pass all": false,
	} {
		if got := defaultBlock(rules); got != want {
			t.Errorf("%q: %v", rules, got)
		}
	}
	for conf, want := range map[string]bool{
		"set skip on lo0\nset state-policy if-bound\nblock log all": true,
		"set state-policy \\\n  if-bound":                           true,
		"# set state-policy if-bound\nblock log all":                false,
		"set state-policy floating":                                 false,
	} {
		if got := reStatePolicy.MatchString(stripPFComments(conf)); got != want {
			t.Errorf("%q: %v", conf, got)
		}
	}
}
