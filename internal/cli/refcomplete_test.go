package cli_test

import (
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// A reference is completed in two levels in the --from and --to of a rule: the kinds where a reference is expected,
// the names after a kind. The rule commands complete their other words too: the policy, the direction, the flags'
// values and the rules of a policy.
func TestRuleCompletion(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}})
	h.srv.SeedGeneration("freebsd-151")
	for _, args := range [][]string{
		{"app", "install", "postgresql", "db", "--image", "freebsd-151@stable"},
		{"app", "install", "nginx", "web", "--image", "freebsd-151@stable"},
		{"firewall", "address-set", "create", "office", "--address", "198.51.100.0/24"},
		{"firewall", "address-set", "create", "vpn", "--address", "203.0.113.0/24"},
		{"firewall", "policy", "create", "p"},
		{"firewall", "rule", "add", "p", "in", "--action", "allow", "--proto", "tcp", "--port", "80,443", "--name", "site", "--comment", "the site"},
		{"firewall", "rule", "add", "p", "in", "--action", "allow", "--proto", "tcp", "--port", "22", "--from", "set:office", "--comment", "ssh from the office"},
	} {
		if o, e, code := h.run("", args...); code != 0 {
			t.Fatalf("%v: %s %s", args, o, e)
		}
	}
	add := []string{"firewall", "rule", "add", "p", "in", "--action", "allow"}
	for _, c := range []struct {
		args       []string
		want, none []string
	}{
		{append(slices.Clone(add), "--from", ""), []string{"jail:", "set:", "tag:", "any"}, []string{"host", "jail:web", "@web"}},
		{append(slices.Clone(add), "--from", "j"), []string{"jail:"}, []string{"set:"}},
		{append(slices.Clone(add), "--from", "jail:"), []string{"jail:web", "jail:db"}, []string{"set:office"}},
		{append(slices.Clone(add), "--from", "set:"), []string{"set:office", "set:vpn"}, nil},
		{append(slices.Clone(add), "--from", "set:office,"), []string{"set:office,jail:", "set:office,set:", "set:office,any"}, nil},
		{append(slices.Clone(add), "--from", "set:office,set:v"), []string{"set:office,set:vpn"}, []string{"set:office,set:office"}},
		{[]string{"firewall", "rule", "add", "p", "out", "--action", "allow", "--to", ""}, []string{"jail:", "set:"}, nil},
		{append(slices.Clone(add), "--proto", ""), []string{"tcp", "udp", "icmp", "icmp6"}, nil},
		{append(slices.Clone(add), "--port", ""), []string{"22", "80", "443", "5432"}, nil},
		{append(slices.Clone(add), "--port", "80,"), []string{"80,22", "80,443"}, nil},
		{[]string{"firewall", "rule", "add", "p", "in", "--action", ""}, []string{"allow", "deny"}, nil},
		{[]string{"firewall", "rule", "add", "p", ""}, []string{"in", "out"}, nil},
		{[]string{"firewall", "rule", "add", ""}, []string{"p"}, nil},
		{[]string{"firewall", "rule", "remove", "p", ""}, []string{"1", "2", "site"}, nil},
		{[]string{"firewall", "rule", "list", ""}, []string{"p"}, nil},
		{[]string{"firewall", "rule", "move", "p", "2", "--before", ""}, []string{"1", "site"}, nil},
		{[]string{"firewall", "rule", "edit", "p", "site", "--direction", ""}, []string{"in", "out"}, nil},
		{[]string{"firewall", "rule", "enable", "p", ""}, []string{"1", "2"}, nil},
	} {
		out, _, code := h.run("", append([]string{"__complete"}, c.args...)...)
		if code != 0 {
			t.Fatalf("%v: %d", c.args, code)
		}
		has := func(s string) bool {
			for _, l := range strings.Split(out, "\n") {
				if l == s || strings.HasPrefix(l, s+"\t") {
					return true
				}
			}
			return false
		}
		for _, w := range c.want {
			if !has(w) {
				t.Errorf("complete %v: %q missing in %q", c.args, w, out)
			}
		}
		for _, w := range c.none {
			if has(w) {
				t.Errorf("complete %v: %q offered in %q", c.args, w, out)
			}
		}
		if strings.HasSuffix(out, ":0\n") && len(c.want) > 0 {
			t.Errorf("complete %v: falls back to files: %q", c.args, out)
		}
	}
}

// '@' is not part of a reference: a rule, a set member and a source that use it are refused with what to write instead.
func TestAtSignIsRefused(t *testing.T) {
	h := newHarness(t)
	h.seed()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"firewall", "rule", "add", "p", "in", "--action", "allow", "--from", "@office"}, "@ is not used: write jail:office, set:office or tag:office"},
		{[]string{"firewall", "address-set", "create", "s", "--address", "@web"}, "@ is not used"},
		{[]string{"firewall", "rule", "add", "p", "in", "--action", "allow", "--from", "group:office"}, "unknown kind"},
	} {
		_, e, code := h.run("", c.args...)
		if code == 0 || !strings.Contains(e, c.want) {
			t.Errorf("%v: exit %d, %q does not say %q", c.args, code, e, c.want)
		}
	}
}
