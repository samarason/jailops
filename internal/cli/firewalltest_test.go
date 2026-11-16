package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// 'firewall test' says pass or block with the rule that decided, in a table and as JSON, and its exit status says it too:
// 0 pass, 1 block, 8 when the test cannot say.
func TestFirewallTest(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}})
	h.srv.SeedGeneration("freebsd-151")
	tr := h.transcript()
	tr.ok("app", "install", "postgresql", "db", "--image", "freebsd-151@stable")
	tr.ok("app", "install", "nginx", "web", "--image", "freebsd-151@stable")
	tr.ok("firewall", "address-set", "create", "postgresql-allow", "--address", "jail:web", "--comment", "the web jail")
	tr.ok("firewall", "policy", "create", "postgres")
	tr.ok("firewall", "rule", "add", "postgres", "in", "--action", "allow", "--proto", "tcp", "--from", "set:postgresql-allow", "--port", "5432", "--comment", "who may reach PostgreSQL")
	tr.ok("config", "set", "db", "firewall.policies", "postgres")
	_, _, code := tr.do("", "firewall", "test", "--from", "jail:web", "--to", "jail:db", "--port", "5432")
	if code != 0 {
		t.Fatalf("web -> db:5432 exited %d", code)
	}
	if _, _, code = tr.do("", "firewall", "test", "--from", "jail:web", "--to", "jail:db", "--port", "5433"); code != 1 {
		t.Fatalf("web -> db:5433 exited %d, want 1", code)
	}
	tr.do("", "firewall", "test", "--from", "jail:web", "--to", "jail:db", "--proto", "icmp")
	tr.do("", "firewall", "test", "--from", "jail:web", "--to", "jail:db", "--port", "5432", "-o", "json")
	// refusals
	tr.do("", "firewall", "test", "--to", "jail:db", "--port", "5432")
	tr.do("", "firewall", "test", "--from", "jail:web", "--to", "jail:db")
	tr.do("", "firewall", "test", "--from", "jail:web", "--to", "jail:nobody", "--port", "5432")
	tr.golden("firewall_test")

	// the JSON answer has the verdict, the hops and the rule that decided
	out, _, code := h.run("", "firewall", "test", "--from", "jail:web", "--to", "jail:db", "--port", "5432", "-o", "json")
	var res api.FirewallTestResult
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.Verdict != api.TestPass || len(res.Cases) != 1 || len(res.Cases[0].Hops) == 0 {
		t.Fatalf("%d %s", code, out)
	}
	last := res.Cases[0].Hops[len(res.Cases[0].Hops)-1]
	if last.DecidedBy == nil || last.DecidedBy.Policy != "postgres" || last.DecidedBy.Comment != "who may reach PostgreSQL" {
		t.Fatalf("the rule that decided: %+v", last.DecidedBy)
	}
}

// --from and --to complete in two levels: jail: and host, then the jails of the project; --proto and --family complete their values.
func TestFirewallTestCompletion(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}})
	h.srv.SeedGeneration("freebsd-151")
	for _, args := range [][]string{
		{"app", "install", "postgresql", "db", "--image", "freebsd-151@stable"},
		{"firewall", "address-set", "create", "office", "--address", "198.51.100.0/24"},
	} {
		if o, e, code := h.run("", args...); code != 0 {
			t.Fatalf("%v: %s %s", args, o, e)
		}
	}
	for _, c := range []struct {
		args       []string
		want, none []string
	}{
		{[]string{"firewall", "test", "--from", ""}, []string{"jail:db", "host", "10.20.0.10"}, []string{"jail:", "set:", "set:office"}},
		{[]string{"firewall", "test", "--from", "jail:"}, []string{"jail:db"}, []string{"set:office", "host"}},
		{[]string{"firewall", "test", "--to", "jail:"}, []string{"jail:db"}, []string{"set:office"}},
		{[]string{"firewall", "test", "--proto", ""}, []string{"tcp", "udp", "icmp", "icmp6"}, []string{"jail:db"}},
	} {
		out, _, code := h.run("", append([]string{"__complete"}, c.args...)...)
		if code != 0 {
			t.Fatalf("%v: %d", c.args, code)
		}
		lines := strings.Split(out, "\n")
		has := func(s string) bool {
			for _, l := range lines {
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
	}
}
