package render

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func pfBase() PFInput {
	return PFInput{
		Jail: "alpha_web", Interfaces: []string{"jo0123456789a0a"},
		Addresses:  []netip.Addr{ip("2001:db8:1::100"), ip("10.20.0.10")},
		Tags:       []string{"web", "tier-1"},
		TagMembers: map[string][]netip.Addr{"admin": {ip("10.20.0.5"), ip("10.20.0.4"), ip("10.20.0.5")}},
		Sets: map[string]api.AddressSetSpec{
			"office": {Addresses: api.Entries("203.0.113.0/24", "2001:db8:ffff::/48", "set:vpn")},
			"vpn":    {Addresses: api.Entries("198.51.100.7")},
		},
		Uplink:    "em0",
		Antispoof: true,
		DefaultIn: "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Name: "ssh from office", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office", "tag:admin"}, Ports: []string{"22"}, Log: true},
			{Name: "web", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"80", "8000-8100"}},
			{Name: "ping", Action: "allow", Direction: "in", Proto: "icmp"},
			{Name: "ping6", Action: "allow", Direction: "in", Proto: "icmp6"},
			{Name: "forward", Action: "allow", Direction: "in", Proto: "tcp", Redirect: &api.Redirect{HostPort: 8080, JailPort: 80}},
			{Name: "no smtp", Action: "deny", Direction: "out", Proto: "tcp", Ports: []string{"25"}},
			{Name: "dns", Action: "allow", Direction: "out", Proto: "udp", To: []string{"9.9.9.9", "2620:fe::fe"}, Ports: []string{"53"}},
		}}}},
	}
}

func TestPFGolden(t *testing.T) {
	s, err := PFAnchor(pfBase())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_anchor_full", s)

	in := pfBase()
	in.Addresses = []netip.Addr{ip("10.20.0.10")}
	in.Antispoof = false
	in.DefaultIn, in.DefaultOut = "allow", "deny"
	in.Policies = []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{}}}
	if s, err = PFAnchor(in); err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_anchor_defaults", s)

	in = pfBase()
	in.Policies[0].Policy.Raw = "pass quick on lo0 all\n"
	in.AllowRaw = true
	if s, err = PFAnchor(in); err != nil {
		t.Fatal(err)
	}
	// (a raw fragment is the administrator's own text and stays as written)
	if !strings.Contains(s, "# raw fragment (admin)\npass quick on lo0 all\n# end of raw fragment (admin)\n# the host:") {
		t.Fatalf("raw fragment misplaced:\n%s", s)
	}
	golden(t, "pf_anchor_raw", s)

	nat, err := PFNet("lan", api.NetworkSpec{Uplink: "em0", IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.20", NAT: true}})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_nat", nat)
	golden(t, "pf_anchor_lines", AnchorLines())
	// without NAT the anchor has no translation rule
	if s, err := PFNet("lan", api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.20"}}); err != nil || strings.Contains(s, "nat-to") || strings.Contains(s, "pass ") {
		t.Fatalf("no nat: %q %v", s, err)
	}
	if JailAnchor("alpha_web") != "jailops/alpha/web" || NetAnchor("lan") != "jailops/net.lan" {
		t.Fatal("anchor names")
	}
}

func TestPFOrdering(t *testing.T) {
	s, _ := PFAnchor(pfBase())
	idx := func(sub string) int { return strings.Index(s, sub) }
	if !(idx("table <") < idx("rdr-to") && idx("rdr-to") < idx("pass out quick") && idx("pass out quick") < idx("# defaults")) {
		t.Fatalf("sections out of order:\n%s", s)
	}
	// icmp is IPv4 only, icmp6 is IPv6 only
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, "proto icmp ") && strings.Contains(ln, "inet6") || strings.Contains(ln, "proto icmp6") && strings.Contains(ln, " inet ") {
			t.Fatalf("wrong family: %s", ln)
		}
	}
	// mixed-family lists are split per family
	if strings.Contains(s, "9.9.9.9, 2620") {
		t.Fatal("mixed-family list")
	}
}

func TestPFErrors(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*PFInput)
	}{
		{"no ifaces", func(i *PFInput) { i.Interfaces = nil }},
		{"bad iface", func(i *PFInput) { i.Interfaces = []string{"em0 all"} }},
		{"jail name", func(i *PFInput) { i.Jail = "a\npass all" }},
		{"raw without admin", func(i *PFInput) { i.Policies[0].Policy.Raw = "pass all"; i.AllowRaw = false }},
		{"unknown set", func(i *PFInput) { i.Policies[0].Policy.Rules[0].From = []string{"set:nope"} }},
		{"bad set ref", func(i *PFInput) { i.Policies[0].Policy.Rules[0].From = []string{"set:a b"} }},
		{"cycle", func(i *PFInput) {
			i.Sets["vpn"] = api.AddressSetSpec{Addresses: api.Entries("set:office")}
		}},
		{"self cycle", func(i *PFInput) { i.Sets["vpn"] = api.AddressSetSpec{Addresses: api.Entries("set:vpn")} }},
		{"bad set member", func(i *PFInput) { i.Sets["vpn"] = api.AddressSetSpec{Addresses: api.Entries("1.2.3.4 pass all")} }},
		{"rdr outbound", func(i *PFInput) {
			i.Policies[0].Policy.Rules = []api.FirewallRule{{Action: "allow", Direction: "out", Proto: "tcp", Redirect: &api.Redirect{HostPort: 1, JailPort: 2}}}
		}},
		{"rdr no uplink", func(i *PFInput) { i.Uplink = "" }},
		{"bad tag", func(i *PFInput) { i.Tags = []string{"a b"} }},
		{"bad rule name", func(i *PFInput) { i.Policies[0].Policy.Rules[0].Name = "x\npass all" }},
		{"bad port", func(i *PFInput) { i.Policies[0].Policy.Rules[1].Ports = []string{"80 }"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := pfBase()
			tc.mut(&in)
			if s, err := PFAnchor(in); err == nil {
				t.Fatalf("accepted:\n%s", s)
			}
		})
	}
	in := pfBase()
	in.Policies[0].Policy.Raw = "pass all"
	_, err := PFAnchor(in)
	if !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("raw error: %v", err)
	}
	var ae *api.Error
	if !errors.As(err, &ae) {
		t.Fatal("not api error")
	}
	in = pfBase()
	in.Sets["vpn"] = api.AddressSetSpec{Addresses: api.Entries("set:office")}
	if _, err := PFAnchor(in); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle message: %v", err)
	}
}

func TestPFSetDiamondIsNotACycle(t *testing.T) {
	in := pfBase()
	in.Sets = map[string]api.AddressSetSpec{
		"office": {Addresses: api.Entries("set:b", "set:c")},
		"b":      {Addresses: api.Entries("set:d")},
		"c":      {Addresses: api.Entries("set:d")},
		"d":      {Addresses: api.Entries("10.0.0.1")},
	}
	if _, err := PFAnchor(in); err != nil {
		t.Fatal(err)
	}
}

const pfAddr = `(any|[0-9a-f:./]+|<[st]_[a-z0-9_]+>|\{ ([0-9a-f:./]+|<[st]_[a-z0-9_]+>)(, ([0-9a-f:./]+|<[st]_[a-z0-9_]+>))* \})`
const pfIfs = `([a-z0-9]+|\{ [a-z0-9]+(, [a-z0-9]+)* \})`
const pfPort = `([0-9]+(:[0-9]+)?|\{ [0-9]+(:[0-9]+)?(, [0-9]+(:[0-9]+)?)* \})`

var pfLineRE = regexp.MustCompile(`^(` +
	`# [A-Za-z0-9 :;._,()/-]*|` +
	`table <([st]_[a-z0-9_]+|jail_addrs)> persist( \{ [0-9a-f:./]+(, [0-9a-f:./]+)* \})?|` +
	`block in quick on ` + pfIfs + ` from ! <jail_addrs> to any|` +
	`match in on [a-z0-9]+ inet6? proto (tcp|udp) from ` + pfAddr + ` to \([a-z0-9]+\) port [0-9]+ rdr-to [0-9a-f:.]+ port [0-9]+|` +
	`pass quick on ` + pfIfs + ` inet6 proto icmp6 icmp6-type \{ neighbrsol, neighbradv \}|` +
	`(pass|block drop) (in|out)( log)? quick on ` + pfIfs + ` inet6? ( ?proto (tcp|udp|icmp|icmp6) )?from ` + pfAddr + ` to ` + pfAddr + `( port ` + pfPort + `)?|` +
	`(pass|block drop) (in|out) on ` + pfIfs + ` all` +
	`)$`)

func FuzzPFAnchor(f *testing.F) {
	f.Add("web", "em0", "x", "office", "10.0.0.0/8", "22", "admin")
	f.Add("a\npass all", "em0\n", "x\nblock all", "a b", "1.2.3.4\npass all", "22\n80", "t\n")
	f.Add("web", "e", "x", "@@", "any; pass", "1-2 }", "tag:")
	f.Fuzz(func(t *testing.T, jail, ifn, ruleName, set, ep, port, tag string) {
		for _, dir := range []string{"in", "out"} {
			in := PFInput{
				Jail: jail, Interfaces: []string{ifn}, Uplink: ifn, Antispoof: true,
				Addresses:  []netip.Addr{ip("10.0.0.5"), ip("2001:db8::5")},
				Tags:       []string{tag},
				TagMembers: map[string][]netip.Addr{tag: {ip("10.0.0.9")}},
				Sets:       map[string]api.AddressSetSpec{set: {Addresses: api.Entries(ep)}},
				DefaultIn:  "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
					{Name: ruleName, Action: "allow", Direction: dir, Proto: "tcp", From: []string{"set:" + set, "tag:" + tag, ep}, To: []string{ep}, Ports: []string{port}},
					{Name: ruleName, Action: "deny", Direction: "in", Proto: "udp", Ports: []string{port}},
				}}}},
			}
			if dir == "in" {
				in.Policies[0].Policy.Rules = append(in.Policies[0].Policy.Rules, api.FirewallRule{Action: "allow", Direction: "in", Proto: "tcp", From: []string{ep}, Redirect: &api.Redirect{HostPort: 80, JailPort: 8080}})
			}
			out, err := PFAnchor(in)
			if err != nil {
				continue
			}
			for _, ln := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
				if !pfLineRE.MatchString(ln) {
					t.Fatalf("unexpected PF line %q in\n%s", ln, out)
				}
			}
		}
	})
}

func FuzzPFNet(f *testing.F) {
	f.Add("lan", "em0", "10.0.0.0/24", "10.0.0.1")
	f.Add("lan\npass all", "em0\n", "10.0.0.0/24\n", "10.0.0.1")
	re := regexp.MustCompile(`^(# .*|match out on [a-z0-9]+ inet from [0-9./]+ to ! [0-9./]+ nat-to \([a-z0-9]+:0\))$`)
	f.Fuzz(func(t *testing.T, name, up, subnet, gw string) {
		out, err := PFNet(name, api.NetworkSpec{Uplink: up, IPv4: &api.IPv4Net{Subnet: subnet, Gateway: gw, Range: gw, NAT: true}})
		if err != nil || out == "" {
			return
		}
		for _, ln := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if !re.MatchString(ln) {
				t.Fatalf("unexpected line %q", ln)
			}
		}
	})
}

func mandBase() PFPolicy {
	return PFPolicy{Name: "baseline", Project: true, Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
		{Name: "no telnet", Action: "deny", Direction: "in", Proto: "tcp", Ports: []string{"23"}},
		{Name: "no smtp", Action: "deny", Direction: "out", Proto: "tcp", Ports: []string{"25"}},
		{Name: "mgmt", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office"}, Ports: []string{"22"}},
		{Name: "fwd", Action: "allow", Direction: "in", Proto: "tcp", Redirect: &api.Redirect{HostPort: 2222, JailPort: 22}},
	}}}
}

func TestPFMandatoryGolden(t *testing.T) {
	jailOnly := pfBase()
	jailOnly.Jail = "web_nginx"
	s, err := PFAnchor(jailOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "# anchor jailops/web/nginx\n") {
		t.Fatalf("anchor comment:\n%s", s)
	}
	golden(t, "pf_anchor_project_jail_only", s)

	only := pfBase()
	only.DefaultIn, only.DefaultOut = "deny", "allow"
	only.Policies = []PFPolicy{mandBase()}
	s, err = PFAnchor(only)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_anchor_mandatory_only", s)

	both := pfBase()
	both.Policies = append([]PFPolicy{mandBase()}, both.Policies...)
	s, err = PFAnchor(both)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_anchor_mandatory_and_jail", s)
	lines := strings.Split(s, "\n")
	pos := func(sub string) int {
		for i, l := range lines {
			if strings.Contains(l, sub) {
				return i
			}
		}
		t.Fatalf("%q not in output", sub)
		return -1
	}
	// The deny rules of all the policies come first, then the allow rules; in each group the project's policy comes
	// before the jail's own, so the jail's heading appears twice and the mandatory rules stand before its second one.
	denyStart := pos("# deny rules of all policies")
	jailAllow := -1
	for i, l := range lines {
		if strings.Contains(l, "# policy web") {
			jailAllow = i
		}
	}
	jailDeny, defaults := pos("# policy web"), pos("# defaults")
	if jailDeny == jailAllow {
		t.Fatalf("the jail policy is not in both groups:\n%s", s)
	}
	for _, m := range []string{"# rule 1: no telnet", "# rule 2: no smtp"} { // mandatory deny rules
		if i := pos(m); i > jailDeny {
			t.Fatalf("mandatory deny rule %q after the jail's deny rules", m)
		}
	}
	for _, m := range []string{"# rule 3: mgmt", "# rule 4: fwd"} { // mandatory allow rules
		if i := pos(m); i > jailAllow || i < jailDeny {
			t.Fatalf("mandatory allow rule %q not in the allow group before the jail's allow rules", m)
		}
	}
	if !(denyStart < pos("# project policy baseline") && pos("# project policy baseline") < pos("# rule 1: no telnet") && jailAllow < defaults) {
		t.Fatalf("block order:\n%s", s)
	}
	// the mandatory redirect is the first rdr line, and tables are defined once
	if !strings.Contains(s, "port 2222 rdr-to") || strings.Index(s, "port 2222 rdr-to") > strings.Index(s, "port 8080 rdr-to") {
		t.Fatalf("rdr order:\n%s", s)
	}
	if strings.Count(s, "table <s_office>") != 1 {
		t.Fatalf("table defined %d times", strings.Count(s, "table <s_office>"))
	}
	// the policy's own defaults are not used: the input's are
	if !strings.Contains(s, "block drop out quick on") || strings.Contains(s, "pass out quick on jo0123456789a0a all") {
		t.Fatalf("defaults:\n%s", s)
	}
}

func TestPFMandatoryErrors(t *testing.T) {
	in := pfBase()
	in.Policies = append([]PFPolicy{mandBase()}, in.Policies...)
	in.Policies[0].Policy.Raw = "pass all"
	if _, err := PFAnchor(in); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("raw without admin: %v", err)
	}
	in.Policies[0].AllowRaw = true
	s, err := PFAnchor(in)
	if err != nil || strings.Index(s, "pass all") > strings.LastIndex(s, "# policy web") || !strings.Contains(s, "# raw fragment (admin)") {
		t.Fatalf("raw with admin: %v\n%s", err, s)
	}
	for name, mut := range map[string]func(*PFInput){
		"name":        func(i *PFInput) { i.Policies[0].Name = "x\npass all" },
		"unknown":     func(i *PFInput) { i.Policies[0].Policy.Rules[2].From = []string{"set:nope"} },
		"bad rule":    func(i *PFInput) { i.Policies[0].Policy.Rules[0].Name = "x\npass all" },
		"jail name":   func(i *PFInput) { i.Jail = "web_Nginx" },
		"no project":  func(i *PFInput) { i.Jail = "nginx" },
		"bad default": func(i *PFInput) { i.DefaultIn = "maybe" },
	} {
		in := pfBase()
		in.Policies = append([]PFPolicy{mandBase()}, in.Policies...)
		mut(&in)
		if s, err := PFAnchor(in); err == nil {
			t.Errorf("%s accepted:\n%s", name, s)
		}
	}
}

// Several policies are rendered in the order they are given, each under its own heading and with its own rule numbers;
// the proxy devices come after them, and the defaults come last.
func TestPFSeveralPolicies(t *testing.T) {
	rule := func(name string, port string) api.FirewallRule {
		return api.FirewallRule{Name: name, Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{port}}
	}
	in := pfBase()
	in.Policies = []PFPolicy{
		{Name: "floor", Project: true, Policy: api.FirewallPolicySpec{Comment: "for every jail", Rules: []api.FirewallRule{rule("ssh", "22")}}},
		{Name: "monitoring", Project: true, Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{rule("metrics", "9100")}}},
		{Name: "app-web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{rule("access a", "5432")}}},
		{Name: "postgres", Policy: api.FirewallPolicySpec{Comment: "who may reach PostgreSQL", Rules: []api.FirewallRule{rule("from the set", "5432"), rule("second", "5433")}}},
		{Name: "ssh-office", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{rule("office", "22")}}},
	}
	in.Proxy = []api.FirewallRule{rule("proxy web", "80")}
	s, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_anchor_several_policies", s)
	at := func(sub string) int {
		i := strings.Index(s, sub)
		if i < 0 {
			t.Fatalf("%q not in:\n%s", sub, s)
		}
		return i
	}
	order := []string{"# project policy floor", "#   for every jail", "# rule 1: ssh", "# project policy monitoring", "# rule 1: metrics",
		"# policy app-web", "# rule 1: access a", "# policy postgres", "#   who may reach PostgreSQL", "# rule 1: from the set", "# rule 2: second",
		"# policy ssh-office", "# rule 1: office", "# proxy devices", "# rule 1: proxy web", "# defaults"}
	for i := 1; i < len(order); i++ {
		if at(order[i-1]) >= at(order[i]) {
			t.Errorf("%q does not come before %q:\n%s", order[i-1], order[i], s)
		}
	}
	if strings.Count(s, "# rule 1:") != 6 {
		t.Errorf("each policy numbers its rules from 1:\n%s", s)
	}
}

func TestProjectAnchors(t *testing.T) {
	for key, want := range map[string]string{"db_web": "jailops/db/web", "a-b_c-d": "jailops/a-b/c-d", "plain": "jailops/plain"} {
		if got := JailAnchor(key); got != want {
			t.Errorf("%s: %s", key, got)
		}
	}
	if JailAnchorFor("db", "web") != "jailops/db/web" || ProjectAnchor("db") != "jailops/db" {
		t.Fatal("anchor helpers")
	}
	golden(t, "pf_project_anchor_rules", ProjectAnchorRules())
}

func TestRedirectOnAListenAddress(t *testing.T) {
	out, err := PFAnchor(PFInput{Jail: "alpha_web", Interfaces: []string{"jo123456789012a"}, Uplink: "em0",
		Addresses: []netip.Addr{netip.MustParseAddr("10.20.0.10")},
		DefaultIn: "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Name: "proxy http", Action: "allow", Direction: "in", Proto: "tcp", Redirect: &api.Redirect{Listen: "192.0.2.7", HostPort: 8080, JailPort: 80}},
			{Name: "proxy dns", Action: "allow", Direction: "in", Proto: "udp", Redirect: &api.Redirect{HostPort: 53, JailPort: 53}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "match in on em0 inet proto tcp from any to 192.0.2.7 port 8080 rdr-to 10.20.0.10 port 80") ||
		!strings.Contains(out, "match in on em0 inet proto udp from any to (em0) port 53 rdr-to 10.20.0.10 port 53") {
		t.Fatal(out)
	}
	_, err = PFAnchor(PFInput{Jail: "alpha_web", Interfaces: []string{"jo123456789012a"}, Uplink: "em0", Addresses: []netip.Addr{netip.MustParseAddr("10.20.0.10")},
		DefaultIn: "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", Redirect: &api.Redirect{Listen: "x; pass all", HostPort: 1, JailPort: 1}}}}}}})
	if err == nil {
		t.Fatal("an injected listen address was rendered")
	}
}

func devfsRuleLines(rules [][]string) string {
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(strings.Join(r, " ") + "\n")
	}
	return b.String()
}

func TestDevfsRulesetIsAllowListedAndDeterministic(t *testing.T) {
	n1, rules, err := DevfsRuleset([]string{"tun", "dri", "tun"})
	if err != nil {
		t.Fatal(err)
	}
	n2, _, _ := DevfsRuleset([]string{"dri", "tun"})
	n3, _, _ := DevfsRuleset([]string{"tun"})
	if n1 != n2 || n1 == n3 || n1 < DevfsRulesetBase {
		t.Fatalf("%d %d %d", n1, n2, n3)
	}
	txt := devfsRuleLines(rules)
	s := fmt.Sprint(n1)
	for _, want := range []string{
		"devfs rule -s " + s + " add include 1\n", "devfs rule -s " + s + " add include 2\n", "devfs rule -s " + s + " add include 3\n",
		"devfs rule -s " + s + " add path tun* unhide\n", "devfs rule -s " + s + " add path dri/* unhide\n",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "kmem") || strings.Contains(txt, "$") {
		t.Fatal(txt)
	}
	for _, bad := range []string{"mem", "../mem", "tun\nadd path mem unhide", ""} {
		if _, _, err := DevfsRuleset([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if n, rules, _ := DevfsRuleset(nil); n != DefaultDevfsRuleset || len(rules) != 0 {
		t.Fatal(n, rules)
	}
}

// Two different sets of devices never share a ruleset number, whatever the OS: the number is the bits of the devices.
func TestDevfsRulesetNumbersNeverCollide(t *testing.T) {
	seen := map[int]string{}
	for mask := 0; mask < 1<<len(devfsOrder); mask++ {
		var devs []string
		for bit, d := range devfsOrder {
			if mask&(1<<bit) != 0 {
				devs = append(devs, d)
			}
		}
		for _, linux := range []bool{false, true} {
			var n int
			var err error
			if linux {
				n, _, err = LinuxDevfsRuleset(devs)
			} else if len(devs) > 0 {
				n, _, err = DevfsRuleset(devs)
			} else {
				continue // no devices: the stock ruleset 4
			}
			if err != nil {
				t.Fatal(err)
			}
			key := fmt.Sprint(linux, devs)
			if other, dup := seen[n]; dup {
				t.Fatalf("ruleset %d is both %s and %s", n, other, key)
			}
			seen[n] = key
			if n < DevfsRulesetBase || n >= BuildDevfsRuleset {
				t.Fatalf("ruleset %d (%s) is outside the private range", n, key)
			}
		}
	}
	if _, dup := seen[BuildDevfsRuleset]; dup {
		t.Fatal("the build jail's ruleset is shared")
	}
}

func TestAntispoofNeverNegatesAList(t *testing.T) {
	in := PFInput{Jail: "alpha_web", Interfaces: []string{"joe1a", "joe2a"}, Antispoof: true,
		Addresses: []netip.Addr{netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("fd00::10")},
		DefaultIn: "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{}}}}
	out, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "! {") || strings.Contains(out, "!{") {
		t.Errorf("a negated list is a pf syntax error:\n%s", out)
	}
	// The table is defined in the anchor that uses it and lets ND and DAD through.
	if !strings.Contains(out, "table <jail_addrs> persist { 10.20.0.10, fd00::10, fe80::/10 }") {
		t.Errorf("no allowed-source table:\n%s", out)
	}
	golden(t, "pf_antispoof_epair", out)
}

func TestEveryAnchorDefinesTheTablesItReferences(t *testing.T) {
	in := PFInput{Jail: "alpha_web", Interfaces: []string{"joe1a"}, Antispoof: true, Uplink: "em0",
		Addresses:  []netip.Addr{netip.MustParseAddr("10.20.0.10")},
		Tags:       []string{"app"},
		TagMembers: map[string][]netip.Addr{"db": {netip.MustParseAddr("10.20.0.20")}},
		Sets:       map[string]api.AddressSetSpec{"office": {Addresses: api.Entries("192.0.2.0/24")}},
		DefaultIn:  "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office", "tag:db"}, Ports: []string{"22"}}}}}}}
	out, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	def := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^table <([a-z0-9_]+)>`).FindAllStringSubmatch(out, -1) {
		def[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`<([a-z0-9_]+)>`).FindAllStringSubmatch(out, -1) {
		if !def[m[1]] {
			t.Errorf("table <%s> is used but not defined in the anchor:\n%s", m[1], out)
		}
	}
	if len(def) != 5 { // the jail's addresses, the host, what "any" does not reach, the set and the tag
		t.Errorf("tables %v", def)
	}
}

func TestProjectAnchorEndsWithAnchorWildcardAndAdminLines(t *testing.T) {
	rules := strings.Split(strings.TrimSpace(ProjectAnchorRules()), "\n")
	if rules[len(rules)-1] != `anchor "*"` {
		t.Fatalf("a project anchor must end with anchor \"*\": %v", rules)
	}
	if AnchorLines() != "anchor \"jailops/*\"\n" {
		t.Fatalf("%q", AnchorLines())
	}
}

func TestPFProjectsAreIsolatedUnlessARuleOpensIt(t *testing.T) {
	in := pfBase()
	in.Foreign = []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24"), netip.MustParsePrefix("fd30::/64")}
	in.DefaultIn, in.DefaultOut = "allow", "allow"
	in.Policies = []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
		{Name: "from-common", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"10.30.0.5"}, Ports: []string{"5432"}},
	}}}}
	s, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	iAllow := strings.Index(s, "from 10.30.0.5")
	iBlock := strings.Index(s, "block drop out quick on jo0123456789a0a from <foreign> to any")
	if iAllow < 0 || iBlock < 0 || iAllow > iBlock {
		t.Fatalf("the explicit allow must come before the isolation:\n%s", s)
	}
	for _, want := range []string{
		"table <foreign> persist { 10.30.0.0/24, fd30::/64 }",
		"block drop in quick on jo0123456789a0a from any to <foreign>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	golden(t, "pf_anchor_foreign", s)
}

// Every rendered PF golden must be accepted by the real pfctl. It runs where pfctl exists (FreeBSD); elsewhere it is
// skipped, and scripts/ci-freebsd-pf.sh runs the same check in CI. (This is how misplaced icmp6-type and tagged
// keywords were found: the renderer's own tests cannot know the grammar of pf.)
func TestPFGoldensParseWithPfctl(t *testing.T) {
	pfctl, err := exec.LookPath("pfctl")
	if err != nil {
		t.Skip("pfctl is not installed")
	}
	files, _ := filepath.Glob("testdata/pf_*.golden")
	if len(files) == 0 {
		t.Fatal("no goldens")
	}
	for _, f := range files {
		out, err := exec.Command(pfctl, "-n", "-a", "jailops/x/y", "-f", f).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "Permission denied") {
			t.Errorf("%s: %v\n%s", f, err, out)
		}
	}
}

func TestPassRuleLabelsAreStableAndSayWhenARuleChanged(t *testing.T) {
	render := func(mut func(*PFInput)) string {
		in := pfBase()
		if mut != nil {
			mut(&in)
		}
		s, err := PFAnchor(in)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	labels := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range regexp.MustCompile(`label "(jo-[0-9a-f]{12})"`).FindAllStringSubmatch(s, -1) {
			m[l[1]] = true
		}
		return m
	}
	a := render(nil)
	if la := labels(a); len(la) == 0 {
		t.Fatal("no labels")
	} else if lb := labels(render(nil)); len(lb) != len(la) {
		t.Fatal("rendering is not deterministic")
	}
	// the same rule in another jail's anchor has another label, so killing one jail's flows never touches another's
	b := render(func(in *PFInput) { in.Jail = "alpha_db" })
	for l := range labels(a) {
		if labels(b)[l] {
			t.Fatalf("label %s is shared by two jails", l)
		}
	}
	// a member removed from an address set changes the label of the rule that names the set, so its flows end
	c := render(func(in *PFInput) {
		in.Sets = map[string]api.AddressSetSpec{"office": {Addresses: api.Entries("203.0.113.0/24")}, "vpn": {Addresses: api.Entries("198.51.100.7")}}
	})
	if len(labels(a)) == len(labels(c)) {
		same := true
		for l := range labels(a) {
			same = same && labels(c)[l]
		}
		if same {
			t.Fatal("changing a set did not change any label")
		}
	}
	// rules without a state have no label
	for _, ln := range strings.Split(a, "\n") {
		if strings.Contains(ln, "no state") && strings.Contains(ln, "label") {
			t.Fatalf("a stateless rule has a label: %s", ln)
		}
	}
}

// A deny put in front of an unchanged pass rule changes what the pass rule lets through, so its label changes and the
// states of the flows it admitted end; a rule added below it leaves it alone.
func TestALabelChangesWhenARuleIsInsertedAbove(t *testing.T) {
	base := "pass out quick on jo0a inet proto tcp port 443\n" +
		"pass in quick on jo0a all\n"
	deny := "block drop out quick on jo0a inet from any to 10.0.0.0/8\n"
	label := func(text, rule string) string {
		for _, ln := range strings.Split(labelPassRules("jailops/alpha/web", text, 0), "\n") {
			if strings.HasPrefix(ln, rule) {
				if i := strings.Index(ln, `label "`); i >= 0 {
					return ln[i:]
				}
			}
		}
		t.Fatalf("no labelled %q in %q", rule, text)
		return ""
	}
	first, second := "pass out quick on jo0a inet proto tcp port 443", "pass in quick on jo0a all"
	if label(base, second) != label(base, second) {
		t.Fatal("a label is not stable")
	}
	withDeny := first + "\n" + deny + second + "\n"
	if label(base, first) != label(withDeny, first) {
		t.Error("a rule that has nothing new above it changed its label")
	}
	if label(base, second) == label(withDeny, second) {
		t.Error("a deny inserted above a pass rule did not change its label: its established flows would go on")
	}
	// the members of a table used by a rule above count too
	tbl := func(members string) string {
		return "table <bad> persist { " + members + " }\n" + "block drop out quick on jo0a from any to <bad>\n" + second + "\n"
	}
	if label(tbl("10.0.0.0/8"), second) == label(tbl("10.0.0.0/8, 192.168.0.0/16"), second) {
		t.Error("an address added to a table used by a deny above did not change the label")
	}
	// a rule added below changes nothing above it
	extra := base + "pass out quick on jo0a inet proto udp port 53\n"
	if label(base, second) != label(extra, second) || label(base, first) != label(extra, first) {
		t.Error("a rule added at the end changed the labels above it")
	}
}

func TestPFNeighbourDiscoveryAndICMPv6(t *testing.T) {
	in := PFInput{Jail: "alpha_web", Interfaces: []string{"joe1a"}, Antispoof: true,
		Addresses: []netip.Addr{ip("10.20.0.10"), ip("2001:db8:1::100")},
		LinkLocal: []netip.Addr{ip("fe80::2858:8aff:fe88:fcd2"), ip("10.1.1.1")}, // a non link-local entry is ignored
		DefaultIn: "deny", DefaultOut: "deny", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{}}}}
	out, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_nd_icmp6", out)
	for _, want := range []string{
		"table <jail_addrs> persist { 10.20.0.10, 2001:db8:1::100, fe80::2858:8aff:fe88:fcd2 }",
		// a jail is not a router
		"block in quick on joe1a inet6 proto icmp6 from any to any icmp6-type { routeradv, redir }",
		// :: only for DAD, only to a solicited-node group
		"pass in quick on joe1a inet6 proto icmp6 from :: to ff02::1:ff00:0/104 icmp6-type neighbrsol",
		// no advertisement to a multicast group
		"block in quick on joe1a inet6 proto icmp6 from any to ff02::/16 icmp6-type neighbradv",
		// the jail's own addresses are the only sources
		"from { 2001:db8:1::100, fe80::2858:8aff:fe88:fcd2 } to any icmp6-type { neighbrsol, neighbradv }",
		// only its own addresses and groups reach the jail
		"to { 2001:db8:1::100, fe80::2858:8aff:fe88:fcd2, ff02::1:ff00:100, ff02::1:ff88:fcd2 } icmp6-type { neighbrsol, neighbradv }",
		// path MTU discovery: ICMPv6 errors pass both ways, also under a default deny
		"pass in quick on joe1a inet6 proto icmp6 from { 2001:db8:1::100, fe80::2858:8aff:fe88:fcd2 } to any icmp6-type { unreach, toobig, timex, paramprob }",
		"pass out quick on joe1a inet6 proto icmp6 from any to any icmp6-type { unreach, toobig, timex, paramprob }",
		"to ff02::/16 icmp6-type { listenrep, listendone, 143 }",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fe80::/10") {
		t.Errorf("the jail's own link-local address is known, fe80::/10 must not appear:\n%s", out)
	}
	// every ICMPv6 pass comes before the default deny
	if i, j := strings.Index(out, "toobig"), strings.Index(out, "block drop out quick on joe1a all"); i < 0 || j < i {
		t.Errorf("ICMPv6 errors must precede the defaults")
	}
	// unknown link-local address: the whole range stays allowed
	in.LinkLocal = nil
	out, _ = PFAnchor(in)
	if !strings.Contains(out, "fe80::/10") || !strings.Contains(out, "ff02::1:ff00:0/104") {
		t.Errorf("fallback without link-local addresses:\n%s", out)
	}
	// an IPv4-only jail has no IPv6 rules
	in.Addresses = []netip.Addr{ip("10.20.0.10")}
	if out, _ = PFAnchor(in); strings.Contains(out, "icmp6") {
		t.Errorf("IPv4-only jail has IPv6 rules:\n%s", out)
	}
}

// The host asks the jail for its address with a solicitation and the jail answers with an advertisement from one of its
// own addresses; an advertisement never goes to a multicast group.
func TestPFNeighbourDiscoveryOnTheJailsLink(t *testing.T) {
	in := PFInput{Jail: "alpha_web", Interfaces: []string{"joe1a"}, Antispoof: true,
		Addresses: []netip.Addr{ip("2001:db8:1::100")}, LinkLocal: []netip.Addr{ip("fe80::2858:8aff:fe88:fcd2")},
		DefaultIn: "allow", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{}}}}
	out, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_nd_link", out)
	if !strings.Contains(out, "from { 2001:db8:1::100, fe80::2858:8aff:fe88:fcd2 } to any icmp6-type { neighbrsol, neighbradv }") {
		t.Errorf("the jail cannot answer the host's solicitation:\n%s", out)
	}
	if !strings.Contains(out, "block in quick on joe1a inet6 proto icmp6 from any to ff02::/16 icmp6-type neighbradv") {
		t.Errorf("an advertisement to a multicast group is not blocked:\n%s", out)
	}
	// the DAD solicitation from :: still passes
	if !strings.Contains(out, "from :: to ff02::1:ff00:0/104 icmp6-type neighbrsol") {
		t.Errorf("DAD is blocked:\n%s", out)
	}
}

// The comments of an address set's entries are lines of the rendered anchor, so that a review of the loaded rules says
// what a table holds.
func TestAnchorCarriesTheCommentsOfASet(t *testing.T) {
	in := PFInput{Jail: "alpha_db", Interfaces: []string{"jo0123456789a0a"}, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Uplink: "jo0",
		DefaultIn: "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:git-allow"}, Ports: []string{"22"}}}}}},
		Sets: map[string]api.AddressSetSpec{"git-allow": {Addresses: []api.AddressEntry{
			{Address: "192.0.2.7", Comment: "the office"}, {Address: "198.51.100.9", Comment: "the branch"}}}}, TagMembers: map[string][]netip.Addr{}}
	rs, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# set git-allow: 192.0.2.7 the office\n", "# set git-allow: 198.51.100.9 the branch\n", "table <s_git_allow> persist { 192.0.2.7, 198.51.100.9 }"} {
		if !strings.Contains(rs, want) {
			t.Errorf("%q not in the anchor:\n%s", want, rs)
		}
	}
}

// Rules, policies and sets say what they are for in comment lines of the anchor, for a review of the loaded rules.
func TestAnchorCarriesTheCommentsOfRulesAndPolicies(t *testing.T) {
	in := PFInput{Jail: "alpha_db", Interfaces: []string{"jo0123456789a0a"}, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Uplink: "jo0",
		DefaultIn: "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Comment: "the database of the shop", Rules: []api.FirewallRule{
			{Name: "app", Comment: "the web jail asks for rows", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office"}, Ports: []string{"5432"}}}}}},
		Sets: map[string]api.AddressSetSpec{"office": {Comment: "who works from the office", Addresses: []api.AddressEntry{{Address: "192.0.2.7"}}}}, TagMembers: map[string][]netip.Addr{}}
	rs, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# policy web\n#   the database of the shop\n", "# rule 1: app\n#   the web jail asks for rows\n", "# set office: who works from the office\n"} {
		if !strings.Contains(rs, want) {
			t.Errorf("%q not in the anchor:\n%s", want, rs)
		}
	}
}

// A comment that was not checked cannot leave its comment line: no backslash (it would continue the comment onto the next line,
// and the rule after it would be gone), no line break, no quote, no hidden character.
func TestAnchorCommentsCannotLeaveTheirLine(t *testing.T) {
	evil := "x\\\nblock drop in all\r\n\"y\u202e\u2028z"
	in := PFInput{Jail: "alpha_db", Interfaces: []string{"jo0123456789a0a"}, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Uplink: "jo0",
		DefaultIn: "deny", DefaultOut: "allow", Policies: []PFPolicy{{Name: "web", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office"}, Ports: []string{"22"}}}}}},
		Sets: map[string]api.AddressSetSpec{"office": {Comment: evil, Addresses: []api.AddressEntry{{Address: "192.0.2.7", Comment: evil}}}}, TagMembers: map[string][]netip.Addr{}}
	// the policy and its rules are checked by the render itself
	bad := in
	bad.Policies = []PFPolicy{in.Policies[0]}
	bad.Policies[0].Policy.Comment = evil
	if _, err := PFAnchor(bad); err == nil {
		t.Error("a policy comment with a backslash and a line break was rendered")
	}
	bad = in
	bad.Policies = []PFPolicy{in.Policies[0]}
	bad.Policies[0].Policy.Rules = []api.FirewallRule{{Comment: evil, Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"22"}}}
	if _, err := PFAnchor(bad); err == nil {
		t.Error("a rule comment with a backslash and a line break was rendered")
	}
	// the sets are checked where they are stored, and made safe here as well
	rs, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range strings.Split(rs, "\n") {
		if strings.Contains(ln, "block drop in all") && !strings.HasPrefix(strings.TrimSpace(ln), "#") {
			t.Errorf("a comment became a rule: %q", ln)
		}
		if strings.HasPrefix(strings.TrimSpace(ln), "#") && (strings.HasSuffix(ln, `\`) || strings.ContainsAny(ln, "\r\"\u202e\u2028")) {
			t.Errorf("an unsafe character is in a comment line: %q", ln)
		}
	}
	if !strings.Contains(rs, "pass in quick on") {
		t.Errorf("the rule after the comment is gone:\n%s", rs)
	}
}

// Every deny rule of the policies stands before every allow rule; the headings and the numbers are the policies'.
func TestPFDenyRulesComeBeforeAllowRules(t *testing.T) {
	in := pfBase()
	in.Policies = []PFPolicy{
		{Name: "a", Policy: api.FirewallPolicySpec{Comment: "first", Rules: []api.FirewallRule{
			{Name: "ssh", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"22"}},
			{Name: "pg", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"5432"}},
		}}},
		{Name: "b", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
			{Name: "no ssh", Action: "deny", Direction: "in", Proto: "tcp", Ports: []string{"22"}},
		}}},
	}
	s, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	order := []string{"# deny rules of all policies", "# policy b", "# rule 1: no ssh", "block drop out quick", "# allow rules of the policies",
		"# policy a", "#   first", "# rule 1: ssh", "# rule 2: pg", "# defaults"}
	at := 0
	for _, w := range order {
		i := strings.Index(s[at:], w)
		if i < 0 {
			t.Fatalf("%q is not after position %d:\n%s", w, at, s)
		}
		at += i + len(w)
	}
	if strings.Count(s, "# policy a") != 1 || strings.Count(s, "#   first") != 1 {
		t.Errorf("the policy that has no deny rule appears more than once, or its comment does:\n%s", s)
	}
	// the structured rules are in the same order: the deny rule is walked first
	a, err := BuildAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	var first *Rule
	for i := range a.Rules {
		if a.Rules[i].Origin.Stage == StagePolicy {
			first = &a.Rules[i]
			break
		}
	}
	if first == nil || first.Action != "block" || first.Origin.Policy != "b" {
		t.Errorf("the first policy rule walked: %+v", first)
	}
}

// A disabled rule is a comment line with its number, not a rule, and it does not group the anchor.
func TestPFDisabledRuleIsAComment(t *testing.T) {
	in := pfBase()
	in.Policies = []PFPolicy{{Name: "p", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
		{Name: "ssh", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"22"}, Disabled: true, Comment: "switched off"},
		{Name: "no telnet", Action: "deny", Direction: "in", Proto: "tcp", Ports: []string{"23"}, Disabled: true},
		{Name: "forward", Action: "allow", Direction: "in", Proto: "tcp", Disabled: true, Redirect: &api.Redirect{HostPort: 8080, JailPort: 80}},
		{Name: "web", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"80"}},
	}}}}
	s, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"# rule 1 (disabled): ssh", "#   switched off", "# rule 2 (disabled): no telnet", "# rule 3 (disabled): forward", "# rule 4: web"} {
		if !strings.Contains(s, w) {
			t.Errorf("%q is missing:\n%s", w, s)
		}
	}
	for _, w := range []string{"port 22", "port 23", "port 8080", "rdr-to", "deny rules of all policies"} {
		if strings.Contains(s, w) {
			t.Errorf("%q is in the anchor of a policy whose only other rules are disabled:\n%s", w, s)
		}
	}
	if !strings.Contains(s, "port 80 label") && !strings.Contains(s, "port 80") {
		t.Errorf("the enabled rule is not rendered:\n%s", s)
	}
}

// The rendered text and the structured rules agree for a grouped anchor too.
func TestPFGroupedAnchorTextAndRulesAgree(t *testing.T) {
	a, err := BuildAnchor(pfBase())
	if err != nil {
		t.Fatal(err)
	}
	old, err := PFAnchor(pfBase())
	if err != nil || old != FormatAnchor(a) {
		t.Fatalf("the text differs: %v", err)
	}
	for _, r := range a.Rules {
		if r.Kind != RuleFilter {
			continue
		}
		l := a.Lines[r.Line]
		if !strings.HasPrefix(l, r.Action) {
			t.Errorf("rule line %d %q does not start with %s", r.Line, l, r.Action)
		}
	}
}

// jail:NAME is a table of its own (j_<name>, a hyphen read as an underscore) that holds the addresses of the jail, also
// as a member of a set; a jail that is not in Jails is an empty table and matches nobody; a set and a jail of one name
// are two tables.
func TestPFJailReferences(t *testing.T) {
	in := pfBase()
	in.Sets["web"] = api.AddressSetSpec{Addresses: api.Entries("192.0.2.9", "jail:web-2", "jail:ghost")}
	in.Jails = map[string][]string{"web": {"10.20.0.11", "2001:db8:1::11"}, "web-2": {"10.20.0.12"}}
	in.Policies[0].Policy.Rules = []api.FirewallRule{
		{Name: "from jail", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"jail:web", "jail:web-2"}, Ports: []string{"5432"}},
		{Name: "from set", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:web"}, Ports: []string{"5433"}},
		{Name: "from nobody", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"jail:ghost"}, Ports: []string{"5434"}},
	}
	an, err := BuildAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	s := FormatAnchor(an)
	for _, want := range []string{
		"table <j_web> persist { 10.20.0.11, 2001:db8:1::11 }\n",
		"table <j_web_2> persist { 10.20.0.12 }\n",
		"table <j_ghost> persist\n",
		"table <s_web> persist { 10.20.0.12, 192.0.2.9 }\n",
		"from { <j_web>, <j_web_2> } to 10.20.0.10 port 5432",
		"from <s_web> to 10.20.0.10 port 5433",
		"from <j_ghost> to 10.20.0.10 port 5434",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the anchor lacks %q:\n%s", want, s)
		}
	}
	// the structured rules say the same: the tables a rule names and the prefixes it holds
	for _, r := range an.Rules {
		if r.Origin.RuleName == "from jail" && r.Family == "inet" {
			if len(r.From.Tables) != 2 || r.From.Tables[0] != "j_web" || r.From.Tables[1] != "j_web_2" || len(r.From.Prefixes) != 3 {
				t.Errorf("the match of a jail rule: %+v", r.From)
			}
		}
		if r.Origin.RuleName == "from nobody" && r.Family == "inet" && (len(r.From.Tables) != 1 || len(r.From.Prefixes) != 0) {
			t.Errorf("a jail that does not exist has a table and no prefix: %+v", r.From)
		}
	}
	// a set that does not exist is an error
	in.Policies[0].Policy.Rules = []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:nope"}}}
	if _, err := BuildAnchor(in); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("a set that does not exist: %v", err)
	}
}

// Every pass rule binds its states to the interface (if-bound); a state limit adds "max N" to it, on every pass rule of
// the anchor, never on a block rule, and does not change the label of a rule: a label that changed would end the
// running flows of the rule.
func TestPFStateLimit(t *testing.T) {
	in := pfBase()
	plain, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range strings.Split(plain, "\n") {
		if strings.HasPrefix(ln, "pass ") && !strings.HasSuffix(ln, " keep state (if-bound)") {
			t.Fatalf("a pass rule whose states are not bound to its interface: %s", ln)
		}
		if strings.Contains(ln, "max ") && strings.Contains(ln, "keep state") {
			t.Fatalf("an anchor without a limit has a state limit: %s", ln)
		}
	}
	in.MaxStates = 5000
	limited, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	passes := 0
	for _, ln := range strings.Split(limited, "\n") {
		switch {
		case strings.HasPrefix(ln, "pass "):
			passes++
			if !strings.HasSuffix(ln, " keep state (max 5000, if-bound)") {
				t.Errorf("a pass rule without the limit: %s", ln)
			}
		case strings.HasPrefix(ln, "block "), strings.HasPrefix(ln, "#"):
			if strings.Contains(ln, "keep state") {
				t.Errorf("a limit on a line that makes no state: %s", ln)
			}
		}
	}
	if passes == 0 {
		t.Fatal("no pass rule in the anchor")
	}
	if got := strings.ReplaceAll(limited, "max 5000, ", ""); got != plain {
		t.Errorf("the limit changed more than the state option:\n--- without\n%s\n--- with, option removed\n%s", plain, got)
	}
}

// The host is an endpoint of a rule (host) and is closed to the jail after the rules of its policies, ping and the
// resolver the network points at excepted: a jail reaches no service of the machine it runs on unless a rule says so.
func TestPFHostEndpointAndClosedHost(t *testing.T) {
	in := pfBase()
	in.Host = []netip.Addr{ip("10.20.0.1"), ip("fe80::1"), ip("192.0.2.5")}
	in.DNS = []netip.Addr{ip("10.20.0.1")}
	in.Policies = []PFPolicy{{Name: "p", Policy: api.FirewallPolicySpec{Rules: []api.FirewallRule{
		{Name: "ntp", Action: "allow", Direction: "out", Proto: "udp", To: []string{"host"}, Ports: []string{"123"}},
		{Name: "from host", Action: "allow", Direction: "in", Proto: "tcp", From: []string{"host"}, Ports: []string{"22"}},
	}}}}
	s, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_anchor_host", s)
	for _, want := range []string{
		"table <host> persist { 10.20.0.1, 192.0.2.5, fe80::1 }",
		"proto udp from 10.20.0.10 to <host> port 123",
		"proto tcp from <host> to 10.20.0.10 port 22",
		"pass in quick on jo0123456789a0a inet proto icmp from any to <host>",
		"pass in quick on jo0123456789a0a inet6 proto icmp6 from any to <host>",
		"pass in quick on jo0123456789a0a inet proto tcp from any to 10.20.0.1 port 53",
		"pass in quick on jo0123456789a0a inet proto udp from any to 10.20.0.1 port 53",
		"block drop in quick on jo0123456789a0a from any to <host>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	// the rule of the policy comes before the closing of the host, which comes before the defaults
	i, j, k := strings.Index(s, "to <host> port 123"), strings.Index(s, "block drop in quick on jo0123456789a0a from any to <host>"), strings.Index(s, "# defaults")
	if !(i >= 0 && i < j && j < k) {
		t.Errorf("order of the policy rule, the closed host and the defaults: %d %d %d\n%s", i, j, k, s)
	}
	// the simulator's rules: the host is a block unless a rule opened it
	a, _ := BuildAnchor(in)
	found := false
	for _, r := range a.Rules {
		if r.Origin.Stage == StageHost && r.Action == "block" && r.To.Contains(ip("192.0.2.5")) && !r.To.Contains(ip("10.30.0.1")) {
			found = true
		}
	}
	if !found {
		t.Error("the structured rules lack the closing of the host")
	}
}

// A jail with a link and no address (a network entry of "none") has an anchor that closes both directions: with no
// anchor it would be open to the rules of the host alone, and could send in the name of another jail.
func TestPFNoAddressClosesTheLinks(t *testing.T) {
	in := pfBase()
	in.Addresses = nil
	in.Policies = nil
	a, err := BuildAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	text := a.Text()
	for _, want := range []string{"block drop in quick on " + in.Interfaces[0] + " all", "block drop out quick on " + in.Interfaces[0] + " all"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "pass") {
		t.Errorf("a closed anchor passes something:\n%s", text)
	}
	if len(a.Rules) != 2 || a.Rules[0].Origin.Stage != StageClosed || a.Rules[0].Action != "block" {
		t.Errorf("rules %+v", a.Rules)
	}
}

// The rules of an administrator's raw fragment stay as written even after a comment of the administrator's own: a
// rule that already says keep state must not get a second one (pf refuses to load such a rule, and the whole anchor
// with it).
func TestRawFragmentIsUntouchedAfterItsOwnComments(t *testing.T) {
	in := pfBase()
	in.Policies[0].Policy.Raw = "# my rules\npass in quick on lo0 proto tcp to port 25 keep state\n# more\npass out quick on lo0 all\n"
	in.AllowRaw = true
	s, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pass in quick on lo0 proto tcp to port 25 keep state\n", "pass out quick on lo0 all\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("a raw rule was changed: want %q in\n%s", want, s)
		}
	}
	if strings.Count(s, "keep state") > 0 && strings.Contains(s, "keep state label") {
		t.Errorf("a label was put behind keep state:\n%s", s)
	}
	// the rules JailOps wrote after the fragment are labelled again
	after := s[strings.Index(s, "# end of raw fragment (admin)"):]
	if !strings.Contains(after, "keep state (if-bound)") {
		t.Errorf("the rules after the fragment are not labelled:\n%s", after)
	}
}
