package api

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestHostFirewallValidateAndCanonical(t *testing.T) {
	ok := []HostFirewallSpec{
		{},
		{Template: HostFirewallOpen},
		{NAT: "none"},
		{SSH: &HostFirewallSSH{Ports: []int{2222}, AllowFrom: []string{"192.0.2.7", "2001:DB8::/32", "0.0.0.0/0"}}},
		{Template: HostFirewallCustom, Sets: []HostFirewallSet{{Name: "ops-1", Members: []string{"198.51.100.0/24"}}},
			Allow: []HostFirewallAllow{{Proto: "udp", Ports: []string{"53", "60000-61000"}, From: []string{"@ops-1"}, Comment: "dns and mosh, ok: €"}}},
	}
	for i, s := range ok {
		if err := s.Validate(); err != nil {
			t.Errorf("%d: %v", i, err)
		}
	}
	for name, s := range map[string]HostFirewallSpec{
		"comment newline": {Template: HostFirewallCustom, Allow: []HostFirewallAllow{{Proto: "tcp", Ports: []string{"1"}, Comment: "a\nb"}}},
		"host bits":       {SSH: &HostFirewallSSH{AllowFrom: []string{"2001:db8::1/64"}}},
		"unspecified":     {SSH: &HostFirewallSSH{AllowFrom: []string{"::"}}},
		"undefined set":   {Console: &HostFirewallConsole{AllowFrom: []string{"@x"}}},
		"range":           {Template: HostFirewallCustom, Allow: []HostFirewallAllow{{Proto: "tcp", Ports: []string{"2-1"}}}},
	} {
		if err := s.Validate(); !IsCode(err, CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c := HostFirewallSpec{SSH: &HostFirewallSSH{AllowFrom: []string{"2001:DB8:0::7", "192.0.2.0/24"}}}.Canonical()
	if c.Template != HostFirewallDefault || c.NAT != "none" || !slices.Equal(c.SSH.Ports, []int{22}) || !slices.Equal(c.SSH.AllowFrom, []string{"2001:db8::7", "192.0.2.0/24"}) || c.Console == nil {
		t.Errorf("%+v %+v", c, c.SSH)
	}
	for in, want := range map[int]int{0: 120, 10: 10, 1800: 1800} {
		if got, err := ConfirmWindow(in); err != nil || got != want {
			t.Errorf("%d: %d %v", in, got, err)
		}
	}
	for _, id := range []string{"", "0123456789abcdef"} {
		if ValidHostPendingID(id) != nil {
			t.Errorf("%q", id)
		}
	}
}

func TestHostFirewallAdmitsAndWarnings(t *testing.T) {
	s := HostFirewallSpec{Template: HostFirewallCustom,
		SSH:     &HostFirewallSSH{Ports: []int{22}, AllowFrom: []string{"@admins"}},
		Console: &HostFirewallConsole{Port: 39110, AllowFrom: []string{"2001:db8:c::/48"}},
		Sets:    []HostFirewallSet{{Name: "admins", Members: []string{"192.0.2.0/24"}}},
		Allow:   []HostFirewallAllow{{Proto: "tcp", Ports: []string{"8000-8100"}, From: []string{"203.0.113.0/24"}}},
	}.Canonical()
	a := netip.MustParseAddr
	for _, c := range []struct {
		addr string
		port int
		want bool
	}{
		{"192.0.2.9", 22, true}, {"192.0.2.9", 39110, false}, {"2001:db8:c::1", 39110, true}, {"2001:db8:c::1", 22, false},
		{"203.0.113.1", 8050, true}, {"203.0.113.1", 8101, false}, {"198.51.100.1", 22, false}, {"::ffff:192.0.2.9", 22, true},
	} {
		if got := s.Admits(a(c.addr), c.port); got != c.want {
			t.Errorf("%s:%d = %v", c.addr, c.port, got)
		}
	}
	if !s.AdmitsAdmin(a("2001:db8:c::1")) || s.AdmitsAdmin(a("203.0.113.1")) {
		t.Error("AdmitsAdmin")
	}
	if s.SSHOpenToWorld() || len(s.Warnings()) != 0 {
		t.Errorf("%v", s.Warnings())
	}
	for _, open := range []HostFirewallSpec{
		{},
		{SSH: &HostFirewallSSH{AllowFrom: []string{"::/0"}}},
		{SSH: &HostFirewallSSH{AllowFrom: []string{"@all"}}, Sets: []HostFirewallSet{{Name: "all", Members: []string{"0.0.0.0/0"}}}},
		{Template: HostFirewallOpen},
	} {
		if c := open.Canonical(); !c.SSHOpenToWorld() || !strings.Contains(strings.Join(c.Warnings(), " "), "ssh is open to the world") {
			t.Errorf("%+v", open)
		}
	}
	rules := s.Rules()
	var fixed, ssh int
	for _, r := range rules {
		if r.Fixed {
			fixed++
		}
		if r.Comment == "ssh" && r.From == "@admins" && r.Ports == "22" {
			ssh++
		}
	}
	if fixed < 5 || ssh != 1 || rules[len(rules)-1].Ports != "8000-8100" {
		t.Errorf("%+v", rules)
	}
}
