package api

import (
	"strings"
	"testing"
)

func TestACMESpecValidate(t *testing.T) {
	ok := ACMESpec{Enabled: true, Domains: []string{"Console.Example.com"}, AcceptTOS: true}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	c := ok.Canonical()
	if c.DirectoryURL != ACMEDirectoryProduction || c.Challenge != ACMEHTTP01 || c.Domains[0] != "console.example.com" {
		t.Errorf("%+v", c)
	}
	if err := (ACMESpec{}).Validate(); err != nil {
		t.Errorf("a disabled, empty setting: %v", err)
	}
	for name, c := range map[string]struct {
		spec ACMESpec
		code Code
		want string
	}{
		"terms":          {ACMESpec{Enabled: true, Domains: []string{"a.example.com"}}, CodeInvalid, "accept_tos"},
		"no domain":      {ACMESpec{Enabled: true, AcceptTOS: true}, CodeInvalid, "at least one domain"},
		"wildcard":       {ACMESpec{Domains: []string{"*.example.com"}}, CodeUnsupported, "dns-01"},
		"inner wildcard": {ACMESpec{Domains: []string{"a.*.example.com"}}, CodeInvalid, "not a DNS name"},
		"ipv4":           {ACMESpec{Domains: []string{"192.0.2.1"}}, CodeInvalid, "is an address"},
		"ipv6":           {ACMESpec{Domains: []string{"2001:db8::1"}}, CodeInvalid, "is an address"},
		"one label":      {ACMESpec{Domains: []string{"console"}}, CodeInvalid, "fully qualified"},
		"trailing dot":   {ACMESpec{Domains: []string{"console.example.com."}}, CodeInvalid, "not a DNS name"},
		"underscore":     {ACMESpec{Domains: []string{"a_b.example.com"}}, CodeInvalid, "not a DNS name"},
		"space":          {ACMESpec{Domains: []string{"a b.example.com"}}, CodeInvalid, "not a DNS name"},
		"long label":     {ACMESpec{Domains: []string{strings.Repeat("a", 64) + ".example.com"}}, CodeInvalid, "not a DNS name"},
		"twice":          {ACMESpec{Domains: []string{"a.example.com", "A.EXAMPLE.COM"}}, CodeInvalid, "twice"},
		"email name":     {ACMESpec{Email: "Admin <admin@example.com>"}, CodeInvalid, "not an email"},
		"email bare":     {ACMESpec{Email: "admin"}, CodeInvalid, "not an email"},
		"email no dot":   {ACMESpec{Email: "admin@localhost"}, CodeInvalid, "with a domain"},
		"email newline":  {ACMESpec{Email: "admin@example.com\nX: y"}, CodeInvalid, "not an email"},
		"http directory": {ACMESpec{DirectoryURL: "http://ca.example.com/dir"}, CodeInvalid, "https"},
		"user in url":    {ACMESpec{DirectoryURL: "https://u:p@ca.example.com/dir"}, CodeInvalid, "https"},
		"dns-01":         {ACMESpec{Challenge: "dns-01"}, CodeInvalid, "not http-01 or tls-alpn-01"},
	} {
		err := c.spec.Validate()
		if !IsCode(err, c.code) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := (ACMESpec{Email: "admin@example.com", DirectoryURL: ACMEDirectoryStaging, Challenge: ACMETLSALPN01}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestACMERedirectLines(t *testing.T) {
	l := ACMERedirectLines(ACMEHTTP01, 39080)
	if len(l) != 2 || l[0] != "pass in quick inet proto tcp from any to (self) port 80 rdr-to 127.0.0.1 port 39080" || l[1] != "pass in quick inet6 proto tcp from any to (self) port 80 rdr-to ::1 port 39080" {
		t.Errorf("%q", l)
	}
	if l := ACMERedirectLines(ACMETLSALPN01, 39110); !strings.Contains(l[0], "port 443 rdr-to 127.0.0.1 port 39110") {
		t.Errorf("%q", l)
	}
}

// The redirect in the firewall spec: two checked values, and a rule in the plain-words list.
func TestHostFirewallACME(t *testing.T) {
	s := DefaultHostFirewall(39110)
	s.ACME = &HostFirewallACME{Challenge: ACMEHTTP01, Port: 39080}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	c := s.Canonical()
	if c.ACME == s.ACME || *c.ACME != *s.ACME {
		t.Error("not copied")
	}
	found := false
	for _, r := range c.Rules() {
		found = found || (r.Ports == "80" && strings.Contains(r.Comment, "port 39080"))
	}
	if !found {
		t.Errorf("%+v", c.Rules())
	}
	s.ACME = &HostFirewallACME{Challenge: ACMETLSALPN01, Port: 39110}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if w := s.Canonical().Warnings(); !strings.Contains(strings.Join(w, ";"), "port 443 leads to the console from any address") {
		t.Errorf("%q", w)
	}
}
