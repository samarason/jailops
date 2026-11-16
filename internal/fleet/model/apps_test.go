package model

import (
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// A declared source compares with a live grant in the form the host stores it.
func TestCanonicalSource(t *testing.T) {
	for in, want := range map[string]string{
		"host": "host", "jail:web": "jail:web", "set:office-net": "set:office-net",
		"192.0.2.7": "192.0.2.7", "192.0.2.7/32": "192.0.2.7", "192.0.2.9/24": "192.0.2.0/24",
		"2001:db8::1": "2001:db8::1", "2001:db8::1/64": "2001:db8::/64",
	} {
		got, err := CanonicalSource(in)
		if err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "any", "@", "@web", "jail:Web", "jail:a/", "jail:shop/web", "set:a_b", "tag:web", "web", "192.0.2.300", "fe80::1%em0", "::ffff:192.0.2.1"} {
		if _, err := CanonicalSource(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalizePorts(t *testing.T) {
	got, err := NormalizePorts([]string{"80", "443/tcp", "53/udp", "80/tcp"})
	if err != nil || !slices.Equal(got, []string{"443/tcp", "53/udp", "80/tcp"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"0", "65536", "80/sctp", "x", "-1/tcp"} {
		if _, err := NormalizePorts([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAppSpecsDecodeStrictly(t *testing.T) {
	if _, err := DecodeSpec(KindApp, map[string]any{"app": "postgresql", "network": "lan", "limits": map[string]any{"memory": "2G"}}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []map[string]any{{"app": "Postgres"}, {"app": "postgresql", "rotate": true}, {}} {
		if _, err := DecodeSpec(KindApp, raw); err == nil {
			t.Errorf("%v accepted", raw)
		}
	}
	s, err := DecodeSpec(api.KindAppAccess, map[string]any{"grants": []any{map[string]any{"source": "jail:web", "database": "shop"}}})
	if err != nil || len(s.(AppAccessSpec).Grants) != 1 {
		t.Fatalf("%v %v", s, err)
	}
	// a password is never part of a declaration
	if _, err := DecodeSpec(api.KindAppAccess, map[string]any{"grants": []any{map[string]any{"source": "jail:web", "password": "x"}}}); err == nil {
		t.Fatal("a password key was accepted")
	}
}

func TestAppAccessSpecValidate(t *testing.T) {
	ok := AppAccessSpec{Grants: []AppGrant{{Source: "jail:web", Database: "shop"}, {Source: "192.0.2.0/24", Ports: []string{"5432"}}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for want, s := range map[string]AppAccessSpec{
		"listed twice":            {Grants: []AppGrant{{Source: "jail:web"}, {Source: "jail:web"}}},
		"must match":              {Grants: []AppGrant{{Source: "jail:web", Database: "Shop;drop"}}},
		"reserves":                {Grants: []AppGrant{{Source: "jail:web", Database: "postgres"}}},
		"N or N/tcp":              {Grants: []AppGrant{{Source: "jail:web", Ports: []string{"http"}}}},
		"not an address":          {Grants: []AppGrant{{Source: "web"}}},
		"name a jail (jail:web),": {Grants: []AppGrant{{Source: ""}}},
	} {
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", s, err, want)
		}
	}
}

// The app kinds come after every stored kind: an app needs its project, network, storage and image.
func TestAppKindsOrderLast(t *testing.T) {
	last := Order(api.KindJail)
	if Order(KindApp) <= last || Order(api.KindAppAccess) <= Order(KindApp) {
		t.Fatalf("orders %d %d %d", last, Order(KindApp), Order(api.KindAppAccess))
	}
	if ki, ok := KindOf(api.KindAppAccess); !ok || !ki.ProjectLevel || ki.Dir != "app-access" {
		t.Fatalf("%+v %v", ki, ok)
	}
}
