package plan

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/fleet/secrets"
	"jailops.net/jailops/sdk/api"
)

func diff(t *testing.T, want, have any) []string {
	t.Helper()
	d, err := diffSpec(want, have)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestServerDefaultsAreNotDrift(t *testing.T) {
	want := api.JailSpec{Image: "i@stable", Network: []api.NetworkAttach{{Network: "n", IPv4: "auto"}}}
	have := api.JailSpec{Image: "i@stable", Layout: api.LayoutThin, Hostname: "x", OS: api.OSFreeBSD,
		Network: []api.NetworkAttach{{Network: "n", IPv4: "10.0.0.5", MAC: "02:00:00:00:00:01"}}}
	if d := diff(t, want, have); len(d) != 0 {
		t.Fatalf("defaults reported as drift: %v", d)
	}
}

func TestDeclaredFieldsAreCompared(t *testing.T) {
	want := api.JailSpec{Image: "i@stable", Resources: api.Resources{Memory: "2G", CPU: 2},
		Network: []api.NetworkAttach{{Network: "n", IPv4: "10.0.0.7"}}}
	have := api.JailSpec{Image: "i@stable", Resources: api.Resources{Memory: "1G", CPU: 2},
		Network: []api.NetworkAttach{{Network: "n", IPv4: "10.0.0.5"}}}
	d := strings.Join(diff(t, want, have), "\n")
	for _, w := range []string{`spec.resources.memory: live "1G", want "2G"`, `spec.network[0].ipv4: live "10.0.0.5", want "10.0.0.7"`} {
		if !strings.Contains(d, w) {
			t.Fatalf("missing %q in\n%s", w, d)
		}
	}
	if strings.Contains(d, "cpu") {
		t.Fatalf("an equal field was reported: %s", d)
	}
}

func TestListLengthAndMissingFields(t *testing.T) {
	want := api.AddressSetSpec{Addresses: api.Entries("a", "b")}
	have := api.AddressSetSpec{Addresses: api.Entries("a")}
	if d := diff(t, want, have); len(d) != 1 || !strings.Contains(d[0], "spec.addresses") {
		t.Fatalf("%v", d)
	}
	n := api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.0.0.0/24"}}
	if d := diff(t, n, api.NetworkSpec{}); len(d) == 0 {
		t.Fatal("a missing live ipv4 block was not reported")
	}
}

func TestSealedValuesAreComparedByHashOnly(t *testing.T) {
	want := api.JailSpec{Image: "i", Env: map[string]string{"P": secrets.SealedPrefix + "AAAA", "M": "x"}}
	have := api.JailSpec{Image: "i", Env: map[string]string{"M": "x"}} // server does not echo secrets
	if d := diff(t, want, have); len(d) != 0 {
		t.Fatalf("a sealed value the server does not echo was reported: %v", d)
	}
}

func TestSpecHashIsStableAndSensitive(t *testing.T) {
	a := api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", Range: "10.0.0.2-10.0.0.9"}}
	h1, l1, _ := SpecHash(a, map[string]string{"k": "v"})
	h2, _, _ := SpecHash(a, map[string]string{"k": "v"})
	if h1 != h2 || l1[HashLabel] != h1 || l1["k"] != "v" {
		t.Fatal("hash is not stable")
	}
	a.MTU = 1400
	if h3, _, _ := SpecHash(a, map[string]string{"k": "v"}); h3 == h1 {
		t.Fatal("hash ignores the spec")
	}
	if h4, _, _ := SpecHash(a, nil); h4 == h1 {
		t.Fatal("hash ignores labels")
	}
}

func TestDangers(t *testing.T) {
	cases := []struct {
		name       string
		kind       api.Kind
		live, want any
		danger     bool
	}{
		{"policy emptied", api.KindFirewallPolicy, api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{{Action: "allow"}}}, api.FirewallPolicySpec{}, true},
		{"policy opened", api.KindFirewallPolicy, api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}, api.FirewallPolicySpec{DefaultIn: "allow"}, true},
		{"policy edited", api.KindFirewallPolicy, api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{{Action: "allow"}}}, api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{{Action: "deny"}}}, false},
		{"set emptied", api.KindAddressSet, api.AddressSetSpec{Addresses: api.Entries("1.1.1.1")}, api.AddressSetSpec{}, true},
		{"set grown", api.KindAddressSet, api.AddressSetSpec{}, api.AddressSetSpec{Addresses: api.Entries("1.1.1.1")}, false},
		{"jail unencrypted", api.KindJail, api.JailSpec{Image: "i", Encrypted: true}, api.JailSpec{Image: "i"}, true},
		{"jail policy detached", api.KindJail, api.JailSpec{Image: "i", Firewall: api.FirewallAttach{Policies: []string{"p"}}}, api.JailSpec{Image: "i"}, true},
		{"jail new image", api.KindJail, api.JailSpec{Image: "a@stable"}, api.JailSpec{Image: "b@stable"}, true},
		{"jail new alias", api.KindJail, api.JailSpec{Image: "a@stable"}, api.JailSpec{Image: "a#g3"}, false},
		{"network renumbered", api.KindNetwork, api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.0.0.0/24"}}, api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.1.0.0/24"}}, true},
		{"network range changed", api.KindNetwork, api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.0.0.0/24", Range: "a"}}, api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.0.0.0/24", Range: "b"}}, false},
		{"target repinned", api.KindBackupTarget, api.BackupTargetSpec{Kind: "node", Fingerprint: "aa"}, api.BackupTargetSpec{Kind: "node", Fingerprint: "bb"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(dangers(c.kind, c.live, c.want)) > 0; got != c.danger {
				t.Fatalf("danger = %v, want %v: %v", got, c.danger, dangers(c.kind, c.live, c.want))
			}
		})
	}
	for _, k := range []api.Kind{api.KindJail, api.KindImage, api.KindNetwork, api.KindFirewallPolicy, api.KindAddressSet, api.KindBackupTarget, api.KindBackupPolicy} {
		var live any
		switch k {
		case api.KindJail:
			live = api.JailSpec{}
		case api.KindImage:
			live = api.ImageSpec{}
		case api.KindNetwork:
			live = api.NetworkSpec{}
		case api.KindFirewallPolicy:
			live = api.FirewallPolicySpec{}
		case api.KindAddressSet:
			live = api.AddressSetSpec{}
		case api.KindBackupTarget:
			live = api.BackupTargetSpec{}
		case api.KindBackupPolicy:
			live = api.BackupPolicySpec{}
		}
		if len(dangers(k, live, nil)) == 0 {
			t.Errorf("deleting a %s is not flagged", k)
		}
	}
}

func TestDriftedIgnoresUnmanaged(t *testing.T) {
	p := &Plan{Items: []Item{{Action: ActionMatch}, {Action: ActionUnmanaged}}}
	if p.Drifted() {
		t.Fatal("unmanaged objects are not drift")
	}
	for _, a := range []Action{ActionCreate, ActionUpdate, ActionDelete, ActionRefuse, ActionError} {
		if !(&Plan{Items: []Item{{Action: a}}}).Drifted() {
			t.Errorf("%s is drift", a)
		}
	}
}
