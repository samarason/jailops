package service_test

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

func redirectPolicy(name string, hostPort int, listen string) api.FirewallPolicy {
	return api.FirewallPolicy{Metadata: api.ObjectMeta{Name: name}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow",
		Rules: []api.FirewallRule{{Name: "fwd", Action: "allow", Direction: "in", Proto: "tcp",
			Redirect: &api.Redirect{Listen: listen, HostPort: hostPort, JailPort: 8080}}}}}
}

// A port forward takes traffic that would reach the host: only a global administrator publishes one, and never on a port
// the host listens on or on an address the host does not have.
func TestPolicyForwardsAreGlobalAndKeepOffTheHostsOwnPorts(t *testing.T) {
	_, s := newEnv(t)
	project := as(alphaOnly, dtest.SeedProject)
	for _, c := range []struct {
		port   int
		listen string
	}{{22, ""}, {39110, ""}, {2224, ""}, {443, "198.51.100.77"}} {
		_, err := s.CreatePolicy(project, redirectPolicy("fwd", c.port, c.listen))
		wantCode(t, err, api.CodeForbidden)
		if err == nil || !strings.Contains(err.Error(), "global administrator") {
			t.Errorf("port %d: the refusal should say a global administrator: %v", c.port, err)
		}
	}
	admin := as(globalAdmin, dtest.SeedProject)
	for _, c := range []struct {
		port   int
		listen string
		want   string
	}{
		{22, "", "ssh"},
		{39110, "", "console"},
		{39111, "", "backup node"},
		{2224, "198.51.100.77", "not an address of this host"},
		{2224, "2001:db8::77", "not an address of this host"},
	} {
		_, err := s.CreatePolicy(admin, redirectPolicy("fwd", c.port, c.listen))
		wantCode(t, err, api.CodeInvalid)
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("port %d on %q: %v, want %q", c.port, c.listen, err, c.want)
		}
	}
	if _, err := s.CreatePolicy(admin, redirectPolicy("fwd", 2224, "")); err != nil {
		t.Fatalf("a forward of a free port on the uplink address: %v", err)
	}
	// an address the host has is allowed
	var own string
	if as, _ := net.InterfaceAddrs(); as != nil {
		for _, a := range as {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
				own = p.Addr().String()
				break
			}
		}
	}
	if own != "" {
		if _, err := s.CreatePolicy(admin, redirectPolicy("fwd2", 2225, own)); err != nil {
			t.Fatalf("a forward on %s, an address of the host: %v", own, err)
		}
	}
}

// The proxy devices of a jail, in the jail or in a profile, follow the same rule.
func TestProxyDevicesAreGlobalAndKeepOffTheHostsOwnPorts(t *testing.T) {
	_, s := newEnv(t)
	project := as(alphaOnly, dtest.SeedProject)
	admin := as(globalAdmin, dtest.SeedProject)
	jail := func(name, listen string) api.Jail {
		j := dtest.WebJail(name)
		j.Spec.Proxy = []api.ProxyDevice{{Name: "p", Listen: listen, JailPort: 80}}
		return j
	}
	_, err := s.CreateJail(project, jail("a", ":8081"))
	wantCode(t, err, api.CodeForbidden)
	for _, c := range []struct{ listen, want string }{
		{":22", "ssh"}, {":39110", "console"}, {"198.51.100.77:443", "not an address of this host"}} {
		_, err := s.CreateJail(admin, jail("b", c.listen))
		wantCode(t, err, api.CodeInvalid)
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.listen, err, c.want)
		}
	}
	// a free port gets past the port rules (the seeded network has no uplink, which is the next check)
	if _, err := s.CreateJail(admin, jail("c", ":8082")); err == nil || !strings.Contains(err.Error(), "need a network with an uplink") {
		t.Fatalf("a free port on the uplink address: %v", err)
	}
	// a profile cannot carry it past the rule either
	_, err = s.CreateProfile(project, api.Profile{Metadata: api.ObjectMeta{Name: "pub"}, Spec: api.ProfileSpec{
		Config: map[string]string{"proxy.web.listen": ":8083", "proxy.web.jail_port": "80"}}})
	wantCode(t, err, api.CodeForbidden)
	// and a project administrator does not set the key on a jail
	op, err := s.CreateJail(admin, dtest.WebJail("d"))
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("%+v", got)
	}
	_, err = s.ConfigureJail(project, "d", api.ConfigChange{Set: map[string]string{"proxy.x.listen": ":8084", "proxy.x.jail_port": "80"}}, false)
	wantCode(t, err, api.CodeForbidden)
}

// A forward the policy already has stays when an administrator of the project edits the other rules; a new or changed
// forward is a global administrator's.
func TestProjectAdminEditsAPolicyWithAForwardButNotTheForward(t *testing.T) {
	_, s := newEnv(t)
	admin := as(globalAdmin, dtest.SeedProject)
	project := as(alphaOnly, dtest.SeedProject)
	if _, err := s.CreatePolicy(admin, redirectPolicy("fwd", 2224, "")); err != nil {
		t.Fatal(err)
	}
	cur, err := s.GetPolicy(project, "fwd")
	if err != nil {
		t.Fatal(err)
	}
	more := cur
	more.Spec.Rules = append(append([]api.FirewallRule(nil), cur.Spec.Rules...),
		api.FirewallRule{Name: "ssh", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"2200"}, Comment: "another rule"})
	if _, err := s.UpdatePolicy(project, "fwd", more, cur.Metadata.Generation); err != nil {
		t.Fatalf("another rule of a policy with a forward: %v", err)
	}
	cur, _ = s.GetPolicy(project, "fwd")
	changed := cur
	changed.Spec.Rules = append([]api.FirewallRule(nil), cur.Spec.Rules...)
	rd := *changed.Spec.Rules[0].Redirect
	rd.HostPort = 2225
	changed.Spec.Rules[0].Redirect = &rd
	_, err = s.UpdatePolicy(project, "fwd", changed, cur.Metadata.Generation)
	wantCode(t, err, api.CodeForbidden)
}
