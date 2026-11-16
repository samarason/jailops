package server_test

import (
	"testing"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// A forward opens a port of the host to the network: only a global administrator makes one, as a proxy device of a jail
// or as a rule of a policy.
func TestPortForwardsNeedAGlobalAdministrator(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	op := e.Scoped(api.PermOperator, "alpha")
	adm := e.Scoped(api.PermAdmin, "alpha")
	if _, err := e.Admin.Networks().Patch(c, "lan", map[string]any{"spec": map[string]any{"uplink": "em0"}}, ""); err != nil {
		t.Fatal(err)
	}
	sp := webSpec()
	sp.Proxy = []api.ProxyDevice{{Name: "ssh", Listen: ":2222", JailPort: 22}}
	create := func(cl *sdk.Client, name string, sp api.JailSpec) error {
		o, err := cl.Jails().Create(c, sdk.NewJail(name, sp))
		if err == nil {
			_, err = o.Wait(c)
		}
		return err
	}
	if err := create(op, "fwd", sp); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("an operator made a proxy device: %v", err)
	}
	if err := create(adm, "fwd", sp); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("an administrator of the project made a proxy device: %v", err)
	}
	if err := create(e.Admin, "fwd", sp); err != nil {
		t.Fatalf("a global administrator could not: %v", err)
	}
	// the same through the configuration of a jail that exists
	plain := webSpec()
	if err := create(e.Admin, "plain", plain); err != nil {
		t.Fatal(err)
	}
	for who, cl := range map[string]*sdk.Client{"an operator": op, "an administrator of the project": adm} {
		if _, err := cl.Jails().Config(c, "plain", map[string]string{"proxy.ssh.listen": ":2223", "proxy.ssh.jail_port": "22"}, nil, false); err == nil {
			t.Errorf("%s set a proxy key", who)
		}
	}
	// a rule of a policy that forwards a port
	rule := api.FirewallRule{Name: "fwd", Action: "allow", Direction: "in", Proto: "tcp", Redirect: &api.Redirect{HostPort: 2224, JailPort: 22}}
	pol := api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "fwd"}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{rule}}}
	if _, err := op.Firewall().Policies().Create(c, pol); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("an operator made a forwarding policy: %v", err)
	}
	if _, err := adm.Firewall().Policies().Create(c, pol); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("an administrator of the project made a forwarding policy: %v", err)
	}
	if _, err := e.Admin.Firewall().Policies().Create(c, pol); err != nil {
		t.Errorf("a global administrator could not: %v", err)
	}
}
