package service_test

import (
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// Two jails that forward the same host port leave the second dead without a word, so the second is refused when it is
// made, naming the first: a proxy device against a proxy device, a redirect rule of a policy against a proxy device, and
// a project's mandatory policy with a redirect against the second jail of the project.
func TestTwoJailsCannotForwardTheSameHostPort(t *testing.T) {
	_, s := newEnv(t)
	admin := as(globalAdmin, dtest.SeedProject)
	// the seeded network has no uplink, and a forward needs one
	lan, err := s.GetNetwork(as(globalAdmin, ""), "lan")
	if err != nil {
		t.Fatal(err)
	}
	lan.Spec.Uplink = "em0"
	if _, err := s.UpdateNetwork(as(globalAdmin, ""), "lan", lan, lan.Metadata.Generation); err != nil {
		t.Fatal(err)
	}
	withProxy := func(name, listen string) api.Jail {
		j := dtest.WebJail(name)
		j.Spec.Proxy = []api.ProxyDevice{{Name: "web", Listen: listen, JailPort: 80}}
		return j
	}
	create := func(j api.Jail) error {
		op, err := s.CreateJail(admin, j)
		if err != nil {
			return err
		}
		if got := wait(t, s, op); got.Status != api.OpSuccess {
			t.Fatalf("create %s: %+v", j.Metadata.Name, got)
		}
		return nil
	}
	if err := create(withProxy("one", ":2301")); err != nil {
		t.Fatal(err)
	}
	err = create(withProxy("two", ":2301"))
	wantCode(t, err, api.CodeAlreadyExists)
	if err == nil || !strings.Contains(err.Error(), `"one"`) {
		t.Fatalf("the refusal should name the first jail: %v", err)
	}
	// another port is fine
	if err := create(withProxy("two", ":2302")); err != nil {
		t.Fatal(err)
	}
	// a redirect rule of a policy takes the port of a proxy device too
	jt := dtest.WebJail("three")
	jt.Spec.Firewall.Policies = []string{"fwd"}
	if _, err := s.CreatePolicy(admin, redirectPolicy("fwd", 2301, "")); err != nil {
		t.Fatal(err) // no jail uses the policy yet: nothing clashes
	}
	err = create(jt)
	wantCode(t, err, api.CodeAlreadyExists)
	if err == nil || !strings.Contains(err.Error(), "2301") {
		t.Fatalf("a jail whose policy forwards a taken port: %v", err)
	}
	// a policy that a jail uses cannot be changed to take a port another jail forwards
	jf := dtest.WebJail("four")
	jf.Spec.Firewall.Policies = []string{"other"}
	if _, err := s.CreatePolicy(admin, redirectPolicy("other", 2303, "")); err != nil {
		t.Fatal(err)
	}
	if err := create(jf); err != nil {
		t.Fatal(err)
	}
	clash := redirectPolicy("other", 2301, "")
	if _, err := s.UpdatePolicy(admin, "other", clash, 0); err == nil || !strings.Contains(err.Error(), "2301") {
		t.Fatalf("a policy whose forward takes a port of another jail: %v", err)
	}
}

// A jail with a link and no address (a network entry of "none") has a rendered anchor that closes both directions, and
// so has a jail with an address: no jail with an interface is left without one.
func TestEveryJailWithALinkHasARenderedAnchor(t *testing.T) {
	e, s := newEnv(t)
	admin := as(globalAdmin, dtest.SeedProject)
	for _, c := range []struct {
		name, ipv4 string
		closed     bool
	}{{"addressed", "", false}, {"nowhere", "none", true}} {
		j := dtest.WebJail(c.name)
		j.Spec.Network = []api.NetworkAttach{{Network: "lan", IPv4: c.ipv4}}
		op, err := s.CreateJail(admin, j)
		if err != nil {
			t.Fatal(err)
		}
		if got := wait(t, s, op); got.Status != api.OpSuccess {
			t.Fatalf("create %s: %+v", c.name, got)
		}
		jailAction(t, s, c.name, "start")
		text := e.File(filepath.Join(e.Cfg.StateDir, "rendered", "pf", dtest.SeedProject+"_"+c.name+".conf"))
		if text == "" {
			t.Fatalf("%s: no rendered anchor", c.name)
		}
		closed := strings.Contains(text, "the jail has no address on its links") &&
			strings.Contains(text, "block drop in quick on ") && !strings.Contains(text, "pass")
		if closed != c.closed {
			t.Errorf("%s: closed anchor %v, want %v:\n%s", c.name, closed, c.closed, text)
		}
	}
}
