package server_test

import (
	"fmt"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func TestConfigKeysEndpointIsTheRegistry(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	keys, err := e.Admin.ConfigKeys(ctxT(t))
	if err != nil || len(keys) != len(api.ConfigKeys()) {
		t.Fatalf("%v %d", err, len(keys))
	}
	// Every authenticated identity may read it, one that has no scope too.
	if code, _ := e.Raw("GET", "/api/v1/config-keys", e.ScopelessToken(api.PermReadonly), ""); code != 200 {
		t.Fatal(code)
	}
	if code, _ := e.Raw("GET", "/api/v1/config-keys", "", ""); code != 401 {
		t.Fatal(code)
	}
}

func TestConfigNeverRestartsAJailOnItsOwn(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	mustJail(t, e, "web")
	so, _ := e.Admin.Jails().Start(c, "web")
	if _, err := so.Wait(c); err != nil {
		t.Fatal(err)
	}
	before, _, _ := e.Jails.Get(c, "alpha_web")
	op, err := e.Admin.Jails().Config(c, "web", map[string]string{"limits.memory": "2G", "boot.priority": "4", "hostname": "w.example"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := op.Wait(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.RestartRequired, ",") != "hostname,limits.memory" || res.Restarted || res.Spec.Resources.Memory != "2G" || res.Status.Power != api.PowerRunning {
		t.Fatalf("%+v", res)
	}
	after, _, _ := e.Jails.Get(c, "alpha_web")
	if after.JID != before.JID {
		t.Fatal("the jail was restarted by a configuration change")
	}
	// An explicit request restarts it.
	op, _ = e.Admin.Jails().Config(c, "web", map[string]string{"limits.cpu": "2"}, nil, true)
	res, err = op.Wait(c)
	if err != nil || !res.Restarted {
		t.Fatalf("%v %+v", err, res)
	}
	// A change that needs no restart restarts nothing even when asked.
	op, _ = e.Admin.Jails().Config(c, "web", map[string]string{"boot.priority": "9"}, nil, true)
	res, _ = op.Wait(c)
	if res.Restarted || len(res.RestartRequired) != 0 {
		t.Fatalf("%+v", res)
	}
	// Bad keys and values change nothing.
	if _, err := e.Admin.Jails().Config(c, "web", map[string]string{"limits.nope": "1"}, nil, false); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("%v", err)
	}
	j, _ := e.Admin.Jails().Get(c, "web")
	if j.Spec.Resources.CPU != 2 {
		t.Fatalf("%+v", j.Spec.Resources)
	}
	// Other projects' jails are not found.
	if _, err := e.Admin.Project("nope").Jails().Config(c, "web", nil, nil, false); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
}

func TestProfilesDevicesAndRendering(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	if _, err := e.Admin.Networks().Patch(c, "lan", map[string]any{"spec": map[string]any{"uplink": "em0", "mtu": 1400}}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Profiles().Create(c, api.Profile{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.ProfileSpec{Config: map[string]string{
		"limits.memory": "1G", "nic.eth0.mtu": "1400", "proxy.http.listen": ":8080", "proxy.http.jail_port": "80", "devfs.t.device": "tun", "boot.autostart": "true"}}}); err != nil {
		t.Fatal(err)
	}
	sp := webSpec()
	sp.Profiles = []string{"web"}
	sp.Network = []api.NetworkAttach{{Network: "lan", IPv4: "auto"}}
	sp.Resources.Memory = "4G"
	op, err := e.Admin.Jails().Create(c, sdk.NewJail("web", sp))
	if err != nil {
		t.Fatal(err)
	}
	j, err := op.Wait(c)
	if err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	if j.Spec.Network[0].Name != "eth0" || j.Spec.Resources.Memory != "4G" {
		t.Fatalf("%+v", j.Spec)
	}
	ex, _ := e.Admin.Jails().Expanded(c, "web")
	if ex.Sources["limits.memory"] != "jail" || ex.Sources["nic.eth0.mtu"] != "web" || ex.Jail.Spec.Network[0].MTU != 1400 || !ex.Jail.Spec.Boot.Autostart {
		t.Fatalf("%+v", ex)
	}
	so, _ := e.Admin.Jails().Start(c, "web")
	if _, err := so.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	conf := e.File("/etc/jailops/jails/alpha_web/jail.conf")
	if !strings.Contains(conf, "devfs_ruleset") || strings.Contains(conf, "devfs_ruleset = 4;") {
		t.Fatalf("jail.conf:\n%s", conf)
	}
	// the ruleset the jail's devfs mounts is the one the helper loads before the jail is created: same number
	if n, _, err := render.DevfsRuleset([]string{"tun"}); err != nil || !strings.Contains(conf, fmt.Sprintf("devfs_ruleset = %d;", n)) {
		t.Fatalf("jail.conf does not name the devfs ruleset of a jail with tun (%d, %v):\n%s", n, err, conf)
	}
	if rules := e.File("/etc/jailops/jails/alpha_web/devfs.rules"); rules != "" {
		t.Fatalf("a devfs.rules file nobody loads was written: %q", rules)
	}
	rs := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_web.conf")
	if !strings.Contains(rs, "port 8080 rdr-to "+j.Spec.Network[0].IPv4+" port 80") {
		t.Fatalf("the proxy device is not an rdr rule:\n%s", rs)
	}
	// Two jails cannot forward the same host port, in any project.
	sp2 := webSpec()
	sp2.Profiles = []string{"web"}
	_, err = e.Admin.Jails().Create(c, sdk.NewJail("web2", sp2))
	if err == nil {
		t.Fatal("two jails forward :8080")
	}
	if code := e.Admin.Jails(); code == nil {
		t.Fatal()
	}
	// Device nodes need the admin role.
	op2, err := e.Client(api.PermOperator).Jails().Config(c, "web", map[string]string{"devfs.b.device": "bpf"}, nil, false)
	if err == nil {
		t.Fatalf("an operator exposed a device: %v", op2)
	}
	wantCode(t, err, api.CodeForbidden)
	// A profile in use is not deleted; an unknown one is not accepted.
	wantCode(t, e.Admin.Profiles().Delete(c, "web"), api.CodeBusy)
	sp3 := webSpec()
	sp3.Profiles = []string{"ghost"}
	_, err = e.Admin.Jails().Create(c, sdk.NewJail("w3", sp3))
	wantCode(t, err, api.CodeNotFound)
	// Host-level profiles: global writes, everyone reads.
	hp := e.Admin.Project(api.HostProfileProject).Profiles()
	if _, err := hp.Create(c, api.Profile{Metadata: api.ObjectMeta{Name: "base"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.pids": "300"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "p"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: e.MakeNetwork("p")}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	pc := e.Scoped(api.PermAdmin, "p")
	hostC := pc.Project(api.HostProfileProject).Profiles()
	if _, err := hostC.Get(c, "base"); err != nil {
		t.Fatalf("a project user cannot read host-level profiles: %v", err)
	}
	if _, err := hostC.Create(c, api.Profile{Metadata: api.ObjectMeta{Name: "x"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("%v", err)
	}
	sp4 := webSpecIn("p")
	sp4.Profiles = []string{"base"}
	pop, err := pc.Jails().Create(c, sdk.NewJail("pj", sp4))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pop.Wait(c); err != nil {
		t.Fatal(err)
	}
	pex, _ := pc.Jails().Expanded(c, "pj")
	if pex.Jail.Spec.Resources.PIDs != 300 || pex.Sources["limits.pids"] != "base" {
		t.Fatalf("%+v", pex)
	}
}

// A project profile cannot take the name of a host-level one, and editing a profile re-runs the checks of every
// jail that uses it.
func TestProfileShadowingAndReadmission(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	if _, err := e.Admin.Project(api.HostProfileProject).Profiles().Create(c, api.Profile{Metadata: api.ObjectMeta{Name: "base"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.memory": "1G"}}}); err != nil {
		t.Fatal(err)
	}
	_, err := e.Admin.Profiles().Create(c, api.Profile{Metadata: api.ObjectMeta{Name: "base"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.memory": "64G"}}})
	wantCode(t, err, api.CodeAlreadyExists)

	if _, err := e.Admin.Profiles().Create(c, api.Profile{Metadata: api.ObjectMeta{Name: "mine"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.memory": "1G"}}}); err != nil {
		t.Fatal(err)
	}
	sp := webSpec()
	sp.Profiles = []string{"mine"}
	op, err := e.Admin.Jails().Create(c, sdk.NewJail("p1", sp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	// A proxy device needs a network with an uplink; the lan has none, so the edit is refused for the jail it would reach.
	cur, err := e.Admin.Profiles().Get(c, "mine")
	if err != nil {
		t.Fatal(err)
	}
	cur.Spec.Config = map[string]string{"proxy.http.listen": ":8099", "proxy.http.jail_port": "80"}
	_, err = e.Admin.Profiles().Update(c, "mine", cur, "")
	if err == nil {
		t.Fatal("a profile edit gave a jail a proxy it could not have been admitted with")
	}
}
