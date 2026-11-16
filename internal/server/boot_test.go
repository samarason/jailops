package server_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// The boot plan over HTTP: the order of the whole host (a dependency first, then the priority, then the name), the
// jails that wait for a passphrase and the jails that depend on them, and what each identity sees of it.
func TestBootPlan(t *testing.T) {
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) { off := false; c.Reconcile.Autostart = &off }})
	e.Seed()
	c := ctxT(t)
	create := func(project string, j api.Jail, pass string) {
		t.Helper()
		if pass != "" {
			// the encrypted volume the jail attaches is made first
			op, e2 := e.Admin.Project(project).Volumes().Create(c, sdk.NewVolume("data", api.VolumeSpec{Encrypted: true}), pass)
			if e2 != nil {
				t.Fatal(e2)
			}
			if _, err := op.Wait(c); err != nil {
				t.Fatalf("volume: %v\n%s", err, e.Log())
			}
		}
		op, e2 := e.Admin.Project(project).Jails().Create(c, j)
		if e2 != nil {
			t.Fatal(e2)
		}
		_, err := op.Wait(c)
		if err != nil {
			t.Fatalf("create %s: %v\n%s", j.Metadata.Name, err, e.Log())
		}
	}
	jail := func(name string, auto bool, prio int, depends ...string) api.Jail {
		j := dtest.WebJail(name)
		j.Spec.Boot = api.BootPolicy{Autostart: auto, Priority: prio, Depends: depends}
		return j
	}
	create(dtest.SeedProject, jail("db", false, 5), "")
	create(dtest.SeedProject, jail("web", true, 1, "db"), "")
	create(dtest.SeedProject, jail("cache", true, 0), "")
	create(dtest.SeedProject, jail("idle", false, 0), "")
	vault := jail("vault", true, 0)
	vault.Spec.Volumes = []api.VolumeAttach{{Name: "data", Mount: "/var/db/vault"}}
	create(dtest.SeedProject, vault, "pass-phrase-1")
	create(dtest.SeedProject, jail("report", true, 0, "vault"), "")

	net := e.MakeNetwork("beta")
	if _, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: net}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	edge := jail("edge", true, -1)
	edge.Spec.Network = []api.NetworkAttach{{Network: net, IPv4: "auto"}}
	create("beta", edge, "")

	info, err := e.Admin.Info(c)
	if err != nil || !hasStr(info.APIExtensions, "boot_plan") {
		t.Fatalf("extension: %v %v", err, info.APIExtensions)
	}

	// the whole host, for a global identity
	p, err := e.Admin.BootPlan(c, true)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, en := range p.Order {
		got = append(got, en.Project+"/"+en.Jail+":"+en.Reason)
	}
	want := []string{
		"beta/edge:autostart", // priority -1
		"alpha/cache:autostart",
		"alpha/db:dependency of web", // before web, though it has no autostart
		"alpha/web:autostart",
	}
	if len(got) != len(want) {
		t.Fatalf("order: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order: got %v want %v", got, want)
		}
	}
	for i, en := range p.Order {
		if en.Position != i+1 {
			t.Errorf("position %d for entry %d", en.Position, i)
		}
	}
	if len(p.Order[3].Depends) != 1 || p.Order[3].Depends[0] != "db" || p.Order[3].Priority != 1 {
		t.Errorf("web: %+v", p.Order[3])
	}
	skipped := map[string]string{}
	for _, s := range p.NotStarted {
		skipped[s.Project+"/"+s.Jail] = s.Reason
	}
	if len(skipped) != 2 || skipped["alpha/vault"] == "" || skipped["alpha/report"] == "" {
		t.Fatalf("not started: %+v", p.NotStarted)
	}
	if !strings.Contains(skipped["alpha/vault"], "jailops volume unlock VOLUME") || !strings.Contains(skipped["alpha/report"], "depends on vault") {
		t.Errorf("reasons: %+v", skipped)
	}
	if _, ok := skipped["alpha/idle"]; ok {
		t.Error("a jail without autostart is not listed")
	}

	// an operator of beta sees its own jails, numbered from 1, in the order of the host
	beta := e.Scoped(api.PermOperator, "beta")
	p, err = beta.BootPlan(c, true)
	if err != nil || len(p.Order) != 1 || p.Order[0].Jail != "edge" || p.Order[0].Position != 1 || len(p.NotStarted) != 0 {
		t.Fatalf("%v %+v", err, p)
	}
	// readonly may read it; a project it may not use is not found
	ro := e.Client(api.PermReadonly)
	if _, err := ro.BootPlan(c, true); err != nil {
		t.Fatal(err)
	}
	_, err = beta.Project("alpha").BootPlan(c, false)
	wantCode(t, err, api.CodeNotFound)
	// a named project shows that project only
	p, err = e.Admin.Project("alpha").BootPlan(c, false)
	if err != nil || len(p.Order) != 3 || p.Order[0].Jail != "cache" {
		t.Fatalf("%v %+v", err, p)
	}
}
