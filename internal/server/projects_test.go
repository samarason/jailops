package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// twoProjects has the project alpha that Seed made (granted the network "lan") and the project beta with a network of
// its own, "lan-beta": networks are not shared between projects. It returns a restricted identity in each.
func twoProjects(t *testing.T) (e *dtest.Env, alpha, beta *sdk.Client) {
	t.Helper()
	e = seeded(t)
	c := ctxT(t)
	n := dtest.LAN()
	n.Metadata.Name = "lan-beta"
	n.Spec.IPv4 = &api.IPv4Net{Subnet: "10.21.0.0/24", Gateway: "10.21.0.1", Range: "10.21.0.10-10.21.0.50"}
	if _, err := e.Admin.Networks().Create(c, n); err != nil {
		t.Fatal(err)
	}
	_, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "lan-beta"}},
		Storage:  []api.ProjectStorage{{Storage: "default", Quota: "500G"}},
	}})
	if err != nil {
		t.Fatalf("project beta: %v", err)
	}
	return e, e.Scoped(api.PermAdmin, dtest.SeedProject), e.Scoped(api.PermAdmin, "beta")
}

// webSpec is a jail spec for the seeded project: its network and a storage, named explicitly.
func webSpec() api.JailSpec { return webSpecIn(dtest.SeedProject) }

// webSpecIn is a jail spec for a project of twoProjects: the network that project holds.
func webSpecIn(project string) api.JailSpec {
	net := "lan"
	if project != dtest.SeedProject {
		net = "lan-" + project
	}
	return api.JailSpec{Image: "fb@stable", Storage: "default", Network: []api.NetworkAttach{{Network: net}},
		Update: api.UpdatePolicy{Strategy: api.UpdateRebase, Healthcheck: "/bin/true"}}
}

func createJail(t *testing.T, c *sdk.Client, name string) api.Jail {
	t.Helper()
	op, err := c.Jails().Create(ctxT(t), sdk.NewJail(name, webSpecIn(c.ProjectName())))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	j, err := op.Wait(ctxT(t))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return j
}

func TestProjectsNamesAddressesAndStorageAreIsolated(t *testing.T) {
	e, alpha, beta := twoProjects(t)
	c := ctxT(t)
	ja := createJail(t, alpha, "web")
	jo := createJail(t, beta, "web") // same name, other project
	if ja.Metadata.Project != "alpha" || jo.Metadata.Project != "beta" || ja.Metadata.UUID == jo.Metadata.UUID {
		t.Fatalf("%+v %+v", ja.Metadata, jo.Metadata)
	}
	// The network and storage are the ones the jail named.
	if len(ja.Spec.Network) != 1 || ja.Spec.Network[0].Network != "lan" || ja.Spec.Storage != "default" {
		t.Fatalf("%+v", ja.Spec)
	}
	// Each project has its own network, so each starts at the beginning of its own range.
	if a, b := ja.Spec.Network[0].IPv4, jo.Spec.Network[0].IPv4; a != "10.20.0.10" || b != "10.21.0.10" {
		t.Fatalf("alpha got %s, beta got %s", a, b)
	}
	// Project-qualified names: the datasets and the OS names cannot collide.
	for _, ds := range []string{"tank/jailops/projects/alpha/jails/web", "tank/jailops/projects/beta/jails/web"} {
		if ok, _ := e.ZFS.Exists(c, ds); !ok {
			t.Fatalf("dataset %s missing", ds)
		}
	}
	for _, j := range []struct {
		cl   *sdk.Client
		name string
	}{{alpha, "web"}, {beta, "web"}} {
		op, err := j.cl.Jails().Start(c, j.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := op.Wait(c); err != nil {
			t.Fatalf("%v\n%s", err, e.Log())
		}
	}
	if _, ok, _ := e.Jails.Get(c, "alpha_web"); !ok {
		t.Fatal("alpha's jail is not running under its qualified name")
	}
	if _, ok, _ := e.Jails.Get(c, "beta_web"); !ok {
		t.Fatal("beta's jail is not running under its qualified name")
	}
	// The lists show one project each.
	for _, tc := range []struct {
		cl   *sdk.Client
		want string
	}{{alpha, "alpha"}, {beta, "beta"}} {
		n := 0
		for j, err := range tc.cl.Jails().List(c) {
			if err != nil {
				t.Fatal(err)
			}
			n++
			if j.Metadata.Project != tc.want {
				t.Fatalf("%s sees %+v", tc.want, j.Metadata)
			}
		}
		if n != 1 {
			t.Fatalf("%s sees %d jails", tc.want, n)
		}
	}
	// There is no default project that could hold them.
	for _, err := range e.Admin.Project("default").Jails().List(c) {
		wantCode(t, err, api.CodeNotFound)
		break
	}
}

// An object of another project is not_found on every verb, never forbidden.
func TestCrossProjectIsNotFound(t *testing.T) {
	e, alpha, beta := twoProjects(t)
	c := ctxT(t)
	createJail(t, alpha, "web")
	other := alpha.Project("beta")
	_, err := other.Jails().Get(c, "web")
	wantCode(t, err, api.CodeNotFound)
	for _, call := range []func() error{
		func() error { _, err := other.Jails().Create(c, sdk.NewJail("x", webSpec())); return err },
		func() error { _, err := other.Jails().Start(c, "web"); return err },
		func() error { _, err := other.Jails().Delete(c, "web"); return err },
		func() error { _, err := other.Jails().Snapshots("web").Create(c, "s", ""); return err },
		func() error { _, err := other.Jails().State(c, "web"); return err },
		func() error { return firstErr(other.Jails().List(c)) },
		func() error { return firstErr(other.Firewall().Policies().List(c)) },
		func() error {
			_, err := other.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "s"}})
			return err
		},
	} {
		wantCode(t, call(), api.CodeNotFound)
	}
	// A project that does not exist looks the same.
	_, err = alpha.Project("nope").Jails().Get(c, "web")
	wantCode(t, err, api.CodeNotFound)
	// The cross-project identity cannot learn that the jail exists by creating it either.
	_, err = beta.Project("alpha").Jails().Create(c, sdk.NewJail("web", webSpec()))
	wantCode(t, err, api.CodeNotFound)
	// A global admin sees both.
	if _, err := e.Admin.Project("alpha").Jails().Get(c, "web"); err != nil {
		t.Fatal(err)
	}
}

func firstErr[T any](seq func(func(T, error) bool)) error {
	var out error
	seq(func(_ T, err error) bool { out = err; return err == nil })
	return out
}

func TestGrantsAreEnforced(t *testing.T) {
	e, alpha, _ := twoProjects(t)
	c := ctxT(t)
	// A network that exists but is not granted: forbidden, and so is one that does not exist.
	other := dtest.LAN()
	other.Metadata.Name = "dmz"
	other.Spec.IPv4.Subnet, other.Spec.IPv4.Gateway, other.Spec.IPv4.Range = "10.30.0.0/24", "10.30.0.1", "10.30.0.10-10.30.0.50"
	if _, err := e.Admin.Networks().Create(c, other); err != nil {
		t.Fatal(err)
	}
	for _, nw := range []string{"dmz", "ghost"} {
		sp := webSpec()
		sp.Network = []api.NetworkAttach{{Network: nw, IPv4: "auto"}}
		_, err := alpha.Jails().Create(c, sdk.NewJail("w1", sp))
		wantCode(t, err, api.CodeForbidden)
	}
	// Storage that is not granted.
	if _, err := e.Admin.Storage().Create(c, api.Storage{Metadata: api.ObjectMeta{Name: "fast"}, Spec: api.StorageSpec{Dataset: "tank/fast"}}); err == nil {
		t.Fatal("storage on a missing dataset was accepted")
	}
	if err := e.ZFS.Create(c, zfs.CreateOpts{Name: "tank/fast"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Storage().Create(c, api.Storage{Metadata: api.ObjectMeta{Name: "fast"}, Spec: api.StorageSpec{Dataset: "tank/fast"}}); err != nil {
		t.Fatal(err)
	}
	sp := webSpec()
	sp.Storage = "fast"
	_, err := alpha.Jails().Create(c, sdk.NewJail("w2", sp))
	wantCode(t, err, api.CodeForbidden)
	// The project user sees its own networks only, and cannot write any.
	var names []string
	for n, err := range alpha.Networks().List(c) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, n.Metadata.Name)
	}
	if strings.Join(names, ",") != "lan" {
		t.Fatalf("networks seen: %v", names)
	}
	_, err = alpha.Networks().Get(c, "dmz")
	wantCode(t, err, api.CodeNotFound)
	_, err = alpha.Networks().Create(c, dtest.LAN())
	wantCode(t, err, api.CodeForbidden)
	// An image allow-list.
	if _, err := e.Admin.Projects().Patch(c, "alpha", map[string]any{"spec": map[string]any{"images": []string{"other"}}}, ""); err != nil {
		t.Fatal(err)
	}
	_, err = alpha.Jails().Create(c, sdk.NewJail("w4", webSpec()))
	wantCode(t, err, api.CodeNotFound)
	_, err = alpha.Images().Get(c, "fb")
	wantCode(t, err, api.CodeNotFound)
}

func TestQuotasAreChecked(t *testing.T) {
	e, alpha, _ := twoProjects(t)
	c := ctxT(t)
	if _, err := e.Admin.Projects().Patch(c, "alpha", map[string]any{"spec": map[string]any{
		"quotas": map[string]any{"jails": 2, "cpu": 3, "memory": "2G", "pids": 100, "addresses": 2}}}, ""); err != nil {
		t.Fatal(err)
	}
	mk := func(name string, cpu int, mem string, pids int) error {
		sp := webSpec()
		sp.Resources = api.Resources{CPU: cpu, Memory: mem, PIDs: pids}
		op, err := alpha.Jails().Create(c, sdk.NewJail(name, sp))
		if err != nil {
			return err
		}
		_, err = op.Wait(c)
		return err
	}
	// A quota needs the jail to say what it uses.
	wantCode(t, mk("a", 0, "1G", 10), api.CodeInvalid)
	if err := mk("a", 2, "1G", 50); err != nil {
		t.Fatal(err)
	}
	wantCode(t, mk("b", 2, "512M", 10), api.CodeQuotaExceeded) // cpu 4 > 3
	wantCode(t, mk("b", 1, "2G", 10), api.CodeQuotaExceeded)   // memory 3G > 2G
	wantCode(t, mk("b", 1, "512M", 60), api.CodeQuotaExceeded) // pids 110 > 100
	if err := mk("b", 1, "512M", 10); err != nil {
		t.Fatal(err)
	}
	wantCode(t, mk("c", 0, "", 0), api.CodeQuotaExceeded) // jails 3 > 2
	st, err := e.Admin.Projects().Get(c, "alpha")
	if err != nil || st.Status.Jails != 2 || st.Status.CPU != 3 || st.Status.Addresses != 2 {
		t.Fatalf("%v %+v", err, st.Status)
	}
	// Nothing was created for the refused requests.
	n := 0
	for _, err := range alpha.Jails().List(c) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("%d jails", n)
	}
	// The error says what was exceeded.
	err = mk("d", 1, "512M", 1)
	var ae *api.Error
	if !asAPI(err, &ae) || ae.Detail["resource"] == "" {
		t.Fatalf("%v", err)
	}
	// A quota cannot be set below what is in use.
	_, err = e.Admin.Projects().Patch(c, "alpha", map[string]any{"spec": map[string]any{"quotas": map[string]any{"jails": 1}}}, "")
	wantCode(t, err, api.CodeQuotaExceeded)
}

// The per-storage quota becomes a ZFS quota on the project dataset.
func TestProjectDatasetQuota(t *testing.T) {
	e, _, _ := twoProjects(t)
	c := context.Background()
	if _, err := e.Admin.Projects().Patch(ctxT(t), "alpha", map[string]any{"spec": map[string]any{"storage": []map[string]any{{"storage": "default", "quota": "500G"}}}}, ""); err != nil {
		t.Fatal(err)
	}
	p, err := e.ZFS.Get(c, "tank/jailops/projects/alpha", "quota")
	// stored and written as bytes: ZFS reports bytes (zfs get -p) and the helper takes no other spelling
	if err != nil || p["quota"].Value != "536870912000" {
		t.Fatalf("%v %v", err, p)
	}
	if _, err := e.Admin.Projects().Patch(ctxT(t), "alpha", map[string]any{"spec": map[string]any{"storage": []map[string]any{{"storage": "default", "quota": "1T"}}}}, ""); err != nil {
		t.Fatal(err)
	}
	p, _ = e.ZFS.Get(c, "tank/jailops/projects/alpha", "quota")
	if p["quota"].Value != "1099511627776" {
		t.Fatalf("%v", p)
	}
}

func TestProjectDeletionNeedsEmptiness(t *testing.T) {
	e, alpha, _ := twoProjects(t)
	c := ctxT(t)
	createJail(t, alpha, "web")
	err := e.Admin.Projects().Delete(c, "alpha")
	wantCode(t, err, api.CodeBusy)
	op, err := alpha.Jails().Delete(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	if err := e.Admin.Projects().Delete(c, "alpha"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.ZFS.Exists(c, "tank/jailops/projects/alpha"); ok {
		t.Fatal("the project dataset survived")
	}
	wantCode(t, e.Admin.Projects().Delete(c, "default"), api.CodeNotFound) // there is no such project
	_, err = e.Admin.Projects().Get(c, "alpha")
	wantCode(t, err, api.CodeNotFound)
}

// Lists, operations and events carry only what the caller may see.
func TestListsEventsAndOperationsAreFiltered(t *testing.T) {
	e, alpha, beta := twoProjects(t)
	c := ctxT(t)
	// Subscribe before anything happens.
	ectx, stop := context.WithCancel(c)
	defer stop()
	evs := e.Events(ectx, beta)
	op, err := alpha.Jails().Create(c, sdk.NewJail("web", webSpec()))
	if err != nil {
		t.Fatal(err)
	}
	opID := op.ID()
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	createJail(t, beta, "db")
	// beta never sees alpha's operation, in the list or by id.
	for o, err := range beta.Operations().List(c) {
		if err != nil {
			t.Fatal(err)
		}
		if o.ID == opID || o.Project != "beta" {
			t.Fatalf("beta sees %+v", o)
		}
	}
	_, err = beta.Operations().Get(c, opID)
	wantCode(t, err, api.CodeNotFound)
	wantCode(t, beta.Operations().Cancel(c, opID), api.CodeNotFound)
	// A global admin sees both.
	seen := map[string]bool{}
	for o, err := range e.Global().Operations().List(c) {
		if err != nil {
			t.Fatal(err)
		}
		seen[o.Project] = true
	}
	if !seen["alpha"] || !seen["beta"] {
		t.Fatalf("%v", seen)
	}
	// Events: beta's stream carries beta's events and nothing of alpha or the host. Events arrive in order, so
	// everything up to the creation of beta's jail (alpha's and the host's events included) has been seen by then.
	for created := false; !created; {
		var ev api.Event
		select {
		case ev = <-evs:
		case <-c.Done():
			t.Fatal("beta's jail-created event never arrived")
		}
		var m struct {
			Project string `json:"project"`
			Action  string `json:"action"`
		}
		_ = json.Unmarshal(ev.Metadata, &m)
		if ev.Type == api.EventLogging || m.Project != "beta" {
			t.Fatalf("beta received %s %s", ev.Type, ev.Metadata)
		}
		created = m.Action == "jail-created"
	}
	stop()
	// Audit: a restricted admin reads its own entries only.
	entries, err := beta.Audit(c, 200)
	if err != nil || len(entries) == 0 {
		t.Fatalf("%v %v", err, entries)
	}
	for _, a := range entries {
		if a.Project != "beta" {
			t.Fatalf("beta reads %+v", a)
		}
	}
	all, _ := e.Global().Audit(c, 500)
	projects := map[string]bool{}
	for _, a := range all {
		projects[a.Project] = true
	}
	if !projects["alpha"] || !projects["beta"] {
		t.Fatalf("the global admin should read both projects: %v", projects)
	}
}

func asAPI(err error, target **api.Error) bool { return errors.As(err, target) }

// The project's mandatory policy is rendered before the jail's own and project
// users cannot remove or edit it.
func TestMandatoryFirewallPolicyComesFirst(t *testing.T) {
	e, alpha, _ := twoProjects(t)
	c := ctxT(t)
	admin := e.Admin.Project("alpha")
	pol := func(name string, rules ...api.FirewallRule) api.FirewallPolicy {
		return api.FirewallPolicy{Metadata: api.ObjectMeta{Name: name}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow", Rules: rules}}
	}
	if _, err := admin.Firewall().Policies().Create(c, pol("corp", api.FirewallRule{Name: "corp-deny-telnet", Action: "deny", Direction: "in", Proto: "tcp", Ports: []string{"23"}})); err != nil {
		t.Fatal(err)
	}
	// The mandatory policy must exist in the project.
	_, err := e.Admin.Projects().Patch(c, "alpha", map[string]any{"spec": map[string]any{"firewall_policies": []string{"missing"}}}, "")
	wantCode(t, err, api.CodeNotFound)
	if _, err := e.Admin.Projects().Patch(c, "alpha", map[string]any{"spec": map[string]any{"firewall_policies": []string{"corp"}}}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := alpha.Firewall().Policies().Create(c, pol("own", api.FirewallRule{Name: "own-allow-web", Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"80"}})); err != nil {
		t.Fatal(err)
	}
	// A project user cannot change, patch, replace or delete the mandatory policy, nor unset it on the project.
	cur, etag, _ := alpha.Firewall().Policies().GetETag(c, "corp")
	_, err = alpha.Firewall().Policies().Update(c, "corp", cur, etag)
	wantCode(t, err, api.CodeForbidden)
	_, err = alpha.Firewall().Policies().Patch(c, "corp", map[string]any{"spec": map[string]any{"default_in": "allow"}}, "")
	wantCode(t, err, api.CodeForbidden)
	wantCode(t, alpha.Firewall().Policies().Delete(c, "corp"), api.CodeForbidden)
	_, err = alpha.Projects().Patch(c, "alpha", map[string]any{"spec": map[string]any{"firewall_policies": []string{}}}, "")
	wantCode(t, err, api.CodeForbidden)
	// Even the global admin cannot delete it while the project names it.
	wantCode(t, admin.Firewall().Policies().Delete(c, "corp"), api.CodeBusy)

	sp := webSpec()
	sp.Firewall.Policies = []string{"own"}
	op, err := alpha.Jails().Create(c, sdk.NewJail("web", sp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	// A jail without a policy of its own gets the project's.
	createJail(t, alpha, "bare")
	for _, name := range []string{"web", "bare"} {
		so, _ := alpha.Jails().Start(c, name)
		if _, err := so.Wait(c); err != nil {
			t.Fatalf("%v\n%s", err, e.Log())
		}
	}
	rs := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_web.conf")
	iCorp, iOwn := strings.Index(rs, "corp-deny-telnet"), strings.Index(rs, "own-allow-web")
	if iCorp < 0 || iOwn < 0 || iCorp > iOwn {
		t.Fatalf("the mandatory rule must come before the jail's own:\n%s", rs)
	}
	if !strings.Contains(rs, "# anchor jailops/alpha/web") {
		t.Fatalf("anchor name:\n%s", rs)
	}
	bare := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_bare.conf")
	if !strings.Contains(bare, "corp-deny-telnet") {
		t.Fatalf("a jail without a policy escapes the project's:\n%s", bare)
	}
	// The reconciler loads the anchor under the project, with its parent.
	e.D.Reconciler().Pass(c)
	live, err := e.PF.Read(c, "jailops/alpha/web")
	if err != nil || !strings.Contains(live, "corp-deny-telnet") {
		t.Fatalf("%v %q", err, live)
	}
	if parent, _ := e.PF.Read(c, "jailops/alpha"); !strings.Contains(parent, `anchor "*"`) {
		t.Fatalf("parent anchor: %q", parent)
	}
}

// A project and a jail can each have several policies. The anchor holds the project's in their order, then the jail's in
// theirs, each under its own heading with its own rule numbers; the strictest default of them all applies, and a jail
// without any policy is open.
func TestSeveralPoliciesOfAJailAndAProject(t *testing.T) {
	e, alpha, _ := twoProjects(t)
	c := ctxT(t)
	admin := e.Admin.Project("alpha")
	pol := func(name, in, out string, rules ...api.FirewallRule) {
		t.Helper()
		if _, err := admin.Firewall().Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: name}, Spec: api.FirewallPolicySpec{DefaultIn: in, DefaultOut: out, Rules: rules}}); err != nil {
			t.Fatal(err)
		}
	}
	allow := func(name, port string) api.FirewallRule {
		return api.FirewallRule{Name: name, Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{port}}
	}
	pol("corp", "deny", "allow", allow("corp-ssh", "22"))
	pol("mon", "deny", "allow", allow("mon-metrics", "9100"))
	pol("pg", "allow", "allow", allow("pg-5432", "5432"), allow("pg-5433", "5433"))
	pol("closed-out", "allow", "deny", allow("office-22", "22"))
	if _, err := e.Admin.Projects().Patch(c, "alpha", map[string]any{"spec": map[string]any{"firewall_policies": []string{"corp", "mon"}}}, ""); err != nil {
		t.Fatal(err)
	}
	sp := webSpec()
	sp.Firewall.Policies = []string{"pg", "closed-out"}
	op, err := alpha.Jails().Create(c, sdk.NewJail("web", sp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	so, _ := alpha.Jails().Start(c, "web")
	if _, err := so.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	rs := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_web.conf")
	last := -1
	for _, m := range []string{"# project policy corp", "# rule 1: corp-ssh", "# project policy mon", "# rule 1: mon-metrics",
		"# policy pg", "# rule 1: pg-5432", "# rule 2: pg-5433", "# policy closed-out", "# rule 1: office-22", "# defaults"} {
		i := strings.Index(rs, m)
		if i < 0 || i < last {
			t.Fatalf("%q is missing or out of order:\n%s", m, rs)
		}
		last = i
	}
	// strictest wins: deny inbound from corp, deny outbound from closed-out
	for _, want := range []string{"block drop out quick on", "block drop in quick on"} {
		found := false
		for _, ln := range strings.Split(rs[strings.Index(rs, "# defaults"):], "\n") {
			if strings.HasPrefix(ln, want) && strings.Contains(ln, " all") {
				found = true
			}
		}
		if !found {
			t.Fatalf("the defaults lack %q:\n%s", want, rs)
		}
	}
	// a jail that names nothing gets the project's policies, and their defaults
	createJail(t, alpha, "bare")
	bo, _ := alpha.Jails().Start(c, "bare")
	if _, err := bo.Wait(c); err != nil {
		t.Fatal(err)
	}
	bare := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_bare.conf")
	if !strings.Contains(bare, "# project policy corp") || !strings.Contains(bare, "# project policy mon") || strings.Contains(bare, "# policy pg") {
		t.Fatalf("a jail without policies of its own:\n%s", bare)
	}
	// the policies a list names are not deleted, and a list does not name one twice or one that is not there
	wantCode(t, admin.Firewall().Policies().Delete(c, "pg"), api.CodeBusy)
	wantCode(t, admin.Firewall().Policies().Delete(c, "mon"), api.CodeBusy)
	dup := webSpec()
	dup.Firewall.Policies = []string{"pg", "pg"}
	_, err = alpha.Jails().Create(c, sdk.NewJail("dup", dup))
	wantCode(t, err, api.CodeInvalid)
	missing := webSpec()
	missing.Firewall.Policies = []string{"ghost"}
	_, err = alpha.Jails().Create(c, sdk.NewJail("ghost", missing))
	wantCode(t, err, api.CodeNotFound)
}

// --new-network: a dedicated network and subnet from the configured pool.
func TestNewNetworkCarvesASubnetFromThePool(t *testing.T) {
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) {
		c.Projects.NetworkPool, c.Projects.NetworkBits = "10.64.0.0/16", 24
		c.Projects.Uplink, c.Projects.NAT = "em0", true
	}})
	e.Seed()
	c := ctxT(t)
	mk := func(name string) api.Project {
		p, err := e.Global().Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: name}, Spec: api.ProjectSpec{
			NewNetwork: true, Storage: []api.ProjectStorage{{Storage: "default"}}}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return p
	}
	a := mk("web")
	mk("db")
	if a.Spec.NewNetwork || len(a.Spec.Networks) != 1 || a.Spec.Networks[0].Network != "web" {
		t.Fatalf("%+v", a.Spec)
	}
	na, _ := e.Global().Networks().Get(c, "web")
	nb, _ := e.Global().Networks().Get(c, "db")
	if na.Spec.IPv4.Subnet != "10.64.0.0/24" || nb.Spec.IPv4.Subnet != "10.64.1.0/24" ||
		na.Spec.IPv4.Gateway != "10.64.0.1" || !na.Spec.IPv4.NAT || na.Spec.Uplink != "em0" {
		t.Fatalf("%+v\n%+v", na.Spec, nb.Spec)
	}
	// A jail of that project uses the dedicated network once it names it.
	pc := e.Scoped(api.PermAdmin, "web")
	wsp := webSpec()
	wsp.Network = []api.NetworkAttach{{Network: "web"}}
	wop, err := pc.Jails().Create(c, sdk.NewJail("w", wsp))
	if err != nil {
		t.Fatal(err)
	}
	j, err := wop.Wait(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Spec.Network) != 1 || j.Spec.Network[0].Network != "web" || !strings.HasPrefix(j.Spec.Network[0].IPv4, "10.64.0.") {
		t.Fatalf("%+v", j.Spec.Network)
	}
	// The network is granted to the project, so it cannot be deleted under it.
	wantCode(t, e.Global().Networks().Delete(c, "web"), api.CodeBusy)
	// A name that is taken is refused and nothing is left behind.
	if _, err := e.Global().Networks().Create(c, api.Network{Metadata: api.ObjectMeta{Name: "taken"}, Spec: api.NetworkSpec{
		IPv4: &api.IPv4Net{Subnet: "10.99.0.0/24", Gateway: "10.99.0.1", Range: "10.99.0.10-10.99.0.20"}}}); err != nil {
		t.Fatal(err)
	}
	_, err = e.Global().Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "taken"}, Spec: api.ProjectSpec{NewNetwork: true}})
	wantCode(t, err, api.CodeAlreadyExists)
	if _, err := e.Global().Projects().Get(c, "taken"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
	// Without a pool the convenience says so.
	e2 := dtest.New(t, dtest.Options{})
	_, err = e2.Admin.Projects().Create(ctxT(t), api.Project{Metadata: api.ObjectMeta{Name: "x"}, Spec: api.ProjectSpec{NewNetwork: true}})
	wantCode(t, err, api.CodeUnsupported)
	// It is create-only.
	_, err = e.Global().Projects().Patch(c, "web", map[string]any{"spec": map[string]any{"new_network": true}}, "")
	wantCode(t, err, api.CodeInvalid)
}

// Grants cannot be taken away from jails that use them, and ZFS delegation
// is a global admin's decision.
func TestGrantRemovalAndDelegation(t *testing.T) {
	e, alpha, _ := twoProjects(t)
	c := ctxT(t)
	createJail(t, alpha, "web")
	_, err := e.Admin.Projects().Patch(c, "alpha", map[string]any{"spec": map[string]any{"networks": []map[string]any{{"network": "other"}}}}, "")
	wantCode(t, err, api.CodeNotFound) // the network must exist
	cur, _ := e.Admin.Projects().Get(c, "alpha")
	cur.Spec.Networks = nil
	_, err = e.Admin.Projects().Update(c, "alpha", cur, "")
	wantCode(t, err, api.CodeBusy)
	// Delegation.
	sp := webSpec()
	sp.Delegate = true
	sp.Resources.Disk = "10G"
	_, err = alpha.Jails().Create(c, sdk.NewJail("deleg", sp))
	wantCode(t, err, api.CodeForbidden)
	gop, err := e.Admin.Project("alpha").Jails().Create(c, sdk.NewJail("deleg", sp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gop.Wait(c); err != nil {
		t.Fatal(err)
	}
	so, _ := e.Admin.Project("alpha").Jails().Start(c, "deleg")
	if _, err := so.Wait(c); err != nil {
		t.Fatal(err)
	}
	conf := e.File("/etc/jailops/jails/alpha_deleg/jail.conf")
	if !strings.Contains(conf, "allow.mount.zfs") {
		t.Fatalf("delegation is not rendered:\n%s", conf)
	}
	dds := "tank/jailops/projects/alpha/jails/deleg/delegated"
	if !strings.Contains(conf, `zfs.dataset = "`+dds+`";`) {
		t.Fatalf("the delegated dataset is not named for jail(8):\n%s", conf)
	}
	if p, err := e.ZFS.Get(c, dds, "jailed"); err != nil || p["jailed"].Value != "on" {
		t.Fatalf("the delegated dataset is not jailed: %v %v", p, err)
	}
	// doctor: a jail that asks for the dataset and a dataset that is jailed
	delegCheck := func() api.DoctorCheck {
		rep, err := e.Admin.Doctor(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range rep.Checks {
			if ch.Name == "jail.delegation" {
				return ch
			}
		}
		t.Fatalf("no jail.delegation check: %+v", rep.Checks)
		return api.DoctorCheck{}
	}
	if ch := delegCheck(); ch.Status != api.DoctorOK {
		t.Fatalf("%+v", ch)
	}
	// a jail does not start without the property: the dataset would be mounted on the host too
	st, _ := e.Admin.Project("alpha").Jails().Stop(c, "deleg")
	if _, err := st.Wait(c); err != nil {
		t.Fatal(err)
	}
	if err := e.ZFS.Set(c, dds, map[string]string{"jailed": "off"}); err != nil {
		t.Fatal(err)
	}
	if ch := delegCheck(); ch.Status != api.DoctorFail || !strings.Contains(ch.Message, "deleg") {
		t.Fatalf("a delegated dataset without jailed: %+v", ch)
	}
	if so, err := e.Admin.Project("alpha").Jails().Start(c, "deleg"); err == nil {
		if _, err = so.Wait(c); err == nil {
			t.Fatal("the jail started although its delegated dataset is not jailed")
		}
	}
	// turning it off and on again hands the dataset over again
	dj, tag, _ := e.Admin.Project("alpha").Jails().GetETag(c, "deleg")
	dj.Spec.Delegate = false
	if _, err := e.Admin.Project("alpha").Jails().Update(c, "deleg", dj, tag); err != nil {
		t.Fatal(err)
	}
	dj, tag, _ = e.Admin.Project("alpha").Jails().GetETag(c, "deleg")
	dj.Spec.Delegate = true
	dj.Spec.Resources.Disk = "10G"
	if _, err := e.Admin.Project("alpha").Jails().Update(c, "deleg", dj, tag); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.ZFS.Get(c, dds, "jailed"); p["jailed"].Value != "on" {
		t.Fatalf("turning delegation on did not hand the dataset over: %v", p)
	}
	if ch := delegCheck(); ch.Status != api.DoctorOK {
		t.Fatalf("after turning it on again: %+v", ch)
	}
	// The project user cannot switch it on for another jail by update.
	j, etag, _ := alpha.Jails().GetETag(c, "web")
	j.Spec.Delegate = true
	j.Spec.Resources.Disk = "10G"
	_, err = alpha.Jails().Update(c, "web", j, etag)
	wantCode(t, err, api.CodeForbidden)
}

// Backups are listed and read per project like everything else.
func TestBackupsAreFilteredByProject(t *testing.T) {
	bk := &memBackups{items: map[string]api.Backup{
		"b-alpha": {Metadata: api.ObjectMeta{Name: "b-alpha", Project: "alpha"}},
		"b-beta":  {Metadata: api.ObjectMeta{Name: "b-beta", Project: "beta"}},
		"b-old":   {Metadata: api.ObjectMeta{Name: "b-old"}}, // taken before projects existed: the default project
	}}
	e := dtest.New(t, dtest.Options{Backups: bk})
	c := ctxT(t)
	for _, p := range []string{"alpha", "beta"} {
		if _, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: p}}); err != nil {
			t.Fatal(err)
		}
	}
	names := func(cl *sdk.Client) string {
		var out []string
		for b, err := range cl.Backups().List(c) {
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, b.Metadata.Name)
		}
		return strings.Join(out, ",")
	}
	alpha, beta := e.Scoped(api.PermReadonly, "alpha"), e.Scoped(api.PermReadonly, "beta")
	if got := names(alpha); got != "b-alpha" {
		t.Fatalf("alpha sees %q", got)
	}
	if got := names(beta); got != "b-beta" {
		t.Fatalf("beta sees %q", got)
	}
	if got := names(e.Admin); got != "b-alpha,b-beta,b-old" {
		t.Fatalf("the global admin sees %q", got)
	}
	if got := names(e.Admin.Project("beta")); got != "b-beta" {
		t.Fatalf("narrowed to beta: %q", got)
	}
	if _, err := alpha.Backups().Get(c, "b-alpha"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"b-beta", "b-old"} {
		_, err := alpha.Backups().Get(c, name)
		wantCode(t, err, api.CodeNotFound)
	}
	for b, err := range alpha.Project("beta").Backups().List(c) {
		_ = b
		wantCode(t, err, api.CodeNotFound)
	}
}

// Tags and address sets resolve inside the project: a tag never reaches
// jails of another project.
func TestTagsDoNotCrossProjects(t *testing.T) {
	e, alpha, beta := twoProjects(t)
	c := ctxT(t)
	pol := api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "from-db"}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow",
		Rules: []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"tag:db"}, Ports: []string{"5432"}}}}}
	if _, err := alpha.Firewall().Policies().Create(c, pol); err != nil {
		t.Fatal(err)
	}
	mk := func(cl *sdk.Client, name, policy string, tags ...string) api.Jail {
		sp := webSpecIn(cl.ProjectName())
		sp.Firewall = api.FirewallAttach{Tags: tags}
		if policy != "" {
			sp.Firewall.Policies = []string{policy}
		}
		op, err := cl.Jails().Create(c, sdk.NewJail(name, sp))
		if err != nil {
			t.Fatal(err)
		}
		j, err := op.Wait(c)
		if err != nil {
			t.Fatalf("%v\n%s", err, e.Log())
		}
		return j
	}
	app := mk(alpha, "app", "from-db")
	adb := mk(alpha, "db", "", "db")
	bdb := mk(beta, "db", "", "db")
	so, _ := alpha.Jails().Start(c, "app")
	if _, err := so.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	rs := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_app.conf")
	if !strings.Contains(rs, adb.Spec.Network[0].IPv4) {
		t.Fatalf("alpha's db (%s) is not in the table:\n%s", adb.Spec.Network[0].IPv4, rs)
	}
	if strings.Contains(rs, bdb.Spec.Network[0].IPv4) {
		t.Fatalf("beta's db (%s) reached alpha's anchor:\n%s", bdb.Spec.Network[0].IPv4, rs)
	}
	_ = app
	// An address set of one project is not visible from another.
	if _, err := alpha.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "office"}, Spec: api.AddressSetSpec{Addresses: api.Entries("203.0.113.0/24")}}); err != nil {
		t.Fatal(err)
	}
	_, err := beta.Firewall().AddressSets().Get(c, "office")
	wantCode(t, err, api.CodeNotFound)
	bp := pol
	bp.Metadata.Name = "uses-office"
	bp.Spec.Rules = []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"@office"}, Ports: []string{"22"}}}
	_, err = beta.Firewall().Policies().Create(c, bp)
	if err == nil {
		t.Fatal("a policy referenced an address set of another project")
	}
}

// A global identity that is only an operator is not an administrator: it can set neither host mounts nor delegation,
// which would otherwise start at the next boot under the daemon's own assertion.
func TestAGlobalOperatorCannotSetDelegation(t *testing.T) {
	e, _, _ := twoProjects(t)
	c := ctxT(t)
	op, err := sdk.Connect(c, sdk.Remote(e.HTTP.URL, sdk.WithToken(e.IdentityToken(api.PermOperator, true)), sdk.WithProject(dtest.SeedProject), sdk.WithRetries(0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = op.Close() })
	sp := webSpec()
	sp.Delegate = true
	sp.Resources.Disk = "10G"
	_, err = op.Jails().Create(c, sdk.NewJail("d1", sp))
	wantCode(t, err, api.CodeForbidden)
}
