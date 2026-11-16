package e2e

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/internal/fleet/fleettest"
	"jailops.net/jailops/sdk/api"
)

// appFleet is one host with a project, PostgreSQL and nginx declared as apps,
// and the grants of examples/app-access-fleet.
func appFleet(t *testing.T) *fleettest.Env {
	t.Helper()
	e := fleettest.New(t, "appfleet", "db1")
	e.Write("shared/images/freebsd-15.yaml", "apiVersion: jailops/v1\nkind: Image\nmetadata:\n  name: freebsd-15\nspec:\n  os: freebsd\n  release: 15.1-RELEASE\n  arch: amd64\n  source: {type: pkgbase}\n  aliases: [stable]\n")
	e.Write("shared/networks/shop.yaml", "apiVersion: jailops/v1\nkind: Network\nmetadata:\n  name: shop\nspec:\n  ipv4: {subnet: 10.70.0.0/24, gateway: 10.70.0.1, range: 10.70.0.10-10.70.0.250}\n")
	e.Write("projects/shop.yaml", "apiVersion: jailops/v1\nkind: Project\nmetadata:\n  name: shop\nspec:\n  hosts: [db1]\n  networks: [{network: shop}]\n  storage: [{storage: default}]\n")
	app := func(name, def string) {
		e.Write("projects/shop/apps/"+name+".yaml", "apiVersion: jailops/v1\nkind: App\nmetadata:\n  name: "+name+"\nhosts: [db1]\nspec:\n  app: "+def+"\n  image: freebsd-15@stable\n")
	}
	app("db", "postgresql")
	app("web", "nginx")
	e.Write("projects/shop/app-access/db.yaml", "apiVersion: jailops/v1\nkind: AppAccess\nmetadata:\n  name: db\nhosts: [db1]\nspec:\n  grants:\n    - {source: \"jail:web\", database: shop}\n")
	e.Write("projects/shop/app-access/web.yaml", "apiVersion: jailops/v1\nkind: AppAccess\nmetadata:\n  name: web\nhosts: [db1]\nspec:\n  grants:\n    - {source: 203.0.113.0/24, ports: [\"80\"]}\n")
	return e
}

var connRE = regexp.MustCompile(`postgres://shop:([A-Za-z0-9]{32})@[^ \n]+`)

// Apps are installed and their grants allowed in one apply; the connection
// string of the new role is printed once, lands in no file sync writes, and a
// second apply changes nothing and makes no new password.
func TestAppsAndGrantsApplyOnce(t *testing.T) {
	e := appFleet(t)
	p := mustOK(t, run(t, e, "plan")).out
	for _, want := range []string{"create    App/shop/db", "install app postgresql as jail db", "create    AppAccess/shop/db from jail:web", "allow jail:web, database shop"} {
		contains(t, p, want)
	}
	ap := mustOK(t, run(t, e, "sync", "--apply")).out
	contains(t, ap, "0 failed")
	m := connRE.FindStringSubmatch(ap)
	if m == nil {
		t.Fatalf("no connection string in the apply output:\n%s", ap)
	}
	contains(t, ap, "shown once, stored nowhere")
	// nothing sync wrote holds it: the apply log, the state, the repository
	for _, dir := range []string{e.State, e.Dir} {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), m[1]) || strings.Contains(string(b), "postgres://") {
				t.Errorf("%s holds the connection string", p)
			}
			return nil
		})
	}
	c := client(t, e.Hosts["db1"]).Project("shop")
	ctx := context.Background()
	for _, j := range []string{"db", "web"} {
		jl, err := c.Jails().Get(ctx, j)
		if err != nil || jl.Metadata.Labels[api.LabelApp] == "" {
			t.Fatalf("%s: %v %+v", j, err, jl.Metadata)
		}
	}
	acc, err := c.Apps().Access(ctx, "db")
	if err != nil || len(acc.Grants) != 1 || acc.Grants[0].Source != "jail:web" || acc.Grants[0].Database != "shop" {
		t.Fatalf("%v %+v", err, acc)
	}
	again := mustOK(t, run(t, e, "plan")).out
	contains(t, again, "0 create, 0 update, 0 delete")
	if strings.Contains(again, "unmanaged") && strings.Contains(again, "Jail/shop/db") {
		t.Fatalf("an app's jail is reported as an undeclared jail:\n%s", again)
	}
	second := mustOK(t, run(t, e, "sync", "--apply")).out
	if strings.Contains(second, "postgres://") {
		t.Fatalf("a second apply made a new password:\n%s", second)
	}
	mustOK(t, run(t, e, "drift"))
}

// Changed ports are allowed again; a grant the document does not list is
// denied only with --prune.
func TestAppAccessUpdateAndPrune(t *testing.T) {
	e := appFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	ctx := context.Background()
	c := client(t, e.Hosts["db1"]).Project("shop")

	e.Write("projects/shop/app-access/web.yaml", "apiVersion: jailops/v1\nkind: AppAccess\nmetadata:\n  name: web\nhosts: [db1]\nspec:\n  grants:\n    - {source: 203.0.113.0/24, ports: [\"80\", \"443\"]}\n")
	p := mustOK(t, run(t, e, "plan")).out
	contains(t, p, "update    AppAccess/shop/web from 203.0.113.0/24")
	contains(t, p, "ports 80/tcp, declared 443/tcp,80/tcp")
	mustOK(t, run(t, e, "sync", "--apply"))
	acc, _ := c.Apps().Access(ctx, "web")
	if len(acc.Grants) != 1 || !slices.Equal(slices.Sorted(slices.Values(acc.Grants[0].Ports)), []string{"443/tcp", "80/tcp"}) {
		t.Fatalf("%+v", acc.Grants)
	}

	// a grant made by hand on an app whose AppAccess document sync applies
	if _, err := c.Apps().Allow(ctx, "web", api.AppAllow{Source: "198.51.100.7", Ports: []string{"80"}}); err != nil {
		t.Fatal(err)
	}
	p = mustOK(t, run(t, e, "plan")).out
	contains(t, p, "delete    AppAccess/shop/web from 198.51.100.7")
	ap := mustOK(t, run(t, e, "sync", "--apply")).out
	contains(t, ap, "pass --prune to delete")
	if acc, _ := c.Apps().Access(ctx, "web"); len(acc.Grants) != 2 {
		t.Fatalf("denied without --prune: %+v", acc.Grants)
	}
	mustOK(t, run(t, e, "sync", "--apply", "--prune"))
	if acc, _ := c.Apps().Access(ctx, "web"); len(acc.Grants) != 1 || acc.Grants[0].Source != "203.0.113.0/24" {
		t.Fatalf("%+v", acc.Grants)
	}
	contains(t, mustOK(t, run(t, e, "plan")).out, "0 create, 0 update, 0 delete")
}

// A jail of the app's name that runs another app is refused, never
// reinstalled; a changed database of a grant is a plan error.
func TestAppRefusalsAndErrors(t *testing.T) {
	e := appFleet(t)
	ctx := context.Background()
	c := client(t, e.Hosts["db1"])
	// the project and its network must exist before a jail can be installed by hand
	os.Remove(filepath.Join(e.Dir, "projects/shop/app-access/db.yaml"))
	os.Remove(filepath.Join(e.Dir, "projects/shop/apps/db.yaml"))
	mustOK(t, run(t, e, "sync", "--apply"))
	op, err := c.Project("shop").Apps().Install(ctx, "nginx", api.AppInstall{Jail: "db", Image: "freebsd-15@stable"})
	if err == nil {
		_, err = op.Wait(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	e.Write("projects/shop/apps/db.yaml", "apiVersion: jailops/v1\nkind: App\nmetadata:\n  name: db\nhosts: [db1]\nspec:\n  app: postgresql\n")
	p := mustOK(t, run(t, e, "plan")).out
	contains(t, p, "refuse")
	contains(t, p, "jail db runs app nginx, not postgresql")
	mustFail(t, run(t, e, "sync", "--apply"), "refusing")

	e2 := appFleet(t)
	mustOK(t, run(t, e2, "sync", "--apply"))
	e2.Write("projects/shop/app-access/db.yaml", "apiVersion: jailops/v1\nkind: AppAccess\nmetadata:\n  name: db\nhosts: [db1]\nspec:\n  grants:\n    - {source: \"jail:web\", database: other}\n")
	mustFail(t, run(t, e2, "plan"), "the database of a grant does not change")
}
