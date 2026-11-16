package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/internal/fleet/fleettest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

const netYAML = `apiVersion: jailops/v1
kind: Network
metadata:
  name: %s
spec:
  ipv4:
    subnet: %s
    gateway: %s
    range: %s
`

// projectFleet is two hosts, a shared network and a dedicated one, storage
// "fast" on each host, a project "web" spanning both with a mandatory
// firewall policy, a shared profile and one jail on web1.
func projectFleet(t *testing.T) *fleettest.Env {
	t.Helper()
	e := fleettest.New(t, "testfleet", "web1", "web2")
	e.Write("shared/images/freebsd-15.yaml", "apiVersion: jailops/v1\nkind: Image\nmetadata:\n  name: freebsd-15\nspec:\n  os: freebsd\n  release: 15.0-RELEASE\n  arch: amd64\n  source: {type: pkgbase}\n  aliases: [stable]\n")
	e.Write("shared/networks/web.yaml", fmt.Sprintf(netYAML, "web", "10.50.0.0/24", "10.50.0.1", "10.50.0.10-10.50.0.200"))
	e.Write("shared/networks/db.yaml", fmt.Sprintf(netYAML, "db", "10.60.0.0/24", "10.60.0.1", "10.60.0.10-10.60.0.200"))
	for _, h := range []string{"web1", "web2"} {
		e.Write("hosts/"+h+"/storage/fast.yaml", "apiVersion: jailops/v1\nkind: Storage\nmetadata:\n  name: fast\nspec:\n  dataset: tank/jailops-fast\n")
	}
	e.Write("projects/web.yaml", `apiVersion: jailops/v1
kind: Project
metadata:
  name: web
spec:
  hosts: [web1, web2]
  networks:
    - {network: web}
  storage:
    - {storage: fast, quota: 50G}
  quotas: {jails: 5}
  firewall_policies: [base]
  images: [freebsd-15]
`)
	e.Write("projects/web/firewall-policies/base.yaml", "apiVersion: jailops/v1\nkind: FirewallPolicy\nmetadata:\n  name: base\nspec:\n  default_in: deny\n  default_out: allow\n")
	e.Write("profiles/small.yaml", `apiVersion: jailops/v1
kind: Profile
metadata:
  name: small
spec:
  resources: {memory: 1G, cpu: 1}
  network:
    - {name: eth0, network: web, ipv4: auto}
  boot: {autostart: true}
`)
	e.Write("projects/web/jails/blog.yaml", `apiVersion: jailops/v1
kind: Jail
metadata:
  name: blog
  labels: {tier: web}
hosts: [web1]
spec:
  image: freebsd-15@stable
  storage: fast
  profiles: [small]
  resources: {memory: 2G}
  network:
    - {name: eth0, mtu: 1400}
`)
	return e
}

func TestProjectSpansHostsAndConverges(t *testing.T) {
	e := projectFleet(t)
	r := mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "projects\n  web\n    web1")
	contains(t, r.out, "will be created")
	contains(t, r.out, "create    Jail/web/blog")

	mustOK(t, run(t, e, "sync", "--apply"))
	var uuids []string
	for _, h := range []string{"web1", "web2"} {
		p, err := client(t, e.Hosts[h]).Projects().Get(context.Background(), "web")
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		if p.Metadata.ManagedBy != "sync:testfleet" {
			t.Fatalf("%s: managed_by %q", h, p.Metadata.ManagedBy)
		}
		if !slices.Equal(p.Spec.FirewallPolicies, []string{"base"}) {
			t.Fatalf("%s: the mandatory policy was not set after its policy existed", h)
		}
		if len(p.Spec.Hosts) != 0 {
			t.Fatalf("%s: the fleet host list leaked into the host copy", h)
		}
		uuids = append(uuids, p.Metadata.UUID)
	}
	if uuids[0] == "" || uuids[0] != uuids[1] {
		t.Fatalf("project UUIDs differ across hosts: %v", uuids)
	}
	// The jail lives in the project, with the profile expanded and its own value on top.
	j, err := client(t, e.Hosts["web1"]).Project("web").Jails().Get(context.Background(), "blog")
	if err != nil {
		t.Fatal(err)
	}
	if j.Spec.Resources.Memory != "2G" || j.Spec.Resources.CPU != 1 || !j.Spec.Boot.Autostart || len(j.Spec.Profiles) != 0 {
		t.Fatalf("profile expansion: %+v", j.Spec)
	}
	if len(j.Spec.Network) != 1 || j.Spec.Network[0].MTU != 1400 || j.Spec.Network[0].Network != "web" {
		t.Fatalf("devices merge by name: %+v", j.Spec.Network)
	}
	if _, err := client(t, e.Hosts["web2"]).Project("web").Jails().Get(context.Background(), "blog"); err == nil {
		t.Fatal("the jail leaked to web2")
	}
	r = mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "web1         in sync")
	mustOK(t, run(t, e, "drift"))
}

func TestMissingNetworkOrStorageIsAPlanErrorBeforeAnythingIsApplied(t *testing.T) {
	e := projectFleet(t)
	if err := os.Remove(filepath.Join(e.Dir, "hosts/web2/storage/fast.yaml")); err != nil {
		t.Fatal(err)
	}
	r := mustFail(t, run(t, e, "sync", "--apply"), `host web2 lacks storage "fast"`)
	contains(t, r.out, "web2")
	for _, h := range []string{"web1", "web2"} {
		if _, ok := e.Hosts[h].Server.Network("web"); ok {
			t.Fatalf("%s: something was applied despite the plan error", h)
		}
	}
	mustFail(t, run(t, e, "plan"), "lacks storage")
}

func TestOfflineProjectHostIsReported(t *testing.T) {
	e := projectFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	e.Hosts["web2"].HTTP.Close()
	r := mustFail(t, run(t, e, "plan"), "")
	contains(t, r.out, "OFFLINE")
	contains(t, r.out, "web2")
	if r := run(t, e, "drift"); r.code != 2 {
		t.Fatalf("drift exit %d, want 2", r.code)
	}
	r = mustFail(t, run(t, e, "doctor"), "check(s) failed")
	contains(t, r.out, "FAIL  project web on web2")
}

func TestManualChangeShowsAsDriftAndIsReverted(t *testing.T) {
	e := projectFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	c := client(t, e.Hosts["web1"]).Project("web")
	if err := sdk.Modify(context.Background(), c.Jails(), "blog", func(j *api.Jail) { j.Spec.Resources.Memory = "8G" }); err != nil {
		t.Fatal(err)
	}
	p := mustOK(t, run(t, e, "plan", "--host", "web1"))
	contains(t, p.out, "update    Jail/web/blog")
	contains(t, p.out, `spec.resources.memory: live "8G", want "2G"`)
	mustFail(t, run(t, e, "drift"), "drift detected")
	mustOK(t, run(t, e, "sync", "--apply"))
	mustOK(t, run(t, e, "drift"))
}

func TestProjectIsDeletedOnlyWhenEmptyAndOwned(t *testing.T) {
	e := projectFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	// A jail nobody owns appears in the project.
	e.Hosts["web2"].Server.SeedJail(api.Jail{
		Metadata: api.ObjectMeta{Name: "squatter", Project: "web"},
		Spec:     api.JailSpec{Image: "freebsd-15@stable", Storage: "fast"},
	})
	// The repository drops the project, its policy and its jail.
	for _, p := range []string{"projects/web.yaml", "projects/web", "profiles/small.yaml"} {
		if err := os.RemoveAll(filepath.Join(e.Dir, p)); err != nil {
			t.Fatal(err)
		}
	}
	r := mustOK(t, run(t, e, "prune-check"))
	contains(t, r.out, "owned, undeclared  Jail/web/blog")
	contains(t, r.out, "blocked            Project/web")
	contains(t, r.out, "Remaining: Jail/squatter")
	mustFail(t, run(t, e, "drift"), "drift detected")

	mustOK(t, run(t, e, "sync", "--apply", "--prune", "--force"))
	if _, err := client(t, e.Hosts["web1"]).Projects().Get(context.Background(), "web"); err == nil {
		t.Fatal("web1: the emptied, owned project should have been deleted")
	}
	if _, err := client(t, e.Hosts["web2"]).Projects().Get(context.Background(), "web"); err != nil {
		t.Fatalf("web2: a project that still holds a foreign jail must stay: %v", err)
	}
	if _, ok := e.Hosts["web2"].Server.JailIn("web", "squatter"); !ok {
		t.Fatal("a foreign jail was deleted")
	}
}

func TestAdoptCoversProjectsAndStorage(t *testing.T) {
	e := fleettest.New(t, "testfleet", "web1")
	srv := e.Hosts["web1"].Server
	srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-15"}, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.0-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}})
	srv.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "lan"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.9.0.0/24", Gateway: "10.9.0.1", Range: "10.9.0.10-10.9.0.20"}}})
	srv.SeedStorage(api.Storage{Metadata: api.ObjectMeta{Name: "fast"}, Spec: api.StorageSpec{Dataset: "tank/fast"}})
	srv.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "legacy"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "lan"}},
		Storage:  []api.ProjectStorage{{Storage: "fast"}},
	}})
	srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "old", Project: "legacy"},
		Spec: api.JailSpec{Image: "freebsd-15@stable", Storage: "fast", Layout: api.LayoutThin, Hostname: "old",
			Network: []api.NetworkAttach{{Network: "lan", IPv4: "10.9.0.12"}}}})

	r := mustOK(t, run(t, e, "adopt", "--host", "web1", "--claim"))
	for _, w := range []string{"projects/legacy.yaml", "hosts/web1/storage/fast.yaml", "projects/legacy/jails/old.yaml", "claimed web1 Project/legacy"} {
		contains(t, r.out, w)
	}
	if strings.Contains(r.out, "Project/default") || strings.Contains(r.out, "Storage/default") {
		t.Fatalf("host-owned built-ins were adopted:\n%s", r.out)
	}
	mustOK(t, run(t, e, "validate"))
	r = mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "0 create, 0 update, 0 delete, 5 unchanged, 0 unmanaged")
	mustOK(t, run(t, e, "drift"))
}

func TestDoctorReportsIdentitiesOfUndefinedProjects(t *testing.T) {
	e := projectFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	srv := e.Hosts["web1"].Server
	srv.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "ghost"}, Spec: api.ProjectSpec{}})
	c := client(t, e.Hosts["web1"])
	if _, err := c.Certificates().Create(context.Background(), api.Certificate{
		Metadata: api.ObjectMeta{Name: "laptop"},
		Spec:     api.CertificateSpec{Fingerprint: strings.Repeat("ab", 32), Permission: "operator", Kind: "client", Projects: []string{"web", "ghost"}},
	}); err != nil {
		t.Fatal(err)
	}
	r := mustOK(t, run(t, e, "doctor", "--host", "web1"))
	contains(t, r.out, `certificate "laptop" is scoped to project "ghost", which the fleet does not define`)
	if strings.Contains(r.out, `project "web", which`) {
		t.Fatal("a defined project was reported")
	}
	// Sync never touches identities.
	mustOK(t, run(t, e, "drift"))
}
