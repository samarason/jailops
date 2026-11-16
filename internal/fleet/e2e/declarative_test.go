package e2e

import (
	"context"
	"strings"
	"testing"

	"jailops.net/jailops/internal/fleet/fleettest"
	"jailops.net/jailops/sdk/api"
)

func TestImageBuildFlagBuildsTheFirstGenerationOnce(t *testing.T) {
	e := newEnv(t, "buildfleet", "h1")
	e.Write("shared/images/base.yaml", `apiVersion: jailops/v1
kind: Image
metadata:
  name: base
build: true
spec:
  os: freebsd
  release: 15.1-RELEASE
  arch: amd64
  source: {type: pkgbase}
  aliases: [stable]
`)
	h := e.Hosts["h1"]
	count := func() int {
		n := 0
		for _, err := range client(t, h).Images().Generations(context.Background(), "base") {
			if err != nil {
				t.Fatal(err)
			}
			n++
		}
		return n
	}
	r := mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "create    Image/base")
	mustOK(t, run(t, e, "sync", "--apply"))
	if n := count(); n != 1 {
		t.Fatalf("generations after the first apply: %d", n)
	}
	// A second run changes nothing and builds nothing more.
	r = mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "in sync")
	mustOK(t, run(t, e, "sync", "--apply"))
	if n := count(); n != 1 {
		t.Fatalf("generations after the second apply: %d", n)
	}
	// build only makes sense on an image.
	e.Write("shared/networks/x.yaml", "apiVersion: jailops/v1\nkind: Network\nmetadata:\n  name: x\nbuild: true\nspec:\n  ipv4: {subnet: 10.1.0.0/24, gateway: 10.1.0.1, range: 10.1.0.2-10.1.0.9}\n")
	mustFail(t, run(t, e, "validate"), "build applies to images only")
}

// Every kind of the API that a user creates by CLI can be written as a file, and the fake accepts what sync sends:
// an IPv6 proxy network, a routed one, storage, a project with grants and quotas, a jail with volumes, host mounts
// and per-jail firewall, address sets, a backup target and a policy with a verify schedule.
func TestEveryDeclarativeObjectApplies(t *testing.T) {
	e := newEnv(t, "all", "h1")
	e.Write("hosts/h1/storage/bulk.yaml", "apiVersion: jailops/v1\nkind: Storage\nmetadata:\n  name: bulk\nspec:\n  dataset: tank/bulk\n  compression: zstd\n")
	e.Write("shared/images/base.yaml", "apiVersion: jailops/v1\nkind: Image\nmetadata:\n  name: base\nspec:\n  os: freebsd\n  release: 15.1-RELEASE\n  arch: amd64\n  source: {type: pkgbase}\n  aliases: [stable]\n")
	e.Write("shared/networks/proxy.yaml", `apiVersion: jailops/v1
kind: Network
metadata:
  name: proxy
spec:
  uplink: vtnet0
  ipv4: {subnet: 10.94.0.0/24, gateway: 10.94.0.1, range: 10.94.0.2-10.94.0.254, nat: true}
  ipv6:
    mode: proxy
    subnet: "2001:db8:1:2:100::/80"
    range: "2001:db8:1:2:100::10-2001:db8:1:2:100::ffff"
  dns: [1.1.1.1, 2606:4700:4700::1111]
`)
	e.Write("shared/networks/routed.yaml", `apiVersion: jailops/v1
kind: Network
metadata:
  name: routed
spec:
  uplink: vtnet0
  ipv6:
    mode: routed
    subnet: "2001:db8:abcd:1:1::/80"
    range: "2001:db8:abcd:1:1::10-2001:db8:abcd:1:1::ffff"
`)
	e.Write("shared/backup-targets/vault.yaml", "apiVersion: jailops/v1\nkind: BackupTarget\nmetadata:\n  name: vault\nspec:\n  kind: node\n  address: https://backup.example.test:8444\n  fingerprint: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n")
	e.Write("projects/p.yaml", "apiVersion: jailops/v1\nkind: Project\nmetadata:\n  name: p\nspec:\n  hosts: [h1]\n  networks: [{network: proxy}, {network: routed}]\n  storage: [{storage: bulk, quota: 2T}]\n  quotas: {jails: 5, cpu: 8, memory: 16G, pids: 4000, addresses: 100}\n  firewall_policies: [floor]\n  images: [base]\n")
	e.Write("projects/p/firewall-policies/floor.yaml", "apiVersion: jailops/v1\nkind: FirewallPolicy\nmetadata:\n  name: floor\nspec:\n  default_in: deny\n  default_out: allow\n")
	e.Write("projects/p/address-sets/admins.yaml", "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: admins\nspec:\n  addresses: [{address: 203.0.113.7}, {address: \"2001:db8:ffff::/48\"}]\n")
	e.Write("projects/p/backup-policies/nightly.yaml", "apiVersion: jailops/v1\nkind: BackupPolicy\nmetadata:\n  name: nightly\nspec:\n  selector: {backup: nightly}\n  targets: [vault]\n  schedule: \"17 2 * * *\"\n  retention: {daily: 7, weekly: 4, monthly: 6}\n  verify_schedule: \"30 4 * * 0\"\n  verify_mode: deep\n")
	e.Write("projects/p/volumes/data.yaml", "apiVersion: jailops/v1\nkind: Volume\nhosts: [h1]\nmetadata:\n  name: data\nspec:\n  storage: bulk\n  size: 1T\n  uid: 770\n  gid: 770\n  mode: \"0700\"\n")
	e.Write("projects/p/jails/db.yaml", `apiVersion: jailops/v1
kind: Jail
hosts: [h1]
start: true
metadata:
  name: db
  labels: {backup: nightly}
spec:
  image: base@stable
  storage: bulk
  network: [{network: proxy, ipv4: auto, ipv6: "2001:db8:1:2:100::80"}]
  resources: {cpu: 2, memory: 4G, pids: 500}
  volumes:
    - {volume: data, mount: /var/db/postgres}
`)
	r := mustOK(t, run(t, e, "validate"))
	contains(t, r.out, "ok:")
	mustOK(t, run(t, e, "sync", "--apply"))
	r = mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "0 create, 0 update, 0 delete")
	mustOK(t, run(t, e, "drift"))

	c := client(t, e.Hosts["h1"])
	n, err := c.Networks().Get(context.Background(), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if n.Spec.IPv6 == nil || n.Spec.IPv6.Mode != api.IPv6Proxy || n.Metadata.ManagedBy != "sync:all" {
		t.Fatalf("%+v", n.Spec.IPv6)
	}
	j := getJailIn(t, e, "p", "db")
	if len(j.Spec.Volumes) != 1 || j.Spec.Network[0].IPv6 != "2001:db8:1:2:100::80" {
		t.Fatalf("%+v", j.Spec)
	}
	// the volume is made before the jail that attaches it, with the owner and the mode of the file
	v, err := c.Project("p").Volumes().Get(context.Background(), "data")
	if err != nil || v.Spec.UID != 770 || v.Spec.Mode != "0700" || v.Spec.Size != "1T" || v.Metadata.ManagedBy != "sync:all" {
		t.Fatalf("%+v %v", v, err)
	}
	if !strings.Contains(r.out, "in sync") && !strings.Contains(r.out, "unchanged") {
		t.Fatalf("%s", r.out)
	}
}

func TestAdoptWarnsAboutHostProfiles(t *testing.T) {
	e := newEnv(t, "adoptp", "h1")
	srv := e.Hosts["h1"].Server
	srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-15"}, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}})
	srv.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "legacy"}, Spec: api.ProjectSpec{}})
	srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "old", Project: "legacy"},
		Spec: api.JailSpec{Image: "freebsd-15@stable", Storage: "default", Profiles: []string{"small"}}})
	r := mustOK(t, run(t, e, "adopt", "--host", "h1"))
	contains(t, r.out, "lists the host's profiles [small]")
}

// A policy or an address set may name a jail that the same repository declares: jail:NAME is read at every render, so
// the policy is made before the jail (sets, policies, jails is the order of an apply) and a fresh host takes the whole
// repository in one apply.
func TestAPolicyNamesAJailThatIsMadeLater(t *testing.T) {
	e := fleettest.New(t, "order", "h1")
	e.StandardObjects()
	e.Write("projects/"+fleettest.Project+"/firewall-policies/pg.yaml", `apiVersion: jailops/v1
kind: FirewallPolicy
metadata:
  name: pg
spec:
  default_in: deny
  default_out: allow
  rules:
    - {name: from-app, action: allow, direction: in, proto: tcp, ports: ["5432"], from: ["jail:app"], comment: the application}
`)
	e.Write("projects/"+fleettest.Project+"/address-sets/clients.yaml", "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: clients\nspec:\n  addresses: [{address: \"jail:app\", comment: the application}]\n")
	e.Jail("h1", "app", "tier: app", "")
	r := mustOK(t, run(t, e, "validate"))
	contains(t, r.out, "ok:")
	mustOK(t, run(t, e, "sync", "--apply"))
	c := client(t, e.Hosts["h1"])
	if p, err := c.Project(fleettest.Project).Firewall().Policies().Get(context.Background(), "pg"); err != nil || p.Spec.Rules[0].From[0] != "jail:app" {
		t.Fatalf("the policy that names a jail made later is not there: %v %+v", err, p)
	}
	if _, err := c.Project(fleettest.Project).Firewall().AddressSets().Get(context.Background(), "clients"); err != nil {
		t.Fatalf("the set that holds a jail made later is not there: %v", err)
	}
	getJailIn(t, e, fleettest.Project, "app")
	r = mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "0 create, 0 update, 0 delete")
}
