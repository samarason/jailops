package e2e

import (
	"context"
	"jailops.net/jailops/internal/fleet/fleettest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func TestPlanOnEmptyFleet(t *testing.T) {
	e := standardFleet(t)
	r := mustOK(t, run(t, e, "plan"))
	// Per host: 1 image, 2 networks, 1 address set, 1 policy, 1 target,
	// 1 backup policy and 1 project = 8 objects, plus one jail each.
	contains(t, r.out, "27 create, 0 update, 0 delete, 0 unchanged, 0 unmanaged")
	contains(t, r.out, "create    Jail/main/blog")
	// Planning wrote nothing.
	if _, ok := e.Hosts["web1"].Server.Network("internal"); ok {
		t.Fatal("plan created a network")
	}
	// sync without --apply is the same plan and also writes nothing.
	mustOK(t, run(t, e, "sync"))
	if _, ok := e.Hosts["web1"].Server.JailIn(fleettest.Project, "blog"); ok {
		t.Fatal("sync without --apply created a jail")
	}
}

func TestApplyThenZeroDiff(t *testing.T) {
	e := standardFleet(t)
	r := mustOK(t, run(t, e, "sync", "--apply"))
	contains(t, r.out, "27 change(s) applied, 0 failed")

	j := getJail(t, e.Hosts["web1"], "blog")
	if j.Metadata.ManagedBy != "sync:testfleet" {
		t.Fatalf("managed_by = %q", j.Metadata.ManagedBy)
	}
	if len(j.Spec.Network) != 1 || j.Spec.Network[0].IPv4 == "auto" || j.Spec.Network[0].IPv4 == "" {
		t.Fatalf("address was not allocated: %+v", j.Spec.Network)
	}
	if j.Metadata.Labels["tier"] != "web" {
		t.Fatalf("labels: %v", j.Metadata.Labels)
	}

	p := mustOK(t, run(t, e, "plan"))
	contains(t, p.out, "0 create, 0 update, 0 delete, 27 unchanged, 0 unmanaged")
	mustOK(t, run(t, e, "drift"))

	// The apply log exists, is JSONL, and names what was done without contents.
	logs, _ := filepath.Glob(filepath.Join(e.State, "apply-*-testfleet.log"))
	if len(logs) != 1 {
		t.Fatalf("apply logs: %v", logs)
	}
	b, _ := os.ReadFile(logs[0])
	for _, want := range []string{`"kind":"apply_start"`, `"kind":"change"`, `"kind":"apply_end"`} {
		contains(t, string(b), want)
	}
}

func TestDriftDetection(t *testing.T) {
	e := standardFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	mustOK(t, run(t, e, "drift"))

	// Someone edits a network on web2 behind the repository's back.
	c := client(t, e.Hosts["web2"])
	err := sdk.Modify(context.Background(), c.Networks(), "internal", func(n *api.Network) {
		n.Spec.IPv4.Range = "10.20.0.50-10.20.0.60"
	})
	if err != nil {
		t.Fatal(err)
	}
	r := mustFail(t, run(t, e, "drift"), "drift detected")
	if r.code != 1 {
		t.Fatalf("drift exit code = %d, want 1", r.code)
	}
	contains(t, r.out, "host web2")
	contains(t, r.out, "update    Network/internal")
	contains(t, r.out, "spec.ipv4.range")
	if strings.Contains(r.out, "host web1\n  update") {
		t.Fatal("web1 reported as drifted")
	}

	// sync repairs it and drift is clean again.
	mustOK(t, run(t, e, "sync", "--apply"))
	mustOK(t, run(t, e, "drift"))
}

func TestDriftOnUnreachableHostIsExit2(t *testing.T) {
	e := standardFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	e.Hosts["db1"].HTTP.Close()
	r := run(t, e, "drift")
	if r.code != 2 {
		t.Fatalf("exit %d, want 2\n%s", r.code, r.all())
	}
	contains(t, r.all(), "db1")
}

func TestRemovedFieldIsAppliedByHash(t *testing.T) {
	e := standardFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	// Remove a declared field. The live object still has a value for it, but
	// the spec hash changes, so sync notices.
	e.Write("shared/networks/internal.yaml", `apiVersion: jailops/v1
kind: Network
metadata:
  name: internal
spec:
  mtu: 1400
  ipv4:
    subnet: 10.20.0.0/24
    gateway: 10.20.0.1
    range: 10.20.0.10-10.20.0.100
`)
	mustOK(t, run(t, e, "sync", "--apply"))
	n, _ := e.Hosts["db1"].Server.Network("internal")
	if n.Spec.MTU != 1400 {
		t.Fatalf("mtu = %d", n.Spec.MTU)
	}
	e.Write("shared/networks/internal.yaml", `apiVersion: jailops/v1
kind: Network
metadata:
  name: internal
spec:
  ipv4:
    subnet: 10.20.0.0/24
    gateway: 10.20.0.1
    range: 10.20.0.10-10.20.0.100
`)
	r := mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "update    Network/internal")
	mustOK(t, run(t, e, "sync", "--apply"))
	n, _ = e.Hosts["db1"].Server.Network("internal")
	if n.Spec.MTU != 0 {
		t.Fatalf("mtu not removed: %d", n.Spec.MTU)
	}
}

func TestPruneCheckNeverDeletes(t *testing.T) {
	e := standardFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))

	// A network nobody declared and nobody owns, and one the fleet created
	// that is now removed from the repository.
	e.Hosts["web1"].Server.SeedNetwork(api.Network{
		Metadata: api.ObjectMeta{Name: "legacy"},
		Spec:     api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "192.0.2.0/24", Gateway: "192.0.2.1", Range: "192.0.2.10-192.0.2.20"}},
	})
	if err := os.Remove(filepath.Join(e.Dir, "shared/networks/dmz.yaml")); err != nil {
		t.Fatal(err)
	}

	r := mustOK(t, run(t, e, "prune-check", "--host", "web1"))
	contains(t, r.out, "owned, undeclared  Network/dmz")
	contains(t, r.out, "unmanaged          Network/legacy")
	if _, ok := e.Hosts["web1"].Server.Network("dmz"); !ok {
		t.Fatal("prune-check deleted dmz")
	}

	// sync --apply without --prune does not delete, and exits cleanly.
	r = mustOK(t, run(t, e, "sync", "--apply"))
	contains(t, r.out, "pass --prune")
	if _, ok := e.Hosts["web1"].Server.Network("dmz"); !ok {
		t.Fatal("sync deleted without --prune")
	}
	// A delete is refuse-worthy: --prune alone is not enough.
	mustFail(t, run(t, e, "sync", "--apply", "--prune"), "dangerous changes need --force")
	mustOK(t, run(t, e, "sync", "--apply", "--prune", "--force"))
	for _, h := range []string{"web1", "web2", "db1"} {
		if _, ok := e.Hosts[h].Server.Network("dmz"); ok {
			t.Fatalf("%s: owned dmz was not pruned", h)
		}
	}
	if _, ok := e.Hosts["web1"].Server.Network("legacy"); !ok {
		t.Fatal("an unowned network was deleted")
	}
	// An object owned by another fleet is also unmanaged and untouched.
	e.Hosts["web2"].Server.SeedNetwork(api.Network{
		Metadata: api.ObjectMeta{Name: "theirs", ManagedBy: "sync:other"},
		Spec:     api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "192.0.2.0/24", Gateway: "192.0.2.1", Range: "192.0.2.10-192.0.2.20"}},
	})
	mustOK(t, run(t, e, "sync", "--apply", "--prune", "--force"))
	if _, ok := e.Hosts["web2"].Server.Network("theirs"); !ok {
		t.Fatal("another fleet's object was deleted")
	}
}

func TestOwnershipRefusal(t *testing.T) {
	for _, owner := range []string{"", "sync:other"} {
		t.Run("owner="+owner, func(t *testing.T) {
			e := standardFleet(t)
			// Same name as a declared network, different content, not ours.
			e.Hosts["web1"].Server.SeedNetwork(api.Network{
				Metadata: api.ObjectMeta{Name: "internal", ManagedBy: owner},
				Spec:     api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "172.16.0.0/24", Gateway: "172.16.0.1", Range: "172.16.0.10-172.16.0.20"}},
			})
			r := mustOK(t, run(t, e, "plan"))
			contains(t, r.out, "refuse    Network/internal")
			r = mustFail(t, run(t, e, "sync", "--apply", "--force"), "does not own")
			contains(t, r.all(), "adopt --claim")
			n, _ := e.Hosts["web1"].Server.Network("internal")
			if n.Spec.IPv4.Subnet != "172.16.0.0/24" || n.Metadata.ManagedBy != owner {
				t.Fatalf("a foreign object was modified: %+v", n)
			}
			// Nothing at all was applied on any host: refusal is checked first.
			if _, ok := e.Hosts["web2"].Server.Network("internal"); ok {
				t.Fatal("apply proceeded despite a refusal")
			}
			mustFail(t, run(t, e, "drift"), "drift detected")
		})
	}
}

func TestDangerousChangeNeedsForce(t *testing.T) {
	e := standardFleet(t)
	mustOK(t, run(t, e, "sync", "--apply"))
	e.Write("projects/main/address-sets/office.yaml", "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: office\nspec:\n  addresses: []\n")
	r := mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "DANGER: address set would become empty")
	mustFail(t, run(t, e, "sync", "--apply"), "dangerous changes need --force")
	mustOK(t, run(t, e, "sync", "--apply", "--force"))
	mustOK(t, run(t, e, "drift"))
}

func TestHostSelectionAndGroups(t *testing.T) {
	e := standardFleet(t)
	e.Write("hosts/web1/host.yaml", "apiVersion: jailops/v1\nkind: Host\nmetadata:\n  name: web1\n  labels: {role: web, env: prod}\nspec:\n  url: "+e.Hosts["web1"].URL()+"\n")
	e.Write("hosts/web2/host.yaml", "apiVersion: jailops/v1\nkind: Host\nmetadata:\n  name: web2\n  labels: {role: web, env: staging}\nspec:\n  url: "+e.Hosts["web2"].URL()+"\n")
	e.Write("hosts/db1/host.yaml", "apiVersion: jailops/v1\nkind: Host\nmetadata:\n  name: db1\n  labels: {role: db, env: prod}\nspec:\n  url: "+e.Hosts["db1"].URL()+"\n")
	e.Write("groups/prod.yaml", "apiVersion: jailops/v1\nkind: HostGroup\nmetadata:\n  name: prod\nspec:\n  selector: {env: prod}\n")
	e.Write("groups/everything.yaml", "apiVersion: jailops/v1\nkind: HostGroup\nmetadata:\n  name: everything\nspec:\n  members: [\"@prod\", web2]\n")
	e.Write("projects/main/address-sets/prod-only.yaml", "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: prod-only\nhosts: [\"@prod\"]\nspec:\n  addresses: [{address: 192.0.2.1}]\n")

	mustOK(t, run(t, e, "validate"))
	mustOK(t, run(t, e, "sync", "--apply", "--host", "@everything"))
	for h, want := range map[string]bool{"web1": true, "web2": false, "db1": true} {
		_, err := client(t, e.Hosts[h]).Project(fleettest.Project).Firewall().AddressSets().Get(context.Background(), "prod-only")
		if (err == nil) != want {
			t.Fatalf("%s: prod-only present=%v, want %v (%v)", h, err == nil, want, err)
		}
	}
	// --host limits what is planned and applied.
	r := mustOK(t, run(t, e, "plan", "--host", "@prod"))
	if strings.Contains(r.out, "host web2") {
		t.Fatalf("web2 planned although only @prod was asked:\n%s", r.out)
	}
	mustFail(t, run(t, e, "plan", "--host", "@nope"), "unknown group")
}

func TestTemplatesAndHooks(t *testing.T) {
	e := standardFleet(t)
	e.Write("templates/web-base/manifest.yaml", `apiVersion: jailops/v1
kind: JailTemplate
metadata:
  name: web-base
spec:
  comment: a web jail
  jail:
    image: freebsd-15@stable
    storage: default
    network:
      - network: internal
        ipv4: auto
    firewall: {policies: [web]}
    resources: {memory: 1G, cpu: 1}
  after:
    - action: snapshot
      name: first
    - action: start
`)
	e.Write("projects/main/jails/shop.yaml", `apiVersion: jailops/v1
kind: Jail
hosts: [web1]
metadata:
  name: shop
  labels: {tier: web}
templates: [web-base]
spec:
  resources: {memory: 2G}
`)
	mustOK(t, run(t, e, "validate"))
	r := mustOK(t, run(t, e, "render", "--host", "web1"))
	contains(t, r.out, "memory: 2G")
	contains(t, r.out, "cpu: 1")
	mustOK(t, run(t, e, "sync", "--apply", "--host", "web1"))
	j := getJail(t, e.Hosts["web1"], "shop")
	if j.Spec.Resources.Memory != "2G" || j.Spec.Resources.CPU != 1 {
		t.Fatalf("template merge: %+v", j.Spec.Resources)
	}
	if j.Status.Power != api.PowerRunning {
		t.Fatalf("after hook start did not run: %s", j.Status.Power)
	}
	if snaps := e.Hosts["web1"].Server.Snapshots(fleettest.Project, "shop"); len(snaps) != 1 || snaps[0] != "first" {
		t.Fatalf("after hook snapshot: %v", snaps)
	}
	// Hooks run once, at creation: a second sync changes nothing.
	mustOK(t, run(t, e, "drift", "--host", "web1"))
}

func TestExecHookNeedsARunningJail(t *testing.T) {
	e := standardFleet(t)
	e.Write("projects/main/jails/exec.yaml", `apiVersion: jailops/v1
kind: Jail
hosts: [web1]
metadata:
  name: exec
after:
  - action: exec
    argv: [/usr/local/bin/setup, "--flag", "a b; rm -rf /"]
spec:
  image: freebsd-15@stable
  storage: default
  network: [{network: internal}]
  firewall: {policies: [web]}
`)
	mustOK(t, run(t, e, "validate"))
	mustFail(t, run(t, e, "sync", "--apply", "--host", "web1"), "is not running")
}

func TestFilenameMustEqualName(t *testing.T) {
	e := standardFleet(t)
	e.Write("shared/networks/lan.yaml", "apiVersion: jailops/v1\nkind: Network\nmetadata:\n  name: other\nspec:\n  ipv4: {subnet: 10.1.0.0/24, gateway: 10.1.0.1, range: 10.1.0.2-10.1.0.9}\n")
	r := mustFail(t, run(t, e, "validate"), "does not match the file name")
	contains(t, r.err, "lan")
	// The same rule for directories (templates) and hosts.
	e2 := standardFleet(t)
	e2.Write("templates/alpha/manifest.yaml", "apiVersion: jailops/v1\nkind: JailTemplate\nmetadata:\n  name: beta\nspec: {}\n")
	mustFail(t, run(t, e2, "validate"), "does not match the directory name")
}

func TestValidateReportsEveryReferenceError(t *testing.T) {
	e := standardFleet(t)
	e.Write("projects/main/jails/bad.yaml", `apiVersion: jailops/v1
kind: Jail
hosts: [web1]
metadata:
  name: bad
spec:
  image: nothing@stable
  network:
    - network: nowhere
  firewall: {policies: [missing]}
  env: {TOKEN: "secret:absent"}
`)
	r := mustFail(t, run(t, e, "validate"), "")
	for _, w := range []string{`unknown Image "nothing"`, `unknown Network "nowhere"`, `unknown FirewallPolicy`, `no secrets/absent.age`} {
		contains(t, r.err, w)
	}
	// Unknown keys are errors, not ignored.
	e2 := standardFleet(t)
	e2.Write("shared/networks/typo.yaml", "apiVersion: jailops/v1\nkind: Network\nmetadata:\n  name: typo\nspec:\n  ipv5: {}\n")
	mustFail(t, run(t, e2, "validate"), "unknown field")
}

func TestRiskWarnings(t *testing.T) {
	e := standardFleet(t)
	e.Write("projects/main/firewall-policies/open.yaml", `apiVersion: jailops/v1
kind: FirewallPolicy
metadata:
  name: open
spec:
  default_in: allow
  default_out: allow
  rules:
    - {action: allow, direction: in, proto: tcp, ports: ["22"]}
`)
	r := mustOK(t, run(t, e, "validate"))
	contains(t, r.out, "default_in is allow")
	contains(t, r.out, "allows inbound traffic from anywhere")
}

func TestAdoptAndClaim(t *testing.T) {
	e := fleetWithoutObjects(t)
	srv := e.Hosts["web1"].Server
	srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-15"}, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.0-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}})
	srv.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "lan"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.9.0.0/24", Gateway: "10.9.0.1", Range: "10.9.0.10-10.9.0.20"}}})
	srv.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: fleettest.Project}, Spec: api.ProjectSpec{
		Hosts:    []string{"web1"},
		Networks: []api.ProjectNetwork{{Network: "lan"}},
		Storage:  []api.ProjectStorage{{Storage: "default"}},
	}})
	srv.SeedFirewallPolicy(api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "base", Project: fleettest.Project}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}})
	srv.SeedJail(api.Jail{
		Metadata: api.ObjectMeta{Name: "old", Project: fleettest.Project, Labels: map[string]string{"tier": "web"}},
		Spec: api.JailSpec{Image: "freebsd-15@stable", Hostname: "old", Layout: api.LayoutThin, Storage: "default",
			Network: []api.NetworkAttach{{Network: "lan", IPv4: "10.9.0.12"}}, Firewall: api.FirewallAttach{Policies: []string{"base"}}},
	})
	// A foreign object is skipped.
	srv.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "theirs", ManagedBy: "sync:other"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.8.0.0/24", Gateway: "10.8.0.1", Range: "10.8.0.10-10.8.0.20"}}})

	r := mustOK(t, run(t, e, "adopt", "--host", "web1"))
	contains(t, r.out, "projects/main/jails/old.yaml")
	contains(t, r.out, `skip   web1 Network/theirs`)
	if _, err := os.Stat(filepath.Join(e.Dir, "hosts/web1/networks/theirs.yaml")); err == nil {
		t.Fatal("adopted another fleet's object")
	}
	mustOK(t, run(t, e, "validate"))

	// Not owned yet: the first sync refuses them.
	mustFail(t, run(t, e, "sync", "--apply"), "does not own")
	// adopt --claim writes nothing new (files exist) but marks ownership.
	e2 := run(t, e, "adopt", "--host", "web1", "--claim", "--overwrite")
	mustOK(t, e2)
	if j, _ := srv.JailIn(fleettest.Project, "old"); j.Metadata.ManagedBy != "sync:testfleet" {
		t.Fatalf("jail not claimed: %q", j.Metadata.ManagedBy)
	}
	r = mustOK(t, run(t, e, "plan"))
	contains(t, r.out, "0 create, 0 update, 0 delete, 5 unchanged, 1 unmanaged")
	mustOK(t, run(t, e, "drift"))
}

func fleetWithoutObjects(t *testing.T) *fleettestEnv {
	t.Helper()
	return newEnv(t, "testfleet", "web1")
}

func TestVersionAndCompletion(t *testing.T) {
	e := standardFleet(t)
	r := mustOK(t, run(t, e, "version"))
	contains(t, r.out, "jailops-sync test")
	r = mustOK(t, run(t, e, "completion", "bash"))
	contains(t, r.out, "jailops-sync")
	// Dynamic completion of --host lists hosts and groups.
	e.Write("groups/all.yaml", "apiVersion: jailops/v1\nkind: HostGroup\nmetadata:\n  name: all\nspec:\n  members: [web1]\n")
	r = mustOK(t, run(t, e, "__complete", "plan", "--host", ""))
	for _, w := range []string{"web1", "db1", "@all"} {
		contains(t, r.out, w)
	}
}
