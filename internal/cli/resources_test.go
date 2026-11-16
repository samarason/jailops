package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

func TestImages(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("image", "create", "alpine-3", "--os", "linux", "--release", "3.22", "--source-type", "minirootfs", "--alias", "latest")
	tr.do("", "image", "create", "bad")
	tr.ok("image", "list")
	tr.ok("image", "show", "freebsd-15")
	tr.ok("image", "build", "freebsd-15")
	tr.ok("image", "generation", "list", "freebsd-15")
	tr.ok("image", "build", "freebsd-15", "--dry-run")
	tr.ok("image", "build", "freebsd-15", "--from-generation", "g1")
	tr.do("", "image", "build", "freebsd-15", "--from-generation", "x")
	tr.ok("image", "generation", "list", "freebsd-15", "-o", "name")
	tr.ok("image", "alias", "add", "freebsd-15", "edge")                            // newest
	tr.ok("image", "alias", "add", "freebsd-15", "stable", "--generation", "g1")    // pin
	tr.do("", "image", "alias", "add", "freebsd-15", "stable", "--generation", "9") // no such generation
	tr.do("", "image", "alias", "add", "freebsd-15", "stable", "--generation", "x")
	tr.ok("image", "show", "freebsd-15", "-o", "json")
	tr.ok("image", "alias", "remove", "-y", "freebsd-15", "edge")
	tr.do("", "image", "alias", "remove", "-y", "freebsd-15", "edge") // already gone
	tr.ok("image", "list", "-o", "name")
	tr.ok("jail", "create", "web", "--image", "freebsd-15#g1", "--network", "lan", "--storage", "default")
	tr.do("", "image", "generation", "delete", "-y", "freebsd-15", "1") // in use
	tr.ok("image", "alias", "add", "freebsd-15", "latest")              // newest (g3)
	tr.ok("image", "generation", "delete", "-y", "freebsd-15", "3")     // the alias that pointed at it moves to g2
	tr.ok("image", "show", "freebsd-15")
	tr.do("", "image", "delete", "-y", "freebsd-15") // in use by web
	tr.ok("image", "delete", "-y", "alpine-3")
	// an image with generations and aliases is deleted as a whole once no jail uses it
	tr.ok("jail", "delete", "--confirm-data-loss", "web")
	tr.ok("image", "delete", "-y", "freebsd-15")
	tr.ok("image", "list", "-o", "name")
	tr.golden("images")
	if im, ok := collectImages(t, h); ok && len(im) != 0 {
		t.Fatalf("images: %d", len(im))
	}
}

func TestImageUpgrade(t *testing.T) {
	h := newHarness(t)
	h.seed()
	// A second project with a jail on the same image: an image upgrade moves the jails of every project.
	h.srv.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "shop"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "lan"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}})
	h.srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "api", Project: "shop"}, Spec: api.JailSpec{Image: "freebsd-15@stable", Storage: "default"}})
	tr := h.transcript()
	tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	tr.ok("jail", "create", "pin", "--image", "freebsd-15#g1", "--network", "lan", "--storage", "default")
	before := len(h.mutations())
	tr.ok("image", "upgrade", "freebsd-15", "--dry-run")
	var u api.ImageUpgrade
	_ = json.Unmarshal(h.lastBody("POST", "/api/v1/images/freebsd-15/upgrade"), &u)
	if !u.DryRun || u.Project != "" || len(h.mutations()) != before+1 {
		t.Fatalf("dry-run request: %+v %v", u, h.mutations())
	}
	if j, _ := h.srv.JailIn("main", "web"); j.Status.Generation != "g1" {
		t.Fatalf("dry-run moved the jail: %+v", j.Status)
	}
	tr.ok("image", "upgrade", "freebsd-15")
	if j, _ := h.srv.JailIn("shop", "api"); j.Status.Generation != "g2" {
		t.Fatalf("the other project's jail did not move: %+v", j.Status)
	}
	tr.ok("image", "upgrade", "freebsd-15", "--project", "shop", "-o", "json")
	_ = json.Unmarshal(h.lastBody("POST", "/api/v1/images/freebsd-15/upgrade"), &u)
	if u.Project != "shop" {
		t.Fatalf("request: %+v", u)
	}
	if j, _ := h.srv.JailIn("main", "web"); j.Status.Generation != "g2" {
		t.Fatalf("--project shop moved a jail of main: %+v", j.Status)
	}
	tr.ok("image", "upgrade", "freebsd-15", "--no-jails")
	h.srv.SeedImageCurrent("freebsd-15", true)
	tr.ok("image", "upgrade", "freebsd-15")
	h.srv.SeedImageCurrent("freebsd-15", false)
	h.srv.SeedUpdateFailure("main", "web", true)
	tr.do("", "image", "upgrade", "freebsd-15") // web fails: the jails after it are not attempted, exit 1
	tr.do("", "image", "upgrade", "freebsd-15", "--project", "nope")
	tr.do("", "image", "upgrade", "nope")
	tr.ok("image", "upgrade", "freebsd-15", "--no-wait", "--no-jails")
	tr.ok("image", "generation", "list", "freebsd-15")
	tr.golden("image_upgrade")
}

func collectImages(t *testing.T, h *harness) ([]api.Image, bool) {
	out, _, code := h.run("", "image", "list", "-o", "json")
	if code != 0 {
		return nil, false
	}
	var im []api.Image
	if err := json.Unmarshal([]byte(out), &im); err != nil {
		t.Fatal(err)
	}
	return im, true
}

func TestNetworks(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("network", "create", "dmz", "--subnet", "10.30.0.0/24", "--gateway", "10.30.0.1", "--range", "10.30.0.10-10.30.0.12", "--nat", "--dns", "10.30.0.1", "--uplink", "em1")
	tr.do("", "network", "create", "bad", "--subnet", "nonsense", "--gateway", "10.30.0.1", "--range", "a-b")
	tr.do("", "network", "create", "short")
	tr.ok("network", "list")
	tr.ok("network", "grant", "dmz", "--project", "main")
	tr.do("", "network", "grant", "lan", "--project", "other") // no such project
	tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--storage", "default", "--network", "dmz")
	tr.ok("jail", "create", "db", "--image", "freebsd-15@stable", "--storage", "default", "--network", "dmz")
	tr.ok("network", "leases", "dmz")
	tr.ok("network", "leases", "dmz", "-o", "json")
	tr.ok("network", "show", "dmz", "-o", "yaml")
	// The fake picks which user to name from a map; one user keeps the output stable.
	tr.ok("network", "create", "solo", "--subnet", "10.50.0.0/24", "--gateway", "10.50.0.1", "--range", "10.50.0.5-10.50.0.9")
	tr.ok("network", "grant", "solo", "--project", "main")
	tr.ok("jail", "create", "only", "--image", "freebsd-15@stable", "--storage", "default", "--network", "solo")
	tr.do("", "network", "delete", "-y", "solo") // busy
	tr.do("", "network", "delete", "-y", "lan")  // granted to a project
	tr.ok("network", "revoke", "lan", "--project", "main")
	tr.ok("network", "delete", "-y", "lan")
	f := writeFile(t, h.dir, "net.yaml", "kind: Network\nmetadata: {name: viafile}\nspec:\n  ipv4: {subnet: 10.40.0.0/24, gateway: 10.40.0.1, range: 10.40.0.5-10.40.0.9}\n", 0o644)
	tr.ok("network", "create", "-f", f)
	tr.ok("network", "edit", "viafile", "-f", writeFile(t, h.dir, "net2.yaml", "ipv4: {subnet: 10.40.0.0/24, gateway: 10.40.0.1, range: 10.40.0.5-10.40.0.30}\nmtu: 1400\n", 0o644))
	tr.ok("network", "show", "viafile")
	tr.ok("network", "create", "sw", "--ipv4", "10.94.0.1/24", "--uplink", "em0", "--ipv6", "2001:db8:1:2:100::/80", "--ipv6-mode", "proxy")
	tr.ok("network", "show", "sw", "-o", "yaml")
	tr.do("", "network", "create", "badmode", "--ipv4", "10.95.0.1/24", "--ipv6", "2001:db8:1:2:200::/80", "--ipv6-mode", "bogus")
	tr.do("", "network", "create", "nomode", "--ipv4", "10.96.0.1/24", "--ipv6-mode", "proxy")
	tr.golden("networks")
}

func TestFirewall(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("firewall", "address-set", "create", "office", "--address", "192.0.2.0/24", "--address", "198.51.100.7")
	// a set is made empty and filled one member at a time, like a policy and its rules
	tr.ok("firewall", "address-set", "create", "hq", "--comment", "the office")
	tr.ok("firewall", "address-set", "add", "hq", "192.0.2.9", "--comment", "the office network")
	tr.ok("firewall", "address-set", "add", "hq", "192.0.2.9", "192.0.2.10")
	tr.do("", "firewall", "address-set", "add", "hq", "not-an-address")
	tr.ok("firewall", "address-set", "show", "hq", "-o", "yaml")
	tr.ok("firewall", "address-set", "show", "hq")
	tr.do("", "firewall", "address-set", "remove", "hq", "192.0.2.77")
	tr.ok("firewall", "address-set", "remove", "hq", "192.0.2.10")
	tr.ok("firewall", "policy", "create", "documented", "--default-in", "deny", "--default-out", "allow", "--comment", "the public web server")
	tr.ok("firewall", "rule", "add", "documented", "in", "--action", "allow", "--proto", "tcp", "--port", "80,443", "--comment", "the site")
	tr.ok("firewall", "rule", "add", "documented", "in", "--action", "allow", "--proto", "tcp", "--from", "set:hq", "--port", "22", "--comment", "ssh from the office")
	tr.ok("firewall", "policy", "show", "documented", "-o", "yaml")
	tr.ok("firewall", "policy", "show", "documented")
	// a rule can be switched off without deleting it: it keeps its number and says so
	tr.ok("firewall", "policy", "create", "switchable")
	tr.ok("firewall", "rule", "add", "switchable", "in", "--action", "allow", "--proto", "tcp", "--port", "80", "--comment", "the site")
	tr.ok("firewall", "rule", "add", "switchable", "in", "--action", "allow", "--proto", "tcp", "--port", "22", "--disabled", "--comment", "ssh, switched off")
	tr.ok("firewall", "rule", "add", "switchable", "in", "--action", "deny", "--proto", "tcp", "--port", "23", "--disabled")
	tr.ok("firewall", "policy", "show", "switchable")
	tr.ok("firewall", "policy", "show", "switchable", "-o", "yaml")
	tr.do("", "firewall", "policy", "create", "nodefaults")
	tr.ok("firewall", "policy", "create", "web", "--default-in", "deny", "--default-out", "allow")
	tr.ok("firewall", "rule", "add", "web", "in", "--action", "allow", "--proto", "tcp", "--port", "80,443")
	tr.ok("firewall", "rule", "add", "web", "in", "--action", "allow", "--proto", "tcp", "--from", "set:office", "--port", "22", "--log")
	tr.ok("firewall", "rule", "add", "web", "in", "--action", "allow", "--proto", "tcp", "--redirect", "8080:80")
	tr.do("", "firewall", "rule", "add", "web", "in")
	tr.do("", "firewall", "rule", "add", "web", "in", "--action", "allow", "--proto", "bogus")
	tr.ok("firewall", "policy", "list")
	tr.ok("firewall", "policy", "show", "web")
	tr.ok("firewall", "address-set", "list")
	tr.ok("firewall", "address-set", "show", "office", "-o", "json")

	good := writeFile(t, h.dir, "good.yaml", `kind: FirewallPolicy
metadata: {name: p1}
spec:
  default_in: deny
  default_out: allow
  rules:
    - {action: allow, direction: in, proto: tcp, ports: ["22", "8000-8100"], from: ["set:office", "10.0.0.0/8", "tag:admin"]}
---
kind: AddressSet
metadata: {name: office}
spec: {addresses: [{address: "192.0.2.0/24", comment: "the office"}], comment: "who works from the office"}
`, 0o644)
	badf := writeFile(t, h.dir, "bad.yaml", `kind: FirewallPolicy
metadata: {name: p2}
spec:
  default_in: maybe
  rules:
    - {action: permit, direction: sideways, proto: tcp, ports: ["99999"], from: ["300.1.1.1", "set:nowhere"]}
    - {action: allow, direction: in, ports: ["80"]}
    - {action: allow, direction: out, proto: tcp, redirect: {host_port: 80, jail_port: 80}}
  raw: "block all"
---
kind: AddressSet
metadata: {name: a}
spec: {addresses: ["10.0.0.0/8", "nope", "set:b"]}
---
kind: AddressSet
metadata: {name: b}
spec: {addresses: ["set:a"]}
`, 0o644)
	tr.ok("firewall", "validate", "-f", good)
	tr.ok("firewall", "validate", "-f", good, "--offline")
	_, _, code := tr.do("", "firewall", "validate", "-f", badf)
	if code != 2 {
		t.Fatalf("validate bad: %d", code)
	}
	tr.do("", "firewall", "validate", "-f", badf, "-o", "json")
	tr.do("", "firewall", "validate")
	tr.do("", "firewall", "validate", "-f", writeFile(t, h.dir, "j.yaml", "kind: Jail\nmetadata: {name: x}\nspec: {}\n", 0o644))
	tr.ok("firewall", "policy", "edit", "web", "-f", writeFile(t, h.dir, "p.yaml", "default_in: allow\nrules: []\n", 0o644))
	tr.ok("firewall", "policy", "delete", "-y", "web")
	tr.ok("firewall", "address-set", "delete", "-y", "office")
	tr.golden("firewall")
}

// A jail and a project have several firewall policies, given in order: --firewall-policy is repeatable on create and on
// project set, config sets the list, and info and show print it in the order it is rendered.
func TestSeveralFirewallPolicies(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	for _, n := range []string{"floor", "monitoring", "postgres", "ssh-office"} {
		tr.ok("firewall", "policy", "create", n)
		tr.ok("firewall", "rule", "add", n, "in", "--action", "allow", "--proto", "tcp", "--port", "22", "--comment", "ssh")
	}
	tr.ok("jail", "create", "db", "--image", "freebsd-15@stable", "--storage", "default", "--network", "lan",
		"--firewall-policy", "postgres", "--firewall-policy", "ssh-office")
	tr.ok("config", "get", "db", "firewall.policies")
	tr.ok("config", "set", "db", "firewall.policies", "ssh-office,postgres")
	tr.ok("config", "get", "db", "firewall.policies")
	tr.ok("project", "set", "main", "--firewall-policy", "floor", "--firewall-policy", "monitoring")
	tr.ok("project", "show", "main")
	tr.ok("jail", "info", "db")
	tr.ok("jail", "info", "db", "-o", "json")
	tr.ok("project", "set", "main", "--firewall-policy", "")
	tr.ok("project", "show", "main")
	tr.golden("firewall_policies")
	// the values of the key complete to the names of the policies, also after a comma and in KEY=VALUE
	for args, want := range map[string]string{
		"config set db firewall.policies ":           "postgres",
		"config set db firewall.policies postgres,s": "postgres,ssh-office",
		"config set db firewall.policies=ssh":        "firewall.policies=ssh-office",
	} {
		out, _, code := h.run("", append([]string{"__complete"}, strings.Split(args, " ")...)...)
		if code != 0 || !strings.Contains(out, want+"\n") {
			t.Errorf("complete %q: %d %q lacks %q", args, code, out, want)
		}
	}
}

func TestBackup(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedBackup(api.Backup{
		Metadata: api.ObjectMeta{Name: "20260101020000-ab12cd34", Project: "main"},
		Spec: api.BackupSpec{Jail: "web", JailUUID: "11111111-2222-4333-8444-555555555555", Target: "nightly", Snapshot: "20260101020000-ab12cd34",
			Bundle: api.RestoreBundle{Spec: api.JailSpec{Image: "freebsd-15@stable", Network: []api.NetworkAttach{{Network: "lan", IPv4: "10.20.0.15"}}}}},
		Status: api.BackupStatus{Bytes: 5 << 20, NewBytes: 1 << 20, Verified: true},
	})
	h.srv.SeedBackup(api.Backup{
		Metadata: api.ObjectMeta{Name: "20260102020000-ee00ff11", Project: "main"},
		Spec:     api.BackupSpec{Jail: "db", Target: "usb", Snapshot: "20260102020000-ee00ff11", Bundle: api.RestoreBundle{Spec: api.JailSpec{Image: "freebsd-15@stable"}}},
		Status:   api.BackupStatus{Bytes: 100, Failed: true},
	})
	tr := h.transcript()
	tr.ok("backup", "target", "create", "nightly", "--kind", "node", "--url", "https://b.example:8443", "--fingerprint", "abcd")
	tr.ok("backup", "target", "list")
	tr.ok("backup", "policy", "create", "nightly", "--selector", "env=prod", "--target", "nightly", "--schedule", "0 2 * * *", "--keep-daily", "14", "--keep-weekly", "8")
	tr.do("", "backup", "policy", "create", "x", "--target", "nightly")
	tr.ok("backup", "policy", "list")
	tr.ok("backup", "policy", "show", "nightly")
	tr.ok("backup", "list")
	tr.ok("backup", "list", "--jail", "db", "-o", "name")
	tr.ok("backup", "show", "20260101020000-ab12cd34")
	tr.do("", "backup", "run", "nightly")
	tr.do("", "backup", "verify", "20260101020000-ab12cd34")

	id := "20260101020000-ab12cd34"
	n := len(h.mutations())
	tr.ok("backup", "restore", id, "--dry-run")
	var rr api.RestoreRequest
	_ = json.Unmarshal(h.lastBody("POST", "/api/v1/restores"), &rr)
	if !rr.DryRun {
		t.Fatalf("dry-run restore sent a real restore: %+v", rr)
	}
	if _, ok := h.srv.JailIn("main", "web"); ok {
		t.Fatal("dry-run restored")
	}
	_ = n
	// No answer: refuses.
	_, _, code := tr.do("", "backup", "restore", id)
	if code != 2 {
		t.Fatalf("restore without confirmation: %d", code)
	}
	if _, ok := h.srv.JailIn("main", "web"); ok {
		t.Fatal("restored without confirmation")
	}
	// Declined.
	_, _, code = tr.do("n\n", "backup", "restore", id)
	if code != 1 {
		t.Fatalf("declined: %d", code)
	}
	// Confirmed.
	out, errs, code := tr.do("y\n", "backup", "restore", id)
	if code != 0 || !strings.Contains(out, "jail/web restored") || !strings.Contains(errs, "Restore backup") {
		t.Fatalf("confirmed: %d %s %s", code, out, errs)
	}
	// The preflight now fails: the jail exists.
	_, _, code = tr.do("", "backup", "restore", id, "-y")
	if code != 2 {
		t.Fatalf("preflight failure: %d", code)
	}
	tr.do("", "backup", "restore", id, "--as", "web-b", "--map", "lan=elsewhere", "-y")
	tr.ok("backup", "restore", id, "--as", "web-b", "-y")
	// --replace needs the typed name; -y is not enough.
	_, _, code = tr.do("", "backup", "restore", id, "--replace", "-y")
	if code != 2 {
		t.Fatalf("replace with -y: %d", code)
	}
	_, _, code = tr.do("web\n", "backup", "restore", id, "--replace")
	if code != 0 {
		t.Fatalf("replace typed: %d", code)
	}
	tr.do("", "backup", "restore", "nope", "--dry-run")
	tr.do("", "backup", "delete", "-y", "20260101020000-ab12cd34")
	tr.golden("backup")
}

func TestBackupExtensions(t *testing.T) {
	h := newHarness(t)
	h.seed()
	// The fake server implements backup_run now: an unknown policy is not_found
	// (exit 4), no longer unsupported.
	out, errs, code := h.run("", "backup", "run", "nightly")
	if code != 4 || out != "" || !strings.HasPrefix(errs, "not_found:") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

// A proxy-mode network on a host that drops the off-link probes of its segment's routers: the server warns in its
// answer and the client prints it, for a network from flags, from a file and through apply.
func TestNetworkCreateWarnsAboutOnlinkNS(t *testing.T) {
	h := newHarness(t, fake.WithSysctl("net.inet6.icmp6.nd6_onlink_ns_rfc4861", "0"))
	h.seed()
	tr := h.transcript()
	tr.ok("network", "create", "sw", "--ipv4", "10.94.0.1/24", "--uplink", "em0", "--ipv6", "2001:db8:1:2:100::/80", "--ipv6-mode", "proxy")
	f := writeFile(t, h.dir, "sw2.yaml", "kind: Network\nmetadata: {name: sw2}\nspec:\n  uplink: em0\n  ipv6: {mode: proxy, subnet: \"2001:db8:1:2:200::/80\", range: \"2001:db8:1:2:200::10-2001:db8:1:2:200::ff\"}\n", 0o644)
	tr.ok("network", "create", "-f", f)
	f = writeFile(t, h.dir, "sw3.yaml", "kind: Network\nmetadata: {name: sw3}\nspec:\n  uplink: em0\n  ipv6: {mode: proxy, subnet: \"2001:db8:1:2:300::/80\", range: \"2001:db8:1:2:300::10-2001:db8:1:2:300::ff\"}\n", 0o644)
	tr.ok("apply", "-f", f)
	// A routed network does not depend on it.
	tr.ok("network", "create", "rt", "--ipv6", "2001:db8:1:2:1::1/80")
	tr.golden("networks_onlink_warning")
}
