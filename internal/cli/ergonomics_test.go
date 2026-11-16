package cli_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

// Jails are started, stopped, restarted and deleted by name, by label
// selector or all at once; a bulk delete is confirmed with the project name.
func TestJailBulkActions(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--label", "env=prod", "--start")
	tr.ok("create", "db", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--label", "env=prod", "--label", "tier=data")
	tr.ok("create", "tmp", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--label", "env=test")
	tr.ok("list", "-c", "name,state")
	tr.ok("stop", "-l", "env=prod")
	tr.ok("start", "--all")
	tr.ok("list", "--state", "running", "-o", "name")
	tr.do("", "stop", "web", "-l", "env=prod")
	tr.do("", "stop")
	tr.do("", "stop", "--all", "-l", "env=prod")
	tr.do("", "restart", "-l", "env=nothing")
	tr.ok("restart", "-l", "env=prod,tier=data", "--grace", "1m30s")
	var act api.JailAction
	if err := json.Unmarshal(h.lastBody("PUT", "/api/v1/jails/db/state"), &act); err != nil || act.Action != "restart" || act.Timeout != 90 {
		t.Fatalf("restart request: %+v %v", act, err)
	}
	tr.do("", "restart", "db", "--grace", "soon")
	tr.ok("stop", "db", "--grace", "5")
	_ = json.Unmarshal(h.lastBody("PUT", "/api/v1/jails/db/state"), &act)
	if act.Timeout != 5 {
		t.Fatalf("grace in seconds: %+v", act)
	}
	// A bulk delete destroys data: it shows what goes and needs the project name typed, or --confirm-data-loss;
	// -y does not answer it, and it never asks per jail. A running jail needs --force first.
	tr.do("", "delete", "-l", "env=test")
	tr.ok("stop", "tmp")
	tr.do("", "delete", "-l", "env=test")
	tr.do("wrong\n", "delete", "-l", "env=test")
	tr.do("", "delete", "-l", "env=test", "-y")
	if _, ok := h.srv.JailIn("main", "tmp"); !ok {
		t.Fatal("tmp deleted without confirmation")
	}
	tr.do("main\n", "delete", "-l", "env=test")
	if _, ok := h.srv.JailIn("main", "tmp"); ok {
		t.Fatal("tmp survived the typed confirmation")
	}
	tr.do("", "delete", "web") // running, no --force
	// a dry run shows the summary of a running jail without --force too, and says --force is needed
	tr.ok("--dry-run", "delete", "web")
	tr.ok("--dry-run", "delete", "web", "-o", "json")
	tr.ok("--dry-run", "delete", "--stop", "web")
	tr.ok("--dry-run", "delete", "--stop", "web", "-o", "json")
	tr.do("", "--dry-run", "delete", "nosuch") // a dry run of a missing jail is an error
	if _, ok := h.srv.JailIn("main", "web"); !ok {
		t.Fatal("dry-run deleted web")
	}
	tr.do("", "delete", "--stop", "-y", "web")
	tr.ok("delete", "--stop", "--confirm-data-loss", "web")
	tr.ok("delete", "--all", "--stop", "--confirm-data-loss")
	tr.ok("list")
	tr.golden("jail_bulk")
}

// Lists take name patterns, chosen columns, an order, CSV and the compact
// form; -q leaves out confirmations.
func TestListErgonomics(t *testing.T) {
	h := newHarness(t)
	h.seedDualStack()
	tr := h.transcript()
	tr.ok("list", "w*")
	tr.ok("list", "nothing*", "d?")
	tr.do("", "list", "[")
	tr.ok("list", "-c", "name,state,age")
	tr.ok("list", "--sort", "state")
	tr.ok("list", "--sort", "state", "-o", "name")
	tr.do("", "list", "-c", "name,bogus")
	tr.do("", "list", "--sort", "bogus")
	tr.do("", "list", "--state", "foo")
	tr.ok("list", "-o", "csv")
	tr.ok("list", "-o", "csv", "--no-headers", "-c", "name,addresses")
	tr.ok("network", "list", "-o", "csv")
	tr.do("", "jail", "show", "web", "-o", "csv")
	h.tty = true
	h.env["NO_COLOR"] = "1"
	tr.ok("list", "-o", "compact")
	tr.ok("list", "-c", "name,state")
	tr.ok("image", "list", "--sort", "name", "-o", "compact")
	h.tty = false
	tr.ok("-q", "stop", "web")
	tr.ok("-q", "jail", "snapshot", "create", "db", "s1")
	tr.do("", "-q", "stop", "ghost")
	tr.ok("-q", "start", "web", "-o", "name")
	tr.golden("list_ergonomics")
}

// One generation notation: gN everywhere, N and IMAGE#gN accepted.
func TestGenerationNotation(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedGeneration("freebsd-15")
	h.srv.SeedGeneration("freebsd-15")
	tr := h.transcript()
	tr.ok("image", "build", "freebsd-15", "--from-generation", "1")
	tr.ok("image", "build", "freebsd-15", "--from-generation", "freebsd-15#g2", "--dry-run")
	tr.do("", "image", "build", "freebsd-15", "--from-generation", "other#g2")
	tr.ok("image", "alias", "add", "freebsd-15", "stable", "--generation", "g1")
	tr.ok("image", "alias", "add", "freebsd-15", "edge", "--generation", "freebsd-15#g4")
	tr.ok("image", "generation", "delete", "-y", "freebsd-15", "g3")
	tr.do("", "image", "generation", "delete", "-y", "freebsd-15", "three")
	tr.ok("jail", "create", "web", "--image", "freebsd-15#g1", "--network", "lan", "--storage", "default")
	tr.ok("jail", "upgrade", "web", "--generation", "2")
	var up api.JailUpgrade
	if err := json.Unmarshal(h.lastBody("POST", "/api/v1/jails/web/upgrade"), &up); err != nil || up.Generation != "g2" {
		t.Fatalf("upgrade request: %+v %v", up, err)
	}
	tr.do("", "jail", "upgrade", "web", "--generation", "x")
	tr.golden("generations")
}

// The architecture of a new image comes from the server unless --arch says
// otherwise; a server that reports none makes the command ask for the flag.
func TestImageArchFromServer(t *testing.T) {
	h := newHarness(t, fake.WithArch("arm64"))
	arch := func(name string) string {
		var img api.Image
		if err := json.Unmarshal(h.lastBody("POST", "/api/v1/images"), &img); err != nil || img.Metadata.Name != name {
			t.Fatalf("image request: %+v %v", img, err)
		}
		return img.Spec.Arch
	}
	if _, errs, code := h.run("", "image", "create", "arm", "--release", "15.1-RELEASE"); code != 0 {
		t.Fatal(errs)
	}
	if got := arch("arm"); got != "arm64" {
		t.Fatalf("default arch %q", got)
	}
	if _, errs, code := h.run("", "image", "create", "x86", "--release", "15.1-RELEASE", "--arch", "amd64"); code != 0 {
		t.Fatal(errs)
	}
	if got := arch("x86"); got != "amd64" {
		t.Fatalf("--arch %q", got)
	}
	none := newHarness(t, fake.WithArch(""))
	_, errs, code := none.run("", "image", "create", "noarch", "--release", "15.1-RELEASE")
	if code != 1 || !strings.Contains(errs, "does not report its architecture") || !strings.Contains(errs, "hint: pass --arch") {
		t.Fatalf("no arch: %d %s", code, errs)
	}
	if len(none.mutations()) != 0 {
		t.Fatalf("an image was created without an architecture: %v", none.mutations())
	}
}

// apply creates what is missing, updates what differs and leaves the rest.
func TestApply(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	docs := `kind: Network
metadata: {name: dmz}
spec: {ipv4: {subnet: 10.30.0.0/24, gateway: 10.30.0.1, range: 10.30.0.10-10.30.0.20}}
---
apiVersion: jailops/v1
kind: Jail
metadata: {name: web, labels: {env: prod}}
spec: {image: freebsd-15@stable, storage: default, layout: thin, hostname: web, network: [{network: lan, ipv4: 10.20.0.15}]}
---
kind: Image
metadata: {name: alpine-3}
spec: {os: linux, release: "3.22", arch: amd64, source: {type: minirootfs}}
`
	f := writeFile(t, h.dir, "site.yaml", docs, 0o644)
	tr.ok("--dry-run", "apply", "-f", f)
	if m := h.mutations(); len(m) != 0 {
		t.Fatalf("dry-run sent: %v", m)
	}
	tr.ok("apply", "-f", f)
	tr.ok("apply", "-f", f)
	f2 := writeFile(t, h.dir, "site2.yaml", strings.Replace(docs, "range: 10.30.0.10-10.30.0.20}}", "range: 10.30.0.10-10.30.0.20}, mtu: 1400}", 1), 0o644)
	tr.ok("apply", "-f", f2)
	if n, _ := h.srv.Network("dmz"); n.Spec.MTU != 1400 {
		t.Fatalf("network not updated: %+v", n.Spec)
	}
	tr.ok("apply", "-f", f2, "-o", "name")
	tr.do("", "apply", "-f", writeFile(t, h.dir, "nokind.yaml", "metadata: {name: x}\nspec: {}\n", 0o644))
	tr.do("", "apply", "-f", writeFile(t, h.dir, "badkind.yaml", "kind: Rollout\nmetadata: {name: x}\nspec: {}\n", 0o644))
	tr.do("", "apply", "-f", writeFile(t, h.dir, "typo.yaml", "kind: Network\nmetadata: {name: dmz}\nspec: {ipv4: {subnet: 10.30.0.0/24, gateway: 10.30.0.1, range: 10.30.0.10-10.30.0.20}, mtuu: 1}\n", 0o644))
	tr.do("", "apply")
	out, _, code := tr.do("kind: Image\nmetadata: {name: viastdin}\nspec: {os: freebsd, release: 15.1-RELEASE, arch: amd64, source: {type: pkgbase}}\n", "apply", "-f", "-")
	if code != 0 || !strings.Contains(out, "image/viastdin created") {
		t.Fatalf("stdin: %d %s", code, out)
	}
	// A project-level document needs a project; a host-level one does not.
	h.writeConfig(fmt.Sprintf("current: t\nremotes:\n  t:\n    url: %s\n", h.ts.URL))
	tr.do("", "apply", "-f", f)
	tr.ok("apply", "-f", writeFile(t, h.dir, "img.yaml", "kind: Image\nmetadata: {name: alpine-3}\nspec: {os: linux, release: \"3.22\", arch: amd64, source: {type: minirootfs}}\n", 0o644))
	tr.golden("apply")
}

// --project narrows operations and events to one project.
func TestProjectFilters(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "shop"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "lan"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}})
	h.run("", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "--project", "shop", "create", "api", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	out, errs, code := h.run("", "op", "list", "--project", "shop")
	if code != 0 || !strings.Contains(out, "Creating jail api") || strings.Contains(out, "web") {
		t.Fatalf("op list --project: %d %q %s", code, out, errs)
	}
	reqs := h.srv.Requests()
	if last := reqs[len(reqs)-1]; last.Path != "/api/v1/operations" || !strings.Contains(last.Query, "project=shop") {
		t.Fatalf("the project was not sent: %+v", last)
	}
	out, errs, code = h.run("", "events", "--project", "shop", "--since-id", "0", "--count", "1", "-o", "json")
	if code != 0 || !strings.Contains(out, `"project":"shop"`) || strings.Contains(out, `"project":"main"`) {
		t.Fatalf("events --project: %d %q %s", code, out, errs)
	}
}

// Harmonised flags and names: cert enroll --role, remote add/delete, backup restore --to-host by name.
func TestFlagHarmonisation(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("cert", "enroll", "laptop", "--role", "operator", "--projects", "main", "-o", "json")
	tr.ok("cert", "enroll", "old", "--role", "admin", "--global", "-o", "json")
	out, _, _ := h.run("", "cert", "enroll", "--help")
	if !strings.Contains(out, "--role") || !strings.Contains(out, "--expires") {
		t.Fatalf("cert enroll help: %s", out)
	}
	tr.ok("remote", "add", "lab", "unix:/run/lab.sock")
	tr.ok("remote", "delete", "lab")
	h.srv.SeedRemote(api.Remote{Metadata: api.ObjectMeta{Name: "host-b"}, Spec: api.RemoteSpec{Address: "https://10.94.0.2:39110", HostUUID: h.srv.HostUUID()}})
	h.srv.SeedBackup(api.Backup{
		Metadata: api.ObjectMeta{Name: "20260101020000-ab12cd34", Project: "main"},
		Spec:     api.BackupSpec{Jail: "web", Target: "usb", Snapshot: "20260101020000-ab12cd34", Bundle: api.RestoreBundle{Spec: api.JailSpec{Image: "freebsd-15@stable"}}},
	})
	tr.ok("backup", "restore", "20260101020000-ab12cd34", "--to-host", "host-b", "--dry-run")
	var rr api.RestoreRequest
	if err := json.Unmarshal(h.lastBody("POST", "/api/v1/restores"), &rr); err != nil || rr.Host != h.srv.HostUUID() {
		t.Fatalf("restore request: %+v %v", rr, err)
	}
	tr.ok("backup", "restore", "20260101020000-ab12cd34", "--to-host", h.srv.HostUUID(), "--dry-run")
	tr.do("", "backup", "restore", "20260101020000-ab12cd34", "--to-host", "nowhere", "--dry-run")
	tr.golden("harmonised")
}

// Generated help uses "a" and "an" correctly, and the jail group has label.
func TestHelpGrammarAndJailLabel(t *testing.T) {
	h := newHarness(t)
	h.seed()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"image", "create"}, "Create an image"},
		{[]string{"image", "edit"}, "Edit an image in your editor"},
		{[]string{"firewall", "address-set", "create"}, "Create an address set"},
		{[]string{"network", "create"}, "Create a network"},
		{[]string{"jail", "label"}, "Set or remove labels of a jail"},
	} {
		out, _, code := h.run("", append(c.args, "--help")...)
		if code != 0 || !strings.Contains(out, c.want) {
			t.Errorf("%v: %d, want %q in:\n%s", c.args, code, c.want, out)
		}
	}
	h.run("", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	if out, errs, code := h.run("", "jail", "label", "web", "tier=front"); code != 0 || !strings.Contains(out, "tier=front") {
		t.Fatalf("jail label: %d %q %s", code, out, errs)
	}
}

// Completion works after the first argument and for flag values.
func TestCompletionEverywhere(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "jail", "create", "db", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "jail", "snapshot", "create", "web", "s1")
	h.run("", "firewall", "policy", "create", "floor", "--default-in", "deny", "--default-out", "allow")
	h.srv.SeedRemote(api.Remote{Metadata: api.ObjectMeta{Name: "host-b"}, Spec: api.RemoteSpec{Address: "https://10.94.0.2:39110"}})
	for _, c := range []struct {
		args       []string
		want, none string
	}{
		{[]string{"stop", "web", ""}, "db\n", "web\n"},
		{[]string{"delete", "web", "db", ""}, ":", "web"},
		{[]string{"jail", "snapshot", "delete", "web", ""}, "s1\n", "web"},
		{[]string{"jail", "snapshot", "show", "web", ""}, "s1\n", ""},
		{[]string{"image", "alias", "add", "freebsd-15", ""}, "stable\n", ""},
		{[]string{"image", "alias", "add", "freebsd-15", "stable", "--generation", ""}, "g1\n", ""},
		{[]string{"image", "generation", "delete", "freebsd-15", ""}, "g1\n", ""},
		{[]string{"image", "build", "freebsd-15", "--from-generation", ""}, "g1\n", ""},
		{[]string{"jail", "list", "--state", ""}, "running\n", ""},
		{[]string{"list", "-c", ""}, "addresses", ""},
		{[]string{"list", "--sort", ""}, "age", ""},
		{[]string{"create", "x", "--layout", ""}, "thick\n", ""},
		{[]string{"create", "x", "--update-strategy", ""}, "rebase\n", ""},
		{[]string{"create", "x", "--depends", ""}, "web\n", ""},
		{[]string{"project", "set", "main", "--firewall-policy", ""}, "floor\n", ""},
		{[]string{"firewall", "test", "--proto", ""}, "tcp\n", ""},
		{[]string{"firewall", "test", "--proto", ""}, "icmp6\n", ""},
		{[]string{"firewall", "test", "--family", ""}, "6\n", ""},
		{[]string{"firewall", "test", "--icmp-type", ""}, "echoreq\n", ""},
		{[]string{"firewall", "test", "--from", ""}, "host\n", ""},
		{[]string{"firewall", "test", "--from", ""}, "jail:db\n", ""},
		{[]string{"firewall", "test", "--from", "host", "--to", ""}, "jail:db\n", ""},
		{[]string{"firewall", "test", "--from", "host", "--to", "jail:d"}, "jail:db\n", ""},
		{[]string{"firewall", "test", "--from", "jail:web", "--to", "jail:db", "--proto", ""}, "udp\n", ""},
		{[]string{"image", "create", "x", "--os", ""}, "linux\n", ""},
		{[]string{"image", "create", "x", "--arch", ""}, "arm64\n", ""},
		{[]string{"image", "create", "x", "--source-type", ""}, "debootstrap\n", ""},
		{[]string{"network", "create", "x", "--ipv6-mode", ""}, "proxy\n", ""},
		{[]string{"storage", "create", "x", "--compression", ""}, "zstd\n", ""},
		{[]string{"backup", "target", "create", "x", "--kind", ""}, "directory\n", ""},
		{[]string{"backup", "policy", "create", "x", "--verify-mode", ""}, "extract\n", ""},
		{[]string{"events", "--type", ""}, "lifecycle\n", ""},
		{[]string{"--host", ""}, "host-b\n", ""},
		{[]string{"--remote", ""}, "local\n", ""},
		{[]string{"-o", ""}, "csv\n", ""},
		{[]string{"jail", "rollback", "web", "--snapshot", ""}, "s1\n", ""},
		{[]string{"jail", "upgrade", "web", "--generation", ""}, "g1\n", ""},
	} {
		out, _, code := h.run("", append([]string{"__complete"}, c.args...)...)
		if code != 0 || !strings.Contains(out, c.want) || (c.none != "" && strings.Contains(out, c.none)) {
			t.Errorf("%v: exit %d, want %q (and not %q) in %q", c.args, code, c.want, c.none, out)
		}
	}
}

// "image set" changes single attributes of a stored image without asking the server for an architecture or building
// anything from the flags that were not given.
func TestImageSetAutoUpgrade(t *testing.T) {
	h := newHarness(t, fake.WithArch("arm64"))
	if _, errs, code := h.run("", "image", "create", "base", "--release", "15.1-RELEASE"); code != 0 {
		t.Fatal(errs)
	}
	if _, errs, code := h.run("", "image", "set", "base", "--auto-upgrade", "--upgrade-at", "04:30"); code != 0 {
		t.Fatalf("image set: %d %s", code, errs)
	}
	out, errs, code := h.run("", "image", "show", "base", "-o", "yaml")
	if code != 0 || !strings.Contains(out, "04:30") || !strings.Contains(out, "arch: arm64") || !strings.Contains(out, "release: 15.1-RELEASE") {
		t.Fatalf("image show: %d %q %s", code, out, errs)
	}
}

// "set" clears a list with an empty value, as its help says, and does not store an empty entry.
func TestJailSetClearsAList(t *testing.T) {
	h := newHarness(t)
	h.seed()
	if _, errs, code := h.run("", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--tag", "front"); code != 0 {
		t.Fatal(errs)
	}
	if out, _, _ := h.run("", "jail", "show", "web", "-o", "yaml"); !strings.Contains(out, "front") {
		t.Fatalf("the tag was not set: %s", out)
	}
	if _, errs, code := h.run("", "jail", "set", "web", "--tag", ""); code != 0 || strings.Contains(errs, "cannot tell") {
		t.Fatalf("set --tag \"\": %d %s", code, errs)
	}
	out, _, _ := h.run("", "jail", "show", "web", "-o", "yaml")
	if strings.Contains(out, "front") || strings.Contains(out, `""`) {
		t.Fatalf("the tag list was not cleared: %s", out)
	}
}
