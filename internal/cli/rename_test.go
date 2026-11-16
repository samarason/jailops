package cli_test

import (
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// The rename commands: they show what changes, ask (tier 2: -y answers), rename and say what changed.
func TestRenameCommands(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedAddressSet(api.AddressSet{Metadata: api.ObjectMeta{Name: "office", Project: "main"}, Spec: api.AddressSetSpec{Addresses: api.Entries("192.0.2.0/24")}})
	h.srv.SeedFirewallPolicy(api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "web", Project: "main"}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow",
		Rules: []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office"}, Ports: []string{"443"}}}}})
	tr := h.transcript()
	tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--firewall-policy", "web")
	tr.ok("jail", "create", "db", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--depends", "web")

	// a network: the plan, then the rename
	tr.ok("network", "rename", "lan", "office", "--dry-run")
	tr.do("", "network", "rename", "lan", "office") // no answer, nothing changes
	if _, ok := h.srv.JailIn("main", "web"); !ok {
		t.Fatal("web is gone")
	}
	tr.do("y\n", "network", "rename", "lan", "office")
	j, _ := h.srv.JailIn("main", "web")
	if j.Spec.Network[0].Network != "office" {
		t.Fatalf("%+v", j.Spec.Network)
	}
	tr.do("", "network", "rename", "office", "Bad_Name", "-y")

	// firewall objects
	tr.ok("firewall", "address-set", "rename", "office", "hq", "-y")
	tr.ok("firewall", "policy", "rename", "web", "public", "-y")
	if j, _ = h.srv.JailIn("main", "web"); !slices.Equal(j.Spec.Firewall.Policies, []string{"public"}) {
		t.Fatalf("%+v", j.Spec.Firewall)
	}

	// a jail, with the short form; a running one is refused
	tr.ok("start", "web")
	tr.do("", "rename", "web", "www", "-y")
	tr.ok("stop", "web")
	tr.ok("rename", "web", "www", "-y")
	if d, _ := h.srv.JailIn("main", "db"); strings.Join(d.Spec.Boot.Depends, ",") != "www" {
		t.Fatalf("%+v", d.Spec.Boot)
	}
	tr.ok("jail", "rename", "www", "web", "-y", "-o", "json")

	// an image and a project
	tr.ok("image", "rename", "freebsd-15", "freebsd-15-0", "-y")
	if j, _ = h.srv.JailIn("main", "web"); j.Spec.Image != "freebsd-15-0@stable" {
		t.Fatalf("%+v", j.Spec.Image)
	}
	tr.ok("project", "rename", "main", "primary", "-y")
	if _, ok := h.srv.JailIn("primary", "web"); !ok {
		t.Fatal("the jails did not move to the new project")
	}
	tr.golden("rename")
}

// An edit that changes metadata.name renames first (shown and asked), then applies the rest.
func TestEditRenames(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	ed := writeFile(t, h.dir, "ed.sh", "#!/bin/sh\nsed -e 's/name: lan/name: office/' -e 's/uplink: em0/uplink: em1/' \"$1\" > \"$1.new\" && mv \"$1.new\" \"$1\"\n", 0o755)
	h.env["EDITOR"] = ed
	tr.ok("network", "edit", "lan", "-y") // the editor reads standard input here, so the question is answered with -y
	if out := tr.ok("network", "show", "office", "-o", "json"); !strings.Contains(out, `"uplink": "em1"`) {
		t.Fatal(out)
	}
	tr.golden("edit_rename")
}

// The renames of the objects that stand on their own: a volume (with the attachments of the jails), a user.
func TestRenameVolumeAndUserCommands(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	tr.ok("volume", "create", "data")
	tr.ok("volume", "attach", "web", "data", "/srv/data")
	tr.ok("volume", "rename", "data", "store", "--dry-run")
	tr.ok("volume", "rename", "data", "store", "-y")
	if j, _ := h.srv.JailIn("main", "web"); len(j.Spec.Volumes) != 1 || j.Spec.Volumes[0].Name != "store" {
		t.Fatalf("%+v", j.Spec.Volumes)
	}
	tr.do("", "volume", "rename", "store", "Bad_Name", "-y")
	tr.ok("user", "create", "ann", "--role", "admin", "--global")
	tr.ok("user", "rename", "ann", "carl", "-y")
	if out, _, code := h.run("", "user", "show", "carl"); code != 0 || !strings.Contains(out, "carl") {
		t.Fatalf("user show carl: %d %q", code, out)
	}
}
