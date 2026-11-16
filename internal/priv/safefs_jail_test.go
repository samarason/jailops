package priv

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// jailPair lays out two jails of two projects below one storage root and returns their roots. B holds the files
// root in A must not reach.
func jailPair(t *testing.T, e *env) (a, b string) {
	t.Helper()
	a = filepath.Join(e.cfg.MountBase, "projects", "a", "jails", "x", "root")
	b = filepath.Join(e.cfg.MountBase, "projects", "b", "jails", "y", "root")
	mustWrite(t, filepath.Join(b, "var/db/postgres/data/pg_hba.conf"), "B hba\n")
	mustWrite(t, filepath.Join(b, "etc/rc.conf"), "B rc\n")
	mustWrite(t, filepath.Join(b, "usr/local/etc/b.conf"), "B conf\n")
	mustWrite(t, filepath.Join(a, "opt/etc/real.conf"), "A real\n")
	if err := os.MkdirAll(filepath.Join(a, "var/db/postgres"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(a, "usr"), 0o755); err != nil {
		t.Fatal(err)
	}
	// what root in jail A can do to its own tree: relative symlinks that climb out of it into B
	link := func(at, target string) {
		t.Helper()
		rel, err := filepath.Rel(filepath.Dir(at), target)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(rel, at); err != nil {
			t.Fatal(err)
		}
	}
	link(filepath.Join(a, "var/db/postgres/data"), filepath.Join(b, "var/db/postgres/data"))
	link(filepath.Join(a, "etc"), filepath.Join(b, "etc"))
	link(filepath.Join(a, "usr/local"), filepath.Join(b, "usr/local"))
	if err := os.Symlink("..", filepath.Join(a, "up")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/etc/real.conf", filepath.Join(a, "abs.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("opt/etc", filepath.Join(a, "inside")); err != nil {
		t.Fatal(err)
	}
	return a, b
}

// The file operations open a path below a jail root at that jail root: no symlink the jail made leads into
// another jail, another project or the rest of the storage root, through any component.
func TestFileOpsStayInsideTheJail(t *testing.T) {
	e := newEnv(t)
	a, b := jailPair(t, e)
	ctx := context.Background()
	refused := func(what string, err error) {
		t.Helper()
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s: %v, want forbidden", what, err)
		}
	}
	hba := filepath.Join(a, "var/db/postgres/data/pg_hba.conf")
	got, err := e.local.ReadFile(ctx, hba)
	refused("read through a symlinked directory", err)
	if string(got) == "B hba\n" {
		t.Error("read jail B's pg_hba.conf through jail A")
	}
	refused("write through a symlinked directory", e.local.WriteFile(ctx, WriteFileReq{Path: hba, Data: []byte("pwned\n"), Mode: 0o644, Parents: true}))
	_, err = e.local.ReadFile(ctx, filepath.Join(a, "etc/rc.conf"))
	refused("read rc.conf through a symlinked /etc", err)
	refused("write with Parents below a symlinked parent", e.local.WriteFile(ctx, WriteFileReq{Path: filepath.Join(a, "usr/local/etc/new/x.conf"), Data: []byte("x"), Mode: 0o644, Parents: true}))
	refused("mkdir below a symlinked parent", e.local.MkdirAll(ctx, MkdirReq{Path: filepath.Join(a, "usr/local/made"), Mode: 0o755}))
	refused("remove below a symlinked parent", e.local.Remove(ctx, filepath.Join(a, "usr/local/etc/b.conf")))
	_, err = e.local.ReadFile(ctx, filepath.Join(a, "up/root/opt/etc/real.conf"))
	refused("a symlink to .. of the jail root", err)
	_, err = e.local.ReadFile(ctx, filepath.Join(a, "abs.conf"))
	refused("an absolute symlink (refused, not resolved as the jail would)", err)
	for _, p := range []string{a + "/../../../b/jails/y/root/etc/rc.conf", a + "/etc/../../../../b/jails/y/root/etc/rc.conf"} {
		_, err = e.local.ReadFile(ctx, p)
		refused(p, err)
	}
	for p, want := range map[string]string{
		filepath.Join(b, "var/db/postgres/data/pg_hba.conf"): "B hba\n",
		filepath.Join(b, "usr/local/etc/b.conf"):             "B conf\n",
	} {
		if c, err := os.ReadFile(p); err != nil || string(c) != want {
			t.Errorf("%s changed: %q %v", p, c, err)
		}
	}
	for _, p := range []string{filepath.Join(b, "usr/local/etc/new"), filepath.Join(b, "usr/local/made")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s was created in jail B", p)
		}
	}
	// a relative symlink that stays inside the jail is followed as the jail sees it
	if got, err := e.local.ReadFile(ctx, filepath.Join(a, "inside/real.conf")); err != nil || string(got) != "A real\n" {
		t.Errorf("symlink inside the jail: %q %v", got, err)
	}
	// a symlink as the final component is not replaced
	if err := os.Symlink("../../../../../b/jails/y/root/etc/rc.conf", filepath.Join(a, "var/rc.conf")); err != nil {
		t.Fatal(err)
	}
	if c, err := os.ReadFile(filepath.Join(a, "var/rc.conf")); err != nil || string(c) != "B rc\n" {
		t.Fatalf("the test symlink does not reach jail B: %q %v", c, err)
	}
	refused("write over a final symlink", e.local.WriteFile(ctx, WriteFileReq{Path: filepath.Join(a, "var/rc.conf"), Data: []byte("x"), Mode: 0o644}))
	_, err = e.local.ReadFile(ctx, filepath.Join(a, "var/rc.conf"))
	refused("read a final symlink out of the jail", err)
	// a path outside every jail tree (the container of a jail) still works below the storage root
	spec := filepath.Join(e.cfg.MountBase, "projects", "a", "jails", "x", "spec.json")
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: spec, Data: []byte("{}"), Mode: 0o644}); err != nil {
		t.Errorf("container file: %v", err)
	}
}

// The same refusals over the socket, through the helper's dispatcher and allow-list, and through the daemon's
// paths (pg_hba.conf of app access, rc.conf of an app draft) in the volume and image trees as well.
func TestFileOpsStayInsideTheJailOverTheSocket(t *testing.T) {
	var a, b string
	f := newFixtureWith(t, func(e *env) {
		a, b = jailPair(t, e)
		vol := filepath.Join(e.cfg.MountBase, "projects", "a", "volumes", "v1")
		img := filepath.Join(e.cfg.MountBase, "images", "base", "g1")
		mustWrite(t, filepath.Join(img, "etc", "keep"), "x")
		for _, d := range []string{vol, filepath.Join(img, "usr")} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for at, target := range map[string]string{
			filepath.Join(vol, "out"):        filepath.Join(b, "etc"),
			filepath.Join(img, "usr", "out"): filepath.Join(b, "etc"),
		} {
			rel, _ := filepath.Rel(filepath.Dir(at), target)
			if err := os.Symlink(rel, at); err != nil {
				t.Fatal(err)
			}
		}
	})
	ctx := context.Background()
	for _, p := range []string{
		a + "/var/db/postgres/data/pg_hba.conf",
		a + "/etc/rc.conf",
		f.cfg.MountBase + "/projects/a/volumes/v1/out/rc.conf",
		f.cfg.MountBase + "/images/base/g1/usr/out/rc.conf",
	} {
		if _, err := f.client.ReadFile(ctx, p); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("read %s: %v", p, err)
		}
		if err := f.client.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("pwned\n"), Mode: 0o644, Parents: true}); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("write %s: %v", p, err)
		}
	}
	if c, _ := os.ReadFile(filepath.Join(b, "etc/rc.conf")); string(c) != "B rc\n" {
		t.Errorf("jail B's rc.conf changed: %q", c)
	}
}

// The path arguments of allow-listed commands (mount points, tar and pkg roots) below a jail's tree must resolve
// inside that tree too.
func TestCommandPathsStayInsideTheJail(t *testing.T) {
	e := newEnv(t)
	a, _ := jailPair(t, e)
	for _, p := range []string{a + "/etc", a + "/etc/rc.conf", a + "/usr/local/etc", a + "/var/db/postgres/data", a + "/up"} {
		if err := e.cfg.checkRulePath(pathJailTree, p); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s: %v, want forbidden", p, err)
		}
	}
	for _, p := range []string{a, a + "/opt/etc", a + "/inside", a + "/var/db/postgres/new"} {
		if err := e.cfg.checkRulePath(pathJailTree, p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
