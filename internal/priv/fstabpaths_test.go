package priv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// jailTree makes the tree of a stopped jail below the storage mount and returns its root and a directory of "the host".
func jailTree(t *testing.T, e *env) (root, host string) {
	t.Helper()
	root = filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root")
	host = filepath.Join(e.base, "hostetc")
	for _, d := range []string{filepath.Join(root, "data"), filepath.Join(host, "ssh")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root, host
}

func TestFstabMountPointsMayNotPassThroughLinks(t *testing.T) {
	e := newEnv(t)
	root, host := jailTree(t, e)
	data := filepath.Join(e.cfg.MountBase, "projects", "alpha", "volumes", "vol")
	fstab := data + " " + root + "/data/ssh nullfs rw 0 0\n"
	if err := e.cfg.checkFstabPaths(fstab, root); err != nil {
		t.Fatalf("a plain tree was refused: %v", err)
	}
	// the jail's root user replaces /data with a link to a directory of the host
	if err := os.RemoveAll(filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	err := e.cfg.checkFstabPaths(fstab, root)
	if !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a mount point behind a link was accepted: %v", err)
	}
	// and without knowing the jail's root, the storage mount is the base
	if err := e.cfg.checkFstabPaths(fstab, ""); err == nil {
		t.Fatal("a mount point behind a link was accepted when checked on its own")
	}
}

func TestFstabSourcesMayNotPassThroughLinks(t *testing.T) {
	e := newEnv(t)
	root, host := jailTree(t, e)
	archive := filepath.Join(e.base, "archive")
	if err := os.MkdirAll(filepath.Join(archive, "shared"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := e.cfg
	cfg.Admin.HostMountRoots = []string{archive}
	l, err := NewLocal(cfg, Deps{ZFS: e.zfs}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	cfg = l.Config()
	good := filepath.Join(archive, "shared") + " " + root + "/data nullfs ro 0 0\n"
	if err := cfg.checkFstabPaths(good, root); err != nil {
		t.Fatalf("a plain source was refused: %v", err)
	}
	// another jail that has /archive/shared read-write turns "data" into a link to the host
	if err := os.Symlink(host, filepath.Join(archive, "shared", "data")); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(archive, "shared", "data") + " " + root + "/data nullfs rw 0 0\n"
	if err := cfg.checkFstabPaths(bad, root); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a source that is a link out of the approved directory was accepted: %v", err)
	}
	// a mount point outside the jail's root is refused when the root is known
	out := filepath.Join(archive, "shared") + " " + e.cfg.MountBase + "/projects/alpha/jails/other/root/x nullfs ro 0 0\n"
	if err := cfg.checkFstabPaths(out, root); err == nil {
		t.Fatal("a mount point in another jail's root was accepted")
	}
}

// Starting a jail rechecks its fstab: a file that was fine when it was written is refused after a link appears.
func TestStartingAJailRechecksItsFstab(t *testing.T) {
	e := newEnv(t)
	root, host := jailTree(t, e)
	ctx := context.Background()
	fstabPath := filepath.Join(e.cfg.ConfDir, "alpha_web.fstab")
	conf := strings.Replace(e.goodConf(), "\tmount.devfs;\n", "\tmount.devfs;\n\tmount.fstab = \""+fstabPath+"\";\n", 1)
	data := filepath.Join(e.cfg.MountBase, "projects", "alpha", "volumes", "vol")
	mustWrite(t, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), conf)
	mustWrite(t, fstabPath, data+" "+root+"/data/ssh nullfs rw 0 0\n")
	g := jailGuard{e.local}
	if _, err := g.confPathFor(ctx, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatalf("a good jail was refused: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.confPathFor(ctx, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err == nil {
		t.Fatal("a jail whose mount point became a link was started")
	}
}

// The helper accepts an fstab that is rewritten unchanged by someone who is not an administrator (every start of a
// jail does it), and still refuses a new or changed host mount from them; the operator's allow-list applies to both.
func TestAnUnchangedHostMountSurvivesARewriteByAnOperator(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, _ := jailTree(t, e)
	archive := filepath.Join(e.base, "archive")
	if err := os.MkdirAll(filepath.Join(archive, "movies"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := e.cfg
	cfg.Admin.HostMountRoots = []string{archive}
	l, err := NewLocal(cfg, Deps{ZFS: e.zfs}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.cfg.ConfDir, "alpha_web.fstab")
	w := func(ctx context.Context, text string) error {
		return l.WriteFile(ctx, WriteFileReq{Path: path, Data: []byte(text), Mode: 0o644})
	}
	hm := filepath.Join(archive, "movies") + " " + root + "/mnt nullfs ro 0 0\n"
	if err := w(ctx, hm); err == nil {
		t.Fatal("a new host mount without the assertion")
	}
	if err := w(WithAdmin(ctx, "alice"), hm); err != nil {
		t.Fatalf("the administrator's host mount: %v", err)
	}
	if err := w(ctx, hm); err != nil {
		t.Fatalf("the same file rewritten by an operator: %v", err)
	}
	if err := w(ctx, hm+hm); err != nil {
		t.Logf("a repeated line is still the same line: %v", err)
	}
	changed := filepath.Join(archive, "movies") + " " + root + "/mnt nullfs rw 0 0\n"
	if err := w(ctx, changed); err == nil {
		t.Fatal("an operator turned a read-only host mount into a read-write one")
	}
	other := filepath.Join(archive, "movies") + " " + root + "/srv nullfs ro 0 0\n"
	if err := w(ctx, other); err == nil {
		t.Fatal("an operator added another host mount")
	}
}
