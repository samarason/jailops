package priv

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func volPath(e *env, project, name string) string {
	return filepath.Join(e.cfg.MountBase, "projects", project, "volumes", name)
}

func TestSetVolumeOwnerSetsTheModeOfAnEmptyVolumeRoot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := volPath(e, "a", "maildir")
	if err := os.MkdirAll(v, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.local.SetVolumeOwner(ctx, VolumeOwnerReq{Path: v, UID: 5000, GID: 5000, Mode: 0o770}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(v); err != nil || fi.Mode().Perm() != 0o770 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	// once: a volume with files in it keeps its owner
	mustWrite(t, filepath.Join(v, "mail"), "x")
	if err := e.local.SetVolumeOwner(ctx, VolumeOwnerReq{Path: v, UID: 0, GID: 0, Mode: 0o777}); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a volume with files: %v", err)
	}
	if fi, _ := os.Stat(v); fi.Mode().Perm() != 0o770 {
		t.Fatal("the mode of a volume with files changed")
	}
}

func TestSetVolumeOwnerRefusesEverythingButAVolumeRoot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	mp := e.cfg.MountBase
	for _, d := range []string{volPath(e, "a", "v1"), filepath.Join(volPath(e, "a", "v1"), "sub"), filepath.Join(mp, "projects", "a", "jails", "x", "root"),
		filepath.Join(mp, "images", "base", "g1"), filepath.Join(e.base, "elsewhere")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, p := range map[string]string{
		"the storage root":    mp,
		"a project":           filepath.Join(mp, "projects", "a"),
		"the volumes parent":  filepath.Join(mp, "projects", "a", "volumes"),
		"below a volume":      filepath.Join(volPath(e, "a", "v1"), "sub"),
		"a jail root":         filepath.Join(mp, "projects", "a", "jails", "x", "root"),
		"an image":            filepath.Join(mp, "images", "base", "g1"),
		"outside the storage": filepath.Join(e.base, "elsewhere"),
		"a relative path":     "projects/a/volumes/v1",
		"dot dot":             volPath(e, "a", "v1") + "/../v1",
		"dot dot out":         filepath.Join(mp, "projects", "a", "volumes", "..", "..", "..", "elsewhere"),
		"empty":               "",
	} {
		err := e.local.SetVolumeOwner(ctx, VolumeOwnerReq{Path: p, Mode: 0o755})
		if !api.IsCode(err, api.CodeForbidden) && !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mode := range map[string]uint32{"setuid": 0o4755, "setgid": 0o2755, "sticky": 0o1777, "a file type bit": 0o100755} {
		if err := e.local.SetVolumeOwner(ctx, VolumeOwnerReq{Path: volPath(e, "a", "v1") + "x", Mode: mode}); err == nil {
			t.Errorf("%s accepted", name)
		}
		if err := e.local.SetVolumeOwner(ctx, VolumeOwnerReq{Path: filepath.Join(volPath(e, "a", "v1"), "sub"), Mode: mode}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := os.Remove(filepath.Join(volPath(e, "a", "v1"), "sub")); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]uint32{"setuid": 0o4755, "setgid": 0o2755, "sticky": 0o1777, "a file type bit": 0o100755} {
		if err := e.local.SetVolumeOwner(ctx, VolumeOwnerReq{Path: volPath(e, "a", "v1"), Mode: mode}); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if fi, _ := os.Stat(volPath(e, "a", "v1")); fi.Mode().Perm() != 0o755 {
		t.Fatal("a refused request changed the mode")
	}
}

// Root in a jail that has a volume attached can replace entries of it with links; nothing the helper does for a
// volume may follow one out of the volume or onto another tree.
func TestSetVolumeOwnerFollowsNoSymlink(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	victim := filepath.Join(e.cfg.MountBase, "projects", "a", "jails", "x", "root", "etc")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	// the volume itself is a link to a jail's directory
	if err := os.MkdirAll(filepath.Join(e.cfg.MountBase, "projects", "a", "volumes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, volPath(e, "a", "linked")); err != nil {
		t.Fatal(err)
	}
	if err := e.local.SetVolumeOwner(ctx, VolumeOwnerReq{Path: volPath(e, "a", "linked"), Mode: 0o700}); err == nil {
		t.Fatal("a link as the root of a volume was followed")
	}
	// the parent of the volumes is a link to another project's tree
	other := filepath.Join(e.cfg.MountBase, "projects", "b", "volumes", "v")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.cfg.MountBase, "projects", "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.cfg.MountBase, "projects", "b", "volumes"), filepath.Join(e.cfg.MountBase, "projects", "d", "volumes")); err != nil {
		t.Fatal(err)
	}
	if err := e.local.SetVolumeOwner(ctx, VolumeOwnerReq{Path: filepath.Join(e.cfg.MountBase, "projects", "d", "volumes", "v"), Mode: 0o700}); err == nil {
		t.Fatal("a linked volumes directory was followed")
	}
	if fi, _ := os.Stat(other); fi.Mode().Perm() != 0o755 {
		t.Fatalf("the mode of another project's volume changed: %v", fi.Mode())
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o755 {
		t.Fatalf("the mode of a jail's directory changed: %v", fi.Mode())
	}
}

func TestSetVolumeOwnerOverTheSocket(t *testing.T) {
	var v string
	f := newFixtureWith(t, func(e *env) {
		v = volPath(e, "a", "db")
		if err := os.MkdirAll(v, 0o755); err != nil {
			t.Fatal(err)
		}
	})
	ctx := context.Background()
	if err := f.client.SetVolumeOwner(ctx, VolumeOwnerReq{Path: v, Mode: 0o750}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(v); fi.Mode().Perm() != 0o750 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if err := f.client.SetVolumeOwner(ctx, VolumeOwnerReq{Path: f.cfg.MountBase, Mode: 0o750}); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("the storage root: %v", err)
	}
}
