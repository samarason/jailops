package priv

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// probeEnv makes an approved directory with a "box" below it that the test calls a mount (a device of its own) and a
// plain directory next to it.
func probeEnv(t *testing.T) (l *Local, root, box string) {
	t.Helper()
	e := newEnv(t)
	root = filepath.Join(e.base, "mnt")
	box = filepath.Join(root, "box")
	for _, d := range []string{filepath.Join(box, "backups"), filepath.Join(root, "local", "backups")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := e.cfg
	cfg.Admin.HostMountRoots = []string{root}
	l, err := NewLocal(cfg, Deps{ZFS: e.zfs}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	old := sourceDev
	sourceDev = func(p string, fi fs.FileInfo) (uint64, bool) {
		if p == box || strings.HasPrefix(p, box+"/") {
			return 7, true
		}
		return old(p, fi)
	}
	t.Cleanup(func() { sourceDev = old })
	return l, root, box
}

func TestProbeSourceSeesAMountBelowTheApprovedDirectory(t *testing.T) {
	l, _, box := probeEnv(t)
	for _, p := range []string{box, filepath.Join(box, "backups")} {
		got, err := l.ProbeSource(context.Background(), SourceProbeReq{Path: p})
		if err != nil || !got.Mounted {
			t.Fatalf("%s: %+v %v", p, got, err)
		}
	}
}

func TestProbeSourceRefusesAnEmptyDirectoryLeftByAMount(t *testing.T) {
	l, root, _ := probeEnv(t)
	// the directory is there and is the host's own: what a lost mount leaves behind
	got, err := l.ProbeSource(context.Background(), SourceProbeReq{Path: filepath.Join(root, "local")})
	if err != nil || got.Mounted || !strings.Contains(got.Detail, "not on a mount") {
		t.Fatalf("%+v %v", got, err)
	}
	got, err = l.ProbeSource(context.Background(), SourceProbeReq{Path: filepath.Join(root, "local", "backups")})
	if err != nil || got.Mounted {
		t.Fatalf("a subdirectory of a directory of the host is on a mount: %+v %v", got, err)
	}
}

func TestProbeSourceSaysWhenTheDirectoryIsGone(t *testing.T) {
	l, root, _ := probeEnv(t)
	got, err := l.ProbeSource(context.Background(), SourceProbeReq{Path: filepath.Join(root, "gone", "backups")})
	if err != nil || got.Mounted || !strings.Contains(got.Detail, "does not exist") {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestProbeSourceRefusesWhatIsOutsideOrTheApprovedDirectoryItself(t *testing.T) {
	l, root, _ := probeEnv(t)
	ctx := context.Background()
	for name, p := range map[string]string{
		"outside":   filepath.Join(filepath.Dir(root), "elsewhere"),
		"the root":  root,
		"dot dot":   root + "/box/../..",
		"not clean": root + "//box",
		"relative":  "box",
		"empty":     "",
		"above":     filepath.Dir(root),
		"a prefix":  root + "x/box",
	} {
		if _, err := l.ProbeSource(ctx, SourceProbeReq{Path: p}); err == nil {
			t.Errorf("%s: %q was probed", name, p)
		}
	}
	_, err := l.ProbeSource(ctx, SourceProbeReq{Path: root})
	if !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("the approved directory itself: %v", err)
	}
}

func TestProbeSourceFollowsNoSymbolicLink(t *testing.T) {
	l, root, box := probeEnv(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(box, "inner")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(root, "link"), filepath.Join(root, "link", "x"), filepath.Join(box, "inner")} {
		_, err := l.ProbeSource(context.Background(), SourceProbeReq{Path: p})
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s: a path through a link was probed: %v", p, err)
		}
	}
}

func TestProbeSourceWriteMakesAndRemovesItsFile(t *testing.T) {
	l, _, box := probeEnv(t)
	dir := filepath.Join(box, "backups")
	got, err := l.ProbeSource(context.Background(), SourceProbeReq{Path: dir, Write: true})
	if err != nil || !got.Mounted || !got.Writable {
		t.Fatalf("%+v %v", got, err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("the probe left %d files", len(left))
	}
	// a directory that takes no file is reported, not an error
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if os.Geteuid() != 0 {
		got, err = l.ProbeSource(context.Background(), SourceProbeReq{Path: dir, Write: true})
		if err != nil || !got.Mounted || got.Writable || !strings.Contains(got.Detail, "no file can be created") {
			t.Fatalf("%+v %v", got, err)
		}
	}
}

func TestProbeSourceNeedsAHostMountDirectory(t *testing.T) {
	e := newEnv(t) // no admin-host-mount
	if _, err := e.local.ProbeSource(context.Background(), SourceProbeReq{Path: filepath.Join(e.base, "mnt", "box")}); !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), "admin-host-mount") {
		t.Fatalf("%v", err)
	}
}

// A running jail gets a host directory's mount again with the same mount(8) a start does, for an administrator only,
// from below an approved directory and through no link.
func TestMountRuleTakesAHostDirectorySourceForAnAdministrator(t *testing.T) {
	r := newRuleEnv(t)
	share := filepath.Join(r.base, "mnt", "box", "backups")
	if err := os.MkdirAll(share, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := r.cfg
	cfg.Admin.HostMountRoots = []string{filepath.Join(r.base, "mnt")}
	l, err := NewLocal(cfg, Deps{ZFS: r.zfs}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	cfg = l.Config()
	target := filepath.Join(r.root, "srv", "backups")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	check := func(ctx context.Context, argv ...string) error {
		rule, out, err := cfg.CheckCommandCtx(ctx, argv)
		if err != nil {
			return err
		}
		if rule.Verify != nil {
			return rule.Verify(ctx, l, out[1:])
		}
		return nil
	}
	admin, plain := WithAdmin(context.Background(), "root"), context.Background()
	for _, a := range [][]string{
		{"mount", "-t", "nullfs", share, target},
		{"mount", "-t", "nullfs", "-o", "ro", share, target},
	} {
		if err := check(admin, a...); err != nil {
			t.Errorf("%q: %v", a, err)
		}
		if err := check(plain, a...); err == nil {
			t.Errorf("%q: accepted without the admin assertion", a)
		}
	}
	for name, a := range map[string][]string{
		"outside the approved directory": {"mount", "-t", "nullfs", filepath.Join(r.base, "elsewhere"), target},
		"the approved directory above":   {"mount", "-t", "nullfs", filepath.Dir(filepath.Dir(share)) + "/../..", target},
		"a target outside a jail":        {"mount", "-t", "nullfs", share, filepath.Join(r.base, "mnt", "box")},
	} {
		if err := check(admin, a...); err == nil {
			t.Errorf("%s: %q was accepted", name, a)
		}
	}
	// a link inside the approved directory that leads out of it
	if err := os.Symlink(r.root, filepath.Join(r.base, "mnt", "box", "out")); err != nil {
		t.Fatal(err)
	}
	if err := check(admin, "mount", "-t", "nullfs", filepath.Join(r.base, "mnt", "box", "out"), target); err == nil {
		t.Error("a source behind a link was accepted")
	}
}
