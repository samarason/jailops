package priv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// addDS creates a dataset with the given properties in the env's fake pool.
func (e *env) addDS(name string, props map[string]string) {
	e.t.Helper()
	if err := e.zfs.Create(context.Background(), zfs.CreateOpts{Name: name, Parents: true, Props: props}); err != nil {
		e.t.Fatal(err)
	}
}

// root adds a managed dataset with a mountpoint below the test directory.
func (e *env) root(name string) string {
	e.t.Helper()
	mp := filepath.Join(e.base, strings.ReplaceAll(name, "/", "_"))
	if err := os.MkdirAll(mp, 0o755); err != nil {
		e.t.Fatal(err)
	}
	e.addDS(name, map[string]string{"jailops:managed": "on", "mountpoint": mp})
	return mp
}

func (e *env) reopen() *Local {
	e.t.Helper()
	cfg := e.cfg
	cfg.reg = nil
	l, err := NewLocal(cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

func TestRegisterStorageValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	adm := WithAdmin(ctx, "alice")
	e.root("tank/second")
	e.addDS("tank/unmanaged", map[string]string{"mountpoint": filepath.Join(e.base, "unm")})
	e.addDS("tank/nomount", map[string]string{"jailops:managed": "on", "mountpoint": "none"})
	e.addDS("tank/legacy", map[string]string{"jailops:managed": "on", "mountpoint": "legacy"})
	e.addDS("tank/overlap", map[string]string{"jailops:managed": "on", "mountpoint": filepath.Join(e.cfg.MountBase, "inner")})
	e.addDS("tank/overlap2", map[string]string{"jailops:managed": "on", "mountpoint": filepath.Dir(e.cfg.MountBase)})
	e.addDS("tank/etc", map[string]string{"jailops:managed": "on", "mountpoint": "/etc"})
	e.addDS("tank/usrlocal", map[string]string{"jailops:managed": "on", "mountpoint": "/usr/local"})
	e.addDS("tank/underconf", map[string]string{"jailops:managed": "on", "mountpoint": filepath.Join(e.cfg.ConfDir, "x")})
	e.addDS("tank/ROOT", map[string]string{"jailops:managed": "on", "mountpoint": filepath.Join(e.base, "rootc")})
	e.addDS("tank/ROOT/default", map[string]string{"mountpoint": "/"})
	e.addDS("tank/clean/parent", map[string]string{"jailops:managed": "on", "mountpoint": filepath.Join(e.base, "cp")})
	e.addDS("tank/clean/parent/var", map[string]string{"mountpoint": "/var"})
	// inherited managed flag: a child of a managed dataset is not itself managed
	e.addDS("tank/second/child", nil)

	cases := []struct {
		name string
		ds   string
		ctx  context.Context
		code api.Code
	}{
		{"no admin assertion", "tank/second", ctx, api.CodeForbidden},
		{"empty", "", adm, api.CodeInvalid},
		{"snapshot name", "tank/second@s", adm, api.CodeInvalid},
		{"bookmark name", "tank/second#b", adm, api.CodeInvalid},
		{"option-like", "-r", adm, api.CodeInvalid},
		{"dotdot", "tank/../x", adm, api.CodeInvalid},
		{"pool root", "tank", adm, api.CodeInvalid},
		{"does not exist", "tank/ghost", adm, api.CodeNotFound},
		{"pool not imported", "other/x", adm, api.CodeNotFound},
		{"not managed", "tank/unmanaged", adm, api.CodeForbidden},
		{"inherited managed", "tank/second/child", adm, api.CodeForbidden},
		{"no mountpoint", "tank/nomount", adm, api.CodeInvalid},
		{"legacy mountpoint", "tank/legacy", adm, api.CodeInvalid},
		{"already a static root", "tank/jailops", adm, api.CodeAlreadyExists},
		{"inside a root", "tank/jailops/x", adm, api.CodeForbidden},
		{"mountpoint inside another root", "tank/overlap", adm, api.CodeForbidden},
		{"mountpoint containing another root", "tank/overlap2", adm, api.CodeForbidden},
		{"mounted on /etc", "tank/etc", adm, api.CodeForbidden},
		{"mounted on /usr/local", "tank/usrlocal", adm, api.CodeForbidden},
		{"mounted inside the conf dir", "tank/underconf", adm, api.CodeForbidden},
		{"ancestor of the system root", "tank/ROOT", adm, api.CodeForbidden},
		{"holds a system mountpoint", "tank/clean/parent", adm, api.CodeForbidden},
	}
	for _, c := range cases {
		err := e.local.RegisterStorage(c.ctx, c.ds)
		if !api.IsCode(err, c.code) {
			t.Errorf("%s: %v (want %s)", c.name, err, c.code)
		}
	}
	if got, _ := e.local.Storages(ctx); strings.Join(got, ",") != "tank/jailops" {
		t.Errorf("a refused registration changed the set: %v", got)
	}
	if _, err := os.Stat(e.cfg.StorageFile); err == nil {
		t.Error("a refused registration wrote the storage file")
	}
	// a containing dataset is refused once its child is a root
	if err := e.local.RegisterStorage(adm, "tank/second"); err != nil {
		t.Fatal(err)
	}
	e.root("tank/wide")
	e.root("tank/wide/narrow")
	if err := e.local.RegisterStorage(adm, "tank/wide/narrow"); err != nil {
		t.Fatal(err)
	}
	if err := e.local.RegisterStorage(adm, "tank/wide"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("containing a root: %v", err)
	}
}

func TestPoolRootNeedsExplicitConfig(t *testing.T) {
	e := newEnv(t)
	mp := filepath.Join(e.base, "pool")
	os.MkdirAll(mp, 0o755)
	// the fake pool root carries the properties of a dataset
	if err := e.zfs.Set(context.Background(), "tank", map[string]string{"jailops:managed": "on", "mountpoint": mp}); err != nil {
		t.Fatalf("fake cannot set properties on a pool root: %v", err)
	}
	if err := e.local.RegisterStorage(WithAdmin(context.Background(), "a"), "tank"); err == nil {
		t.Error("pool root accepted without allow-pool-root")
	}
	if _, err := (Config{StorageRoots: []string{"tank"}, StateDir: "/x"}).Normalize(); err == nil {
		t.Error("pool root in the static config accepted")
	}
	if _, err := (Config{StorageRoots: []string{"tank"}, StateDir: "/x", AllowPoolRoot: true}).Normalize(); err != nil {
		t.Errorf("explicitly allowed pool root: %v", err)
	}
}

func TestRegisterUnregisterPersistence(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	adm := WithAdmin(ctx, "alice")
	mp2 := e.root("tank/second")
	e.root("tank/third")
	if err := e.local.RegisterStorage(adm, "tank/second"); err != nil {
		t.Fatal(err)
	}
	if err := e.local.RegisterStorage(adm, "tank/second"); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Errorf("twice: %v", err)
	}
	if err := e.local.RegisterStorage(adm, "tank/third"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(e.cfg.StorageFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("storage file %v %v", st, err)
	}
	b, _ := os.ReadFile(e.cfg.StorageFile)
	if strings.Contains(string(b), "tank/jailops") || !strings.Contains(string(b), "root = tank/second\n") {
		t.Errorf("storage file %q: static roots must not be persisted", b)
	}
	if ents, _ := os.ReadDir(filepath.Dir(e.cfg.StorageFile)); len(ents) != 1 {
		t.Errorf("temporary files left: %v", ents)
	}
	// a restarted helper sees the same roots, with their mountpoints
	l2 := e.reopen()
	got, _ := l2.Storages(ctx)
	if strings.Join(got, ",") != "tank/jailops,tank/second,tank/third" {
		t.Errorf("after restart: %v", got)
	}
	if _, err := l2.ReadFile(ctx, filepath.Join(mp2, "none")); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("a path below the second root is not allowed: %v", err)
	}
	// unregister
	if err := l2.UnregisterStorage(ctx, "tank/second"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("unregister without admin: %v", err)
	}
	if err := l2.UnregisterStorage(adm, "tank/jailops"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a static root was unregistered: %v", err)
	}
	if err := l2.UnregisterStorage(adm, "tank/ghost"); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("unknown: %v", err)
	}
	if err := l2.UnregisterStorage(adm, "tank/second"); err != nil {
		t.Fatal(err)
	}
	if _, err := l2.ReadFile(ctx, filepath.Join(mp2, "x")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("unregistered root still readable: %v", err)
	}
	if got, _ := e.reopen().Storages(ctx); strings.Join(got, ",") != "tank/jailops,tank/third" {
		t.Errorf("after unregister and restart: %v", got)
	}
}

func TestReloadRootsOnSIGHUP(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.root("tank/second")
	if err := os.MkdirAll(filepath.Dir(e.cfg.StorageFile), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(s string, mode os.FileMode) {
		t.Helper()
		_ = os.Remove(e.cfg.StorageFile)
		if err := os.WriteFile(e.cfg.StorageFile, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("# hand edited\nroot = tank/second\n", 0o600)
	if err := e.local.ReloadRoots(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.local.Storages(ctx); strings.Join(got, ",") != "tank/jailops,tank/second" {
		t.Errorf("reload: %v", got)
	}
	// a corrupt or unsafe file is an error and the previous set stays
	for name, c := range map[string]struct {
		text string
		mode os.FileMode
	}{
		"garbage":       {"nonsense\n", 0o600},
		"unknown key":   {"mount = /x\n", 0o600},
		"overlap":       {"root = tank/second\nroot = tank/second/x\n", 0o600},
		"duplicate":     {"root = tank/second\nroot = tank/second\n", 0o600},
		"bad name":      {"root = tank/a b\n", 0o600},
		"group access":  {"root = tank/second\n", 0o640},
		"world access":  {"root = tank/second\n", 0o604},
		"too long line": {"root = " + strings.Repeat("a", 5000) + "\n", 0o600},
	} {
		write(c.text, c.mode)
		_ = os.Chmod(e.cfg.StorageFile, c.mode)
		if err := e.local.ReloadRoots(ctx); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if got, _ := e.local.Storages(ctx); strings.Join(got, ",") != "tank/jailops,tank/second" {
			t.Errorf("%s: the set changed to %v", name, got)
		}
	}
	// a root that disappeared becomes inactive and allows nothing
	write("root = tank/second\n", 0o600)
	if err := e.zfs.Destroy(ctx, "tank/second", zfs.DestroyOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := e.local.ReloadRoots(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.local.Storages(ctx); strings.Join(got, ",") != "tank/jailops" {
		t.Errorf("vanished root still active: %v", got)
	}
	var found bool
	for _, s := range e.local.RootStatuses() {
		if s.Dataset == "tank/second" {
			found = !s.Active && s.Error != ""
		}
	}
	if !found {
		t.Errorf("statuses %v", e.local.RootStatuses())
	}
	// the inactive root is not lost from the file when another is registered
	e.root("tank/fourth")
	if err := e.local.RegisterStorage(WithAdmin(ctx, "a"), "tank/fourth"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(e.cfg.StorageFile); !strings.Contains(string(b), "tank/second") {
		t.Errorf("inactive root dropped from the file: %q", b)
	}
	// a root that lost jailops:managed is inactive too
	if err := e.zfs.Set(ctx, "tank/jailops", map[string]string{"jailops:managed": "off"}); err != nil {
		t.Fatal(err)
	}
	_ = e.local.ReloadRoots(ctx)
	if got, _ := e.local.Storages(ctx); strings.Join(got, ",") != "tank/fourth" {
		t.Errorf("unmanaged root still active: %v", got)
	}
}

func TestOperationsUseTheRegisteredSet(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	adm := WithAdmin(ctx, "alice")
	mp2 := e.root("tank/second")
	z := e.local.ZFS()
	if _, err := z.Exists(ctx, "tank/second/x"); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("before registering: %v", err)
	}
	if err := e.local.RegisterStorage(adm, "tank/second"); err != nil {
		t.Fatal(err)
	}
	if err := z.Create(ctx, zfs.CreateOpts{Name: "tank/second/projects", Props: map[string]string{"jailops:managed": "on", "mountpoint": filepath.Join(mp2, "projects")}}); err != nil {
		t.Errorf("create in the second root: %v", err)
	}
	// the mountpoint must lie below a root's mountpoint, any of them
	if err := z.Set(ctx, "tank/second/projects", map[string]string{"mountpoint": filepath.Join(e.cfg.MountBase, "p")}); err != nil {
		t.Errorf("mountpoint under the first root: %v", err)
	}
	for _, bad := range []string{"/etc", "/", filepath.Dir(mp2), mp2 + "/../x"} {
		if err := z.Set(ctx, "tank/second/projects", map[string]string{"mountpoint": bad}); err == nil {
			t.Errorf("mountpoint %q accepted", bad)
		}
	}
	// roots themselves cannot be destroyed or renamed
	if err := z.Destroy(ctx, "tank/second", zfs.DestroyOpts{}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("destroy a root: %v", err)
	}
	if err := z.Rename(ctx, "tank/second", "tank/jailops/s", zfs.RenameOpts{}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("rename a root: %v", err)
	}
	// a name is under one root only: a sibling that merely shares the prefix is outside
	if _, err := z.Exists(ctx, "tank/secondary"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("prefix confusion: %v", err)
	}
	// unrooted listing spans the roots
	ls, err := z.List(ctx, zfs.ListOpts{Recursive: true})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, d := range ls {
		seen[d.Name] = true
	}
	if !seen["tank/jailops"] || !seen["tank/second/projects"] {
		t.Errorf("list: %v", seen)
	}
	if feats, err := z.ActiveFeatures(ctx, "tank"); err != nil {
		t.Errorf("features of a root's pool: %v (%v)", err, feats)
	}
	if _, err := z.ActiveFeatures(ctx, "other"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("features of another pool: %v", err)
	}
	// file paths follow the second root's mountpoint
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: filepath.Join(mp2, "f"), Data: []byte("x"), Mode: 0o644}); err != nil {
		t.Errorf("write below the second mountpoint: %v", err)
	}
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: filepath.Join(filepath.Dir(mp2), "f"), Data: []byte("x"), Mode: 0o644}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("write beside the mountpoint: %v", err)
	}
	// and mounting
	e.runner.On("zfs", []string{"mount", "tank/second/projects"}, "")
	if err := e.local.Mount(ctx, "tank/second/projects"); err != nil && !api.IsCode(err, api.CodeInternal) {
		t.Errorf("mount: %v", err)
	}
	if err := e.local.Mount(ctx, "tank/elsewhere"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("mount outside: %v", err)
	}
}

func TestStorageFileParse(t *testing.T) {
	c, _ := Config{StorageRoots: []string{"tank/x"}, StateDir: "/s"}.Normalize()
	good := "# c\n\nroot = tank/a\n  root=tank/b  \n"
	roots, err := c.parseStorageFile([]byte(good))
	if err != nil || strings.Join(roots, ",") != "tank/a,tank/b" {
		t.Fatalf("%v %v", roots, err)
	}
	for _, bad := range []string{"root tank/a", "root = ", "root = tank", "root = tank/a@s", "root = /tank/a", "root = tank//a",
		"root = tank/a\nroot = tank/a", "root = tank/a\nroot = tank/a/b", "storage = tank/a", "root = tank/a\x00", "root = -tank/a"} {
		if _, err := c.parseStorageFile([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	many := strings.Repeat("root = tank/a\n", 3)
	if _, err := c.parseStorageFile([]byte(many)); err == nil {
		t.Error("duplicates accepted")
	}
	var b strings.Builder
	for i := 0; i <= MaxStorageRoots; i++ {
		b.WriteString("root = tank/r" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\n")
	}
	if _, err := c.parseStorageFile([]byte(b.String())); err == nil {
		t.Error("more than the maximum number of roots accepted")
	}
}

func FuzzStorageFile(f *testing.F) {
	c, _ := Config{StateDir: "/s"}.Normalize()
	for _, s := range []string{"root = tank/a\n", "# x\nroot=tank/a\nroot = tank/b\n", "root = tank/a\nroot = tank/a/b\n", "\x00", "root = ", strings.Repeat("root = tank/a\n", 100)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		roots, err := c.parseStorageFile(b)
		if err != nil {
			return
		}
		// what parses renders to something that parses to the same set
		again, err := c.parseStorageFile(renderStorageFile(roots))
		if err != nil || len(again) != len(roots) {
			t.Fatalf("round trip of %q: %v %v", roots, again, err)
		}
		for i, r := range roots {
			if err := c.checkRootName(r); err != nil {
				t.Fatalf("accepted bad root %q", r)
			}
			for _, o := range roots[i+1:] {
				if dsInside(r, o) || dsInside(o, r) {
					t.Fatalf("overlapping roots %q %q", r, o)
				}
			}
		}
	})
}
