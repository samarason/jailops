package priv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

func wantCode(t *testing.T, err error, code api.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", code)
	}
	if !api.IsCode(err, code) {
		t.Fatalf("expected %s error, got %v", code, err)
	}
}

func TestZFSNamesHostile(t *testing.T) {
	e := newEnv(t)
	z := e.local.ZFS()
	ctx := context.Background()
	bad := map[string]api.Code{
		"tank":                      api.CodeForbidden, // the pool itself
		"tank/other":                api.CodeForbidden,
		"tank/jailops2":             api.CodeForbidden, // prefix without separator
		"tank/jailops/../other":     api.CodeInvalid,
		"-tank/jailops":             api.CodeInvalid,
		"tank/jailops/-x":           api.CodeInvalid,
		"tank/jailops/a b":          api.CodeInvalid,
		"tank/jailops/a;rm":         api.CodeInvalid,
		"tank/jailops/x\x00":        api.CodeInvalid,
		"tank/jailops/jails/web@-x": api.CodeInvalid,
		"other/jailops/jails":       api.CodeForbidden,
		"tank/jailops/" + strings.Repeat("a", 300): api.CodeInvalid,
		"": api.CodeInvalid,
	}
	for name, code := range bad {
		if _, err := z.Exists(ctx, name); err == nil || !api.IsCode(err, code) {
			t.Errorf("Exists(%q): got %v, want %s", name, err, code)
		}
		if err := z.Create(ctx, zfs.CreateOpts{Name: name}); err == nil {
			t.Errorf("Create(%q) succeeded", name)
		}
		if err := z.Destroy(ctx, name, zfs.DestroyOpts{}); err == nil {
			t.Errorf("Destroy(%q) succeeded", name)
		}
	}
	// Snapshots and bookmarks are checked through their dataset.
	for _, n := range []string{"tank/other@s", "tank/other#b", "tank@s"} {
		if _, err := z.Exists(ctx, n); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("Exists(%q): %v", n, err)
		}
	}
	if err := z.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops@ok", "tank/other@bad"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("mixed snapshot: %v", err)
	}
	if err := z.Clone(ctx, "tank/other@s", "tank/jailops/x", nil, false); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("clone from outside: %v", err)
	}
	if err := z.Clone(ctx, "tank/jailops@s", "tank/x", nil, false); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("clone to outside: %v", err)
	}
	if err := z.Rename(ctx, "tank/jailops/a", "tank/elsewhere", zfs.RenameOpts{}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("rename out: %v", err)
	}
	if _, err := z.List(ctx, zfs.ListOpts{Root: "tank"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("list pool: %v", err)
	}
	if _, err := z.ActiveFeatures(ctx, "other"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("features of another pool: %v", err)
	}
	many := make([]string, 300)
	for i := range many {
		many[i] = "tank/jailops@s"
	}
	if err := z.Hold(ctx, "t", many...); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("too many names: %v", err)
	}
}

func TestZFSRootAndForeignObjectsProtected(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	z := e.local.ZFS()
	if err := z.Destroy(ctx, "tank/jailops", zfs.DestroyOpts{Recursive: true}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("destroying the root: %v", err)
	}
	// A dataset below the root that JailOps does not own is never touched.
	if err := e.zfs.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/foreign"}); err != nil {
		t.Fatal(err)
	}
	if err := z.Destroy(ctx, "tank/jailops/foreign", zfs.DestroyOpts{}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("destroy unmanaged: %v", err)
	}
	if err := z.Set(ctx, "tank/jailops/foreign", map[string]string{"jailops:x": "1"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("set on unmanaged: %v", err)
	}
	if err := z.Rename(ctx, "tank/jailops/foreign", "tank/jailops/f2", zfs.RenameOpts{}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("rename unmanaged: %v", err)
	}
	e.managedDS("tank/jailops/mine")
	if err := z.Destroy(ctx, "tank/jailops/mine", zfs.DestroyOpts{}); err != nil {
		t.Errorf("destroy managed: %v", err)
	}
}

func TestZFSProps(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	z := e.local.ZFS()
	mp := filepath.Join(e.cfg.MountBase, "jails", "x")
	good := []map[string]string{
		{"compression": "zstd"}, {"quota": "10G"}, {"quota": "none"}, {"jailops:id": "abc"},
		{"mountpoint": mp}, {"mountpoint": "none"}, {"mountpoint": "legacy"}, {"readonly": "on"},
	}
	for _, p := range good {
		if err := z.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/p", Props: p}); err != nil {
			t.Errorf("props %v: %v", p, err)
		}
		_ = e.zfs.Destroy(ctx, "tank/jailops/p", zfs.DestroyOpts{})
	}
	bad := []map[string]string{
		{"mountpoint": "/etc"},
		{"mountpoint": "/"},
		{"mountpoint": e.cfg.MountBase + "/../etc"},
		{"mountpoint": e.cfg.MountBase + "x"}, // sibling with the same prefix
		{"mountpoint": "relative"},
		{"sharenfs": "on"}, {"sharesmb": "on"}, {"jailed": "on"},
		{"canmount2": "on"}, {"exec2": "on"},
		{"quota": "99999999T"}, {"quota": "-1"}, {"quota": "1.5G"}, {"quota": "10X"},
		{"keylocation": "file:///etc/shadow"},
		{"-o": "x"}, {"a:b": "line\nbreak"},
		{"compression": "x\x00y"},
	}
	for _, p := range bad {
		if err := z.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/p", Props: p}); err == nil {
			t.Errorf("props %v were accepted", p)
			_ = e.zfs.Destroy(ctx, "tank/jailops/p", zfs.DestroyOpts{})
		}
	}
	if err := z.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/v", VolumeSize: "100000T"}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("huge volume: %v", err)
	}
	if err := z.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/v", VolumeSize: "1G"}); err != nil {
		t.Errorf("1G volume: %v", err)
	}
	tooMany := map[string]string{}
	for i := 0; i < 100; i++ {
		tooMany["jailops:k"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	if err := z.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/q", Props: tooMany}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("too many props: %v", err)
	}
	// An admin may use a native property only when the policy lists it.
	if err := z.Create(WithAdmin(ctx, "root"), zfs.CreateOpts{Name: "tank/jailops/a1", Props: map[string]string{"redundant_metadata": "most"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("admin without policy: %v", err)
	}
	cfg := e.cfg
	cfg.Admin.ZFSProps = []string{"redundant_metadata"}
	l2, _ := NewLocal(cfg, Deps{ZFS: e.zfs}, WithoutChown())
	if err := l2.ZFS().Create(WithAdmin(ctx, "root"), zfs.CreateOpts{Name: "tank/jailops/a2", Props: map[string]string{"redundant_metadata": "most"}}); err != nil {
		t.Errorf("admin with policy: %v", err)
	}
	if err := l2.ZFS().Create(ctx, zfs.CreateOpts{Name: "tank/jailops/a3", Props: map[string]string{"redundant_metadata": "most"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("policy without admin: %v", err)
	}
}

func TestZFSSendReceiveRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	z := e.local.ZFS()
	var sink strings.Builder
	if err := z.Send(ctx, zfs.SendOpts{Snapshot: "tank/other@s"}, &sink); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("send outside: %v", err)
	}
	if err := z.Send(ctx, zfs.SendOpts{Snapshot: "tank/jailops@s", From: "tank/jailops"}, &sink); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("incremental from a dataset: %v", err)
	}
	if err := z.Send(ctx, zfs.SendOpts{ResumeToken: "1-abc"}, &sink); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("resume send without admin: %v", err)
	}
	if err := z.Receive(ctx, zfs.ReceiveOpts{Target: "tank/other"}, strings.NewReader("")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("receive outside: %v", err)
	}
	if err := z.Receive(ctx, zfs.ReceiveOpts{Target: "tank/jailops/r", Props: map[string]string{"mountpoint": "/etc"}}, strings.NewReader("")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("receive with a hostile mountpoint: %v", err)
	}
	if err := z.Receive(ctx, zfs.ReceiveOpts{Target: "tank/jailops", Force: true}, strings.NewReader("")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("receive over the root: %v", err)
	}
}

func TestInterfaceRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	n := e.local.Net()
	for _, name := range []string{"em0", "lo0", "bridge0", "mybr", "-jo0", "jo0;x", "jo0 x", "jo/0", "jo" + strings.Repeat("x", 20), ""} {
		if _, _, err := n.EpairCreate(ctx, name); err == nil && name != "mybr" && name != "" {
			t.Errorf("EpairCreate(%q) succeeded", name)
		}
		if err := n.SetLink(ctx, name, true); err == nil {
			t.Errorf("SetLink(%q) succeeded", name)
		}
		if err := n.EpairDestroy(ctx, name); err == nil {
			t.Errorf("EpairDestroy(%q) succeeded", name)
		}
	}
	if _, _, err := n.EpairCreate(ctx, "jo0"); err != nil {
		t.Fatal(err)
	}
	if err := n.SetDescription(ctx, "jo0a", "line\nbreak"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("description: %v", err)
	}
	if _, _, err := n.EpairCreate(ctx, "em2"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("epair under a driver's names: %v", err)
	}
	if err := n.MoveToJail(ctx, "jo0a", "alpha_nojail"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("moving into an unmanaged jail: %v", err)
	}
	if err := n.MoveToJail(ctx, "jo0a", "-x"); err == nil {
		t.Error("jail name starting with a dash was accepted")
	}
}

func TestRouteRules(t *testing.T) {
	e := newEnv(t)
	e.storeLan(t, "10.1.0.0/16")
	ctx := context.Background()
	n := e.local.Net()
	if _, _, err := e.net.EpairCreate(ctx, "jo0"); err != nil {
		t.Fatal(err)
	}
	bad := []ifconfig.Route{
		{Dest: "default", Gateway: "10.0.0.1"},
		{Dest: "default", Interface: "jo0a"},
		{Dest: "10.0.0.0/8", Interface: "jo0a"},
		{Dest: "0.0.0.0/0", Interface: "jo0a"},
		{Dest: "2001:db8::/32", Interface: "jo0a"},
		{Dest: "10.1.1.1", Gateway: "10.0.0.1"},
		{Dest: "10.1.1.1", Interface: "em0"},
		{Dest: "10.1.1.1"},
	}
	for _, r := range bad {
		if err := n.RouteAdd(ctx, r); err == nil {
			t.Errorf("route %+v was accepted", r)
		}
	}
	for _, r := range []ifconfig.Route{{Dest: "10.1.1.1/32", Interface: "jo0a"}, {Dest: "2001:db8:1:2:100::5/128", Interface: "jo0a"}, {Dest: "10.1.1.2", Interface: "jo0a"}} {
		if err := n.RouteAdd(ctx, r); err != nil {
			t.Errorf("route %+v: %v", r, err)
		}
	}
	cfg := e.cfg
	cfg.Admin.Routes = true
	l2, _ := NewLocal(cfg, Deps{Net: e.net}, WithoutChown())
	if err := l2.Net().RouteAdd(ctx, ifconfig.Route{Dest: "10.9.0.0/16", Gateway: "10.0.0.1"}); err == nil {
		t.Error("gateway route without the admin assertion")
	}
	if err := l2.Net().RouteAdd(WithAdmin(ctx, "root"), ifconfig.Route{Dest: "10.9.0.0/16", Gateway: "10.0.0.1"}); err != nil {
		t.Errorf("admin route: %v", err)
	}
}

func TestPFRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p := e.local.PF()
	for _, a := range []string{"", "jailops", "jailops/", "other/x", "jailops2/x", "../jailops/x", "jailops/../x", "jailops/.hidden", "-jailops/x", "jailops/x y", "jailops//x", "jailops/x;y"} {
		if err := p.Load(ctx, a, "pass all\n"); err == nil {
			t.Errorf("Load(%q) succeeded", a)
		}
		if err := p.Flush(ctx, a); err == nil {
			t.Errorf("Flush(%q) succeeded", a)
		}
		if _, err := p.Read(ctx, a); err == nil {
			t.Errorf("Read(%q) succeeded", a)
		}
	}
	for _, rs := range []string{
		"include \"/etc/pf.conf\"\n",
		"  INCLUDE \"/etc/x\"\n",
		"load anchor \"x\" from \"/etc/pf.conf\"\n",
		"set skip on lo0\n",
		"table <t> persist file \"/etc/passwd\"\n",
		"pass all\x00\n",
		strings.Repeat("pass all\n", 200000),
	} {
		if err := p.Load(ctx, "jailops/web", rs); err == nil {
			t.Errorf("ruleset %.30q was accepted", rs)
		}
	}
	if _, _, err := e.net.EpairCreate(ctx, "jo0"); err != nil {
		t.Fatal(err)
	}
	if err := p.Load(ctx, "jailops/web", "pass in on jo0a proto tcp to port 22\n"); err != nil {
		t.Errorf("good ruleset: %v", err)
	}
	if err := p.TableAdd(ctx, "jailops/shared.pf", "t_x", "10.0.0.1", "2001:db8::/64"); err != nil {
		t.Errorf("table add: %v", err)
	}
	if err := p.TableAdd(ctx, "jailops/shared.pf", "t_x", "-F"); err == nil {
		t.Error("table address -F accepted")
	}
	if err := p.TableAdd(ctx, "jailops/shared.pf", "-t", "10.0.0.1"); err == nil {
		t.Error("table name -t accepted")
	}
	// Raw PF needs the assertion and the policy flag.
	cfg := e.cfg
	cfg.Admin.RawPF = true
	l2, _ := NewLocal(cfg, Deps{PF: e.pf}, WithoutChown())
	raw := "table <t> file \"/usr/local/etc/jailops/t\"\n"
	if err := l2.PF().Load(ctx, "jailops/web", raw); err == nil {
		t.Error("raw ruleset without admin")
	}
	if err := l2.PF().Load(WithAdmin(ctx, "root"), "jailops/web", raw); err != nil {
		t.Errorf("raw ruleset with admin: %v", err)
	}
}

func TestPathResolution(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	l := e.local
	outside := filepath.Join(e.base, "outside")
	mustWrite(t, filepath.Join(outside, "secret"), "s3cret")
	jails := filepath.Join(e.cfg.MountBase, "jails")
	if err := os.MkdirAll(jails, 0o755); err != nil {
		t.Fatal(err)
	}
	// symlinks that point out of the root, to a file and to a directory
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(jails, "link-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(jails, "link-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside/secret", filepath.Join(jails, "link-rel")); err != nil {
		t.Fatal(err)
	}
	hostile := []string{
		"", "relative/path", "/etc/passwd", "/",
		jails + "/../../outside/secret",
		jails + "/./../../outside/secret",
		e.cfg.MountBase + "x/y",
		filepath.Join(jails, "link-file"),
		filepath.Join(jails, "link-dir", "secret"),
		filepath.Join(jails, "link-rel"),
		jails + "/a\x00b",
		e.cfg.MountBase, // a root itself
		strings.Repeat("/a", 3000),
	}
	for _, p := range hostile {
		if _, err := l.ReadFile(ctx, p); err == nil {
			t.Errorf("ReadFile(%q) succeeded", p)
		}
		if err := l.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("x"), Mode: 0o644}); err == nil {
			t.Errorf("WriteFile(%q) succeeded", p)
		}
	}
	// the symlink target must not have been written through
	if b, _ := os.ReadFile(filepath.Join(outside, "secret")); string(b) != "s3cret" {
		t.Errorf("outside file was modified: %q", b)
	}
	// Writing through a directory symlink would escape too.
	if err := l.WriteFile(ctx, WriteFileReq{Path: filepath.Join(jails, "link-dir", "new"), Data: []byte("x"), Mode: 0o644}); err == nil {
		t.Error("write through a directory symlink succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); err == nil {
		t.Error("file appeared outside the root")
	}
	// A symlink at the destination is not followed or replaced silently.
	if err := l.WriteFile(ctx, WriteFileReq{Path: filepath.Join(jails, "link-file"), Data: []byte("x"), Mode: 0o644}); err == nil {
		t.Error("overwrote a symlink")
	}
	// Removing a symlink removes the link, never its target.
	if err := l.Remove(ctx, filepath.Join(jails, "link-dir")); err != nil {
		t.Errorf("remove link: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "secret")); err != nil {
		t.Errorf("target of a removed link is gone: %v", err)
	}
	for _, p := range []string{"/etc/passwd", jails + "/../../outside/secret", ""} {
		if err := l.Remove(ctx, p); err == nil {
			t.Errorf("Remove(%q) succeeded", p)
		}
	}
	// Good paths work.
	good := filepath.Join(jails, "web", "x.txt")
	if err := l.WriteFile(ctx, WriteFileReq{Path: good, Data: []byte("hello"), Mode: 0o640, Parents: true}); err != nil {
		t.Fatal(err)
	}
	if b, err := l.ReadFile(ctx, good); err != nil || string(b) != "hello" {
		t.Errorf("read back: %q %v", b, err)
	}
	if st, _ := os.Stat(good); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode())
	}
}

func TestWriteFileLimitsAndModes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p := filepath.Join(e.cfg.MountBase, "f")
	for _, mode := range []uint32{0o4755, 0o2755, 0o1777, 0o666, 0o777 | 0o10000} {
		if err := e.local.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("x"), Mode: mode}); err == nil {
			t.Errorf("mode %#o accepted", mode)
		}
	}
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: p, Data: make([]byte, 5<<20), Mode: 0o644}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("huge file: %v", err)
	}
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("x"), Mode: 0o644, UID: 0xffffffff}); err == nil {
		t.Error("invalid uid accepted")
	}
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("x"), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	// no temp file is left behind
	ents, _ := os.ReadDir(e.cfg.MountBase)
	for _, en := range ents {
		if strings.Contains(en.Name(), "jotmp") {
			t.Errorf("leftover %s", en.Name())
		}
	}
	// removing a root is refused, a missing file is not an error
	if err := e.local.Remove(ctx, e.cfg.ConfDir); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("remove root: %v", err)
	}
	if err := e.local.Remove(ctx, filepath.Join(e.cfg.MountBase, "missing")); err != nil {
		t.Errorf("remove missing: %v", err)
	}
	// reads are bounded
	big := filepath.Join(e.cfg.MountBase, "big")
	mustWrite(t, big, strings.Repeat("a", 5<<20))
	if _, err := e.local.ReadFile(ctx, big); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("big read: %v", err)
	}
	if _, err := e.local.ReadFile(ctx, e.cfg.ConfDir); err == nil {
		t.Error("read of a root")
	}
}

func TestConfDirContent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	l := e.local
	w := func(ctx context.Context, name, content string) error {
		return l.WriteFile(ctx, WriteFileReq{Path: filepath.Join(e.cfg.ConfDir, name), Data: []byte(content), Mode: 0o644})
	}
	if err := w(ctx, "alpha_web.conf", e.goodConf()); err != nil {
		t.Fatalf("the renderer's output was refused: %v", err)
	}
	// what the renderer writes for a jail with System V IPC, FreeBSD and Linux, passes as it is
	for _, osf := range []api.OS{api.OSFreeBSD, api.OSLinux} {
		jc, err := render.JailConf(render.JailConfInput{Name: "alpha_web", Path: filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root"),
			Hostname: "web.example.org", OS: osf, Interfaces: []string{"jo0123456789a0b"}, SysVIPC: true,
			Where: api.PromptContext{Jail: "web", Project: "alpha", Host: "babel"}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(jc, "sysvshm = new;") || !strings.Contains(jc, "exec.consolelog") || !strings.Contains(jc, "env.jailops_host = \"babel\";") {
			t.Fatalf("not rendered:\n%s", jc)
		}
		if err := w(ctx, "alpha_web.conf", jc); err != nil {
			t.Errorf("%s: the renderer's output with sysvipc was refused: %v", osf, err)
		}
	}
	if err := w(ctx, "notes.txt", "x"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("other file in the conf dir: %v", err)
	}
	if err := w(ctx, "other.conf", e.goodConf()); err == nil {
		t.Error("a conf whose block name differs from the file name was accepted")
	}
	mut := func(old, new string) string { return strings.Replace(e.goodConf(), old, new, 1) }
	hostile := map[string]string{
		"path outside":         mut(`path = "`+filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root")+`"`, `path = "/"`),
		"path traversal":       mut(`"`+filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root")+`"`, `"`+e.cfg.MountBase+`/../../etc"`),
		"no vnet":              mut("\tvnet;\n", ""),
		"allow flag":           mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tallow.mount.zfs;\n"),
		"raw param":            mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tcpuset = \"0\";\n"),
		"devfs ruleset":        mut("devfs_ruleset = 4", "devfs_ruleset = 1"),
		"enforce_statfs 0":     mut("enforce_statfs = 2", "enforce_statfs = 0"),
		"securelevel -1":       mut("securelevel = 2", "securelevel = -1"),
		"exec hook swapped":    mut(`exec.prestart = "/usr/local/libexec/jailops-priv hook prestart ${name}"`, `exec.prestart = "/tmp/evil ${name}"`),
		"hook with shell":      mut(`hook prestart ${name}"`, `hook prestart ${name}; id"`),
		"exec.start custom":    mut(`"/bin/sh /etc/rc"`, `"/bin/sh -c id"`),
		"variable in value":    mut(`host.hostname = "web.example.org"`, `host.hostname = "${x}"`),
		"foreign interface":    mut(`"jo0123456789a0b"`, `"em0"`),
		"second block":         e.goodConf() + "evil {\n\tpath = \"/\";\n}\n",
		"text after block":     e.goodConf() + "exec.start = \"id\";\n",
		"include":              "include \"/etc/jail.conf\";\n" + e.goodConf(),
		"no block":             "# nothing\n",
		"semicolon injection":  mut(`host.hostname = "web.example.org";`, `host.hostname = "a"; exec.start = "id";`),
		"multi value list":     mut(`vnet.interface = "jo0123456789a0b"`, `vnet.interface = "jo0123456789a0b", "em0"`),
		"quote in string":      mut(`"web.example.org"`, `"a\"b"`),
		"mount.fstab outside":  mut("\tmount.devfs;\n", "\tmount.fstab = \"/etc/fstab\";\n"),
		"nul":                  mut("vnet;", "vnet;\x00"),
		"consolelog elsewhere": mut(`"/var/log/jailops/jail_${name}_console.log"`, `"/etc/rc.conf"`),
		"consolelog variable":  mut(`"/var/log/jailops/jail_${name}_console.log"`, `"/var/log/jailops/jail_${path}_console.log"`),
		"consolelog bare":      mut(`exec.consolelog = "/var/log/jailops/jail_${name}_console.log";`, `exec.consolelog;`),
		"sysvshm inherit":      mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tsysvshm = inherit;\n"),
		"sysvsem quoted":       mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tsysvsem = \"new\";\n"),
		"sysvmsg bare":         mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tsysvmsg;\n"),
		"sysvmsg disable then": mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tsysvmsg = new; exec.start = \"id\";\n"),
		"env other key":        mut("\tvnet;\n", "\tenv.PATH = \"/evil\";\n\tvnet;\n"),
		"env short key":        mut("\tvnet;\n", "\tenv.jail = \"web\";\n\tvnet;\n"),
		"env upper case key":   mut("\tvnet;\n", "\tenv.JAILOPS_JAIL = \"web\";\n\tvnet;\n"),
		"env prefixed other":   mut("\tvnet;\n", "\tenv.jailops_x = \"web\";\n\tvnet;\n"),
		"env value with space": mut("\tvnet;\n", "\tenv.jailops_jail = \"a b\";\n\tvnet;\n"),
		"env value variable":   mut("\tvnet;\n", "\tenv.jailops_host = \"${x}\";\n\tvnet;\n"),
		"env value upper case": mut("\tvnet;\n", "\tenv.jailops_project = \"Shop\";\n\tvnet;\n"),
		"env bare":             mut("\tvnet;\n", "\tenv.jailops_jail;\n\tvnet;\n"),
		"meta key":             mut("\tvnet;\n", "\tmeta.jailops_jail = \"web\";\n\tvnet;\n"),
	}
	for name, c := range hostile {
		if err := w(ctx, "alpha_web.conf", c); err == nil {
			t.Errorf("%s: hostile conf was accepted", name)
		}
	}
	// Admin allow-lists.
	cfg := e.cfg
	cfg.Admin = AdminPolicy{AllowFlags: []string{"mount.zfs"}, RawJailParams: []string{"cpuset"}, DevfsRulesets: []int{10}}
	l2, _ := NewLocal(cfg, Deps{ZFS: e.zfs}, WithoutChown())
	w2 := func(ctx context.Context, c string) error {
		return l2.WriteFile(ctx, WriteFileReq{Path: filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), Data: []byte(c), Mode: 0o644})
	}
	withFlag := mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tallow.mount.zfs;\n")
	if err := w2(ctx, withFlag); err == nil {
		t.Error("allow flag without the admin assertion")
	}
	adm := WithAdmin(ctx, "alice")
	if err := w2(adm, withFlag); err != nil {
		t.Errorf("allow-listed flag with admin: %v", err)
	}
	if err := w2(adm, mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tallow.raw_sockets;\n")); err == nil {
		t.Error("a flag that is not on the allow-list was accepted")
	}
	if err := w2(adm, mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tcpuset = \"0\";\n")); err != nil {
		t.Errorf("allow-listed raw param: %v", err)
	}
	if err := w2(adm, mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tchildren.max = 5;\n")); err == nil {
		t.Error("raw param that is not on the allow-list")
	}
	if err := w2(adm, mut("devfs_ruleset = 4", "devfs_ruleset = 10")); err != nil {
		t.Errorf("allow-listed devfs ruleset: %v", err)
	}
	if err := w2(adm, mut("devfs_ruleset = 4", "devfs_ruleset = 11")); err == nil {
		t.Error("devfs ruleset 11")
	}
	if err := w2(adm, mut("\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tcpuset = \"0;id\";\n")); err == nil {
		t.Error("unsafe raw value")
	}
}

func TestFstabContent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	b := e.cfg.MountBase
	path := filepath.Join(b, "jails", "alpine1", "fstab")
	w := func(ctx context.Context, l *Local, c string) error {
		return l.WriteFile(ctx, WriteFileReq{Path: path, Data: []byte(c), Mode: 0o644, Parents: true})
	}
	good := "# device mountpoint fstype options dump pass\n" +
		"devfs " + b + "/jails/alpine1/root/dev devfs rw,late 0 0\n" +
		"tmpfs " + b + "/jails/alpine1/root/dev/shm tmpfs rw,late,size=536870912,mode=1777 0 0\n" +
		b + "/projects/alpha/volumes/db " + b + "/jails/alpine1/root/var/lib/db nullfs rw 0 0\n" +
		b + "/projects/alpha/jails/alpine1/root " + b + "/projects/alpha/jails/alpine1/root/compat/linux nullfs rw,late 0 0\n"
	if err := w(ctx, e.local, good); err != nil {
		t.Fatalf("renderer style fstab refused: %v", err)
	}
	bad := map[string]string{
		"jail data as a source": b + "/projects/alpha/jails/web/data/db " + b + "/jails/a/root/x nullfs rw 0 0\n",
		"below a volume":        b + "/projects/alpha/volumes/db/sub " + b + "/jails/a/root/x nullfs rw 0 0\n",
		"the volumes parent":    b + "/projects/alpha/volumes " + b + "/jails/a/root/x nullfs rw 0 0\n",
		"a whole project":       b + "/projects/alpha " + b + "/jails/a/root/x nullfs rw 0 0\n",
		"another jail's root":   b + "/projects/alpha/jails/web/root " + b + "/jails/a/root/x nullfs rw 0 0\n",
		"host mount":            "/etc " + b + "/jails/a/root/etc nullfs ro 0 0\n",
		"mountpoint outside":    "devfs /dev devfs rw 0 0\n",
		"traversal":             b + "/../etc " + b + "/jails/a/root/x nullfs ro 0 0\n",
		"zfs type":              "tank/x " + b + "/jails/a/root/x zfs rw 0 0\n",
		"fields":                "devfs " + b + "/x devfs rw 0\n",
		"option injection":      "devfs " + b + "/jails/a/root/dev devfs rw;id 0 0\n",
		"device mismatch":       "/dev/ada0 " + b + "/jails/a/root/x tmpfs rw 0 0\n",
	}
	for name, c := range bad {
		if err := w(ctx, e.local, c); err == nil {
			t.Errorf("%s: hostile fstab accepted", name)
		}
	}
	cfg := e.cfg
	cfg.Admin.HostMountRoots = []string{filepath.Join(e.base, "share")}
	l2, _ := NewLocal(cfg, Deps{ZFS: e.zfs}, WithoutChown())
	hm := filepath.Join(e.base, "share", "pub") + " " + b + "/jails/a/root/srv nullfs ro 0 0\n"
	if err := w(ctx, l2, hm); err == nil {
		t.Error("host mount without the assertion")
	}
	if err := w(WithAdmin(ctx, "alice"), l2, hm); err != nil {
		t.Errorf("allow-listed host mount: %v", err)
	}
	evil := "/etc " + b + "/jails/a/root/srv nullfs ro 0 0\n"
	if err := w(WithAdmin(ctx, "alice"), l2, evil); err == nil {
		t.Error("host mount outside the allow-list")
	}
}

func TestJailControlRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	j := e.local.Jails()
	conf := filepath.Join(e.cfg.ConfDir, "alpha_web.conf")
	// The conf path must be the jail's own file in the conf dir.
	if err := j.Create(ctx, "/etc/passwd", "alpha_web"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("foreign conf: %v", err)
	}
	if err := j.Create(ctx, filepath.Join(e.cfg.ConfDir, "other.conf"), "alpha_web"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("another jail's conf: %v", err)
	}
	if err := j.Create(ctx, conf, "alpha_web"); err == nil {
		t.Error("create without a conf file")
	}
	mustWrite(t, conf, e.goodConf())
	if err := j.Create(ctx, conf, "-x"); err == nil {
		t.Error("jail named -x")
	}
	if err := j.Create(ctx, conf, "alpha_web"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// A conf replaced behind the helper's back is re-validated.
	mustWrite(t, conf, strings.Replace(e.goodConf(), "vnet;\n", "", 1))
	if err := j.Create(ctx, conf, "alpha_web"); err == nil {
		t.Error("tampered conf accepted")
	}
	// A symlinked conf is refused.
	mustWrite(t, filepath.Join(e.base, "evil.conf"), e.goodConf())
	_ = os.Remove(conf)
	if err := os.Symlink(filepath.Join(e.base, "evil.conf"), conf); err != nil {
		t.Fatal(err)
	}
	if err := j.Create(ctx, conf, "alpha_web"); err == nil {
		t.Error("symlinked conf accepted")
	}
	_ = os.Remove(conf)
	mustWrite(t, conf, e.goodConf())
	// Exec only enters managed jails and bounds its arguments.
	if _, err := j.Exec(ctx, "alpha_unmanaged", jailosExec("id")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("exec in an unmanaged jail: %v", err)
	}
	if _, err := j.Exec(ctx, "alpha_web", jailosExec()); err == nil {
		t.Error("empty argv")
	}
	if _, err := j.Exec(ctx, "alpha_web", jailosExec("-x")); err == nil {
		t.Error("argv[0] with a dash")
	}
	huge := make([]string, 300)
	for i := range huge {
		huge[i] = "a"
	}
	if _, err := j.Exec(ctx, "alpha_web", jailosExec(huge...)); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("argv count: %v", err)
	}
	if _, err := j.Exec(ctx, "alpha_web", jailosExec(strings.Repeat("a", 200<<10))); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("argv size: %v", err)
	}
	if _, err := j.Exec(ctx, "alpha_web", jailosExec("echo", "a\x00b")); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("NUL in argv: %v", err)
	}
	if _, err := j.Exec(ctx, "alpha_web", jailosExec("echo", "hi")); err != nil {
		t.Errorf("good exec: %v", err)
	}
}

func TestSysctlRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.runner.On("/sbin/sysctl", []string{"-n", "kern.osrelease"}, "15.0-RELEASE\n")
	if v, err := e.local.Sysctl(ctx, "kern.osrelease"); err != nil || v != "15.0-RELEASE" {
		t.Errorf("sysctl: %q %v", v, err)
	}
	for _, n := range []string{"kern.securelevel", "-a", "kern.osrelease=1", "kern.osrelease ", "", "vm.overcommit;id", "../x"} {
		if _, err := e.local.Sysctl(ctx, n); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("sysctl %q: %v", n, err)
		}
	}
}

func TestConfigNormalize(t *testing.T) {
	good := Config{StorageRoots: []string{"tank/jailops"}, MountBase: "/jailops"}
	if _, err := good.Normalize(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Config{
		"pool as root":   {StorageRoots: []string{"tank"}, MountBase: "/jailops"},
		"nested roots":   {StorageRoots: []string{"tank/a", "tank/a/b"}, MountBase: "/jailops"},
		"duplicate root": {StorageRoots: []string{"tank/a", "tank/a"}, MountBase: "/jailops"},
		"no state dir":   {StorageRoots: []string{"tank/a"}},
		"relative file":  {StorageRoots: []string{"tank/a"}, MountBase: "/j", StorageFile: "x/storage.conf"},
		"relative base":  {StorageRoots: []string{"tank/jailops"}, MountBase: "jailops"},
		"slash base":     {StorageRoots: []string{"tank/jailops"}, MountBase: "/"},
		"bad host mount": {StorageRoots: []string{"tank/jailops"}, MountBase: "/j", Admin: AdminPolicy{HostMountRoots: []string{"/"}}},
	} {
		if _, err := c.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Two writes of one path do not disturb each other, and a directory that a tenant planted under the name an older
// build used for the temporary file does not stop the write.
func TestWriteFileTemporaryNamesAreUnique(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p := filepath.Join(e.cfg.MountBase, "shared")
	if err := os.MkdirAll(filepath.Join(e.cfg.MountBase, ".shared.jotmp", "planted"), 0o755); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- e.local.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte(fmt.Sprintf("writer %d\n", i)), Mode: 0o644})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a concurrent write failed: %v", err)
		}
	}
	b, err := os.ReadFile(p)
	if err != nil || !strings.HasPrefix(string(b), "writer ") || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("the file is %q (%v)", b, err)
	}
	ents, _ := os.ReadDir(e.cfg.MountBase)
	for _, en := range ents {
		if strings.HasSuffix(en.Name(), ".jotmp") && en.Name() != ".shared.jotmp" {
			t.Errorf("leftover %s", en.Name())
		}
	}
}

// stop.timeout is the jail's own time to shut down: what the renderer writes passes, and only a number of seconds
// within the limit does.
func TestConfDirStopTimeout(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := func(content string) error {
		return e.local.WriteFile(ctx, WriteFileReq{Path: filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), Data: []byte(content), Mode: 0o644})
	}
	jc, err := render.JailConf(render.JailConfInput{Name: "alpha_web", Path: filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root"),
		Hostname: "web.example.org", OS: api.OSFreeBSD, Interfaces: []string{"jo0123456789a0b"}, StopTimeout: 90,
		Where: api.PromptContext{Jail: "web", Project: "alpha", Host: "babel"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jc, "\tstop.timeout = 90;\n") {
		t.Fatalf("not rendered:\n%s", jc)
	}
	if err := w(jc); err != nil {
		t.Fatalf("the renderer's output with a stop timeout was refused: %v", err)
	}
	for name, v := range map[string]string{"zero": "0", "too long": "3601", "negative": "-5", "text": "soon", "quoted": `"90"`, "variable": "${x}"} {
		if err := w(strings.Replace(jc, "stop.timeout = 90;", "stop.timeout = "+v+";", 1)); err == nil {
			t.Errorf("stop.timeout %s (%s) was accepted", name, v)
		}
	}
}
