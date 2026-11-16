package priv

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

func TestParseJailName(t *testing.T) {
	good := map[string]JailName{
		"default_web":                  {Project: "default", Name: "web"},
		"shop_web-1":                   {Project: "shop", Name: "web-1"},
		"shop_web":                     {Project: "shop", Name: "web"},
		"p1-x_n-1":                     {Project: "p1-x", Name: "n-1"},
		"a_b":                          {Project: "a", Name: "b"},
		"a_" + strings.Repeat("a", 61): {Project: "a", Name: strings.Repeat("a", 61)},
	}
	for in, want := range good {
		got, err := ParseJailName(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
		if got.Internal() != in {
			t.Errorf("%q: Internal() = %q", in, got.Internal())
		}
	}
	for _, in := range []string{
		"", "_", "_web", "shop_", "Shop_web", "shop_Web", "1shop_web", "shop_1web", "shop__web", "shop_web_x", "a_b_c", "web", "web-1", strings.Repeat("a", 63),
		"-web", "web\n", "web\x00", "../x", "shop/web", "shop_../x", "Web", "web.conf", " web", "web ",
		strings.Repeat("a", 65), strings.Repeat("a", 40) + "_" + strings.Repeat("b", 40), "shop:web", "jo0_web;id", "shop\u00e9_web",
	} {
		if _, err := ParseJailName(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if JailAnchor(JailName{Project: "shop", Name: "web"}) != "jailops/shop/web" || JailAnchor(JailName{Project: "default", Name: "web"}) != "jailops/default/web" {
		t.Error("anchors")
	}
	if got := jailDatasets("tank/j", JailName{Project: "shop", Name: "web"}); len(got) != 1 || got[0] != "tank/j/projects/shop/jails/web" {
		t.Errorf("datasets %v", got)
	}
	if got := jailDatasets("tank/j", JailName{Project: "default", Name: "web"}); len(got) != 1 || got[0] != "tank/j/projects/default/jails/web" {
		t.Errorf("a project named default is an ordinary project: %v", got)
	}
}

func FuzzParseJailName(f *testing.F) {
	for _, s := range []string{"shop_web", "web", "a_b_c", "", "A_b", "x_", "_"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseJailName(s)
		if err != nil {
			return
		}
		if n.Internal() != s {
			t.Fatalf("%q -> %+v -> %q", s, n, n.Internal())
		}
		if strings.ContainsAny(s, "/\x00 \n.;$\"") || len(s) > MaxInternalName || strings.Contains(n.Name, "_") {
			t.Fatalf("accepted %q", s)
		}
		if err := checkAnchor(JailAnchor(n)); err != nil {
			t.Fatalf("anchor of %q: %v", s, err)
		}
	})
}

// newProjectEnv lays out one jail in the project layout:
// <root>/projects/<project>/jails/<name>, conf <project>_<name>.conf.
func newProjectEnv(t *testing.T, project, name string) *hookEnv {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	h := &hookEnv{env: e}
	internal := project + "_" + name
	h.host, h.jail, _ = ipam.EpairNames(hookUUID, 0)
	ds := "tank/jailops/projects/" + project + "/jails/" + name
	mp := filepath.Join(e.cfg.MountBase, "projects", project, "jails", name)
	e.managedDS("tank/jailops/projects/" + project + "/jails")
	if err := e.zfs.Create(ctx, zfs.CreateOpts{Name: ds, Props: map[string]string{"jailops:managed": "on", "mountpoint": mp}}); err != nil {
		t.Fatal(err)
	}
	spec := api.JailSpec{Image: "freebsd-15-0@stable", OS: api.OSFreeBSD, Network: []api.NetworkAttach{{Network: "lan", IPv4: "10.20.0.12"}}}
	rec, _ := json.Marshal(map[string]any{"version": 1, "metadata": api.ObjectMeta{Name: name, UUID: hookUUID, Project: project}, "spec": spec})
	mustWrite(t, filepath.Join(mp, "spec.json"), string(rec))
	nw := api.NetworkSpec{Uplink: "em0", MTU: 1400, IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.200"}}
	doc, _ := json.Marshal(map[string]any{"kind": "Network", "metadata": api.ObjectMeta{Name: "lan", UUID: "aaaa-1111-2222"}, "spec": nw})
	mustWrite(t, filepath.Join(e.cfg.StateDir, "objects", "Network", "aaaa-1111-2222.json"), string(doc))
	conf := e.goodConfNamed(internal)
	mustWrite(t, filepath.Join(e.cfg.ConfDir, internal+".conf"), conf)
	e.runner.Add(run.Rule{Name: "ifconfig", Args: []string{run.RestArgs}})
	e.runner.Add(run.Rule{Name: "rctl", Args: []string{run.RestArgs}})
	e.runner.Add(run.Rule{Name: "/sbin/ifconfig", Args: []string{"-j", internal, run.AnyArg, "description", run.AnyArg}})
	return h
}

func TestHookInTheProjectLayout(t *testing.T) {
	h := newProjectEnv(t, "shop", "web")
	ctx := context.Background()
	const internal = "shop_web"
	// the anchor file is named by the internal name and loads into jailops/<project>/<jail>
	mustWrite(t, h.cfg.PFAnchorFile(internal), "pass in on "+h.host+" all\n")
	if err := h.local.RunHook(ctx, PhasePreStart, internal); err != nil {
		t.Fatalf("prestart: %v", err)
	}
	if _, ok := h.ifaces()[h.host]; !ok {
		t.Errorf("host epair end %s missing: %v", h.host, h.ifaces())
	}
	if err := h.jails.Create(ctx, filepath.Join(h.cfg.ConfDir, internal+".conf"), internal); err != nil {
		t.Fatal(err)
	}
	if err := h.local.RunHook(ctx, PhasePostStart, internal); err != nil {
		t.Fatalf("poststart: %v", err)
	}
	if h.pf.LoadCalls["jailops/shop/web"] != 1 || h.pf.LoadCalls["jailops/shop"] != 1 || len(h.pf.LoadCalls) != 2 {
		t.Errorf("anchor loads: %v", h.pf.LoadCalls)
	}
	if err := h.local.RunHook(ctx, PhasePostStop, internal); err != nil {
		t.Fatalf("poststop: %v", err)
	}
	if a, _ := h.pf.Read(ctx, "jailops/shop/web"); a != "" {
		t.Errorf("anchor left behind: %q", a)
	}
	if _, ok := h.ifaces()[h.host]; ok {
		t.Errorf("epair left behind: %v", h.ifaces())
	}
}

func TestHookRefusesProjectMismatchAndAmbiguity(t *testing.T) {
	h := newProjectEnv(t, "shop", "web")
	ctx := context.Background()
	// the same name in another project is a different jail: no dataset
	if err := h.local.RunHook(ctx, PhasePreStart, "blog_web"); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("another project: %v", err)
	}
	// a spec.json that names another project is refused
	ds := "tank/jailops/projects/blog/jails/web"
	h.managedDS("tank/jailops/projects/blog/jails")
	mp := filepath.Join(h.cfg.MountBase, "blog")
	if err := h.zfs.Create(ctx, zfs.CreateOpts{Name: ds, Props: map[string]string{"jailops:managed": "on", "mountpoint": mp}}); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(filepath.Join(h.cfg.MountBase, "projects", "shop", "jails", "web", "spec.json"))
	mustWrite(t, filepath.Join(mp, "spec.json"), string(src))
	if err := h.local.RunHook(ctx, PhasePreStart, "blog_web"); !api.IsCode(err, api.CodeConflict) {
		t.Errorf("spec of another project: %v", err)
	}
	for _, bad := range []string{"", "web/../x", "shop_", "shop_web;id", "SHOP_web", "a_b_c", "../shop_web"} {
		if err := h.local.RunHook(ctx, PhasePreStart, bad); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("hook %q: %v", bad, err)
		}
	}
	// the same jail in two storage roots is a conflict
	mp2 := h.root("tank/second")
	_ = mp2
	if err := h.local.RegisterStorage(WithAdmin(ctx, "a"), "tank/second"); err != nil {
		t.Fatal(err)
	}
	h.addDS("tank/second/projects/shop/jails/web", map[string]string{"jailops:managed": "on", "mountpoint": filepath.Join(mp2, "x")})
	if err := h.local.RunHook(ctx, PhasePreStart, "shop_web"); !api.IsCode(err, api.CodeConflict) {
		t.Errorf("two roots: %v", err)
	}
}

func TestHookFindsAJailInTheSecondRoot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.runner.Add(run.Rule{Name: "rctl", Args: []string{run.RestArgs}})
	mp := e.root("tank/second")
	if err := e.local.RegisterStorage(WithAdmin(ctx, "a"), "tank/second"); err != nil {
		t.Fatal(err)
	}
	jmp := filepath.Join(mp, "j")
	e.addDS("tank/second/projects/p/jails/n", map[string]string{"jailops:managed": "on", "mountpoint": jmp})
	spec := api.JailSpec{OS: api.OSFreeBSD}
	rec, _ := json.Marshal(map[string]any{"metadata": api.ObjectMeta{Name: "n", UUID: hookUUID, Project: "p"}, "spec": spec})
	mustWrite(t, filepath.Join(jmp, "spec.json"), string(rec))
	conf := e.goodConfNamed("p_n")
	mustWrite(t, filepath.Join(e.cfg.ConfDir, "p_n.conf"), conf)
	for _, ph := range []string{PhasePreStart, PhasePostStart, PhasePostStop} {
		if err := e.local.RunHook(ctx, ph, "p_n"); err != nil {
			t.Errorf("%s: %v", ph, err)
		}
	}
}

func TestConfDirNamesFollowTheProjectScheme(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := func(file, name string) error {
		conf := e.goodConfNamed(name)
		return e.local.WriteFile(ctx, WriteFileReq{Path: filepath.Join(e.cfg.ConfDir, file), Data: []byte(conf), Mode: 0o644})
	}
	for _, n := range []string{"shop_web", "default_web", "a-b_c-d"} {
		if err := w(n+".conf", n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for file, name := range map[string]string{
		"shop_web.conf": "shop_db",   // block named differently from the file
		"Shop_web.conf": "Shop_web",  // upper case
		"shop-web.conf": "shop-web.", // bad name
		"shop_.conf":    "shop_",
		"a_b_c.conf":    "a_b_c",
		"1_b.conf":      "1_b",
		"web_1.conf":    "web_1",
		"web.conf":      "web", // a jail key carries its project
	} {
		if err := w(file, name); err == nil {
			t.Errorf("%s with block %s accepted", file, name)
		}
	}
	// the directory form
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: filepath.Join(e.cfg.ConfDir, "shop_db", "jail.conf"),
		Data: []byte(e.goodConfNamed("shop_db")), Mode: 0o644, Parents: true}); err != nil {
		t.Errorf("dir form: %v", err)
	}
	// a fstab for a project jail
	fs := filepath.Join(e.cfg.ConfDir, "shop_web.fstab")
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: fs, Data: []byte("tmpfs " + e.cfg.MountBase + "/projects/shop/jails/web/root/tmp tmpfs rw 0 0\n"), Mode: 0o644}); err != nil {
		t.Errorf("fstab: %v", err)
	}
}

func TestJailMayOnlyBeUsedWhenItsConfExists(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const internal = "shop_web"
	j := e.local.Jails()
	conf := filepath.Join(e.cfg.ConfDir, internal+".conf")
	if err := j.Create(ctx, conf, internal); err == nil {
		t.Error("created a jail whose conf does not exist")
	}
	if _, err := j.Exec(ctx, internal, jailosExec("echo")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("exec in a jail without a conf: %v", err)
	}
	if _, _, err := e.net.EpairCreate(ctx, "jo0"); err != nil {
		t.Fatal(err)
	}
	if err := e.local.Net().MoveToJail(ctx, "jo0a", internal); err == nil {
		t.Error("moved an interface into a jail without a conf")
	}
	mustWrite(t, conf, e.goodConfNamed(internal))
	if err := j.Create(ctx, conf, internal); err != nil {
		t.Errorf("create with conf: %v", err)
	}
	if _, err := j.Exec(ctx, internal, jailosExec("echo", "hi")); err != nil {
		t.Errorf("exec: %v", err)
	}
	// a conf that is a symlink, a directory, or for another name does not count
	other := "shop_db"
	if err := os.Symlink(conf, filepath.Join(e.cfg.ConfDir, other+".conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Exec(ctx, other, jailosExec("echo")); err == nil {
		t.Error("a symlinked conf made a jail 'managed'")
	}
	if err := j.Create(ctx, filepath.Join(e.cfg.ConfDir, internal+".conf"), other); err == nil {
		t.Error("the conf of another jail was accepted")
	}
	for _, bad := range []string{"", "..", "shop_web;id", "shop/web", "SHOP_web"} {
		if _, err := j.Exec(ctx, bad, jailosExec("echo")); err == nil {
			t.Errorf("exec in %q", bad)
		}
	}
	var _ jailos.Jails = j
}

func TestPFAnchorsStayUnderJailOps(t *testing.T) {
	for _, a := range []string{"jailops/shop/web", "jailops/web", "jailops/shared.pf", "jailops/net.lan"} {
		if err := checkAnchor(a); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"", "jailops", "jailops/", "other/shop/web", "jailops/../x", "/jailops/x", "jailops//x", "jailops/x y", "jailops/x\n", "jailopsX/web"} {
		if err := checkAnchor(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
}

func TestHookRefusesSpecWithAnotherName(t *testing.T) {
	h := newProjectEnv(t, "shop", "web")
	ctx := context.Background()
	p := filepath.Join(h.cfg.MountBase, "projects", "shop", "jails", "web", "spec.json")
	b, _ := os.ReadFile(p)
	for name, edit := range map[string]string{
		"name":    strings.Replace(string(b), `"name":"web"`, `"name":"db"`, 1),
		"project": strings.Replace(string(b), `"project":"shop"`, `"project":"other"`, 1),
		"default": strings.Replace(string(b), `"project":"shop"`, `"project":"default"`, 1),
	} {
		if edit == string(b) {
			t.Fatalf("%s: edit did not apply to %s", name, b)
		}
		os.WriteFile(p, []byte(edit), 0o644)
		if err := h.local.RunHook(ctx, PhasePreStart, "shop_web"); !api.IsCode(err, api.CodeConflict) {
			t.Errorf("spec with another %s: %v", name, err)
		}
	}
}
