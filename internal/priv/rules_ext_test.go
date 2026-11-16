package priv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

type ruleEnv struct {
	*env
	root, state, conf string
}

func newRuleEnv(t *testing.T) *ruleEnv {
	e := newEnv(t)
	r := &ruleEnv{env: e}
	r.root = filepath.Join(e.cfg.MountBase, "projects", "shop", "jails", "web", "root")
	r.state = e.cfg.StateDir
	os.MkdirAll(filepath.Join(r.root, "dev"), 0o755)
	os.MkdirAll(filepath.Join(r.root, "compat", "linux"), 0o755)
	os.MkdirAll(filepath.Join(e.cfg.MountBase, "projects", "default", "jails", "plain", "root", "etc"), 0o755)
	e.conf(t, "shop_web")
	e.conf(t, "default_plain")
	r.trustDirs(t)
	// the jail ends of their epairs, in their vnets, with the marker they were created with
	e.net.AddToJail("shop_web", ifconfig.Iface{Name: "jo0123456789ab", Groups: []string{"epair"}, Description: "jailops jail=shop/web net=lan (jail side)"})
	e.net.AddToJail("default_plain", ifconfig.Iface{Name: "jo0123456789cb", Groups: []string{"epair"}, Description: ifconfig.Marker})
	// what a jail's root could make in its own vnet: an interface without the marker, one with a description of its own
	e.net.AddToJail("shop_web", ifconfig.Iface{Name: "mine0x", Groups: []string{"epair"}})
	e.net.AddToJail("shop_web", ifconfig.Iface{Name: "forged", Groups: []string{"epair"}, Description: "my own"})
	e.net.AddToJail("shop_web", ifconfig.Iface{Name: "tunnel", Groups: []string{"tun"}, Description: ifconfig.Marker})
	return r
}

// check runs argv through the rule table and the jail verification, like the
// Runner does, without executing anything.
func (r *ruleEnv) check(ctx context.Context, argv ...string) error {
	rule, out, err := r.cfg.CheckCommandCtx(ctx, argv)
	if err != nil {
		return err
	}
	if rule.Verify != nil {
		return rule.Verify(ctx, r.local, out[1:])
	}
	return nil
}

func (r *ruleEnv) ok(t *testing.T, argv ...string) {
	t.Helper()
	if err := r.check(context.Background(), argv...); err != nil {
		t.Errorf("%q: %v", argv, err)
	}
}

func (r *ruleEnv) bad(t *testing.T, argv ...string) {
	t.Helper()
	if err := r.check(WithAdmin(context.Background(), "alice"), argv...); err == nil {
		t.Errorf("accepted %q", argv)
	}
}

func TestSysctlFallbackBrand(t *testing.T) {
	r := newRuleEnv(t)
	adm := WithAdmin(context.Background(), "a")
	for _, v := range []string{"-1", "3"} {
		if err := r.check(adm, "sysctl", "kern.elf64.fallback_brand="+v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
		if err := r.check(context.Background(), "sysctl", "kern.elf64.fallback_brand="+v); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("without admin: %v", err)
		}
	}
	for _, v := range []string{"0", "1", "2", "4", "-2", "03", "+3", " 3", "3 ", "", "-", "3;id", "0x3", "-01"} {
		r.bad(t, "sysctl", "kern.elf64.fallback_brand="+v)
	}
	r.ok(t, "sysctl", "-n", "kern.elf64.fallback_brand")
	r.ok(t, "sysctl", "-n", "net.inet.ip.forwarding")
	r.bad(t, "sysctl", "kern.elf64.fallback_brand")
	r.bad(t, "sysctl", "kern.elf32.fallback_brand=3")
}

func TestFetchRule(t *testing.T) {
	r := newRuleEnv(t)
	out := filepath.Join(r.state, "dl", "mini.tar.gz")
	os.MkdirAll(filepath.Dir(out), 0o755)
	const base = "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.0-aarch64.tar.gz"
	r.ok(t, "fetch", "-o", out, base)
	r.ok(t, "fetch", "-o", out, "https://pkg.freebsd.org/FreeBSD:15:aarch64/base_release_1/meta.conf")
	for _, u := range []string{
		"http://dl-cdn.alpinelinux.org/x", "https://evil.example/x", "https://dl-cdn.alpinelinux.org.evil.example/x", "https://evil.example/dl-cdn.alpinelinux.org/x",
		"https://user@dl-cdn.alpinelinux.org/x", "https://dl-cdn.alpinelinux.org:8443/x", "https://dl-cdn.alpinelinux.org/x?a=b", "https://dl-cdn.alpinelinux.org/x#f",
		"https://dl-cdn.alpinelinux.org/../x", "https://dl-cdn.alpinelinux.org/a/../../x", "https://dl-cdn.alpinelinux.org//x", "https://dl-cdn.alpinelinux.org",
		"https://DL-CDN.alpinelinux.org/x", "ftp://dl-cdn.alpinelinux.org/x", "file:///etc/passwd", "/etc/passwd", "", "-x", "https://dl-cdn.alpinelinux.org/x y",
		"https://dl-cdn.alpinelinux.org/x\n", "https://dl-cdn.alpinelinux.org/x;id", "https://dl-cdn.alpinelinux.org/é", "https://127.0.0.1/x", "https://[::1]/x",
		"https://pkg.freebsd.org\\@evil.example/x", "https://" + strings.Repeat("a", 300) + "/x", "https://dl-cdn.alpinelinux.org/" + strings.Repeat("a", 500),
	} {
		r.bad(t, "fetch", "-o", out, u)
	}
	for _, o := range []string{"/etc/passwd", "/tmp/x", "relative", "-", ""} {
		r.bad(t, "fetch", "-o", o, base)
	}
	r.bad(t, "fetch", base)
	r.bad(t, "fetch", "-o", out)
	r.bad(t, "fetch", "-o", out, base, base)
	r.bad(t, "fetch", "-q", "-o", out, base)
	r.bad(t, "fetch", "-o", out, "-T", "1", base)
	// the host list is configurable
	cfg := r.cfg
	cfg.FetchHosts = []string{"mirror.internal"}
	cfg, _ = cfg.Normalize()
	cfg.reg = r.cfg.reg
	if _, _, err := cfg.CheckCommand([]string{"fetch", "-o", out, "https://mirror.internal/x"}); err != nil {
		t.Error(err)
	}
	if _, _, err := cfg.CheckCommand([]string{"fetch", "-o", out, base}); err == nil {
		t.Error("default host accepted after configuring another")
	}
	if _, err := (Config{StateDir: "/x", FetchHosts: []string{"Bad Host"}}).Normalize(); err == nil {
		t.Error("bad fetch host accepted")
	}
}

func TestTarRuleCreatesOnlyTheMergeArchives(t *testing.T) {
	r := newRuleEnv(t)
	merge := filepath.Join(r.root, ".merge-1793281905")
	os.MkdirAll(merge, 0o755)
	old, new_ := filepath.Join(merge, "old-etc.tar"), filepath.Join(merge, "new-etc.tar")
	r.ok(t, "tar", "-C", r.root, "-cf", old, "./etc")
	r.ok(t, "tar", "-C", r.root, "-cf", new_, "./etc")
	for _, a := range [][]string{
		{"-C", r.root, "-cf", filepath.Join(merge, "x.tar"), "./etc"},              // another name
		{"-C", r.root, "-cf", filepath.Join(r.root, "old-etc.tar"), "./etc"},       // not in a .merge-* directory
		{"-C", r.root, "-cf", old, "./root"},                                       // another member
		{"-C", r.root, "-cf", old, "./etc", "./root"},                              // more members
		{"-C", r.root, "-cf", old, "etc"},                                          // not the exact member
		{"-C", "/", "-cf", old, "./etc"},                                           // outside the storage roots
		{"-C", "/etc", "-cf", old, "./etc"},                                        //
		{"-C", r.cfg.MountBase, "-cf", old, "./etc"},                               // the storage root itself
		{"-C", r.root, "-cf", "/etc/passwd", "./etc"},                              // a file outside
		{"-C", r.root, "-cf", "/var/tmp/.merge-1/old-etc.tar", "./etc"},            // outside the roots
		{"-C", r.root, "-chf", old, "./etc"}, {"-C", r.root, "-czf", old, "./etc"}, // other flags
		{"-C", r.root, "-cf", old, "--absolute-paths", "./etc"}, //
		{"-C", r.root, "-cf", old, "./etc", "--to-command=sh"},  //
		{"-cf", old, "./etc"}, {"-C", r.root, "-cf", old}, // missing parts
	} {
		r.bad(t, append([]string{"tar"}, a...)...)
	}
}

func TestTarRuleListsBeforeExtracting(t *testing.T) {
	r := newRuleEnv(t)
	ctx := context.Background()
	archive := filepath.Join(r.state, "mini.tar.gz")
	os.WriteFile(archive, []byte("x"), 0o644)
	dest := filepath.Join(r.root)
	r.ok(t, "tar", "-tzf", archive)
	r.runner.On("/usr/bin/tar", []string{"-tzf", archive}, "bin/\nbin/sh\n")
	r.ok(t, "tar", "-C", dest, "-xpzf", archive)
	for _, a := range [][]string{
		{"-C", "/", "-xpzf", archive}, {"-C", "/etc", "-xpzf", archive}, {"-C", r.cfg.MountBase, "-xpzf", archive}, {"-C", dest, "-xpzf", "/etc/x.tgz"},
		{"-C", dest, "-xpPzf", archive}, {"-C", dest, "-xzf", archive}, {"-C", dest, "-xpzf", archive, "extra"}, {"-xpzf", archive}, {"-C", dest, "-xpzf"},
		{"-tzf", "/etc/x.tgz"}, {"-czf", archive, "/etc"}, {"-tzf", archive, "x"}, {"--use-compress-program=sh", "-xf", archive}, {"-C", dest, "-xpzf", archive, "--absolute-paths"},
		{"-C", dest, "--to-command=sh", "-xpzf", archive}, {"-C", dest, "-xpzf", "-P"},
	} {
		r.bad(t, append([]string{"tar"}, a...)...)
	}
	// verification through the Runner: a hostile archive is never extracted
	run1 := func(list string) error {
		e := r.env
		e.runner = run.NewFake()
		l, _ := NewLocal(e.cfg, Deps{ZFS: e.zfs, Runner: e.runner}, WithoutChown())
		// the archive is copied into a directory of the helper's: listed and extracted from the copy
		e.runner.On("/usr/bin/tar", []string{"-tzf", run.AnyArg}, list)
		e.runner.On("/usr/bin/tar", []string{"-C", dest, "-xpzf", run.AnyArg}, "")
		_, err := l.Runner().Run(ctx, run.Cmd{Name: "tar", Args: []string{"-C", dest, "-xpzf", archive}})
		return err
	}
	if err := run1("./\n./bin/\n./bin/sh\netc/passwd\n"); err != nil {
		t.Errorf("clean archive: %v", err)
	}
	for name, list := range map[string]string{
		"absolute":      "bin/sh\n/etc/passwd\n",
		"dotdot":        "bin/sh\n../etc/passwd\n",
		"nested dotdot": "a/b/../../../x\n",
		"trailing dd":   "a/..\n",
		"only dotdot":   "..\n",
		"absolute dir":  "/\n",
	} {
		if err := run1(list); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the extract command did not run for a hostile archive
	e := r.env
	for _, c := range e.runner.Calls() {
		if len(c.Cmd.Args) > 0 && c.Cmd.Args[0] == "-C" {
			t.Error("a hostile archive was extracted")
		}
	}
}

func TestChmodRule(t *testing.T) {
	r := newRuleEnv(t)
	f := filepath.Join(r.root, "etc", "x")
	os.MkdirAll(filepath.Dir(f), 0o755)
	os.WriteFile(f, nil, 0o644)
	for _, m := range []string{"644", "0755", "1777", "0644", "600", "0", "1000"} {
		if m == "0" {
			r.bad(t, "chmod", m, f)
			continue
		}
		r.ok(t, "chmod", m, f)
	}
	for _, m := range []string{"4755", "2755", "6755", "7777", "3755", "u+s", "+s", "a+x", "-R", "0o755", "888", "75", "07555", "", "--reference=/etc/passwd", "u=rwx"} {
		r.bad(t, "chmod", m, f)
	}
	for _, p := range []string{"/etc/passwd", "/", r.cfg.MountBase, "relative", "-R", f + "/../../..", "/etc/../" + f} {
		r.bad(t, "chmod", "644", p)
	}
	r.bad(t, "chmod", "644")
	r.bad(t, "chmod", "-R", "644", f)
	r.bad(t, "chmod", "644", f, "/etc/passwd")
	link := filepath.Join(r.root, "etc", "link")
	os.Symlink("/etc/passwd", link)
	r.bad(t, "chmod", "644", link)
}

func TestMountRules(t *testing.T) {
	r := newRuleEnv(t)
	dev, mirror := filepath.Join(r.root, "dev"), filepath.Join(r.root, "compat", "linux")
	shm := filepath.Join(mirror, "dev", "shm")
	os.MkdirAll(shm, 0o755)
	r.ok(t, "mount", "-t", "devfs", "-o", "ruleset=100", "devfs", dev)
	r.ok(t, "mount", "-t", "devfs", "-o", "ruleset=4", "devfs", dev)
	r.ok(t, "mount", "-t", "devfs", "devfs", dev)
	r.ok(t, "mount", "-t", "fdescfs", "fdescfs", filepath.Join(r.root, "dev", "fd"))
	r.ok(t, "mount", "-t", "nullfs", r.root, mirror)
	r.ok(t, "mount", "-t", "nullfs", "-o", "ro", r.root, mirror)
	r.ok(t, "mount", "-t", "tmpfs", "-o", "size=67108864,mode=1777", "tmpfs", shm)
	r.ok(t, "mount", "-t", "linprocfs", "linprocfs", filepath.Join(r.root, "proc"))
	r.ok(t, "mount", "-t", "linsysfs", "linsysfs", filepath.Join(r.root, "sys"))
	for _, a := range [][]string{
		{"-t", "zfs", "tank/x", dev}, {"-t", "ufs", "/dev/ada0", dev}, {"-t", "msdosfs", "x", dev}, {"-t", "procfs", "procfs", dev}, {"-t", "devfs"},
		{"devfs", "devfs", dev}, {"-t", "devfs", "devfs"}, {"-t", "devfs", "devfs", dev, "extra"}, {"-a"}, {"-t", "nullfs", "/", mirror}, {"-t", "nullfs", "/etc", mirror},
		{"-t", "nullfs", r.cfg.MountBase, mirror}, {"-t", "nullfs", r.root, "/etc"}, {"-t", "nullfs", r.root, "/"}, {"-t", "nullfs", r.root, r.root},
		{"-t", "devfs", "devfs", "/dev"}, {"-t", "devfs", "devfs", r.cfg.MountBase}, {"-t", "tmpfs", "tmpfs", filepath.Join(r.cfg.MountBase, "state")},
		{"-t", "devfs", "-o", "ruleset=3", "devfs", dev}, {"-t", "devfs", "-o", "ruleset=99", "devfs", dev}, {"-t", "devfs", "-o", "ruleset=100000", "devfs", dev},
		{"-t", "tmpfs", "-o", "mode=4755", "tmpfs", shm}, {"-t", "tmpfs", "-o", "mode=2755", "tmpfs", shm}, {"-t", "tmpfs", "-o", "size=1g;id", "tmpfs", shm},
		{"-t", "nullfs", "-o", "ruleset=100", r.root, mirror}, {"-t", "devfs", "-o", "size=1m", "devfs", dev}, {"-t", "nullfs", "-o", "suid", r.root, mirror},
		{"-t", "nullfs", "-o", "ro,-t", r.root, mirror}, {"-t", "nullfs", "-o", "", r.root, mirror}, {"-t", "nullfs", "-o", "ro", r.root},
		{"-t", "devfs", "-u", "devfs", dev}, {"-t", "devfs", "devfs", dev + "/../../../etc"}, {"-t", "devfs", "devfs", "relative/dev"},
		// not below a jail root: the jail dataset itself, its sibling, another jail without a conf
		{"-t", "devfs", "devfs", filepath.Dir(r.root)}, {"-t", "devfs", "devfs", filepath.Join(filepath.Dir(r.root), "other")},
		{"-t", "devfs", "devfs", filepath.Join(r.cfg.MountBase, "projects", "shop", "jails", "ghost", "root", "dev")},
		{"-t", "devfs", "devfs", filepath.Join(r.cfg.MountBase, "projects", "Shop", "jails", "web", "root", "dev")},
		{"-t", "devfs", "devfs", filepath.Join(r.cfg.MountBase, "images", "x", "g1", "root", "dev")},
	} {
		r.bad(t, append([]string{"mount"}, a...)...)
	}
	// a symlink inside the root that leads out
	os.Symlink("/etc", filepath.Join(r.root, "evil"))
	r.bad(t, "mount", "-t", "devfs", "devfs", filepath.Join(r.root, "evil"))
	// umount
	r.ok(t, "umount", dev)
	r.ok(t, "umount", "-f", mirror)
	for _, a := range [][]string{{"/"}, {"/dev"}, {"-a"}, {"-A"}, {"-f"}, {"-f", "-f", dev}, {"-fv", dev}, {dev, dev}, {"tank/x"}, {r.cfg.MountBase}, {filepath.Dir(r.root)},
		{"-t", "nullfs", dev}, {dev + "/../../.."}, {"-f", "/etc"}, {filepath.Join(filepath.Dir(r.root), "other", "dev")}, {""}} {
		r.bad(t, append([]string{"umount"}, a...)...)
	}
	r.bad(t, "umount", filepath.Join(r.cfg.MountBase, "projects", "shop", "jails", "ghost", "root", "dev"))
	// a project named default is an ordinary project; the layout from before projects does not exist
	plain := filepath.Join(r.cfg.MountBase, "projects", "default", "jails", "plain", "root", "etc")
	r.ok(t, "mount", "-t", "devfs", "devfs", plain)
	legacy := filepath.Join(r.cfg.MountBase, "jails", "plain", "root", "dev")
	os.MkdirAll(legacy, 0o755)
	r.bad(t, "mount", "-t", "devfs", "devfs", legacy)
}

func TestJailRule(t *testing.T) {
	r := newRuleEnv(t)
	conf := filepath.Join(r.cfg.ConfDir, "shop_web.conf")
	r.ok(t, "jail", "-c", "-f", conf)
	r.ok(t, "jail", "-f", conf, "-c")
	r.ok(t, "jail", "-r", "-f", conf, "shop_web")
	r.ok(t, "jail", "-c", "-f", conf, "shop_web")
	for _, a := range [][]string{
		{"-c"}, {"-f", conf}, {"-c", "-r", "-f", conf}, {"-c", "-f", conf, "-f", conf}, {"-c", "-f", "/etc/jail.conf"}, {"-c", "-f", filepath.Join(r.cfg.ConfDir, "..", "x.conf")},
		{"-c", "-f", r.cfg.ConfDir}, {"-c", "-f", conf, "default_plain"}, {"-c", "-f", conf, "shop_web", "extra"}, {"-c", "-f", conf, "-m"}, {"-c", "-f", conf, "persist"},
		{"-c", "-f", conf, "path=/", "name=x"}, {"-c", "-f", conf, "exec.start=/bin/sh"}, {"-cmr", "-f", conf}, {"-c", "-f"}, {"-c", "-f", "relative.conf"},
		{"-c", "-f", filepath.Join(r.cfg.ConfDir, "ghost.conf")}, {"-c", "-f", filepath.Join(r.cfg.ConfDir, "shop_web.conf.bak")}, {"-e", "x"}, {"-c", "-f", conf, "-l"},
		{"-c", "-f", filepath.Join(r.cfg.ConfDir, "Shop_web.conf")},
	} {
		r.bad(t, append([]string{"jail"}, a...)...)
	}
	// a conf file whose content is not acceptable is not run
	evil := filepath.Join(r.cfg.ConfDir, "evil.conf")
	os.WriteFile(evil, []byte("evil {\n\tpath = \"/\";\n\texec.start = \"/bin/sh -c id\";\n}\n"), 0o644)
	r.bad(t, "jail", "-c", "-f", evil)
}

func TestDevfsRule(t *testing.T) {
	r := newRuleEnv(t)
	for _, a := range [][]string{
		{"rule", "-s", "100", "add", "hide"}, {"rule", "-s", "100", "add", "include", "4"}, {"rule", "-s", "65535", "add", "path", "null", "unhide"},
		{"rule", "-s", "101", "add", "path", "dri/*", "unhide"}, {"rule", "-s", "101", "add", "path", "zfs", "hide"}, {"rule", "-s", "101", "add", "path", "pts/*", "include", "4"},
		{"rule", "-s", "101", "add", "path", "random", "mode", "666"}, {"rule", "-s", "101", "add", "path", "tty", "mode", "0666"},
		{"rule", "-s", "101", "add", "path", "tty", "user", "root"}, {"rule", "-s", "101", "add", "path", "tty", "group", "tty"},
	} {
		r.ok(t, append([]string{"devfs"}, a...)...)
	}
	for _, a := range [][]string{
		{"rule", "-s", "4", "add", "hide"}, {"rule", "-s", "99", "add", "hide"}, {"rule", "-s", "0", "add", "hide"}, {"rule", "-s", "65536", "add", "hide"}, {"rule", "-s", "-1", "add", "hide"},
		{"rule", "-s", "100x", "add", "hide"}, {"rule", "-s", "", "add", "hide"}, {"rule", "-s", "100", "del", "1"}, {"rule", "-s", "100", "apply", "hide"},
		{"rule", "add", "hide"}, {"rule", "-s", "100", "add"}, {"rule", "-s", "100", "add", "path"}, {"rule", "-s", "100", "add", "path", "tty"}, {"rule", "-s", "100", "add", "show"},
		{"rule", "-s", "100", "add", "path", "/dev/null", "unhide"}, {"rule", "-s", "100", "add", "path", "../x", "unhide"}, {"rule", "-s", "100", "add", "path", "a b", "unhide"},
		{"rule", "-s", "100", "add", "path", "x;id", "unhide"}, {"rule", "-s", "100", "add", "path", "tty", "mode", "4755"}, {"rule", "-s", "100", "add", "path", "tty", "mode", "2755"},
		{"rule", "-s", "100", "add", "path", "tty", "mode", "u+s"}, {"rule", "-s", "100", "add", "path", "tty", "mode", "77777"}, {"rule", "-s", "100", "add", "path", "tty", "user", "-x"},
		{"rule", "-s", "100", "add", "path", "tty", "user", "a b"}, {"rule", "-s", "100", "add", "path", "tty", "user", "0"}, {"rule", "-s", "100", "add", "path", "tty", "include", "x"},
		{"rule", "-s", "100", "add", "include", "x"}, {"rule", "-s", "100", "add", "hide", "extra"}, {"rule", "-s", "100", "add", "path", "tty", "unhide", "extra"},
		{"-m", "/dev", "rule", "-s", "100", "add", "hide"}, {"ruleset", "100"}, {"rule", "showsets"}, {"rule", "-s", "5", "delset"}, {"rule", "-s", "100", "delset", "x"}, {"rule", "-s", "100", "add", "path", "tty", "mode", "666", "user", "root", "x", "y"},
		{"rule", "-s", "100", "add", "path", "tty", "-x"}, {"rule", "-s", "100", "add", "path", "*", "unhide", ";", "id"}, {},
	} {
		r.bad(t, append([]string{"devfs"}, a...)...)
	}
	// an admin may add rulesets below 100 through AdminPolicy.DevfsRulesets only for mounting, not defining
	r.bad(t, "devfs", "rule", "-s", "10", "add", "hide")
	// dropping the ruleset of a build jail is for an admin (the daemon's system actor) only
	if err := r.check(WithAdmin(context.Background(), "jailopsd"), "devfs", "rule", "-s", "37885", "delset"); err != nil {
		t.Errorf("admin delset: %v", err)
	}
	if err := r.check(context.Background(), "devfs", "rule", "-s", "37885", "delset"); err == nil {
		t.Error("delset without the admin assertion")
	}
}

func TestJexecApkRule(t *testing.T) {
	r := newRuleEnv(t)
	r.ok(t, "jexec", "shop_web", "/sbin/apk", "add", "--no-cache", "openssh", "nginx")
	r.ok(t, "jexec", "shop_web", "/sbin/apk", "update")
	r.ok(t, "jexec", "shop_web", "/sbin/apk", "upgrade", "--simulate")
	r.ok(t, "jexec", "shop_web", "/sbin/apk", "del", "nginx")
	r.ok(t, "jexec", "shop_web", "/sbin/apk", "info", "-v")
	// the build jail of an image (jobuild-<image>-g<N>) runs apk too, and only apk, and only through jexec
	r.ok(t, "jexec", "jobuild-alpine-3-g1", "/sbin/apk", "--no-interactive", "add", "--no-cache", "openssh")
	r.ok(t, "jexec", "jobuild-debian-12-g12", "/sbin/apk", "update")
	r.bad(t, "jexec", "jobuild-alpine-3-g1", "/bin/sh", "-c", "id")
	r.bad(t, "jexec", "jobuild-alpine-3", "/sbin/apk", "update")    // no generation
	r.bad(t, "jexec", "jobuild-Alpine-g1", "/sbin/apk", "update")   // not a build jail name
	r.bad(t, "jexec", "jobuild_alpine_g1", "/sbin/apk", "update")   // not a build jail name, not a key
	r.bad(t, "ifconfig", "-j", "jobuild-alpine-3-g1", "jo1b", "up") // the build jail has no vnet interface
	r.bad(t, "route", "-j", "jobuild-alpine-3-g1", "add", "default", "10.0.0.1")
	r.bad(t, "route", "-j", "jobuild-alpine-3-g1", "add", "-host", "10.0.0.1", "-interface", "jo1b")
	r.ok(t, "jexec", "shop_web", "/sbin/apk", "--version")
	r.ok(t, "jexec", "default_plain", "/sbin/apk", "add", "curl=8.0.0-r0", "libressl>=3.0")
	for _, a := range [][]string{
		{"ghost", "/sbin/apk", "add", "x"}, {"shop_web", "/bin/sh", "-c", "id"}, {"shop_web", "/sbin/apk"}, {"shop_web", "/sbin/apk", "fix"}, {"shop_web", "/sbin/apk", "add", "-X", "http://evil/"},
		{"shop_web", "/sbin/apk", "add", "--repositories-file", "/x"}, {"shop_web", "/sbin/apk", "add", "--allow-untrusted", "x"}, {"shop_web", "/sbin/apk", "add", "x;id"}, {"shop_web", "/sbin/apk", "add", "$(id)"},
		{"shop_web", "/sbin/apk", "add", "-p", "/"}, {"shop_web", "/sbin/apk", "add", "--root", "/"}, {"shop_web", "/sbin/apk", "add", "x y"}, {"shop_web", "/sbin/apk", "add", "-"},
		{"-U", "root", "shop_web", "/sbin/apk", "add", "x"}, {"-l", "shop_web", "/sbin/apk", "add", "x"}, {"shop_web", "apk", "add", "x"}, {"shop_web", "/usr/sbin/pkg", "add", "x"},
		{"../x", "/sbin/apk", "add", "x"}, {"Shop_web", "/sbin/apk", "add", "x"}, {"shop_web;id", "/sbin/apk", "add", "x"}, {"", "/sbin/apk", "add", "x"}, {"1", "/sbin/apk", "add", "x"},
		{"shop_web", "/sbin/apk", "add", strings.Repeat("a", 200)}, {"shop_web", "/sbin/apk", "add", "x\n"},
	} {
		r.bad(t, append([]string{"jexec"}, a...)...)
	}
	r.bad(t, "jexec", "shop_web", "/sbin/apk", "add", strings.Repeat("x ", 100))
}

func TestIfconfigRules(t *testing.T) {
	r := newRuleEnv(t)
	i := "jo0123456789ab"
	r.ok(t, "ifconfig", "-j", "shop_web", i, "up")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "down")
	r.ok(t, "ifconfig", "-j", "shop_web", i)
	r.ok(t, "ifconfig", "-j", "shop_web", i, "description", "jailops jail=shop/web net=lan (jail side)")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "description", "jailops managed")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "mtu", "1400")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "inet", "10.20.0.12/24", "up")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "inet", "10.20.0.12", "prefixlen", "24")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "inet", "10.20.0.12", "netmask", "255.255.255.0")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "inet", "10.20.0.12", "-alias")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "inet6", "fd00:20::12", "prefixlen", "64")
	r.ok(t, "ifconfig", "-j", "shop_web", i, "inet6", "fd00:20::12", "-alias")
	r.ok(t, "ifconfig", "-j", "default_plain", "jo0123456789cb", "inet6", "2001:db8::5", "prefixlen", "128", "alias")
	r.ok(t, "ifconfig", "-j", "shop_web", "em0") // reading is not changing
	for _, a := range [][]string{
		// interfaces of the host are made and renamed by the typed operations only (they mark them), never here
		{"bridge", "create"}, {"epair", "create"}, {"bridge0", "name", "jo0"}, {"bridge12", "name", "office"}, {"epair3a", "name", i + "a"},
		{"bridge0", "name", "mybr"}, {"bridge0", "name", "jo7"},
		// inside the jail: only an interface with the marker
		{"-j", "shop_web", "mine0x", "up"}, {"-j", "shop_web", "forged", "up"}, {"-j", "shop_web", "forged", "description", "jailops x"},
		{"-j", "shop_web", "tunnel", "up"}, {"-j", "shop_web", "jo0123456789cb", "up"}, // another jail's
		{"create"}, {"bridge"}, {"bridge", "create", "x"}, {"lo", "create"}, {"vlan", "create"}, {"tap", "create"}, {"bridge0", "destroy"}, {"bridge0", "name", "em0"}, {"bridge0", "name", "lo0"},
		{"bridge0", "name", "jo"}, {"bridge0", "name", "-x"}, {"bridge0", "name", "jo0", "extra"}, {"em0", "name", "jo0"}, {"bridge", "name", "jo0"}, {"epair3", "name", "jo0"}, {"epair3c", "name", "jo0"},
		{"bridge0", "addm", "em0"}, {"em0", "up"}, {"em0", "inet", "10.0.0.1/24"}, {"-a"}, {"-l"}, {}, {"jo0", "mtu", "1400"}, {"jo0", "up"},
		// -j forms
		{"-j", "ghost", i, "up"}, {"-j", "shop_web", "em0", "up"}, {"-j", "shop_web", "lo0", "up"}, {"-j", "shop_web", "-x", "up"}, {"-j", "shop_web", i, "destroy"},
		{"-j", "ghost", i}, {"-j", "shop_web", i, "description"}, {"-j", "shop_web", i, "description", ""},
		{"-j", "shop_web", i, "description", "my text"}, {"-j", "shop_web", i, "description", "jailops a;b"}, {"-j", "shop_web", i, "description", "jailops a\nb"},
		{"-j", "shop_web", i, "description", "jailops " + strings.Repeat("x", 60)}, {"-j", "shop_web", i, "description", "jailops ok", "up"}, {"-j", "shop_web", i, "-description"},
		{"-j", "shop_web", i, "mtu", "100"}, {"-j", "shop_web", i, "mtu", "99999"}, {"-j", "shop_web", i, "mtu", "x"}, {"-j", "shop_web", i, "mtu"}, {"-j", "shop_web", i, "up", "down"},
		{"-j", "shop_web", i, "vnet", "x"}, {"-j", "shop_web", i, "-vnet", "x"}, {"-j", "shop_web", i, "ether", "00:00:00:00:00:01"}, {"-j", "shop_web", i, "name", "jo9"},
		{"-j", "shop_web", i, "inet", "10.20.0.12/33"}, {"-j", "shop_web", i, "inet", "10.20.0.12/-1"}, {"-j", "shop_web", i, "inet", "fd00::1/64"}, {"-j", "shop_web", i, "inet", "x"},
		{"-j", "shop_web", i, "inet", "0.0.0.0/0"}, {"-j", "shop_web", i, "inet", "224.0.0.1"}, {"-j", "shop_web", i, "inet", "10.0.0.1", "prefixlen", "24", "prefixlen", "24"},
		{"-j", "shop_web", i, "inet", "10.0.0.1/24", "prefixlen", "24"}, {"-j", "shop_web", i, "inet", "10.0.0.1", "netmask", "x"}, {"-j", "shop_web", i, "inet", "10.0.0.1", "broadcast", "10.0.0.255"},
		{"-j", "shop_web", i, "inet", "10.0.0.1", "up", "-alias"}, {"-j", "shop_web", i, "inet", "10.0.0.1", "prefixlen", "24;id"},
		{"-j", "shop_web", i, "inet6", "fd00::1/64"}, {"-j", "shop_web", i, "inet6", "fd00::1/64", "prefixlen", "64"}, {"-j", "shop_web", i, "inet6", "10.0.0.1"}, {"-j", "shop_web", i, "inet6", "::"},
		{"-j", "shop_web", i, "inet6", "ff02::1"}, {"-j", "shop_web", i, "inet6", "fe80::1%em0"}, {"-j", "shop_web", i, "inet6", "fd00::1", "prefixlen", "129"}, {"-j", "shop_web", i, "inet6", "fd00::1", "up"},
		{"-j", "shop_web", i, "inet6", "fd00::1", "netmask", "ffff::"}, {"-j", "shop_web", i, "inet", "::ffff:10.0.0.1"}, {"-j", "shop_web", i, "inet6", "::ffff:10.0.0.1"},
		{"-j", "0", i, "up"}, {"-j", "shop_web;id", i, "up"}, {"-j", "-x", i, "up"}, {"-j"}, {"-j", "shop_web"},
		{"-v", "-j", "shop_web", i, "up"}, {"-j", "shop_web", "-j", "default_plain", i, "up"},
	} {
		r.bad(t, append([]string{"ifconfig"}, a...)...)
	}
}

func TestJailRouteCommandRules(t *testing.T) {
	r := newRuleEnv(t)
	i := "jo0123456789ab"
	r.ok(t, "route", "-j", "shop_web", "add", "default", "10.20.0.1")
	r.ok(t, "route", "-j", "shop_web", "delete", "default", "10.20.0.1")
	r.ok(t, "route", "-j", "shop_web", "add", "-inet6", "default", "fd00:20::1")
	r.ok(t, "route", "-j", "shop_web", "add", "-inet6", "default", "fe80::1%"+i)
	r.ok(t, "route", "-j", "default_plain", "add", "10.20.0.7", "10.20.0.1")
	r.ok(t, "route", "-j", "default_plain", "add", "-inet6", "2001:db8::7", "fd00:20::1")
	for _, a := range [][]string{
		{"add", "default", "10.20.0.1"}, {"-j", "shop_web", "add"}, {"-j", "shop_web", "add", "default"}, {"-j", "shop_web", "flush"}, {"-j", "shop_web", "get", "default"},
		{"-j", "shop_web", "change", "default", "10.20.0.1"}, {"-j", "ghost", "add", "default", "10.20.0.1"}, {"-j", "shop_web", "add", "default", "fd00::1"}, {"-j", "shop_web", "add", "-inet6", "default", "10.20.0.1"},
		{"-j", "shop_web", "add", "-inet", "default", "10.20.0.1"}, {"-j", "shop_web", "add", "default", "x"}, {"-j", "shop_web", "add", "default", "0.0.0.0"}, {"-j", "shop_web", "add", "default", "224.0.0.1"},
		{"-j", "shop_web", "add", "default", "10.20.0.1", "extra"}, {"-j", "shop_web", "add", "-net", "10.0.0.0/8", "10.20.0.1"}, {"-j", "shop_web", "add", "10.0.0.0/8", "10.20.0.1"},
		{"-j", "shop_web", "add", "default", "-interface", "em0"}, {"-j", "shop_web", "add", "default", "10.20.0.1/24"}, {"-j", "shop_web", "add", "-inet6", "default", "fe80::1%em0"},
		{"-j", "shop_web", "add", "-inet6", "default", "fd00::1%" + i}, {"-j", "shop_web", "add", "default", "10.20.0.1%" + i}, {"-j", "shop_web", "add", "-inet6", "default", "fe80::1%"},
		{"-n", "-j", "shop_web", "add", "default", "10.20.0.1"}, {"-j", "shop_web;id", "add", "default", "10.20.0.1"}, {"-j", "-x", "add", "default", "10.20.0.1"}, {"-j", "shop_web", "add", "-inet6", "-inet6", "default", "fd00::1"},
		{"-j", "shop_web", "add", "default", "10.20.0.1\n"}, {"-j", "shop_web", "add", "-inet6", "::", "fd00::1"}, {"-j"},
		// an interface of the jail's vnet without the marker
		{"-j", "shop_web", "add", "-inet6", "default", "fe80::1%forged"}, {"-j", "shop_web", "add", "-inet6", "default", "fe80::1%mine0x"},
		{"-j", "shop_web", "add", "-host", "10.20.0.1", "-interface", "forged"}, {"-j", "shop_web", "add", "-host", "10.20.0.1", "-interface", "em0"},
	} {
		r.bad(t, append([]string{"route"}, a...)...)
	}
}

func TestReadFileAllowList(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	mirror := filepath.Join(e.base, "mirror")
	os.MkdirAll(filepath.Join(mirror, "alpine"), 0o755)
	os.WriteFile(filepath.Join(mirror, "alpine", "SHA256SUMS"), []byte("sums"), 0o644)
	os.Symlink("/etc/passwd", filepath.Join(mirror, "alpine", "evil"))
	outside := filepath.Join(e.base, "secret")
	os.WriteFile(outside, []byte("s"), 0o600)
	os.Symlink(outside, filepath.Join(mirror, "alpine", "escape"))
	cfg := e.cfg
	cfg.ImageMirrors = []string{mirror}
	l, err := NewLocal(cfg, Deps{ZFS: e.zfs}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	if b, err := l.ReadFile(ctx, filepath.Join(mirror, "alpine", "SHA256SUMS")); err != nil || string(b) != "sums" {
		t.Errorf("mirror read: %q %v", b, err)
	}
	for _, p := range []string{filepath.Join(mirror, "alpine", "evil"), filepath.Join(mirror, "alpine", "escape"), mirror + "/../secret", "/etc/passwd", "/etc/shadow", "/etc/sysctl.conf.bak",
		"/etc/resolv.conf/x", "/etc/../etc/passwd", "/etc", "/", filepath.Join(e.base, "secret")} {
		if _, err := l.ReadFile(ctx, p); err == nil {
			t.Errorf("read %q accepted", p)
		}
	}
	// the fixed files, when they exist on this host
	for _, p := range ReadOnlyFiles {
		st, err := os.Lstat(p)
		if err != nil {
			if _, err := l.ReadFile(ctx, p); !api.IsCode(err, api.CodeNotFound) {
				t.Errorf("%s (absent): %v", p, err)
			}
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 {
			// e.g. /etc/resolv.conf on a systemd host points into /run: a link out of /etc is refused on purpose
			if _, err := l.ReadFile(ctx, p); err != nil && !api.IsCode(err, api.CodeForbidden) {
				t.Errorf("%s (a symlink): %v", p, err)
			}
			continue
		}
		if _, err := l.ReadFile(ctx, p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	// reading is all the mirror and the fixed files allow
	if err := l.WriteFile(ctx, WriteFileReq{Path: filepath.Join(mirror, "x"), Data: []byte("x"), Mode: 0o644}); err == nil {
		t.Error("write into a mirror accepted")
	}
	if err := l.WriteFile(ctx, WriteFileReq{Path: "/etc/resolv.conf", Data: []byte("x"), Mode: 0o644}); err == nil {
		t.Error("write to /etc/resolv.conf accepted")
	}
	if err := l.Remove(ctx, "/etc/resolv.conf"); err == nil {
		t.Error("remove of /etc/resolv.conf accepted")
	}
	if _, err := (Config{StateDir: "/s", ImageMirrors: []string{"/"}}).Normalize(); err == nil {
		t.Error("/ as a mirror accepted")
	}
	if _, err := (Config{StateDir: "/s", ImageMirrors: []string{"relative"}}).Normalize(); err == nil {
		t.Error("relative mirror accepted")
	}
}

func TestExtendedRulesRunThroughTheRunner(t *testing.T) {
	r := newRuleEnv(t)
	ctx := context.Background()
	e := r.env
	e.runner.On("/sbin/ifconfig", []string{"-j", "shop_web", "jo0123456789ab", "up"}, "")
	e.runner.On("/sbin/route", []string{"-j", "shop_web", "add", "default", "10.20.0.1"}, "")
	e.runner.On("/sbin/mount", []string{"-t", "devfs", "-o", "ruleset=100", "devfs", filepath.Join(r.root, "dev")}, "")
	rn := e.local.Runner()
	for _, c := range []run.Cmd{
		{Name: "ifconfig", Args: []string{"-j", "shop_web", "jo0123456789ab", "up"}},
		{Name: "route", Args: []string{"-j", "shop_web", "add", "default", "10.20.0.1"}},
		{Name: "mount", Args: []string{"-t", "devfs", "-o", "ruleset=100", "devfs", filepath.Join(r.root, "dev")}},
	} {
		if _, err := rn.Run(ctx, c); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
	// refused by the guard, never reaching the fake
	for _, c := range []run.Cmd{
		{Name: "route", Args: []string{"-j", "ghost", "add", "default", "10.20.0.1"}},
		{Name: "mount", Args: []string{"-t", "devfs", "devfs", "/etc"}},
		{Name: "chmod", Args: []string{"4755", filepath.Join(r.root, "x")}},
		{Name: "/sbin/route", Args: []string{"-j", "shop_web", "add", "default", "10.20.0.1"}},
	} {
		if _, err := rn.Run(ctx, c); err == nil {
			t.Errorf("%s %q accepted", c.Name, c.Args)
		}
	}
	for _, c := range e.runner.Calls() {
		if strings.Contains(strings.Join(c.Cmd.Args, " "), "ghost") || c.Cmd.Name == "/bin/chmod" {
			t.Errorf("refused command reached the runner: %v", c.Cmd)
		}
	}
}

func TestCommandTableIsComplete(t *testing.T) {
	want := []string{"sysctl", "kldstat", "kldload", "pfctl", "fetch", "tar", "chmod", "mount", "umount", "jail", "devfs", "jexec", "ifconfig", "route", "uname", "rctl", "dnctl", "pkg", "etcupdate", "pwd_mkdb", "freebsd-version", "debootstrap"}
	have := map[string]bool{}
	for _, r := range CommandRules {
		have[r.Name] = true
		if r.Custom == nil && r.Exact == nil && len(r.Subcommands) == 0 {
			t.Errorf("rule %s accepts nothing", r.Name)
		}
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("rule %s missing", n)
		}
	}
	if len(CommandRules) != len(want) {
		t.Errorf("table has %d rules, want %d: update the test when adding one", len(CommandRules), len(want))
	}
}

func TestBuildJailForms(t *testing.T) {
	r := newRuleEnv(t)
	root := r.cfg.reg.mounts()[0] + "/images/alpine/staging-g1"
	good := []string{"jail", "-c", "name=jobuild-alpine-g1", "path=" + root, "host.hostname=jobuild-alpine-g1", "persist", "ip4=inherit", "ip6=inherit", "devfs_ruleset=37885", "exec.clean"}
	admin := WithAdmin(context.Background(), "jailopsd")
	if err := r.check(admin, good...); err != nil {
		t.Fatalf("%v", err)
	}
	if err := r.check(context.Background(), good...); err == nil {
		t.Error("build jail without the admin assertion")
	}
	for i, v := range map[int]string{2: "name=web", 3: "path=/", 8: "devfs_ruleset=3", 6: "ip6=new", 7: "exec.prestart=id"} {
		a := append([]string(nil), good...)
		a[i] = v
		if err := r.check(admin, a...); err == nil {
			t.Errorf("accepted %q", a)
		}
	}
	if err := r.check(admin, "jail", "-r", "jobuild-alpine-g1"); err != nil {
		t.Error(err)
	}
	if err := r.check(admin, "jail", "-r", "alpha_web"); err == nil {
		t.Error("removed a jail that is not a build jail")
	}
}

// trustDirs makes the root-owned key and keyring directories the helper trusts (the test's user stands in for root).
func (r *ruleEnv) trustDirs(t *testing.T) {
	t.Helper()
	base, _ := filepath.EvalSymlinks(t.TempDir())
	oldUID, oldAnchor := trustUID, trustAnchor
	trustUID, trustAnchor = uint32(os.Getuid()), base
	t.Cleanup(func() { trustUID, trustAnchor = oldUID, oldAnchor })
	r.cfg.PkgKeysDir = filepath.Join(base, "trust", "keys")
	r.cfg.KeyringDir = filepath.Join(base, "trust", "keyrings")
	for _, d := range []string{filepath.Join(r.cfg.PkgKeysDir, "vendor", "trusted"), r.cfg.KeyringDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(r.cfg.PkgKeysDir, "vendor", "trusted", "key1"), filepath.Join(r.cfg.KeyringDir, "debian-archive-keyring.gpg"), filepath.Join(r.cfg.KeyringDir, "k.gpg")} {
		if err := os.WriteFile(f, []byte("key\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fixModes(t, base)
}
