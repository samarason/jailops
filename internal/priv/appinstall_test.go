package priv

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Everything the app installer asks of the helper, with the exact argument
// vectors and paths the service builds (internal/apps), goes through the real
// checks: the command allow-list for pkg -r, the file operations for
// rc.conf, and the jail guard for the in-jail commands. The hostile forms
// are refused.
func TestAppInstallThroughTheHelper(t *testing.T) {
	e := newEnv(t)
	c := e.cfg
	ctx := context.Background()
	root := filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	ok := func(argv ...string) {
		t.Helper()
		_, out, err := c.CheckCommandCtx(ctx, argv)
		if err != nil {
			t.Errorf("%q: %v", argv, err)
			return
		}
		if out[0] != "/usr/sbin/pkg" || strings.Join(out[1:], "\x00") != strings.Join(argv[1:], "\x00") {
			t.Errorf("%q ran as %q", argv, out)
		}
	}
	bad := func(code api.Code, argv ...string) {
		t.Helper()
		if _, _, err := c.CheckCommandCtx(WithAdmin(ctx, "a"), argv); !api.IsCode(err, code) {
			t.Errorf("%q: %v (want %s)", argv, err, code)
		}
	}
	// pkg -r <root> install, from the FreeBSD repository and from the jailops one, and the version query
	ok(apps.PkgInstallArgv(root, "ports", []string{"nginx"})...)
	ok(apps.PkgInstallArgv(root, "ports", []string{"postgresql18-server", "postgresql18-contrib"})...)
	ok(apps.PkgInstallArgv(root, "jailops", []string{"jailops-tool"})...)
	ok(apps.PkgInstallArgv(root, "jailops", []string{"isms"})...)
	ok(apps.PkgInstallArgv(root, "ports", []string{"postfix", "dovecot"})...)
	ok(apps.PkgVersionArgv(root, "nginx")...)
	ok(apps.PkgVersionArgv(root, "py311-prometheus_client")...)
	// the download cache of the host, shared by every install: below the storage roots, nowhere else
	ok(apps.PkgInstallCachedArgv(root, "ports", e.cfg.MountBase+"/cache/pkg", []string{"bash"})...)
	ok(apps.PkgInstallCachedArgv(root, "jailops", e.cfg.MountBase+"/cache/pkg", []string{"isms"})...)
	bad(api.CodeForbidden, apps.PkgInstallCachedArgv(root, "ports", "/etc", []string{"bash"})...)
	bad(api.CodeForbidden, apps.PkgInstallCachedArgv(root, "ports", "/tmp/cache", []string{"bash"})...)
	// not a jail root: the storage root itself, outside it, climbing out, relative
	bad(api.CodeForbidden, apps.PkgInstallArgv(e.cfg.MountBase, "ports", []string{"nginx"})...)
	bad(api.CodeForbidden, apps.PkgInstallArgv("/usr/local", "ports", []string{"nginx"})...)
	bad(api.CodeForbidden, apps.PkgInstallArgv(root+"/../../../../../..", "ports", []string{"nginx"})...)
	bad(api.CodeForbidden, apps.PkgInstallArgv("projects/alpha/jails/web/root", "ports", []string{"nginx"})...)
	bad(api.CodeForbidden, apps.PkgVersionArgv("/etc", "nginx")...)
	// package names that are not names (pkg's own flags, -f and -x, stay what they are: the catalog refuses a
	// package name that starts with a dash, so the service never sends one)
	for _, n := range []string{"nginx; id", "nginx curl", "--rootdir=/", "-o", "", "nginx\n", "../nginx", "nginx|sh", "$(id)", "`id`"} {
		bad(api.CodeForbidden, apps.PkgInstallArgv(root, "ports", []string{n})...)
		bad(api.CodeForbidden, apps.PkgVersionArgv(root, n)...)
	}
	bad(api.CodeForbidden, "pkg", "-r", root, "query", "%v;id", "nginx")
	bad(api.CodeInvalid, "pkg", "install", "-y", "nginx") // no root
	bad(api.CodeForbidden, "pkg", "-r", root, "shell")
	bad(api.CodeForbidden, "pkg", "-r", root, "install", "-y", "-r", "../repos", "nginx")
	// a symbolic link as the root cannot lead out of the storage
	evil := filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "evil", "root")
	os.MkdirAll(filepath.Dir(evil), 0o755)
	os.Symlink("/etc", evil)
	bad(api.CodeForbidden, apps.PkgInstallArgv(evil, "ports", []string{"nginx"})...)

	// through the runner, the fixed binary runs with the arguments as they are
	e.runner.On("/usr/sbin/pkg", []string{run.RestArgs}, "1.30.6,3\n")
	res, err := e.local.Runner().Run(ctx, run.Cmd{Name: "pkg", Args: apps.PkgVersionArgv(root, "nginx")[1:]})
	if err != nil || string(res.Stdout) != "1.30.6,3\n" {
		t.Fatalf("%q %v", res.Stdout, err)
	}
	if _, err := e.local.Runner().Run(ctx, run.Cmd{Name: "pkg", Args: apps.PkgInstallArgv("/tmp/x", "ports", []string{"nginx"})[1:]}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a root outside the storage reached the runner: %v", err)
	}
	for _, call := range e.runner.Calls() {
		if call.Cmd.Name != "/usr/sbin/pkg" {
			t.Errorf("%q reached the runner", call.Cmd.Name)
		}
	}

	// rc.conf: written and read below the jail root through the file operations
	var vars []render.RcVar
	for _, v := range apps.RcVars([]api.AppService{{Name: "nginx"}, {Name: "postgresql", RC: map[string]string{"postgresql_initdb_flags": "--encoding=utf-8"}}}) {
		vars = append(vars, render.RcVar(v))
	}
	content, err := render.RcConfSet("hostname=\"web\"\n", vars)
	if err != nil {
		t.Fatal(err)
	}
	rc := apps.RcConfPath(root)
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: rc, Data: []byte(content), Mode: 0o644, Parents: true}); err != nil {
		t.Fatalf("write rc.conf: %v", err)
	}
	if b, err := e.local.ReadFile(ctx, rc); err != nil || string(b) != content {
		t.Fatalf("%q %v", b, err)
	}
	if b, _ := os.ReadFile(rc); !strings.Contains(string(b), "nginx_enable=\"YES\"") {
		t.Fatalf("not on disk: %q", b)
	}
	for _, p := range []string{"/etc/rc.conf", apps.RcConfPath("/usr/local"), apps.RcConfPath(root + "/../../../../../.."), e.cfg.MountBase, apps.RcConfPath(evil)} {
		if err := e.local.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("x_enable=\"YES\"\n"), Mode: 0o644}); err == nil {
			t.Errorf("wrote %s", p)
		}
	}
	if _, err := os.Stat("/etc/rc.conf.jotmp"); err == nil {
		t.Error("a temporary file was left in /etc")
	}

	// in-jail commands: the jail guard runs them in a managed jail only, as argv
	setup := []string{"/usr/sbin/chown", "postgres:postgres", "/var/db/postgres"}
	start, err := apps.ServiceStartArgv("nginx")
	if err != nil {
		t.Fatal(err)
	}
	jails := e.local.Jails()
	for _, argv := range [][]string{setup, apps.ServiceArgv("nginx", "start"), {"/usr/local/bin/pg_isready", "-U", "postgres"}, start} {
		if _, err := jails.Exec(ctx, "alpha_ghost", jailosExec(argv...)); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%q in an unmanaged jail: %v", argv, err)
		}
	}
	e.conf(t, "alpha_web")
	if err := e.jails.Create(ctx, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatal(err)
	}
	// the service start wrapper (/bin/sh -c with the fixed script, the name as an argument) is an ordinary in-jail
	// command: the jail guard passes it as it is
	for _, argv := range [][]string{setup, apps.ServiceArgv("nginx", "start"), {"/usr/local/bin/pg_isready", "-U", "postgres"}, start} {
		if _, err := jails.Exec(ctx, "alpha_web", jailosExec(argv...)); err != nil {
			t.Errorf("%q: %v", argv, err)
		}
	}
	var ran [][]string
	for _, call := range e.jails.Calls() {
		if call.Op == "exec" {
			ran = append(ran, call.Argv)
		}
	}
	if len(ran) != 4 || strings.Join(ran[0], " ") != strings.Join(setup, " ") || strings.Join(ran[1], " ") != "/usr/sbin/service nginx start" ||
		!slices.Equal(ran[3], []string{"/bin/sh", "-c", apps.ServiceStartScript, "jailops-start", "nginx"}) {
		t.Errorf("%q", ran)
	}
	if _, err := jails.Exec(ctx, "alpha_web", jailosExec("/bin/sh", "-c", "id\x00")); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("a NUL byte was accepted: %v", err)
	}
	if _, err := jails.Exec(ctx, "alpha_web; id", jailosExec(setup...)); err == nil {
		t.Error("a jail name with a shell character was accepted")
	}
}

// What an app draft asks of the helper: the one pkg query of the packages
// installed on purpose, exactly as internal/apps builds it, and read-only
// commands in a managed jail through the jail guard. Every other form of
// pkg query -e is refused.
func TestAppDraftThroughTheHelper(t *testing.T) {
	e := newEnv(t)
	c := e.cfg
	ctx := context.Background()
	root := filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "cache", "root")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	argv := apps.PkgLeavesArgv("alpha_cache")
	if _, out, err := c.CheckCommandCtx(ctx, argv); err != nil || out[0] != "/usr/sbin/pkg" || !slices.Equal(out[1:], argv[1:]) {
		t.Fatalf("%q: %q %v", argv, out, err)
	}
	bad := func(code api.Code, argv ...string) {
		t.Helper()
		if _, _, err := c.CheckCommandCtx(WithAdmin(ctx, "a"), argv); !api.IsCode(err, code) {
			t.Errorf("%q: %v (want %s)", argv, err, code)
		}
	}
	for _, rest := range [][]string{
		{"query", "-e", "%a = 1", "%n %v %R %w"},
		{"query", "-e", "%a = 0", "%n %v %R %w", "extra"},
		{"query", "-e", "%a = 0", "%n %v %R %w %M"},
		{"query", "-e", "%a = 0"},
		{"query", "-e", "%a = 0 || %n ~ *", "%n"},
		{"query", "-e", "%a = 0", "%n %v %R %w", "-x"},
		{"rquery", "-e", "%a = 0", "%n %v %R %w"},
		{"query", "-a", "-e", "%a = 0", "%n %v %R %w"},
	} {
		bad(api.CodeForbidden, append([]string{"pkg", "-r", root}, rest...)...)
	}
	// the exact form still needs a jail root
	bad(api.CodeInvalid, "pkg", "query", "-e", apps.PkgLeavesQuery, apps.PkgLeavesFormat)
	bad(api.CodeInvalid, apps.PkgLeavesArgv("/usr/local")...)
	bad(api.CodeInvalid, apps.PkgLeavesArgv(e.cfg.MountBase)...)
	bad(api.CodeInvalid, apps.PkgLeavesArgv(root+"/../../../../../..")...)
	bad(api.CodeInvalid, apps.PkgLeavesArgv("cache")...)
	bad(api.CodeForbidden, "pkg", "-o", "REPOS_DIR=/etc", "-r", root, "query", "-e", apps.PkgLeavesQuery, apps.PkgLeavesFormat)

	// the in-jail reads run in a managed jail only, as argv
	reads := [][]string{apps.SockstatArgv(), apps.FindNewerArgv("/usr/local/etc"), apps.FindNewerArgv("/var/log"), apps.StatOwnerArgv([]string{"/var/db/memcached", "/var/run/memcached"})}
	jails := e.local.Jails()
	for _, argv := range reads {
		if _, err := jails.Exec(ctx, "alpha_ghost", jailosExec(argv...)); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%q in an unmanaged jail: %v", argv, err)
		}
	}
	e.conf(t, "alpha_cache")
	if err := e.jails.Create(ctx, filepath.Join(e.cfg.ConfDir, "alpha_cache.conf"), "alpha_cache"); err != nil {
		t.Fatal(err)
	}
	for _, argv := range reads {
		if _, err := jails.Exec(ctx, "alpha_cache", jailosExec(argv...)); err != nil {
			t.Errorf("%q: %v", argv, err)
		}
	}
}
