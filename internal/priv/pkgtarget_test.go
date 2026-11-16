package priv

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// pkg runs as root and runs package scripts in a chroot of the root it is given, with what it finds there: so `-r`
// never names the root of a running jail, and a running jail gets pkg inside it with `-j`.
func TestPkgRefusesTheRootOfARunningJail(t *testing.T) {
	e := newEnv(t)
	ctx := WithAdmin(context.Background(), "a")
	mk := func(proj, name string) string {
		root := filepath.Join(e.cfg.MountBase, "projects", proj, "jails", name, "root")
		if err := os.MkdirAll(filepath.Join(root, "usr", "local"), 0o755); err != nil {
			t.Fatal(err)
		}
		return root
	}
	running := mk("alpha", "web")
	stopped := mk("alpha", "db")
	mustWrite(t, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), "alpha_web {\n\tpath = \""+running+"\";\n}\n")
	mustWrite(t, filepath.Join(e.cfg.ConfDir, "alpha_db.conf"), "alpha_db {\n\tpath = \""+stopped+"\";\n}\n")
	e.jails.Put(jailos.Jail{Name: "alpha_web", Path: running})
	e.runner.On("/usr/sbin/pkg", []string{run.RestArgs}, "ok\n")
	runPkg := func(args ...string) error {
		_, err := e.local.Runner().Run(ctx, run.Cmd{Name: "pkg", Args: args})
		return err
	}

	// a root nobody runs in
	if err := runPkg("-r", stopped, "install", "-y", "nginx"); err != nil {
		t.Errorf("a stopped jail's root: %v", err)
	}
	// the root of a running jail, spelled in every way
	link := filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "alias")
	if err := os.Symlink(filepath.Dir(running), link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{running, running + "/", running + "/usr/local", running + "/./usr", filepath.Join(link, "root")} {
		err := runPkg("-r", p, "install", "-y", "nginx")
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("pkg -r %s: %v (want forbidden)", p, err)
		}
	}
	if err := runPkg("-r", running+"/../../../../../..", "install", "-y", "nginx"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("with ..: %v", err)
	}
	// -o first does not hide the root from the check
	if err := runPkg("-o", "ABI=FreeBSD:15:amd64", "-r", running, "update", "-q"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("-o before -r: %v", err)
	}

	// -j: a running jail of JailOps, with none of the root's options
	if err := runPkg("-j", "alpha_web", "upgrade", "-n"); err != nil {
		t.Errorf("pkg -j of a running jail: %v", err)
	}
	if err := runPkg("-j", "alpha_db", "upgrade", "-n"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("pkg -j of a stopped jail: %v (want invalid)", err)
	}
	if err := runPkg("-j", "alpha_none", "upgrade", "-n"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("pkg -j of a jail JailOps does not manage: %v (want forbidden)", err)
	}
	if err := runPkg("-j", "web", "upgrade", "-n"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("pkg -j with a bare name: %v (want invalid)", err)
	}
	if err := runPkg("-j", "alpha_web", "-o", "REPOS_DIR="+e.cfg.StateDir, "update", "-q"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("pkg -j with REPOS_DIR: %v (want forbidden)", err)
	}
	// the host's ABI names no root
	if err := runPkg("config", "abi"); err != nil {
		t.Errorf("pkg config abi: %v", err)
	}
	// one target, not none and not two
	if err := runPkg("update", "-q"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("no target: %v", err)
	}
	if err := runPkg("-j", "alpha_web", "-r", stopped, "update", "-q"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("two targets: %v", err)
	}
}
