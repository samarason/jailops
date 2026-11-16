package priv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

func TestCommandAllowList(t *testing.T) {
	e := newEnv(t)
	root := filepath.Join(e.cfg.MountBase, "jails", "web", "root")
	other := filepath.Join(e.cfg.MountBase, "jails", "web", "new")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	c := e.cfg
	type tc struct {
		name string
		argv []string
		ok   bool
	}
	cases := []tc{
		// what lifecycle runs
		{"pkg install", []string{"pkg", "-r", root, "install", "-y", "nginx"}, true},
		{"pkg upgrade", []string{"pkg", "-r", root, "upgrade", "-y"}, true},
		{"pkg update -f", []string{"pkg", "-r", root, "update", "-f"}, true},
		{"pkg delete", []string{"pkg", "-r", root, "delete", "-y", "curl"}, true},
		{"pkg info", []string{"pkg", "-r", root, "info"}, true},
		{"etcupdate", []string{"etcupdate", "-D", root, "-s", other}, true},
		{"etcupdate resolve", []string{"etcupdate", "-D", root, "resolve"}, true},

		// hostile
		{"no command", nil, false},
		{"empty name", []string{""}, false},
		{"shell", []string{"sh", "-c", "id"}, false},
		{"absolute path", []string{"/usr/sbin/pkg", "-r", root, "info"}, false},
		{"relative binary", []string{"./pkg", "-r", root, "info"}, false},
		{"zfs", []string{"zfs", "destroy", "-r", "tank"}, false},
		{"pkg no root", []string{"pkg", "install", "nginx"}, false},
		{"pkg root /", []string{"pkg", "-r", "/", "install", "x"}, false},
		{"pkg root outside", []string{"pkg", "-r", "/usr/local", "install", "x"}, false},
		{"pkg root mount base", []string{"pkg", "-r", e.cfg.MountBase, "install", "x"}, false},
		{"pkg root traversal", []string{"pkg", "-r", root + "/../../../..", "install", "x"}, false},
		{"pkg root relative", []string{"pkg", "-r", "jails/web", "install", "x"}, false},
		{"pkg root twice", []string{"pkg", "-r", root, "-r", "/", "install", "x"}, false},
		{"pkg option before root", []string{"pkg", "-o", "REPOS_DIR=/tmp", "-r", root, "install", "x"}, false},
		{"pkg -C config", []string{"pkg", "-r", root, "-C", "/tmp/x.conf", "install", "x"}, false},
		{"pkg unknown subcommand", []string{"pkg", "-r", root, "register", "x"}, false},
		{"pkg --option rest", []string{"pkg", "-r", root, "install", "--option", "x"}, false},
		{"pkg flag injection", []string{"pkg", "-r", root, "install", "-y", "-o", "x"}, false},
		{"pkg name with shell chars", []string{"pkg", "-r", root, "install", "x;id"}, false},
		{"pkg name with space", []string{"pkg", "-r", root, "install", "a b"}, false},
		{"pkg leading dash name", []string{"pkg", "-r", root, "install", "-evil"}, false},
		{"pkg NUL", []string{"pkg", "-r", root, "install", "a\x00b"}, false},
		{"etcupdate no -D", []string{"etcupdate", "-s", other}, false},
		{"etcupdate -D outside", []string{"etcupdate", "-D", "/etc", "-s", other}, false},
		{"etcupdate -s outside", []string{"etcupdate", "-D", root, "-s", "/"}, false},
		{"etcupdate unknown flag", []string{"etcupdate", "-D", root, "-p"}, false},
		{"etcupdate -d outside", []string{"etcupdate", "-D", root, "-d", "/tmp/x"}, false},
	}
	for _, k := range cases {
		rule, argv, err := c.CheckCommand(k.argv)
		if k.ok {
			if err != nil {
				t.Errorf("%s: %v", k.name, err)
				continue
			}
			if !strings.HasPrefix(argv[0], "/usr/sbin/") || rule.Name != k.argv[0] {
				t.Errorf("%s: binary %q", k.name, argv[0])
			}
		} else if err == nil {
			t.Errorf("%s: accepted %q", k.name, k.argv)
		}
	}
}

func TestCommandSymlinkEscape(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(e.base, "elsewhere")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	jails := filepath.Join(e.cfg.MountBase, "jails")
	if err := os.MkdirAll(jails, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(jails, "sneaky")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.cfg.CheckCommand([]string{"pkg", "-r", link, "install", "x"}); err == nil {
		t.Error("a jail root symlinked outside the base was accepted")
	}
}

func TestRunnerGuard(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := filepath.Join(e.cfg.MountBase, "jails", "web", "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	e.runner.On("/usr/sbin/pkg", []string{"-r", root, "info"}, "ok\n")
	r := e.local.Runner()
	res, err := r.Run(ctx, run.Cmd{Name: "pkg", Args: []string{"-r", root, "info"}})
	if err != nil || string(res.Stdout) != "ok\n" {
		t.Fatalf("%q %v", res.Stdout, err)
	}
	last := e.runner.Calls()[len(e.runner.Calls())-1].Cmd
	if last.Name != "/usr/sbin/pkg" || last.Timeout != 3600*1e9 {
		t.Errorf("ran %+v", last)
	}
	if _, err := r.Run(ctx, run.Cmd{Name: "pkg", Args: []string{"-r", root, "info"}, Env: []string{"LD_PRELOAD=/x"}}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("env: %v", err)
	}
	if _, err := r.Run(ctx, run.Cmd{Name: "pkg", Args: []string{"-r", root, "info"}, Dir: "/"}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("dir: %v", err)
	}
	if _, err := r.Run(ctx, run.Cmd{Name: "rm", Args: []string{"-rf", "/"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("rm: %v", err)
	}
	for _, c := range e.runner.Calls() {
		if c.Cmd.Name == "rm" {
			t.Error("rm reached the runner")
		}
	}
}

func TestOperationListHasNoCommandOperation(t *testing.T) {
	// The wire surface is this list; "run.exec" is the only operation that
	// runs a program and it is limited by CommandRules.
	for _, n := range OperationNames() {
		if strings.Contains(n, "shell") || strings.HasSuffix(n, ".sh") || strings.HasPrefix(n, "run.") && n != OpRun {
			t.Errorf("suspicious operation %q", n)
		}
	}
	if len(OperationNames()) < 60 {
		t.Errorf("only %d operations registered", len(OperationNames()))
	}
}

// The boot pass of the daemon reads kern.boottime through the helper to tell a restart of the daemon (no jail is started)
// from a boot of the host (autostart jails start). A name missing here is refused, the daemon reads an empty id, and
// every restart of the daemon then counts as a boot.
func TestBootTimeIsReadableThroughTheHelper(t *testing.T) {
	c := Config{}
	if err := customSysctl(c, false, []string{"-n", "kern.boottime"}); err != nil {
		t.Fatalf("kern.boottime: %v", err)
	}
}
