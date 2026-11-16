package cli_test

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

func TestExecAndExitStatus(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "start", "web")
	tr := h.transcript()
	tr.ok("exec", "web", "--", "echo", "hello", "world")
	out, _, code := tr.do("piped input\n", "exec", "web", "--", "cat")
	if code != 0 || out != "piped input\n" {
		t.Fatalf("cat: %d %q", code, out)
	}
	_, errs, code := tr.do("", "exec", "web", "--", "exit", "3")
	if code != 3 || errs != "" {
		t.Fatalf("exit status must pass through quietly: %d %q", code, errs)
	}
	_, errs, code = tr.do("", "exec", "web", "--", "stderr", "oops")
	if code != 0 || errs != "oops" {
		t.Fatalf("stderr: %d %q", code, errs)
	}
	_, _, code = tr.do("", "exec", "web", "--", "nosuchprogram")
	if code != 127 {
		t.Fatalf("127: %d", code)
	}
	tr.do("", "exec", "ghost", "--", "echo", "x")
	tr.do("", "exec", "web")
	tr.ok("--dry-run", "exec", "web", "--", "rm", "-rf", "/")
	for _, c := range h.srv.ExecCalls() {
		if len(c.Argv) > 0 && c.Argv[0] == "rm" {
			t.Fatal("dry-run ran the command")
		}
		if c.TTY {
			t.Fatal("a terminal was requested without one")
		}
	}
	// -t without a terminal quietly runs without one.
	tr.ok("exec", "-t", "web", "--", "echo", "plain")
	tr.golden("exec")
}

func TestShellChoiceAndTerminal(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "start", "web")
	last := func() api.ExecRequest {
		var r api.ExecRequest
		if err := json.Unmarshal(h.lastBody("POST", "/api/v1/jails/web/exec"), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	tr := h.transcript()
	// The jail's shell key, set through the short alias.
	tr.ok("set", "web", "shell", "/usr/local/bin/bash")
	if out := tr.ok("config", "get", "web", "shell"); strings.TrimSpace(out) != "/usr/local/bin/bash" {
		t.Fatalf("shell key: %q", out)
	}
	out, _, code := tr.do("echo from the shell\n", "shell", "web")
	if code != 0 || out != "echo from the shell\n" {
		t.Fatalf("shell: %d %q", code, out)
	}
	// Nothing is chosen on the client: the server applies flag, key, /bin/sh.
	if r := last(); !r.Shell || r.ShellPath != "" || r.TTY {
		t.Fatalf("default shell request: %+v", r)
	}
	tr.do("", "shell", "web", "--shell", "/bin/tcsh")
	if r := last(); !r.Shell || r.ShellPath != "/bin/tcsh" {
		t.Fatalf("--shell request: %+v", r)
	}
	_, errs, code := tr.do("", "shell", "web", "--shell", "bash")
	if code != 2 || !strings.Contains(errs, "absolute path") {
		t.Fatalf("relative shell: %d %s", code, errs)
	}
	tr.ok("config", "unset", "web", "shell")

	// The shell that does not exist is the server's clear error, passed on
	// as it came; the client does not try another one.
	h.srv.FailRequests("POST", "/api/v1/jails/web/exec", api.Errorf(api.CodeNotFound, "shell /usr/local/bin/zsh does not exist in jail web").
		WithHint("install it, or pick another with --shell"), 1)
	before := len(h.srv.Requests())
	_, errs, code = tr.do("", "shell", "web", "--shell", "/usr/local/bin/zsh")
	if code != 4 || !strings.HasPrefix(errs, "not_found: shell /usr/local/bin/zsh does not exist") || !strings.Contains(errs, "hint: install it") {
		t.Fatalf("missing shell: %d %s", code, errs)
	}
	execs := 0
	for _, r := range h.srv.Requests()[before:] {
		if strings.HasSuffix(r.Path, "/exec") {
			execs++
		}
	}
	if execs != 1 {
		t.Fatalf("the client retried or fell back: %d exec requests", execs)
	}

	// With a terminal: raw mode for the session, restored afterwards, the
	// size sent, resizes forwarded.
	var raw, restored int
	h.rawTerm = func(any) (func(), error) { raw++; return func() { restored++ }, nil }
	h.resize = make(chan struct{}, 1)
	h.tty = true
	h.resize <- struct{}{}
	_, errs, code = tr.do("exit\n", "shell", "web")
	if code != 0 {
		t.Fatalf("tty shell: %d %s", code, errs)
	}
	if r := last(); !r.TTY || r.Rows != 24 || r.Cols != 80 {
		t.Fatalf("tty request: %+v", r)
	}
	if raw != 1 || restored != 1 {
		t.Fatalf("raw mode entered %d, restored %d", raw, restored)
	}
	// exec gets a terminal on its own when both ends are terminals; -T never does.
	tr.ok("exec", "web", "--", "echo", "auto")
	if r := last(); !r.TTY || r.Rows != 24 {
		t.Fatalf("automatic terminal: %+v", r)
	}
	tr.ok("exec", "-T", "web", "--", "echo", "plain")
	if r := last(); r.TTY {
		t.Fatalf("-T requested a terminal: %+v", r)
	}
	// with a terminal the session learns which (bash falls back to a dumb terminal without TERM); a value that is
	// not a terminal name, and a session without a terminal, send none
	h.env["TERM"] = "xterm-256color"
	h.run("exit\n", "shell", "web")
	if r := last(); !slices.Contains(r.Env, "TERM=xterm-256color") {
		t.Fatalf("TERM was not forwarded: %+v", r)
	}
	h.run("", "exec", "-T", "web", "--", "echo", "plain")
	if r := last(); len(r.Env) != 0 {
		t.Fatalf("TERM went to a session without a terminal: %+v", r)
	}
	h.env["TERM"] = "x;rm -rf /"
	h.run("exit\n", "shell", "web")
	if r := last(); len(r.Env) != 0 {
		t.Fatalf("a TERM that is not a name was forwarded: %+v", r)
	}
	delete(h.env, "TERM")
	h.tty = false
	tr.golden("shell")
}

func TestExecThroughHub(t *testing.T) {
	b := fake.New(fake.WithHostName("host-b"))
	t.Cleanup(b.Close)
	seedMainProject(b)
	h := newHarness(t, fake.WithHosts(map[string]*fake.Server{"host-b": b}))
	b.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-15"}, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15", Arch: "amd64"}})
	b.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "on-b", Project: "main"}, Spec: api.JailSpec{Image: "freebsd-15"}})
	if _, errs, code := h.run("", "--host", "host-b", "start", "on-b"); code != 0 {
		t.Fatal(errs)
	}
	out, errs, code := h.run("", "--host", "host-b", "exec", "on-b", "--", "echo", "via hub")
	if code != 0 || out != "via hub\n" {
		t.Fatalf("hub exec: %d %q %s", code, out, errs)
	}
	if len(b.ExecCalls()) != 1 || len(h.srv.ExecCalls()) != 0 {
		t.Fatalf("exec went to the wrong host: %v %v", b.ExecCalls(), h.srv.ExecCalls())
	}
	_, _, code = h.run("", "--host", "host-b", "exec", "on-b", "--", "exit", "9")
	if code != 9 {
		t.Fatalf("hub exit status: %d", code)
	}
}

func TestUpdates(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedGeneration("freebsd-15") // g2: an OS update for jails on g1
	tr := h.transcript()
	tr.ok("create", "web", "--image", "freebsd-15#g1", "--network", "lan", "--storage", "default")
	tr.ok("create", "db", "--image", "freebsd-15#g1", "--network", "lan", "--storage", "default")
	tr.ok("start", "web")
	tr.ok("start", "db")
	h.srv.SeedPackageUpdates("main", "web", []api.PackageUpdate{{Name: "nginx", From: "1.24", To: "1.26"}, {Name: "curl", From: "8.0", To: "8.1"}})
	tr.ok("update", "list")
	tr.do("", "update", "check")
	tr.do("", "update", "check", "web", "--all")
	tr.ok("update", "check", "web")
	tr.ok("update", "list")
	tr.ok("update", "check", "--all", "-o", "json")
	tr.ok("--dry-run", "update", "apply", "web")
	tr.ok("--dry-run", "update", "apply", "--all")
	if m := h.mutations(); containsApply(m) {
		t.Fatalf("dry-run applied: %v", m)
	}
	tr.do("", "update", "apply")
	// Named jails ask a yes/no question; -y skips it.
	tr.do("", "update", "apply", "web")
	tr.do("n\n", "update", "apply", "web")
	tr.ok("update", "apply", "web", "-y", "--packages")
	tr.ok("update", "history", "web")
	// A batch needs the project name typed; -y answers it too.
	_, errs, code := tr.do("wrong\n", "update", "apply", "--all")
	if code != 1 || !strings.Contains(errs, "did not match") {
		t.Fatalf("batch confirm: %d %s", code, errs)
	}
	tr.ok("update", "check", "--all")
	out, _, code := tr.do("main\n", "update", "apply", "--all")
	if code != 0 || !strings.Contains(out, "db") {
		t.Fatalf("typed project: %d %s", code, out)
	}
	h.srv.SeedUpdateFailure("main", "web", true)
	h.srv.SeedPackageUpdates("main", "web", []api.PackageUpdate{{Name: "nginx", From: "1.26", To: "1.28"}})
	tr.ok("update", "check", "web")
	_, errs, code = tr.do("", "update", "apply", "web", "-y")
	if code != 1 || !strings.Contains(errs, "failed") {
		t.Fatalf("failed update must exit 1: %d %s", code, errs)
	}
	tr.ok("update", "history", "web", "-o", "name")
	tr.do("", "update", "history", "ghost")
	tr.golden("updates")
}

func containsApply(ms []string) bool {
	for _, m := range ms {
		if strings.HasSuffix(m, "/updates/apply") {
			return true
		}
	}
	return false
}

func TestProvision(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	spec := writeFile(t, h.dir, "p.yaml", "kind: Jail\nmetadata: {name: web}\nspec:\n  image: freebsd-15@stable\n  storage: default\n  network: [{network: lan}]\n  provision:\n    packages: [nginx]\n    services: {enable: [nginx], start: [nginx]}\n    commands: [[echo, done]]\n", 0o644)
	tr.ok("create", "-f", spec)
	tr.ok("jail", "show", "web")
	tr.do("", "provision", "web") // not running
	tr.ok("start", "web")
	tr.ok("provision", "web")
	tr.ok("jail", "show", "web")
	tr.do("", "provision", "web")
	tr.do("", "provision", "web", "--again")
	tr.ok("provision", "web", "--again", "-y")
	tr.ok("--dry-run", "provision", "web")
	tr.do("", "provision", "ghost")
	tr.golden("provision")
}

func TestShellSetupAndShellFlags(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--shell", "sh", "--prompt", "none")
	tr.ok("config", "get", "web", "shell")
	tr.ok("config", "get", "web", "prompt")
	tr.do("", "create", "bad", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--prompt", "$(id)")
	tr.do("", "jail", "shell-setup", "web") // not running
	tr.ok("start", "web")
	tr.ok("config", "unset", "web", "shell")
	tr.ok("config", "unset", "web", "prompt")
	tr.ok("jail", "shell-setup", "web")
	tr.ok("jail", "shell-setup", "web", "-o", "json")
	tr.ok("--dry-run", "jail", "shell-setup", "web")
	tr.ok("config", "set", "web", "prompt", `\[\e[38;5;196m\]\u@\h:\w\$\[\e[0m\] `)
	tr.do("", "config", "set", "web", "prompt", "`id`")
	tr.do("", "jail", "shell-setup", "ghost")
	tr.golden("shell_setup")
}

func TestBackupKeyRunVerify(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("backup", "key", "status")
	tr.do("", "backup", "key", "create", "--recipient", "notakey")
	out, errs, code := tr.do("", "backup", "key", "create", "--recipient", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	rec := strings.TrimSpace(out)
	if code != 0 || !strings.HasPrefix(rec, "recovery-") || strings.Count(rec, "\n") != 0 || !strings.Contains(errs, "shown only once") {
		t.Fatalf("key create: %d %q %q", code, out, errs)
	}
	// The recovery key is shown once and appears nowhere else.
	for _, c := range []string{"status"} {
		o, _, _ := h.run("", "backup", "key", c, "-o", "json")
		if strings.Contains(o, rec) {
			t.Fatal("the recovery key was shown again")
		}
	}
	tr.do("", "backup", "key", "create") // exists
	tr.ok("backup", "key", "escrow", "--recipient", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	tr.ok("backup", "key", "status")
	tr.ok("--dry-run", "backup", "key", "create")
	tr.golden("backup_key")
}

func TestBackupRunVerifyRestoreProject(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--label", "env=prod")
	tr.ok("backup", "target", "create", "usb", "--kind", "pool", "--path", "tank/backup")
	tr.ok("backup", "policy", "create", "nightly", "--selector", "env=prod", "--target", "usb", "--schedule", "0 2 * * *")
	tr.do("", "backup", "run", "nightly") // no key yet: nothing leaves the host unencrypted
	tr.ok("backup", "key", "create", "--recipient", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	tr.ok("backup", "run", "nightly")
	out := tr.ok("backup", "list", "-o", "name")
	id := strings.Fields(out)[0]
	tr.ok("backup", "verify", id)
	tr.ok("backup", "verify", id, "--depth", "extract")
	tr.ok("--dry-run", "backup", "run", "nightly")
	tr.do("", "backup", "run", "ghost")
	tr.ok("project", "create", "restored")
	tr.ok("storage", "grant", "default", "--project", "restored")
	tr.ok("backup", "restore", id, "--project", "restored", "--as", "web-r", "-y")
	var rr api.RestoreRequest
	if err := json.Unmarshal(h.lastBody("POST", "/api/v1/restores"), &rr); err != nil || rr.Project != "restored" || rr.DryRun {
		t.Fatalf("restore request: %+v %v", rr, err)
	}
	tr.ok("--project", "restored", "list", "-o", "name")
	tr.golden("backup_run")
}

func TestJailConsole(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	_, errs, code := h.run("", "jail", "console", "web")
	if code == 0 || !strings.Contains(errs, "not running") {
		t.Fatalf("stopped jail: %d %q", code, errs)
	}
	h.run("", "start", "web")
	// without a terminal the input is sent as it is, then Ctrl-D ends the shell
	out, errs, code := h.run("echo hi\n", "jail", "console", "web")
	if code != 0 || out != "echo hi\n" {
		t.Fatalf("console: %d %q %q", code, out, errs)
	}
	if got := h.srv.ConsoleCalls(); len(got) != 1 || got[0].Jail != "web" {
		t.Fatalf("calls %+v", got)
	}
	_, errs, code = h.run("", "jail", "console", "web", "--shell", "bash")
	if code == 0 || !strings.Contains(errs, "absolute path") {
		t.Fatalf("relative shell: %d %q", code, errs)
	}
}

// A signal (SIGINT, SIGTERM, SIGHUP end the command's context) ends a session that waits for input, and the terminal
// leaves raw mode before the command exits.
func TestExecEndsAndRestoresTheTerminalOnASignal(t *testing.T) {
	for _, args := range [][]string{{"exec", "web", "--", "cat"}, {"shell", "web"}} {
		h := newHarness(t)
		h.seed()
		h.run("", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
		h.run("", "start", "web")
		var raw, restored atomic.Int32
		h.rawTerm = func(any) (func(), error) { raw.Add(1); return func() { restored.Add(1) }, nil }
		h.resize = make(chan struct{})
		h.tty = true
		pr, pw := io.Pipe() // input that never comes
		defer pw.Close()
		h.stdin = pr
		ctx, cancel := context.WithCancel(context.Background())
		h.ctx = ctx
		go func() {
			for raw.Load() == 0 {
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
		}()
		done := make(chan int, 1)
		go func() { _, _, code := h.run("", args...); done <- code }()
		select {
		case code := <-done:
			if code == 0 || restored.Load() != 1 {
				t.Errorf("%v: exit %d, terminal restored %d times", args, code, restored.Load())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%v: the session ignored the signal", args)
		}
	}
}
