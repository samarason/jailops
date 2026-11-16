//go:build linux

package priv

import (
	"bytes"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"jailops.net/jailops/sdk/api"
)

// hosts runs a test against the in-process helper and against a client over
// the socket: both implement Host.
func execHosts(t *testing.T, f func(t *testing.T, h Host, e *env)) {
	t.Run("local", func(t *testing.T) {
		e := newEnv(t)
		e.conf(t, "alpha_web")
		f(t, e.local, e)
	})
	t.Run("socket", func(t *testing.T) {
		fx := newFixture(t)
		fx.conf(t, "alpha_web")
		f(t, fx.client, fx.env)
	})
}

func readAll(t *testing.T, r io.Reader) <-chan string {
	ch := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); ch <- string(b) }()
	return ch
}

// liveOut collects a session's output as it arrives, so a test can wait for a
// sign of progress instead of sleeping.
type liveOut struct {
	mu   sync.Mutex
	b    []byte
	done chan struct{}
}

func tail(r io.Reader) *liveOut {
	o := &liveOut{done: make(chan struct{})}
	go func() {
		defer close(o.done)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			o.mu.Lock()
			o.b = append(o.b, buf[:n]...)
			o.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return o
}

func (o *liveOut) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.b)
}

// waitFor polls until the output contains sub, within a deadline.
func (o *liveOut) waitFor(t *testing.T, sub string) {
	t.Helper()
	waitFor(t, func() bool { return strings.Contains(o.String(), sub) }, "session output "+strconv.Quote(sub)+", have "+strconv.Quote(o.String()))
}

// all waits for the end of the output and returns it.
func (o *liveOut) all(t *testing.T) string {
	t.Helper()
	select {
	case <-o.done:
		return o.String()
	case <-time.After(10 * time.Second):
		t.Fatal("timeout reading session output")
		return ""
	}
}

func get(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("timeout reading session output")
		return ""
	}
}

func waitExit(t *testing.T, s ExecSession) int {
	t.Helper()
	type r struct {
		c   int
		err error
	}
	ch := make(chan r, 1)
	go func() { c, err := s.Wait(); ch <- r{c, err} }()
	select {
	case x := <-ch:
		if x.err != nil {
			t.Fatalf("wait: %v", x.err)
		}
		return x.c
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the session")
		return -1
	}
}

func gone(pid int) bool {
	for i := 0; i < 600; i++ {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return true
		}
		// a zombie still answers kill(0); it must be reaped soon
		if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil && bytes.Contains(b, []byte(") Z ")) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestExecPipesAndExitCodes(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		ctx := context.Background()
		s, err := h.Exec(ctx, "alpha_web", []string{"sh", "-c", "echo out; echo err >&2; exit 3"}, ExecOpts{})
		if err != nil {
			t.Fatal(err)
		}
		out, errs := readAll(t, s.Stdout()), readAll(t, s.Stderr())
		if got := get(t, out); got != "out\n" {
			t.Errorf("stdout %q", got)
		}
		if got := get(t, errs); got != "err\n" {
			t.Errorf("stderr %q", got)
		}
		if c := waitExit(t, s); c != 3 {
			t.Errorf("exit %d", c)
		}
		for want, argv := range map[int][]string{0: {"true"}, 1: {"false"}, 7: {"sh", "-c", "exit 7"}, 127: {"no-such-command-here"}} {
			s, err := h.Exec(ctx, "alpha_web", argv, ExecOpts{})
			if err != nil {
				t.Fatal(err)
			}
			go io.Copy(io.Discard, s.Stdout())
			go io.Copy(io.Discard, s.Stderr())
			if c := waitExit(t, s); c != want {
				t.Errorf("%v: exit %d want %d", argv, c, want)
			}
		}
		// stdin, end of file, and a lot of data in both directions
		s, err = h.Exec(ctx, "alpha_web", []string{"cat"}, ExecOpts{})
		if err != nil {
			t.Fatal(err)
		}
		out = readAll(t, s.Stdout())
		go io.Copy(io.Discard, s.Stderr())
		payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
		go func() { s.Stdin().Write(payload); s.Stdin().Close() }()
		if got := get(t, out); got != string(payload) {
			t.Errorf("cat returned %d bytes, want %d", len(got), len(payload))
		}
		if c := waitExit(t, s); c != 0 {
			t.Errorf("cat exit %d", c)
		}
	})
}

func TestExecArgumentsReachJexecUnchanged(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		s, err := h.Exec(context.Background(), "alpha_web", []string{"sh", "-c", "echo $FOO:$BAR"}, ExecOpts{User: "www", Env: []string{"FOO=a b", "BAR=$(id);x"}})
		if err != nil {
			t.Fatal(err)
		}
		out := readAll(t, s.Stdout())
		go io.Copy(io.Discard, s.Stderr())
		if got := get(t, out); got != "a b:$(id);x\n" {
			t.Errorf("env %q", got)
		}
		waitExit(t, s)
		b, _ := os.ReadFile(e.jexec + ".args")
		if got := strings.Split(strings.TrimSpace(string(b)), "\n"); len(got) < 8 || got[0] != "-U" || got[1] != "www" || got[2] != "alpha_web" || got[3] != "/usr/bin/env" || got[4] != "FOO=a b" {
			t.Errorf("jexec arguments %q", got)
		}
	})
}

func TestExecTTY(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		ctx := context.Background()
		s, err := h.Exec(ctx, "alpha_web", []string{"cat"}, ExecOpts{TTY: true, Rows: 30, Cols: 100})
		if err != nil {
			t.Fatal(err)
		}
		if s.Stderr() != nil {
			t.Error("Stderr must be nil in TTY mode")
		}
		out := tail(s.Stdout())
		if _, err := s.Stdin().Write([]byte("hi\n")); err != nil {
			t.Fatal(err)
		}
		// the line discipline echoes the input and cat repeats it
		out.waitFor(t, "hi\r\nhi\r\n")
		s.Stdin().Close() // ^D
		if c := waitExit(t, s); c != 0 {
			t.Errorf("exit %d", c)
		}
		if got := out.all(t); !strings.Contains(got, "hi\r\nhi\r\n") {
			t.Errorf("tty output %q", got)
		}
	})
}

func TestExecTTYWindowSizeAndResize(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		s, err := h.Exec(context.Background(), "alpha_web", []string{"sh", "-c", "stty size; until [ \"$(stty size)\" != \"30 100\" ]; do sleep 0.02; done; stty size"}, ExecOpts{TTY: true, Rows: 30, Cols: 100})
		if err != nil {
			t.Fatal(err)
		}
		out := tail(s.Stdout())
		out.waitFor(t, "30 100")
		if err := s.Resize(0, 10); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("zero rows: %v", err)
		}
		if err := s.Resize(40, 120); err != nil {
			t.Fatal(err)
		}
		// the script polls for the new size and prints it
		waitExit(t, s)
		got := out.all(t)
		i1, i2 := strings.Index(got, "30 100"), strings.Index(got, "40 120")
		if i1 < 0 || i2 < i1 {
			t.Errorf("window sizes %q", got)
		}
		if err := s.Resize(10, 10); err == nil {
			t.Error("resize after the end succeeded")
		}
		// default size, and no terminal without TTY
		s2, _ := h.Exec(context.Background(), "alpha_web", []string{"stty", "size"}, ExecOpts{TTY: true})
		o2 := readAll(t, s2.Stdout())
		waitExit(t, s2)
		if got := get(t, o2); !strings.Contains(got, "24 80") {
			t.Errorf("default size %q", got)
		}
		s3, _ := h.Exec(context.Background(), "alpha_web", []string{"true"}, ExecOpts{})
		go io.Copy(io.Discard, s3.Stdout())
		go io.Copy(io.Discard, s3.Stderr())
		if err := s3.Resize(10, 10); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("resize without a terminal: %v", err)
		}
		waitExit(t, s3)
	})
}

func TestExecTTYSessionCommandIsTheForegroundGroupWithControllingTerminal(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		// the command leads a process group of its own (pgid == pid) that is the foreground group of the terminal
		// (tpgid == pgid), below the session leader of the helper (sid != pid), and its fd 0 is a terminal that is also its
		// controlling terminal (/dev/tty opens)
		script := `[ "$(cut -d' ' -f5 /proc/$$/stat)" = "$$" ] && echo leader; [ "$(cut -d' ' -f8 /proc/$$/stat)" = "$$" ] && echo foreground; [ "$(cut -d' ' -f6 /proc/$$/stat)" != "$$" ] && echo below; [ -t 0 ] && echo tty0; : > /dev/tty && echo ctty`
		s, err := h.Exec(context.Background(), "alpha_web", []string{"sh", "-c", script}, ExecOpts{TTY: true})
		if err != nil {
			t.Fatal(err)
		}
		out := readAll(t, s.Stdout())
		waitExit(t, s)
		got := get(t, out)
		for _, want := range []string{"leader", "foreground", "below", "tty0", "ctty"} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in %q", want, got)
			}
		}
	})
}

func TestExecSignals(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		ctx := context.Background()
		for sig, want := range map[int]int{int(unix.SIGTERM): 143, int(unix.SIGKILL): 137, int(unix.SIGINT): 130, int(unix.SIGHUP): 129, int(unix.SIGQUIT): 131} {
			s, err := h.Exec(ctx, "alpha_web", []string{"sh", "-c", "echo ready; exec sleep 30"}, ExecOpts{})
			if err != nil {
				t.Fatal(err)
			}
			out := tail(s.Stdout())
			go io.Copy(io.Discard, s.Stderr())
			out.waitFor(t, "ready")
			if err := s.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if c := waitExit(t, s); c != want {
				t.Errorf("signal %d: exit %d want %d", sig, c, want)
			}
			if err := s.Signal(sig); err == nil {
				t.Error("signal after the end succeeded")
			}
		}
		// a TTY session: INT reaches the foreground command
		s, _ := h.Exec(ctx, "alpha_web", []string{"sh", "-c", "echo ready; exec sleep 30"}, ExecOpts{TTY: true})
		out := tail(s.Stdout())
		out.waitFor(t, "ready")
		s.Signal(int(unix.SIGINT))
		if c := waitExit(t, s); c != 130 {
			t.Errorf("tty INT: %d", c)
		}
		// the allow-list
		s, _ = h.Exec(ctx, "alpha_web", []string{"sleep", "30"}, ExecOpts{})
		go io.Copy(io.Discard, s.Stdout())
		go io.Copy(io.Discard, s.Stderr())
		for _, bad := range []int{0, -1, 10, 12, 17, 18, 19, 20, 64, 1 << 20, int(unix.SIGSTOP), int(unix.SIGUSR1), int(unix.SIGCONT)} {
			if err := s.Signal(bad); !api.IsCode(err, api.CodeForbidden) {
				t.Errorf("signal %d: %v", bad, err)
			}
		}
		// WINCH is allowed and harmless
		if err := s.Signal(int(unix.SIGWINCH)); err != nil {
			t.Error(err)
		}
		s.Signal(int(unix.SIGKILL))
		waitExit(t, s)
	})
}

func TestExecRefusals(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		ctx := context.Background()
		long := make([]string, 300)
		for i := range long {
			long[i] = "x"
		}
		cases := map[string]struct {
			jail string
			argv []string
			o    ExecOpts
			code api.Code
		}{
			"no conf file":    {"alpha_ghost", []string{"id"}, ExecOpts{}, api.CodeForbidden},
			"other project":   {"blog_web", []string{"id"}, ExecOpts{}, api.CodeForbidden},
			"empty jail":      {"", []string{"id"}, ExecOpts{}, api.CodeInvalid},
			"bad key":         {"web;id", []string{"id"}, ExecOpts{}, api.CodeInvalid},
			"path key":        {"../web", []string{"id"}, ExecOpts{}, api.CodeInvalid},
			"option key":      {"-x", []string{"id"}, ExecOpts{}, api.CodeInvalid},
			"no argv":         {"alpha_web", nil, ExecOpts{}, api.CodeInvalid},
			"empty command":   {"alpha_web", []string{""}, ExecOpts{}, api.CodeInvalid},
			"option command":  {"alpha_web", []string{"-l"}, ExecOpts{}, api.CodeInvalid},
			"assignment":      {"alpha_web", []string{"A=b"}, ExecOpts{}, api.CodeInvalid},
			"NUL":             {"alpha_web", []string{"a\x00b"}, ExecOpts{}, api.CodeInvalid},
			"too many":        {"alpha_web", long, ExecOpts{}, api.CodeInvalid},
			"bad user":        {"alpha_web", []string{"id"}, ExecOpts{User: "-u"}, api.CodeInvalid},
			"user with space": {"alpha_web", []string{"id"}, ExecOpts{User: "a b"}, api.CodeInvalid},
			"env no equals":   {"alpha_web", []string{"id"}, ExecOpts{Env: []string{"FOO"}}, api.CodeInvalid},
			"env bad name":    {"alpha_web", []string{"id"}, ExecOpts{Env: []string{"1A=b"}}, api.CodeInvalid},
			"env option":      {"alpha_web", []string{"id"}, ExecOpts{Env: []string{"-i=b"}}, api.CodeInvalid},
			"env NUL":         {"alpha_web", []string{"id"}, ExecOpts{Env: []string{"A=b\x00"}}, api.CodeInvalid},
			"env too big":     {"alpha_web", []string{"id"}, ExecOpts{Env: []string{"A=" + strings.Repeat("x", 5000)}}, api.CodeInvalid},
			"huge window":     {"alpha_web", []string{"id"}, ExecOpts{TTY: true, Rows: 60000, Cols: 10}, api.CodeInvalid},
			"half a window":   {"alpha_web", []string{"id"}, ExecOpts{TTY: true, Rows: 10}, api.CodeInvalid},
		}
		for name, c := range cases {
			s, err := h.Exec(ctx, c.jail, c.argv, c.o)
			if err == nil {
				t.Errorf("%s: accepted", name)
				continue
			}
			if !api.IsCode(err, c.code) {
				t.Errorf("%s: %v (want %s)", name, err, c.code)
			}
			if s != nil {
				t.Errorf("%s: a session came back with an error", name)
			}
		}
		// nothing leaked: the slots are free again
		if e.local.execTotal != 0 {
			t.Errorf("slots held after refusals: %d", e.local.execTotal)
		}
	})
}

func TestExecDisconnectKillsTheSession(t *testing.T) {
	fx := newFixture(t)
	fx.conf(t, "alpha_web")
	for _, tty := range []bool{false, true} {
		s, err := fx.client.Exec(context.Background(), "alpha_web", []string{"sh", "-c", "sleep 300 & echo $! $$; wait"}, ExecOpts{TTY: tty})
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, _ := s.Stdout().Read(buf)
		f := strings.Fields(string(buf[:n]))
		if len(f) != 2 {
			t.Fatalf("pids %q", buf[:n])
		}
		bg, _ := strconv.Atoi(f[0])
		sh, _ := strconv.Atoi(f[1])
		fx.client.Close() // the daemon vanishes
		if !gone(sh) || !gone(bg) {
			t.Errorf("tty=%v: the session survived the disconnect (sh %d, background %d)", tty, sh, bg)
		}
		// reconnect for the next round
		c, err := Dial(fx.sock)
		if err != nil {
			t.Fatal(err)
		}
		fx.client = c
		t.Cleanup(func() { c.Close() })
	}
	waitFor(t, func() bool { fx.local.execMu.Lock(); defer fx.local.execMu.Unlock(); return fx.local.execTotal == 0 }, "slots released")
}

func waitFor(t *testing.T, f func() bool, what string) {
	t.Helper()
	for i := 0; i < 1200; i++ {
		if f() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func TestExecContextCancelKillsTheSession(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		ctx, cancel := context.WithCancel(context.Background())
		s, err := h.Exec(ctx, "alpha_web", []string{"sh", "-c", "echo $$; exec sleep 300"}, ExecOpts{})
		if err != nil {
			t.Fatal(err)
		}
		go io.Copy(io.Discard, s.Stderr())
		buf := make([]byte, 32)
		n, _ := s.Stdout().Read(buf)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
		go io.Copy(io.Discard, s.Stdout())
		cancel()
		type r struct {
			c   int
			err error
		}
		ch := make(chan r, 1)
		go func() { c, err := s.Wait(); ch <- r{c, err} }()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatal("Wait did not return after cancel")
		}
		if !gone(pid) {
			t.Error("process survived the cancel")
		}
	})
}

func TestExecReapsAndLeavesNoBackgroundProcess(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		s, err := h.Exec(context.Background(), "alpha_web", []string{"sh", "-c", "sleep 300 & echo $!"}, ExecOpts{})
		if err != nil {
			t.Fatal(err)
		}
		go io.Copy(io.Discard, s.Stderr())
		out := readAll(t, s.Stdout())
		waitExit(t, s)
		pid, _ := strconv.Atoi(strings.TrimSpace(get(t, out)))
		if pid == 0 || !gone(pid) {
			t.Errorf("the background process %d outlived the session", pid)
		}
	})
}

func TestExecLimits(t *testing.T) {
	e := newEnv(t)
	cfg := e.cfg
	cfg.Limits.MaxExecPerJail, cfg.Limits.MaxExecTotal = 2, 3
	l, err := NewLocal(cfg, Deps{ZFS: e.zfs, Jexec: e.jexec}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	e.conf(t, "alpha_web")
	e.conf(t, "shop_db")
	e.conf(t, "shop_cache")
	ctx := context.Background()
	start := func(jail string) (ExecSession, error) {
		s, err := l.Exec(ctx, jail, []string{"sleep", "300"}, ExecOpts{})
		if err == nil {
			go io.Copy(io.Discard, s.Stdout())
			go io.Copy(io.Discard, s.Stderr())
		}
		return s, err
	}
	a, err := start("alpha_web")
	if err != nil {
		t.Fatal(err)
	}
	b, err := start("alpha_web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := start("alpha_web"); !api.IsCode(err, api.CodeBusy) {
		t.Errorf("per jail limit: %v", err)
	}
	c, err := start("shop_db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := start("shop_cache"); !api.IsCode(err, api.CodeBusy) {
		t.Errorf("total limit: %v", err)
	}
	a.Signal(int(unix.SIGKILL))
	waitExit(t, a)
	waitFor(t, func() bool {
		s, err := start("shop_cache")
		if err == nil {
			s.Signal(int(unix.SIGKILL))
			waitExit(t, s)
		}
		return err == nil
	}, "slot freed after exit")
	for _, s := range []ExecSession{b, c} {
		s.Signal(int(unix.SIGKILL))
		waitExit(t, s)
	}
}

// The audit log names the program and how many arguments it got, never the arguments: a command line may carry a secret.
func TestExecIsAuditedWithItsProgramButNotItsArguments(t *testing.T) {
	fx := newFixture(t)
	fx.conf(t, "alpha_web")
	s, err := fx.client.Exec(WithAdmin(context.Background(), "alice"), "alpha_web", []string{"sh", "-c", "exit 0"}, ExecOpts{})
	if err != nil {
		t.Fatal(err)
	}
	go io.Copy(io.Discard, s.Stdout())
	go io.Copy(io.Discard, s.Stderr())
	waitExit(t, s)
	waitFor(t, func() bool {
		return strings.Contains(fx.audit.String(), `"outcome":"ok"`) && strings.Contains(fx.audit.String(), "jail.session")
	}, "audit line")
	out := fx.audit.String()
	for _, want := range []string{`"op":"jail.session"`, `"argv":"sh (2 arguments)"`, `"jail":"alpha_web"`, `"admin":"alice"`} {
		if !strings.Contains(out, want) {
			t.Errorf("audit lacks %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "exit 0") {
		t.Errorf("the arguments are in the audit log:\n%s", out)
	}
	// a refused session is audited too
	_, _ = fx.client.Exec(context.Background(), "alpha_ghost", []string{"id"}, ExecOpts{})
	waitFor(t, func() bool { return strings.Contains(fx.audit.String(), `"jail":"alpha_ghost"`) }, "refusal audited")
}

func TestExecSessionsShareAConnection(t *testing.T) {
	fx := newFixture(t)
	fx.conf(t, "alpha_web")
	var ss []ExecSession
	for i := 0; i < 4; i++ {
		s, err := fx.client.Exec(context.Background(), "alpha_web", []string{"cat"}, ExecOpts{})
		if err != nil {
			t.Fatal(err)
		}
		go io.Copy(io.Discard, s.Stderr())
		ss = append(ss, s)
	}
	outs := make([]<-chan string, len(ss))
	for i, s := range ss {
		outs[i] = readAll(t, s.Stdout())
		s.Stdin().Write([]byte("session " + strconv.Itoa(i)))
		s.Stdin().Close()
	}
	for i := range ss {
		if got := get(t, outs[i]); got != "session "+strconv.Itoa(i) {
			t.Errorf("session %d got %q", i, got)
		}
		waitExit(t, ss[i])
	}
}

func TestSignalAllowListIsFixed(t *testing.T) {
	var names []string
	for _, n := range AllowedSignals {
		names = append(names, n)
	}
	if len(names) != 6 {
		t.Errorf("allowed signals changed: %v", names)
	}
}

// A command without a terminal runs as long as it runs: the grace period is for what is left after it ended (a command
// that took longer than it was killed at ten seconds).
func TestExecWithoutATerminalIsNotCutOffAfterTheGracePeriod(t *testing.T) {
	old := sessionGrace
	sessionGrace = 300 * time.Millisecond
	defer func() { sessionGrace = old }()
	execHosts(t, func(t *testing.T, h Host, e *env) {
		s, err := h.Exec(context.Background(), "alpha_web", []string{"sh", "-c", "sleep 1; echo done"}, ExecOpts{})
		if err != nil {
			t.Fatal(err)
		}
		go io.Copy(io.Discard, s.Stderr())
		if got := get(t, readAll(t, s.Stdout())); got != "done\n" {
			t.Errorf("stdout %q", got)
		}
		if c := waitExit(t, s); c != 0 {
			t.Errorf("exit %d: the command was killed while it ran", c)
		}
	})
}
