package cli_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/cli"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

func seedUnified(h *harness) {
	h.seed()
	for _, j := range [][]string{{"web", "tier=front"}, {"db", "jailops.app=postgresql"}, {"cache", "tier=back"}} {
		h.run("", "jail", "create", j[0], "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--label", j[1])
	}
	h.srv.SeedJailLog("main", "web", "messages", []byte("Mar  1 08:50:00 web sshd[1]: Accepted publickey\nMar  1 08:55:00 web nginx[3]: upstream timed out\n"))
	h.srv.SeedJailLog("main", "db", "messages", []byte("Mar  1 08:52:00 db postgres[9]: checkpoint starting\n  DETAIL: no time of its own\nMar  1 08:56:00 db postgres[9]: checkpoint complete\n"))
	h.srv.SeedJailUnmounted("main", "cache", true)
}

// 'logs' without a jail merges the project's jails by time; the selection
// flags narrow it; -o json prints one object per line; a single jail is
// still 'jail logs'.
func TestUnifiedLogs(t *testing.T) {
	h := newHarness(t)
	seedUnified(h)
	tr := h.transcript()
	tr.do("", "logs")
	tr.ok("logs", "--jail", "web", "--jail", "db", "--since", "7m")
	tr.ok("logs", "-l", "tier=front", "--grep", "UPSTREAM")
	tr.ok("logs", "--app", "postgresql", "--tail", "1")
	tr.ok("logs", "--jail", "db", "-o", "json")
	tr.ok("logs", "--all-projects", "--jail", "web")
	tr.ok("logs", "web", "messages", "--tail", "1")
	tr.do("", "logs", "web", "--jail", "db")
	tr.do("", "logs", "--tail", "0")
	tr.do("", "logs", "-l", "tier")
	tr.do("", "logs", "--file", "../x")
	tr.do("", "logs", "--events")
	tr.golden("logs_unified")

	// on a terminal each jail has its colour, the same in every run
	h.tty = true
	out, _, code := h.run("", "logs", "--jail", "web", "--jail", "db")
	if code != 0 || !strings.Contains(out, "\x1b[") || strings.Count(out, "\x1b[0m") != 5 {
		t.Fatalf("%d %q", code, out)
	}
	h.env["NO_COLOR"] = "1"
	if out, _, _ := h.run("", "logs"); strings.Contains(out, "\x1b[") {
		t.Fatalf("colour with NO_COLOR: %q", out)
	}
	// without a project, only --all-projects works
	h.writeConfig("current: t\nremotes:\n  t:\n    url: " + h.ts.URL + "\n")
	if _, errs, code := h.run("", "logs"); code != 2 || !strings.Contains(errs, "a project is required") {
		t.Fatalf("%d %s", code, errs)
	}
	if _, errs, code := h.run("", "logs", "--all-projects"); code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	// an old server
	old := newHarness(t, fake.WithExtensions("operations", "etag", "events", "jails", "jail_logs"))
	if _, errs, code := old.run("", "logs"); code != 6 || !strings.Contains(errs, `server does not support "logs_unified"`) {
		t.Fatalf("old server: %d %s", code, errs)
	}
}

// -f prints what is appended to any of the files, continuing from the cursor.
func TestUnifiedLogsFollow(t *testing.T) {
	h := newHarness(t)
	seedUnified(h)
	var out, errb syncBuilder
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := h.environ("", nil, nil)
	env.Stdout, env.Stderr = &out, &errb
	env.PollInterval = 5 * time.Millisecond
	done := make(chan int, 1)
	go func() {
		done <- cli.Execute(ctx, env, []string{"logs", "-f", "--jail", "web", "--jail", "db", "--tail", "1"})
	}()
	waitFor(t, func() bool { return h.srv.LogReads() >= 2 })
	h.srv.SeedJailLog("main", "db", "messages", []byte("Mar  1 08:52:00 db postgres[9]: checkpoint starting\n  DETAIL: no time of its own\nMar  1 08:56:00 db postgres[9]: checkpoint complete\nMar  1 08:59:00 db postgres[9]: new\n"))
	waitFor(t, func() bool { return strings.Contains(out.String(), "new") })
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	want := "web/messages  Mar  1 08:55:00 web nginx[3]: upstream timed out\ndb/messages   Mar  1 08:56:00 db postgres[9]: checkpoint complete\ndb/messages   Mar  1 08:59:00 db postgres[9]: new\n"
	if got := out.String(); got != want {
		t.Fatalf("output %q", got)
	}
}

// 'logs forward': list, add, edit, test, status, remove, reset, with
// --dry-run and the errors a person meets.
func TestLogForwardCLI(t *testing.T) {
	h := newHarness(t)
	h.srv.SeedLogForward([]api.LogSink{{Name: "file", Type: api.LogSinkSyslog, To: "udp://127.0.0.1"}})
	tr := h.transcript()
	tr.ok("logs", "forward", "list")
	tr.ok("logs", "forward", "add", "logs", "--url", "tls://logs.example.com:6514", "--facility", "local3", "--jail", "web", "-l", "tier=front")
	tr.ok("--dry-run", "logs", "forward", "add", "hooks", "--url", "https://hooks.example.com/jailops", "--token-file", "/usr/local/etc/jailops/hook.token", "--audit-only")
	tr.ok("logs", "forward", "add", "hooks", "--url", "https://hooks.example.com/jailops", "--token-file", "/usr/local/etc/jailops/hook.token", "--audit-only")
	tr.ok("logs", "forward", "add", "lan", "--url", "udp://192.0.2.10")
	tr.ok("logs", "forward", "list")
	tr.ok("logs", "forward", "set", "logs", "--facility", "local5", "--file", "messages", "--file", "auth.log")
	tr.ok("logs", "forward", "list", "-o", "yaml")
	h.srv.SeedLogSinkStatus(api.LogSinkStatus{Name: "logs", Sources: 2, Sent: 120, LastSuccess: ptrTime(clock.Add(-time.Minute))})
	h.srv.SeedLogSinkStatus(api.LogSinkStatus{Name: "hooks", Queued: 40, Dropped: 7, SkippedBytes: 2048, LastError: "HTTP 503: busy", FailingSince: ptrTime(clock.Add(-10 * time.Minute))})
	tr.ok("logs", "forward", "status")
	tr.ok("logs", "forward", "test", "logs")
	h.srv.SeedLogSinkTestFailure("hooks", "dial tcp: connection refused")
	tr.do("", "logs", "forward", "test", "hooks")
	tr.ok("logs", "forward", "remove", "lan", "--dry-run")
	tr.do("", "logs", "forward", "remove", "lan") // a removal asks first
	tr.do("n\n", "logs", "forward", "remove", "lan")
	tr.do("y\n", "logs", "forward", "remove", "lan")
	tr.do("", "logs", "forward", "add", "other", "--url", "gelf://h")
	tr.do("", "logs", "forward", "add", "other")
	tr.do("", "logs", "forward", "add", "logs", "--url", "udp://h")
	tr.do("", "logs", "forward", "set", "nope", "--facility", "local1")
	tr.do("", "logs", "forward", "set", "logs")
	tr.do("", "logs", "forward", "reset")
	tr.ok("logs", "forward", "reset", "-y")
	tr.ok("logs", "forward", "list")
	tr.golden("logs_forward")
	// the forwarding needs a global admin
	h2 := newHarnessWith(t, nil, fake.WithIdentity("op", fake.Identity{Name: "op", Permission: api.PermOperator, Global: true}))
	h2.env["JAILOPS_TOKEN"] = "op"
	if _, errs, code := h2.run("", "logs", "forward", "list"); code != 3 {
		t.Fatalf("%d %s", code, errs)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
