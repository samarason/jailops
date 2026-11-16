package server_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/logfwd"
	"jailops.net/jailops/sdk/api"
)

const logRoot = "/jailops/projects/alpha/jails/"

// The unified view merges the files of the project's jails by time, keeps
// each file's order for lines without a timestamp, continues from the
// cursor, reports a jail that is not mounted and is scoped like jail logs.
func TestUnifiedLogsOverHTTP(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	mustJail(t, e, "web")
	mustJail(t, e, "db")
	mustJail(t, e, "idle")
	e.Files.Put(logRoot+"web/root/var/log/messages", []byte("Oct 29 11:00:00 web one\nOct 29 11:20:00 web three\n"))
	e.Files.Put(logRoot+"db/root/var/log/messages", []byte("Oct 29 11:10:00 db two\n  continued\nOct 29 11:30:00 db four\n"))
	_ = e.Files.RemoveAll(c, logRoot+"idle/root") // its root is not mounted
	info, err := e.Admin.Info(c)
	if err != nil || !hasStr(info.APIExtensions, "logs_unified") || !hasStr(info.APIExtensions, "log_forward") {
		t.Fatalf("extensions: %v %v", err, info.APIExtensions)
	}
	_, err = e.Client(api.PermReadonly).Logs().Read(c, api.LogsQuery{}, false)
	wantCode(t, err, api.CodeForbidden)
	op := e.Client(api.PermOperator)
	r, err := op.Logs().Read(c, api.LogsQuery{}, false)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range r.Lines {
		got = append(got, l.Jail+"/"+l.File+" "+l.Line)
	}
	want := "web/messages Oct 29 11:00:00 web one|db/messages Oct 29 11:10:00 db two|db/messages   continued|web/messages Oct 29 11:20:00 web three|db/messages Oct 29 11:30:00 db four"
	if strings.Join(got, "|") != want {
		t.Fatalf("order:\n%s\nwant\n%s", strings.Join(got, "|"), want)
	}
	if r.Lines[2].Time != nil || r.Lines[0].Time == nil || r.Lines[0].Project != "alpha" {
		t.Fatalf("%+v", r.Lines[:3])
	}
	if len(r.Sources) != 3 || r.Sources[1].Jail != "idle" || r.Sources[1].Error == nil || r.Sources[1].Error.Code != api.CodeBusy {
		t.Fatalf("sources %+v", r.Sources)
	}
	// follow: only what was appended
	e.Files.Put(logRoot+"web/root/var/log/messages", []byte("Oct 29 11:00:00 web one\nOct 29 11:20:00 web three\nOct 29 11:40:00 web five\n"))
	r2, err := op.Logs().Read(c, api.LogsQuery{Cursor: r.Next}, false)
	if err != nil || len(r2.Lines) != 1 || r2.Lines[0].Line != "Oct 29 11:40:00 web five" {
		t.Fatalf("%v %+v", err, r2.Lines)
	}
	// filters
	r3, err := op.Logs().Read(c, api.LogsQuery{Jails: []string{"db"}, Grep: "FOUR"}, false)
	if err != nil || len(r3.Lines) != 1 || len(r3.Sources) != 1 {
		t.Fatalf("%v %+v", err, r3)
	}
	// another project's operator sees none of alpha's jails, with or without all projects
	net := e.MakeNetwork("beta")
	if _, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: net}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	beta := e.Scoped(api.PermOperator, "beta")
	if r, err := beta.Logs().Read(c, api.LogsQuery{}, true); err != nil || len(r.Sources) != 0 {
		t.Fatalf("%v %+v", err, r)
	}
	_, err = beta.Project("alpha").Logs().Read(c, api.LogsQuery{}, false)
	wantCode(t, err, api.CodeNotFound)
	if r, err := e.Global().Logs().Read(c, api.LogsQuery{}, true); err != nil || len(r.Sources) != 3 {
		t.Fatalf("global: %v %+v", err, r)
	}
	tok := e.IdentityToken(api.PermOperator, true)
	for _, q := range []string{"tail=0", "cursor=nope", "file=../x", "jail=Bad", "app_logs=maybe", "file=messages.1.gz"} {
		if code, body := e.Raw("GET", "/api/v1/logs?project=alpha&"+q, tok, ""); code != 400 {
			t.Errorf("%s: %d %s", q, code, body)
		}
	}
}

// listener collects the octet-counted frames a syslog sink sends over tcp.
type listener struct {
	ln     net.Listener
	frames chan string
}

func newListener(t *testing.T) *listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{ln: ln, frames: make(chan string, 1000)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					ls, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(ls))
					if err != nil {
						return
					}
					b := make([]byte, n)
					if _, err := io.ReadFull(r, b); err != nil {
						return
					}
					l.frames <- string(b)
				}
			}()
		}
	}()
	return l
}

// await returns the first frame containing every one of want.
func (l *listener) await(t *testing.T, want ...string) string {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case f := <-l.frames:
			ok := true
			for _, w := range want {
				ok = ok && strings.Contains(f, w)
			}
			if ok {
				return f
			}
		case <-deadline:
			t.Fatalf("no frame with %q", want)
		}
	}
}

// Forwarding: the file's sink list is in force until an admin stores one;
// lines of a jail that appears reach the sink with the jail in the
// structured data; only a global admin reads or changes the list; files
// the daemon would read are checked first.
func TestLogForwardOverHTTP(t *testing.T) {
	a, b := newListener(t), newListener(t)
	e := dtest.New(t, dtest.Options{
		Mutate: func(c *daemon.Config) {
			c.Logging.Forward = []api.LogSink{{Name: "file", Type: api.LogSinkSyslog, To: "tcp://" + a.ln.Addr().String(), Facility: "local3"}}
		},
		LogForwardTune: func(env *logfwd.Env) {
			env.Poll, env.Refresh = 5*time.Millisecond, 5*time.Millisecond
			// the receivers of this test listen on the loopback address; TestLogForwardAPISinkLimits checks the guard
			env.TargetCheck = func(netip.AddrPort) error { return nil }
			env.CheckFile = func(p string, _ bool) error {
				if strings.HasPrefix(p, "/bad") {
					return errors.New(p + " is not owned by root")
				}
				return nil
			}
		},
	})
	e.Seed()
	c := ctxT(t)
	_, err := e.Client(api.PermOperator).Logs().Forward(c)
	wantCode(t, err, api.CodeForbidden)
	_, err = e.Scoped(api.PermAdmin, "alpha").Logs().Forward(c)
	wantCode(t, err, api.CodeForbidden)
	adm := e.Global()
	f, err := adm.Logs().Forward(c)
	if err != nil || f.Status.Origin != api.LogForwardFromConfig || len(f.Spec.Sinks) != 1 || len(f.Status.Sinks) != 1 || f.Status.Sinks[0].Warning != "" {
		t.Fatalf("%v %+v", err, f)
	}
	// a jail made after the sink started is read from its beginning
	mustJail(t, e, "web")
	e.Files.Put(logRoot+"web/root/var/log/messages", []byte("Oct 29 11:00:00 web sshd[7]: hello from web\n"))
	frame := a.await(t, "hello from web")
	if !strings.HasPrefix(frame, "<158>1 ") || !strings.Contains(frame, `[jailops project="alpha" jail="web" app="" file="messages"]`) {
		t.Fatalf("%s", frame)
	}
	// store a list: it replaces the file's
	spec := api.LogForwardSpec{Sinks: []api.LogSink{{Name: "central", Type: api.LogSinkSyslog, To: "tcp://" + b.ln.Addr().String(),
		Sources: api.LogSinkSource{Audit: true, NoJails: true}}}}
	f, err = adm.Logs().SetForward(c, spec, 0)
	if err != nil || f.Status.Origin != api.LogForwardFromAPI || f.Status.Generation != 1 || f.Spec.Sinks[0].Name != "central" {
		t.Fatalf("%v %+v", err, f)
	}
	_, err = adm.Logs().SetForward(c, spec, 0)
	wantCode(t, err, api.CodeConflict)
	res, err := adm.Logs().TestForward(c, "central")
	if err != nil || !res.OK || !strings.HasPrefix(res.Line, "jailops log forwarding test ") {
		t.Fatalf("%v %+v", err, res)
	}
	b.await(t, res.Line, `file="test"`)
	// the audit log as a source: a change made now reaches the sink
	if _, err := adm.Logs().SetForward(c, api.LogForwardSpec{Sinks: spec.Sinks}, 1); err != nil {
		t.Fatal(err)
	}
	_, _ = adm.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "gamma"}})
	b.await(t, " audit [jailops ", "POST /api/v1/projects")
	_, err = adm.Logs().TestForward(c, "nope")
	wantCode(t, err, api.CodeNotFound)
	// refused lists
	for _, bad := range []api.LogSink{
		{Name: "h", Type: api.LogSinkWebhook, To: "http://hooks.example.com/x"},
		{Name: "h", Type: api.LogSinkWebhook, To: "https://hooks.example.com/x", TokenFile: "/bad/token"},
		{Name: "h", Type: api.LogSinkSyslog, To: "tls://logs.example.com", CAFile: "/bad/ca.pem"},
		{Name: "h", Type: api.LogSinkSyslog, To: "tcp://logs.example.com", Facility: "kern"},
	} {
		_, err := adm.Logs().SetForward(c, api.LogForwardSpec{Sinks: []api.LogSink{bad}}, -1)
		wantCode(t, err, api.CodeInvalid)
	}
	// a plain sink to a remote address carries a warning
	f, err = adm.Logs().SetForward(c, api.LogForwardSpec{Sinks: []api.LogSink{{Name: "plain", Type: api.LogSinkSyslog, To: "udp://192.0.2.10"}}}, -1)
	if err != nil || len(f.Status.Sinks) != 1 || !strings.Contains(f.Status.Sinks[0].Warning, "in the clear") {
		t.Fatalf("%v %+v", err, f)
	}
	rep, err := adm.Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ch := range rep.Checks {
		found = found || ch.Name == "logs.forward"
	}
	if !found {
		t.Fatalf("doctor has no logs.forward: %+v", rep.Checks)
	}
	f, err = adm.Logs().ResetForward(c)
	if err != nil || f.Status.Origin != api.LogForwardFromConfig || f.Spec.Sinks[0].Name != "file" {
		t.Fatalf("%v %+v", err, f)
	}
	entries, err := adm.Audit(c, 100)
	if err != nil {
		t.Fatal(err)
	}
	var acts []string
	for _, en := range entries {
		if strings.Contains(en.Action, "/api/v1/logs/forward") {
			acts = append(acts, en.Action)
		}
	}
	if !hasStr(acts, "PUT /api/v1/logs/forward") || !hasStr(acts, "DELETE /api/v1/logs/forward") || !hasStr(acts, "POST /api/v1/logs/forward/test") {
		t.Fatalf("audit %v", acts)
	}
}

// stepClock is a clock the test moves; After fires on the next move.
type stepClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []chan time.Time
}

func (c *stepClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *stepClock) After(time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waiters = append(c.waiters, ch)
	return ch
}
func (c *stepClock) move(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, w := range c.waiters {
		w <- c.now
	}
	c.waiters = nil
}

// doctor warns about a sink that has failed for more than five minutes, and names no receiver or error.
func TestLogForwardDoctor(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	clk := &stepClock{now: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)}
	e := dtest.New(t, dtest.Options{
		Now: clk.Now,
		Mutate: func(c *daemon.Config) {
			c.Logging.Forward = []api.LogSink{{Name: "down", Type: api.LogSinkSyslog, To: "tcp://" + dead, Sources: api.LogSinkSource{NoJails: true, Audit: true}}}
		},
		LogForwardTune: func(env *logfwd.Env) { env.Clock = clk },
	})
	e.Seed()
	c := ctxT(t)
	failing := func() *time.Time {
		f, err := e.Global().Logs().Forward(c)
		if err != nil || len(f.Status.Sinks) != 1 {
			t.Fatalf("%v %+v", err, f)
		}
		return f.Status.Sinks[0].FailingSince
	}
	// the audit entries of the seed are queued at the next round and the send fails
	deadline := time.Now().Add(20 * time.Second)
	for failing() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the sink never failed")
		}
		_, _ = e.Global().Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "p" + strconv.Itoa(int(time.Now().UnixNano()%100000))}})
		clk.move(2 * time.Second)
	}
	check := func() api.DoctorCheck {
		rep, err := e.Global().Doctor(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range rep.Checks {
			if ch.Name == "logs.forward" {
				return ch
			}
		}
		t.Fatalf("no logs.forward in %+v", rep.Checks)
		return api.DoctorCheck{}
	}
	if ch := check(); ch.Status != api.DoctorOK {
		t.Fatalf("a fresh failure is not a warning yet: %+v", ch)
	}
	clk.move(6 * time.Minute)
	ch := check()
	if ch.Status != api.DoctorWarn || !strings.Contains(ch.Message, "down (since ") || strings.Contains(ch.Message, dead) {
		t.Fatalf("%+v", ch)
	}
}

// A sink set through the API may not send to this host's loopback or link-local addresses (a name is checked on
// the address it resolves to, when it is dialled) and reads its files only from logging.secrets_dir; a sink of
// jailopsd.yaml still delivers to the loopback address. The forward test answers a short class, not what the
// receiver said.
func TestLogForwardAPISinkLimits(t *testing.T) {
	a := newListener(t)
	secrets := t.TempDir()
	tok := filepath.Join(secrets, "hook.token")
	if err := os.WriteFile(tok, []byte("t0k3n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := dtest.New(t, dtest.Options{
		Mutate: func(c *daemon.Config) {
			c.Logging.Forward = []api.LogSink{{Name: "file", Type: api.LogSinkSyslog, To: "tcp://" + a.ln.Addr().String(), Sources: api.LogSinkSource{NoJails: true, Audit: true}}}
			c.Logging.SecretsDir = secrets
		},
		LogForwardTune: func(env *logfwd.Env) {
			env.Poll, env.Refresh = 5*time.Millisecond, 5*time.Millisecond
			env.CheckFile = func(string, bool) error { return nil } // the test's files are not root's
			env.CheckDir = func(string) error { return nil }
		},
	})
	e.Seed()
	c := ctxT(t)
	adm := e.Global()
	// the file's sink delivers to the loopback address
	res, err := adm.Logs().TestForward(c, "file")
	if err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	a.await(t, res.Line)
	_, port, _ := net.SplitHostPort(a.ln.Addr().String())
	for _, bad := range []api.LogSink{
		{Name: "lo", Type: api.LogSinkSyslog, To: "tcp://127.0.0.1:" + port},
		{Name: "lo", Type: api.LogSinkSyslog, To: "udp://[::1]:514"},
		{Name: "lo", Type: api.LogSinkSyslog, To: "tcp://localhost:" + port},
		{Name: "md", Type: api.LogSinkWebhook, To: "https://169.254.169.254/latest"},
		{Name: "w", Type: api.LogSinkWebhook, To: "https://hooks.example.com/in", TokenFile: "/usr/local/etc/jailops/priv.conf"},
		{Name: "w", Type: api.LogSinkWebhook, To: "https://hooks.example.com/in", TokenFile: filepath.Join(secrets, "sub", "t")},
		{Name: "w", Type: api.LogSinkWebhook, To: "https://hooks.example.com/in", CAFile: "/etc/ssl/cert.pem"},
	} {
		_, err := adm.Logs().SetForward(c, api.LogForwardSpec{Sinks: []api.LogSink{bad}}, 0)
		wantCode(t, err, api.CodeInvalid)
	}
	ok := api.LogSink{Name: "w", Type: api.LogSinkWebhook, To: "https://hooks.example.com/in", TokenFile: tok}
	if _, err := adm.Logs().SetForward(c, api.LogForwardSpec{Sinks: []api.LogSink{ok}}, 0); err != nil {
		t.Fatal(err)
	}
	// the stored list is the API's: its sink reads the token from the secrets directory at each send
	f, err := adm.Logs().Forward(c)
	if err != nil || f.Status.Origin != api.LogForwardFromAPI || f.Spec.Sinks[0].TokenFile != tok {
		t.Fatalf("%v %+v", err, f)
	}
}
