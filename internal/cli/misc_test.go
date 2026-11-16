package cli_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/cli"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

func TestErrorFormatAndExitCodes(t *testing.T) {
	want := map[api.Code]int{
		api.CodeInvalid: 2, api.CodeNotFound: 4, api.CodeAlreadyExists: 5, api.CodeConflict: 5, api.CodeUnauthorized: 3,
		api.CodeForbidden: 3, api.CodeUnsupported: 6, api.CodeBusy: 5, api.CodeInternal: 7, api.CodeIPConflict: 5,
		api.CodePoolExhausted: 5, api.CodeImageInUse: 5, api.CodeDataLoss: 2, api.CodeVersionSkew: 6,
	}
	for code, exit := range want {
		t.Run(string(code), func(t *testing.T) {
			h := newHarness(t, fake.WithClock(func() time.Time { return clock }))
			// A 5xx would be retried by the SDK; the fake only fails the first call anyway.
			h.srv.FailRequests("GET", "/api/v1/jails", api.Errorf(code, "boom %s", code).WithHint("do the thing"), -1)
			out, errs, got := h.run("", "jail", "list")
			if got != exit || out != "" {
				t.Fatalf("exit %d (want %d), stdout %q", got, exit, out)
			}
			lines := strings.Split(strings.TrimRight(errs, "\n"), "\n")
			if len(lines) != 2 || lines[0] != fmt.Sprintf("%s: boom %s", code, code) || lines[1] != "hint: do the thing" {
				t.Fatalf("error format: %q", errs)
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t)
	tr := h.transcript()
	for _, args := range [][]string{
		{"nonsense"}, {"jail", "bogus"}, {"jail", "list", "--nope"}, {"jail", "show"}, {"jail", "show", "a", "b"},
		{"-o", "bogus", "jail", "list"}, {"jail", "list", "-l", "novalue"}, {"jail", "create"}, {"explain", "a", "b"},
		{"completion", "powershell"}, {"completion"},
	} {
		_, errs, code := tr.do("", args...)
		if code != 2 || !strings.HasPrefix(errs, "usage: ") || !strings.Contains(errs, "\nhint: ") {
			t.Errorf("%v: exit %d, %q", args, code, errs)
		}
	}
	tr.golden("usage_errors")
}

func TestAuthentication(t *testing.T) {
	h := newHarness(t, fake.WithToken("sekret"))
	h.seed()
	out, errs, code := h.run("", "jail", "list")
	if code != 3 || !strings.HasPrefix(errs, "unauthorized:") || out != "" {
		t.Fatalf("no token: %d %q", code, errs)
	}
	h.writeConfig(fmt.Sprintf("current: t\nremotes:\n  t:\n    url: %s\n    token: sekret\nprojects:\n  t: main\n", h.ts.URL))
	if _, errs, code = h.run("", "jail", "list"); code != 0 {
		t.Fatalf("token from file: %d %s", code, errs)
	}
	h.env["JAILOPS_TOKEN"] = "wrong"
	if _, _, code = h.run("", "jail", "list"); code != 3 {
		t.Fatalf("env token must win: %d", code)
	}
	h.env["JAILOPS_TOKEN"] = "sekret"
	h.writeConfig(fmt.Sprintf("current: t\nremotes:\n  t:\n    url: %s\n    token: wrong\nprojects:\n  t: main\n", h.ts.URL))
	if _, errs, code = h.run("", "jail", "list"); code != 0 {
		t.Fatalf("env token over file: %d %s", code, errs)
	}
	for _, r := range h.srv.Requests() {
		if r.Header.Get("User-Agent") == "" {
			t.Fatal("no user agent")
		}
	}
	// Tokens never appear in remote list output.
	out, _, _ = h.run("", "remote", "list")
	if strings.Contains(out, "wrong") || strings.Contains(out, "sekret") {
		t.Fatalf("token leaked: %s", out)
	}
}

func TestUnreachableSocket(t *testing.T) {
	h := newHarness(t)
	h.writeConfig("")
	h.env["JAILOPS_PROJECT"] = "main"
	h.env["JAILOPS_SOCKET"] = filepath.Join(h.dir, "missing.sock")
	_, errs, code := h.run("", "jail", "list")
	if code != 1 || !strings.HasPrefix(errs, "unavailable: cannot reach jailopsd at "+h.env["JAILOPS_SOCKET"]) || !strings.Contains(errs, "hint: is jailopsd running? Check with 'service jailopsd status'") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestOutputFormats(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--label", "env=prod")
	tr := h.transcript()
	tr.ok("jail", "list", "-o", "yaml")
	tr.ok("jail", "list", "-o", "json")
	tr.ok("jail", "list", "-o", "name")
	h.env["JAILOPS_OUTPUT"] = "json"
	out := tr.ok("jail", "show", "web")
	var j api.Jail
	if err := json.Unmarshal([]byte(out), &j); err != nil || j.Metadata.Name != "web" {
		t.Fatalf("JAILOPS_OUTPUT: %v %s", err, out)
	}
	tr.ok("jail", "show", "web", "-o", "table") // the flag wins over the environment
	h.env["JAILOPS_OUTPUT"] = ""
	tr.ok("jail", "create", "x", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "-o", "json")
	tr.ok("jail", "delete", "--confirm-data-loss", "x", "-o", "json")
	tr.ok("jail", "start", "web", "-o", "name")
	tr.golden("output_formats")
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func TestColourOnlyOnTTY(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "jail", "create", "db", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "jail", "start", "web")
	plain, _, _ := h.run("", "jail", "list")
	if ansiRe.MatchString(plain) {
		t.Fatalf("colour without a terminal: %q", plain)
	}
	h.tty = true
	coloured, _, _ := h.run("", "jail", "list")
	if !strings.Contains(coloured, "\x1b[32mrunning\x1b[0m") || !strings.Contains(coloured, "\x1b[90mstopped\x1b[0m") {
		t.Fatalf("no state colour on a terminal: %q", coloured)
	}
	// A terminal gets the boxed table; the colour must not move anything.
	boxed := ansiRe.ReplaceAllString(coloured, "")
	if boxed == plain || !strings.Contains(boxed, "┌") {
		t.Fatalf("no boxed table on a terminal:\n%s", boxed)
	}
	h.env["NO_COLOR"] = "1"
	if out, _, _ := h.run("", "jail", "list"); out != boxed {
		t.Fatalf("NO_COLOR ignored, or colour breaks alignment:\n%q\n%q", out, boxed)
	}
	delete(h.env, "NO_COLOR")
	h.env["TERM"] = "dumb"
	if out, _, _ := h.run("", "jail", "list"); out != boxed {
		t.Fatalf("TERM=dumb ignored: %q", out)
	}
	// --no-headers keeps the script form even on a terminal.
	if out, _, _ := h.run("", "jail", "list", "--no-headers"); ansiRe.MatchString(out) || strings.Contains(out, "│") {
		t.Fatalf("--no-headers on a terminal: %q", out)
	}
	// Machine formats never carry colour.
	h.env["TERM"] = "xterm"
	if out, _, _ := h.run("", "jail", "list", "-o", "json"); ansiRe.MatchString(out) {
		t.Fatalf("colour in json: %q", out)
	}
	// Errors are red on a terminal.
	_, errs, _ := h.run("", "jail", "show", "nope")
	if !strings.HasPrefix(errs, "\x1b[31mnot_found\x1b[0m: ") {
		t.Fatalf("error colour: %q", errs)
	}
}

func TestProgressLine(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SetOperationDelay(700 * time.Millisecond)
	_, errs, code := h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	if code != 0 || strings.Contains(errs, "\r") {
		t.Fatalf("progress without a terminal: %d %q", code, errs)
	}
	h.tty = true
	_, errs, code = h.run("", "jail", "create", "web2", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	if code != 0 || !strings.Contains(errs, "\r\x1b[K") || !strings.Contains(errs, "Creating jail web2") || !strings.HasSuffix(errs, "\r\x1b[K") {
		t.Fatalf("progress line: %d %q", code, errs)
	}
	// --no-wait prints no progress even on a terminal.
	_, errs, _ = h.run("", "jail", "create", "web3", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--no-wait")
	if errs != "" {
		t.Fatalf("progress with --no-wait: %q", errs)
	}
}

func TestExplainCommand(t *testing.T) {
	h := newHarness(t)
	tr := h.transcript()
	tr.ok("explain")
	tr.ok("explain", "data_loss_unconfirmed")
	tr.ok("explain", "not_found", "-o", "json")
	tr.do("", "explain", "no_such_code")
	tr.golden("explain")
	var codes []string
	out, _, _ := h.run("", "explain", "-o", "name")
	codes = strings.Fields(out)
	if len(codes) < 20 {
		t.Fatalf("explain lists %d codes", len(codes))
	}
}

func TestCompletion(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "jail", "create", "db", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	for shell, marker := range map[string]string{"bash": "__start_jailops", "zsh": "#compdef jailops", "fish": "complete -c jailops"} {
		out, errs, code := h.run("", "completion", shell)
		if code != 0 || !strings.Contains(out, marker) || errs != "" {
			t.Errorf("%s: exit %d, marker %q missing in %d bytes (%s)", shell, code, marker, len(out), errs)
		}
	}
	// Names come from the server.
	out, _, code := h.run("", "__complete", "jail", "show", "")
	if code != 0 || !strings.Contains(out, "web\n") || !strings.Contains(out, "db\n") {
		t.Fatalf("dynamic completion: %d %q", code, out)
	}
	out, _, _ = h.run("", "__complete", "network", "leases", "")
	if !strings.Contains(out, "lan\n") {
		t.Fatalf("network completion: %q", out)
	}
	out, _, _ = h.run("", "__complete", "-o", "")
	if !strings.Contains(out, "json") || !strings.Contains(out, "yaml") {
		t.Fatalf("output completion: %q", out)
	}
	out, _, _ = h.run("", "__complete", "remote", "switch", "")
	if !strings.Contains(out, "local") || !strings.Contains(out, "t\n") {
		t.Fatalf("remote completion: %q", out)
	}
}

func TestEveryCommandIsDocumented(t *testing.T) {
	h := newHarness(t)
	var out, errb strings.Builder
	env := h.environ("", nil, nil)
	_ = out
	_ = errb
	root := cli.NewRootCommand(env)
	n := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		n++
		if c.Name() == "help" {
			return
		}
		if c.Short == "" || len(c.Long) < 30 || c.Example == "" {
			t.Errorf("%s: help text incomplete (short %q, long %d bytes, example %d bytes)", c.CommandPath(), c.Short, len(c.Long), len(c.Example))
		}
		if strings.Contains(c.Example, "@P@") {
			t.Errorf("%s: unexpanded placeholder in example", c.CommandPath())
		}
		if !strings.Contains(c.Example, "jailops") && c.Parent() != nil {
			t.Errorf("%s: example does not show a command line", c.CommandPath())
		}
		if strings.HasPrefix(c.Short, "A ") || strings.HasSuffix(c.Short, ".") {
			t.Errorf("%s: short text style: %q", c.CommandPath(), c.Short)
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	if n < 100 {
		t.Fatalf("only %d commands in the tree", n)
	}
}

func TestManPageHelp(t *testing.T) {
	h := newHarness(t)
	out, _, code := h.run("", "jail", "rollback", "--help")
	if code != 0 {
		t.Fatal(code)
	}
	for _, section := range []string{"NAME\n    jailops jail rollback - ", "SYNOPSIS\n", "DESCRIPTION\n", "OPTIONS\n", "--confirm-data-loss", "GLOBAL OPTIONS\n", "--dry-run", "EXAMPLES\n"} {
		if !strings.Contains(out, section) {
			t.Errorf("help lacks %q:\n%s", section, out)
		}
	}
	out, _, _ = h.run("", "jail", "--help")
	if !strings.Contains(out, "COMMANDS\n") || !strings.Contains(out, "rollback") {
		t.Errorf("group help:\n%s", out)
	}
	out, _, code = h.run("")
	if code != 0 || !strings.Contains(out, "COMMANDS") {
		t.Errorf("bare invocation: %d %s", code, out)
	}
}

func TestServerInfoVersionDoctor(t *testing.T) {
	wrap := func(s *fake.Server) http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v1/doctor", func(w http.ResponseWriter, r *http.Request) {
			rep := api.DoctorReport{Status: api.DoctorWarn, Checks: []api.DoctorCheck{
				{Name: "zfs.pool", Status: api.DoctorOK, Message: "pool tank is online"},
				{Name: "kernel.module.if_epair", Status: api.DoctorWarn, Message: "not loaded", Hint: "kldload if_epair"},
				{Name: "pf.enabled", Status: api.DoctorUnknown, Message: "cannot tell without FreeBSD"},
			}}
			raw, _ := json.Marshal(rep)
			_ = json.NewEncoder(w).Encode(api.Response{Type: api.ResponseSync, StatusCode: 200, Metadata: raw})
		})
		mux.HandleFunc("GET /api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
			raw, _ := json.Marshal([]api.AuditEntry{{ID: "1", Timestamp: clock, Requestor: "alice", Action: "POST /api/v1/jails", Resource: "web", Result: "ok"}})
			_ = json.NewEncoder(w).Encode(api.Response{Type: api.ResponseSync, StatusCode: 200, Metadata: raw})
		})
		mux.Handle("/", s)
		return mux
	}
	h := newHarnessWith(t, wrap, fake.WithExtensions("operations", "events", "jails", "doctor", "audit_log"), fake.WithHostName("alpha"))
	tr := h.transcript()
	tr.ok("server", "info")
	tr.ok("server", "info", "-o", "json")
	tr.ok("version")
	tr.ok("version", "--client")
	tr.ok("version", "-o", "json")
	_, _, code := tr.do("", "doctor")
	if code != 0 {
		t.Fatalf("doctor with warnings only: %d", code)
	}
	tr.ok("audit")
	tr.golden("server_doctor")

	// A dead server fails the doctor and still reports the configuration.
	h.ts.Close()
	out, _, code := tr.do("", "doctor")
	if code != 1 || !strings.Contains(out, "FAIL") || !strings.Contains(out, "configuration") {
		t.Fatalf("doctor against a dead server: %d %s", code, out)
	}
	// version does not fail when the server is down.
	if out, _, code = h.run("", "version"); code != 0 || !strings.Contains(out, "Server:  -") {
		t.Fatalf("version offline: %d %s", code, out)
	}
	_ = sdk.Version
}

func TestRemoteCommands(t *testing.T) {
	srv := fake.New(fake.WithToken("tok"), fake.WithHostName("tls-host"), fake.WithClock(func() time.Time { return clock }))
	ts := httptest.NewUnstartedServer(srv)
	ts.Config.ErrorLog = log.New(io.Discard, "", 0) // the pin probe makes the server log a handshake error
	ts.StartTLS()
	t.Cleanup(func() { ts.Close(); srv.Close() })
	dir := t.TempDir()
	h := &harness{t: t, srv: srv, ts: ts, dir: dir, env: map[string]string{}, cfgFile: filepath.Join(dir, "user.yaml")}
	h.env["JAILOPS_CONFIG"] = h.cfgFile
	h.env["JAILOPS_PROJECT"] = "main"
	seedMainProject(srv)
	fp := sdk.Fingerprint(ts.Certificate())
	colon := regexp.MustCompile(`..`).ReplaceAllStringFunc(fp, func(s string) string { return s + ":" })
	colon = strings.TrimSuffix(colon, ":")
	tr := h.transcript()
	url := ts.URL

	// The fingerprint is shown and must be confirmed; -y is not an answer.
	_, errs, code := tr.do("tok\n", "remote", "add", "lab", url, "--token-file", "-", "-y")
	if code != 2 || !strings.Contains(errs, colon) || !strings.Contains(errs, "Pin this certificate") {
		t.Fatalf("-y must not answer the pin question: %d %s", code, errs)
	}
	if _, code := statFile(h.cfgFile); code == nil {
		t.Fatal("config written without confirmation")
	}
	_, errs, code = tr.do("tok\nn\n", "remote", "add", "lab", url, "--token-file", "-")
	if code != 1 || !strings.Contains(errs, "not trusted") {
		t.Fatalf("refused pin: %d %s", code, errs)
	}
	out, errs, code := tr.do("tok\ny\n", "remote", "add", "lab", url, "--token-file", "-")
	if code != 0 || !strings.Contains(out, "remote/lab added") || !strings.Contains(out, "connected to tls-host") || !strings.Contains(errs, colon) {
		t.Fatalf("add: %d %s %s", code, out, errs)
	}
	raw, _ := osReadFile(h.cfgFile)
	if !strings.Contains(string(raw), "fingerprint: "+fp) || !strings.Contains(string(raw), "current: lab") {
		t.Fatalf("config: %s", raw)
	}
	if st, _ := statFile(h.cfgFile); st&0o077 != 0 {
		t.Fatalf("config mode %o", st)
	}
	// The pinned remote works; without the pin the self-signed certificate is refused.
	if _, errs, code = h.run("", "jail", "list"); code != 0 {
		t.Fatalf("pinned use: %d %s", code, errs)
	}
	tr.ok("remote", "list")
	h.writeConfig(fmt.Sprintf("current: bare\nremotes:\n  bare:\n    url: %s\n    token: tok\nprojects:\n  bare: main\n", url))
	if _, _, code = h.run("", "jail", "list"); code != 1 {
		t.Fatalf("unpinned self-signed certificate accepted: %d", code)
	}
	h.writeConfig("")
	// A known fingerprint is verified against the server without a prompt.
	_, errs, code = tr.do("", "remote", "add", "wrong", url, "--token", "tok", "--fingerprint", strings.Repeat("ab", 32))
	if code != 1 || !strings.Contains(errs, "does not match") {
		t.Fatalf("wrong fingerprint: %d %s", code, errs)
	}
	out, _, code = tr.do("", "remote", "add", "known", url, "--token", "tok", "--fingerprint", colon)
	if code != 0 || !strings.Contains(out, "remote/known added") {
		t.Fatalf("known fingerprint: %d %s", code, out)
	}
	tr.ok("remote", "add", "sock", "unix:/run/other.sock", "--switch")
	tr.ok("remote", "list")
	tr.ok("remote", "switch", "known")
	tr.ok("jail", "list")
	tr.do("", "remote", "switch", "nowhere")
	tr.do("", "remote", "add", "local", url)
	tr.ok("remote", "remove", "sock")
	tr.do("", "remote", "remove", "sock")
	tr.ok("remote", "switch", "local")
	tr.ok("remote", "list", "-o", "name")
	tr.golden("remote")
}

func TestEventStreamEndsOnInterrupt(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	for _, args := range [][]string{{"events"}, {"jail", "logs", "web", "--events"}} {
		for h.srv.EventStreams() != 0 { // the previous stream is still closing
			time.Sleep(5 * time.Millisecond)
		}
		var out, errb strings.Builder
		ctx, cancel := context.WithCancel(context.Background())
		env := h.environ("", nil, nil)
		env.Stdout, env.Stderr = &out, &errb
		done := make(chan int, 1)
		go func() { done <- cli.Execute(ctx, env, args) }()
		deadline := time.Now().Add(10 * time.Second)
		for h.srv.EventStreams() == 0 {
			if time.Now().After(deadline) {
				t.Fatal("no event stream opened")
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		if code := <-done; code != 0 || errb.String() != "" {
			t.Fatalf("%v: exit %d, stderr %q", args, code, errb.String())
		}
	}
}
