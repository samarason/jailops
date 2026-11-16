package cli_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/cli"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var clock = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

// harness runs the CLI in-process against a fake server over httptest.
type harness struct {
	t   *testing.T
	srv *fake.Server
	ts  *httptest.Server
	dir string
	env map[string]string
	tty bool
	// cols is the terminal width tables see; zero leaves it unknown
	cols    uint16
	probe   func(ctx context.Context, hp string) (*cli.CertProbe, error)
	cfgFile string
	// terminal hooks, nil for the defaults
	rawTerm func(any) (func(), error)
	resize  chan struct{}
	// secrets are what the password prompt returns, in order; nil keeps the real prompt
	secrets []string
	// ctx and stdin replace the context of a run and its standard input when set
	ctx   context.Context
	stdin io.Reader
	// timeout bounds one command; zero is 30 seconds
	timeout time.Duration
}

func newHarness(t *testing.T, opts ...fake.Option) *harness {
	t.Helper()
	return newHarnessWith(t, nil, opts...)
}

// newHarnessWith lets a test put its own handler in front of the fake, for
// routes the fake does not serve.
func newHarnessWith(t *testing.T, wrap func(*fake.Server) http.Handler, opts ...fake.Option) *harness {
	t.Helper()
	opts = append([]fake.Option{fake.WithClock(func() time.Time { return clock })}, opts...)
	srv := fake.New(opts...)
	var handler http.Handler = srv
	if wrap != nil {
		handler = wrap(srv)
	}
	ts := httptest.NewServer(handler)
	t.Cleanup(func() { ts.Close(); srv.Close() })
	dir := t.TempDir()
	h := &harness{t: t, srv: srv, ts: ts, dir: dir, env: map[string]string{}}
	h.cfgFile = filepath.Join(dir, "user.yaml")
	h.env["JAILOPS_CONFIG"] = h.cfgFile
	// There is no default project: the harness works in "main", chosen as 'project switch' would.
	seedMainProject(srv)
	h.writeConfig(fmt.Sprintf("current: t\nremotes:\n  t:\n    url: %s\nprojects:\n  t: main\n", ts.URL))
	return h
}

// seedMainProject creates the project the tests work in; every server of a test (hosts behind a hub too) needs it.
func seedMainProject(s *fake.Server) {
	s.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "main"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "lan"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}})
}

func (h *harness) writeConfig(s string) {
	h.t.Helper()
	if err := os.WriteFile(h.cfgFile, []byte(s), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) seed() {
	h.srv.SeedImage(api.Image{
		Metadata: api.ObjectMeta{Name: "freebsd-15"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.0-RELEASE", Arch: "amd64",
			Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}},
	})
	h.srv.SeedGeneration("freebsd-15")
	h.srv.SeedNetwork(api.Network{
		Metadata: api.ObjectMeta{Name: "lan"},
		Spec: api.NetworkSpec{Uplink: "em0", IPv4: &api.IPv4Net{
			Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.20", NAT: true}},
	})
}

func (h *harness) environ(stdin string, out, errb *bytes.Buffer) *cli.Env {
	e := &cli.Env{
		Stdin:  strings.NewReader(stdin),
		Stdout: out, Stderr: errb,
		Getenv:       func(k string) string { return h.env[k] },
		IsTTY:        func(any) bool { return h.tty },
		Now:          func() time.Time { return clock.Add(3 * time.Hour) },
		Version:      "1.2.3",
		HomeDir:      func() string { return h.dir },
		SystemConfig: filepath.Join(h.dir, "system.yaml"),
		ProbeCert:    h.probe,
		SDKOptions:   []sdk.Option{sdk.WithBackoff(time.Millisecond, 5*time.Millisecond)},
	}
	if h.secrets != nil {
		e.ReadSecret = func(string) (string, error) {
			if len(h.secrets) == 0 {
				return "", errors.New("no more secrets")
			}
			v := h.secrets[0]
			h.secrets = h.secrets[1:]
			return v, nil
		}
	}
	if h.rawTerm != nil {
		e.RawTerminal = h.rawTerm
		e.TermSize = func(any) (uint16, uint16, bool) { return 24, 80, true }
		e.ResizeSignal = func() (<-chan struct{}, func()) { return h.resize, func() {} }
	}
	if h.cols > 0 {
		e.TermSize = func(any) (uint16, uint16, bool) { return 24, h.cols, true }
	}
	return e
}

func (h *harness) run(stdin string, args ...string) (stdout, stderr string, code int) {
	h.t.Helper()
	var out, errb bytes.Buffer
	parent := h.ctx
	if parent == nil {
		parent = context.Background()
	}
	limit := h.timeout
	if limit == 0 {
		limit = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	env := h.environ(stdin, &out, &errb)
	if h.stdin != nil {
		env.Stdin = h.stdin
	}
	if h.probe == nil {
		env.ProbeCert = nil
	}
	code = cli.Execute(ctx, env, args)
	return out.String(), errb.String(), code
}

var (
	uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	tokRe  = regexp.MustCompile(`jot_[0-9a-f]{32}`)
	snapRe = regexp.MustCompile(`snap-[0-9a-f]{6}`)
	addrRe = regexp.MustCompile(`127\.0\.0\.1:\d+`)
	tmpRe  = regexp.MustCompile(`/[^\s"']*/(jailops-[A-Za-z0-9_.-]+\.yaml)`)
	pwRe   = regexp.MustCompile(`(?m)^[0-9a-f]{20}$`)
)

func normalize(s string) string {
	s = uuidRe.ReplaceAllString(s, "<uuid>")
	s = tokRe.ReplaceAllString(s, "<token>")
	s = snapRe.ReplaceAllString(s, "<snap>")
	s = addrRe.ReplaceAllString(s, "<addr>")
	s = regexp.MustCompile(`joc_[A-Za-z0-9_.-]+`).ReplaceAllString(s, "<trust-token>")
	s = regexp.MustCompile(`\b[0-9a-f]{64}\b`).ReplaceAllString(s, "<sha256>")
	s = regexp.MustCompile(`recovery-[0-9a-f]{32}`).ReplaceAllString(s, "<recovery-key>")
	s = regexp.MustCompile(`upd-[0-9a-f]{8}`).ReplaceAllString(s, "upd-<id>")
	s = regexp.MustCompile(`(update|jo-pre-upgrade)-[0-9a-f]{6}`).ReplaceAllString(s, "$1-<id>")
	s = regexp.MustCompile(`dom-[0-9a-f]{8}`).ReplaceAllString(s, "dom-<id>")
	s = regexp.MustCompile(`20260301090000-[0-9a-f]{8}`).ReplaceAllString(s, "<snapshot-id>")
	s = pwRe.ReplaceAllString(s, "<password>")
	s = regexp.MustCompile(`(postgres://[a-z0-9_]+:)[A-Za-z0-9]{32}@`).ReplaceAllString(s, "$1<password>@")
	s = regexp.MustCompile(`([0-9a-f]{2}:){31}[0-9a-f]{2}`).ReplaceAllString(s, "<fingerprint>")
	s = regexp.MustCompile(`sha256:[0-9a-f]{12,32}`).ReplaceAllString(s, "sha256:<hex>")
	s = tmpRe.ReplaceAllString(s, "<tmp>/$1")
	s = regexp.MustCompile(`jailops-([a-z-]+)-([a-z0-9-]+)-\d+\.yaml`).ReplaceAllString(s, "jailops-$1-$2-N.yaml")
	return s
}

// transcript records commands and their output for a golden file.
type transcript struct {
	h   *harness
	buf strings.Builder
}

func (h *harness) transcript() *transcript { return &transcript{h: h} }

// do runs a command and records it; it returns the raw results too.
func (tr *transcript) do(stdin string, args ...string) (string, string, int) {
	tr.h.t.Helper()
	out, errs, code := tr.h.run(stdin, args...)
	dir := func(s string) string { return strings.ReplaceAll(s, tr.h.dir, "<dir>") }
	fmt.Fprintf(&tr.buf, "$ jailops %s\n", normalize(dir(strings.Join(args, " "))))
	out, errs = dir(out), dir(errs)
	tr.buf.WriteString(normalize(out))
	if errs != "" {
		for _, l := range strings.Split(strings.TrimRight(normalize(errs), "\n"), "\n") {
			tr.buf.WriteString("! " + l + "\n")
		}
	}
	if code != 0 {
		fmt.Fprintf(&tr.buf, "[exit %d]\n", code)
	}
	tr.buf.WriteString("\n")
	return out, errs, code
}

// ok runs a command that must succeed.
func (tr *transcript) ok(args ...string) string {
	tr.h.t.Helper()
	out, errs, code := tr.do("", args...)
	if code != 0 {
		tr.h.t.Fatalf("jailops %v exited %d: %s", args, code, errs)
	}
	return out
}

func (tr *transcript) golden(name string) {
	tr.h.t.Helper()
	golden(tr.h.t, name, tr.buf.String())
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("output differs from %s (run go test -update to accept):\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

// statFile returns the permission bits of a file.
func statFile(p string) (os.FileMode, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return fi.Mode().Perm(), nil
}

func ctxT() context.Context { return context.Background() }
