package priv

import (
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files of the host firewall renderer")

const origPF = "# my own rules\nset skip on lo0\npass all\n"

// pfSim stands in for pf: pfctl -s info|rules, -n -f -, -f FILE, -e and -d act on its state.
type pfSim struct {
	mu       sync.Mutex
	enabled  bool
	loaded   string
	noPF     bool   // pf is not loaded: every pfctl call fails
	badCheck string // pfctl -n refuses a ruleset that contains this
	loadFail string // pfctl -f refuses a file that contains this
	loads    int
}

func (p *pfSim) rules(r *run.Fake, etc string) {
	fail := func(msg string) (run.Result, error) {
		return run.Result{ExitCode: 1}, &run.ExitError{Name: pfctlBin, Code: 1, Stderr: msg}
	}
	r.Add(run.Rule{Name: pfctlBin, Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.noPF {
			return fail("/dev/pf: No such file or directory")
		}
		switch strings.Join(c.Args, " ") {
		case "-s info":
			st := "Disabled"
			if p.enabled {
				st = "Enabled for 0 days 00:01:02"
			}
			return run.Result{Stdout: []byte("Status: " + st + "          Debug: Urgent\n")}, nil
		case "-s rules":
			var out []string
			for _, ln := range splitLines(p.loaded) {
				if strings.HasPrefix(ln, "anchor ") || strings.HasPrefix(ln, "pass ") || strings.HasPrefix(ln, "block ") {
					out = append(out, ln+" all")
				}
			}
			return run.Result{Stdout: []byte(strings.Join(out, "\n") + "\n")}, nil
		case "-n -f -":
			b, _ := io.ReadAll(c.Stdin)
			if p.badCheck != "" && strings.Contains(string(b), p.badCheck) {
				return fail("stdin:7: syntax error")
			}
			return run.Result{}, nil
		case "-f " + etc + "/pf.conf":
			b, err := os.ReadFile(etc + "/pf.conf")
			if err != nil {
				return fail("cannot open the given rules file")
			}
			if p.loadFail != "" && strings.Contains(string(b), p.loadFail) {
				return fail("pfctl: DIOCADDRULENV: Invalid argument")
			}
			p.loaded, p.loads = string(b), p.loads+1
			return run.Result{}, nil
		case "-e":
			if p.enabled {
				return fail("pf already enabled")
			}
			p.enabled = true
			return run.Result{}, nil
		case "-d":
			if !p.enabled {
				return fail("pf not enabled")
			}
			p.enabled = false
			return run.Result{}, nil
		}
		return fail("unexpected pfctl " + strings.Join(c.Args, " "))
	}})
}

func (p *pfSim) state() (bool, string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled, p.loaded, p.loads
}

// fakeTimer is the timer of a pending change, fired by the test.
type fakeTimer struct {
	mu    sync.Mutex
	d     time.Duration
	f     func()
	armed bool
	arms  int
}

func (t *fakeTimer) after(d time.Duration, f func()) func() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.d, t.f, t.armed, t.arms = d, f, true, t.arms+1
	return func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()
		was := t.armed
		t.armed = false
		return was
	}
}

// fire runs the armed timer, as the deadline would.
func (t *fakeTimer) fire(tb testing.TB) {
	t.mu.Lock()
	f, armed := t.f, t.armed
	t.armed = false
	t.mu.Unlock()
	if !armed {
		tb.Fatal("no timer is armed")
	}
	f()
}

func (t *fakeTimer) isArmed() (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.armed, t.d
}

type fwEnv struct {
	*env
	h     *hostSys
	pf    *pfSim
	timer *fakeTimer
	etc   string
	mu    sync.Mutex
	clock time.Time
}

func (f *fwEnv) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.clock }
func (f *fwEnv) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(d)
}

// newFWEnv is a helper with an etc directory holding the administrator's pf.conf, pf running, a clock the test moves
// and a timer it fires.
func newFWEnv(t *testing.T, modules ...string) *fwEnv {
	t.Helper()
	e := newEnv(t)
	f := &fwEnv{env: e, pf: &pfSim{enabled: true, loaded: origPF}, timer: &fakeTimer{}, etc: filepath.Join(e.base, "etc"),
		clock: time.Date(2026, 10, 30, 10, 15, 0, 0, time.UTC)}
	mustWrite(t, filepath.Join(f.etc, "pf.conf"), origPF)
	mustWrite(t, filepath.Join(f.etc, "rc.conf"), origRC)
	mustWrite(t, filepath.Join(f.etc, "resolv.conf"), origResolv)
	mustWrite(t, filepath.Join(f.etc, "ntp.conf"), origNTP)
	f.h = &hostSys{etc: f.etc, hostname: "old.example.org"}
	f.h.rules(e.runner)
	f.pf.rules(e.runner, f.etc)
	f.reopen(t, modules...)
	return f
}

// reopen starts a new helper over the same directories: a restart.
func (f *fwEnv) reopen(t *testing.T, modules ...string) {
	t.Helper()
	cfg := f.cfg
	cfg.HostManage = modules
	cfg.HostDir = filepath.Join(f.base, "priv", "host")
	l, err := NewLocal(cfg, Deps{ZFS: f.zfs, Jails: f.jails, PF: f.env.pf, Net: f.net, Runner: f.runner, Jexec: f.jexec, Etc: f.etc,
		Now: f.now, AfterFunc: f.timer.after}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	f.local, f.cfg = l, l.Config()
}

func fwSpec() api.HostFirewallSpec {
	return api.HostFirewallSpec{Template: api.HostFirewallCustom, ICMP: true,
		SSH:     &api.HostFirewallSSH{Ports: []int{22}, AllowFrom: []string{"@admins"}},
		Console: &api.HostFirewallConsole{Port: 39110, AllowFrom: []string{"@admins", "198.51.100.7"}},
		Sets:    []api.HostFirewallSet{{Name: "admins", Members: []string{"192.0.2.0/24", "2001:db8:a::/48"}}},
		Allow:   []api.HostFirewallAllow{{Proto: "tcp", Ports: []string{"80", "443"}, Comment: "web"}}}
}

func fwReq(spec api.HostFirewallSpec, dry bool) service.HostFirewallRequest {
	return service.HostFirewallRequest{Spec: spec.Canonical(), DryRun: dry, ConfirmWithin: 60, Peer: "192.0.2.10"}
}

func fwGolden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name+".golden")
	if *updateGolden {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test -run %s -update)", err, t.Name())
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file:\n%s", name, got)
	}
}

func TestHostFWRenderGolden(t *testing.T) {
	def := api.DefaultHostFirewall(39110).Canonical()
	fwGolden(t, "hostfw_default", renderHostPF(def))
	fwGolden(t, "hostfw_open", renderHostPF(api.HostFirewallSpec{Template: api.HostFirewallOpen, Console: &api.HostFirewallConsole{Port: 39110}}.Canonical()))
	custom := api.HostFirewallSpec{Template: api.HostFirewallCustom, Logging: true, ICMP: false,
		SSH:     &api.HostFirewallSSH{Ports: []int{22, 2222}, AllowFrom: []string{"@admins", "203.0.113.9", "2001:db8:ff::/64"}},
		Console: &api.HostFirewallConsole{Port: 8443, AllowFrom: []string{"@admins"}},
		Sets: []api.HostFirewallSet{{Name: "admins", Members: []string{"192.0.2.0/24", "2001:db8:a::/48", "198.51.100.7"}},
			{Name: "monitoring", Members: []string{"2001:db8:f::5"}}},
		Allow: []api.HostFirewallAllow{
			{Proto: "tcp", Ports: []string{"80", "443"}, Comment: "web"},
			{Proto: "udp", Ports: []string{"51820"}, From: []string{"2001:db8:1::/56"}, Comment: "wireguard for the branch office"},
			{Proto: "tcp", Ports: []string{"9100-9110"}, From: []string{"@monitoring", "192.0.2.77"}},
		}}
	if err := custom.Validate(); err != nil {
		t.Fatal(err)
	}
	fwGolden(t, "hostfw_custom", renderHostPF(custom.Canonical()))
	noConsole := api.DefaultHostFirewall(0)
	noConsole.SSH.AllowFrom = []string{"192.0.2.10"}
	fwGolden(t, "hostfw_no_console", renderHostPF(noConsole.Canonical()))
	// ACME: the redirect of the CA's port to the daemon, after the jails' anchor, and its pass rule
	acmeHTTP := api.DefaultHostFirewall(39110)
	acmeHTTP.SSH.AllowFrom = []string{"192.0.2.10"}
	acmeHTTP.ACME = &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: 39080}
	fwGolden(t, "hostfw_acme_http", renderHostPF(acmeHTTP.Canonical()))
	acmeALPN := api.HostFirewallSpec{Template: api.HostFirewallOpen, Console: &api.HostFirewallConsole{Port: 39110},
		ACME: &api.HostFirewallACME{Challenge: api.ACMETLSALPN01, Port: 39110}}
	if err := acmeALPN.Validate(); err != nil {
		t.Fatal(err)
	}
	fwGolden(t, "hostfw_acme_alpn_open", renderHostPF(acmeALPN.Canonical()))
	for _, s := range []api.HostFirewallSpec{acmeHTTP.Canonical(), acmeALPN.Canonical()} {
		out := renderHostPF(s)
		if a, x := strings.Index(out, "\nanchor \"jailops/*\"\n"), strings.Index(out, "\nmatch in inet proto tcp"); a < 0 || x < a {
			t.Errorf("the redirect does not come after the jails' anchor:\n%s", out)
		}
	}
	// every rendering has the anchor line of design 5.2 (and no translation anchors) before the first rule
	for _, s := range []api.HostFirewallSpec{def, custom.Canonical(), api.HostFirewallSpec{Template: api.HostFirewallOpen}.Canonical()} {
		out := renderHostPF(s)
		a, first := strings.Index(out, "\nanchor \"jailops/*\"\n"), firstFilterRule(out)
		if a < 0 || first < a || strings.Contains(out, "nat-anchor") || strings.Contains(out, "rdr-anchor") || !strings.HasPrefix(out, HostResolvHeader+"\n") {
			t.Errorf("order: anchor %d first rule %d\n%s", a, first, out)
		}
	}
}

func firstFilterRule(s string) int {
	i := len(s)
	for _, w := range []string{"\npass ", "\nblock "} {
		if j := strings.Index(s, w); j >= 0 && j < i {
			i = j
		}
	}
	return i
}

func TestHostPfctlAllowList(t *testing.T) {
	etc := "/etc"
	for _, ok := range [][]string{{"-n", "-f", "-"}, {"-f", "/etc/pf.conf"}, {"-e"}, {"-d"}, {"-s", "info"}, {"-s", "rules"}} {
		if err := checkHostPfctl(etc, ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][]string{
		{}, {"-f", "/tmp/pf.conf"}, {"-f", "/etc/pf.conf.d/../pf.conf"}, {"-f", "-"}, {"-n", "-f", "/etc/pf.conf"}, {"-F", "all"}, {"-F", "states"},
		{"-k", "0.0.0.0/0"}, {"-a", "jailops", "-f", "-"}, {"-s", "states"}, {"-s", "info", "-v"}, {"-e", "-d"}, {"-f", "/etc/pf.conf", "-e"},
		{"-x", "loud"}, {"-t", "x", "-T", "flush"}, {"-nf", "-"}, {"-f /etc/pf.conf"},
	} {
		if err := checkHostPfctl(etc, bad); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	// and nothing runs when the form is refused
	f := newFWEnv(t, "firewall")
	if _, err := f.local.hostPfctl(context.Background(), "", "-F", "all"); err == nil {
		t.Fatal("pfctl -F all ran")
	}
	for _, c := range f.runner.Calls() {
		if c.Cmd.Name == pfctlBin && c.Cmd.Args[0] == "-F" {
			t.Fatal("pfctl -F ran")
		}
	}
	// pfctl is not reachable through run.exec either: the daemon's read-only forms do not load
	for _, args := range [][]string{{"-f", "/etc/pf.conf"}, {"-e"}, {"-d"}, {"-n", "-f", "-"}} {
		if err := customPfctl(Config{}, true, args); err == nil {
			t.Errorf("run.exec accepts pfctl %v", args)
		}
	}
}

// Validation runs in the helper too: every field is refused over the wire when it could carry more than its value.
func TestHostFWRefusalsOverTheWire(t *testing.T) {
	f := newFWEnv(t, "firewall")
	c := hostWire(t, f.env)
	long := strings.Repeat("x", 81)
	sets := []api.HostFirewallSet{{Name: "admins", Members: []string{"192.0.2.0/24"}}}
	many := func(n int, f func(i int) string) []string {
		var out []string
		for i := range n {
			out = append(out, f(i))
		}
		return out
	}
	rows := func(n int) []api.HostFirewallAllow {
		var out []api.HostFirewallAllow
		for i := range n {
			out = append(out, api.HostFirewallAllow{Proto: "tcp", Ports: []string{"1000"}, Comment: "row " + strings.Repeat("i", i%3)})
		}
		return out
	}
	custom := func(a ...api.HostFirewallAllow) api.HostFirewallSpec {
		return api.HostFirewallSpec{Template: api.HostFirewallCustom, Sets: sets, Allow: a}
	}
	cases := map[string]api.HostFirewallSpec{
		"template":             {Template: "permissive"},
		"template newline":     {Template: "default\npass all"},
		"ssh port 0":           {SSH: &api.HostFirewallSSH{Ports: []int{0}}},
		"ssh port 65536":       {SSH: &api.HostFirewallSSH{Ports: []int{65536}}},
		"ssh port negative":    {SSH: &api.HostFirewallSSH{Ports: []int{-22}}},
		"ssh port twice":       {SSH: &api.HostFirewallSSH{Ports: []int{22, 22}}},
		"five ssh ports":       {SSH: &api.HostFirewallSSH{Ports: []int{22, 23, 24, 25, 26}}},
		"ssh source name":      {SSH: &api.HostFirewallSSH{AllowFrom: []string{"admin.example.com"}}},
		"ssh source newline":   {SSH: &api.HostFirewallSSH{AllowFrom: []string{"192.0.2.1\npass all"}}},
		"ssh source space":     {SSH: &api.HostFirewallSSH{AllowFrom: []string{"192.0.2.1 }"}}},
		"ssh source brace":     {SSH: &api.HostFirewallSSH{AllowFrom: []string{"{ any }"}}},
		"ssh source any":       {SSH: &api.HostFirewallSSH{AllowFrom: []string{"any"}}},
		"ssh source zone":      {SSH: &api.HostFirewallSSH{AllowFrom: []string{"fe80::1%em0"}}},
		"ssh source mapped":    {SSH: &api.HostFirewallSSH{AllowFrom: []string{"::ffff:192.0.2.1"}}},
		"ssh source host bits": {SSH: &api.HostFirewallSSH{AllowFrom: []string{"192.0.2.1/24"}}},
		"ssh source bad len":   {SSH: &api.HostFirewallSSH{AllowFrom: []string{"192.0.2.0/33"}}},
		"ssh source twice":     {SSH: &api.HostFirewallSSH{AllowFrom: []string{"2001:db8::1", "2001:db8:0::1"}}},
		"ssh source unknown @": {SSH: &api.HostFirewallSSH{AllowFrom: []string{"@nobody"}}},
		"ssh source bad @":     {SSH: &api.HostFirewallSSH{AllowFrom: []string{"@Admins"}}},
		"33 sources":           {SSH: &api.HostFirewallSSH{AllowFrom: many(33, func(i int) string { return "192.0.2." + itoa(i+1) })}},
		"console port big":     {Console: &api.HostFirewallConsole{Port: 70000}},
		"console source":       {Console: &api.HostFirewallConsole{AllowFrom: []string{"192.0.2.0/24; pass all"}}},
		"allow without custom": {Allow: rows(1)},
		"65 rows":              custom(rows(65)...),
		"proto icmp":           custom(api.HostFirewallAllow{Proto: "icmp", Ports: []string{"1"}}),
		"proto empty":          custom(api.HostFirewallAllow{Ports: []string{"1"}}),
		"proto newline":        custom(api.HostFirewallAllow{Proto: "tcp\npass", Ports: []string{"1"}}),
		"no port":              custom(api.HostFirewallAllow{Proto: "tcp"}),
		"17 ports":             custom(api.HostFirewallAllow{Proto: "tcp", Ports: many(17, func(i int) string { return itoa(1000 + i) })}),
		"port 0":               custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"0"}}),
		"port 65536":           custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"65536"}}),
		"port name":            custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"ssh"}}),
		"port plus":            custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"+80"}}),
		"port leading zero":    custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"080"}}),
		"port range reversed":  custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"90-80"}}),
		"port range same":      custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80-80"}}),
		"port range open":      custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80-"}}),
		"port pf range":        custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80:90"}}),
		"port twice":           custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80", "80"}}),
		"port space":           custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80 }"}}),
		"from bad":             custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80"}, From: []string{"!192.0.2.1"}}),
		"comment newline":      custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80"}, Comment: "web\npass all"}),
		"comment cr":           custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80"}, Comment: "web\rpass all"}),
		"comment quote":        custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80"}, Comment: `web "x"`}),
		"comment single quote": custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80"}, Comment: "it's"}),
		"comment backslash":    custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80"}, Comment: `web\`}),
		"comment tab":          custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80"}, Comment: "web\tx"}),
		"comment too long":     custom(api.HostFirewallAllow{Proto: "tcp", Ports: []string{"80"}, Comment: long}),
		"set name":             {Sets: []api.HostFirewallSet{{Name: "a b", Members: []string{"192.0.2.1"}}}},
		"set name long":        {Sets: []api.HostFirewallSet{{Name: "a" + strings.Repeat("b", 24), Members: []string{"192.0.2.1"}}}},
		"set name underscore":  {Sets: []api.HostFirewallSet{{Name: "a_b", Members: []string{"192.0.2.1"}}}},
		"set twice":            {Sets: []api.HostFirewallSet{{Name: "a", Members: []string{"192.0.2.1"}}, {Name: "a", Members: []string{"192.0.2.2"}}}},
		"set empty":            {Sets: []api.HostFirewallSet{{Name: "a"}}},
		"set member @":         {Sets: []api.HostFirewallSet{{Name: "a", Members: []string{"@b"}}}},
		"set member twice":     {Sets: []api.HostFirewallSet{{Name: "a", Members: []string{"192.0.2.0/24", "192.0.2.0/24"}}}},
		"set member newline":   {Sets: []api.HostFirewallSet{{Name: "a", Members: []string{"192.0.2.1\n}"}}}},
		"257 members":          {Sets: []api.HostFirewallSet{{Name: "a", Members: many(257, func(i int) string { return "2001:db8::" + itoa(i+1) })}}},
		"17 sets": {Sets: func() []api.HostFirewallSet {
			var s []api.HostFirewallSet
			for i := range 17 {
				s = append(s, api.HostFirewallSet{Name: "s" + itoa(i), Members: []string{"192.0.2.1"}})
			}
			return s
		}()},
		"open with sources": {Template: api.HostFirewallOpen, SSH: &api.HostFirewallSSH{AllowFrom: []string{"192.0.2.1"}}},
		"open with rows":    {Template: api.HostFirewallOpen, Allow: rows(1)},
		// the ACME redirect: only the two values, each checked
		"acme challenge":         {ACME: &api.HostFirewallACME{Challenge: "dns-01", Port: 39080}},
		"acme challenge newline": {ACME: &api.HostFirewallACME{Challenge: "http-01\nrdr pass all", Port: 39080}},
		"acme port 0":            {ACME: &api.HostFirewallACME{Challenge: api.ACMEHTTP01}},
		"acme port 80":           {ACME: &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: 80}},
		"acme port 1023":         {ACME: &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: 1023}},
		"acme port 65536":        {ACME: &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: 65536}},
		"acme port negative":     {ACME: &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: -39080}},
		"acme port is ssh":       {SSH: &api.HostFirewallSSH{Ports: []int{2222}}, ACME: &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: 2222}},
		"acme port is console":   {Console: &api.HostFirewallConsole{Port: 39110}, ACME: &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: 39110}},
		"alpn not the console":   {Console: &api.HostFirewallConsole{Port: 39110}, ACME: &api.HostFirewallACME{Challenge: api.ACMETLSALPN01, Port: 39080}},
		"alpn without console":   {ACME: &api.HostFirewallACME{Challenge: api.ACMETLSALPN01, Port: 39110}},
	}
	for name, spec := range cases {
		if _, err := c.HostFirewallApply(admin(), service.HostFirewallRequest{Spec: spec, DryRun: true, Peer: "192.0.2.10"}); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.HostFirewallApply(admin(), service.HostFirewallRequest{Spec: api.HostFirewallSpec{NAT: "masquerade"}, DryRun: true}); !api.IsCode(err, api.CodeUnsupported) {
		t.Errorf("nat: %v", err)
	}
	for _, w := range []int{-1, 9, 1801, 100000} {
		if _, err := c.HostFirewallApply(admin(), service.HostFirewallRequest{Spec: fwSpec(), DryRun: true, ConfirmWithin: w, Peer: "192.0.2.10"}); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("confirm within %d: %v", w, err)
		}
	}
	for _, p := range []string{"192.0.2.10:22", "unix", "fe80::1%em0 ", "a.example.com"} {
		if _, err := c.HostFirewallApply(admin(), service.HostFirewallRequest{Spec: fwSpec(), DryRun: true, Peer: p}); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("peer %q: %v", p, err)
		}
	}
	for _, id := range []string{"x", "../pending", "0123456789ABCDEF", strings.Repeat("a", 17)} {
		if _, err := c.HostPendingConfirm(admin(), id); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("confirm id %q: %v", id, err)
		}
		if _, err := c.HostPendingRevert(admin(), id); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("revert id %q: %v", id, err)
		}
	}
	// the limits themselves pass: 64 rows, 32 sources, 16 sets, 256 members, a comment of 80
	ok := custom(rows(64)...)
	ok.Allow[0].Comment = strings.Repeat("x", 80)
	ok.SSH = &api.HostFirewallSSH{Ports: []int{22, 2222, 22222, 65535}, AllowFrom: many(32, func(i int) string { return "198.51.100." + itoa(i+1) })}
	for i := range 15 {
		ok.Sets = append(ok.Sets, api.HostFirewallSet{Name: "s" + itoa(i), Members: many(256, func(j int) string { return "2001:db8:" + itoa(i+1) + "::" + itoa(j+1) })})
	}
	if _, err := c.HostFirewallApply(admin(), service.HostFirewallRequest{Spec: ok, DryRun: true, Peer: "198.51.100.1"}); err != nil {
		t.Errorf("the limits: %v", err)
	}
	if readFile(t, filepath.Join(f.etc, "pf.conf")) != origPF {
		t.Error("a refused or dry request changed pf.conf")
	}
}

// The ACME redirect goes through the real allow-list and the wire: the helper renders it from the two numbers, checks
// it with pfctl -n, loads it with the pending record like every change, and a revert takes it away again.
func TestHostFWACMERedirectOverTheWire(t *testing.T) {
	f := newFWEnv(t, "firewall")
	c := hostWire(t, f.env)
	spec := fwSpec()
	spec.ACME = &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: 39080}
	dry, err := c.HostFirewallApply(admin(), fwReq(spec, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"+match in inet proto tcp from any to (self) port 80 rdr-to 127.0.0.1 port 39080",
		"+match in inet6 proto tcp from any to (self) port 80 rdr-to ::1 port 39080", "+pass in proto tcp from any to { 127.0.0.1, ::1 } port 39080"} {
		if !strings.Contains(dry.Diff, want) {
			t.Errorf("the diff lacks %q:\n%s", want, dry.Diff)
		}
	}
	if !slices.ContainsFunc(dry.Rules, func(r api.HostFirewallRule) bool { return r.Ports == "80" && strings.Contains(r.Comment, "port 39080") }) {
		t.Errorf("rules: %+v", dry.Rules)
	}
	res, err := c.HostFirewallApply(admin(), fwReq(spec, false))
	if err != nil || res.Pending == nil {
		t.Fatalf("%v %+v", err, res)
	}
	if _, loaded, _ := f.pf.state(); !strings.Contains(loaded, "rdr-to 127.0.0.1 port 39080") {
		t.Errorf("not loaded:\n%s", loaded)
	}
	// every pfctl call was an allow-listed form
	for _, call := range f.runner.Calls() {
		if call.Cmd.Name == pfctlBin {
			if err := checkHostPfctl(f.etc, call.Cmd.Args); err != nil {
				t.Errorf("pfctl %v: %v", call.Cmd.Args, err)
			}
		}
	}
	if _, err := c.HostPendingRevert(admin(), res.Pending.ID); err != nil {
		t.Fatal(err)
	}
	if _, loaded, _ := f.pf.state(); strings.Contains(loaded, "39080") {
		t.Errorf("the revert kept the redirect:\n%s", loaded)
	}
	// the redirect cannot target a port below 1024 or name a challenge of its own, whatever the daemon sends
	bad := fwSpec()
	bad.ACME = &api.HostFirewallACME{Challenge: api.ACMEHTTP01, Port: 22}
	if _, err := c.HostFirewallApply(admin(), fwReq(bad, false)); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("port 22: %v", err)
	}
	if readFile(t, filepath.Join(f.etc, "pf.conf")) != origPF {
		t.Error("pf.conf is not the administrator's again")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestHostFWNeedsAdminAndModule(t *testing.T) {
	f := newFWEnv(t, "identity")
	c := hostWire(t, f.env)
	if _, err := c.HostFirewallApply(context.Background(), fwReq(fwSpec(), true)); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("without the assertion: %v", err)
	}
	_, err := c.HostFirewallApply(admin(), fwReq(fwSpec(), true))
	var ae *api.Error
	if !asAPIError(err, &ae) || ae.Code != api.CodeForbidden || ae.Detail["module"] != "firewall" || !strings.Contains(ae.Hint, "host-manage = firewall") {
		t.Errorf("module not in priv.conf: %v", err)
	}
	// reading needs nothing
	st, err := c.HostFirewallRead(context.Background())
	if err != nil || !st.FileExists || st.FileManaged || st.Applied != nil || st.PFEnabled == nil || !*st.PFEnabled {
		t.Errorf("%+v %v", st, err)
	}
	if p, err := c.HostPending(context.Background()); err != nil || p.Pending != nil || p.Last != nil {
		t.Errorf("%+v %v", p, err)
	}
	if _, err := c.HostPendingConfirm(context.Background(), ""); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("confirm without the assertion: %v", err)
	}
	if _, err := c.HostPendingRevert(context.Background(), ""); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("revert without the assertion: %v", err)
	}
	if _, err := c.HostPendingConfirm(admin(), ""); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("nothing to confirm: %v", err)
	}
	if readFile(t, filepath.Join(f.etc, "pf.conf")) != origPF {
		t.Error("pf.conf changed")
	}
	if _, _, loads := f.pf.state(); loads != 0 {
		t.Error("pf was loaded")
	}
}

func TestHostFWLockoutGuard(t *testing.T) {
	spec := fwSpec().Canonical()
	for peer, ok := range map[string]bool{
		"192.0.2.10":       true,  // in @admins: ssh and the console
		"2001:db8:a::99":   true,  // the IPv6 member of @admins
		"198.51.100.7":     true,  // the console only
		"203.0.113.5":      false, // the allow row (tcp 80, 443 from anywhere) opens neither ssh nor the console
		"2001:db8:b::1":    false, // outside every source
		"::ffff:192.0.2.9": true,  // a mapped address is the IPv4 address
	} {
		err := lockoutGuard(spec, peer, false)
		if (err == nil) != ok {
			t.Errorf("%s: %v", peer, err)
		}
		if err != nil && (!api.IsCode(err, api.CodeForbidden) || err.(*api.Error).Detail["guard"] != "lockout") {
			t.Errorf("%s: %v", peer, err)
		}
	}
	// a custom row on an ssh port counts too
	s2 := fwSpec()
	s2.Allow = append(s2.Allow, api.HostFirewallAllow{Proto: "tcp", Ports: []string{"20-30"}, From: []string{"203.0.113.0/24"}})
	if err := lockoutGuard(s2.Canonical(), "203.0.113.5", false); err != nil {
		t.Errorf("a custom row for port 22: %v", err)
	}
	// udp does not count
	s2.Allow[1].Proto = "udp"
	if err := lockoutGuard(s2.Canonical(), "203.0.113.5", false); err == nil {
		t.Error("a udp row let the guard pass")
	}
	// open: always reachable; default spec: everybody
	if lockoutGuard(api.HostFirewallSpec{Template: api.HostFirewallOpen}.Canonical(), "203.0.113.5", false) != nil ||
		lockoutGuard(api.DefaultHostFirewall(39110).Canonical(), "2001:db8::1", false) != nil {
		t.Error("open or default")
	}
	// unknown caller: refused without confirm_lockout, accepted with it
	if err := lockoutGuard(spec, "", false); !api.IsCode(err, api.CodeInvalid) || !strings.Contains(err.(*api.Error).Hint, "--confirm-lockout") {
		t.Errorf("unknown peer: %v", err)
	}
	if err := lockoutGuard(spec, "", true); err != nil {
		t.Errorf("confirm_lockout: %v", err)
	}

	// through the helper: refused before anything changes; the dry run says so
	f := newFWEnv(t, "firewall")
	c := hostWire(t, f.env)
	req := fwReq(fwSpec(), false)
	req.Peer = "2001:db8:b::1"
	if _, err := c.HostFirewallApply(admin(), req); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("lockout: %v", err)
	}
	req.DryRun = true
	dry, err := c.HostFirewallApply(admin(), req)
	if err != nil || !slices.ContainsFunc(dry.Warnings, func(w string) bool { return strings.Contains(w, "would be refused") }) {
		t.Errorf("dry run: %+v %v", dry, err)
	}
	req.DryRun, req.Peer = false, ""
	if _, err := c.HostFirewallApply(admin(), req); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("unknown peer: %v", err)
	}
	if readFile(t, filepath.Join(f.etc, "pf.conf")) != origPF {
		t.Error("a refused apply changed pf.conf")
	}
	if snaps, _ := c.HostSnapshots(context.Background()); len(snaps) != 0 {
		t.Errorf("a refused apply took a snapshot: %v", snaps)
	}
	req.ConfirmLockout = true
	res, err := c.HostFirewallApply(admin(), req)
	if err != nil || res.Pending == nil {
		t.Fatalf("confirm_lockout: %+v %v", res, err)
	}
}

// The life of a pending change: apply (snapshot, record, file, load), the timer, confirm, revert, busy.
func TestHostFWPendingLifecycle(t *testing.T) {
	f := newFWEnv(t, "firewall", "identity")
	c := hostWire(t, f.env)
	pfPath := filepath.Join(f.etc, "pf.conf")
	rcBefore := readFile(t, filepath.Join(f.etc, "rc.conf"))

	dry, err := c.HostFirewallApply(admin(), fwReq(fwSpec(), true))
	if err != nil || !dry.DryRun || !dry.Changed || dry.Pending != nil || dry.Snapshot != "" {
		t.Fatalf("%+v %v", dry, err)
	}
	for _, want := range []string{"--- " + pfPath, "-pass all", "+" + HostResolvHeader, `+anchor "jailops/*"`, "+table <jo_hf_admins> const { 192.0.2.0/24, 2001:db8:a::/48 }",
		`+pf_enable="YES"`} {
		if !strings.Contains(dry.Diff, want) {
			t.Errorf("the dry run diff lacks %q:\n%s", want, dry.Diff)
		}
	}
	if !slices.ContainsFunc(dry.Actions, func(a string) bool { return strings.Contains(a, "reverts in 60 seconds") }) || len(dry.Rules) == 0 {
		t.Errorf("%v %v", dry.Actions, dry.Rules)
	}
	if readFile(t, pfPath) != origPF {
		t.Fatal("the dry run wrote")
	}

	// arm: the record is written before the file, and names the snapshot
	res, err := c.HostFirewallApply(admin(), fwReq(fwSpec(), false))
	if err != nil || res.Pending == nil || res.Snapshot == "" || res.Pending.Snapshot != res.Snapshot || res.Pending.SecondsLeft != 60 {
		t.Fatalf("%+v %v", res, err)
	}
	if armed, d := f.timer.isArmed(); !armed || d != 60*time.Second {
		t.Fatalf("timer %v %v", armed, d)
	}
	cur := readFile(t, pfPath)
	if !strings.HasPrefix(cur, HostResolvHeader+"\n") {
		t.Fatal("pf.conf was not written")
	}
	if on, loaded, _ := f.pf.state(); !on || loaded != cur {
		t.Fatal("pf did not load the file")
	}
	if !strings.Contains(readFile(t, filepath.Join(f.etc, "rc.conf")), `pf_enable="YES"`) {
		t.Error("pf_enable")
	}
	snaps, _ := c.HostSnapshots(context.Background())
	if len(snaps) != 1 || snaps[0].Module != "firewall" || snaps[0].Reason != "adopt" || !slices.Equal(snaps[0].Files, []string{pfPath, filepath.Join(f.etc, "rc.conf")}) {
		t.Errorf("%+v", snaps)
	}
	p, err := c.HostPending(context.Background())
	if err != nil || p.Pending == nil || p.Pending.ID != res.Pending.ID || p.Pending.Module != "firewall" {
		t.Fatalf("%+v %v", p, err)
	}
	f.advance(15 * time.Second)
	if p, _ := c.HostPending(context.Background()); p.Pending.SecondsLeft != 45 {
		t.Errorf("seconds left %d", p.Pending.SecondsLeft)
	}

	// one at a time: every other change is busy, naming the first; a dry run still works
	_, err = c.HostFirewallApply(admin(), fwReq(api.DefaultHostFirewall(39110), false))
	var ae *api.Error
	if !asAPIError(err, &ae) || ae.Code != api.CodeBusy || ae.Detail["pending"] != res.Pending.ID {
		t.Errorf("second change: %v", err)
	}
	if _, err := c.HostIdentityApply(admin(), goodSpec(), false); !api.IsCode(err, api.CodeBusy) {
		t.Errorf("identity while pending: %v", err)
	}
	if _, err := c.HostSnapshotRestore(admin(), res.Snapshot, false); !api.IsCode(err, api.CodeBusy) {
		t.Errorf("restore while pending: %v", err)
	}
	if _, err := c.HostFirewallApply(admin(), fwReq(api.DefaultHostFirewall(39110), true)); err != nil {
		t.Errorf("a dry run while pending: %v", err)
	}
	if _, err := c.HostPendingConfirm(admin(), "0123456789abcdef"); !api.IsCode(err, api.CodeConflict) {
		t.Errorf("another id: %v", err)
	}

	// the timer fires: the file comes back byte for byte, pf reloads it, the record goes
	f.advance(46 * time.Second)
	f.timer.fire(t)
	if readFile(t, pfPath) != origPF || readFile(t, filepath.Join(f.etc, "rc.conf")) != rcBefore {
		t.Fatal("the timeout did not put the files back")
	}
	if on, loaded, _ := f.pf.state(); !on || loaded != origPF {
		t.Fatalf("pf runs %q", loaded)
	}
	p, _ = c.HostPending(context.Background())
	if p.Pending != nil || p.Last == nil || p.Last.Outcome != api.HostPendingTimedOut || p.Last.ID != res.Pending.ID {
		t.Fatalf("%+v", p)
	}
	st, _ := c.HostFirewallRead(context.Background())
	if st.Applied != nil || st.FileManaged || len(st.Drift) != 0 {
		t.Errorf("after the timeout: %+v", st)
	}
	if _, err := c.HostPendingConfirm(admin(), res.Pending.ID); !api.IsCode(err, api.CodeNotFound) || !strings.Contains(err.Error(), "timed_out") {
		t.Errorf("a late confirmation: %v", err)
	}

	// confirm: the file stays, the timer stops
	res2, err := c.HostFirewallApply(admin(), fwReq(fwSpec(), false))
	if err != nil || res2.Pending == nil {
		t.Fatal(err)
	}
	p, err = c.HostPendingConfirm(admin(), res2.Pending.ID)
	if err != nil || p.Pending != nil || p.Last.Outcome != api.HostPendingConfirmed {
		t.Fatalf("%+v %v", p, err)
	}
	if armed, _ := f.timer.isArmed(); armed {
		t.Error("the timer still runs")
	}
	if !strings.HasPrefix(readFile(t, pfPath), HostResolvHeader) {
		t.Error("the confirmed file is gone")
	}
	st, _ = c.HostFirewallRead(context.Background())
	if st.Applied == nil || !st.FileManaged || len(st.Drift) != 0 {
		t.Errorf("confirmed: %+v", st)
	}
	// the same spec again changes nothing and arms nothing
	same, err := c.HostFirewallApply(admin(), fwReq(fwSpec(), false))
	if err != nil || same.Changed || same.Pending != nil || same.Snapshot != "" {
		t.Errorf("idempotent: %+v %v", same, err)
	}

	// a hand edit is drift; a revert of the next change puts the confirmed file back, not the original
	confirmed := readFile(t, pfPath)
	mustWrite(t, pfPath, confirmed+"pass in quick all\n")
	st, _ = c.HostFirewallRead(context.Background())
	if !slices.Equal(st.Drift, []string{"pf.conf"}) {
		t.Errorf("drift %v", st.Drift)
	}
	mustWrite(t, pfPath, confirmed)
	open := api.HostFirewallSpec{Template: api.HostFirewallOpen}
	res3, err := c.HostFirewallApply(admin(), fwReq(open, false))
	if err != nil || res3.Pending == nil || !slices.Equal(snapFiles(t, c, res3.Snapshot), []string{pfPath}) {
		t.Fatalf("%+v %v", res3, err)
	}
	p, err = c.HostPendingRevert(admin(), "")
	if err != nil || p.Pending != nil || p.Last.Outcome != api.HostPendingReverted {
		t.Fatalf("%+v %v", p, err)
	}
	if readFile(t, pfPath) != confirmed {
		t.Error("the revert did not put the confirmed file back")
	}
	if _, loaded, _ := f.pf.state(); loaded != confirmed {
		t.Error("pf was not reloaded")
	}
	st, _ = c.HostFirewallRead(context.Background())
	if st.Applied == nil || st.Applied.Template != api.HostFirewallCustom || len(st.Drift) != 0 {
		t.Errorf("after the revert: %+v", st)
	}
	if _, err := c.HostPendingRevert(admin(), ""); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("nothing to revert: %v", err)
	}

	// back to the administrator's own file through the first snapshot, byte for byte
	if _, err := c.HostSnapshotRestore(admin(), res.Snapshot, false); err != nil {
		t.Fatal(err)
	}
	if readFile(t, pfPath) != origPF || readFile(t, filepath.Join(f.etc, "rc.conf")) != rcBefore {
		t.Error("the restore of the adopted file")
	}
	if st, _ := c.HostFirewallRead(context.Background()); st.Applied != nil {
		t.Errorf("the record survived the restore: %+v", st.Applied)
	}
}

func snapFiles(t *testing.T, c *Client, name string) []string {
	t.Helper()
	snaps, err := c.HostSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range snaps {
		if s.Name == name {
			return s.Files
		}
	}
	return nil
}

// The record survives a restart of the helper: the timer is armed again for the time left, or the change is
// reverted at once when the deadline passed. At boot the files go back without pfctl.
func TestHostFWPendingSurvivesRestart(t *testing.T) {
	f := newFWEnv(t, "firewall")
	ctx := admin()
	pfPath := filepath.Join(f.etc, "pf.conf")
	res, err := f.local.HostFirewallApply(ctx, fwReq(fwSpec(), false))
	if err != nil || res.Pending == nil {
		t.Fatal(err)
	}
	// restart before the deadline: re-armed for the 40 seconds left
	f.advance(20 * time.Second)
	f.reopen(t, "firewall")
	if o, err := f.local.ResumePending(context.Background()); err != nil || o != nil {
		t.Fatalf("%v %v", o, err)
	}
	if armed, d := f.timer.isArmed(); !armed || d != 40*time.Second || f.timer.arms != 2 {
		t.Errorf("re-armed %v %v %d", armed, d, f.timer.arms)
	}
	// restart after the deadline: reverted at once, before any request
	f.advance(41 * time.Second)
	f.reopen(t, "firewall")
	o, err := f.local.ResumePending(context.Background())
	if err != nil || o == nil || o.Outcome != api.HostPendingTimedOut {
		t.Fatalf("%+v %v", o, err)
	}
	if readFile(t, pfPath) != origPF {
		t.Error("not reverted")
	}
	if _, loaded, _ := f.pf.state(); loaded != origPF {
		t.Error("not reloaded")
	}
	// a stale timer of the helper before the restart does nothing now
	f.local.pendingTimeout(res.Pending.ID)

	// at boot: the files go back, pf is not touched (its rc.d script loads the file afterwards)
	res, err = f.local.HostFirewallApply(ctx, fwReq(fwSpec(), false))
	if err != nil {
		t.Fatal(err)
	}
	_, _, loads := f.pf.state()
	f.reopen(t, "firewall")
	o, err = f.local.RevertPendingAtBoot(context.Background())
	if err != nil || o == nil || o.Outcome != api.HostPendingRevertedAtBoot {
		t.Fatalf("%+v %v", o, err)
	}
	if readFile(t, pfPath) != origPF {
		t.Error("not reverted at boot")
	}
	if _, _, l2 := f.pf.state(); l2 != loads {
		t.Error("pfctl ran at boot")
	}
	if o, err := f.local.ResumePending(context.Background()); o != nil || err != nil {
		t.Errorf("after boot %v %v", o, err)
	}
	if o, err := f.local.RevertPendingAtBoot(context.Background()); o != nil || err != nil {
		t.Errorf("nothing pending at the next boot %v %v", o, err)
	}
}

// pf was off: the apply turns it on, the revert turns it off again. A first apply on a host without pf.conf
// restores the absence.
func TestHostFWPFWasDisabledAndNoFile(t *testing.T) {
	f := newFWEnv(t, "firewall")
	f.pf.enabled = false
	if err := os.Remove(filepath.Join(f.etc, "pf.conf")); err != nil {
		t.Fatal(err)
	}
	ctx := admin()
	res, err := f.local.HostFirewallApply(ctx, fwReq(api.DefaultHostFirewall(39110), false))
	if err != nil || !slices.Contains(res.Actions, "pfctl -e (pf does not run now)") {
		t.Fatalf("%+v %v", res, err)
	}
	if on, _, _ := f.pf.state(); !on {
		t.Fatal("pf is not on")
	}
	if _, err := f.local.HostPendingRevert(ctx, res.Pending.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.etc, "pf.conf")); !os.IsNotExist(err) {
		t.Error("pf.conf exists again")
	}
	if on, _, _ := f.pf.state(); on {
		t.Error("pf still runs")
	}
}

// A failure after the record was written puts everything back and ends the record.
func TestHostFWFailuresAreUndone(t *testing.T) {
	f := newFWEnv(t, "firewall")
	ctx := admin()
	pfPath := filepath.Join(f.etc, "pf.conf")
	f.pf.badCheck = "jo_hf_admins"
	if _, err := f.local.HostFirewallApply(ctx, fwReq(fwSpec(), true)); !api.IsCode(err, api.CodeInvalid) || !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("syntax: %v", err)
	}
	f.pf.badCheck = ""
	f.pf.loadFail = HostResolvHeader
	_, err := f.local.HostFirewallApply(ctx, fwReq(fwSpec(), false))
	if err == nil || !strings.Contains(err.Error(), "were put back") {
		t.Fatalf("load failure: %v", err)
	}
	f.pf.loadFail = ""
	if readFile(t, pfPath) != origPF {
		t.Error("pf.conf not put back")
	}
	p, _ := f.local.HostPending(context.Background())
	if p.Pending != nil || p.Last == nil || p.Last.Outcome != api.HostPendingReverted {
		t.Errorf("%+v", p)
	}
	if armed, _ := f.timer.isArmed(); armed {
		t.Error("a timer for a change that failed")
	}
	// pf is not loaded at all: the read says unknown, the apply fails and is undone
	f.pf.noPF = true
	st, _ := f.local.HostFirewallRead(context.Background())
	if st.PFEnabled != nil {
		t.Errorf("%+v", st)
	}
	if _, err := f.local.HostFirewallApply(ctx, fwReq(fwSpec(), false)); err == nil {
		t.Error("an apply without pf")
	}
	if readFile(t, pfPath) != origPF {
		t.Error("pf.conf not put back")
	}
}

// A snapshot manifest that names a file its module does not touch, or a module the helper does not know, is
// refused; a pending record that is not the helper's own is an error, never acted on.
func TestHostFWForeignRecords(t *testing.T) {
	f := newFWEnv(t, "firewall")
	ctx := admin()
	res, err := f.local.HostFirewallApply(ctx, fwReq(fwSpec(), false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.HostPendingConfirm(ctx, res.Pending.ID); err != nil {
		t.Fatal(err)
	}
	man := filepath.Join(f.cfg.HostDir, "snapshots", res.Snapshot, "snapshot.json")
	b := readFile(t, man)
	mustWrite(t, man, strings.Replace(b, `"name": "pf.conf"`, `"name": "master.passwd"`, 1))
	if _, err := f.local.HostSnapshotRestore(ctx, res.Snapshot, true); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("foreign file: %v", err)
	}
	mustWrite(t, man, strings.Replace(b, `"module": "firewall"`, `"module": "network"`, 1))
	if _, err := f.local.HostSnapshotRestore(ctx, res.Snapshot, true); err == nil {
		t.Error("unknown module")
	}
	mustWrite(t, filepath.Join(f.cfg.HostDir, "pending.json"), `{"id":"0123456789abcdef","module":"firewall","snapshot":"../../etc","deadline":"2026-10-30T10:15:00Z"}`)
	if _, err := f.local.HostPending(context.Background()); err == nil {
		t.Error("a forged record was read")
	}
	if o, err := f.local.ResumePending(context.Background()); err == nil || o != nil {
		t.Errorf("a forged record was acted on: %v %v", o, err)
	}
}

// Many readers and a timer at once (go test -race).
func TestHostFWConcurrent(t *testing.T) {
	f := newFWEnv(t, "firewall")
	c := hostWire(t, f.env)
	if _, err := c.HostFirewallApply(admin(), fwReq(fwSpec(), false)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 5 {
				_, _ = c.HostPending(context.Background())
				_, _ = c.HostFirewallRead(context.Background())
			}
		})
	}
	wg.Go(func() { f.timer.fire(t) })
	wg.Wait()
	if p, _ := c.HostPending(context.Background()); p.Pending != nil || p.Last.Outcome != api.HostPendingTimedOut {
		t.Errorf("%+v", p)
	}
}
