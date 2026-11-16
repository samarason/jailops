package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

// The rc.conf switch reaches the helper as -appliance-modules: the effective list is host-manage of priv.conf and
// the modules of rc.conf together, check-config says where each comes from, an unknown module stops the helper, and
// priv.conf cannot carry the switch itself.
func TestApplianceModulesJoinHostManage(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	useFakeSystem(t, map[string]string{"tank/jailops": filepath.Join(dir, "jo")})
	conf := filepath.Join(dir, "priv.conf")
	write := func(body string) {
		if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := "state-dir = " + filepath.Join(dir, "st") + "\nhost-dir = " + filepath.Join(dir, "host") + "\n"
	write(base)
	for _, c := range []struct {
		name  string
		file  string
		args  []string
		hosts string
		rc    string
	}{
		{"off", "", nil, "host manage:    none (the host is only read)", "appliance:      off"},
		{"all", "", []string{"-appliance-modules", "all"}, "host manage:    identity, firewall (snapshots in", "appliance:      on: rc.conf (jailops_appliance) adds identity, firewall to host-manage of priv.conf (none)"},
		{"union", "host-manage = identity\n", []string{"-appliance-modules", "firewall"}, "host manage:    identity, firewall", "adds firewall to host-manage of priv.conf (identity)"},
		{"both name it", "host-manage = firewall\n", []string{"-appliance-modules", "identity,firewall"}, "host manage:    firewall, identity", "adds identity, firewall"},
		{"rc list with spaces turned to commas", "", []string{"-appliance-modules", "identity,,firewall"}, "host manage:    identity, firewall", "appliance:      on"},
	} {
		write(base + c.file)
		args := append(append([]string{"-config", conf}, c.args...), "check-config")
		code, out, errs := runArgs(t, 0, args...)
		if code != 0 || !strings.Contains(out, c.hosts) || !strings.Contains(out, c.rc) {
			t.Errorf("%s: %d %q\n%s", c.name, code, errs, out)
		}
	}
	write(base)
	if code, _, errs := runArgs(t, 0, "-config", conf, "-appliance-modules", "network", "check-config"); code != 2 || !strings.Contains(errs, `"network" is not a module`) {
		t.Errorf("unknown module: %d %q", code, errs)
	}
	write(base + "appliance-modules = all\n")
	if code, _, errs := runArgs(t, 0, "-config", conf, "check-config"); code != 2 || !strings.Contains(errs, "set jailops_appliance in /etc/rc.conf") {
		t.Errorf("the switch in priv.conf: %d %q", code, errs)
	}
	// a module priv.conf names twice is still refused, whatever rc.conf adds
	write(base + "host-manage = identity\nhost-manage = identity\n")
	if code, _, errs := runArgs(t, 0, "-config", conf, "-appliance-modules", "all", "check-config"); code != 2 || !strings.Contains(errs, "listed twice") {
		t.Errorf("duplicate: %d %q", code, errs)
	}
}

func TestExpandAppliance(t *testing.T) {
	for in, want := range map[string]string{"all": "identity,firewall", "firewall": "firewall", "firewall,all": "firewall,identity", "": ""} {
		var l list
		_ = l.Set(in)
		got, err := expandAppliance(l)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
}

// appliance-init: nothing when the helper is set up; the pool of the root file system by default; never a pool
// that holds another JailOps dataset; every command it runs is logged.
func TestApplianceInit(t *testing.T) {
	setup := func(t *testing.T, r *recorder, pool string) (applianceInit, *[]string, string) {
		var notes []string
		root := t.TempDir()
		a := applianceInit{config: filepath.Join(root, "missing", "priv.conf"), pool: pool, run: r.run, stat: os.Stat,
			note: func(event string, kv ...any) { notes = append(notes, event+" "+fmt.Sprint(kv...)) },
			prepare: func(o *initOptions) {
				o.root = root
				o.lookupUser = func(string) (int, int, error) { return 1001, 1001, nil }
				o.lookupGrp = func(string) (int, int, error) { return 0, 1001, nil }
				o.chown = func(string, int, int) error { return nil }
			}}
		return a, &notes, root
	}
	t.Run("root pool", func(t *testing.T) {
		r := &recorder{exist: map[string]bool{}, flag: map[string]string{}, root: "zroot/ROOT/default"}
		a, notes, root := setup(t, r, "")
		var out bytes.Buffer
		if err := a.do(&out); err != nil {
			t.Fatal(err)
		}
		all := strings.Join(r.cmds, "\n")
		for _, want := range []string{"zfs list -H -o name /", "zfs get -H -r -s local -o name,value -t filesystem jailops:managed zroot",
			"zfs create -o mountpoint=/usr/local/jailops -o jailops:managed=on zroot/jailops"} {
			if !strings.Contains(all, want) {
				t.Errorf("missing %q in\n%s", want, all)
			}
		}
		logged := strings.Join(*notes, "\n")
		for _, c := range r.cmds {
			if !strings.Contains(logged, "run: "+c) {
				t.Errorf("not logged: %q\n%s", c, logged)
			}
		}
		if !strings.Contains(logged, "writing /usr/local/etc/jailops/priv.conf") || !strings.Contains(out.String(), "prints the setup token") {
			t.Errorf("%s\n%s", logged, out.String())
		}
		if b, err := os.ReadFile(filepath.Join(root, "usr/local/etc/jailops/priv.conf")); err != nil || !strings.Contains(string(b), "storage-root = zroot/jailops") {
			t.Errorf("%q %v", b, err)
		}
	})
	t.Run("set up already", func(t *testing.T) {
		r := &recorder{exist: map[string]bool{}, flag: map[string]string{}}
		a, _, root := setup(t, r, "tank")
		a.config = filepath.Join(root, "priv.conf")
		os.WriteFile(a.config, nil, 0o600)
		var out bytes.Buffer
		if err := a.do(&out); err != nil || len(r.cmds) != 0 || !strings.Contains(out.String(), "does nothing") {
			t.Errorf("%v %v %q", err, r.cmds, out.String())
		}
	})
	t.Run("another JailOps dataset", func(t *testing.T) {
		r := &recorder{exist: map[string]bool{}, flag: map[string]string{}, managed: "tank/old/jailops\ton\n"}
		a, _, _ := setup(t, r, "tank")
		var out bytes.Buffer
		err := a.do(&out)
		if err == nil || !strings.Contains(err.Error(), "already holds the JailOps dataset tank/old/jailops") {
			t.Fatalf("%v", err)
		}
		for _, c := range r.cmds {
			if strings.Contains(c, "create") || strings.HasPrefix(c, "pw") {
				t.Errorf("changed something: %q", c)
			}
		}
	})
	t.Run("its own dataset again", func(t *testing.T) {
		r := &recorder{exist: map[string]bool{"tank/jailops": true}, flag: map[string]string{"tank/jailops": "on\tlocal"},
			managed: "tank/jailops\ton\ntank/jailops/state\ton\n"}
		a, _, _ := setup(t, r, "tank")
		var out bytes.Buffer
		if err := a.do(&out); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a pool with a leading dash", func(t *testing.T) {
		r := &recorder{exist: map[string]bool{}, flag: map[string]string{}}
		a, _, _ := setup(t, r, "-n")
		if err := a.do(&bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not a pool name") || len(r.cmds) != 0 {
			t.Fatalf("%v %v", err, r.cmds)
		}
		o := initOptions{pool: "-dtank", mount: "/usr/local/jailops"}
		if err := o.validate(); err == nil {
			t.Error("init accepted a pool with a leading dash")
		}
	})
	t.Run("no zfs root", func(t *testing.T) {
		r := &recorder{exist: map[string]bool{}, flag: map[string]string{}, rootErr: true}
		a, _, _ := setup(t, r, "")
		if err := a.do(&bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "set jailops_pool") {
			t.Fatalf("%v", err)
		}
	})
	if code, _, _ := runArgs(t, 1000, "appliance-init"); code != 1 {
		t.Errorf("not root: %d", code)
	}
	if code, _, _ := runArgs(t, 0, "appliance-init", "extra"); code != 2 {
		t.Errorf("an argument: %d", code)
	}
}

// fakeDaemon answers the two requests setup-token makes on a unix socket.
func fakeDaemon(t *testing.T, sock string, status int, tok api.SetupToken) func() {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	reply := func(w http.ResponseWriter, code int, v any, e *api.Error) {
		raw, _ := json.Marshal(v)
		r := api.Response{Type: api.ResponseSync, StatusCode: code, Metadata: raw}
		if e != nil {
			r = api.Response{Type: api.ResponseError, StatusCode: code, Error: e}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(r)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 200, api.ServerInfo{APIVersion: api.Version, APIExtensions: []string{"setup"}, Role: api.RoleHost, Auth: "trusted"}, nil)
	})
	mux.HandleFunc("POST /api/v1/setup/token", func(w http.ResponseWriter, _ *http.Request) {
		if status != 200 {
			reply(w, status, nil, api.Errorf(api.CodeNotFound, "an administrator exists"))
			return
		}
		reply(w, 200, tok, nil)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go srv.Serve(ln)
	return func() { srv.Close() }
}

// setup-token asks the daemon on its socket, waits for a daemon that is starting, prints the token and the console
// addresses, logs them when asked, and exits 3 once an administrator exists.
func TestSetupTokenCommand(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "d.sock")
	exp := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	tok := api.SetupToken{Token: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST", ExpiresAt: exp,
		URLs: []string{"https://web1.example.com:39110/", "https://192.0.2.10:39110/"}}
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	var stop func()
	sleeps := 0
	// the socket appears while the command waits: the first sleep starts the daemon
	env := setupTokenEnv{socket: sock, wait: 30 * time.Second, now: clock, sleep: func(d time.Duration) {
		sleeps++
		now = now.Add(d)
		if stop == nil {
			stop = fakeDaemon(t, sock, 200, tok)
		}
	}}
	var logged []string
	env.log = func(s string) { logged = append(logged, s) }
	var out, errb bytes.Buffer
	if code := setupToken(context.Background(), env, &out, &errb); code != 0 {
		t.Fatalf("%d %q", code, errb.String())
	}
	defer stop()
	if sleeps == 0 {
		t.Error("did not wait for the socket")
	}
	for _, want := range []string{"Open the console:  https://web1.example.com:39110/", "                     https://192.0.2.10:39110/",
		"Setup token:       " + tok.Token, "Valid until 2026-11-03 10:00 UTC"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("lacks %q:\n%s", want, out.String())
		}
	}
	if len(logged) != 1 || !strings.Contains(logged[0], tok.Token) || !strings.Contains(logged[0], "https://192.0.2.10:39110/") || strings.Contains(logged[0], "\n") {
		t.Errorf("syslog: %q", logged)
	}
	// no daemon within the wait: an error, not a hang
	env2 := setupTokenEnv{socket: filepath.Join(dir, "none.sock"), wait: time.Second, now: clock, sleep: func(d time.Duration) { now = now.Add(d) }}
	if code := setupToken(context.Background(), env2, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Errorf("no daemon: %d", code)
	}
	// an administrator exists: exit 3
	sock3 := filepath.Join(dir, "done.sock")
	defer fakeDaemon(t, sock3, 404, tok)()
	errb.Reset()
	if code := setupToken(context.Background(), setupTokenEnv{socket: sock3, now: clock, sleep: func(time.Duration) {}}, &bytes.Buffer{}, &errb); code != 3 || !strings.Contains(errb.String(), "setup is complete") {
		t.Errorf("done: %d %q", code, errb.String())
	}
	if code, _, _ := runArgs(t, 1000, "setup-token"); code != 1 {
		t.Errorf("not root: %d", code)
	}
	if got := setupTokenText(api.SetupToken{Token: "T", ExpiresAt: exp, Hint: "set jailopsd_web=YES"}); !strings.Contains(got, "The web console is off: set jailopsd_web=YES") {
		t.Error(got)
	}
}

// The banner goes to root's terminal and to the system console, and everything in it comes from the daemon: an escape
// sequence, a bidirectional control or another control character never reaches them, a token of another shape is
// refused, and an address that is not https://HOST:PORT/ is left out.
func TestSetupTokenBannerIsCleaned(t *testing.T) {
	exp := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	good := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"
	text := setupTokenText(api.SetupToken{Token: good, ExpiresAt: exp, URLs: []string{
		"https://web1.example.com:39110/",
		"https://evil.example.com/\x1b]0;owned\x07",
		"http://web1.example.com:39110/",
		"https://web1.example.com:39110/‮gnp.exe",
		"javascript:alert(1)",
	}})
	if !strings.Contains(text, "Open the console:  https://web1.example.com:39110/\n") || !strings.Contains(text, "4 address(es) of the daemon were not shown") {
		t.Errorf("%q", text)
	}
	hint := setupTokenText(api.SetupToken{Token: good, ExpiresAt: exp, Hint: "set jailopsd_web=YES\x1b[2J\x1b]52;c;aGk=\x07\r\nfake line‮\x9b" + strings.Repeat("x", 300)})
	for _, bad := range []string{"\x1b", "\x07", "\r", "‮", "\x9b", "\nfake line"} {
		if strings.Contains(hint, bad) {
			t.Errorf("the banner holds %q: %q", bad, hint)
		}
	}
	if !strings.Contains(hint, "set jailopsd_web=YES�[2J") || strings.Contains(hint, strings.Repeat("x", 201)) {
		t.Errorf("%q", hint)
	}
	for _, tok := range []string{"", "abc", good + "A", strings.ToLower(good), good[:51] + "\x1b", good[:51] + "1"} {
		if strings.Contains(setupTokenText(api.SetupToken{Token: tok, ExpiresAt: exp}), "Setup token:       "+tok+"\n") && tok != "" {
			t.Errorf("token %q was shown", tok)
		}
	}
	// the command refuses a malformed token from the daemon and prints nothing of it
	dir := t.TempDir()
	sock := filepath.Join(dir, "d.sock")
	defer fakeDaemon(t, sock, 200, api.SetupToken{Token: "\x1b]0;owned\x07", ExpiresAt: exp})()
	var out, errb bytes.Buffer
	clock := func() time.Time { return exp }
	if code := setupToken(context.Background(), setupTokenEnv{socket: sock, now: clock, sleep: func(time.Duration) {}}, &out, &errb); code != 1 ||
		out.Len() != 0 || !strings.Contains(errb.String(), "malformed setup token") {
		t.Errorf("%d %q %q", code, out.String(), errb.String())
	}
}
