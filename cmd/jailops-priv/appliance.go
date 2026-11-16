package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// The appliance path (docs/appliance.md): one rc.conf switch, jailops_appliance="YES", turns host management on and
// makes the first start need no shell. The rc scripts pass what rc.conf says with -appliance-modules; it is read at
// start only and is never a key of priv.conf: rc.conf is root's file like priv.conf, so it grants nothing an attacker
// who can write it would not have anyway.

// applianceAll is the value of jailops_appliance_modules that means every module this version has.
const applianceAll = "all"

// expandAppliance turns the rc.conf list into module names: "all" is every module, an unknown name is an error.
func expandAppliance(list []string) ([]string, error) {
	var out []string
	for _, m := range list {
		if m == applianceAll {
			for _, a := range api.HostModules {
				if !slices.Contains(out, a) {
					out = append(out, a)
				}
			}
			continue
		}
		if !slices.Contains(api.HostModules, m) {
			return nil, fmt.Errorf("jailops_appliance_modules: %q is not a module (known: %s, or all)", m, strings.Join(api.HostModules, ", "))
		}
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out, nil
}

// unionModules is host-manage of priv.conf followed by the modules of rc.conf it does not list yet. The file's own
// list is kept as it is, so a module it names twice is still refused.
func unionModules(file, rc []string) []string {
	out := append([]string(nil), file...)
	for _, m := range rc {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// ---- appliance-init: the first start without a shell ----

// applianceInitMain is `jailops-priv appliance-init [-pool POOL]`, run by the rc script of jailops_priv when
// jailops_appliance is on: the one-time setup of init, unless the helper is set up already (its configuration file
// exists). Without -pool it takes the pool of the root file system. It never takes a pool that holds a JailOps
// dataset other than the one it would use. Every command it runs and every file it writes goes to syslog.
func applianceInitMain(args []string, stdout, stderr io.Writer, euid int) int {
	fs := flag.NewFlagSet("appliance-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", defaultConfig, "the helper's configuration file: when it exists, the helper is set up and nothing is done")
	pool := fs.String("pool", "", "the ZFS pool (default: the pool of the root file system)")
	dryRun := fs.Bool("dry-run", false, "say what would be done and do nothing")
	logTo := fs.String("log", "syslog", "where the commands are logged: syslog or stderr")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprint(stderr, synopsis)
		return 2
	}
	if euid != 0 && !*dryRun {
		fmt.Fprintln(stderr, "jailops-priv appliance-init: must run as root")
		return 1
	}
	note := func(event string, kv ...any) { fmt.Fprintln(stderr, event, fmt.Sprint(kv...)) }
	if *logTo == "syslog" {
		if w, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, "jailops-priv"); err == nil {
			defer w.Close()
			note = func(event string, kv ...any) { _ = w.Notice(event + " " + fmt.Sprint(kv...)) }
		} else {
			fmt.Fprintf(stderr, "jailops-priv: syslog unavailable (%v), logging to stderr\n", err)
		}
	}
	a := applianceInit{config: *config, pool: *pool, dryRun: *dryRun, run: defaultRun, note: note, stat: os.Stat}
	if err := a.do(stdout); err != nil {
		note("jailops-priv appliance-init: failed:", err.Error())
		fmt.Fprintf(stderr, "jailops-priv appliance-init: %v\n", err)
		return 1
	}
	return 0
}

type applianceInit struct {
	config string
	pool   string
	dryRun bool
	run    func(name string, args ...string) (string, error)
	note   func(event string, kv ...any)
	stat   func(string) (os.FileInfo, error)
	// prepare adjusts the init options (tests: a root prefix, user lookups).
	prepare func(*initOptions)
}

// rootPool is the pool of the root file system: the first component of the dataset mounted at /.
func rootPool(run func(string, ...string) (string, error)) (string, error) {
	out, err := run("zfs", "list", "-H", "-o", "name", "/")
	if err != nil {
		return "", fmt.Errorf("the root file system is not on ZFS (%s): set jailops_pool in /etc/rc.conf", strings.TrimSpace(out))
	}
	ds := strings.TrimSpace(out)
	pool, _, _ := strings.Cut(ds, "/")
	if pool == "" || strings.ContainsAny(pool, " \t\n@#") || strings.HasPrefix(pool, "-") {
		return "", fmt.Errorf("cannot read the pool of the root file system from %q: set jailops_pool in /etc/rc.conf", ds)
	}
	return pool, nil
}

func (a applianceInit) do(stdout io.Writer) error {
	if strings.HasPrefix(a.pool, "-") {
		return fmt.Errorf("-pool %q is not a pool name", a.pool)
	}
	if _, err := a.stat(a.config); err == nil {
		fmt.Fprintf(stdout, "jailops-priv: %s exists: the helper is set up, appliance-init does nothing\n", a.config)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	logged := func(name string, args ...string) (string, error) {
		a.note("jailops-priv appliance-init: run:", name+" "+strings.Join(args, " "))
		return a.run(name, args...)
	}
	pool := a.pool
	if pool == "" {
		p, err := rootPool(logged)
		if err != nil {
			return err
		}
		pool = p
	}
	o := &initOptions{pool: pool, mount: "/usr/local/jailops", user: "jailops", group: "jailops", etc: "/usr/local/etc/jailops",
		dbDir: "/var/db/jailops", dryRun: a.dryRun, run: logged, chown: os.Chown, appliance: true}
	if a.prepare != nil {
		a.prepare(o)
	}
	if err := o.validate(); err != nil {
		return err
	}
	// A pool that already holds a JailOps dataset other than the one init uses belongs to another setup: refuse it.
	out, err := logged("zfs", "get", "-H", "-r", "-s", "local", "-o", "name,value", "-t", "filesystem", "jailops:managed", pool)
	if err != nil {
		return fmt.Errorf("pool %s does not exist or is not imported (%s): set jailops_pool in /etc/rc.conf", pool, strings.TrimSpace(out))
	}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || f[1] != "on" {
			continue
		}
		if f[0] != o.dataset && !strings.HasPrefix(f[0], o.dataset+"/") {
			return fmt.Errorf("pool %s already holds the JailOps dataset %s, which is not %s: refusing to set up a second one; run jailops-priv init -pool %s -dataset %s by hand if it is yours",
				pool, f[0], o.dataset, pool, f[0])
		}
	}
	a.note("jailops-priv appliance-init: setting up", "pool="+pool, " dataset="+o.dataset)
	var buf bytes.Buffer
	err = o.do(&buf)
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for sc.Scan() {
		if ln := strings.TrimSpace(sc.Text()); ln != "" {
			a.note("jailops-priv appliance-init:", ln)
		}
	}
	_, _ = stdout.Write(buf.Bytes())
	return err
}

// ---- setup-token: the one-time token of the first administrator ----

// setupTokenMain is `jailops-priv setup-token`: root asks the daemon, over its unix socket, for a new setup token
// and prints it with the addresses of the console. It replaces the token before. The rc script of jailopsd runs it
// after the start when jailops_appliance is on and writes the result to the system console. Exit 3: an administrator
// exists, there is nothing to set up.
func setupTokenMain(args []string, stdout, stderr io.Writer, euid int) int {
	fs := flag.NewFlagSet("setup-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", sdk.DefaultSocket, "the daemon's unix socket")
	wait := fs.Duration("wait", 0, "how long to wait for the daemon's socket (the rc script waits for a daemon that is starting)")
	toSyslog := fs.Bool("syslog", false, "also log the token and the addresses to syslog, facility authpriv (on FreeBSD /var/log/auth.log, readable by root only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprint(stderr, synopsis)
		return 2
	}
	if euid != 0 {
		fmt.Fprintln(stderr, "jailops-priv setup-token: must run as root (root is the administrator of the daemon's socket)")
		return 1
	}
	var logw func(string)
	if *toSyslog {
		if w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_AUTHPRIV, "jailops-setup"); err == nil {
			defer w.Close()
			logw = func(s string) { _ = w.Info(s) }
		} else {
			fmt.Fprintf(stderr, "jailops-priv: syslog unavailable: %v\n", err)
		}
	}
	return setupToken(context.Background(), setupTokenEnv{socket: *socket, wait: *wait, now: time.Now, sleep: time.Sleep, log: logw}, stdout, stderr)
}

type setupTokenEnv struct {
	socket string
	wait   time.Duration
	now    func() time.Time
	sleep  func(time.Duration)
	log    func(string)
}

func setupToken(ctx context.Context, e setupTokenEnv, stdout, stderr io.Writer) int {
	deadline := e.now().Add(e.wait)
	var tok api.SetupToken
	for {
		var err error
		tok, err = askSetupToken(ctx, e.socket)
		if err == nil {
			break
		}
		if api.IsCode(err, api.CodeNotFound) {
			fmt.Fprintln(stderr, "jailops-priv: setup is complete: an administrator exists (sign in, or reset a password with jailops user set-password)")
			return 3
		}
		var ae *api.Error
		if errors.As(err, &ae) || !e.now().Before(deadline) {
			fmt.Fprintf(stderr, "jailops-priv setup-token: %v\n", err)
			return 1
		}
		// the daemon is still starting: its socket is not there yet
		e.sleep(250 * time.Millisecond)
	}
	if !setupTokenRE.MatchString(tok.Token) {
		// the daemon's answer reaches root's terminal and the system console: only a token of the expected shape does
		fmt.Fprintln(stderr, "jailops-priv setup-token: the daemon answered a malformed setup token")
		return 1
	}
	text := setupTokenText(tok)
	fmt.Fprint(stdout, text)
	if e.log != nil {
		e.log(strings.Join(strings.Fields(strings.ReplaceAll(text, "\n", " ; ")), " "))
	}
	return 0
}

func askSetupToken(ctx context.Context, socket string) (api.SetupToken, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, err := sdk.Connect(cctx, sdk.Local(sdk.WithSocket(socket)), sdk.WithRetries(0))
	if err != nil {
		return api.SetupToken{}, err
	}
	defer c.Close()
	return c.SetupToken(cctx)
}

// setupTokenRE is the shape of a setup token: 32 bytes in base32 without padding.
var setupTokenRE = regexp.MustCompile(`^[A-Z2-7]{52}$`)

// consoleURL reports an address of the console as the daemon makes them: https://HOST:PORT/, printable ASCII only.
func consoleURL(s string) bool {
	if len(s) > 300 || strings.ContainsFunc(s, func(r rune) bool { return r <= 0x20 || r >= 0x7f }) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// bannerText cleans a text of the daemon for the terminal and the system console: control characters (escape
// sequences included), bidirectional and zero-width characters become U+FFFD, and it is cut at 200 characters.
func bannerText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.ToValidUTF8(s, "\uFFFD") {
		if n == 200 {
			b.WriteString("...")
			break
		}
		if api.UnsafeRune(r) {
			r = utf8.RuneError
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// setupTokenText is what the console shows. Everything in it came from the daemon, which the helper does not trust:
// a token of another shape is never printed (setupToken), an address that is not https://HOST:PORT/ in printable
// ASCII is left out, and the hint is cleaned.
func setupTokenText(t api.SetupToken) string {
	var b strings.Builder
	b.WriteString("JailOps first-run setup\n")
	var urls []string
	for _, u := range t.URLs {
		if consoleURL(u) {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		fmt.Fprintf(&b, "  The web console is off: %s\n", bannerText(t.Hint))
	}
	for i, u := range urls {
		label := "  Open the console:  "
		if i > 0 {
			label = "                     "
		}
		b.WriteString(label + u + "\n")
	}
	if len(urls) < len(t.URLs) {
		fmt.Fprintf(&b, "  (%d address(es) of the daemon were not shown: not https://HOST:PORT/)\n", len(t.URLs)-len(urls))
	}
	if !setupTokenRE.MatchString(t.Token) {
		t.Token = "(malformed, not shown)"
	}
	fmt.Fprintf(&b, "  Setup token:       %s\n", t.Token)
	fmt.Fprintf(&b, "  Valid until %s, for one administrator. A new token: jailops-priv setup-token (as root)\n", t.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	return b.String()
}
