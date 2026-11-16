// Package dtest builds an in-process jailopsd on top of the fakes of
// internal/sys, for tests of the service, the server and the daemon. Nothing
// here is used by production code.
package dtest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"jailops.net/jailops/internal/hostbackup"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/lifecycle/fakes"
	"jailops.net/jailops/internal/lifecycle/fault"
	"jailops.net/jailops/internal/logfwd"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// Options tune an Env.
type Options struct {
	Hub bool
	// Dir is the working directory; default t.TempDir().
	Dir string
	// Hostname of the daemon.
	Hostname string
	// Mutate edits the configuration before start.
	Mutate func(*daemon.Config)
	// Listen opens the real listeners (unix socket, HTTPS on loopback).
	Listen bool
	// NoAdmin makes no global administrator token: a host before its first administrator (Admin is nil; the
	// tokens of other roles are made as usual).
	NoAdmin bool
	// Clients wraps or replaces the fake clients.
	Clients func(c *daemon.Clients)
	// Dir of an earlier Env to restart on top of the same state.
	Reuse *Env
	// LogOutput receives the log; default a buffer readable with Env.Log().
	LogOutput io.Writer
	// NoStart builds the Env without starting the daemon.
	NoStart bool
	// Registrar replaces the in-process storage registrar.
	Registrar service.StorageRegistrar
	// Now is the daemon clock (default time.Now), for expiry tests.
	Now func() time.Time
	// Execer runs commands in jails (default: a FakeExecer, available as Env.Exec).
	Execer service.JailExecer
	// Backups is the host-side backup backend (default none).
	Backups service.Backups
	// BackupTLS and BackupMounter configure the daemon's own host-side
	// backup service (a Mutate that sets Config.Backup enables it).
	BackupTLS     *tls.Config
	BackupMounter hostbackup.Mounter
	// ForceWeb and NoWeb are the -web and -no-web flags of the daemon: console on or off, whatever the configuration says.
	ForceWeb, NoWeb bool
	// HostManage is host-manage of the simulated helper's priv.conf (the daemon's own list is
	// Config.Host.Manage.Modules, set with Mutate).
	HostManage []string
	// LogForwardTune adjusts the log forwarder (poll interval, file check).
	LogForwardTune func(*logfwd.Env)
	// KeepAlive and ReadTimeout replace the keepalive interval of long requests and the listeners' read timeout.
	KeepAlive, ReadTimeout time.Duration
	// ApplianceModules is the -appliance-modules flag (jailops_appliance in rc.conf).
	ApplianceModules []string
	// ACMEHTTPClient, TLSRoots and ListenChallenge are the daemon's options of the same names.
	ACMEHTTPClient  *http.Client
	TLSRoots        *x509.CertPool
	ListenChallenge func(addr string) (net.Listener, error)
	ACMEAttempted   func(error)
}

// Env is a running daemon with its fakes.
type Env struct {
	T     *testing.T
	Opts  Options
	Dir   string
	Cfg   daemon.Config
	D     *daemon.Daemon
	ZFS   *zfs.Fake
	PF    *pfctl.Fake
	Net   *ifconfig.Fake
	Jails *jailos.Fake
	Run   *run.Fake
	Files *fakes.Files
	// WG is the WireGuard part of the helper.
	WG    *wireguard.Fake
	Fault *fault.Injector
	// FakeExec is the exec backend unless Options.Execer replaces it.
	FakeExec *service.FakeExecer
	proj     string // the project Seed made, for the clients Client returns
	netN     int    // networks MakeNetwork made
	HTTP     *httptest.Server
	Admin    *sdk.Client
	logbuf   *syncBuf
	tokens   map[api.Permission]string
	sysmu    sync.Mutex
	sysOver  map[string]string
	sysHist  map[string][]string // every value ever set, in order
	repoVer  string              // the package version the fake repository serves (SetRepoVersion)
	// Loaded lists the modules the daemon loaded with kldload.
	Loaded []string
	// DialFn answers the host-to-jail connections of an app installation's
	// health check; nil refuses them (there is no network in tests).
	DialFn func(ctx context.Context, network, address string) (net.Conn, error)
	// PkgInstallErr makes the fake pkg fail an app's package installation.
	PkgInstallErr error
	pkgDry        string // what `pkg -r ROOT upgrade -n` lists until an upgrade ran (SetPkgUpgrades)
	pkgUpgErr     error  // makes `pkg -r ROOT upgrade -y` fail (SetPkgUpgradeErr)
	pkgUpgraded   bool
	// Installed lists what the fake pkg installed into jail roots, "root name".
	Installed []string
	// Host is the simulated host of host management.
	Host *HostSim
	// Keys are the key operations of encrypted volumes.
	Keys *FakeKeys
}

// SetDial replaces DialFn while the daemon may be running.
func (e *Env) SetDial(fn func(ctx context.Context, network, address string) (net.Conn, error)) {
	e.sysmu.Lock()
	defer e.sysmu.Unlock()
	e.DialFn = fn
}

// SetPkgUpgrades sets the dry-run output of `pkg -r ROOT upgrade -n` (the packages a jail would get); once an upgrade
// ran, the fake answers that the packages are up to date.
func (e *Env) SetPkgUpgrades(dry string) {
	e.sysmu.Lock()
	defer e.sysmu.Unlock()
	e.pkgDry, e.pkgUpgraded = dry, false
}

// SetPkgUpgradeErr makes `pkg -r ROOT upgrade -y` fail with err (nil for success).
func (e *Env) SetPkgUpgradeErr(err error) {
	e.sysmu.Lock()
	defer e.sysmu.Unlock()
	e.pkgUpgErr = err
}

// SetPkgInstallErr sets PkgInstallErr while the daemon may be running.
func (e *Env) SetPkgInstallErr(err error) {
	e.sysmu.Lock()
	defer e.sysmu.Unlock()
	e.PkgInstallErr = err
}

func (e *Env) dial(ctx context.Context, network, address string) (net.Conn, error) {
	e.sysmu.Lock()
	fn := e.DialFn
	e.sysmu.Unlock()
	if fn == nil {
		return nil, fmt.Errorf("dial %s %s: no network in tests", network, address)
	}
	return fn(ctx, network, address)
}

// SetSysctl is what `sysctl name=value` does on the fake host.
func (e *Env) SetSysctl(name, value string) {
	e.sysmu.Lock()
	defer e.sysmu.Unlock()
	if e.sysOver == nil {
		e.sysOver = map[string]string{}
	}
	e.sysOver[name] = value
	if e.sysHist == nil {
		e.sysHist = map[string][]string{}
	}
	e.sysHist[name] = append(e.sysHist[name], value)
}

// SysctlHistory lists every value set for a sysctl on the fake host, oldest first. A test that must know a value was
// set at some point reads this: the reconcile loop runs beside the test and may already have given the value back.
func (e *Env) SysctlHistory(name string) []string {
	e.sysmu.Lock()
	defer e.sysmu.Unlock()
	return append([]string(nil), e.sysHist[name]...)
}

// SysctlValue reads a sysctl of the fake host.
func (e *Env) SysctlValue(name string) string { v, _ := e.sysctl(name); return v }

// SetRepoVersion sets the version of every package the fake repository
// serves (default 15.0p1): a build from a parent with the same version
// changes no package, a newer one upgrades them all.
func (e *Env) SetRepoVersion(v string) {
	e.sysmu.Lock()
	defer e.sysmu.Unlock()
	e.repoVer = v
}

func (e *Env) repoVersion() string {
	e.sysmu.Lock()
	defer e.sysmu.Unlock()
	if e.repoVer == "" {
		return "15.0p1"
	}
	return e.repoVer
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// Log returns everything the daemon logged.
func (e *Env) Log() string { return e.logbuf.String() }

// File returns a file of the fake host ("" when there is none).
func (e *Env) File(p string) string { b, _ := e.Files.Get(p); return string(b) }

// HasFile reports whether the fake host has the file.
func (e *Env) HasFile(p string) bool { _, ok := e.Files.Get(p); return ok }

// Events streams this daemon's events through c, from the newest event at the time of the call on: what the test does
// next is seen even when the stream connects later, so no sleep is needed. The channel closes when ctx ends.
func (e *Env) Events(ctx context.Context, c *sdk.Client, opts ...sdk.EventOption) <-chan api.Event {
	last := e.D.Service().Events().Last()
	opts = append(append([]sdk.EventOption(nil), opts...), sdk.FromID(strconv.FormatInt(last, 10)))
	ch := make(chan api.Event, 256)
	go func() {
		defer close(ch)
		for ev, err := range c.Events(ctx, opts...) {
			if err != nil {
				return
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
}

// hostFile reads a file of the simulated host: /etc/NAME is NAME in Host.Etc; nothing else exists.
func (e *Env) hostFile(p string) ([]byte, error) {
	name, ok := strings.CutPrefix(p, "/etc/")
	if !ok || strings.Contains(name, "/") {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(filepath.Join(e.Host.Etc, name))
}

// New builds and starts an Env. The daemon is stopped when the test ends.
func New(t testing.TB, o Options) *Env {
	tt, _ := t.(*testing.T)
	e := &Env{T: tt, Opts: o, tokens: map[api.Permission]string{}, logbuf: &syncBuf{}}
	e.Dir = o.Dir
	if e.Dir == "" {
		e.Dir = t.TempDir()
	}
	if o.Reuse != nil {
		r := o.Reuse
		e.ZFS, e.PF, e.Net, e.Jails, e.Run, e.Files, e.Fault, e.WG, e.Keys = r.ZFS, r.PF, r.Net, r.Jails, r.Run, r.Files, r.Fault, r.WG, r.Keys
		e.Dir = r.Dir
		e.proj = r.proj
	} else {
		e.Fault = &fault.Injector{}
		e.ZFS = zfs.NewFake("tank")
		e.PF = pfctl.NewFake()
		e.Net = ifconfig.NewFake(ifconfig.Options{})
		addHostIfaces(e.Net)
		e.Jails = jailos.NewFake()
		e.Files = fakes.NewFiles(e.Fault)
		e.Run = run.NewFake()
		e.WG = wireguard.NewFake()
		e.Keys = NewFakeKeys(e.ZFS)
		e.script()
	}
	if o.Reuse != nil && o.Reuse.Host != nil {
		e.Host = o.Reuse.Host
	} else {
		e.Host = newHostSim(t, filepath.Join(e.Dir, "host"), o.HostManage)
	}
	e.Cfg = daemon.Defaults()
	e.Cfg.Pool = "tank"
	e.Cfg.Dataset = "tank/jailops"
	e.Cfg.MountBase = "/jailops"
	e.Cfg.StateDir = filepath.Join(e.Dir, "state")
	e.Cfg.DataDir = filepath.Join(e.Dir, "data")
	e.Cfg.ConfDir = "/etc/jailops/jails"
	e.Cfg.WorkDir = filepath.Join(e.Dir, "work")
	// the host's own app definitions: none unless a test puts some there
	e.Cfg.Apps.LocalDir = filepath.Join(e.Dir, "apps-local")
	e.Cfg.Hub = o.Hub
	e.Cfg.Listen.Unix.Path = ""
	if o.Listen {
		e.Cfg.Listen.Unix.Path = filepath.Join(e.Dir, "jailops.sock")
		e.Cfg.Listen.HTTPS.Address = "127.0.0.1:0"
	}
	if o.Mutate != nil {
		o.Mutate(&e.Cfg)
	}
	if !o.NoStart {
		e.Start()
	}
	return e
}

// Start starts the daemon (again, after Stop).
func (e *Env) Start() {
	t := e.T
	t.Helper()
	cfg := e.Cfg
	var out io.Writer = e.logbuf
	if e.Opts.LogOutput != nil {
		out = io.MultiWriter(e.logbuf, e.Opts.LogOutput)
	}
	host := e.Opts.Hostname
	if host == "" {
		host = "testhost"
	}
	env := api.Environment{OS: "FreeBSD", Arch: "amd64", Pool: "tank", PF: true}
	d, err := daemon.Start(context.Background(), daemon.Options{
		Config: &cfg, Version: "test", ForceWeb: e.Opts.ForceWeb, NoWeb: e.Opts.NoWeb, LogOutput: out, Hostname: host, Env: &env, NoListen: !e.Opts.Listen, Registrar: e.Opts.Registrar, Now: e.Opts.Now, Backups: e.Opts.Backups, Execer: e.execer(), BackupTLS: e.Opts.BackupTLS, BackupMounter: e.Opts.BackupMounter, LogForwardTune: e.Opts.LogForwardTune, KeepAlive: e.Opts.KeepAlive, ReadTimeout: e.Opts.ReadTimeout,
		ApplianceModules: e.Opts.ApplianceModules, ACMEHTTPClient: e.Opts.ACMEHTTPClient, TLSRoots: e.Opts.TLSRoots, ListenChallenge: e.Opts.ListenChallenge, ACMEAttempted: e.Opts.ACMEAttempted,
		Clients: func(ctx context.Context, c *daemon.Config, dev bool) (*daemon.Clients, error) {
			cl := &daemon.Clients{ZFS: e.ZFS, Jails: e.Jails, PF: e.PF, Net: e.Net, Runner: e.Run, Files: e.Files, Logs: fileLogs{e.Files},
				Sysctl:  func(_ context.Context, name string) (string, error) { return e.sysctl(name) },
				Mount:   func(context.Context, string) error { return nil },
				Unmount: func(context.Context, string) error { return nil },
				Dial:    e.dial, HostSystem: e.Host.Local, WG: e.WG, Keys: e.Keys, HostFile: e.hostFile}
			if e.Opts.Clients != nil {
				e.Opts.Clients(cl)
			}
			return cl, nil
		},
	})
	if err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	e.D = d
	t.Cleanup(func() { e.Stop() })
	e.HTTP = httptest.NewServer(d.Handler())
	t.Cleanup(e.HTTP.Close)
	if !e.Opts.NoAdmin {
		e.Admin = e.Client(api.PermAdmin)
	}
}

// Stop shuts the daemon down.
func (e *Env) Stop() {
	if e.D == nil {
		return
	}
	if e.Admin != nil {
		_ = e.Admin.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = e.D.Shutdown(ctx)
	e.D = nil
	if e.HTTP != nil {
		e.HTTP.Close()
	}
}

// HostIfaces are the fake host's own interfaces, which networks name as their uplink: em0 and vtnet0 are on a
// segment whose IPv6 prefix 2001:db8:1:2::/64 proxy-mode networks take parts of; em1 has only IPv4.
var HostIfaces = []ifconfig.Iface{
	{Name: "em0", Flags: []string{"UP", "RUNNING"}, Inet: []netip.Prefix{netip.MustParsePrefix("203.0.113.2/24")},
		Inet6: []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::2/64")}},
	{Name: "em1", Flags: []string{"UP", "RUNNING"}, Inet: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}},
	{Name: "vtnet0", Flags: []string{"UP", "RUNNING"}, Inet: []netip.Prefix{netip.MustParsePrefix("198.51.100.15/24")},
		Inet6: []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::3/64")}},
}

func addHostIfaces(f *ifconfig.Fake) {
	for _, i := range HostIfaces {
		f.AddHost(i)
	}
}

// Sysctls are the values the fake host reports.
var Sysctls = map[string]string{
	"net.inet6.ip6.forwarding": "1", "net.inet.ip.forwarding": "1", "kern.racct.enable": "1", "net.inet6.icmp6.nd6_onlink_ns_rfc4861": "1",
	"kern.elf64.fallback_brand": "-1", "kern.osrelease": "15.1-RELEASE-p1", "kern.boottime": "{ sec = 1700000000, usec = 0 }",
}

func (e *Env) sysctl(name string) (string, error) {
	e.sysmu.Lock()
	v, ok := e.sysOver[name]
	e.sysmu.Unlock()
	if ok {
		return v, nil
	}
	if v, ok := Sysctls[name]; ok {
		return v, nil
	}
	return "", fmt.Errorf("unknown oid %s", name)
}

// script teaches the command fake the few commands the lifecycle and the
// image builder run. They write into the in-memory files like the real tools
// write into the jail roots.
func (e *Env) script() {
	// dummynet: the module is there and the pipes of the bandwidth limits can be set
	e.Run.Add(run.Rule{Name: "kldstat", Args: []string{"-q", "-n", "dummynet"}})
	e.Run.Add(run.Rule{Name: "kldstat", Args: []string{"-n", "dummynet"}})
	e.Run.Add(run.Rule{Name: "kldload", Args: []string{"dummynet"}})
	e.Run.Add(run.Rule{Name: "dnctl", Args: []string{run.RestArgs}})
	e.Run.Add(run.Rule{Name: "pkg", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		argv := append([]string{"pkg"}, c.Args...)
		if len(argv) > 2 && argv[1] == "config" && argv[2] == "abi" {
			return run.Result{Stdout: []byte("FreeBSD:15:amd64\n")}, nil
		}
		// pkg -r <root> [-o k=v]... <sub> [args]: the image builder passes -o
		// options and installs a whole base, the app installer names packages.
		root, i, options := "", 1, false
		for i < len(argv) && (argv[i] == "-r" || argv[i] == "-j" || argv[i] == "-o") {
			switch argv[i] {
			case "-r":
				root = argv[i+1]
			case "-j": // inside a running jail: its root, as the storage of the fake lays it out
				if proj, name, ok := strings.Cut(argv[i+1], "_"); ok {
					root = "/jailops/projects/" + proj + "/jails/" + name + "/root"
				}
			default:
				// the cache directory is no sign of an image build: installs into a jail root pass it too
				if !(argv[i] == "-o" && strings.HasPrefix(argv[i+1], "PKG_CACHEDIR=")) {
					options = true
				}
			}
			i += 2
		}
		if i >= len(argv) || root == "" {
			return run.Result{ExitCode: 1, Stderr: []byte("pkg: usage\n")}, nil
		}
		sub, rest := argv[i], argv[i+1:]
		switch sub {
		case "install", "upgrade":
			if sub == "upgrade" && !options {
				e.sysmu.Lock()
				defer e.sysmu.Unlock()
				for _, a := range rest {
					if a == "-n" { // the dry run of a package update
						if e.pkgUpgraded || e.pkgDry == "" {
							return run.Result{Stdout: []byte("Your packages are up to date.\n")}, nil
						}
						return run.Result{Stdout: []byte(e.pkgDry)}, nil
					}
				}
				if e.pkgUpgErr != nil {
					return run.Result{ExitCode: 1, Stderr: []byte("pkg: repository unreachable\n")}, e.pkgUpgErr
				}
				e.pkgUpgraded = true
				return run.Result{}, nil
			}
			if options {
				e.Files.Put(root+"/bin/sh", []byte("x"))
				e.Files.Put(root+"/libexec/ld-elf.so.1", []byte("x"))
				v := e.repoVersion()
				e.Files.Put(root+"/.pkgs", []byte("FreeBSD-runtime "+v+"\nFreeBSD-utilities "+v+"\n"))
				return run.Result{}, nil
			}
			e.sysmu.Lock()
			failErr := e.PkgInstallErr
			e.sysmu.Unlock()
			if failErr != nil {
				return run.Result{ExitCode: 1, Stderr: []byte(failErr.Error() + "\n")}, failErr
			}
			for j := 0; j < len(rest); j++ {
				if rest[j] == "-r" { // the repository name follows
					j++
					continue
				}
				if !strings.HasPrefix(rest[j], "-") {
					e.sysmu.Lock()
					e.Installed = append(e.Installed, root+" "+rest[j])
					e.sysmu.Unlock()
					e.Files.Put(root+"/.app-pkgs/"+rest[j], []byte(rest[j]+" "+e.repoVersion()+"\n"))
					if rest[j] == api.BashPackage { // the jail's shell (docs/shell.md)
						e.Files.Put(root+api.BashPath, []byte("x"))
					}
				}
			}
		case "query":
			if len(rest) == 1 && rest[0] == "%n" { // the installed packages: the base, and what the upgrade dry run names
				e.sysmu.Lock()
				dry := e.pkgDry
				e.sysmu.Unlock()
				var sb strings.Builder
				sb.WriteString("FreeBSD-runtime\nFreeBSD-utilities\n")
				for _, l := range strings.Split(dry, "\n") {
					if t := strings.TrimSpace(l); strings.Contains(t, " -> ") {
						if name, _, ok := strings.Cut(t, ":"); ok {
							sb.WriteString(name + "\n")
						}
					}
				}
				return run.Result{Stdout: []byte(sb.String())}, nil
			}
			if len(rest) == 2 && rest[0] == "%v" { // the version of one package
				if b, ok := e.Files.Get(root + "/.app-pkgs/" + rest[1]); ok {
					_, v, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
					return run.Result{Stdout: []byte(v + "\n")}, nil
				}
				return run.Result{ExitCode: 1, Stderr: []byte("pkg: " + rest[1] + " is not installed\n")}, fmt.Errorf("pkg query: %s is not installed", rest[1])
			}
			if len(rest) == 3 && rest[0] == "-e" && rest[1] == "%a = 0" { // the packages an app installed, for a draft
				var sb strings.Builder
				e.sysmu.Lock()
				installed := append([]string(nil), e.Installed...)
				e.sysmu.Unlock()
				for _, in := range installed {
					if r, name, _ := strings.Cut(in, " "); r == root {
						b, _ := e.Files.Get(root + "/.app-pkgs/" + name)
						_, v, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
						sb.WriteString(name + " " + v + " FreeBSD https://example.com/" + name + "\n")
					}
				}
				return run.Result{Stdout: []byte(sb.String())}, nil
			}
			b, _ := e.Files.ReadFile(context.Background(), root+"/.pkgs")
			var sb strings.Builder
			for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				sb.WriteString(l + "\n")
			}
			return run.Result{Stdout: []byte(sb.String())}, nil
		}
		return run.Result{}, nil
	}})
	e.Run.Add(run.Rule{Name: "sysctl", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		if k, v, ok := strings.Cut(c.Args[0], "="); ok {
			e.SetSysctl(k, v)
		}
		return run.Result{}, nil
	}})
	e.Run.Add(run.Rule{Name: "kldload", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		e.sysmu.Lock()
		e.Loaded = append(e.Loaded, c.Args[0])
		e.sysmu.Unlock()
		return run.Result{}, nil
	}})
	// fetch writes the Alpine tarball (or its digest, or the index) where asked.
	e.Run.Add(run.Rule{Name: "fetch", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		dst, url := c.Args[1], c.Args[2]
		switch {
		case strings.HasSuffix(url, ".sha256"):
			e.Files.Put(dst, []byte(AlpineTarballDigest+"  alpine.tar.gz\n"))
		default:
			e.Files.Put(dst, []byte(AlpineTarball))
		}
		return run.Result{}, nil
	}})
	e.Run.Add(run.Rule{Name: "tar", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		if len(c.Args) < 3 || c.Args[0] != "-C" || c.Args[2] != "-xpzf" { // tar -C <root> -cf <file> ./etc: the /etc merge
			return run.Result{}, nil
		}
		root := c.Args[1]
		e.Files.Put(root+"/bin/busybox", []byte("x"))
		e.Files.Put(root+"/lib/apk/db/installed", []byte("P:busybox\nV:1.37\n\nP:musl\nV:1.2\n\n"))
		return run.Result{}, nil
	}})
	e.Files.Put("/etc/resolv.conf", []byte("nameserver 192.0.2.53\n"))
	for _, n := range []string{"etcupdate", "uname", "pfctl", "ifconfig", "kldstat", "cp", "jexec", "mount", "umount", "jail", "devfs", "pwd_mkdb", "chmod"} {
		e.Run.Add(run.Rule{Name: n, Args: []string{run.RestArgs}})
	}
}

// Token returns a token of the given role, creating it on first use.
func (e *Env) Token(p api.Permission) string {
	if t, ok := e.tokens[p]; ok {
		return t
	}
	ctx := service.WithActor(context.Background(), service.Actor{Name: "test", Kind: "system", Perm: api.PermAdmin, Global: true})
	tok, err := e.D.Service().CreateToken(ctx, api.Token{Metadata: api.ObjectMeta{Name: "t-" + string(p) + "-" + randSuffix()}, Spec: api.TokenSpec{Permission: p, Global: true}})
	if err != nil {
		e.T.Fatalf("token: %v", err)
	}
	e.tokens[p] = tok.Secret
	return tok.Secret
}

// Client returns an SDK client authenticated with a token of the given role.
func (e *Env) Client(p api.Permission) *sdk.Client {
	t := e.T
	t.Helper()
	opts := []sdk.Option{sdk.WithToken(e.Token(p)), sdk.WithRetries(0)}
	if e.proj != "" { // like Admin, bound to the project Seed made
		opts = append(opts, sdk.WithProject(e.proj))
	}
	c, err := sdk.Connect(context.Background(), sdk.Remote(e.HTTP.URL, opts...))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// Global returns an admin client that is not bound to any project (the host-wide view: audit, every project's
// operations and events).
func (e *Env) Global() *sdk.Client { return e.clientWith(e.Token(api.PermAdmin), "") }

// Anonymous returns a client without credentials.
func (e *Env) Anonymous() *sdk.Client {
	c, err := sdk.Connect(context.Background(), sdk.Remote(e.HTTP.URL, sdk.WithRetries(0)))
	if err != nil {
		e.T.Fatalf("connect: %v", err)
	}
	e.T.Cleanup(func() { _ = c.Close() })
	return c
}

// SeedProject is the project Seed creates. There is no default project: Seed makes this one and binds e.Admin to it,
// the way `jailops project switch` does for a person; tests that need other projects create them explicitly.
const SeedProject = "alpha"

// Seed creates the image "fb" with one generation, the network "lan" and the project SeedProject, which is granted
// "lan" and the storage "default", and binds e.Admin to that project.
func (e *Env) Seed() {
	t := e.T
	t.Helper()
	ctx := context.Background()
	if _, err := e.Admin.Images().Create(ctx, api.Image{Metadata: api.ObjectMeta{Name: "fb"}, Spec: api.ImageSpec{
		OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}}); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	op, err := e.Admin.Images().Build(ctx, "fb", api.ImageBuild{})
	if err != nil {
		t.Fatalf("seed build: %v", err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatalf("seed build: %v", err)
	}
	if _, err := e.Admin.Networks().Create(ctx, LAN()); err != nil {
		t.Fatalf("seed network: %v", err)
	}
	e.MakeProject(SeedProject)
	e.Admin = e.Admin.Project(SeedProject)
	e.proj = SeedProject
}

// MakeProject creates a project that is granted the network "lan" and the storage "default" (so it is for the first
// project of a test; a second project needs its own network: networks are not shared).
func (e *Env) MakeProject(name string) {
	e.T.Helper()
	if _, err := e.Admin.Projects().Create(context.Background(), api.Project{Metadata: api.ObjectMeta{Name: name}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "lan"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		e.T.Fatalf("project %s: %v", name, err)
	}
}

// AlpineTarball is the payload the fake mirror serves; its digest is the
// published one.
const AlpineTarball = "alpine-minirootfs"

// AlpineTarballDigest is sha256(AlpineTarball).
var AlpineTarballDigest = func() string { h := sha256.Sum256([]byte(AlpineTarball)); return hex.EncodeToString(h[:]) }()

// SeedLinux adds and builds an Alpine image "alp" (3.22.1) next to the
// FreeBSD one.
func (e *Env) SeedLinux() {
	t := e.T
	t.Helper()
	ctx := context.Background()
	if _, err := e.Admin.Images().Create(ctx, api.Image{Metadata: api.ObjectMeta{Name: "alp"}, Spec: api.ImageSpec{
		OS: api.OSLinux, Release: "3.22.1", Arch: "amd64", Source: api.ImageSource{Type: "minirootfs"}, Aliases: []string{"stable"}}}); err != nil {
		t.Fatalf("seed linux image: %v", err)
	}
	op, err := e.Admin.Images().Build(ctx, "alp", api.ImageBuild{})
	if err != nil {
		t.Fatalf("seed linux build: %v", err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatalf("seed linux build: %v", err)
	}
}

// AlpineJail is a Linux jail spec on the image SeedLinux builds.
func AlpineJail(name string) api.Jail {
	return api.Jail{Metadata: api.ObjectMeta{Name: name}, Spec: api.JailSpec{
		Image: "alp@stable", Storage: "default", Network: []api.NetworkAttach{{Network: "lan", IPv4: "auto"}}}}
}

// LAN is the network the tests use.
func LAN() api.Network {
	return api.Network{Metadata: api.ObjectMeta{Name: "lan"}, Spec: api.NetworkSpec{
		IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.50"}}}
}

// MakeNetwork creates a network of its own, "lan-<name>", and returns its name. Networks are not shared between
// projects, so every project after the first one needs one; each gets its own /24.
func (e *Env) MakeNetwork(name string) string {
	e.T.Helper()
	e.netN++
	n := LAN()
	n.Metadata.Name = "lan-" + name
	n.Spec.IPv4 = &api.IPv4Net{Subnet: fmt.Sprintf("10.%d.0.0/24", 30+e.netN), Gateway: fmt.Sprintf("10.%d.0.1", 30+e.netN),
		Range: fmt.Sprintf("10.%d.0.10-10.%d.0.50", 30+e.netN, 30+e.netN)}
	if _, err := e.Admin.Networks().Create(context.Background(), n); err != nil {
		e.T.Fatalf("network %s: %v", n.Metadata.Name, err)
	}
	return n.Metadata.Name
}

// WebJailOn is WebJail on another network.
func WebJailOn(name, network string) api.Jail {
	j := WebJail(name)
	j.Spec.Network = []api.NetworkAttach{{Network: network, IPv4: "auto"}}
	return j
}

// WebJail is a jail spec on the seeded image and network.
func WebJail(name string) api.Jail {
	return api.Jail{Metadata: api.ObjectMeta{Name: name}, Spec: api.JailSpec{
		Image: "fb@stable", Storage: "default", Update: api.UpdatePolicy{Strategy: api.UpdateRebase, Healthcheck: "/bin/true"},
		Network: []api.NetworkAttach{{Network: "lan", IPv4: "auto"}}}}
}

var _ = os.Getpid

// Raw sends one request with a bearer token and returns status and body.
func (e *Env) Raw(method, path, token, body string) (int, string) {
	return e.RawHdr(method, path, token, body, nil)
}

// RawHdr is Raw with extra headers.
func (e *Env) RawHdr(method, path, token, body string, hdr map[string]string) (int, string) {
	req, err := http.NewRequest(method, e.HTTP.URL+path, strings.NewReader(body))
	if err != nil {
		e.T.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b)
}

var suffixMu sync.Mutex
var suffixN int

func randSuffix() string {
	suffixMu.Lock()
	defer suffixMu.Unlock()
	suffixN++
	return fmt.Sprintf("%d-%d", time.Now().UnixNano()%100000, suffixN)
}

// IdentityToken returns a token of the given role scoped to projects (an
// empty list makes the token global when global is true; a token with
// neither is refused by the service, so scopeless identities are made
// directly in the store by ScopelessToken).
func (e *Env) IdentityToken(p api.Permission, global bool, projects ...string) string {
	ctx := service.WithActor(context.Background(), service.Actor{Name: "test", Kind: "system", Perm: api.PermAdmin, Global: true})
	tok, err := e.D.Service().CreateToken(ctx, api.Token{Metadata: api.ObjectMeta{Name: "i-" + string(p) + "-" + randSuffix()},
		Spec: api.TokenSpec{Permission: p, Global: global, Projects: projects}})
	if err != nil {
		e.T.Fatalf("token: %v", err)
	}
	return tok.Secret
}

// Scoped returns a client whose token has the role and is restricted to the
// projects; it works in the first of them.
func (e *Env) Scoped(p api.Permission, projects ...string) *sdk.Client {
	return e.clientWith(e.IdentityToken(p, false, projects...), projects[0])
}

func (e *Env) clientWith(token, project string) *sdk.Client {
	opts := []sdk.Option{sdk.WithToken(token), sdk.WithRetries(0)}
	if project != "" {
		opts = append(opts, sdk.WithProject(project))
	}
	c, err := sdk.Connect(context.Background(), sdk.Remote(e.HTTP.URL, opts...))
	if err != nil {
		e.T.Fatalf("connect: %v", err)
	}
	e.T.Cleanup(func() { _ = c.Close() })
	return c
}

// ScopelessToken stores a token that has neither projects nor global, which
// the API refuses to create: a stored identity like that must be able to do
// nothing.
func (e *Env) ScopelessToken(p api.Permission) string {
	secret, hash, err := auth.GenerateToken()
	if err != nil {
		e.T.Fatal(err)
	}
	err = e.D.Service().DB().Tokens.Create(context.Background(), store.Token{ID: "scopeless-" + randSuffix(), Name: "scopeless-" + randSuffix(),
		Hash: hash, Permission: p})
	if err != nil {
		e.T.Fatal(err)
	}
	return secret
}

func (e *Env) execer() service.JailExecer {
	if e.Opts.Execer != nil {
		return e.Opts.Execer
	}
	if e.FakeExec == nil {
		e.FakeExec = &service.FakeExecer{}
	}
	return e.FakeExec
}
