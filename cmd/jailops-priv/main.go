// Command jailops-priv is the privileged helper of JailOps. It runs as root,
// listens on a unix socket and performs a fixed list of typed operations for
// jailopsd (see internal/priv). It also implements the hook subcommand that
// jail.conf's exec.* lines call:
//
//	jailops-priv [flags]                     serve
//	jailops-priv [flags] hook <phase> <jail> run one jail hook and exit
//	jailops-priv [flags] check-config        validate the configuration, print the effective roots and allow-lists
//	jailops-priv [flags] revert-pending      put back the snapshot of an unconfirmed host change (rc.d, at boot)
//	jailops-priv init -pool POOL [-dry-run]  one-time setup of a host (init.go)
//	jailops-priv appliance-init [-pool POOL] the same at the first start of an appliance, unless set up (appliance.go)
//	jailops-priv setup-token                 a new one-time token for the first administrator (appliance.go)
//	jailops-priv version | --version
//
// SIGHUP rereads the storage file and verifies every storage root again.
package main

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"jailops.net/jailops/internal/priv"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

const defaultConfig = "/usr/local/etc/jailops/priv.conf"

const synopsis = "usage: jailops-priv [flags] | version | check-config | init -pool POOL [-dry-run] | hook PHASE JAIL | revert-pending | appliance-init [-pool POOL] | setup-token\n"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Geteuid()))
}

// list is a repeatable, comma separated flag.

// prefixList is a list of networks (wireguard-routes), each without host bits.
type prefixList []netip.Prefix

func (l *prefixList) String() string { return fmt.Sprint(len(*l), " network(s)") }
func (l *prefixList) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() || p.Addr().Zone() != "" {
			return fmt.Errorf("%q is not a network without host bits", s)
		}
		*l = append(*l, p)
	}
	return nil
}

type list []string

func (l *list) String() string { return strings.Join(*l, ",") }
func (l *list) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

type options struct {
	config      string
	socket      string
	group       string
	mode        string
	pidfile     string
	logTo       string
	dev         bool
	daemon      bool
	rootDS      string
	storage     list
	storageFile string
	poolRoot    bool
	mountBase   string
	confDir     string
	stateDir    string
	workDir     string
	helperPath  string
	wgDir       string
	pkgKeysDir  string
	keyringDir  string
	unboundConf string
	dnsSuffix   string
	allowUser   list
	allowGroup  list
	sysctl      list
	fetchHost   list
	mirror      list
	hostManage  list
	hostDir     string
	allowNoPF   bool
	// appliance is what rc.conf turns on (jailops_appliance, passed by the rc script); never read from priv.conf.
	appliance list

	adminRawParam list
	adminAllow    list
	adminDevfs    list
	adminMounts   list
	adminZFSProp  list
	adminRoutes   bool
	wgRoutes      prefixList
	adminRawPF    bool
	adminZFSDeleg bool
	adminResume   bool
}

func newFlags(o *options, errw io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("jailops-priv", flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "%s\nWithout a command the helper serves on its socket. PHASE is prestart, poststart, prestop or poststop.\n\nflags (also keys of the configuration file):\n", synopsis)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.config, "config", defaultConfig, "configuration file (key = value lines named like these flags)")
	fs.StringVar(&o.socket, "socket", priv.DefaultSocket, "unix socket path")
	fs.StringVar(&o.group, "group", "jailops", "group that owns the socket (mode 0660)")
	fs.StringVar(&o.mode, "mode", "0660", "socket mode")
	fs.StringVar(&o.pidfile, "pidfile", "", "write the process id here")
	fs.StringVar(&o.logTo, "log", "", "audit log destination: stderr or syslog (default stderr; syslog with -daemon)")
	fs.BoolVar(&o.dev, "dev", false, "development: do not require root, allow the invoking user")
	fs.BoolVar(&o.daemon, "daemon", false, "detach from the terminal (rc.d may use daemon(8) with the foreground default instead)")
	fs.StringVar(&o.rootDS, "root-dataset", "", "deprecated: same as storage-root")
	fs.Var(&o.storage, "storage-root", "storage root dataset fixed in this file, for example tank/jailops (repeatable); more are registered at run time")
	fs.StringVar(&o.storageFile, "storage-file", priv.DefaultStorageFile, "file that persists the storage roots registered at run time (root-owned, mode 0600)")
	fs.BoolVar(&o.poolRoot, "allow-pool-root", false, "allow a pool's top dataset as a storage root")
	fs.StringVar(&o.mountBase, "mount-base", "", "optional: default state-dir is <mount-base>/state; paths are checked against the storage roots' mountpoints")
	fs.StringVar(&o.confDir, "conf-dir", priv.DefaultConfDir, "directory of rendered jail.conf files")
	fs.StringVar(&o.workDir, "work-dir", "", "daemon scratch directory for image builds (optional)")
	fs.StringVar(&o.stateDir, "state-dir", "", "state directory (default <mount-base>/state)")
	fs.StringVar(&o.helperPath, "helper-path", priv.DefaultHelperPath, "path jail.conf hooks call")
	fs.StringVar(&o.wgDir, "wireguard-dir", priv.DefaultWireGuardDir, "directory of the WireGuard keys (root only, mode 0700; outside the daemon's directories)")
	fs.StringVar(&o.pkgKeysDir, "pkg-keys-dir", priv.DefaultPkgKeysDir, "directory of the key directories (fingerprints) a package repository of an image build may use besides /usr/share/keys (root only, not writable by others; outside the daemon's directories)")
	fs.StringVar(&o.keyringDir, "keyring-dir", priv.DefaultKeyringDir, "directory of the keyrings debootstrap may check a release with (root only, not writable by others; outside the daemon's directories)")
	fs.StringVar(&o.dnsSuffix, "dns-suffix", priv.DefaultDNSSuffix, "zone under which the names of the jails live: NAME.PROJECT.<suffix>; DNS labels, not local; a suffix of your own (corp.example) is the clean choice (docs/dns.md)")
	fs.StringVar(&o.unboundConf, "unbound-conf", priv.DefaultUnboundConf, "file the helper writes the names of the running jails into for the host's resolver (name.project.internal; docs/dns.md); the default is the conf.d of the base system's local-unbound, which is used only when it is set up; empty: off")
	fs.Var(&o.allowUser, "allow-user", "user allowed to connect (jailopsd's user)")
	fs.Var(&o.allowGroup, "allow-group", "group allowed to connect")
	fs.Var(&o.sysctl, "sysctl", "extra sysctl name readable through the helper")
	fs.Var(&o.fetchHost, "fetch-host", "host fetch, package repositories and debootstrap mirrors may use over https (http://<host> allows plain http for a package repository on that host); default dl-cdn.alpinelinux.org, pkg.freebsd.org, pkg.jailops.net, deb.debian.org, archive.ubuntu.com, ports.ubuntu.com")
	fs.Var(&o.mirror, "image-mirror", "directory fs.read_file may read (a local mirror of image archives)")
	fs.Var(&o.hostManage, "host-manage", "host management module the helper may change (identity, firewall); empty: the host is only read (docs/appliance.md)")
	fs.BoolVar(&o.allowNoPF, "allow-start-without-pf", false, "start a jail that has a network link while pf is disabled (by default the start is refused: the jail would run without the firewall of its anchor)")
	fs.StringVar(&o.hostDir, "host-dir", priv.DefaultHostDir, "root-owned directory of the host snapshots and the applied record")
	fs.Var(&o.appliance, applianceFlag, "modules rc.conf turns on (jailops_appliance; the rc script passes it): added to host-manage; \"all\" is every module. Not a key of the configuration file")
	fs.Var(&o.adminRawParam, "admin-raw-param", "jail.conf parameter an admin may set")
	fs.Var(&o.adminAllow, "admin-allow-flag", "allow.* flag an admin may set (without prefix)")
	fs.Var(&o.adminDevfs, "admin-devfs-ruleset", "devfs ruleset number an admin may use")
	fs.Var(&o.adminMounts, "admin-host-mount", "host directory an admin may mount into a jail")
	fs.Var(&o.adminZFSProp, "admin-zfs-prop", "native zfs property an admin may set")
	fs.BoolVar(&o.adminRoutes, "admin-routes", false, "admin may add routes through a gateway")
	fs.Var(&o.wgRoutes, "wireguard-routes", "network a WireGuard tunnel may route into itself although it is wider than a /8 (/16 for IPv6) or covers the host's addresses, gateway or resolvers (repeatable)")
	fs.BoolVar(&o.adminRawPF, "admin-raw-pf", false, "admin may load raw pf rulesets")
	fs.BoolVar(&o.adminZFSDeleg, "admin-zfs-delegation", false, "admin may hand a jail a dataset of its own (zfs_delegation)")
	fs.BoolVar(&o.adminResume, "admin-resume-send", false, "admin may resume a zfs send from a token")
	return fs
}

// loadConfigFile applies "key = value" lines to the flag set.
func loadConfigFile(fs *flag.FlagSet, path string, required bool) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"`)
		if !ok || k == "" || k == "config" {
			return fmt.Errorf("%s:%d: expected key = value", path, n)
		}
		if fs.Lookup(k) == nil {
			return fmt.Errorf("%s:%d: unknown key %q", path, n, k)
		}
		if k == applianceFlag {
			return fmt.Errorf("%s:%d: %s is not a key of this file: set jailops_appliance in /etc/rc.conf, or list the modules with host-manage", path, n, k)
		}
		if err := fs.Set(k, v); err != nil {
			return fmt.Errorf("%s:%d: %w", path, n, err)
		}
	}
	return sc.Err()
}

func (o *options) privConfig() priv.Config {
	c := priv.Config{
		StorageRoots: append([]string(nil), o.storage...), StorageFile: o.storageFile, AllowPoolRoot: o.poolRoot,
		MountBase: o.mountBase,
		ConfDir:   o.confDir, StateDir: o.stateDir, WorkDir: o.workDir, HelperPath: o.helperPath, WireGuardDir: o.wgDir, PkgKeysDir: o.pkgKeysDir, UnboundConf: o.unboundConf, DNSSuffix: o.dnsSuffix, KeyringDir: o.keyringDir,
		WireGuardRoutes: o.wgRoutes,
		Sysctls:         o.sysctl, FetchHosts: o.fetchHost, ImageMirrors: o.mirror,
		HostManage: unionModules(o.hostManage, o.applianceModules()), HostDir: o.hostDir, AllowStartWithoutPF: o.allowNoPF,
		Admin: priv.AdminPolicy{
			RawJailParams: o.adminRawParam, AllowFlags: o.adminAllow, HostMountRoots: o.adminMounts,
			ZFSProps: o.adminZFSProp, Routes: o.adminRoutes, RawPF: o.adminRawPF, ResumeSend: o.adminResume, ZFSDelegation: o.adminZFSDeleg,
		},
	}
	for _, d := range o.adminDevfs {
		if n, err := strconv.Atoi(d); err == nil {
			c.Admin.DevfsRulesets = append(c.Admin.DevfsRulesets, n)
		}
	}
	if o.rootDS != "" {
		c.StorageRoots = append(c.StorageRoots, o.rootDS)
	}
	return c
}

// applianceFlag is the flag the rc script passes from jailops_appliance_modules.
const applianceFlag = "appliance-modules"

// applianceModules are the modules rc.conf turns on; checked by run before it is used.
func (o *options) applianceModules() []string {
	m, _ := expandAppliance(o.appliance)
	return m
}

// newSystem builds the real helper; tests replace it.
var newSystem = func(cfg priv.Config) (*priv.Local, error) { return priv.NewSystem(cfg) }

func run(args []string, stdout, stderr io.Writer, euid int) int {
	// The file agent the helper starts for the daemon needs no configuration and must start fast.
	if len(args) > 0 && args[0] == priv.AgentSubcommand {
		return agentMain(args[1:], stderr, euid)
	}
	if len(args) > 0 {
		switch args[0] {
		case "init":
			return initMain(args[1:], stdout, stderr, euid)
		case "appliance-init":
			return applianceInitMain(args[1:], stdout, stderr, euid)
		case "setup-token":
			return setupTokenMain(args[1:], stdout, stderr, euid)
		}
	}
	var o options
	fs := newFlags(&o, stderr)
	// help and the version need no configuration
	for _, a := range args {
		switch a {
		case "-h", "-help", "--help":
			fs.SetOutput(stdout)
			fs.Usage()
			return 0
		case "-version", "--version":
			printVersion(stdout)
			return 0
		}
	}
	// -config is needed before the file can be read.
	for i, a := range args {
		if (a == "-config" || a == "--config") && i+1 < len(args) {
			o.config = args[i+1]
		} else if v, ok := strings.CutPrefix(strings.TrimLeft(a, "-"), "config="); ok && strings.HasPrefix(a, "-") {
			o.config = v
		}
	}
	explicit := o.config != "" && o.config != defaultConfig
	if o.config == "" {
		o.config = defaultConfig
	}
	if err := loadConfigFile(fs, o.config, explicit); err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "version" {
		printVersion(stdout)
		return 0
	}
	if _, err := expandAppliance(o.appliance); err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 2
	}
	cfg := o.privConfig()
	if len(rest) > 0 && rest[0] == "check-config" {
		return checkConfig(&o, cfg, stdout, stderr)
	}
	// the command is checked before root is required
	if len(rest) > 0 && (rest[0] != "hook" || len(rest) != 3) && (rest[0] != "revert-pending" || len(rest) != 1) {
		fmt.Fprint(stderr, synopsis)
		return 2
	}
	if euid != 0 && !o.dev {
		fmt.Fprintln(stderr, "jailops-priv: must run as root (use --dev for development)")
		return 1
	}
	if rest := fs.Args(); len(rest) > 0 && rest[0] == "revert-pending" {
		if _, err := os.Stat(o.config); errors.Is(err, os.ErrNotExist) {
			return 0 // nothing is set up yet (an appliance's first boot): nothing can wait for a confirmation
		}
	}
	if _, err := cfg.Normalize(); err != nil {
		fmt.Fprintf(stderr, "jailops-priv: configuration: %v\n", err)
		return 2
	}
	if !o.dev {
		if err := checkFileSafety(o.config); err != nil {
			fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
			return 2
		}
	}
	if len(rest) == 0 {
		return serve(&o, cfg, stderr)
	}
	if rest[0] == "revert-pending" {
		return revertPending(&o, cfg, stdout, stderr)
	}
	return hook(&o, cfg, rest[1], rest[2], stderr)
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "jailops-priv %s (protocol %d)\n", version, priv.ProtocolVersion)
}

func newAuditor(o *options, daemon bool, stderr io.Writer) *priv.Auditor {
	if o.logTo == "syslog" || (o.logTo == "" && daemon) {
		if a, err := priv.NewSyslogAuditor("jailops-priv"); err == nil {
			return a
		} else {
			fmt.Fprintf(stderr, "jailops-priv: syslog unavailable (%v), logging to stderr\n", err)
		}
	}
	return priv.NewAuditor(stderr)
}

func hook(o *options, cfg priv.Config, phase, jail string, stderr io.Writer) int {
	l, err := newSystem(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	aud := newAuditor(o, true, stderr)
	ev := priv.AuditEvent{UID: uint32(os.Geteuid()), PID: int32(os.Getpid()), Op: "hook." + phase, Target: map[string]string{"jail": jail}}
	start := time.Now()
	err = l.RunHook(ctx, phase, jail)
	ev.Dur = time.Since(start)
	if err != nil {
		ev.Outcome, ev.Err = "error", err.Error()
		aud.Log(ev)
		fmt.Fprintf(stderr, "jailops-priv hook %s %s: %v\n", phase, jail, err)
		return 1
	}
	ev.Outcome = "ok"
	aud.Log(ev)
	return 0
}

// revertPending is run by the rc.d script jailops_revert at boot, before netif and pf: an unconfirmed host change
// is put back (only the files; the scripts that follow load them), so a reboot never makes it permanent.
func revertPending(o *options, cfg priv.Config, stdout, stderr io.Writer) int {
	l, err := newSystem(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 2
	}
	aud := newAuditor(o, true, stderr)
	l.SetHostNote(aud.Note)
	out, err := l.RevertPendingAtBoot(context.Background())
	if out != nil {
		fmt.Fprintf(stdout, "jailops-priv: the unconfirmed %s change %s was %s (snapshot %s)\n", out.Module, out.ID, strings.ReplaceAll(out.Outcome, "_", " "), out.Snapshot)
	}
	if err != nil {
		fmt.Fprintf(stderr, "jailops-priv: revert-pending: %v\n", err)
		return 1
	}
	return 0
}

func resolvePeers(o *options) (priv.PeerPolicy, error) {
	var p priv.PeerPolicy
	for _, name := range o.allowUser {
		u, err := user.Lookup(name)
		if err != nil {
			return p, fmt.Errorf("allow-user %q: %w", name, err)
		}
		n, _ := strconv.ParseUint(u.Uid, 10, 32)
		p.UIDs = append(p.UIDs, uint32(n))
	}
	for _, name := range o.allowGroup {
		g, err := user.LookupGroup(name)
		if err != nil {
			return p, fmt.Errorf("allow-group %q: %w", name, err)
		}
		n, _ := strconv.ParseUint(g.Gid, 10, 32)
		p.GIDs = append(p.GIDs, uint32(n))
	}
	if len(p.UIDs) == 0 && len(p.GIDs) == 0 && o.dev {
		p.UIDs = append(p.UIDs, uint32(os.Geteuid()))
	}
	return p, nil
}

// writePidfile writes the pid without following a symlink at the file's own name: root must not truncate a file
// someone else linked there.
func writePidfile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(strconv.Itoa(os.Getpid()) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// listen creates the socket with mode and group set before anyone can connect.
func listen(path, group string, mode os.FileMode, dev bool) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o710); err != nil {
		return nil, err
	}
	gid := -1
	if group != "" {
		if g, err := user.LookupGroup(group); err == nil {
			n, _ := strconv.Atoi(g.Gid)
			gid = n
		} else if !dev {
			return nil, fmt.Errorf("group %q: %w", group, err)
		}
	}
	if gid >= 0 {
		// The directory is the helper's alone: root writes it, the group may only pass through to the socket. In a
		// directory the daemon's user could write, it could put a file or a socket of its own at this name before
		// the helper starts.
		if err := os.Chown(dir, 0, gid); err != nil && !dev {
			return nil, err
		}
		if err := os.Chmod(dir, 0o710); err != nil {
			return nil, err
		}
	}
	if !dev {
		st, err := os.Lstat(dir)
		if err != nil {
			return nil, err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !st.IsDir() || !ok || sys.Uid != 0 || st.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("%s must be a directory of root that only root can write (mode 0710, group %s)", dir, group)
		}
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another jailops-priv is listening on %s", path)
		}
		os.Remove(path)
	}
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil && !dev {
			ln.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func serve(o *options, cfg priv.Config, stderr io.Writer) int {
	if o.daemon && os.Getenv("JAILOPS_PRIV_CHILD") == "" {
		return detach(stderr)
	}
	mode, err := strconv.ParseUint(o.mode, 8, 32)
	if err != nil || mode&^0o777 != 0 || mode&0o007 != 0 {
		fmt.Fprintf(stderr, "jailops-priv: invalid socket mode %q (others must have no access)\n", o.mode)
		return 2
	}
	peers, err := resolvePeers(o)
	if err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 2
	}
	if len(peers.UIDs) == 0 && len(peers.GIDs) == 0 {
		fmt.Fprintln(stderr, "jailops-priv: no allowed peer: set allow-user (jailopsd's user) or allow-group")
		return 2
	}
	l, err := newSystem(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 2
	}
	aud := newAuditor(o, o.daemon, stderr)
	// A host change that waits for its confirmation is re-armed, or reverted when its deadline passed while the
	// helper was not running, before the first request is accepted.
	l.SetHostNote(aud.Note)
	if _, err := l.ResumePending(context.Background()); err != nil {
		aud.Note("priv.pending_resume_failed", "error", err.Error())
	}
	srv := priv.NewServer(l, priv.ServerOptions{Peers: peers, Audit: aud, Version: version})
	ln, err := listen(o.socket, o.group, os.FileMode(mode), o.dev)
	if err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 1
	}
	if o.pidfile != "" {
		if err := writePidfile(o.pidfile); err != nil {
			fmt.Fprintf(stderr, "jailops-priv: pidfile: %v\n", err)
			ln.Close()
			return 1
		}
		defer os.Remove(o.pidfile)
	}
	defer os.Remove(o.socket)
	aud.Note("priv.start", "version", version, "socket", o.socket, "storage_roots", strings.Join(l.Config().Roots(), ","))
	noteRoots(aud, l)

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	signal.Ignore(syscall.SIGPIPE)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	for {
		select {
		case s := <-sig:
			if s == syscall.SIGHUP {
				if err := l.ReloadRoots(context.Background()); err != nil {
					aud.Note("priv.reload_failed", "error", err.Error())
				} else {
					aud.Note("priv.reload", "storage_roots", strings.Join(l.Config().Roots(), ","))
					noteRoots(aud, l)
				}
				continue
			}
			aud.Note("priv.stop", "signal", s.String())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			<-done
			return 0
		case err := <-done:
			if err != nil {
				fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
				return 1
			}
			return 0
		}
	}
}

// noteRoots logs every storage root that is configured but not usable.
func noteRoots(aud *priv.Auditor, l *priv.Local) {
	for _, r := range l.RootStatuses() {
		if !r.Active {
			aud.Note("priv.storage_root_inactive", "dataset", r.Dataset, "error", r.Error)
		}
	}
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

// checkFileSafety refuses a configuration file others can write.
func checkFileSafety(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return nil // a missing default file is not an error here
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others", path)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 && int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d", path, sys.Uid)
	}
	return nil
}

// detach re-executes the program in a new session with no terminal.
func detach(stderr io.Writer) int {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "JAILOPS_PRIV_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 1
	}
	return 0
}

// checkConfig validates the configuration and prints what it amounts to:
// the effective storage roots (with the reason a root is inactive), the
// interface prefixes, directories, admin policy and every allow-list. It
// exits 2 when the configuration or the storage file is invalid; inactive
// roots are warnings (a pool may not be imported yet).
func checkConfig(o *options, cfg priv.Config, stdout, stderr io.Writer) int {
	if _, err := cfg.Normalize(); err != nil {
		fmt.Fprintf(stderr, "jailops-priv: configuration: %v\n", err)
		return 2
	}
	if err := checkFileSafety(o.config); err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 2
	}
	l, err := newSystem(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "jailops-priv: %v\n", err)
		return 2
	}
	c := l.Config()
	w := func(f string, a ...any) { fmt.Fprintf(stdout, f, a...) }
	w("config file:    %s\n", o.config)
	w("storage file:   %s\n", c.StorageFile)
	w("conf dir:       %s\n", c.ConfDir)
	w("state dir:      %s\n", c.StateDir)
	w("helper path:    %s\n", c.HelperPath)
	w("interfaces:     the epairs that carry the JailOps description\n")
	w("storage roots:\n")
	warn := 0
	if st := l.RootStatuses(); len(st) == 0 {
		w("  (none; register one with storage.register)\n")
	} else {
		for _, r := range st {
			w("  %s\n", r)
			if !r.Active {
				warn++
			}
		}
	}
	w("admin policy:\n")
	w("  raw jail params: %s\n", strings.Join(c.Admin.RawJailParams, ", "))
	w("  allow flags:     %s\n", strings.Join(c.Admin.AllowFlags, ", "))
	w("  devfs rulesets:  %v\n", c.Admin.DevfsRulesets)
	w("  host mounts:     %s\n", strings.Join(c.Admin.HostMountRoots, ", "))
	w("  zfs properties:  %s\n", strings.Join(c.Admin.ZFSProps, ", "))
	w("  routes: %v  raw pf: %v  resume send: %v  zfs delegation: %v\n", c.Admin.Routes, c.Admin.RawPF, c.Admin.ResumeSend, c.Admin.ZFSDelegation)
	w("commands (fixed binaries):\n")
	for _, r := range priv.CommandRules {
		w("  %-15s %-26s %s\n", r.Name, r.Binary, r.Reason)
	}
	w("fetch hosts:    %s\n", strings.Join(c.EffectiveFetchHosts(), ", "))
	w("package keys:   %s (and /usr/share/keys)\n", cmp.Or(c.PkgKeysDir, priv.DefaultPkgKeysDir))
	w("keyrings:       %s\n", cmp.Or(c.KeyringDir, priv.DefaultKeyringDir))
	w("image mirrors:  %s\n", strings.Join(c.ImageMirrors, ", "))
	w("readable files: %s\n", strings.Join(priv.ReadOnlyFiles, ", "))
	if len(c.HostManage) == 0 {
		w("host manage:    none (the host is only read)\n")
	} else {
		w("host manage:    %s (snapshots in %s)\n", strings.Join(c.HostManage, ", "), c.HostDir)
	}
	if rc := o.applianceModules(); len(rc) > 0 {
		w("appliance:      on: rc.conf (jailops_appliance) adds %s to host-manage of priv.conf (%s)\n", strings.Join(rc, ", "), orNone(o.hostManage))
	} else {
		w("appliance:      off (jailops_appliance is not YES in rc.conf); host-manage of priv.conf alone decides\n")
	}
	w("kernel modules: %s\n", strings.Join(priv.KldModules, ", "))
	var reads, writes []string
	reads = append(append(reads, priv.DefaultSysctls...), c.Sysctls...)
	for n := range priv.SysctlWrites {
		writes = append(writes, n)
	}
	sort.Strings(reads)
	sort.Strings(writes)
	w("sysctl read:    %s\n", strings.Join(reads, ", "))
	w("sysctl write (admin only): %s\n", strings.Join(writes, ", "))
	if warn > 0 {
		fmt.Fprintf(stderr, "jailops-priv: warning: %d storage root(s) inactive\n", warn)
	}
	return 0
}
