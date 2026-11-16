package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// logDir is where the jails' exec.consolelog files are (render.ConsoleLog); its dataset is <dataset>/logs.
const logDir = "/var/log/jailops"

// initCmd is `jailops-priv init -pool tank`: the one-time setup of a host. It makes what the daemon cannot make
// for itself, because it is not root: the user and groups, the storage root dataset and the state dataset
// (owned by the daemon's user), and the two configuration files. Everything is idempotent; nothing that exists
// is changed except to say so.
type initOptions struct {
	pool, dataset, mount  string
	mountSet              bool // -mount was given: a mount that differs from the existing dataset's is an error, not a surprise
	user, group           string
	etc                   string // /usr/local/etc/jailops
	dbDir                 string // /var/db/jailops
	dryRun                bool
	web                   bool   // -web: serve the web console (and open the TLS listener it needs)
	webAddress            string // the address of that listener
	root                  string // prefix of every path (tests)
	appliance             bool   // run by appliance-init: the rc scripts start the services and print the setup token
	run                   func(name string, args ...string) (string, error)
	lookupUser, lookupGrp func(string) (uid, gid int, err error)
	chown                 func(path string, uid, gid int) error
}

func defaultRun(name string, args ...string) (string, error) {
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), initCommandTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.WaitDelay = time.Second
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	return strings.TrimSpace(out.String()), err
}

func initMain(args []string, stdout, stderr io.Writer, euid int) int {
	o := &initOptions{run: defaultRun, chown: os.Chown}
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.pool, "pool", "", "the ZFS pool JailOps lives on (required)")
	fs.StringVar(&o.dataset, "dataset", "", "the storage root dataset (default <pool>/jailops)")
	fs.StringVar(&o.mount, "mount", "/usr/local/jailops", "where the storage root is mounted")
	fs.StringVar(&o.user, "user", "jailops", "the unprivileged user jailopsd runs as")
	fs.StringVar(&o.group, "group", "jailops", "the group of that user, which may talk to the helper")
	fs.StringVar(&o.etc, "etc", "/usr/local/etc/jailops", "configuration directory")
	fs.StringVar(&o.dbDir, "data-dir", "/var/db/jailops", "the daemon's data directory")
	fs.BoolVar(&o.web, "web", false, "also turn on the web console: opens the TLS listener (-web-address) and sets web.enabled; sign in with a JailOps user")
	fs.StringVar(&o.webAddress, "web-address", ":39110", "the address of the TLS listener that -web opens (all interfaces by default; 127.0.0.1:39110 keeps it on this host)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "say what would be done and do nothing")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "usage: jailops-priv init -pool POOL [flags]\n\nThe one-time setup of a host: the user and group, the storage root and state datasets, and the two\nconfiguration files. Everything is idempotent; what exists is left as it is.\n\nflags:\n")
		fs.PrintDefaults()
	}
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" {
			fs.SetOutput(stdout)
			fs.Usage()
			return 0
		}
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "mount" {
			o.mountSet = true
		}
	})
	// the arguments are checked before the root check, so a mistake is reported to anyone
	if err := o.validate(); err != nil {
		fmt.Fprintf(stderr, "jailops-priv init: %v\n%s", err, synopsis)
		return 2
	}
	if euid != 0 && !o.dryRun {
		fmt.Fprintln(stderr, "jailops-priv init: must run as root")
		return 1
	}
	if err := o.do(stdout); err != nil {
		fmt.Fprintf(stderr, "jailops-priv init: %v\n", err)
		return 1
	}
	return 0
}

func (o *initOptions) path(p string) string { return filepath.Join(o.root, p) }

func (o *initOptions) say(w io.Writer, format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

// validate checks the arguments without touching the system.
func (o *initOptions) validate() error {
	// a leading "-" would reach zfs and zpool as an option
	if o.pool == "" || strings.ContainsAny(o.pool, "/ @#") || strings.HasPrefix(o.pool, "-") {
		return errors.New("-pool names the pool (for example -pool tank), not a dataset")
	}
	if o.dataset == "" {
		o.dataset = o.pool + "/jailops"
	}
	if !strings.HasPrefix(o.dataset, o.pool+"/") {
		return fmt.Errorf("dataset %s is not in pool %s", o.dataset, o.pool)
	}
	if !filepath.IsAbs(o.mount) || filepath.Clean(o.mount) != o.mount || o.mount == "/" {
		return fmt.Errorf("mount %q must be a clean absolute path other than /", o.mount)
	}
	return nil
}

func (o *initOptions) do(w io.Writer) error {
	if err := o.validate(); err != nil {
		return err
	}
	if out, err := o.run("zpool", "list", "-H", "-o", "name", o.pool); err != nil || strings.TrimSpace(out) != o.pool {
		return fmt.Errorf("pool %s does not exist or is not imported (%s)", o.pool, out)
	}
	// the user and the group
	for _, g := range []string{o.group} {
		if _, err := o.lookupGroup(g); err != nil {
			o.say(w, "creating group %s", g)
			if !o.dryRun {
				if out, err := o.run("pw", "groupadd", g); err != nil {
					return fmt.Errorf("pw groupadd %s: %v: %s", g, err, out)
				}
			}
		}
	}
	if _, err := o.lookupUserName(o.user); err != nil {
		o.say(w, "creating user %s", o.user)
		if !o.dryRun {
			if out, err := o.run("pw", "useradd", o.user, "-g", o.group, "-d", o.dbDir, "-s", "/usr/sbin/nologin", "-c", "JailOps daemon"); err != nil {
				return fmt.Errorf("pw useradd %s: %v: %s", o.user, err, out)
			}
		}
	}
	// the datasets
	managed := func(ds string) (string, error) {
		return o.run("zfs", "get", "-H", "-o", "value,source", "jailops:managed", ds)
	}
	if _, err := o.run("zfs", "list", "-H", "-o", "name", o.dataset); err != nil {
		o.say(w, "creating dataset %s (mounted at %s)", o.dataset, o.mount)
		if !o.dryRun {
			if out, err := o.run("zfs", "create", "-o", "mountpoint="+o.mount, "-o", "jailops:managed=on", o.dataset); err != nil {
				return fmt.Errorf("zfs create %s: %v: %s", o.dataset, err, out)
			}
		}
	} else if v, _ := managed(o.dataset); !strings.HasPrefix(v, "on\tlocal") && !strings.HasPrefix(v, "on local") {
		return fmt.Errorf("dataset %s exists but is not marked jailops:managed=on; mark it yourself if it is meant for JailOps: zfs set jailops:managed=on %s", o.dataset, o.dataset)
	} else if mp, err := o.run("zfs", "get", "-H", "-o", "value", "mountpoint", o.dataset); err == nil {
		// An installed host keeps the mount point its images and jails were made under (their datasets carry absolute
		// mount points below it): running init again on a newer release, whose default differs, must not point
		// mount-base somewhere else, where the helper would refuse every path.
		if have := strings.TrimSpace(mp); have != o.mount && filepath.IsAbs(have) {
			if o.mountSet {
				return fmt.Errorf("dataset %s is mounted at %s, not at %s: its images and jails live there, and moving them is not supported (omit -mount to keep %s)", o.dataset, have, o.mount, have)
			}
			o.say(w, "dataset %s is already mounted at %s: keeping it (the default of this release is %s)", o.dataset, have, o.mount)
			o.mount = have
		}
	}
	// The state dataset is mounted outside the storage root: the daemon owns it, and a directory the daemon can
	// modify must not sit inside a tree the helper (root) walks.
	state := o.dataset + "/state"
	stateDir := filepath.Join(o.dbDir, "state")
	if _, err := o.run("zfs", "list", "-H", "-o", "name", state); err != nil {
		o.say(w, "creating dataset %s (mounted at %s)", state, stateDir)
		if !o.dryRun {
			if out, err := o.run("zfs", "create", "-o", "mountpoint="+stateDir, "-o", "jailops:managed=on", state); err != nil {
				return fmt.Errorf("zfs create %s: %v: %s", state, err, out)
			}
		}
	}
	// The logs of the jails (exec.consolelog) have a dataset of their own, where FreeBSD keeps logs: /var/log/jailops,
	// rotated by newsyslog, with its own compression and a quota the administrator can set.
	logs := o.dataset + "/logs"
	if _, err := o.run("zfs", "list", "-H", "-o", "name", logs); err != nil {
		o.say(w, "creating dataset %s (mounted at %s)", logs, logDir)
		if !o.dryRun {
			if out, err := o.run("zfs", "create", "-o", "mountpoint="+logDir, "-o", "compression=lz4", "-o", "jailops:managed=on", logs); err != nil {
				return fmt.Errorf("zfs create %s: %v: %s", logs, err, out)
			}
		}
	}
	uid, gid, err := o.owner()
	if err != nil && !o.dryRun {
		return err
	}
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{{o.dbDir, 0o750}, {stateDir, 0o750}} {
		o.say(w, "directory %s: owner %s, mode %04o", d.p, o.user, d.mode)
		if o.dryRun {
			continue
		}
		if err := os.MkdirAll(o.path(d.p), d.mode); err != nil {
			return err
		}
		if err := os.Chmod(o.path(d.p), d.mode); err != nil {
			return err
		}
		if err := o.chown(o.path(d.p), uid, gid); err != nil {
			return err
		}
	}
	// The storage root belongs to root alone (the helper reads and writes below it); the scratch directory too.
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{{o.mount, 0o700}, {"/var/tmp/jailops", 0o755}} {
		o.say(w, "directory %s: owner root, mode %04o", d.p, d.mode)
		if o.dryRun {
			continue
		}
		if err := os.MkdirAll(o.path(d.p), d.mode); err != nil {
			return err
		}
		if err := os.Chmod(o.path(d.p), d.mode); err != nil {
			return err
		}
		if err := o.chown(o.path(d.p), 0, 0); err != nil {
			return err
		}
	}
	// the configuration, never overwritten; the directory of the rendered jail.conf files too
	if !o.dryRun {
		for _, d := range []string{o.etc, filepath.Join(o.etc, "jails")} {
			if err := os.MkdirAll(o.path(d), 0o755); err != nil {
				return err
			}
		}
	}
	// the files of log sinks set through the API (logging.secrets_dir): root writes them, the daemon's group reads
	sinks := filepath.Join(o.etc, "sinks")
	o.say(w, "directory %s: owner root, group %s, mode 0750", sinks, o.group)
	if !o.dryRun {
		if err := os.MkdirAll(o.path(sinks), 0o750); err != nil {
			return err
		}
		if err := os.Chmod(o.path(sinks), 0o750); err != nil {
			return err
		}
		if err := o.chown(o.path(sinks), 0, gid); err != nil {
			return err
		}
	}
	// the logs of the jails: root writes them (jail(8)), the daemon's group reads
	o.say(w, "directory %s: owner root, group %s, mode 0750", logDir, o.group)
	if !o.dryRun {
		if err := os.MkdirAll(o.path(logDir), 0o750); err != nil {
			return err
		}
		if err := os.Chmod(o.path(logDir), 0o750); err != nil {
			return err
		}
		if err := o.chown(o.path(logDir), 0, gid); err != nil {
			return err
		}
	}
	files := []struct {
		name string
		mode os.FileMode
		gid  int
		body string
	}{
		{"priv.conf", 0o600, 0, o.privConf()},
		{"jailopsd.yaml", 0o640, gid, o.daemonYAML()},
	}
	for _, f := range files {
		p := filepath.Join(o.etc, f.name)
		if _, err := os.Stat(o.path(p)); err == nil {
			o.say(w, "%s exists, left as it is", p)
			continue
		}
		o.say(w, "writing %s", p)
		if o.dryRun {
			continue
		}
		if err := os.WriteFile(o.path(p), []byte(f.body), f.mode); err != nil {
			return err
		}
		if err := o.chown(o.path(p), 0, f.gid); err != nil {
			return err
		}
	}
	if o.appliance {
		o.say(w, "\nDone. jailopsd prints the setup token of the first administrator on the console when it starts.")
		return nil
	}
	o.say(w, "\nDone. Enable and start the services:")
	o.say(w, "  sysrc jailops_priv_enable=YES jailopsd_enable=YES")
	o.say(w, "  service jailops_priv start && service jailopsd start")
	o.say(w, "Create the first administrator (root reaches the socket as the host's recovery access):")
	o.say(w, "  jailops user create admin --admin --password-prompt")
	o.say(w, "PF needs the line `anchor \"jailops/*\"` (see `jailops doctor`).")
	return nil
}

func (o *initOptions) lookupGroup(name string) (int, error) {
	if o.lookupGrp != nil {
		_, g, err := o.lookupGrp(name)
		return g, err
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

func (o *initOptions) lookupUserName(name string) (int, error) {
	if o.lookupUser != nil {
		u, _, err := o.lookupUser(name)
		return u, err
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

func (o *initOptions) owner() (uid, gid int, err error) {
	if uid, err = o.lookupUserName(o.user); err != nil {
		return 0, 0, err
	}
	gid, err = o.lookupGroup(o.group)
	return uid, gid, err
}

func (o *initOptions) privConf() string {
	return fmt.Sprintf(`# jailops-priv.conf, written by "jailops-priv init". See priv.conf.sample for everything it can say.
storage-root = %s
conf-dir = /usr/local/etc/jailops/jails
mount-base = %s
state-dir = %s
work-dir = /var/tmp/jailops
helper-path = /usr/local/libexec/jailops-priv
socket = /var/run/jailops-priv/priv.sock
group = %s
mode = 0660
allow-user = %s
`, o.dataset, o.mount, filepath.Join(o.dbDir, "state"), o.group, o.user)
}

func (o *initOptions) daemonYAML() string {
	listen, web := "", ""
	if o.web {
		addr := o.webAddress
		if addr == "" {
			addr = ":39110"
		}
		listen = fmt.Sprintf("  https:\n    address: %q\n", addr)
		web = "web:\n  enabled: true\n"
	}
	return fmt.Sprintf(`# jailopsd.yaml, written by "jailops-priv init". See jailopsd.yaml in the packaging directory for every key.
role: host
pool: %s
dataset: %s
mount_base: %s
data_dir: %s
state_dir: %s
listen:
  unix:
    path: /var/run/jailops/jailops.sock
    mode: 0666
%s%spriv:
  socket: /var/run/jailops-priv/priv.sock
`, o.pool, o.dataset, o.mount, o.dbDir, filepath.Join(o.dbDir, "state"), listen, web)
}

// initCommandTimeout bounds each command of `jailops-priv init` (zfs, mkdir and the like): a command that never
// returns must not leave the setup hanging.
const initCommandTimeout = 10 * time.Minute
