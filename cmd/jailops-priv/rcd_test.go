package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"jailops.net/jailops/internal/priv"
)

// rcHeader is the rcorder(8) header of a script: PROVIDE, REQUIRE and BEFORE.
type rcHeader struct{ provide, require, before []string }

func readRCHeader(t *testing.T, path string) rcHeader {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var h rcHeader
	for _, ln := range strings.Split(string(b), "\n") {
		for key, dst := range map[string]*[]string{"# PROVIDE:": &h.provide, "# REQUIRE:": &h.require, "# BEFORE:": &h.before} {
			if v, ok := strings.CutPrefix(ln, key); ok {
				*dst = append(*dst, strings.Fields(v)...)
			}
		}
	}
	return h
}

// rcOrder sorts the scripts as rcorder does: REQUIRE and BEFORE are edges; a cycle fails the test.
func rcOrder(t *testing.T, scripts map[string]rcHeader) []string {
	t.Helper()
	provider := map[string]string{}
	for name, h := range scripts {
		for _, p := range h.provide {
			provider[p] = name
		}
	}
	after := map[string][]string{} // name -> what must run first
	for name, h := range scripts {
		for _, r := range h.require {
			if p, ok := provider[r]; ok {
				after[name] = append(after[name], p)
			}
		}
		for _, b := range h.before {
			if p, ok := provider[b]; ok {
				after[p] = append(after[p], name)
			}
		}
	}
	var out []string
	state := map[string]int{}
	var visit func(string)
	visit = func(n string) {
		switch state[n] {
		case 1:
			t.Fatalf("a cycle through %s", n)
		case 2:
			return
		}
		state[n] = 1
		deps := slices.Clone(after[n])
		slices.Sort(deps)
		for _, d := range deps {
			visit(d)
		}
		state[n] = 2
		out = append(out, n)
	}
	names := make([]string, 0, len(scripts))
	for n := range scripts {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		visit(n)
	}
	return out
}

// The boot order the package's scripts ask for, against the headers of the FreeBSD 15 base scripts they name: an
// unconfirmed host change is put back (jailops_revert) before netif and pf start, and before the helper itself.
// UNVERIFIED: this checks the text of the headers only; a real boot with a pending change has not been run.
func TestRCDOrdering(t *testing.T) {
	dir := filepath.Join("..", "..", "packaging", "rc.d")
	scripts := map[string]rcHeader{
		// the base scripts, with the headers of /etc/rc.d on 15.1 (only the lines that matter here)
		"FILESYSTEMS": {provide: []string{"FILESYSTEMS"}, require: []string{"root", "zfs"}},
		"root":        {provide: []string{"root"}},
		"zfs":         {provide: []string{"zfs"}, require: []string{"zfsbe"}, before: []string{"FILESYSTEMS", "var"}},
		"netif":       {provide: []string{"netif"}, require: []string{"FILESYSTEMS", "iovctl", "serial", "sppp", "sysctl"}},
		"routing":     {provide: []string{"routing"}, require: []string{"faith", "netif", "ppp", "stf"}},
		"pf":          {provide: []string{"pf"}, require: []string{"FILESYSTEMS", "netif", "pflog", "pfsync", "routing"}},
		"NETWORKING":  {provide: []string{"NETWORKING", "NETWORK"}, require: []string{"netif", "netwait", "routing", "ppp", "stf"}},
		"syslogd":     {provide: []string{"syslogd"}, require: []string{"mountcritremote", "FILESYSTEMS", "newsyslog"}, before: []string{"SERVERS"}},
		"SERVERS":     {provide: []string{"SERVERS"}, require: []string{"mountcritremote", "abi", "ldconfig", "savecore", "watchdogd"}},
	}
	for _, n := range []string{"jailops_revert", "jailops_priv", "jailopsd"} {
		scripts[n] = readRCHeader(t, filepath.Join(dir, n))
	}
	rev := scripts["jailops_revert"]
	if !slices.Equal(rev.provide, []string{"jailops_revert"}) || !slices.Contains(rev.require, "FILESYSTEMS") ||
		!slices.Contains(rev.before, "netif") || !slices.Contains(rev.before, "pf") || !slices.Contains(rev.before, "jailops_priv") {
		t.Errorf("jailops_revert: %+v", rev)
	}
	order := rcOrder(t, scripts)
	pos := func(n string) int { return slices.Index(order, n) }
	for _, pair := range [][2]string{
		{"FILESYSTEMS", "jailops_revert"}, {"jailops_revert", "netif"}, {"jailops_revert", "pf"}, {"jailops_revert", "jailops_priv"},
		{"jailops_priv", "jailopsd"}, {"pf", "jailopsd"}, {"NETWORKING", "jailopsd"},
		// appliance mode: the first-start setup (zfs, pw) after the file systems; the setup token after syslogd
		{"FILESYSTEMS", "jailops_priv"}, {"zfs", "jailops_priv"}, {"syslogd", "jailopsd"},
	} {
		if pos(pair[0]) >= pos(pair[1]) {
			t.Errorf("%s does not come before %s: %v", pair[0], pair[1], order)
		}
	}
	// the script runs the helper's own subcommand, whenever the helper is enabled
	b, _ := os.ReadFile(filepath.Join(dir, "jailops_revert"))
	for _, want := range []string{`rcvar="jailops_priv_enable"`, "jailops-priv -log syslog -config ${jailops_priv_config} revert-pending", "run_rc_command"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("jailops_revert lacks %q", want)
		}
	}
	pkg, _ := os.ReadFile(filepath.Join("..", "..", "scripts", "pkg-build.sh"))
	if !strings.Contains(string(pkg), `"$pk/rc.d/jailops_revert"`) {
		t.Error("the package does not install jailops_revert")
	}
}

// The shutdown script stops the jails before the daemon and the helper stop: rc stops the scripts in the reverse of
// the boot order, so a script that requires both is stopped first. It does nothing at boot and is installed with the
// others; restarting the daemon does not run it.
func TestRCDShutdownScript(t *testing.T) {
	dir := filepath.Join("..", "..", "packaging", "rc.d")
	scripts := map[string]rcHeader{
		"FILESYSTEMS": {provide: []string{"FILESYSTEMS"}},
		"NETWORKING":  {provide: []string{"NETWORKING"}},
		"pf":          {provide: []string{"pf"}},
		"syslogd":     {provide: []string{"syslogd"}},
	}
	for _, n := range []string{"jailops_revert", "jailops_priv", "jailopsd", "jailops_shutdown"} {
		scripts[n] = readRCHeader(t, filepath.Join(dir, n))
	}
	sd := scripts["jailops_shutdown"]
	if !slices.Equal(sd.provide, []string{"jailops_shutdown"}) || !slices.Contains(sd.require, "jailopsd") || !slices.Contains(sd.require, "jailops_priv") {
		t.Fatalf("jailops_shutdown: %+v", sd)
	}
	order := rcOrder(t, scripts)
	pos := func(n string) int { return slices.Index(order, n) }
	// the boot order has it after the daemon and the helper; the shutdown order is the reverse
	for _, dep := range []string{"jailopsd", "jailops_priv"} {
		if pos(dep) >= pos("jailops_shutdown") {
			t.Errorf("%s does not come before jailops_shutdown at boot, so it is not stopped after it at shutdown: %v", dep, order)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "jailops_shutdown"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{
		"# KEYWORD: shutdown", `rcvar="jailops_shutdown_enable"`, `start_cmd=":"`, `stop_cmd="jailops_shutdown_stop"`,
		"${jailopsd_enable:-NO}", `stop-all`, "timeout ", "return 0", "run_rc_command",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("jailops_shutdown lacks %q", want)
		}
	}
	// the shutdown must go on whatever happens: the command's failure is a warning, the function returns 0
	if strings.Contains(text, "exit 1") {
		t.Error("the shutdown script can fail the shutdown")
	}
	// the daemon's own script does not run it, so a restart of the daemon never stops a jail
	if d, _ := os.ReadFile(filepath.Join(dir, "jailopsd")); strings.Contains(string(d), "stop-all") || strings.Contains(string(d), "jailops_shutdown stop") {
		t.Error("jailopsd stops the jails")
	}
	pkg, _ := os.ReadFile(filepath.Join("..", "..", "scripts", "pkg-build.sh"))
	if !strings.Contains(string(pkg), `"$pk/rc.d/jailops_shutdown"`) {
		t.Error("the package does not install jailops_shutdown")
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		if out, err := exec.Command(sh, "-n", filepath.Join(dir, "jailops_shutdown")).CombinedOutput(); err != nil {
			t.Errorf("syntax: %v\n%s", err, out)
		}
	}
}

// revert-pending is what the boot script runs: nothing pending is a quiet success; it takes no arguments and
// needs root.
func TestRevertPendingCommand(t *testing.T) {
	useFakeSystem(t, nil)
	dir := t.TempDir()
	conf := filepath.Join(dir, "priv.conf")
	if err := os.WriteFile(conf, []byte("state-dir = "+filepath.Join(dir, "state")+"\nhost-dir = "+filepath.Join(dir, "host")+"\nhost-manage = firewall\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := runArgs(t, 0, "-dev", "-config", conf, "revert-pending"); code != 0 || out != "" {
		t.Errorf("nothing pending: %d %q %q", code, out, errs)
	}
	if code, _, _ := runArgs(t, 0, "-dev", "-config", conf, "revert-pending", "now"); code != 2 {
		t.Errorf("an argument: %d", code)
	}
	if code, _, _ := runArgs(t, 1000, "-config", conf, "revert-pending"); code != 1 {
		t.Errorf("not root: %d", code)
	}
}

// daemon(8) writes the pid files of every packaged service as root. None of them may lie in a directory that a
// service's unprivileged user can write to (a directory a script makes with install -d for another owner, or
// writable by a group), or that user could leave a symlink there and have root write through it.
func TestRCDPidfilesInRootOnlyDirectories(t *testing.T) {
	dir := filepath.Join("..", "..", "packaging", "rc.d")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	type script struct{ pidfiles, unsafe []string }
	all := map[string]script{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var s script
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			for _, key := range []string{"pidfile=", "supervisor_pidfile=", "helper_pidfile="} {
				if v, ok := strings.CutPrefix(ln, key); ok {
					s.pidfiles = append(s.pidfiles, strings.Trim(v, `"`))
				}
			}
			// install -d -m MODE [-o OWNER] [-g GROUP] DIR
			f := strings.Fields(ln)
			if len(f) < 3 || f[0] != "install" || f[1] != "-d" {
				continue
			}
			mode, owner, group := "", "root", "wheel"
			for i := 2; i+1 < len(f); i++ {
				switch f[i] {
				case "-m":
					mode = f[i+1]
				case "-o":
					owner = f[i+1]
				case "-g":
					group = f[i+1]
				}
			}
			m, err := strconv.ParseUint(mode, 8, 32)
			if err != nil {
				t.Fatalf("%s: install -d without an octal mode: %s", e.Name(), ln)
			}
			if owner != "root" || (m&0o020 != 0 && group != "wheel") || m&0o002 != 0 {
				s.unsafe = append(s.unsafe, f[len(f)-1])
			}
		}
		all[e.Name()] = s
	}
	var unsafe []string
	for _, s := range all {
		unsafe = append(unsafe, s.unsafe...)
	}
	if !slices.Contains(unsafe, "/var/run/jailops") || !slices.Contains(unsafe, "/var/run/jailops-backupd") {
		t.Fatalf("the parse missed the run directories: %v", unsafe)
	}
	n := 0
	for name, s := range all {
		for _, p := range s.pidfiles {
			n++
			if !strings.HasPrefix(p, "/var/run/") || strings.Contains(strings.TrimPrefix(p, "/var/run/"), "/") {
				t.Errorf("%s: pid file %s is not directly in /var/run", name, p)
			}
			for _, d := range unsafe {
				if strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/") {
					t.Errorf("%s: pid file %s is in %s, which a service user may write to", name, p, d)
				}
			}
		}
	}
	if n != 6 {
		t.Errorf("found %d pid files, want 6 (two per daemon(8) service)", n)
	}
}

// The helper's own -pidfile does not write through a symlink.
func TestPidfileDoesNotFollowASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "priv.pid")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writePidfile(link); err == nil {
		t.Fatal("wrote the pid through a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Fatalf("target changed: %q", b)
	}
	plain := filepath.Join(dir, "plain.pid")
	if err := writePidfile(plain); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(plain); string(b) != strconv.Itoa(os.Getpid())+"\n" {
		t.Fatalf("%q", b)
	}
}

// The helper's socket lives in a directory only root writes: the daemon's user, a member of the group, may reach the
// socket but cannot put a file or a socket of its own at its name before the helper starts.
func TestHelperSocketDirectoryIsRoots(t *testing.T) {
	dir := filepath.Dir(priv.DefaultSocket)
	if dir == "/var/run/jailops" {
		t.Fatalf("the helper's socket is in the daemon's directory %s", dir)
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "rc.d", "jailops_priv"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "install -d -m 0710 -o root -g jailops "+dir+"\n") {
		t.Errorf("the rc script does not make %s as root's, mode 0710", dir)
	}
	// outside development, a directory that is not root's is refused (this test does not run as root)
	if os.Geteuid() != 0 {
		sock := filepath.Join(t.TempDir(), "priv.sock")
		if ln, err := listen(sock, "", 0o660, false); err == nil {
			ln.Close()
			t.Error("a socket in a directory of another user was opened")
		}
	}
}
