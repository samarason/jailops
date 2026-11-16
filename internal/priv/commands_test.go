package priv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

func TestCommandRulesAreDocumentedAndFixed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range CommandRules {
		if r.Reason == "" {
			t.Errorf("rule %s has no reason", r.Name)
		}
		if !filepath.IsAbs(r.Binary) || filepath.Clean(r.Binary) != r.Binary {
			t.Errorf("rule %s: binary %q", r.Name, r.Binary)
		}
		if seen[r.Name] {
			t.Errorf("rule %s twice", r.Name)
		}
		seen[r.Name] = true
		if r.MaxTimeoutSeconds <= 0 || r.MaxTimeoutSeconds > 3600 {
			t.Errorf("rule %s: timeout %d", r.Name, r.MaxTimeoutSeconds)
		}
	}
	for _, n := range []string{"pkg", "etcupdate", "sysctl", "kldstat", "kldload", "pfctl", "uname", "rctl"} {
		if !seen[n] {
			t.Errorf("no rule for %s", n)
		}
	}
	// ifconfig is in the table only in the forms customIfconfig accepts: the
	// MTU and the host interfaces go through the net.* operations.
}

func TestExtendedCommandRules(t *testing.T) {
	e := newEnv(t)
	c := e.cfg
	ctx := context.Background()
	adm := WithAdmin(ctx, "alice")
	ok := func(ctx context.Context, bin string, argv ...string) {
		t.Helper()
		_, out, err := c.CheckCommandCtx(ctx, argv)
		if err != nil {
			t.Errorf("%q: %v", argv, err)
			return
		}
		if out[0] != bin || strings.Join(out[1:], "\x00") != strings.Join(argv[1:], "\x00") {
			t.Errorf("%q ran as %q", argv, out)
		}
	}
	bad := func(ctx context.Context, code api.Code, argv ...string) {
		t.Helper()
		_, _, err := c.CheckCommandCtx(ctx, argv)
		if !api.IsCode(err, code) {
			t.Errorf("%q: %v (want %s)", argv, err, code)
		}
	}
	// sysctl reads
	ok(ctx, "/sbin/sysctl", "sysctl", "-n", "kern.osrelease")
	ok(ctx, "/sbin/sysctl", "sysctl", "-n", "net.inet.ip.forwarding")
	ok(ctx, "/sbin/sysctl", "sysctl", "-n", "hw.ncpu")
	// The doctor reads the answer-off-link-probes switch of a shared IPv6 segment; nobody writes it through the helper.
	ok(ctx, "/sbin/sysctl", "sysctl", "-n", "net.inet6.icmp6.nd6_onlink_ns_rfc4861")
	bad(adm, api.CodeForbidden, "sysctl", "net.inet6.icmp6.nd6_onlink_ns_rfc4861=1")
	bad(adm, api.CodeForbidden, "sysctl", "-w", "net.inet6.icmp6.nd6_onlink_ns_rfc4861=1")
	for _, a := range [][]string{
		{"-n", "kern.securelevel"}, {"-n", "net.link.epair.q2"}, {"-n"}, {}, {"kern.osrelease"}, {"-a"}, {"-n", "kern.osrelease", "hw.ncpu"}, {"-n", "kern.osrelease=1"},
		{"-n", "../kern"}, {"-N", "kern.osrelease"}, {"-w", "net.inet.ip.forwarding=1"}, {"-n", ""}, {"-n", "kern.osrelease\n"},
		{"--", "-n", "kern.osrelease"}, {"-n", "-n"}, {"-f", "/etc/sysctl.conf"}, {"-n", "net.inet.ip.forwarding=1"},
	} {
		bad(ctx, api.CodeForbidden, append([]string{"sysctl"}, a...)...)
	}
	// sysctl writes: admin, allow-listed name, value 0 or 1
	for _, n := range []string{"net.inet6.ip6.forwarding", "net.inet.ip.forwarding"} {
		ok(adm, "/sbin/sysctl", "sysctl", n+"=1")
		ok(adm, "/sbin/sysctl", "sysctl", n+"=0")
		bad(ctx, api.CodeForbidden, "sysctl", n+"=1")
		bad(adm, api.CodeInvalid, "sysctl", n+"=2")
		bad(adm, api.CodeInvalid, "sysctl", n+"=")
		bad(adm, api.CodeInvalid, "sysctl", n+"=1;id")
		bad(adm, api.CodeInvalid, "sysctl", n+"=01")
		bad(adm, api.CodeInvalid, "sysctl", n+"=-1")
		bad(adm, api.CodeInvalid, "sysctl", n+"=1=1")
	}
	for _, a := range []string{"kern.securelevel=-1", "kern.securelevel=0", "security.jail.allow_raw_sockets=1", "net.inet.ip.forwarding", "=1",
		"hw.ncpu=1", "kern.osrelease=x", "net.inet.ip.forwarding =1", "-w"} {
		bad(adm, api.CodeForbidden, "sysctl", a)
	}
	bad(adm, api.CodeForbidden, "sysctl", "-n", "net.inet.ip.forwarding=1")
	bad(adm, api.CodeForbidden, "sysctl", "net.inet.ip.forwarding=1", "kern.securelevel=3")
	// kldstat / kldload
	for _, m := range KldModules {
		ok(ctx, "/sbin/kldstat", "kldstat", "-n", m)
		ok(ctx, "/sbin/kldload", "kldload", m)
	}
	if len(KldModules) != 12 {
		t.Errorf("module list changed: %v", KldModules)
	}
	for _, a := range [][]string{{"-n", "vmm"}, {"-n", "pf.ko"}, {"-n", "../pf"}, {"-n", "/boot/kernel/pf.ko"}, {"-m", "pf"}, {"-v"}, {}, {"-n"}, {"-n", "pf", "zfs"}, {"-q", "-q", "-n", "pf"}, {"-n", "-q", "pf"}, {"-n", "pf\n"}, {"-n", "PF"}} {
		bad(ctx, api.CodeForbidden, append([]string{"kldstat"}, a...)...)
	}
	for _, a := range [][]string{{"vmm"}, {"pf.ko"}, {"/boot/modules/evil.ko"}, {"-v", "pf"}, {}, {"pf", "zfs"}, {"-n", "pf"}, {"-q", "-n", "pf"}, {"../pf"}, {"linux64 "}} {
		bad(ctx, api.CodeForbidden, append([]string{"kldload"}, a...)...)
	}
	// uname
	for _, f := range []string{"-r", "-m", "-s"} {
		ok(ctx, "/usr/bin/uname", "uname", f)
	}
	for _, a := range [][]string{{"-a"}, {"-rm"}, {"-r", "-m"}, {}, {"-n"}, {"-p"}, {"-s", "x"}} {
		bad(ctx, api.CodeForbidden, append([]string{"uname"}, a...)...)
	}
	// rctl: the usage of one jail by its key, nothing else
	ok(ctx, "/usr/bin/rctl", "rctl", "-u", "jail:alpha_web")
	ok(ctx, "/usr/bin/rctl", "rctl", "-u", "jail:shop_api-v2")
	for _, a := range [][]string{
		{}, {"-u"}, {"-u", "jail:"}, {"-u", "alpha_web"}, {"-u", "jail:web"}, {"-u", "jail:alpha_web", "x"}, {"-hu", "jail:alpha_web"},
		{"-u", "-h", "jail:alpha_web"}, {"-u", "jail:alpha_web\n"}, {"-u", "jail:alpha_web;id"}, {"-u", "jail:alpha_web/x"}, {"-u", "jail:a_b_c"},
		{"-u", "process:1"}, {"-u", "user:0"}, {"-u", "loginclass:default"}, {"-u", ":"}, {"-u", "jail:Alpha_web"}, {"-u", "jail:1"},
		{"-l", "jail:alpha_web"}, {"-r", "jail:alpha_web"}, {"-a", "jail:alpha_web:maxproc:deny=10"}, {"-e", "jail:alpha_web"},
	} {
		_, _, err := c.CheckCommandCtx(adm, append([]string{"rctl"}, a...))
		if err == nil {
			t.Errorf("rctl %q accepted", a)
		}
	}
	// dnctl: the pipes of the bandwidth limits, in JailOps's own range only
	ok(ctx, "/sbin/dnctl", "dnctl", "pipe", "40000", "config", "bw", "0")
	ok(ctx, "/sbin/dnctl", "dnctl", "pipe", "59999", "config", "bw", "10000000bit/s")
	ok(ctx, "/sbin/dnctl", "dnctl", "pipe", "delete", "40001")
	ok(ctx, "/sbin/dnctl", "dnctl", "pipe", "list")
	for _, a := range [][]string{
		{"pipe", "39999", "config", "bw", "10000000bit/s"}, {"pipe", "60000", "config", "bw", "0"}, {"pipe", "1", "config", "bw", "0"},
		{"pipe", "040000", "config", "bw", "0"}, {"pipe", "-1", "config", "bw", "0"}, {"pipe", "40000", "config", "bw", "10M"},
		{"pipe", "40000", "config", "bw", "10Mbit/s"}, {"pipe", "40000", "config", "bw", "-5bit/s"}, {"pipe", "40000", "config", "bw", "tun0"},
		{"pipe", "40000", "config", "delay", "250ms"}, {"pipe", "40000", "config", "bw", "10000bit/s", "queue", "50"},
		{"pipe", "delete", "1"}, {"pipe", "delete", "all"}, {"pipe", "delete"}, {"pipe", "show"}, {"queue", "40000", "config", "bw", "0"},
		{"sched", "40000", "config", "type", "wf2q+"}, {"-f", "pipe", "list"}, {"flush"}, {},
	} {
		bad(ctx, api.CodeForbidden, append([]string{"dnctl"}, a...)...)
	}
	// pfctl: read-only, jailops anchors only
	ok(ctx, "/sbin/pfctl", "pfctl", "-s", "info")
	ok(ctx, "/sbin/pfctl", "pfctl", "-a", "jailops/web/nginx", "-s", "rules")
	ok(ctx, "/sbin/pfctl", "pfctl", "-s", "nat", "-a", "jailops/web/nginx")
	ok(ctx, "/sbin/pfctl", "pfctl", "-a", "jailops/shared.pf", "-s", "Tables")
	ok(ctx, "/sbin/pfctl", "pfctl", "-s", "rules")
	ok(ctx, "/sbin/pfctl", "pfctl", "-s", "nat")
	ok(ctx, "/sbin/pfctl", "pfctl", "-a", "jailops", "-s", "Anchors")
	ok(ctx, "/sbin/pfctl", "pfctl", "-a", "jailops/web", "-s", "Anchors")
	for _, a := range [][]string{
		{"-s", "Tables"}, {"-s", "Anchors"}, // no anchor: only info, rules and nat of the main ruleset are readable
		{"-a", "other", "-s", "rules"}, {"-a", "jailops/../x", "-s", "rules"}, {"-a", "jailopsX/x", "-s", "rules"}, {"-a", "/jailops/x", "-s", "rules"},
		{"-a", "", "-s", "rules"}, {"-s", "all"}, {"-s", "states"}, {"-s", "Sources"}, {"-s", "labels"}, {"-s", "info", "-s", "rules"},
		{"-a", "jailops/x", "-a", "jailops/y", "-s", "rules"}, {"-f", "/etc/pf.conf"}, {"-d"}, {"-e"}, {"-F", "all"}, {"-t", "x", "-T", "flush"},
		{"-s"}, {}, {"-a", "jailops/x"}, {"-a", "jailops/x", "-s", "rules", "-f", "/x"}, {"-a", "jailops/x", "-s", "rules", "extra"}, {"-sr"}, {"-vs", "rules"},
		{"-a", "jailops/x y", "-s", "rules"}, {"-a", "jailops/x\n", "-s", "rules"}, {"-n", "-f", "/etc/pf.conf"},
	} {
		_, _, err := c.CheckCommandCtx(adm, append([]string{"pfctl"}, a...))
		if err == nil {
			t.Errorf("pfctl %q accepted", a)
		}
	}
	// the others stay unreachable
	for _, n := range []string{"ifconfig", "route", "zfs", "jail", "jexec", "sh", "rm", "kldunload", "service", "mount", "umount", "sysctl.conf"} {
		bad(adm, api.CodeForbidden, n, "x")
	}
}

func TestRunnerRunsExtendedRulesWithFixedBinaries(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	adm := WithAdmin(ctx, "alice")
	r := e.local.Runner()
	e.runner.On("/sbin/kldload", []string{"if_epair"}, "")
	e.runner.On("/usr/bin/uname", []string{"-r"}, "15.0-RELEASE\n")
	e.runner.On("/sbin/sysctl", []string{"net.inet.ip.forwarding=1"}, "")
	e.runner.On("/sbin/pfctl", []string{"-a", "jailops/web/x", "-s", "rules"}, "pass\n")
	if _, err := r.Run(ctx, run.Cmd{Name: "kldload", Args: []string{"if_epair"}}); err != nil {
		t.Error(err)
	}
	if res, err := r.Run(ctx, run.Cmd{Name: "uname", Args: []string{"-r"}}); err != nil || string(res.Stdout) != "15.0-RELEASE\n" {
		t.Errorf("%q %v", res.Stdout, err)
	}
	if res, err := r.Run(ctx, run.Cmd{Name: "pfctl", Args: []string{"-a", "jailops/web/x", "-s", "rules"}}); err != nil || string(res.Stdout) != "pass\n" {
		t.Errorf("%q %v", res.Stdout, err)
	}
	if _, err := r.Run(ctx, run.Cmd{Name: "sysctl", Args: []string{"net.inet.ip.forwarding=1"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("sysctl write without admin: %v", err)
	}
	if _, err := r.Run(adm, run.Cmd{Name: "sysctl", Args: []string{"net.inet.ip.forwarding=1"}}); err != nil {
		t.Errorf("sysctl write with admin: %v", err)
	}
	if _, err := r.Run(ctx, run.Cmd{Name: "/sbin/kldload", Args: []string{"if_epair"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a caller named binary: %v", err)
	}
	for _, c := range e.runner.Calls() {
		if !filepath.IsAbs(c.Cmd.Name) {
			t.Errorf("relative binary %q reached the runner", c.Cmd.Name)
		}
	}
}

// rctl reads the usage of a jail JailOps configured; a key without a conf
// file never reaches the runner.
func TestRunnerReadsUsageOfManagedJailsOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r := e.local.Runner()
	const out = "maxproc=3\ncputime=7\nmemoryuse=4096\n"
	e.runner.On("/usr/bin/rctl", []string{"-u", run.AnyArg}, out)
	if _, err := r.Run(ctx, run.Cmd{Name: "rctl", Args: []string{"-u", "jail:alpha_ghost"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("unmanaged jail: %v", err)
	}
	e.conf(t, "alpha_web")
	res, err := r.Run(ctx, run.Cmd{Name: "rctl", Args: []string{"-u", "jail:alpha_web"}, Timeout: time.Hour})
	if err != nil || string(res.Stdout) != out {
		t.Fatalf("%q %v", res.Stdout, err)
	}
	calls := e.runner.Calls()
	if last := calls[len(calls)-1].Cmd; last.Name != "/usr/bin/rctl" || last.Timeout != 10*time.Second {
		t.Errorf("ran %+v", last)
	}
	for _, c := range calls {
		if strings.Contains(strings.Join(c.Cmd.Args, " "), "ghost") {
			t.Errorf("an unmanaged jail reached the runner: %+v", c.Cmd)
		}
	}
}

// The admin assertion travels with the request, so a sysctl write works
// through the socket only for an admin.
func TestSysctlWriteOverTheSocket(t *testing.T) {
	f := newFixture(t)
	f.runner.On("/sbin/sysctl", []string{"net.inet.ip.forwarding=0"}, "")
	cmd := run.Cmd{Name: "sysctl", Args: []string{"net.inet.ip.forwarding=0"}}
	if _, err := f.client.Runner().Run(context.Background(), cmd); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("without admin: %v", err)
	}
	if _, err := f.client.Runner().Run(WithAdmin(context.Background(), "alice"), cmd); err != nil {
		t.Errorf("with admin: %v", err)
	}
}

func TestSetMTU(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, _, err := e.net.EpairCreate(ctx, "jo0"); err != nil {
		t.Fatal(err)
	}
	e.runner.On("ifconfig", []string{"jo0a", "mtu", "1400"}, "")
	if err := e.local.SetMTU(ctx, "jo0a", 1400); err != nil {
		t.Fatal(err)
	}
	last := e.runner.Calls()[len(e.runner.Calls())-1].Cmd
	if last.Name != "ifconfig" || strings.Join(last.Args, " ") != "jo0a mtu 1400" {
		t.Errorf("ran %+v", last)
	}
	for _, c := range []struct {
		iface string
		mtu   int
	}{{"em0", 1400}, {"jo0a", 0}, {"jo0a", -1}, {"jo0a", 575}, {"jo0a", 9217}, {"jo0a", 1 << 40}, {"-x", 1400}, {"", 1400}, {"jo0a mtu 9", 1400}, {"jo", 1400}} {
		if err := e.local.SetMTU(ctx, c.iface, c.mtu); err == nil {
			t.Errorf("SetMTU(%q, %d) accepted", c.iface, c.mtu)
		}
	}
	// the Runner cannot do it
	if _, err := e.local.Runner().Run(ctx, run.Cmd{Name: "ifconfig", Args: []string{"jo0a", "mtu", "1400"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("ifconfig through the runner: %v", err)
	}
}

// A client that implements the proposed ifconfig.Client method is used.
type mtuNet struct {
	*ifconfig.Fake
	got string
}

func (m *mtuNet) SetMTU(_ context.Context, iface string, mtu int) error {
	m.got = iface + ":" + string(rune('0'+mtu%10))
	return nil
}

func TestSetMTUUsesTheInterfaceMethodWhenPresent(t *testing.T) {
	e := newEnv(t)
	m := &mtuNet{Fake: e.net}
	l, err := NewLocal(e.cfg, Deps{ZFS: e.zfs, Net: m, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.net.EpairCreate(context.Background(), "jo0"); err != nil {
		t.Fatal(err)
	}
	if err := l.SetMTU(context.Background(), "jo0a", 1500); err != nil || m.got != "jo0a:0" {
		t.Errorf("%q %v", m.got, err)
	}
	for _, c := range e.runner.Calls() {
		if c.Cmd.Name == "ifconfig" {
			t.Error("the runner was used")
		}
	}
}

func TestSetMTUOverTheSocket(t *testing.T) {
	f := newFixtureWith(t, func(e *env) {
		if _, _, err := e.net.EpairCreate(context.Background(), "jo0"); err != nil {
			t.Fatal(err)
		}
	})
	f.runner.On("ifconfig", []string{"jo0a", "mtu", "9000"}, "")
	if err := f.client.SetMTU(context.Background(), "jo0a", 9000); err != nil {
		t.Error(err)
	}
	if err := f.client.SetMTU(context.Background(), "em0", 9000); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("%v", err)
	}
}

func TestImageBuildingCommands(t *testing.T) {
	e := newEnv(t)
	c := e.cfg
	ctx := context.Background()
	root := filepath.Join(e.cfg.MountBase, "images", "freebsd-15", "g1", "root")
	work := filepath.Join(e.cfg.StateDir, "work")
	tar := filepath.Join(e.cfg.StateDir, "work", "etc.tar.xz")
	repos := filepath.Join(e.cfg.StateDir, "repos")
	for _, d := range []string{root, work, repos, filepath.Join(root, "etc")} {
		os.MkdirAll(d, 0o755)
	}
	mp := filepath.Join(work, "master.passwd")
	os.WriteFile(mp, []byte("root::0:0::0:0:r:/root:/bin/sh\n"), 0o600)
	ok := func(bin string, argv ...string) {
		t.Helper()
		_, out, err := c.CheckCommandCtx(ctx, argv)
		if err != nil || out[0] != bin {
			t.Errorf("%q: %v %q", argv, err, out)
		}
	}
	bad := func(argv ...string) {
		t.Helper()
		if _, _, err := c.CheckCommandCtx(WithAdmin(ctx, "a"), argv); err == nil {
			t.Errorf("accepted %q", argv)
		}
	}
	pkg := func(extra ...string) []string {
		return append([]string{"pkg", "-r", root, "-o", "REPOS_DIR=" + repos, "-o", "ASSUME_ALWAYS_YES=yes", "-o", "IGNORE_OSVERSION=yes", "-o", "ABI=FreeBSD:15:amd64"}, extra...)
	}
	for _, sub := range [][]string{{"install", "-y", "pkg"}, {"upgrade"}, {"query", "%n-%v"}, {"query", "%n-%v", "pkg"}, {"install", "nginx", "curl"}} {
		ok("/usr/sbin/pkg", pkg(sub...)...)
	}
	ok("/usr/sbin/pkg", "pkg", "config", "abi")
	bad("pkg", "config", "abi", "x")
	bad("pkg", "config", "repos")
	for _, o := range []string{"REPOS_DIR=/etc/pkg", "REPOS_DIR=" + root + "/../../..", "ASSUME_ALWAYS_YES=no", "IGNORE_OSVERSION=1", "ABI=;id", "ABI=", "PKG_DBDIR=/x",
		"ASSUME_ALWAYS_YES", "INSTALL_AS_USER=yes", "REPOS_DIR=relative", "ABI=a b"} {
		bad("pkg", "-r", root, "-o", o, "install", "x")
	}
	bad("pkg", "-o", "ABI=FreeBSD:15:amd64", "install", "x") // no -r
	bad("pkg", "-r", root, "query", "%n;id", "x")
	// etcupdate: subcommand before or after the flags
	ok("/usr/sbin/etcupdate", "etcupdate", "extract", "-d", work, "-t", tar, "-D", root)
	ok("/usr/sbin/etcupdate", "etcupdate", "-d", work, "-t", tar, "-D", root, "-L", filepath.Join(work, "log"))
	ok("/usr/sbin/etcupdate", "etcupdate", "-D", root, "-s", filepath.Join(root, "src"), "resolve")
	bad("etcupdate", "extract", "-d", work, "-t", tar)                 // no -D
	bad("etcupdate", "extract", "-d", "/tmp/x", "-t", tar, "-D", root) // work outside
	bad("etcupdate", "extract", "-d", work, "-t", "/etc/passwd", "-D", root)
	bad("etcupdate", "-D", root, "-L", "/var/log/x")
	bad("etcupdate", "-D", "/", "-d", work)
	bad("etcupdate", "-D", root, "-D", root)
	bad("etcupdate", "-D", root, "-p")
	bad("etcupdate", "-D", root, "extract", "extract")
	bad("etcupdate", "-D", root, "extract", "x")
	bad("etcupdate", "-D", root, "-t")
	bad("etcupdate", "-D", root, "-t", work+"/../../x")
	// pwd_mkdb
	ok("/usr/sbin/pwd_mkdb", "pwd_mkdb", "-p", "-d", filepath.Join(root, "etc"), mp)
	bad("pwd_mkdb", "-p", "-d", "/etc", mp)
	bad("pwd_mkdb", "-p", "-d", filepath.Join(root, "etc"), "/etc/master.passwd")
	bad("pwd_mkdb", "-p", "-d", filepath.Join(root, "etc"), filepath.Join(work, "shadow"))
	bad("pwd_mkdb", "-d", filepath.Join(root, "etc"), mp)
	bad("pwd_mkdb", "-p", "-d", filepath.Join(root, "etc"), mp, "x")
	bad("pwd_mkdb", "-u", "root", mp)
	// freebsd-version
	ok("/bin/freebsd-version", "freebsd-version", "-k")
	ok("/bin/freebsd-version", "freebsd-version", "-u")
	bad("freebsd-version", "-r")
	bad("freebsd-version")
	bad("freebsd-version", "-k", "-u")
	// a symlink in the work area cannot lead out of the roots
	os.Symlink("/etc", filepath.Join(work, "evil"))
	bad("etcupdate", "-D", root, "-L", filepath.Join(work, "evil", "log"))
}

func TestSeedKeys(t *testing.T) {
	e := newEnv(t)
	keys := filepath.Join(e.base, "hostkeys")
	os.MkdirAll(filepath.Join(keys, "pkg", "trusted"), 0o755)
	os.WriteFile(filepath.Join(keys, "pkg", "trusted", "pkg.freebsd.org.2013102301"), []byte("key"), 0o644)
	os.Symlink("pkg/trusted", filepath.Join(keys, "link"))
	l, err := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jexec: e.jexec, KeysDir: keys}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	root := filepath.Join(e.cfg.MountBase, "images", "x", "g1", "root")
	os.MkdirAll(root, 0o755)
	res, err := l.SeedKeys(ctx, root)
	if err != nil || res.Files != 1 || res.Symlinks != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "usr", "share", "keys", "pkg", "trusted", "pkg.freebsd.org.2013102301"))
	if string(b) != "key" {
		t.Errorf("key %q", b)
	}
	if res, err := l.SeedKeys(ctx, root); err != nil || res.Files != 0 {
		t.Errorf("not idempotent: %+v %v", res, err)
	}
	// hostile roots
	outside := filepath.Join(e.base, "outside")
	os.MkdirAll(outside, 0o755)
	os.MkdirAll(filepath.Join(e.cfg.MountBase, "images", "evil"), 0o755)
	os.Symlink(outside, filepath.Join(e.cfg.MountBase, "images", "evil", "usr"))
	for name, r := range map[string]string{"outside": "/etc", "mount root": e.cfg.MountBase, "relative": "images/x", "dotdot": e.cfg.MountBase + "/../x",
		"symlinked usr": filepath.Join(e.cfg.MountBase, "images", "evil"), "missing": filepath.Join(e.cfg.MountBase, "nope"), "empty": ""} {
		if _, err := l.SeedKeys(ctx, r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("written outside: %v", ents)
	}
	// missing host directory
	l2, _ := NewLocal(e.cfg, Deps{ZFS: e.zfs, KeysDir: filepath.Join(e.base, "nokeys")}, WithoutChown())
	root2 := filepath.Join(e.cfg.MountBase, "images", "y")
	os.MkdirAll(root2, 0o755)
	if _, err := l2.SeedKeys(ctx, root2); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("no host keys: %v", err)
	}
}

func TestSeedKeysOverTheSocket(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.cfg.MountBase, "images", "z", "root")
	os.MkdirAll(root, 0o755)
	// the fixture's helper reads the real host directory, which may not exist
	// here: only the refusal path is checked over the wire
	if _, err := f.client.SeedKeys(context.Background(), "/etc"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("%v", err)
	}
}
