package main

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	runfake "jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// useFakeSystem replaces the real helper by one over fakes. The datasets map
// is dataset -> mountpoint; each is created with jailops:managed=on.
func useFakeSystem(t *testing.T, datasets map[string]string) *zfs.Fake {
	t.Helper()
	fz := zfs.NewFake("tank")
	for ds, mp := range datasets {
		err := fz.Create(context.Background(), zfs.CreateOpts{Name: ds, Parents: true, Props: map[string]string{"jailops:managed": "on", "mountpoint": mp}})
		if err != nil {
			t.Fatal(err)
		}
	}
	old := newSystem
	newSystem = func(cfg priv.Config) (*priv.Local, error) {
		return priv.NewLocal(cfg, priv.Deps{ZFS: fz, Jails: jailos.NewFake(), PF: pfctl.NewFake(),
			Net: ifconfig.NewFake(ifconfig.Options{}), Runner: runfake.NewFake()}, priv.WithoutChown())
	}
	t.Cleanup(func() { newSystem = old })
	return fz
}

func runArgs(t *testing.T, euid int, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, euid)
	return code, out.String(), errb.String()
}

func emptyConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "empty.conf")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVersion(t *testing.T) {
	code, out, _ := runArgs(t, 1000, "-config", emptyConfig(t), "version")
	if code != 0 || !strings.HasPrefix(out, "jailops-priv ") || !strings.Contains(out, "protocol 1") {
		t.Errorf("%d %q", code, out)
	}
}

// Help and the version flag answer on standard output with exit 0 and read no configuration; init checks its
// arguments before it asks for root.
func TestHelpAndVersionFlags(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.conf")
	for _, args := range [][]string{{"-h"}, {"--help"}, {"-config", missing, "-help"}} {
		code, out, errs := runArgs(t, 1000, args...)
		if code != 0 || errs != "" || !strings.Contains(out, "usage: jailops-priv [flags] | version | check-config | init -pool POOL") || !strings.Contains(out, "-storage-root") {
			t.Errorf("%v: %d %q %q", args, code, out, errs)
		}
	}
	for _, args := range [][]string{{"--version"}, {"-version", "-config", missing}} {
		if code, out, _ := runArgs(t, 1000, args...); code != 0 || !strings.HasPrefix(out, "jailops-priv ") {
			t.Errorf("%v: %d %q", args, code, out)
		}
	}
	code, out, errs := runArgs(t, 1000, "init", "--help")
	if code != 0 || errs != "" || !strings.Contains(out, "usage: jailops-priv init -pool POOL") || !strings.Contains(out, "-dry-run") {
		t.Errorf("init --help: %d %q %q", code, out, errs)
	}
	for _, args := range [][]string{{"init"}, {"init", "-pool", "tank/x"}, {"init", "-pool", "tank", "-mount", "relative"}} {
		if code, _, errs := runArgs(t, 1000, args...); code != 2 || strings.Contains(errs, "must run as root") || !strings.Contains(errs, "usage:") {
			t.Errorf("%v: %d %q", args, code, errs)
		}
	}
	if code, _, errs := runArgs(t, 1000, "init", "-pool", "tank"); code != 1 || !strings.Contains(errs, "must run as root") {
		t.Errorf("init as a user: %d %q", code, errs)
	}
	if code, _, errs := runArgs(t, 0, "-config", emptyConfig(t), "frobnicate"); code != 2 || !strings.Contains(errs, "usage: jailops-priv [flags]") {
		t.Errorf("unknown command: %d %q", code, errs)
	}
}

func TestRefusesToRunWithoutRoot(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-config", emptyConfig(t), "-storage-root", "tank/jailops", "-mount-base", dir}
	code, _, errs := runArgs(t, 1000, args...)
	if code != 1 || !strings.Contains(errs, "must run as root") {
		t.Errorf("%d %q", code, errs)
	}
	code, _, errs = runArgs(t, 1000, append(args, "hook", "prestart", "web")...)
	if code != 1 || !strings.Contains(errs, "must run as root") {
		t.Errorf("hook as a user: %d %q", code, errs)
	}
}

func TestConfigErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "priv.conf")
	for name, c := range map[string]string{
		"unknown key": "bogus = 1\n",
		"no equals":   "storage-root tank/jailops\n",
		"bad value":   "dev = maybe\n",
	} {
		os.WriteFile(cfg, []byte(c), 0o644)
		if code, _, errs := runArgs(t, 0, "-config", cfg, "version"); code != 2 || errs == "" {
			t.Errorf("%s: %d %q", name, code, errs)
		}
	}
	// a missing explicit config is an error, the missing default is not
	if code, _, _ := runArgs(t, 0, "-config", filepath.Join(dir, "missing.conf"), "version"); code != 2 {
		t.Errorf("missing explicit config: %d", code)
	}
	// the dataset must live below a pool, the mount base must be absolute
	if code, _, errs := runArgs(t, 0, "-config", cfg+"x", "-storage-root", "tank", "-mount-base", "/jo"); code != 2 {
		t.Errorf("pool as root: %d %q", code, errs)
	}
	os.WriteFile(cfg, []byte("# comment\nstorage-root = tank/jailops\nmount-base = \"/jo\"\nallow-user = a, b\n"), 0o644)
	// no allowed peer: serving is refused
	os.WriteFile(cfg, []byte("storage-root = tank/jailops\nmount-base = /jo\n"), 0o644)
	if code, _, errs := runArgs(t, 0, "-config", cfg, "-socket", filepath.Join(dir, "s")); code != 2 || !strings.Contains(errs, "no allowed peer") {
		t.Errorf("no peers: %d %q", code, errs)
	}
	if code, _, errs := runArgs(t, 0, "-config", cfg, "-allow-user", "root", "-mode", "0666", "-socket", filepath.Join(dir, "s")); code != 2 || !strings.Contains(errs, "mode") {
		t.Errorf("world accessible socket: %d %q", code, errs)
	}
	if code, _, _ := runArgs(t, 0, "-config", cfg, "frobnicate"); code != 2 {
		t.Errorf("unknown subcommand: %d", code)
	}
}

func TestServeDevAndShutdown(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	sockDir, err := os.MkdirTemp("", "jos")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "priv.sock")
	pid := filepath.Join(dir, "priv.pid")
	mount := filepath.Join(dir, "jailops")
	os.MkdirAll(mount, 0o755)
	os.WriteFile(filepath.Join(mount, "hello"), []byte("hi"), 0o644)
	useFakeSystem(t, map[string]string{"tank/jailops": mount})

	var out, errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"-dev", "-config", emptyConfig(t), "-socket", sock, "-pidfile", pid,
			"-storage-root", "tank/jailops", "-state-dir", filepath.Join(mount, "state"), "-storage-file", filepath.Join(dir, "priv.d", "storage.conf"),
			"-conf-dir", filepath.Join(dir, "conf"),
			"-allow-user", cur.Username, "-group", ""}, &out, &errb, os.Geteuid())
	}()
	var c *priv.Client
	for i := 0; i < 100; i++ {
		if c, err = priv.Dial(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v\n%s", err, errb.String())
	}
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v %v", st, err)
	}
	if b, err := os.ReadFile(pid); err != nil || len(b) == 0 {
		t.Errorf("pidfile %q %v", b, err)
	}
	b, err := c.ReadFile(context.Background(), filepath.Join(mount, "hello"))
	if err != nil || string(b) != "hi" {
		t.Errorf("read through the helper: %q %v", b, err)
	}
	if _, err := c.ReadFile(context.Background(), "/etc/passwd"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("outside the roots: %v", err)
	}
	c.Close()
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d\n%s", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no clean shutdown")
	}
	if _, err := os.Stat(sock); err == nil {
		t.Error("socket left behind")
	}
	if _, err := os.Stat(pid); err == nil {
		t.Error("pidfile left behind")
	}
	if !strings.Contains(errb.String(), "priv.start") || !strings.Contains(errb.String(), "priv.stop") {
		t.Errorf("log: %s", errb.String())
	}
}

func TestSecondInstanceIsRefused(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("the current user cannot be determined: " + err.Error())
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	sockDir, _ := os.MkdirTemp("", "jos")
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "priv.sock")
	useFakeSystem(t, map[string]string{"tank/jailops": dir})
	args := []string{"-dev", "-config", emptyConfig(t), "-socket", sock, "-storage-root", "tank/jailops",
		"-mount-base", dir, "-allow-user", cur.Username, "-group", ""}
	done := make(chan int, 1)
	go func() { var o, e bytes.Buffer; done <- run(args, &o, &e, os.Geteuid()) }()
	for i := 0; i < 100; i++ {
		if c, err := priv.Dial(sock); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	code, _, errs := runArgs(t, os.Geteuid(), args...)
	if code != 1 || !strings.Contains(errs, "another jailops-priv") {
		t.Errorf("%d %q", code, errs)
	}
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	<-done
}

func TestCheckConfigPrintsEffectiveConfiguration(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	mount := filepath.Join(dir, "jo")
	os.MkdirAll(mount, 0o700)
	useFakeSystem(t, map[string]string{"tank/jailops": mount})
	os.MkdirAll(filepath.Join(dir, "priv.d"), 0o700) // the storage file is not in a directory above a root
	sf := filepath.Join(dir, "priv.d", "storage.conf")
	os.WriteFile(sf, []byte("root = tank/missing\n"), 0o600)
	code, out, errs := runArgs(t, 1000, "-config", emptyConfig(t), "-storage-root", "tank/jailops", "-storage-file", sf,
		"-state-dir", filepath.Join(dir, "st"), "-sysctl", "hw.model", "-admin-allow-flag", "mount.zfs", "check-config")
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	for _, want := range []string{"tank/jailops mount=" + mount + " active (priv.conf)", "tank/missing", "inactive (registered)",
		"/sbin/kldload", "/sbin/pfctl", "linprocfs", "hw.model", "net.inet.ip.forwarding", "mount.zfs", "sysctl write (admin only)", "kern.elf64.fallback_brand", "dl-cdn.alpinelinux.org", "/usr/bin/fetch", "image mirror"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errs, "1 storage root(s) inactive") {
		t.Errorf("no warning: %q", errs)
	}
	// invalid configuration is exit 2
	for name, args := range map[string][]string{
		"pool root":   {"-storage-root", "tank"},
		"nested":      {"-storage-root", "tank/a", "-storage-root", "tank/a/b"},
		"no state":    {},
		"bad storage": {"-storage-file", "relative"},
	} {
		a := append([]string{"-config", emptyConfig(t)}, args...)
		if name != "no state" {
			a = append(a, "-state-dir", "/x")
		}
		if code, _, _ := runArgs(t, 0, append(a, "check-config")...); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	// a corrupt storage file is exit 2
	os.WriteFile(sf, []byte("garbage\n"), 0o600)
	if code, _, _ := runArgs(t, 0, "-config", emptyConfig(t), "-storage-file", sf, "-state-dir", "/x", "check-config"); code != 2 {
		t.Errorf("corrupt storage file: %d", code)
	}
	// a configuration file others can write is refused
	bad := filepath.Join(dir, "bad.conf")
	os.WriteFile(bad, nil, 0o666)
	os.Chmod(bad, 0o666)
	if code, _, errs := runArgs(t, 0, "-config", bad, "-state-dir", "/x", "check-config"); code != 2 || !strings.Contains(errs, "writable") {
		t.Errorf("writable config: %d %q", code, errs)
	}
}

func TestRegisterOverTheSocketAndSIGHUP(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	sockDir, _ := os.MkdirTemp("", "jos")
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "priv.sock")
	m1, m2 := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.MkdirAll(m1, 0o755)
	os.MkdirAll(m2, 0o755)
	useFakeSystem(t, map[string]string{"tank/a": m1, "tank/b": m2})
	sf := filepath.Join(dir, "priv.d", "storage.conf")
	var out, errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"-dev", "-config", emptyConfig(t), "-socket", sock, "-storage-root", "tank/a", "-state-dir", filepath.Join(m1, "state"),
			"-storage-file", sf, "-conf-dir", filepath.Join(dir, "conf"), "-allow-user", cur.Username, "-group", ""}, &out, &errb, os.Geteuid())
	}()
	var c *priv.Client
	for i := 0; i < 100; i++ {
		if c, err = priv.Dial(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v\n%s", err, errb.String())
	}
	defer c.Close()
	ctx := context.Background()
	if err := c.RegisterStorage(ctx, "tank/b"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("register without the admin assertion: %v", err)
	}
	if err := c.RegisterStorage(priv.WithAdmin(ctx, "alice"), "tank/b"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Storages(ctx); strings.Join(got, ",") != "tank/a,tank/b" {
		t.Errorf("storages %v", got)
	}
	if st, err := os.Stat(sf); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("storage file %v %v", st, err)
	}
	// An operator edit is picked up on SIGHUP.
	os.WriteFile(sf, []byte("# edited\n"), 0o600)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	ok := false
	for i := 0; i < 100 && !ok; i++ {
		got, _ := c.Storages(ctx)
		ok = strings.Join(got, ",") == "tank/a"
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Error("SIGHUP did not reload the storage file")
	}
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d\n%s", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no clean shutdown")
	}
}
