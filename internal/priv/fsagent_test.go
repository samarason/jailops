package priv

import (
	"context"
	"io"
	"jailops.net/jailops/internal/render"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/fsagent"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// agentEnv makes a jail dataset with a backup snapshot below the storage root. The snapshot is made through the
// helper's ZFS guard, as a backup does: that is what authorises a read agent.
func agentEnv(t *testing.T) (*env, context.Context) {
	t.Helper()
	e := newEnv(t)
	ctx := WithAdmin(context.Background(), "alice")
	mp := filepath.Join(e.cfg.MountBase, "projects", "web", "jails", "nginx")
	if err := os.MkdirAll(mp, 0o755); err != nil {
		t.Fatal(err)
	}
	// created directly in the fake: a finished jail, not one the helper saw being created
	if err := e.zfs.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/projects/web/jails/nginx", Parents: true,
		Props: map[string]string{"jailops:managed": "on", "mountpoint": mp, "jailops:complete": "on", "mounted": "yes"}}); err != nil {
		t.Fatal(err)
	}
	g := e.local.ZFS()
	if err := g.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops/projects/web/jails/nginx@jailops-backup-20261022T100000-ab12"},
		Props: map[string]string{"jailops:managed": "on"}}); err != nil {
		t.Fatal(err)
	}
	if err := g.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops/projects/web/jails/nginx@manual"}}); err != nil {
		t.Fatal(err)
	}
	return e, ctx
}

func TestAgentReadRoots(t *testing.T) {
	e, ctx := agentEnv(t)
	mp := filepath.Join(e.cfg.MountBase, "projects", "web", "jails", "nginx")
	snap := func(name string) string { return mp + "/.zfs/snapshot/" + name }
	if _, err := e.local.checkAgentRoot(ctx, AgentRead, snap("jailops-backup-20261022T100000-ab12")); err != nil {
		t.Fatalf("a backup snapshot: %v", err)
	}
	bad := []string{
		snap("manual"),                        // not a backup snapshot name
		snap("jailops-backup-nope"),           // a name that no snapshot has
		snap("jailops-backup-1/../../etc"),    // dots
		mp,                                    // the live dataset
		mp + "/etc",                           // a directory inside
		"/etc/.zfs/snapshot/jailops-backup-x", // outside the storage root
		filepath.Join(e.cfg.MountBase, "..", "x", ".zfs", "snapshot", "jailops-backup-1"),
		"relative/.zfs/snapshot/jailops-backup-1",
		"",
	}
	for _, r := range bad {
		if _, err := e.local.checkAgentRoot(ctx, AgentRead, r); err == nil {
			t.Errorf("a read agent was allowed in %q", r)
		}
	}
	// A snapshot named like a backup's, made by the daemon with every property set to look right: the daemon can
	// set any user property on its own datasets, so properties prove nothing. Made behind the helper's back (the
	// fake directly), the helper never saw it asked for as a backup's.
	if err := e.zfs.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops/projects/web/jails/nginx@jailops-backup-forged"}, Props: map[string]string{"jailops:managed": "on"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.local.checkAgentRoot(ctx, AgentRead, snap("jailops-backup-forged")); err == nil {
		t.Error("a snapshot with the right name and properties, that the helper did not make for a backup, was readable")
	}
	// a snapshot made through the helper without the backup property is not a backup's either
	if err := e.local.ZFS().Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops/projects/web/jails/nginx@jailops-backup-plain"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.local.checkAgentRoot(ctx, AgentRead, snap("jailops-backup-plain")); err == nil {
		t.Error("a snapshot without jailops:managed=on was readable")
	}
	// destroying the snapshot ends the grant
	if err := e.local.ZFS().Destroy(ctx, "tank/jailops/projects/web/jails/nginx@jailops-backup-20261022T100000-ab12", zfs.DestroyOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.local.checkAgentRoot(ctx, AgentRead, snap("jailops-backup-20261022T100000-ab12")); err == nil {
		t.Error("a destroyed snapshot was readable")
	}
	// no admin assertion, no agent
	if _, err := e.local.checkAgentRoot(context.Background(), AgentRead, snap("jailops-backup-plain")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("without the admin assertion: %v", err)
	}
}

func TestAgentWriteRoots(t *testing.T) {
	e, ctx := agentEnv(t)
	mp := filepath.Join(e.cfg.MountBase, "projects", "web", "jails", "nginx")
	// A finished jail is never written through an agent, whatever its properties say.
	if _, err := e.local.checkAgentRoot(ctx, AgentWrite, mp); err == nil {
		t.Fatal("a finished jail was writable through an agent")
	}
	if err := e.zfs.Set(ctx, "tank/jailops/projects/web/jails/nginx", map[string]string{"jailops:complete": "off"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.local.checkAgentRoot(ctx, AgentWrite, mp); err == nil {
		t.Fatal("setting jailops:complete=off on a finished jail made it writable: the daemon can set any user property")
	}
	// A dataset the helper saw created incomplete is writable until it is marked complete; so are its children.
	g := e.local.ZFS()
	mp2 := filepath.Join(e.cfg.MountBase, "projects", "web", "jails", "web2")
	if err := os.MkdirAll(filepath.Join(mp2, "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := g.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/projects/web/jails/web2", Props: map[string]string{"jailops:managed": "on", "jailops:complete": "off", "mountpoint": mp2}}); err != nil {
		t.Fatal(err)
	}
	_ = e.zfs.Set(ctx, "tank/jailops/projects/web/jails/web2", map[string]string{"mounted": "yes"}) // what ZFS reports once it is mounted
	if err := g.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/projects/web/jails/web2/root", Props: map[string]string{"jailops:managed": "on", "mountpoint": filepath.Join(mp2, "root")}}); err != nil {
		t.Fatal(err)
	}
	_ = e.zfs.Set(ctx, "tank/jailops/projects/web/jails/web2/root", map[string]string{"mounted": "yes"})
	for _, r := range []string{mp2, filepath.Join(mp2, "root")} {
		if _, err := e.local.checkAgentRoot(ctx, AgentWrite, r); err != nil {
			t.Fatalf("a jail being restored, %s: %v", r, err)
		}
	}
	if err := g.Set(ctx, "tank/jailops/projects/web/jails/web2", map[string]string{"jailops:complete": "on"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.local.checkAgentRoot(ctx, AgentWrite, mp2); err == nil {
		t.Fatal("a jail marked complete was still writable")
	}
	if _, err := e.local.checkAgentRoot(ctx, AgentWrite, filepath.Join(mp2, "root")); err == nil {
		t.Fatal("its child was still writable")
	}
	for _, r := range []string{e.cfg.MountBase, filepath.Join(mp, "etc"), "/", "/etc", filepath.Join(e.cfg.MountBase, "nothing")} {
		if _, err := e.local.checkAgentRoot(ctx, AgentWrite, r); err == nil {
			t.Errorf("a write agent was allowed in %q", r)
		}
	}
	if _, err := e.local.checkAgentRoot(ctx, "both", mp); err == nil {
		t.Error("an unknown mode")
	}
}

// A re-executed test binary stands in for jailops-priv: "fsagent" as the first argument makes it serve the
// agent in the directory it is given, without the chroot only root can do (cmd/jailops-priv does the chroot).
func init() {
	if len(os.Args) > 5 && os.Args[1] == AgentSubcommand {
		f := os.NewFile(3, "agent")
		conn, err := net.FileConn(f)
		if err != nil {
			os.Exit(2)
		}
		special := len(os.Args) > 6 && os.Args[6] == AgentSpecialFlag
		err = fsagent.Serve(conn, fsagent.Config{Mode: fsagent.Mode(os.Args[3]), Root: os.Args[5], Special: special})
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func TestFSAgentThroughTheSocket(t *testing.T) {
	e, ctx := agentEnv(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner, AgentBinary: exe}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	e.local = l
	// the snapshot the backup asked this helper for
	if err := l.ZFS().Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops/projects/web/jails/nginx@jailops-backup-20261022T100000-ab12x"},
		Props: map[string]string{"jailops:managed": "on"}}); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(e.cfg.MountBase, "projects", "web", "jails", "nginx")
	snap := mp + "/.zfs/snapshot/jailops-backup-20261022T100000-ab12x"
	mustWrite(t, filepath.Join(snap, "etc", "motd"), "welcome\n")
	f := e.serve(t, selfPeers())
	c, err := Dial(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	file, err := c.FSAgent(ctx, AgentRead, snap)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	agent := fsagent.NewClient(conn)
	names, err := agent.ReadNames("/etc")
	if err != nil || len(names) != 1 || names[0] != "motd" {
		t.Fatalf("the agent listed %v, %v", names, err)
	}
	rc, err := agent.Open("/etc/motd")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "welcome\n" {
		t.Fatalf("read %q", b)
	}
	agent.Close()

	// the helper refuses what checkAgentRoot refuses, over the socket as well
	if _, err := c.FSAgent(ctx, AgentRead, mp); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("the live dataset: %v", err)
	}
	if _, err := c.FSAgent(context.Background(), AgentRead, snap); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("without the admin assertion: %v", err)
	}
}

// An image build writes its repository configuration below the daemon's work directory, through the helper.
func TestWorkDirIsWritableThroughTheHelper(t *testing.T) {
	e := newEnv(t)
	work := filepath.Join(e.base, "var", "tmp", "jailops")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	e.cfg.WorkDir = work
	l, err := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p := filepath.Join(work, "freebsd15-g1", "repos", "jailops.conf")
	if err := l.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("x"), Mode: 0o644, Parents: true}); err != nil {
		t.Fatalf("the work directory: %v", err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "x" {
		t.Fatalf("%q %v", b, err)
	}
	if err := l.WriteFile(ctx, WriteFileReq{Path: filepath.Join(e.base, "elsewhere"), Data: []byte("x"), Mode: 0o644}); err == nil {
		t.Fatal("a path outside every root was written")
	}
}

func TestRemoveAllOnlyWhereTreesAreScratch(t *testing.T) {
	e := newEnv(t)
	work := filepath.Join(e.base, "var", "tmp", "jailops")
	e.cfg.WorkDir = work
	l, err := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	build := filepath.Join(work, "freebsd15-g1")
	mustWrite(t, filepath.Join(build, "repos", "jailops.conf"), "x")
	mustWrite(t, filepath.Join(build, "rootfs.tar"), "y")
	if err := l.RemoveAll(ctx, build); err != nil {
		t.Fatalf("a build's work tree: %v", err)
	}
	if _, err := os.Stat(build); err == nil {
		t.Fatal("it is still there")
	}
	if err := l.RemoveAll(ctx, build); err != nil {
		t.Fatalf("removing what is gone: %v", err)
	}
	if err := l.RemoveAll(ctx, work); err == nil {
		t.Error("the work directory itself was removed")
	}
	// a jail's stage directory yes, the jail's files no
	jail := filepath.Join(e.cfg.MountBase, "projects", "web", "jails", "nginx")
	mustWrite(t, filepath.Join(jail, ".seed-etc", "a", "b"), "z")
	mustWrite(t, filepath.Join(jail, "root", "etc", "passwd"), "z")
	if err := l.RemoveAll(ctx, filepath.Join(jail, ".seed-etc")); err != nil {
		t.Fatalf("a seed stage: %v", err)
	}
	if err := l.RemoveAll(ctx, filepath.Join(jail, "root")); err == nil {
		t.Error("a jail's root with files in it was removed")
	}
	if _, err := os.Stat(filepath.Join(jail, "root", "etc", "passwd")); err != nil {
		t.Error("and its files are gone")
	}
	if err := l.RemoveAll(ctx, filepath.Join(e.base, "elsewhere")); err == nil {
		t.Error("a path outside every root")
	}
}

func TestOwnDirectoriesMustBeRootsAndPlain(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "work")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	c := Config{WorkDir: link}
	if err := c.checkOwnRoot(link); err == nil {
		t.Error("a work directory that is a symlink to / was accepted")
	}
	c = Config{WorkDir: real}
	if os.Geteuid() != 0 {
		if err := c.checkOwnRoot(real); err == nil {
			t.Error("a work directory owned by an ordinary user was accepted")
		}
	}
	if err := (Config{WorkDir: real, noOwnerCheck: true}).checkOwnRoot(real); err != nil {
		t.Errorf("the test switch: %v", err)
	}
	// other roots (storage mountpoints) are not the helper's own
	if err := (Config{WorkDir: real}).checkOwnRoot(dir); err != nil {
		t.Errorf("a storage root: %v", err)
	}
}

func TestDevfsUnhideIsAllowListed(t *testing.T) {
	c := Config{}
	rule := func(tail ...string) []string { return append([]string{"rule", "-s", "5001", "add"}, tail...) }
	for _, ok := range [][]string{rule("path", "tun*", "unhide"), rule("path", "null", "unhide"), rule("hide"), rule("path", "dri/*", "unhide")} {
		if err := customDevfs(c, false, ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][]string{rule("unhide"), rule("path", "mem", "unhide"), rule("path", "*", "unhide"), rule("path", "kmem", "unhide"), rule("path", "ada*", "unhide")} {
		if err := customDevfs(c, false, bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestPkgRepositoryConfIsChecked(t *testing.T) {
	l := &Local{}
	good := "jailops: {\n  url: \"pkg+https://pkg.FreeBSD.org/${ABI}/base_latest\",\n  mirror_type: \"srv\",\n  signature_type: \"fingerprints\",\n  fingerprints: \"/usr/share/keys/pkgbase-${VERSION_MAJOR}\",\n  enabled: yes\n}\n"
	if err := l.checkRepoConf("a.conf", good); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unsigned":   strings.Replace(good, "fingerprints\"", "none\"", 1),
		"file url":   strings.Replace(good, "pkg+https://", "file://", 1),
		"extra key":  strings.Replace(good, "enabled: yes", "enabled: yes\n  pubkey: \"/etc/shadow\"", 1),
		"bad keys":   strings.Replace(good, "/usr/share/keys/pkgbase-${VERSION_MAJOR}", "/etc/ssl", 1),
		"stray line": good + "evil\n",
	} {
		if err := l.checkRepoConf("a.conf", body); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestStateDirectoryIsReadAsUntrusted(t *testing.T) {
	state, secret := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(secret, "s"), []byte("secret"), 0o600)
	os.WriteFile(filepath.Join(state, "ok.json"), []byte("{}"), 0o600)
	os.Symlink(filepath.Join(secret, "s"), filepath.Join(state, "evil.json"))
	os.Symlink(secret, filepath.Join(state, "dir"))
	l := &Local{cfg: Config{StateDir: state}}
	if b, err := l.readState(filepath.Join(state, "ok.json")); err != nil || string(b) != "{}" {
		t.Fatalf("%q %v", b, err)
	}
	for _, p := range []string{"evil.json", "dir/s"} {
		if b, err := l.readState(filepath.Join(state, p)); err == nil {
			t.Errorf("%s read through a symlink: %q", p, b)
		}
	}
	if _, err := l.readState("/etc/passwd"); err == nil {
		t.Error("read outside")
	}
}

func TestChmodRefusesSymlinks(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(d, "f"), nil, 0o600)
	os.Symlink("/etc", filepath.Join(d, "etc"))
	os.Symlink(filepath.Join(d, "f"), filepath.Join(d, "l"))
	if err := verifyChmod(context.Background(), nil, []string{"755", filepath.Join(d, "f")}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"l", "etc", "etc/passwd"} {
		if err := verifyChmod(context.Background(), nil, []string{"755", filepath.Join(d, p)}); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

func TestDebootstrapAlwaysChecksTheSignature(t *testing.T) {
	r := newRuleEnv(t)
	root := r.cfg.reg.mounts()[0] + "/images/deb/staging-g1"
	admin := WithAdmin(context.Background(), "jailopsd")
	good := []string{"debootstrap", "--arch=arm64", "--variant=minbase", "--keyring=" + r.cfg.KeyringDir + "/debian-archive-keyring.gpg", "trixie", root, "https://deb.debian.org/debian"}
	if err := r.check(admin, good...); err != nil {
		t.Fatal(err)
	}
	if err := r.check(context.Background(), good...); err == nil {
		t.Error("accepted without the admin assertion")
	}
	for name, args := range map[string][]string{
		"no keyring":   {"debootstrap", "--arch=arm64", "--variant=minbase", "trixie", root},
		"no gpg check": {"debootstrap", "--arch=arm64", "--variant=minbase", "--no-check-gpg", "trixie", root},
		"http mirror":  {"debootstrap", "--arch=arm64", "--variant=minbase", "--keyring=" + r.cfg.KeyringDir + "/k.gpg", "trixie", root, "http://deb.debian.org/debian"},
		"bad keyring":  {"debootstrap", "--arch=arm64", "--variant=minbase", "--keyring=/etc/shadow", "trixie", root},
		"bad target":   {"debootstrap", "--arch=arm64", "--variant=minbase", "--keyring=" + r.cfg.KeyringDir + "/k.gpg", "trixie", "/etc"},
		"extra flag":   {"debootstrap", "--arch=arm64", "--variant=minbase", "--keyring=" + r.cfg.KeyringDir + "/k.gpg", "--include=evil", "trixie", root},
	} {
		if err := r.check(admin, args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Every rule JailOps renders for a jail's devfs ruleset is inside the helper's devfs grammar, and a rule outside it
// is refused: the hook validates what it runs.
func TestRenderedDevfsRulesAreInTheHelpersGrammar(t *testing.T) {
	c := Config{}
	check := func(rules [][]string) {
		t.Helper()
		for _, r := range rules {
			if err := customDevfs(c, true, r[1:]); err != nil {
				t.Errorf("%v refused: %v", r, err)
			}
		}
	}
	_, lin, err := render.LinuxDevfsRuleset([]string{"tun", "dri"})
	if err != nil {
		t.Fatal(err)
	}
	check(lin)
	_, fb, err := render.DevfsRuleset([]string{"tun", "bpf", "pf"})
	if err != nil {
		t.Fatal(err)
	}
	check(fb)
	for _, bad := range [][]string{
		{"rule", "-s", "5001", "add", "path", "mem", "unhide"},
		{"rule", "-s", "5001", "add", "path", "*", "unhide"},
		{"rule", "-s", "5001", "add", "unhide"},
		{"rule", "-s", "4", "add", "hide"},
		{"rule", "-s", "5001", "delset", "x"},
		{"rule", "-s", "5001", "add", "path", "../mem", "unhide"},
	} {
		if err := customDevfs(c, true, bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestJailConfQuotedValuesRefuseBackslash(t *testing.T) {
	for _, bad := range []string{`"a\"`, `"a\\b"`, `"x;y"`, `"$x"`} {
		if quotedRE.MatchString(bad) {
			t.Errorf("%s accepted", bad)
		}
	}
	if !quotedRE.MatchString(`"fine value"`) {
		t.Error("a plain value was refused")
	}
}

func TestAFrozenDirectoryCannotBeChanged(t *testing.T) {
	l := &Local{}
	done := l.freeze("/work/repos")
	for _, p := range []string{"/work/repos", "/work/repos/a.conf", "/work"} {
		if err := l.checkFrozen(p); err == nil {
			t.Errorf("%s may be changed while frozen", p)
		}
	}
	if err := l.checkFrozen("/work/other"); err != nil {
		t.Errorf("an unrelated path is refused: %v", err)
	}
	done()
	if err := l.checkFrozen("/work/repos/a.conf"); err != nil {
		t.Errorf("still frozen: %v", err)
	}
	if d := reposDirOf([]string{"-r", "/x", "-o", "ABI=a", "-o", "REPOS_DIR=/work/repos", "install"}); d != "/work/repos" {
		t.Errorf("reposDirOf = %q", d)
	}
}
