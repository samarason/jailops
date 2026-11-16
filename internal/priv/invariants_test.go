package priv

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"jailops.net/jailops/internal/fsagent"
	"jailops.net/jailops/internal/repo/catalog"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// The invariants below keep the files of jails (setuid programs among them) out of reach of the daemon's user and
// every other user of the host, and keep the helper from writing system files. Each row names one; a change that
// breaks one fails here, whatever else it changes. The reasoning is in docs/security-model.md ("Files inside jails"
// and "Storage roots").
func TestHelperSecurityInvariants(t *testing.T) {
	for _, inv := range []struct {
		name  string
		check func(t *testing.T)
	}{
		{"no dataset is mounted on a storage root's own directory", invMountpointNeverARoot},
		{"a storage root's directory belongs to root with mode 0700", invRootDirSealed},
		{"a storage root's mountpoint overlaps no system path or helper directory, in either direction", invRootOverlap},
		{"a storage root is never unmounted, remounted or moved through the helper", invRootStaysMounted},
		{"devices is off on every storage root and cannot be turned on", invDevicesOff},
		{"a received stream sets none of the guarded properties", invReceiveSetsNoProps},
		{"a write agent makes device nodes and setuid files only in a tree a jail controls", invAgentSpecialOnlyInJailTrees},
	} {
		t.Run(inv.name, inv.check)
	}
}

// Mounted over a root's directory, a dataset brings its own mode (0755 by default) and opens every jail below.
func invMountpointNeverARoot(t *testing.T) {
	e := newEnv(t)
	ctx := WithAdmin(context.Background(), "alice")
	g := e.local.ZFS()
	root := e.cfg.MountBase
	e.managedDS("tank/jailops/a")
	if err := g.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops/a@s"}}); err != nil {
		t.Fatal(err)
	}
	over := map[string]string{"mountpoint": root}
	for name, err := range map[string]error{
		"create":  g.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/pwn", Props: over}),
		"set":     g.Set(ctx, "tank/jailops/a", over),
		"clone":   g.Clone(ctx, "tank/jailops/a@s", "tank/jailops/c", over, false),
		"receive": g.Receive(ctx, zfs.ReceiveOpts{Target: "tank/jailops/r", Props: over}, strings.NewReader("")),
		"encrypted volume": e.local.CreateEncrypted(ctx, zfs.CreateOpts{Name: "tank/jailops/a/v",
			Props: map[string]string{"mountpoint": root, "jailops:managed": "on", "jailops:kind": "volume"}}, []byte("a passphrase of length")),
	} {
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s with mountpoint=%s: %v", name, root, err)
		}
	}
	// through the socket as well
	f := e.serve(t, selfPeers())
	c, err := Dial(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.ZFS().Create(ctx, zfs.CreateOpts{Name: "tank/jailops/pwn", Props: over}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("over the socket: %v", err)
	}
	// below the root's directory is where datasets belong
	if err := g.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/ok", Props: map[string]string{"mountpoint": filepath.Join(root, "ok")}}); err != nil {
		t.Errorf("a mountpoint below the root: %v", err)
	}
}

func invRootDirSealed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// a root found with another mode (registered before, or made by hand) is set to 0700 when the helper loads it
	if err := os.Chmod(e.cfg.MountBase, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.local.ReloadRoots(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(e.cfg.MountBase); st.Mode().Perm() != 0o700 {
		t.Errorf("after a reload the root has mode %04o", st.Mode().Perm())
	}
	// and a root registered at run time as well
	mp := e.root("tank/second")
	if err := e.local.RegisterStorage(WithAdmin(ctx, "alice"), "tank/second"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(mp); st.Mode().Perm() != 0o700 {
		t.Errorf("a registered root has mode %04o", st.Mode().Perm())
	}
	// a mountpoint that is not a plain directory is not a root
	e.root("tank/third")
	link := filepath.Join(e.base, "link")
	if err := os.Symlink(mp, link); err != nil {
		t.Fatal(err)
	}
	if err := e.zfs.Set(ctx, "tank/third", map[string]string{"mountpoint": link}); err != nil {
		t.Fatal(err)
	}
	if err := e.local.RegisterStorage(WithAdmin(ctx, "alice"), "tank/third"); err == nil {
		t.Error("a symlink was accepted as a root's directory")
	}
	if err := e.local.checkRootDir("tank/second", mp); err != nil {
		t.Errorf("a sealed root: %v", err)
	}
	_ = os.Chmod(mp, 0o711)
	if err := e.local.checkRootDir("tank/second", mp); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("mode 0711: %v", err)
	}
}

func invRootOverlap(t *testing.T) {
	e := newEnv(t)
	c := e.cfg
	for _, m := range []string{"/", "/etc", "/etc/cron.d", "/boot/modules", "/root/.ssh", "/usr", "/usr/local", "/usr/local/etc",
		"/usr/local/etc/rc.d", "/usr/local/libexec/x", "/var", "/var/db/jailops-priv", "/var/run/x", "/var/log/jails", "/dev/x",
		c.ConfDir, filepath.Join(c.ConfDir, "x"), filepath.Dir(c.ConfDir), c.HostDir, filepath.Join(c.HostDir, "x"),
		c.WireGuardDir, filepath.Join(c.WireGuardDir, "x"), filepath.Dir(c.StorageFile), filepath.Join(filepath.Dir(c.StorageFile), "x")} {
		if !c.overlapsSystem(m) {
			t.Errorf("a root mounted at %s was accepted", m)
		}
	}
	for _, m := range []string{"/jailops", "/usr/jails", "/var/jails", "/data/jailops", c.MountBase} {
		if c.overlapsSystem(m) {
			t.Errorf("a root mounted at %s was refused", m)
		}
	}
	// A dataset below a root may sit elsewhere (the daemon's state dataset in /var/db/jailops), but never over a
	// system path or in a directory of the helper.
	for _, m := range []string{"/var/db/jailops/state", "/var/jails/x"} {
		if c.shadowsSystem(m) {
			t.Errorf("a dataset below a root mounted at %s was refused", m)
		}
	}
	for _, m := range []string{"/etc", "/var", c.HostDir, filepath.Join(c.WireGuardDir, "x"), filepath.Join(c.ConfDir, "x")} {
		if !c.shadowsSystem(m) {
			t.Errorf("a dataset below a root mounted at %s was accepted", m)
		}
	}
	// and registration refuses such a root before it touches its directory
	ctx := WithAdmin(context.Background(), "alice")
	e.addDS("tank/cron", map[string]string{"jailops:managed": "on", "mountpoint": "/etc/cron.d"})
	if err := e.local.RegisterStorage(ctx, "tank/cron"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a root inside /etc: %v", err)
	}
}

func invRootStaysMounted(t *testing.T) {
	e := newEnv(t)
	ctx := WithAdmin(context.Background(), "alice")
	g := e.local.ZFS()
	for name, err := range map[string]error{
		"unmount":            e.local.Unmount(ctx, "tank/jailops"),
		"mount":              e.local.Mount(ctx, "tank/jailops"),
		"set mountpoint":     g.Set(ctx, "tank/jailops", map[string]string{"mountpoint": filepath.Join(e.cfg.MountBase, "x")}),
		"set canmount":       g.Set(ctx, "tank/jailops", map[string]string{"canmount": "off"}),
		"inherit mountpoint": g.Inherit(ctx, "tank/jailops", "mountpoint"),
		"inherit devices":    g.Inherit(ctx, "tank/jailops", "devices"),
	} {
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s of the storage root: %v", name, err)
		}
	}
	// other properties of a root may change
	if err := g.Set(ctx, "tank/jailops", map[string]string{"compression": "lz4"}); err != nil {
		t.Errorf("compression of the root: %v", err)
	}
}

func invDevicesOff(t *testing.T) {
	e := newEnv(t)
	ctx := WithAdmin(context.Background(), "alice")
	p, err := e.zfs.Get(ctx, "tank/jailops", "devices")
	if err != nil || p["devices"].Value != "off" || p["devices"].Source != "local" {
		t.Errorf("the root's devices: %+v %v", p["devices"], err)
	}
	g := e.local.ZFS()
	e.managedDS("tank/jailops/a")
	on := map[string]string{"devices": "on"}
	for name, err := range map[string]error{
		"create":  g.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/d", Props: on}),
		"set":     g.Set(ctx, "tank/jailops/a", on),
		"receive": g.Receive(ctx, zfs.ReceiveOpts{Target: "tank/jailops/r", Props: on}, strings.NewReader("")),
	} {
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s with devices=on: %v", name, err)
		}
	}
	if err := g.Set(ctx, "tank/jailops/a", map[string]string{"devices": "off"}); err != nil {
		t.Errorf("devices=off: %v", err)
	}
}

// recvZFS is the fake pool with the real zfs command for receive, so the test sees the argument vector.
type recvZFS struct {
	*zfs.Fake
	cmd *zfs.Command
}

func (r recvZFS) Receive(ctx context.Context, o zfs.ReceiveOpts, in io.Reader) error {
	return r.cmd.Receive(ctx, o, in)
}

func invReceiveSetsNoProps(t *testing.T) {
	e := newEnv(t)
	runner := run.NewFake()
	runner.Add(run.Rule{Name: "zfs", Args: []string{"receive", run.RestArgs}})
	l, err := NewLocal(e.cfg, Deps{ZFS: recvZFS{Fake: e.zfs, cmd: zfs.NewClient(runner)}, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithAdmin(context.Background(), "alice")
	if err := l.ZFS().Receive(ctx, zfs.ReceiveOpts{Target: "tank/jailops/r"}, strings.NewReader("stream")); err != nil {
		t.Fatal(err)
	}
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls %v", calls)
	}
	argv := calls[0].Cmd.Args
	for _, p := range []string{"mountpoint", "sharenfs", "sharesmb", "jailed", "keylocation", "devices", "setuid", "exec"} {
		if i := slices.Index(argv, p); i < 1 || argv[i-1] != "-x" {
			t.Errorf("zfs %v does not exclude %s", argv, p)
		}
	}
	// a name this ZFS does not know makes the receive fail: none on the list
	if slices.Contains(argv, "shareiscsi") {
		t.Errorf("zfs %v names shareiscsi", argv)
	}
	if !slices.Contains(argv, "-u") {
		t.Errorf("zfs %v mounts the received dataset", argv)
	}
}

func invAgentSpecialOnlyInJailTrees(t *testing.T) {
	e := newEnv(t)
	m := e.cfg.MountBase
	for root, want := range map[string]bool{
		filepath.Join(m, "projects/web/jails/a/root"):                true,
		filepath.Join(m, "projects/web/jails/a/root.new"):            true,
		filepath.Join(m, "projects/web/jails/a/root/var/db/pg"):      true,  // a volume mounted in the jail's root
		filepath.Join(m, "projects/web/jails/a"):                     false, // the container
		filepath.Join(m, "projects/web/jails/a/data"):                false,
		filepath.Join(m, "projects/web"):                             false,
		m:                                                            false,
		filepath.Join(e.base, "elsewhere/projects/web/jails/a/root"): false,
	} {
		if got := e.local.agentSpecial(root); got != want {
			t.Errorf("agentSpecial(%s) = %v", root, got)
		}
	}
}

// writeAgentEnv makes a jail being restored (its container and its root, created incomplete through the helper) and
// a helper that starts this test binary as its file agent.
func writeAgentEnv(t *testing.T) (*Local, context.Context, string) {
	t.Helper()
	e := newEnv(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner, AgentBinary: exe}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithAdmin(context.Background(), "alice")
	mp := filepath.Join(e.cfg.MountBase, "projects", "web", "jails", "web2")
	if err := os.MkdirAll(filepath.Join(mp, "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	g := l.ZFS()
	if err := g.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/projects/web/jails/web2", Parents: true, Props: map[string]string{"jailops:managed": "on", "jailops:complete": "off", "mountpoint": mp}}); err != nil {
		t.Fatal(err)
	}
	if err := g.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/projects/web/jails/web2/root", Props: map[string]string{"jailops:managed": "on", "mountpoint": filepath.Join(mp, "root")}}); err != nil {
		t.Fatal(err)
	}
	for _, ds := range []string{"tank/jailops/projects/web/jails/web2", "tank/jailops/projects/web/jails/web2/root"} {
		_ = e.zfs.Set(ctx, ds, map[string]string{"mounted": "yes"})
	}
	return l, ctx, mp
}

func openAgent(t *testing.T, l *Local, ctx context.Context, mode, root string) *fsagent.Client {
	t.Helper()
	f, err := l.FSAgent(ctx, mode, root)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	c := fsagent.NewClient(conn)
	t.Cleanup(func() { c.Close() })
	return c
}

// A write agent restores a jail as the backup recorded it. In the jail's root a setuid program is the jail's own
// (su, sudo); in the container, outside it, the helper's agent drops the bits and makes no device node.
func TestWriteAgentSpecialFilesOnlyInAJailsRoot(t *testing.T) {
	waitAgents(t)
	l, ctx, mp := writeAgentEnv(t)
	put := func(c *fsagent.Client, rel string) []string {
		t.Helper()
		if err := c.WriteFile(rel, 2, nil, bytes.NewReader([]byte("#!"))); err != nil {
			t.Fatal(err)
		}
		e := catalog.Entry{Kind: catalog.KFile, Name: filepath.Base(rel), Mode: 0o4755, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), MtimeNs: time.Now().UnixNano()}
		skipped, err := c.Apply(rel, &e, false, catalog.MetaOptions{NoChown: true})
		if err != nil {
			t.Fatal(err)
		}
		return skipped
	}
	container := openAgent(t, l, ctx, AgentWrite, mp)
	if err := container.Begin(); err != nil {
		t.Fatal(err)
	}
	if skipped := put(container, "suid"); len(skipped) == 0 || !strings.Contains(skipped[0], "without setuid") {
		t.Errorf("not reported: %v", skipped)
	}
	if st, _ := os.Stat(filepath.Join(mp, "suid")); st == nil || st.Mode()&os.ModeSetuid != 0 || st.Mode().Perm() != 0o755 {
		t.Errorf("in the container: %v", st)
	}
	if err := container.Mknod("null", unix.S_IFCHR|0o666, 1, 3); err == nil || !strings.Contains(err.Error(), "device nodes") {
		t.Errorf("a device node in the container: %v", err)
	}
	if err := container.Mknod("fifo", unix.S_IFIFO|0o600, 0, 0); err != nil {
		t.Errorf("a fifo in the container: %v", err)
	}
	root := openAgent(t, l, ctx, AgentWrite, filepath.Join(mp, "root"))
	if err := root.Begin(); err != nil {
		t.Fatal(err)
	}
	put(root, "su")
	if st, _ := os.Stat(filepath.Join(mp, "root", "su")); st == nil || st.Mode()&os.ModeSetuid == 0 {
		t.Errorf("in the jail's root the setuid bit was dropped: %v", st)
	}
}

// waitAgents waits until the agents of earlier tests have ended (they are counted until their process is reaped).
func waitAgents(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for agentsRunning.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d agents of earlier tests still run", agentsRunning.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Every agent is a root process that lives until its client closes the connection: the helper runs at most
// MaxAgents at once, whatever the daemon asks for.
func TestFileAgentsAreBounded(t *testing.T) {
	waitAgents(t)
	l, ctx, mp := writeAgentEnv(t)
	var open []*fsagent.Client
	for range MaxAgents {
		open = append(open, openAgent(t, l, ctx, AgentWrite, mp))
	}
	if _, err := l.FSAgent(ctx, AgentWrite, mp); !api.IsCode(err, api.CodeBusy) {
		t.Fatalf("agent %d: %v", MaxAgents+1, err)
	}
	// one ends, one more may start
	open[0].Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := l.FSAgent(ctx, AgentWrite, mp)
		if err == nil {
			f.Close()
			break
		}
		if !api.IsCode(err, api.CodeBusy) || time.Now().After(deadline) {
			t.Fatalf("after one ended: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
