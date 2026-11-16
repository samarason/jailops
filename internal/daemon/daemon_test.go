package daemon_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func TestConfigStrictAndDefaults(t *testing.T) {
	cfg, err := daemon.Decode(strings.NewReader("pool: tank\nlisten:\n  unix:\n    mode: 0660\nreconcile:\n  interval: 30s\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dataset != "tank/jailops" || cfg.MountBase != "/usr/local/jailops" || cfg.StateDir != "/var/db/jailops/state" || cfg.Listen.Unix.Mode != 0o660 ||
		cfg.Reconcile.Interval.Std() != 30*time.Second || cfg.Log.Format != "text" || cfg.Role != "host" {
		t.Fatalf("%+v", cfg)
	}
	for name, doc := range map[string]string{
		"unknown key":    "pool: tank\nbogus: 1\n",
		"unknown nested": "pool: tank\nlog:\n  lvl: info\n",
		"no pool":        "hub: true\n",
		"bad level":      "pool: tank\nlog:\n  level: loud\n",
		"relative path":  "pool: tank\ndata_dir: var/db\n",
		"bad duration":   "pool: tank\nreconcile:\n  interval: soon\n",
		"too fast":       "pool: tank\nreconcile:\n  interval: 10ms\n",
		"backup role":    "pool: tank\nrole: backup\n",
		"wrong type":     "pool: [a]\n",
	} {
		if _, err := daemon.Decode(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err = daemon.Decode(strings.NewReader("pool: tank\nrole: backup\n"))
	if err == nil || !strings.Contains(err.Error(), "separate daemon") {
		t.Fatalf("%v", err)
	}
}

func TestSampleConfigLoads(t *testing.T) {
	cfg, err := daemon.Load("../../packaging/jailopsd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Pool != "tank" || cfg.Listen.Unix.Mode != 0o666 || cfg.Reconcile.Autostart == nil || !*cfg.Reconcile.Autostart {
		t.Fatalf("%+v", cfg)
	}
}

func TestSingleWriterOnTheStateDirectory(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	cfg := e.Cfg
	_, err := daemon.Start(context.Background(), daemon.Options{Config: &cfg, NoListen: true, LogOutput: &strings.Builder{},
		Clients: func(context.Context, *daemon.Config, bool) (*daemon.Clients, error) {
			return &daemon.Clients{ZFS: e.ZFS, Jails: e.Jails, PF: e.PF, Net: e.Net, Runner: e.Run, Files: e.Files}, nil
		}})
	if err == nil {
		t.Fatal("a second daemon opened the same state directory")
	}
}

func TestRefusesAForeignDataset(t *testing.T) {
	f := zfs.NewFake("tank")
	if err := f.Create(context.Background(), zfs.CreateOpts{Name: "tank/jailops"}); err != nil {
		t.Fatal(err)
	}
	e := dtest.New(t, dtest.Options{NoStart: true})
	e.ZFS = f
	cfg := e.Cfg
	_, err := daemon.Start(context.Background(), daemon.Options{Config: &cfg, NoListen: true, LogOutput: &strings.Builder{},
		Clients: func(context.Context, *daemon.Config, bool) (*daemon.Clients, error) {
			return &daemon.Clients{ZFS: f, Jails: e.Jails, PF: e.PF, Net: e.Net, Runner: e.Run, Files: e.Files}, nil
		}})
	if err == nil || !strings.Contains(err.Error(), "not managed by JailOps") {
		t.Fatalf("%v", err)
	}
}

func TestLayoutIsCreatedOnce(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	for _, ds := range []string{"tank/jailops", "tank/jailops/images", "tank/jailops/projects", "tank/jailops/deleted", "tank/jailops/state"} {
		p, err := e.ZFS.Get(context.Background(), ds, "jailops:managed")
		if err != nil || p["jailops:managed"].Value != "on" {
			t.Fatalf("%s: %v %v", ds, err, p)
		}
	}
	mp, _ := e.ZFS.Get(context.Background(), "tank/jailops", "mountpoint")
	if mp["mountpoint"].Value != "/jailops" {
		t.Fatalf("%v", mp)
	}
}

func TestStartFailsOnUnreachablePriv(t *testing.T) {
	cfg := daemon.Defaults()
	cfg.Pool = "tank"
	defer func(d time.Duration) { daemon.PrivConnectWait = d }(daemon.PrivConnectWait)
	daemon.PrivConnectWait = 200 * time.Millisecond
	cfg.Priv.Socket = filepath.Join(t.TempDir(), "none.sock")
	cfg.StateDir = t.TempDir()
	cfg.DataDir = t.TempDir()
	cfg.WorkDir = t.TempDir()
	_, err := daemon.Start(context.Background(), daemon.Options{Config: &cfg, NoListen: true, LogOutput: &strings.Builder{}})
	if err == nil || !strings.Contains(err.Error(), "jailops-priv") {
		t.Fatalf("%v", err)
	}
}

func TestGracefulShutdownAndRestart(t *testing.T) {
	e := dtest.New(t, dtest.Options{Listen: true})
	sock := e.D.UnixPath()
	if _, err := os.Stat(sock); err != nil {
		t.Fatal(err)
	}
	c, err := sdk.Connect(context.Background(), sdk.Local(sdk.WithSocket(sock), sdk.WithRetries(0)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Info(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Close()
	e.Stop()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("the socket was left behind: %v", err)
	}
	// The same state starts again, with the same identity.
	id := e.Opts.Reuse
	_ = id
	e.Start()
	if e.D == nil || e.D.UnixPath() == "" {
		t.Fatal("restart failed")
	}
	if info, err := e.Admin.Info(context.Background()); err != nil || info.HostUUID == "" {
		t.Fatalf("%v %+v", err, info)
	}
}

func TestHostIdentityIsStable(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	id1 := e.D.Service().HostUUID()
	e.Stop()
	e.Start()
	if id2 := e.D.Service().HostUUID(); id1 != id2 {
		t.Fatalf("%s != %s", id1, id2)
	}
}

func TestDoctor(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	rep, err := e.Admin.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]api.DoctorCheck{}
	for _, c := range rep.Checks {
		by[c.Name] = c
	}
	for name, want := range map[string]api.DoctorStatus{
		"state.files": api.DoctorOK, "db.integrity": api.DoctorOK, "operations.journal": api.DoctorOK,
		"sysctl.net.inet.ip.forwarding": api.DoctorOK,
		"jails.health":                  api.DoctorOK, "render": api.DoctorOK,
	} {
		if c, ok := by[name]; !ok || c.Status != want {
			t.Errorf("%s: %+v", name, c)
		}
	}
	// Kernel modules cannot be read through the fake runner: unknown, not ok.
	if c := by["kernel.module.if_epair"]; c.Status != api.DoctorOK && c.Status != api.DoctorUnknown {
		t.Errorf("%+v", c)
	}
	// A sysctl the networks need but the host lacks fails with a hint.
	e.SetSysctl("net.inet.ip.forwarding", "0")
	rep, _ = e.Admin.Doctor(context.Background())
	for _, c := range rep.Checks {
		if c.Name == "sysctl.net.inet.ip.forwarding" && (c.Status != api.DoctorFail || !strings.Contains(c.Hint, "sysctl.conf")) {
			t.Errorf("%+v", c)
		}
	}
	if rep.Status != api.DoctorFail {
		t.Errorf("overall %s", rep.Status)
	}
}

func TestProjectsConfigAndFirstStart(t *testing.T) {
	cfg, err := daemon.Decode(strings.NewReader("pool: tank\nprojects:\n  network_pool: 10.64.0.0/12\n  network_bits: 24\n  uplink: em0\n  nat: true\nlimits:\n  auth_failure_threshold: 9\n"))
	if err != nil || cfg.Projects.NetworkPool != "10.64.0.0/12" || cfg.Projects.NetworkBits != 24 || !cfg.Projects.NAT || cfg.Limits.AuthFailureThreshold != 9 {
		t.Fatalf("%v %+v", err, cfg.Projects)
	}
	for name, doc := range map[string]string{
		"v6 pool":      "pool: tank\nprojects:\n  network_pool: fd00::/48\n",
		"not a prefix": "pool: tank\nprojects:\n  network_pool: 10.0.0.1\n",
		"bits too big": "pool: tank\nprojects:\n  network_pool: 10.0.0.0/16\n  network_bits: 16\n",
		"unknown key":  "pool: tank\nprojects:\n  pool: x\n",
	} {
		if _, err := daemon.Decode(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The first start creates the storage "default" on the configured dataset and no project at all.
	e := dtest.New(t, dtest.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := e.Admin.Storage().Get(ctx, "default")
	if err != nil || st.Spec.Dataset != e.Cfg.Dataset {
		t.Fatalf("%v %+v", err, st)
	}
	var projects int
	for _, err := range e.Admin.Projects().List(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		projects++
	}
	if projects != 0 {
		t.Fatalf("a fresh host holds %d projects; nothing creates one on its own", projects)
	}
	// A jail names its project, network and storage; Seed makes a project and binds Admin to it.
	e.Seed()
	op, err := e.Admin.Jails().Create(ctx, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	j, err := op.Wait(ctx)
	if err != nil || j.Metadata.Project != dtest.SeedProject || j.Spec.Storage != "default" {
		t.Fatalf("%v %+v", err, j)
	}
	// The project's datasets exist below the storage.
	if ok, _ := e.ZFS.Exists(ctx, "tank/jailops/projects/alpha/jails/web/root"); !ok {
		t.Fatal("jail dataset missing")
	}
}

// The state directory the daemon writes must not default into the storage mount: that tree belongs to the helper
// and the daemon cannot write there. jailops-priv init mounts the state dataset under the data directory.
func TestStateDirDefaultsOutsideTheStorageRoot(t *testing.T) {
	cfg, err := daemon.Decode(strings.NewReader("pool: tank\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(cfg.MountBase, cfg.StateDir); err == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("state_dir %s is inside mount_base %s", cfg.StateDir, cfg.MountBase)
	}
}

// The sample lists every key jailopsd.yaml accepts, commented or not, so an operator never has to read the source.
func TestSampleNamesEveryConfigKey(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/jailopsd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sample := string(raw)
	var walk func(rt reflect.Type)
	seen := map[reflect.Type]bool{}
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if key == "" || key == "-" {
				continue
			}
			if !strings.Contains(sample, key+":") {
				t.Errorf("packaging/jailopsd.yaml does not mention %q (%s.%s)", key, rt.Name(), f.Name)
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(daemon.Config{}))
}
