package hostbackup

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/backup"
	"jailops.net/jailops/internal/node"
	"jailops.net/jailops/internal/node/nodetest"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/keys"
	"jailops.net/jailops/internal/repo/store"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/internal/testdb"
	"jailops.net/jailops/sdk/api"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var bg = context.Background()

// ---- clock ----

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock { return &testClock{t: time.Now().UTC().Truncate(time.Second)} }
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *testClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
func (c *testClock) Set(t time.Time)         { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// ---- ZFS with files ----

// world is a zfs.Fake whose snapshots also copy the files of the dataset, as
// a mounted ZFS snapshot would show them, so that changes after the snapshot
// are not visible through it.
type world struct {
	*zfs.Fake
	m *fakeMounter
}

func newWorld(t *testing.T) *world {
	z := zfs.NewFake("tank")
	m := &fakeMounter{root: t.TempDir(), z: z, live: map[string]string{}, snaps: map[string]string{}}
	return &world{Fake: z, m: m}
}

func (w *world) Snapshot(ctx context.Context, o zfs.SnapshotOpts) error {
	if err := w.Fake.Snapshot(ctx, o); err != nil {
		return err
	}
	for _, n := range o.Names {
		ds, snap := zfs.SplitSnapshot(n)
		if err := w.m.copyIn(ds, snap); err != nil {
			return err
		}
	}
	return nil
}

func (w *world) Destroy(ctx context.Context, name string, o zfs.DestroyOpts) error {
	if err := w.Fake.Destroy(ctx, name, o); err != nil {
		return err
	}
	if strings.Contains(name, "@") {
		w.m.dropSnap(name)
	} else {
		w.m.dropLive(name)
	}
	return nil
}

// snapshots lists every snapshot of the fake with the given name prefix.
func (w *world) snapshots(t *testing.T, prefix string) []string {
	t.Helper()
	l, err := w.List(bg, zfs.ListOpts{Types: []string{"snapshot"}, Recursive: true})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range l {
		if _, s := zfs.SplitSnapshot(d.Name); strings.HasPrefix(s, prefix) {
			out = append(out, d.Name)
		}
	}
	return out
}

func (w *world) datasets(t *testing.T, root string) []string {
	t.Helper()
	l, err := w.List(bg, zfs.ListOpts{Root: root, Recursive: true})
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range l {
		out = append(out, d.Name)
	}
	return out
}

type fakeMounter struct {
	mu    sync.Mutex
	root  string
	z     *zfs.Fake
	live  map[string]string // dataset -> directory
	snaps map[string]string // dataset@snap -> directory
	// failMount fails MountDir for a dataset; failSnapDir fails SnapshotDir.
	failMount   func(ds string) error
	failSnapDir func(ds string) error
}

func safe(s string) string { return strings.NewReplacer("/", "_", "@", "-").Replace(s) }

func (m *fakeMounter) liveDir(ds string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.live[ds]; ok {
		return d
	}
	d := filepath.Join(m.root, "live", safe(ds))
	_ = os.MkdirAll(d, 0o755)
	m.live[ds] = d
	return d
}

// copyIn records the snapshot. The snapshot directory is the live directory:
// the tests change files only between backups, and a real snapshot keeps
// inode numbers and ctimes stable, which a copy would not.
func (m *fakeMounter) copyIn(ds, snap string) error {
	src := m.liveDir(ds)
	m.mu.Lock()
	m.snaps[ds+"@"+snap] = src
	m.mu.Unlock()
	return nil
}

// dropLive forgets the files of a destroyed dataset and of its descendants.
func (m *fakeMounter) dropLive(ds string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, d := range m.live {
		if k == ds || strings.HasPrefix(k, ds+"/") {
			_ = os.RemoveAll(d)
			delete(m.live, k)
		}
	}
}

func (m *fakeMounter) dropSnap(name string) {
	m.mu.Lock()
	delete(m.snaps, name)
	m.mu.Unlock()
}

func (m *fakeMounter) SnapshotDir(_ context.Context, d Dataset, snap string) (string, error) {
	if m.failSnapDir != nil {
		if err := m.failSnapDir(d.Name); err != nil {
			return "", err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	dir, ok := m.snaps[d.Name+"@"+snap]
	if !ok {
		return "", fmt.Errorf("snapshot %s@%s is not mounted", d.Name, snap)
	}
	return dir, nil
}

func (m *fakeMounter) MountDir(ctx context.Context, ds string) (string, error) {
	if m.failMount != nil {
		if err := m.failMount(ds); err != nil {
			return "", err
		}
	}
	ok, err := m.z.Exists(ctx, ds)
	if err != nil || !ok {
		return "", fmt.Errorf("dataset %s does not exist", ds)
	}
	return m.liveDir(ds), nil
}

// ---- jails ----

type objects struct{}

func (objects) Network(n string) (api.NetworkSpec, bool) {
	switch n {
	case "lan":
		return api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.250"}}, true
	}
	return api.NetworkSpec{}, false
}
func (objects) Policy(n string) (api.FirewallPolicySpec, bool) {
	if n == "web" {
		return api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}, true
	}
	return api.FirewallPolicySpec{}, false
}
func (objects) AddressSet(string) (api.AddressSetSpec, bool) { return api.AddressSetSpec{}, false }

var testGen = api.ImageGeneration{Number: 1, Name: "fbsd#g1", Manifest: "mf1", Dataset: "tank/jailops/images/fbsd/g1"}

// makeJail creates the datasets and files of a thin jail in w and returns its
// record. Layout: container (spec.json, bundle.json), root (not captured),
// etc, local and db (a few MiB so it has several chunks).
func makeJail(t *testing.T, w *world, name, uuid string, labels map[string]string) JailRecord {
	t.Helper()
	c := "tank/jailops/projects/src/jails/" + name
	mp := "/jo/" + name
	j := JailRecord{Name: name, Project: "alpha", UUID: uuid, Labels: labels, Container: c, Image: testGen,
		Spec: api.JailSpec{Image: "fbsd@stable", Layout: api.LayoutThin, Hostname: name,
			Network:  []api.NetworkAttach{{Network: "lan", IPv4: "10.20.0.5", MAC: "02:aa:bb"}},
			Firewall: api.FirewallAttach{Policies: []string{"web"}}}}
	mk := func(rel, kind, mount string, props map[string]string) {
		ds := c
		if rel != "" {
			ds = c + "/" + rel
		}
		if err := w.Create(bg, zfs.CreateOpts{Name: ds, Parents: true, Props: map[string]string{"jailops:managed": "on", "jailops:id": uuid}}); err != nil {
			t.Fatal(err)
		}
		j.Datasets = append(j.Datasets, Dataset{Name: ds, Kind: kind, Mountpoint: mount, Props: props})
	}
	mk("", KindContainer, mp, nil)
	mk("root", KindRoot, mp+"/root", nil)
	mk("etc", KindPersistent, mp+"/root/etc", map[string]string{"jailops:path": "/etc", "jailops:class": "system"})
	mk("local", KindPersistent, mp+"/root/usr/local", map[string]string{"jailops:path": "/usr/local", "jailops:class": "data"})
	mk("db", KindPersistent, mp+"/root/var/db/app", map[string]string{"jailops:path": "/var/db/app", "quota": "1G", "jailops:class": "data"})

	rnd := rand.New(rand.NewSource(int64(len(name))*7 + 1))
	write := func(ds, rel string, size int) {
		p := filepath.Join(w.m.liveDir(ds), rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, size)
		rnd.Read(b)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		_ = os.Chtimes(p, old, old)
	}
	write(c, "spec.json", 300)
	write(c, "bundle.json", 500)
	write(c+"/etc", "rc.conf", 400)
	write(c+"/etc", "ssh/sshd_config", 900)
	write(c+"/local", "etc/app.conf", 100)
	write(c+"/db", "main.db", 5<<20)
	write(c+"/db", "wal/001", 70<<10)
	for i := 0; i < 20; i++ {
		write(c+"/db", fmt.Sprintf("small/f%02d", i), 1000+i)
	}
	return j
}

// treeHash lists "relpath size content" of a directory for comparisons.
func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if fi.IsDir() {
			out[rel+"/"] = ""
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ---- host registry ----

type fakeHost struct {
	mu       sync.Mutex
	state    backup.HostState
	created  []string
	undone   []string
	adopted  []AdoptInput
	started  []string
	running  map[string]bool
	failObj  error
	failAdpt error
	failStrt error
	netMaps  []map[string]string
	// DrillHost
	stopped, deleted, execs []string
	execCodes               []int
}

func newFakeHost() *fakeHost {
	return &fakeHost{state: backup.HostState{
		Networks: map[string]api.NetworkSpec{"lan": {IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.250"}},
			"lan2": {IPv4: &api.IPv4Net{Subnet: "10.40.0.0/24", Gateway: "10.40.0.1", Range: "10.40.0.10-10.40.0.250"}}},
		Policies: map[string]api.FirewallPolicySpec{}, AddressSets: map[string]api.AddressSetSpec{},
		Jails: map[string]backup.JailRef{}, Secrets: map[string]bool{}}, running: map[string]bool{}}
}

func (h *fakeHost) State(context.Context, string) (backup.HostState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state, nil
}

func (h *fakeHost) Place(_ context.Context, project, name, _ string) (Placement, error) {
	if project == "" {
		return Placement{}, api.Errorf(api.CodeInvalid, "a project is required")
	}
	return Placement{Container: "tank/jailops/projects/" + project + "/jails/" + name, Mountpoint: "/jo2/" + project + "/" + name}, nil
}

func (h *fakeHost) EnsureObjects(_ context.Context, b api.RestoreBundle, nm map[string]string) (func(context.Context) error, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.netMaps = append(h.netMaps, nm)
	if h.failObj != nil {
		return nil, h.failObj
	}
	h.created = append(h.created, "policy:web")
	return func(context.Context) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.undone = append(h.undone, "objects")
		return nil
	}, nil
}

func (h *fakeHost) Adopt(_ context.Context, in AdoptInput) (func(context.Context) error, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failAdpt != nil {
		return nil, h.failAdpt
	}
	h.adopted = append(h.adopted, in)
	return func(context.Context) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.undone = append(h.undone, "adopt")
		return nil
	}, nil
}

func (h *fakeHost) Running(_ context.Context, _, name string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.running[name], nil
}

func (h *fakeHost) Start(_ context.Context, _, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failStrt != nil {
		return h.failStrt
	}
	h.started = append(h.started, name)
	h.running[name] = true
	return nil
}

type fakeImages struct {
	gens map[string]api.ImageGeneration
}

func (f *fakeImages) Resolve(_ context.Context, _, g string) (api.ImageGeneration, error) {
	if v, ok := f.gens[g]; ok {
		return v, nil
	}
	return api.ImageGeneration{}, api.Errorf(api.CodeNotFound, "generation %s does not exist", g)
}

// addGeneration creates the generation dataset and its @ro in the fake.
func addGeneration(t *testing.T, w *world, f *fakeImages, g api.ImageGeneration) {
	t.Helper()
	if err := w.Create(bg, zfs.CreateOpts{Name: g.Dataset, Parents: true, Props: map[string]string{"jailops:managed": "on"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Fake.Snapshot(bg, zfs.SnapshotOpts{Names: []string{g.Dataset + "@ro"}}); err != nil {
		t.Fatal(err)
	}
	f.gens[g.Name] = g
}

type fakeJails struct {
	mu    sync.Mutex
	jails []JailRecord
}

func (f *fakeJails) Jails(context.Context) ([]JailRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]JailRecord(nil), f.jails...), nil
}

type fakePolicies struct {
	mu       sync.Mutex
	policies []api.BackupPolicy
	targets  []api.BackupTarget
}

func (f *fakePolicies) BackupPolicies(context.Context) ([]api.BackupPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]api.BackupPolicy(nil), f.policies...), nil
}
func (f *fakePolicies) BackupTargets(context.Context) ([]api.BackupTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]api.BackupTarget(nil), f.targets...), nil
}

type fakeHooks struct {
	mu        sync.Mutex
	pre, post int
	failPre   error
	failPost  error
	cur, max  int
	delay     time.Duration
}

func (h *fakeHooks) Pre(context.Context, JailRecord) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failPre != nil {
		return h.failPre
	}
	h.pre++
	return nil
}
func (h *fakeHooks) Post(context.Context, JailRecord) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.post++
	return h.failPost
}

// ---- repositories ----

func memRemote(t *testing.T) (Remote, *store.Store, *datastore.MemBackend) {
	t.Helper()
	b := datastore.NewMemBackend()
	s, err := store.Init(bg, b, store.InitOptions{ServerID: "node"})
	if err != nil {
		t.Fatal(err)
	}
	return NewStoreRemote(s), s, b
}

// nodeServer runs the node's host API behind TLS with an enrolled host.
func nodeServer(t *testing.T) (*nodetest.Env, NodeConfig) {
	t.Helper()
	env := nodetest.NewEnv(t, nodetest.Options{})
	h := env.Host(t, "host-1")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.Node.Handler().ServeHTTP(w, r.WithContext(node.WithHost(r.Context(), h)))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return env, NodeConfig{Address: srv.Listener.Addr().String(), TLS: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}}
}

// ---- the rig ----

type rig struct {
	t         *testing.T
	svc       *Service
	w         *world
	host      *fakeHost
	imgs      *fakeImages
	cat       *MemCatalog
	clock     *testClock
	jails     *fakeJails
	pols      *fakePolicies
	hooks     *fakeHooks
	remote    Remote
	identity  string
	recipient string
	keyPath   string
	cfg       Config
}

type rigOpts struct {
	node       *NodeConfig
	remote     Remote
	noKey      bool
	noEscrow   bool
	allowUnesc bool
	hooks      bool
	cfg        func(*Config)
	identity   string // reuse a recovery identity (a second host)
	recipient  string
	noGen      bool
	agents     Agents
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	r := &rig{t: t, w: newWorld(t), host: newFakeHost(), imgs: &fakeImages{gens: map[string]api.ImageGeneration{}}, cat: NewMemCatalog(),
		clock: newClock(), jails: &fakeJails{}, pols: &fakePolicies{}, remote: o.remote, identity: o.identity, recipient: o.recipient}
	if r.identity == "" {
		var err error
		r.identity, r.recipient, err = keys.GenerateRecoveryIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	r.keyPath = filepath.Join(t.TempDir(), "backup.key")
	r.cfg = Config{KeyPath: r.keyPath, HostUUID: "host-uuid-1", Clock: r.clock.Now, Sleep: func(context.Context, time.Duration) error { return nil },
		AllowUnescrowed: o.allowUnesc, NoTrustCtime: true, JitterWindow: 10 * time.Minute, Concurrency: 2, NoChown: boolPtr(os.Geteuid() != 0),
		ScratchDir: filepath.Join(t.TempDir(), "scratch"), Retry: RetryConfig{Attempts: 3, Base: time.Minute, Max: 10 * time.Minute}}
	if o.node != nil {
		r.cfg.Node = *o.node
	}
	if o.cfg != nil {
		o.cfg(&r.cfg)
	}
	deps := Deps{ZFS: r.w, Mounter: r.w.m, Jails: r.jails, Objects: objects{}, Policies: r.pols, Host: r.host, Images: r.imgs, Catalog: r.cat, Remote: o.remote, Agents: o.agents}
	if o.hooks {
		r.hooks = &fakeHooks{}
		deps.Hooks = r.hooks
	}
	svc, err := New(r.cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	r.svc = svc
	if !o.noGen {
		addGeneration(t, r.w, r.imgs, testGen)
	}
	if !o.noKey {
		recips := []string{r.recipient}
		if o.noEscrow {
			recips = nil
		}
		res, err := svc.CreateKey(bg, CreateKeyOptions{Recipients: recips})
		if err != nil {
			t.Fatal(err)
		}
		if res.EscrowErr != nil {
			t.Fatal(res.EscrowErr)
		}
	}
	return r
}

func boolPtr(b bool) *bool { return &b }

func (r *rig) jail(name, uuid string, labels map[string]string) JailRecord {
	j := makeJail(r.t, r.w, name, uuid, labels)
	r.jails.mu.Lock()
	r.jails.jails = append(r.jails.jails, j)
	r.jails.mu.Unlock()
	return j
}

func (r *rig) backup(j JailRecord) *CaptureResult {
	r.t.Helper()
	res, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "nightly"})
	if err != nil {
		r.t.Fatalf("backup of %s: %v", j.Name, err)
	}
	r.clock.Advance(time.Minute)
	return res
}

func backupJailRef(name, uuid string) backup.JailRef { return backup.JailRef{Name: name, UUID: uuid} }

func mustCreate(t *testing.T, r *rig, name string, props map[string]string) {
	t.Helper()
	if err := r.w.Create(bg, zfs.CreateOpts{Name: name, Parents: true, Props: props}); err != nil {
		t.Fatal(err)
	}
}

// failingZFS fails selected calls of the world.
type failingZFS struct {
	*world
	failSnapshot bool
	failGUID     bool
}

func (f failingZFS) Snapshot(ctx context.Context, o zfs.SnapshotOpts) error {
	if f.failSnapshot {
		return errInjected
	}
	return f.world.Snapshot(ctx, o)
}

func (f failingZFS) GUID(ctx context.Context, n string) (uint64, error) {
	if f.failGUID {
		return 0, errInjected
	}
	return f.world.GUID(ctx, n)
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dirBackend(dir string) (datastore.Backend, error) { return datastore.NewDirBackend(dir) }

func storeInit(b datastore.Backend) (*store.Store, error) {
	return store.Init(bg, b, store.InitOptions{ServerID: "disk"})
}

// DrillHost of the fake host: what a full restore test does with its hidden jail.
func (h *fakeHost) Stop(_ context.Context, _, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = append(h.stopped, name)
	delete(h.running, name)
	return nil
}

func (h *fakeHost) Delete(_ context.Context, _, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deleted = append(h.deleted, name)
	return nil
}

func (h *fakeHost) Exec(_ context.Context, _, name string, argv []string) (string, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.execs = append(h.execs, name+": "+strings.Join(argv, " "))
	if len(h.execCodes) > 0 {
		c := h.execCodes[0]
		h.execCodes = h.execCodes[1:]
		return "service is down", c, nil
	}
	return "", 0, nil
}
