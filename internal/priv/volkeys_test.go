package priv

import (
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

const (
	vkJail    = "tank/jailops/projects/alpha/jails/web"
	vkVolumes = "tank/jailops/projects/alpha/volumes"
	vkVol     = vkVolumes + "/db"
	// vkPass is a marker: it must reach zfs on standard input and nothing else.
	vkPass  = "marker-7f3a-correct-horse"
	vkNew   = "marker-91bc-battery-staple"
	vkWrong = "marker-0000-wrong-passphrase"
)

// keyWorld is a fake zfs that knows one passphrase per dataset and checks what arrives on standard input.
type keyWorld struct {
	e    *env
	mu   sync.Mutex // the server's goroutines run zfs, the test reads
	pass map[string]string
}

func (kw *keyWorld) set(ds, p string) { kw.mu.Lock(); kw.pass[ds] = p; kw.mu.Unlock() }
func (kw *keyWorld) get(ds string) string {
	kw.mu.Lock()
	defer kw.mu.Unlock()
	return kw.pass[ds]
}

func newKeyFixture(t *testing.T, keystatus string) (*fixture, *keyWorld) {
	t.Helper()
	return newKeyFixtureClock(t, keystatus, nil)
}

// newKeyFixtureClock is newKeyFixture with the helper's clock (nil: time.Now).
func newKeyFixtureClock(t *testing.T, keystatus string, now func() time.Time) (*fixture, *keyWorld) {
	t.Helper()
	var kw *keyWorld
	f := newFixtureWith(t, func(e *env) {
		e.local.d.Now = now
		kw = &keyWorld{e: e, pass: map[string]string{vkVol: vkPass}}
		e.addDS(vkJail, map[string]string{"jailops:managed": "on", "jailops:kind": "container"})
		e.addDS(vkVolumes, map[string]string{"jailops:managed": "on", "jailops:kind": "volumes"})
		e.addDS(vkVol, map[string]string{"jailops:managed": "on", "jailops:kind": "volume", "encryptionroot": vkVol, "keyformat": "passphrase", "keystatus": keystatus})
		e.addDS(vkJail+"/etc", map[string]string{"jailops:managed": "on", "jailops:kind": "persistent", "encryptionroot": vkJail + "/etc", "keyformat": "passphrase"})
		// the shape of a volume below a jail is not a volume: the helper knows the volumes of a project only
		e.addDS(vkJail+"/data", map[string]string{"jailops:managed": "on", "jailops:kind": "volumes"})
		e.addDS(vkJail+"/data/db", map[string]string{"jailops:managed": "on", "jailops:kind": "volume", "encryptionroot": vkJail + "/data/db", "keyformat": "passphrase"})
		e.addDS(vkVolumes+"/plain", map[string]string{"jailops:managed": "on", "jailops:kind": "volume"})
		e.addDS(vkVolumes+"/foreign", map[string]string{"jailops:kind": "volume", "encryptionroot": vkVolumes + "/foreign", "keyformat": "passphrase"})
		e.addDS(vkVolumes+"/child", map[string]string{"jailops:managed": "on", "jailops:kind": "volume", "encryptionroot": vkVol, "keyformat": "passphrase"})
		e.addDS(vkVolumes+"/hex", map[string]string{"jailops:managed": "on", "jailops:kind": "volume", "encryptionroot": vkVolumes + "/hex", "keyformat": "hex"})
		e.runner.Add(run.Rule{Name: "zfs", Args: []string{"load-key", run.RestArgs}, Fn: kw.loadKey})
		e.runner.Add(run.Rule{Name: "zfs", Args: []string{"unload-key", run.AnyArg}, Fn: func(c run.Cmd) (run.Result, error) {
			_ = kw.e.zfs.Set(context.Background(), c.Args[1], map[string]string{"keystatus": "unavailable"})
			return run.Result{}, nil
		}})
		e.runner.Add(run.Rule{Name: "zfs", Args: []string{"change-key", run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
			kw.set(c.Args[len(c.Args)-1], strings.TrimSuffix(stdin(c), "\n"))
			return run.Result{}, nil
		}})
		e.runner.Add(run.Rule{Name: "zfs", Args: []string{"create", run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
			name := c.Args[len(c.Args)-1]
			kw.set(name, strings.TrimSuffix(stdin(c), "\n"))
			return run.Result{}, kw.e.zfs.Create(context.Background(), zfs.CreateOpts{Name: name, Props: map[string]string{"jailops:managed": "on"}})
		}})
	})
	return f, kw
}

func stdin(c run.Cmd) string {
	if c.Stdin == nil {
		return ""
	}
	var b strings.Builder
	buf := make([]byte, 64)
	for {
		n, err := c.Stdin.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}

// loadKey answers like zfs: one line of standard input, compared with the passphrase of the dataset.
func (kw *keyWorld) loadKey(c run.Cmd) (run.Result, error) {
	ds := c.Args[len(c.Args)-1]
	if stdin(c) != kw.get(ds)+"\n" {
		stderr := "Key load error: Incorrect key provided for '" + ds + "'."
		return run.Result{ExitCode: 255, Stderr: []byte(stderr)}, &run.ExitError{Name: c.Name, Args: c.Args, Code: 255, Stderr: stderr}
	}
	if c.Args[1] != "-n" {
		_ = kw.e.zfs.Set(context.Background(), ds, map[string]string{"keystatus": "available"})
	}
	return run.Result{}, nil
}

// noSecret fails when a passphrase shows up anywhere but on standard input.
func noSecret(t *testing.T, f *fixture, extra ...string) {
	t.Helper()
	all := append([]string{f.audit.String(), strings.Join(f.runner.Argv(), "\n")}, extra...)
	for _, s := range all {
		for _, m := range []string{"marker-"} {
			if strings.Contains(s, m) {
				t.Fatalf("a passphrase leaked: %q", s)
			}
		}
	}
}

func TestLoadKeyOverTheSocket(t *testing.T) {
	f, _ := newKeyFixture(t, "unavailable")
	ctx := context.Background()
	err := f.client.LoadKey(ctx, vkVol, []byte(vkWrong))
	if !api.IsCode(err, api.CodeBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	noSecret(t, f, err.Error())
	if err := f.client.LoadKey(ctx, vkVol, []byte(vkPass)); err != nil {
		t.Fatal(err)
	}
	calls := f.runner.Calls()
	last := calls[len(calls)-1]
	if got := strings.Join(append([]string{last.Cmd.Name}, last.Cmd.Args...), " "); got != "zfs load-key "+vkVol {
		t.Fatalf("argv %q", got)
	}
	if string(last.StdinData) != vkPass+"\n" {
		t.Fatalf("stdin %q", last.StdinData)
	}
	// loaded: a second unlock does not run zfs again
	n := len(f.runner.Calls())
	if err := f.client.LoadKey(ctx, vkVol, []byte(vkWrong)); err != nil || len(f.runner.Calls()) != n {
		t.Fatalf("a loaded key: %v, %d calls", err, len(f.runner.Calls())-n)
	}
	if err := f.client.UnloadKey(ctx, vkVol); err != nil {
		t.Fatal(err)
	}
	if got := f.runner.Argv()[len(f.runner.Argv())-1]; got != "zfs unload-key "+vkVol {
		t.Fatalf("argv %q", got)
	}
	noSecret(t, f)
	if !strings.Contains(f.audit.String(), `"op":"zfs.load_key"`) || !strings.Contains(f.audit.String(), vkVol) {
		t.Fatalf("the audit names the operation and the dataset: %s", f.audit.String())
	}
}

func TestKeyOperationsRefuse(t *testing.T) {
	f, _ := newKeyFixture(t, "unavailable")
	ctx := context.Background()
	long := strings.Repeat("x", api.MaxPassphrase+1)
	cases := []struct {
		name string
		call func() error
		code api.Code
	}{
		{"outside the storage roots", func() error { return f.client.LoadKey(ctx, "tank/other/projects/alpha/volumes/db", []byte(vkPass)) }, api.CodeForbidden},
		{"not managed", func() error { return f.client.LoadKey(ctx, vkVolumes+"/foreign", []byte(vkPass)) }, api.CodeForbidden},
		{"a persistent dataset", func() error { return f.client.LoadKey(ctx, vkJail+"/etc", []byte(vkPass)) }, api.CodeForbidden},
		{"a volume-shaped dataset of a jail", func() error { return f.client.LoadKey(ctx, vkJail+"/data/db", []byte(vkPass)) }, api.CodeForbidden},
		{"a volume without encryption", func() error { return f.client.LoadKey(ctx, vkVolumes+"/plain", []byte(vkPass)) }, api.CodeForbidden},
		{"not its own encryption root", func() error { return f.client.LoadKey(ctx, vkVolumes+"/child", []byte(vkPass)) }, api.CodeForbidden},
		{"a key that is not a passphrase", func() error { return f.client.LoadKey(ctx, vkVolumes+"/hex", []byte(vkPass)) }, api.CodeForbidden},
		{"the container", func() error { return f.client.LoadKey(ctx, vkJail, []byte(vkPass)) }, api.CodeForbidden},
		{"a snapshot", func() error { return f.client.LoadKey(ctx, vkVol+"@x", []byte(vkPass)) }, api.CodeInvalid},
		{"a line feed in the passphrase", func() error { return f.client.LoadKey(ctx, vkVol, []byte("marker-a\nzfs destroy")) }, api.CodeInvalid},
		{"a NUL in the passphrase", func() error { return f.client.LoadKey(ctx, vkVol, []byte("marker-a\x00b")) }, api.CodeInvalid},
		{"an empty passphrase", func() error { return f.client.LoadKey(ctx, vkVol, nil) }, api.CodeInvalid},
		{"a passphrase over 512 bytes", func() error { return f.client.LoadKey(ctx, vkVol, []byte(long)) }, api.CodeInvalid},
		{"extra arguments", func() error {
			_, err := callJSON[empty](ctx, f.client, OpZFSLoadKey, map[string]string{"name": vkVol, "args": "-L file:///etc/key"}, callOpts{in: strings.NewReader(vkPass)})
			return err
		}, api.CodeInvalid},
		{"the passphrase as an argument", func() error {
			_, err := callJSON[empty](ctx, f.client, OpZFSLoadKey, map[string]string{"name": vkVol, "passphrase": vkPass}, callOpts{in: strings.NewReader(vkPass)})
			return err
		}, api.CodeInvalid},
		{"unload outside the roots", func() error { return f.client.UnloadKey(ctx, "tank/other/projects/alpha/volumes/db") }, api.CodeForbidden},
		{"unload a persistent dataset", func() error { return f.client.UnloadKey(ctx, vkJail+"/etc") }, api.CodeForbidden},
		{"change a locked volume", func() error { return f.client.ChangeKey(ctx, vkVol, []byte(vkPass), []byte(vkNew)) }, api.CodeLocked},
		{"change with one passphrase", func() error {
			_, err := callJSON[empty](ctx, f.client, OpZFSChangeKey, nameArgs{vkVol}, callOpts{in: strings.NewReader(vkPass)})
			return err
		}, api.CodeInvalid},
		{"change with three lines", func() error {
			return f.client.ChangeKey(ctx, vkVol, []byte(vkPass), []byte(vkNew+"\nthird"))
		}, api.CodeInvalid},
		{"raw replicate outside the roots", func() error { return f.client.ReplicateRaw(ctx, vkVol+"@s", "tank/other/copy", nil) }, api.CodeForbidden},
	}
	for _, c := range cases {
		err := c.call()
		if !api.IsCode(err, c.code) {
			t.Errorf("%s: want %s, got %v", c.name, c.code, err)
			continue
		}
		noSecret(t, f, err.Error())
	}
	if n := len(f.runner.Calls()); n != 0 {
		t.Fatalf("a refused request ran zfs: %v", f.runner.Argv())
	}
}

func TestCreateEncryptedOverTheSocket(t *testing.T) {
	f, kw := newKeyFixture(t, "available")
	ctx := context.Background()
	mp := f.cfg.MountBase + "/projects/alpha/jails/web/root/srv/new"
	props := map[string]string{"jailops:managed": "on", "jailops:kind": "volume", "canmount": "noauto", "mountpoint": mp}
	refused := []struct {
		name  string
		o     zfs.CreateOpts
		pass  string
		code  api.Code
		props map[string]string
	}{
		{"short passphrase", zfs.CreateOpts{Name: vkVolumes + "/new"}, "short-pass", api.CodeInvalid, nil},
		{"a key file", zfs.CreateOpts{Name: vkVolumes + "/new"}, vkPass, api.CodeForbidden, map[string]string{"keylocation": "file:///etc/key"}},
		{"another cipher", zfs.CreateOpts{Name: vkVolumes + "/new"}, vkPass, api.CodeForbidden, map[string]string{"encryption": "aes-128-ccm"}},
		{"weaker key derivation", zfs.CreateOpts{Name: vkVolumes + "/new"}, vkPass, api.CodeForbidden, map[string]string{"pbkdf2iters": "1000"}},
		{"not a volume", zfs.CreateOpts{Name: vkJail + "/new"}, vkPass, api.CodeForbidden, nil},
		{"with parents", zfs.CreateOpts{Name: vkVolumes + "/new", Parents: true}, vkPass, api.CodeInvalid, nil},
		{"a zvol", zfs.CreateOpts{Name: vkVolumes + "/new", VolumeSize: "1G"}, vkPass, api.CodeInvalid, nil},
		{"outside the roots", zfs.CreateOpts{Name: "tank/other/projects/alpha/volumes/new"}, vkPass, api.CodeForbidden, nil},
		{"a mountpoint outside", zfs.CreateOpts{Name: vkVolumes + "/new"}, vkPass, api.CodeForbidden, map[string]string{"mountpoint": "/etc"}},
	}
	for _, r := range refused {
		o := r.o
		o.Props = map[string]string{}
		for k, v := range props {
			o.Props[k] = v
		}
		for k, v := range r.props {
			o.Props[k] = v
		}
		if err := f.client.CreateEncrypted(ctx, o, []byte(r.pass)); !api.IsCode(err, r.code) {
			t.Errorf("%s: want %s, got %v", r.name, r.code, err)
		}
	}
	if len(f.runner.Calls()) != 0 {
		t.Fatalf("a refused create ran zfs: %v", f.runner.Argv())
	}
	if err := f.client.CreateEncrypted(ctx, zfs.CreateOpts{Name: vkVolumes + "/new", Props: props}, []byte(vkPass)); err != nil {
		t.Fatal(err)
	}
	want := "zfs create -o canmount=noauto -o encryption=aes-256-gcm -o jailops:kind=volume -o jailops:managed=on -o keyformat=passphrase -o keylocation=prompt -o mountpoint=" + mp + " " + vkVolumes + "/new"
	if got := f.runner.Argv(); len(got) != 1 || got[0] != want {
		t.Fatalf("argv\n got %v\nwant %s", got, want)
	}
	if kw.get(vkVolumes+"/new") != vkPass {
		t.Fatalf("zfs read %q", kw.get(vkVolumes+"/new"))
	}
	noSecret(t, f)
}

func TestChangeKeyChecksTheOldPassphrase(t *testing.T) {
	f, kw := newKeyFixture(t, "available")
	ctx := context.Background()
	if err := f.client.ChangeKey(ctx, vkVol, []byte(vkWrong), []byte(vkNew)); !api.IsCode(err, api.CodeBadPassphrase) {
		t.Fatalf("wrong old passphrase: %v", err)
	}
	for _, a := range f.runner.Argv() {
		if strings.Contains(a, "change-key") {
			t.Fatalf("the key changed after a wrong old passphrase: %v", f.runner.Argv())
		}
	}
	if err := f.client.ChangeKey(ctx, vkVol, []byte(vkPass), []byte("short")); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("short new passphrase: %v", err)
	}
	if err := f.client.ChangeKey(ctx, vkVol, []byte(vkPass), []byte(vkNew)); err != nil {
		t.Fatal(err)
	}
	argv := f.runner.Argv()
	if argv[len(argv)-2] != "zfs load-key -n "+vkVol || argv[len(argv)-1] != "zfs change-key -o keyformat=passphrase -o keylocation=prompt "+vkVol {
		t.Fatalf("argv %v", argv)
	}
	if kw.get(vkVol) != vkNew {
		t.Fatalf("new passphrase %q", kw.get(vkVol))
	}
	noSecret(t, f)
}

func TestReadSecrets(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want []string
	}{
		{"a", 1, []string{"a"}},
		{strings.Repeat("p", 512), 1, []string{strings.Repeat("p", 512)}},
		{"old\nnew", 2, []string{"old", "new"}},
		{strings.Repeat("o", 512) + "\n" + strings.Repeat("n", 512), 2, []string{strings.Repeat("o", 512), strings.Repeat("n", 512)}},
	} {
		got, err := readSecrets(strings.NewReader(c.in), c.n)
		if err != nil || len(got) != len(c.want) {
			t.Fatalf("%q: %v %v", c.in, got, err)
		}
		for i := range got {
			if string(got[i]) != c.want[i] {
				t.Fatalf("%q: %q", c.in, got)
			}
		}
	}
	for _, c := range []struct {
		in string
		n  int
	}{
		{"", 1}, {"a\n", 1}, {"a\rb", 1}, {strings.Repeat("p", 513), 1}, {"old\n", 2}, {"\nnew", 2}, {"a\nb\nc", 2},
		{strings.Repeat("o", 513) + "\nn", 2},
	} {
		if _, err := readSecrets(strings.NewReader(c.in), c.n); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%q (%d): %v", c.in, c.n, err)
		}
	}
}

// sendRecorder records the send options the helper passes to zfs.
type sendRecorder struct {
	*zfs.Fake
	sends []zfs.SendOpts
}

func (r *sendRecorder) Send(ctx context.Context, o zfs.SendOpts, w io.Writer) error {
	r.sends = append(r.sends, o)
	return r.Fake.Send(ctx, o, w)
}

func TestReplicateRawSendsRaw(t *testing.T) {
	e := newEnv(t)
	e.addDS(vkVol, map[string]string{"jailops:managed": "on", "jailops:kind": "volume"})
	if err := e.zfs.Snapshot(context.Background(), zfs.SnapshotOpts{Names: []string{vkVol + "@c"}}); err != nil {
		t.Fatal(err)
	}
	rec := &sendRecorder{Fake: e.zfs}
	cfg := e.cfg
	cfg.reg = nil
	l, err := NewLocal(cfg, Deps{ZFS: rec, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	props := map[string]string{"jailops:managed": "on", "keylocation": "prompt"}
	if err := l.ReplicateRaw(context.Background(), vkVol+"@c", vkVolumes+"/copy", props); err != nil {
		t.Fatal(err)
	}
	if err := (zfsGuard{l}).Replicate(context.Background(), vkVol+"@c", vkVolumes+"/plain", nil); err != nil {
		t.Fatal(err)
	}
	if len(rec.sends) != 2 || !rec.sends[0].Raw || rec.sends[1].Raw {
		t.Fatalf("sends %+v", rec.sends)
	}
}

func TestFeatureStateOverTheSocket(t *testing.T) {
	f := newFixtureWith(t, func(e *env) {
		e.zfs.SetFeatures("tank", "encryption")
	})
	ctx := context.Background()
	fs, ok := f.client.ZFS().(zfs.FeatureStater)
	if !ok {
		t.Fatal("the helper's client reads no pool features")
	}
	if st, err := fs.FeatureState(ctx, "tank", "encryption"); err != nil || st != zfs.FeatureActive {
		t.Fatalf("%q %v", st, err)
	}
	if _, err := fs.FeatureState(ctx, "other", "encryption"); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a pool without a storage root: %v", err)
	}
	if _, err := fs.FeatureState(ctx, "tank", "encryption all"); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("a bad feature name: %v", err)
	}
	if _, err := callJSON[strRes](ctx, f.client, OpZFSFeatureState, map[string]string{"name": "tank", "feature": "encryption", "props": "all"}, callOpts{}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("extra arguments: %v", err)
	}
}

// testClock is a clock a test moves.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// The helper limits wrong passphrases itself, whatever the daemon does: after five for a volume every try waits, at
// first 30 seconds and twice as long after each further wrong one; the wait refuses without running zfs, a right
// passphrase too, and a right one afterwards forgets the failures. Changing the passphrase counts the same.
func TestWrongPassphrasesAreLimitedInTheHelper(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	var f *fixture
	f, _ = newKeyFixtureClock(t, "unavailable", clock.now)
	ctx := context.Background()
	zfsRuns := func() int {
		n := 0
		for _, a := range f.runner.Argv() {
			if strings.HasPrefix(a, "zfs load-key") {
				n++
			}
		}
		return n
	}
	for i := range keyFreeTries {
		if err := f.client.LoadKey(ctx, vkVol, []byte(vkWrong)); !api.IsCode(err, api.CodeBadPassphrase) {
			t.Fatalf("try %d: %v", i+1, err)
		}
	}
	n := zfsRuns()
	for _, p := range []string{vkWrong, vkPass} {
		err := f.client.LoadKey(ctx, vkVol, []byte(p))
		if !api.IsCode(err, api.CodeRateLimited) || !strings.Contains(err.Error(), "too many wrong passphrases") {
			t.Fatalf("while waiting: %v", err)
		}
	}
	if zfsRuns() != n {
		t.Fatal("zfs ran while the volume waited")
	}
	clock.add(keyBaseWait)
	if err := f.client.LoadKey(ctx, vkVol, []byte(vkWrong)); !api.IsCode(err, api.CodeBadPassphrase) {
		t.Fatalf("after the wait: %v", err)
	}
	// one more wrong: the wait doubles
	clock.add(keyBaseWait)
	if err := f.client.LoadKey(ctx, vkVol, []byte(vkPass)); !api.IsCode(err, api.CodeRateLimited) {
		t.Fatalf("the second wait is longer: %v", err)
	}
	clock.add(keyBaseWait)
	if err := f.client.LoadKey(ctx, vkVol, []byte(vkPass)); err != nil {
		t.Fatalf("the right passphrase after the wait: %v", err)
	}
	// forgotten: five wrong ones again before a wait (change-key's check counts the same)
	for i := range keyFreeTries {
		if err := f.client.ChangeKey(ctx, vkVol, []byte(vkWrong), []byte(vkNew)); !api.IsCode(err, api.CodeBadPassphrase) {
			t.Fatalf("change %d: %v", i+1, err)
		}
	}
	if err := f.client.ChangeKey(ctx, vkVol, []byte(vkPass), []byte(vkNew)); !api.IsCode(err, api.CodeRateLimited) {
		t.Fatalf("change while waiting: %v", err)
	}
	noSecret(t, f)
}

// All volumes together: after keyGlobalFree wrong passphrases every volume waits, also one never tried.
func TestKeyLimiterGlobal(t *testing.T) {
	var k keyLimiter
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	bad := api.Errorf(api.CodeBadPassphrase, "the passphrase is not correct")
	for i := range keyGlobalFree {
		ds := "tank/v" + strconv.Itoa(i%10) // ten volumes, two wrong each: none alone reaches its own limit
		if err := k.check(ds, now); err != nil {
			t.Fatalf("try %d: %v", i+1, err)
		}
		k.result(ds, bad, now)
	}
	if err := k.check("tank/never", now); !api.IsCode(err, api.CodeRateLimited) {
		t.Fatalf("a volume never tried: %v", err)
	}
	if err := k.check("tank/never", now.Add(keyBaseWait)); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
	if keyWait(keyFreeTries+20, keyFreeTries) != keyMaxWait || keyWait(keyFreeTries+1, keyFreeTries) != 2*keyBaseWait {
		t.Error("the wait does not double up to its maximum")
	}
}
