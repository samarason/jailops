package priv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type fixture struct {
	*env
	sock   string
	srv    *Server
	client *Client
	audit  *syncBuf
}

func sockPath(t *testing.T) string {
	d, err := os.MkdirTemp("", "jop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "p.sock")
}

func (e *env) serve(t *testing.T, peers PeerPolicy) *fixture {
	t.Helper()
	f := &fixture{env: e, sock: sockPath(t), audit: &syncBuf{}}
	f.srv = NewServer(e.local, ServerOptions{Peers: peers, Audit: NewAuditor(f.audit), Version: "test"})
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := f.srv.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		<-done
	})
	return f
}

func selfPeers() PeerPolicy { return PeerPolicy{UIDs: []uint32{uint32(os.Getuid())}} }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, func(*env) {})
}

// newFixtureWith runs setup before the server starts, so test and server
// goroutines never touch shared fakes concurrently.
func newFixtureWith(t *testing.T, setup func(*env)) *fixture {
	t.Helper()
	e := newEnv(t)
	setup(e)
	f := e.serve(t, selfPeers())
	c, err := Dial(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	f.client = c
	return f
}

func TestRoundTripZFS(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	z := f.client.ZFS()

	if err := z.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/jails", Props: map[string]string{"jailops:managed": "on"}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := z.Exists(ctx, "tank/jailops/jails"); err != nil || !ok {
		t.Fatalf("exists: %v %v", ok, err)
	}
	if ok, _ := z.Exists(ctx, "tank/jailops/nope"); ok {
		t.Error("exists of a missing dataset")
	}
	if err := z.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops/jails@a", "tank/jailops@a"}}); err != nil {
		t.Fatal(err)
	}
	if err := z.Clone(ctx, "tank/jailops/jails@a", "tank/jailops/c1", map[string]string{"jailops:managed": "on"}, false); err != nil {
		t.Fatal(err)
	}
	cl, err := z.Clones(ctx, "tank/jailops/jails@a")
	if err != nil || len(cl) != 1 || cl[0] != "tank/jailops/c1" {
		t.Errorf("clones %v %v", cl, err)
	}
	if o, err := z.Origin(ctx, "tank/jailops/c1"); err != nil || o != "tank/jailops/jails@a" {
		t.Errorf("origin %q %v", o, err)
	}
	if err := z.Set(ctx, "tank/jailops/jails", map[string]string{"jailops:note": "hi"}); err != nil {
		t.Fatal(err)
	}
	props, err := z.Get(ctx, "tank/jailops/jails", "jailops:note", "jailops:managed")
	if err != nil || props["jailops:note"].Value != "hi" || props["jailops:note"].Source != "local" {
		t.Errorf("get %v %v", props, err)
	}
	if err := z.Inherit(ctx, "tank/jailops/jails", "jailops:note"); err != nil {
		t.Fatal(err)
	}
	ds, err := z.List(ctx, zfs.ListOpts{Recursive: true, Props: []string{"jailops:managed"}})
	if err != nil || len(ds) < 3 {
		t.Errorf("list %v %v", ds, err)
	}
	if err := z.Hold(ctx, "keep", "tank/jailops/jails@a"); err != nil {
		t.Fatal(err)
	}
	if h, err := z.Holds(ctx, "tank/jailops/jails@a"); err != nil || len(h) != 1 || h[0].Tag != "keep" {
		t.Errorf("holds %v %v", h, err)
	}
	// errors keep their code and detail across the socket
	err = z.Destroy(ctx, "tank/jailops/jails@a", zfs.DestroyOpts{})
	if !zfs.IsHeld(err) && !zfs.IsHasClones(err) {
		t.Errorf("destroy of a held snapshot: %v", err)
	}
	if err := z.Release(ctx, "keep", "tank/jailops/jails@a"); err != nil {
		t.Fatal(err)
	}
	if err := z.Bookmark(ctx, "tank/jailops/jails@a", "tank/jailops/jails#bm"); err != nil {
		t.Fatal(err)
	}
	if g, err := z.GUID(ctx, "tank/jailops/jails@a"); err != nil || g == 0 {
		t.Errorf("guid %d %v", g, err)
	}
	if _, err := z.Written(ctx, "tank/jailops/jails", ""); err != nil {
		t.Errorf("written %v", err)
	}
	if err := z.Rename(ctx, "tank/jailops/c1", "tank/jailops/c2", zfs.RenameOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := z.Rollback(ctx, "tank/jailops/jails@a", zfs.RollbackOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := z.Destroy(ctx, "tank/jailops/c2", zfs.DestroyOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := z.ListPools(ctx); err != nil {
		t.Errorf("pools %v", err)
	}
	if _, err := z.ActiveFeatures(ctx, "tank"); err != nil {
		t.Errorf("features %v", err)
	}
	if _, err := z.Get(ctx, "tank/jailops/missing"); !zfs.IsNotFound(err) {
		t.Errorf("missing: %v", err)
	}
	// validation happens in the helper
	if _, err := z.Exists(ctx, "tank/other"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("outside the root: %v", err)
	}
	if err := z.ReceiveAbort(ctx, "tank/jailops/jails"); err == nil {
		t.Error("abort without resumable state succeeded")
	}
}

func TestSendReceiveStreams(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	z := f.client.ZFS()
	f.managedDS("tank/jailops/src")
	if err := z.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{"tank/jailops/src@s1"}}); err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	if err := z.Send(ctx, zfs.SendOpts{Snapshot: "tank/jailops/src@s1"}, &stream); err != nil {
		t.Fatal(err)
	}
	if stream.Len() == 0 {
		t.Fatal("empty stream")
	}
	if err := z.Receive(ctx, zfs.ReceiveOpts{Target: "tank/jailops/dst"}, &stream); err != nil {
		t.Fatal(err)
	}
	if ok, _ := z.Exists(ctx, "tank/jailops/dst@s1"); !ok {
		t.Error("received snapshot is missing")
	}
	if err := z.Send(ctx, zfs.SendOpts{Snapshot: "tank/jailops/src@missing"}, io.Discard); !zfs.IsNotFound(err) {
		t.Errorf("send of a missing snapshot: %v", err)
	}
	if err := z.Receive(ctx, zfs.ReceiveOpts{Target: "tank/jailops/bad"}, strings.NewReader("not a stream\n")); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("garbage stream: %v", err)
	}
}

// bigZFS streams a large deterministic payload and hashes what it receives,
// to exercise flow control and memory use.
type bigZFS struct {
	*zfs.Fake
	size     int
	gotSum   chan [32]byte
	sendDone chan error
	block    chan struct{} // Send waits on ctx when set
	sawDone  chan error
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

func (b *bigZFS) Send(ctx context.Context, o zfs.SendOpts, w io.Writer) error {
	if b.block != nil {
		close(b.block)
		<-ctx.Done()
		b.sawDone <- ctx.Err()
		return ctx.Err()
	}
	_, err := w.Write(pattern(b.size))
	if b.sendDone != nil {
		b.sendDone <- err
	}
	return err
}

func (b *bigZFS) Receive(ctx context.Context, o zfs.ReceiveOpts, r io.Reader) error {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return err
	}
	if int(n) != b.size {
		return fmt.Errorf("received %d bytes, want %d", n, b.size)
	}
	var s [32]byte
	copy(s[:], h.Sum(nil))
	b.gotSum <- s
	return nil
}

func bigFixture(t *testing.T, size int) (*fixture, *bigZFS) {
	e := newEnv(t)
	big := &bigZFS{Fake: e.zfs, size: size, gotSum: make(chan [32]byte, 1)}
	l, err := NewLocal(e.cfg, Deps{ZFS: big, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	e.local = l
	f := e.serve(t, selfPeers())
	c, err := Dial(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	f.client = c
	return f, big
}

func TestLargeStreamsKeepMemoryBounded(t *testing.T) {
	const size = 8 << 20
	f, big := bigFixture(t, size)
	ctx := context.Background()
	z := f.client.ZFS()
	h := sha256.New()
	if err := z.Send(ctx, zfs.SendOpts{Snapshot: "tank/jailops@s"}, h); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(pattern(size))
	if string(h.Sum(nil)) != string(want[:]) {
		t.Error("send stream corrupted")
	}
	pr, pw := io.Pipe()
	go func() { pw.Write(pattern(size)); pw.Close() }()
	if err := z.Receive(ctx, zfs.ReceiveOpts{Target: "tank/jailops/x"}, pr); err != nil {
		t.Fatal(err)
	}
	if got := <-big.gotSum; got != want {
		t.Error("receive stream corrupted")
	}
}

func TestSlowConsumerDoesNotBlockOtherCalls(t *testing.T) {
	f, _ := bigFixture(t, 4<<20)
	ctx := context.Background()
	z := f.client.ZFS()
	release := make(chan struct{})
	slow := &slowWriter{release: release, entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- z.Send(ctx, zfs.SendOpts{Snapshot: "tank/jailops@s"}, slow) }()
	// while the writer is stalled, other requests on the same connection work
	select {
	case <-slow.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the send never reached the writer")
	}
	for i := 0; i < 20; i++ {
		if _, err := z.Exists(ctx, "tank/jailops"); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("send finished while its consumer was stalled: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if slow.n != 4<<20 {
		t.Errorf("received %d bytes", slow.n)
	}
}

type slowWriter struct {
	release chan struct{}
	entered chan struct{} // closed when the first Write has started and stalls
	once    sync.Once
	n       int
}

func (s *slowWriter) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered); <-s.release })
	s.n += len(p)
	return len(p), nil
}

func TestCancellationReachesTheHelper(t *testing.T) {
	e := newEnv(t)
	big := &bigZFS{Fake: e.zfs, block: make(chan struct{}), sawDone: make(chan error, 1)}
	l, _ := NewLocal(e.cfg, Deps{ZFS: big, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	e.local = l
	f := e.serve(t, selfPeers())
	c, err := Dial(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- c.ZFS().Send(ctx, zfs.SendOpts{Snapshot: "tank/jailops@s"}, io.Discard) }()
	<-big.block
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("client error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not return after cancel")
	}
	select {
	case err := <-big.sawDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("helper saw %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the helper never saw the cancellation")
	}
	// the connection is still usable
	if _, err := c.ZFS().Exists(context.Background(), "tank/jailops"); err != nil {
		t.Errorf("after cancel: %v", err)
	}
}

func TestDeadlineReachesTheHelper(t *testing.T) {
	e := newEnv(t)
	big := &bigZFS{Fake: e.zfs, block: make(chan struct{}), sawDone: make(chan error, 1)}
	l, _ := NewLocal(e.cfg, Deps{ZFS: big, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	e.local = l
	f := e.serve(t, selfPeers())
	c, _ := Dial(f.sock)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := c.ZFS().Send(ctx, zfs.SendOpts{Snapshot: "tank/jailops@s"}, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("client: %v", err)
	}
	select {
	case err := <-big.sawDone:
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Errorf("helper saw %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the helper never stopped the request")
	}
}

func TestJailsExecRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	mustWrite(t, filepath.Join(f.cfg.ConfDir, "alpha_web.conf"), f.goodConf())
	j := f.client.Jails()
	if err := j.Create(ctx, filepath.Join(f.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := j.Get(ctx, "alpha_web"); err != nil || !ok || got.Name != "alpha_web" {
		t.Errorf("get %+v %v %v", got, ok, err)
	}
	if _, ok, _ := j.Get(ctx, "ghost"); ok {
		t.Error("ghost jail")
	}
	list, err := j.List(ctx)
	if err != nil || len(list) != 1 {
		t.Errorf("list %v %v", list, err)
	}
	f.jails.ExecFn = func(name string, o jailos.ExecOpts) (run.Result, error) {
		var in []byte
		if o.Stdin != nil {
			in, _ = io.ReadAll(o.Stdin)
		}
		fmt.Fprintf(o.Stdout, "%s:%s:%s|", name, strings.Join(o.Argv, " "), in)
		if o.User == "fail" {
			return run.Result{ExitCode: 3, Stderr: []byte("boom")}, &run.ExitError{Name: "jexec", Args: o.Argv, Code: 3, Stderr: "boom"}
		}
		return run.Result{Stderr: []byte("warn")}, nil
	}
	var out bytes.Buffer
	res, err := j.Exec(ctx, "alpha_web", jailos.ExecOpts{Argv: []string{"cat"}, Stdin: strings.NewReader("hello"), Stdout: &out})
	if err != nil || out.String() != "alpha_web:cat:hello|" || string(res.Stderr) != "warn" {
		t.Errorf("exec: %q %+v %v", out.String(), res, err)
	}
	// without a Stdout writer the output is collected into the result
	res, err = j.Exec(ctx, "alpha_web", jailos.ExecOpts{Argv: []string{"id"}, Stdin: strings.NewReader("")})
	if err != nil || string(res.Stdout) != "alpha_web:id:|" {
		t.Errorf("collected: %+v %v", res, err)
	}
	res, err = j.Exec(ctx, "alpha_web", jailos.ExecOpts{Argv: []string{"false"}, User: "fail"})
	ee, ok := run.IsExit(err)
	if !ok || ee.Code != 3 || ee.Stderr != "boom" || res.ExitCode != 3 {
		t.Errorf("exit error: %+v %v", res, err)
	}
	if _, err := j.Exec(ctx, "alpha_ghost", jailos.ExecOpts{Argv: []string{"id"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("unmanaged: %v", err)
	}
	if err := j.Remove(ctx, filepath.Join(f.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerRoundTrip(t *testing.T) {
	f := newFixtureWith(t, func(e *env) { e.runner.CaptureStdin = false })
	ctx := context.Background()
	root := filepath.Join(f.cfg.MountBase, "projects", "alpha", "jails", "alpha_web", "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	f.runner.Add(run.Rule{Name: "/usr/sbin/pkg", Args: []string{"-r", root, "install", "-y", "nginx"}, Fn: func(c run.Cmd) (run.Result, error) {
		in, _ := io.ReadAll(c.Stdin)
		fmt.Fprint(c.Stdout, "installed ", string(in))
		return run.Result{}, nil
	}})
	f.runner.OnFail("/usr/sbin/pkg", []string{"-r", root, "install", "-y", "broken"}, 70, "no such package\n")
	r := f.client.Runner()
	res, err := r.Run(ctx, run.Cmd{Name: "pkg", Args: []string{"-r", root, "install", "-y", "nginx"}, Stdin: strings.NewReader("now")})
	if err != nil || string(res.Stdout) != "installed now" {
		t.Errorf("%+v %v", res, err)
	}
	res, err = r.Run(ctx, run.Cmd{Name: "pkg", Args: []string{"-r", root, "install", "-y", "broken"}})
	ee, ok := run.IsExit(err)
	if !ok || ee.Code != 70 || !strings.Contains(ee.Stderr, "no such package") {
		t.Errorf("%+v %v", res, err)
	}
	if _, err := r.Run(ctx, run.Cmd{Name: "sh", Args: []string{"-c", "id"}}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("sh: %v", err)
	}
	if _, err := r.Run(ctx, run.Cmd{Name: "pkg", Env: []string{"A=b"}}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("env: %v", err)
	}
}

func TestPFAndNetRoundTrip(t *testing.T) {
	f := newFixtureWith(t, func(e *env) { e.storeLan(t, "10.1.0.0/16") })
	ctx := context.Background()
	p := f.client.PF()
	if _, _, err := f.client.Net().EpairCreate(ctx, "jo0123456789a0"); err != nil {
		t.Fatal(err)
	}
	const rs = "pass in on jo0123456789a0a all\n"
	if err := p.Load(ctx, "jailops/web", rs); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Read(ctx, "jailops/web"); err != nil || got != rs {
		t.Errorf("read %q %v", got, err)
	}
	if n, err := p.Validate(ctx, "jailops/web", "pass all\n"); err != nil || n == "" {
		t.Errorf("validate %q %v", n, err)
	}
	if _, err := p.Validate(ctx, "jailops/web", "!syntax-error\n"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("syntax error: %v", err)
	}
	if err := p.TableAdd(ctx, "jailops/shared.pf", "t", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if got, err := p.TableShow(ctx, "jailops/shared.pf", "t"); err != nil || len(got) != 1 {
		t.Errorf("table %v %v", got, err)
	}
	if err := p.TableDelete(ctx, "jailops/shared.pf", "t", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(ctx, "jailops/web"); err != nil {
		t.Fatal(err)
	}
	if err := p.Load(ctx, "other/web", "pass all\n"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("anchor outside: %v", err)
	}

	n := f.client.Net()
	a, b, err := "jo0123456789a0a", "jo0123456789a0b", error(nil) // made above, for the ruleset that stands on it
	_ = b
	if err := n.SetDescription(ctx, a, "jailops jail=p/web net=lan (host side)"); err != nil {
		t.Fatal(err)
	}
	if err := n.AddrAdd(ctx, a, mustPrefix("10.1.0.1/32")); err != nil {
		t.Fatal(err)
	}
	if err := n.SetLink(ctx, a, true); err != nil {
		t.Fatal(err)
	}
	ifs, err := n.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var he *ifconfig.Iface
	for i := range ifs {
		if ifs[i].Name == a {
			he = &ifs[i]
		}
	}
	if he == nil || len(he.Inet) != 1 || !he.Up() {
		t.Errorf("host end %+v", he)
	}
	if err := n.RouteAdd(ctx, ifconfig.Route{Dest: "10.1.0.9/32", Interface: a}); err != nil {
		t.Fatal(err)
	}
	if err := n.RouteDelete(ctx, ifconfig.Route{Dest: "10.1.0.9/32", Interface: a}); err != nil {
		t.Fatal(err)
	}
	if err := n.RouteAdd(ctx, ifconfig.Route{Dest: "default", Gateway: "10.0.0.1"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("default route: %v", err)
	}
	if _, err := n.IPv6Forwarding(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.AddrRemove(ctx, a, mustPrefix("10.1.0.1/32")); err != nil {
		t.Fatal(err)
	}
	if err := n.EpairDestroy(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := n.EpairDestroy(ctx, a); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("second destroy: %v", err)
	}
}

func TestFilesAndMountsRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.client
	p := filepath.Join(f.cfg.MountBase, "projects", "alpha", "jails", "alpha_web", "etc", "rc.conf")
	if err := c.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("sshd_enable=\"YES\"\n"), Mode: 0o644, Parents: true}); err != nil {
		t.Fatal(err)
	}
	if b, err := c.ReadFile(ctx, p); err != nil || string(b) != "sshd_enable=\"YES\"\n" {
		t.Errorf("read %q %v", b, err)
	}
	if err := c.MkdirAll(ctx, MkdirReq{Path: filepath.Join(f.cfg.MountBase, "d", "e"), Mode: 0o750}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(f.cfg.MountBase, "d", "e")); err != nil || st.Mode().Perm() != 0o750 {
		t.Errorf("mkdir %v %v", st, err)
	}
	if err := c.Remove(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadFile(ctx, p); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("after remove: %v", err)
	}
	if _, err := c.ReadFile(ctx, "/etc/passwd"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("outside: %v", err)
	}
	// mount and unmount go through fixed zfs argv
	f.managedDS("tank/jailops/m")
	f.runner.On("zfs", []string{"mount", "tank/jailops/m"}, "")
	f.runner.On("zfs", []string{"unmount", "tank/jailops/m"}, "")
	if err := c.Mount(ctx, "tank/jailops/m"); err != nil {
		t.Fatal(err)
	}
	if err := c.Unmount(ctx, "tank/jailops/m"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mount(ctx, "tank/other"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("mount outside: %v", err)
	}
	if err := c.Mount(ctx, "-a"); err == nil {
		t.Error("mount -a")
	}
	f.runner.On("/sbin/sysctl", []string{"-n", "kern.osrelease"}, "15.0-RELEASE\n")
	if v, err := c.Sysctl(ctx, "kern.osrelease"); err != nil || v != "15.0-RELEASE" {
		t.Errorf("sysctl %q %v", v, err)
	}
}

func TestAdminAssertionTravels(t *testing.T) {
	e := newEnv(t)
	e.cfg.Admin.AllowFlags = []string{"mount.zfs"}
	l, _ := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	e.local = l
	f := e.serve(t, selfPeers())
	c, _ := Dial(f.sock)
	defer c.Close()
	conf := strings.Replace(e.goodConf(), "\tenforce_statfs = 2;\n", "\tenforce_statfs = 2;\n\tallow.mount.zfs;\n", 1)
	req := WriteFileReq{Path: filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), Data: []byte(conf), Mode: 0o644}
	if err := c.WriteFile(context.Background(), req); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("without the assertion: %v", err)
	}
	if err := c.WriteFile(WithAdmin(context.Background(), "alice"), req); err != nil {
		t.Errorf("with the assertion: %v", err)
	}
	if !strings.Contains(f.audit.String(), `"admin":"alice"`) {
		t.Errorf("the admin user is not in the audit log:\n%s", f.audit.String())
	}
	// an empty user is no assertion
	if err := c.WriteFile(WithAdmin(context.Background(), ""), req); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("empty admin user: %v", err)
	}
}

func TestAuditLog(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secret := "TOP-SECRET-CONTENT"
	_ = f.client.WriteFile(ctx, WriteFileReq{Path: filepath.Join(f.cfg.MountBase, "s"), Data: []byte(secret), Mode: 0o600})
	_, _ = f.client.ZFS().Exists(ctx, "tank/other")
	_ = f.client.PF().Load(ctx, "jailops/a", "pass all # "+secret+"\n") // refused: names no interface
	out := f.audit.String()
	if strings.Contains(out, secret) {
		t.Errorf("content leaked into the audit log:\n%s", out)
	}
	for _, want := range []string{`"op":"fs.write_file"`, `"outcome":"ok"`, `"outcome":"start"`, `"op":"zfs.exists"`, `"outcome":"forbidden"`, `"op":"pf.load"`, fmt.Sprintf(`"uid":%d`, os.Getuid()), `"target":{"path":`} {
		if !strings.Contains(out, want) {
			t.Errorf("audit log lacks %s:\n%s", want, out)
		}
	}
}

func TestPeerPolicy(t *testing.T) {
	e := newEnv(t)
	other := uint32(os.Getuid()) + 1
	f := e.serve(t, PeerPolicy{UIDs: []uint32{other}, DenyRoot: true})
	_, err := Dial(f.sock)
	if !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a peer outside the policy connected: %v", err)
	}
	if !strings.Contains(f.audit.String(), `"op":"connect"`) {
		t.Errorf("refusal not audited:\n%s", f.audit.String())
	}
	// by group
	f2 := e.serve(t, PeerPolicy{GIDs: []uint32{uint32(os.Getgid())}, DenyRoot: true})
	c, err := Dial(f2.sock)
	if err != nil {
		t.Fatalf("group policy: %v", err)
	}
	c.Close()
	// a failing credential read refuses the peer
	srv := NewServer(e.local, ServerOptions{Peers: selfPeers(), PeerCred: func(*net.UnixConn) (auth.Cred, error) { return auth.Cred{}, errors.New("no creds") }})
	sock := sockPath(t)
	ln, _ := net.Listen("unix", sock)
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())
	if _, err := Dial(sock); err == nil {
		t.Error("connected without credentials")
	}
}

func TestPeerPolicyUnit(t *testing.T) {
	p := PeerPolicy{UIDs: []uint32{100}, GIDs: []uint32{200}}
	cases := []struct {
		c  auth.Cred
		ok bool
	}{
		{auth.Cred{UID: 100}, true}, {auth.Cred{UID: 101, GID: 200}, true}, {auth.Cred{UID: 101, GID: 1, Groups: []uint32{5, 200}}, true},
		{auth.Cred{UID: 0}, true}, {auth.Cred{UID: 101, GID: 1}, false}, {auth.Cred{UID: 65534, GID: 65534}, false},
	}
	for _, k := range cases {
		if p.Allow(k.c) != k.ok {
			t.Errorf("%+v: %v", k.c, !k.ok)
		}
	}
	p.DenyRoot = true
	if p.Allow(auth.Cred{UID: 0}) {
		t.Error("root allowed with DenyRoot")
	}
	if (PeerPolicy{}).Allow(auth.Cred{UID: 1000}) {
		t.Error("empty policy allowed a user")
	}
}

func rawConn(t *testing.T, sock string) *net.UnixConn {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestVersionSkewAndProtocolErrors(t *testing.T) {
	f := newFixture(t)
	c := rawConn(t, f.sock)
	if err := WriteFrame(c, &Frame{Kind: KindHello, V: 99}); err != nil {
		t.Fatal(err)
	}
	h, err := ReadFrame(c)
	if err != nil || h.Err == nil || h.Err.Code != api.CodeVersionSkew {
		t.Fatalf("hello reply %+v %v", h, err)
	}

	// garbage instead of a hello
	c2 := rawConn(t, f.sock)
	c2.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(c2); err != nil && !errors.Is(err, io.EOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Error("the server kept a garbage connection open")
		}
	}

	// a valid hello, then an unknown operation and a malformed request
	c3 := rawConn(t, f.sock)
	WriteFrame(c3, &Frame{Kind: KindHello, V: ProtocolVersion})
	if h, err := ReadFrame(c3); err != nil || h.Err != nil {
		t.Fatalf("%+v %v", h, err)
	}
	WriteFrame(c3, &Frame{Kind: KindReq, ID: 1, Op: "rm.rf", Args: []byte(`{}`)})
	r, err := ReadFrame(c3)
	if err != nil || r.Err == nil || r.Err.Code != api.CodeUnsupported {
		t.Errorf("unknown op: %+v %v", r, err)
	}
	WriteFrame(c3, &Frame{Kind: KindReq, ID: 2, Op: OpZFSExists, Args: []byte(`{"name":"tank/jailops","extra":1}`)})
	if r, err = ReadFrame(c3); err != nil || r.Err == nil || r.Err.Code != api.CodeInvalid {
		t.Errorf("unknown field: %+v %v", r, err)
	}
	WriteFrame(c3, &Frame{Kind: KindReq, ID: 0, Op: OpZFSExists})
	if r, err = ReadFrame(c3); err != nil || r.Err == nil {
		t.Errorf("id 0: %+v %v", r, err)
	}
	WriteFrame(c3, &Frame{Kind: KindReq, ID: 3, Op: OpZFSExists, Args: []byte(`{"name":"tank/jailops"}`)})
	if r, err = ReadFrame(c3); err != nil || r.Err != nil {
		t.Errorf("valid request after errors: %+v %v", r, err)
	}
	// descriptors from a client are never accepted
	WriteFrame(c3, &Frame{Kind: "bogus", ID: 4})
	c3.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ReadFrame(c3); err == nil {
		t.Error("unknown frame kind did not close the connection")
	}

	// other connections are unaffected
	if _, err := f.client.ZFS().Exists(context.Background(), "tank/jailops"); err != nil {
		t.Errorf("a bad client broke a good one: %v", err)
	}
}

func TestClientIgnoringTheWindowIsDropped(t *testing.T) {
	e := newEnv(t)
	gate := make(chan struct{})
	l, _ := NewLocal(e.cfg, Deps{ZFS: &gatedZFS{Fake: e.zfs, gate: gate}, Runner: e.runner}, WithoutChown())
	e.local = l
	f := e.serve(t, selfPeers())
	c := rawConn(t, f.sock)
	WriteFrame(c, &Frame{Kind: KindHello, V: ProtocolVersion})
	ReadFrame(c)
	WriteFrame(c, &Frame{Kind: KindReq, ID: 1, Op: OpZFSReceive, Args: []byte(`{"Target":"tank/jailops/x"}`)})
	for i := 0; i < 3*Window; i++ {
		if err := WriteFrame(c, &Frame{Kind: KindData, ID: 1, Data: []byte("x")}); err != nil {
			break
		}
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, err := ReadFrame(c); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("a client that ignores the window was not dropped")
			}
			break
		}
	}
	close(gate)
}

type gatedZFS struct {
	*zfs.Fake
	gate chan struct{}
}

func (g *gatedZFS) Receive(ctx context.Context, o zfs.ReceiveOpts, r io.Reader) error {
	select {
	case <-g.gate:
	case <-ctx.Done():
	}
	return ctx.Err()
}

func TestPerConnectionConcurrencyLimit(t *testing.T) {
	e := newEnv(t)
	e.cfg.Limits.MaxInflight = 2
	block := make(chan struct{})
	started := make(chan struct{}, 8)
	e.jails.ExecFn = func(string, jailos.ExecOpts) (run.Result, error) {
		started <- struct{}{}
		<-block
		return run.Result{}, nil
	}
	l, _ := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	e.local = l
	mustWrite(t, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), e.goodConf())
	e.jails.Create(context.Background(), filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), "alpha_web")
	f := e.serve(t, selfPeers())
	c, _ := Dial(f.sock)
	defer c.Close()
	errs := make(chan error, 3)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := c.Jails().Exec(context.Background(), "alpha_web", jailos.ExecOpts{Argv: []string{"sleep"}})
			errs <- err
		}()
	}
	<-started
	<-started
	_, err := c.ZFS().Exists(context.Background(), "tank/jailops")
	if !api.IsCode(err, api.CodeBusy) {
		t.Errorf("third request: %v", err)
	}
	// a second connection has its own budget
	c2, _ := Dial(f.sock)
	defer c2.Close()
	if _, err := c2.ZFS().Exists(context.Background(), "tank/jailops"); err != nil {
		t.Errorf("second connection: %v", err)
	}
	close(block)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if _, err := c.ZFS().Exists(context.Background(), "tank/jailops"); err != nil {
		t.Errorf("after the others finished: %v", err)
	}
}

func TestConnectionLimit(t *testing.T) {
	e := newEnv(t)
	e.cfg.Limits.MaxConns = 2
	l, _ := NewLocal(e.cfg, Deps{ZFS: e.zfs}, WithoutChown())
	e.local = l
	f := e.serve(t, selfPeers())
	var cs []*Client
	for i := 0; i < 2; i++ {
		c, err := Dial(f.sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		cs = append(cs, c)
	}
	if c, err := Dial(f.sock); err == nil {
		// the refused connection fails on its handshake or on first use
		if _, err := c.ZFS().Exists(context.Background(), "tank/jailops"); err == nil {
			t.Error("a third connection worked")
		}
		c.Close()
	}
}

func TestConcurrentCalls(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.managedDS("tank/jailops/c")
	var wg sync.WaitGroup
	var fails atomic.Int32
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				var err error
				switch i % 3 {
				case 0:
					_, err = f.client.ZFS().Exists(ctx, "tank/jailops/c")
				case 1:
					_, err = f.client.ZFS().List(ctx, zfs.ListOpts{})
				case 2:
					_, err = f.client.Net().List(ctx)
				}
				if err != nil && !api.IsCode(err, api.CodeBusy) {
					fails.Add(1)
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatal("failures")
	}
}

func TestReconnect(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.client.ZFS().Exists(ctx, "tank/jailops"); err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	f.client.conn.fc.close()
	f.client.mu.Unlock()
	// the next call redials; poll with a deadline instead of guessing how long the drop takes
	var rerr error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, rerr = f.client.ZFS().Exists(ctx, "tank/jailops"); rerr == nil {
			break
		}
	}
	if rerr != nil {
		t.Errorf("no redial: %v", rerr)
	}
	f.client.Close()
	if _, err := f.client.ZFS().Exists(ctx, "tank/jailops"); err == nil {
		t.Error("a closed client worked")
	}
}

func TestShutdownCancelsRequests(t *testing.T) {
	e := newEnv(t)
	big := &bigZFS{Fake: e.zfs, block: make(chan struct{}), sawDone: make(chan error, 1)}
	l, _ := NewLocal(e.cfg, Deps{ZFS: big}, WithoutChown())
	e.local = l
	f := e.serve(t, selfPeers())
	c, _ := Dial(f.sock)
	defer c.Close()
	errc := make(chan error, 1)
	go func() {
		errc <- c.ZFS().Send(context.Background(), zfs.SendOpts{Snapshot: "tank/jailops@s"}, io.Discard)
	}()
	<-big.block
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Error("send succeeded across a shutdown")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the client hung after shutdown")
	}
}

func mustPrefix(s string) (p netipPrefix) {
	pp, err := parsePrefix(s)
	if err != nil {
		panic(err)
	}
	return pp
}

// A producer that writes in tiny pieces (zfs send does) still moves at the speed of full chunks.
func TestTinyWritesAreCoalesced(t *testing.T) {
	const size = 4 << 20
	f, big := bigFixture(t, size)
	pr, pw := io.Pipe()
	go func() {
		p := pattern(size)
		for len(p) > 0 {
			n := 300
			if n > len(p) {
				n = len(p)
			}
			pw.Write(p[:n])
			p = p[n:]
		}
		pw.Close()
	}()
	start := time.Now()
	if err := f.client.ZFS().Receive(context.Background(), zfs.ReceiveOpts{Target: "tank/jailops/x"}, pr); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(pattern(size))
	if got := <-big.gotSum; got != want {
		t.Error("stream corrupted")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("4 MiB in tiny writes took %v", d)
	}
}
