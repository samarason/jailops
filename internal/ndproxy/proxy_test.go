package ndproxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

type fakeStream struct {
	in   chan []byte
	done chan struct{}
	once sync.Once
}

func newStream() *fakeStream {
	return &fakeStream{in: make(chan []byte, 256), done: make(chan struct{})}
}

func (s *fakeStream) Next() ([]byte, error) {
	select {
	case f := <-s.in:
		return f, nil
	case <-s.done:
		return nil, errors.New("closed")
	}
}
func (s *fakeStream) Close() error { s.once.Do(func() { close(s.done) }); return nil }

type fakeCapture struct {
	mu      sync.Mutex
	info    LinkInfo
	err     error
	opens   int
	promisc []bool
	streams []*fakeStream
}

func (c *fakeCapture) Link() (LinkInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info, c.err
}
func (c *fakeCapture) set(i LinkInfo, err error) {
	c.mu.Lock()
	c.info, c.err = i, err
	c.mu.Unlock()
}
func (c *fakeCapture) Open(i LinkInfo, promisc bool) (Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opens++
	c.promisc = append(c.promisc, promisc)
	s := newStream()
	c.streams = append(c.streams, s)
	return s, nil
}
func (c *fakeCapture) stream(i int) *fakeStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < len(c.streams) {
		return c.streams[i]
	}
	return nil
}

type fakeInjector struct {
	mu     sync.Mutex
	frames [][]byte
	fail   int // the next sends fail (the helper refusing an address whose route it has not read yet)
}

func (f *fakeInjector) Send(b []byte) error {
	f.mu.Lock()
	if f.fail > 0 {
		f.fail--
		f.mu.Unlock()
		return errors.New("refused")
	}
	f.frames = append(f.frames, append([]byte(nil), b...))
	f.mu.Unlock()
	return nil
}

// all returns the answers (frames to one requester); announcements are counted by announced.
func (f *fakeInjector) all() [][]byte { return f.sent(false) }

// announced returns the unsolicited advertisements (frames to all nodes).
func (f *fakeInjector) announced() [][]byte { return f.sent(true) }

func (f *fakeInjector) sent(multicast bool) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for _, b := range f.frames {
		if p, err := Parse(b); err == nil && p.EthDst.IsMulticast() == multicast {
			out = append(out, b)
		}
	}
	return out
}

type fakeRoutes struct {
	mu     sync.Mutex
	routes map[netip.Addr]string
	member bool
	addErr error
	ops    []string
}

func (r *fakeRoutes) Add(_ context.Context, a netip.Addr, b string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.addErr != nil {
		return r.addErr
	}
	if r.routes == nil {
		r.routes = map[netip.Addr]string{}
	}
	r.routes[a] = b
	r.ops = append(r.ops, "add "+a.String())
	return nil
}
func (r *fakeRoutes) Remove(_ context.Context, a netip.Addr, b string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.routes, a)
	r.ops = append(r.ops, "del "+a.String())
	return nil
}
func (r *fakeRoutes) EnsureUplinkNotMember(context.Context, string) error {
	if r.member {
		return api.Errorf(api.CodeConflict, "member")
	}
	return nil
}
func (r *fakeRoutes) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.routes) }

type fakeJoiner struct {
	mu      sync.Mutex
	joined  map[netip.Addr]int // join calls
	left    map[netip.Addr]int
	failing bool
}

func (j *fakeJoiner) Join(_ string, g netip.Addr) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failing {
		return errors.New("join failed")
	}
	if j.joined == nil {
		j.joined = map[netip.Addr]int{}
	}
	j.joined[g]++
	return nil
}
func (j *fakeJoiner) Leave(_ string, g netip.Addr) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.left == nil {
		j.left = map[netip.Addr]int{}
	}
	j.left[g]++
	return nil
}
func (j *fakeJoiner) joins(g netip.Addr) int { j.mu.Lock(); defer j.mu.Unlock(); return j.joined[g] }

type fakeProber struct {
	mu     sync.Mutex
	probed []netip.Addr
}

func (p *fakeProber) Probe(a netip.Addr, _ string) error {
	p.mu.Lock()
	p.probed = append(p.probed, a)
	p.mu.Unlock()
	return nil
}
func (p *fakeProber) n() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.probed) }

type rig struct {
	p   *Proxy
	cap *fakeCapture
	inj *fakeInjector
	rt  *fakeRoutes
	jn  *fakeJoiner
	pr  *fakeProber
	clk *fakeClock
}

func newRig(t *testing.T, cfg Config) *rig {
	t.Helper()
	r := &rig{cap: &fakeCapture{info: LinkInfo{Index: 3, MAC: macH, Up: true}}, inj: &fakeInjector{},
		rt: &fakeRoutes{}, jn: &fakeJoiner{}, pr: &fakeProber{}, clk: newClock()}
	if cfg.Uplink == "" {
		cfg.Uplink = "em0"
	}
	p, err := New(cfg, Deps{Capture: r.cap, Injector: r.inj, Routes: r.rt, Joiner: r.jn, Prober: r.pr, Clock: r.clk})
	if err != nil {
		t.Fatal(err)
	}
	r.p = p
	// For direct HandleFrame tests the host MAC is set as Run would.
	p.hostMAC = macH
	return r
}

func (r *rig) add(t *testing.T, a netip.Addr) {
	t.Helper()
	if err := r.p.AddAddress(context.Background(), a, "jo0"); err != nil {
		t.Fatal(err)
	}
}

func parseOut(t *testing.T, f []byte) *Packet {
	t.Helper()
	p, err := Parse(f)
	if err != nil {
		t.Fatalf("our own frame does not parse: %v", err)
	}
	return p
}

func TestMulticastNSAnswered(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	out := r.inj.all()
	if len(out) != 1 {
		t.Fatalf("%d frames", len(out))
	}
	na := parseOut(t, out[0])
	if na.Type != TypeNeighborAdvertisement || na.Target != jailA || na.Src != jailA || na.Dst != router ||
		na.Flags != FlagSolicited|FlagOverride || na.TargetLLA == nil || *na.TargetLLA != macH ||
		na.EthSrc != macH || na.EthDst != macA {
		t.Fatalf("%+v", na)
	}
	if m := r.p.Metrics(); m.Answered != 1 || m.Dropped != 0 {
		t.Fatalf("%+v", m)
	}
}

func TestRouterFlag(t *testing.T) {
	r := newRig(t, Config{Router: true})
	r.add(t, jailA)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	if na := parseOut(t, r.inj.all()[0]); na.Flags != FlagRouter|FlagSolicited|FlagOverride {
		t.Fatalf("flags %#x", na.Flags)
	}
}

func TestUnicastNUDAnswered(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	// NUD: unicast to the host MAC, no SLLA; reply goes to the Ethernet source.
	f := BuildNS(macB, macH, router, jailA, jailA, nil)
	r.p.HandleFrame(f)
	out := r.inj.all()
	if len(out) != 1 {
		t.Fatal("no answer")
	}
	if na := parseOut(t, out[0]); na.EthDst != macB || na.Flags&FlagSolicited == 0 {
		t.Fatalf("%+v", na)
	}
}

// Another host of the uplink running DAD for an address of a running jail is told it is taken. (The jail's own DAD runs
// on its epair, and never reaches the capture of the uplink.)
func TestDADOfAnotherHostForAProxiedAddressIsDefended(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	before := len(r.inj.announced())
	r.p.HandleFrame(mkNS(netip.IPv6Unspecified(), jailA, SolicitedNode(jailA), macA, nil))
	got := r.inj.announced()
	if len(r.inj.all()) != 0 || len(got) != before+1 {
		t.Fatalf("answers=%d announced %d -> %d", len(r.inj.all()), before, len(got))
	}
	na := parseOut(t, got[len(got)-1])
	if na.Target != jailA || na.Dst != allNodes || na.EthDst != MulticastMAC(allNodes) || na.Flags&FlagSolicited != 0 || na.Flags&FlagOverride == 0 {
		t.Fatalf("%+v", na)
	}
	if m := r.p.Metrics(); m.DADDefended != 1 || m.DADIgnored != 0 {
		t.Fatalf("%+v", m)
	}
}

func TestDADForAnAddressWeDoNotProxyIsIgnored(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	other := netip.MustParseAddr("2001:db8::99")
	n := len(r.inj.all()) + len(r.inj.announced())
	r.p.HandleFrame(mkNS(netip.IPv6Unspecified(), other, SolicitedNode(other), macA, nil))
	if len(r.inj.all())+len(r.inj.announced()) != n {
		t.Fatal("defended an address that is not ours")
	}
	if m := r.p.Metrics(); m.DADIgnored != 1 || m.DADDefended != 0 {
		t.Fatalf("%+v", m)
	}
}

func TestDADDefenceStopsWithTheJail(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	if err := r.p.RemoveAddress(context.Background(), jailA); err != nil {
		t.Fatal(err)
	}
	n := len(r.inj.announced())
	r.p.HandleFrame(mkNS(netip.IPv6Unspecified(), jailA, SolicitedNode(jailA), macA, nil))
	if len(r.inj.announced()) != n {
		t.Fatal("defended the address of a jail that is gone")
	}
}

func TestDADDefenceInProbeModeDoesNotProbe(t *testing.T) {
	r := newRig(t, Config{Table: TableConfig{Mode: ModeProbe}})
	r.add(t, jailA)
	r.p.HandleFrame(mkNS(netip.IPv6Unspecified(), jailA, SolicitedNode(jailA), macA, nil))
	if r.pr.n() != 0 || r.p.Table().Pending() != 0 {
		t.Fatal("DAD triggered a probe")
	}
}

func TestUnknownTargetIgnored(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	other := netip.MustParseAddr("2001:db8::99")
	r.p.HandleFrame(mkNS(router, other, SolicitedNode(other), macA, &macA))
	if len(r.inj.all()) != 0 {
		t.Fatal("answered unknown target")
	}
	if m := r.p.Metrics(); m.Unknown != 1 || m.Dropped != 1 {
		t.Fatalf("%+v", m)
	}
}

func TestMalformedAndOwnFramesIgnored(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	bad := mkNS(router, jailA, SolicitedNode(jailA), macA, &macA)
	bad[etherHdrLen+7] = 1
	r.p.HandleFrame(bad)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macH, nil))                  // from ourselves
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), MAC{1, 0, 0, 0, 0, 1}, nil)) // multicast MAC
	r.p.HandleFrame([]byte{1, 2, 3})
	if len(r.inj.all()) != 0 {
		t.Fatal("answered")
	}
	if m := r.p.Metrics(); m.Malformed != 2 {
		t.Fatalf("%+v", m)
	}
}

func TestRemovalStopsAnswers(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	ns := mkNS(router, jailA, SolicitedNode(jailA), macA, &macA)
	r.p.HandleFrame(ns)
	if err := r.p.RemoveAddress(context.Background(), jailA); err != nil {
		t.Fatal(err)
	}
	r.p.HandleFrame(ns)
	if len(r.inj.all()) != 1 {
		t.Fatal("answered after removal")
	}
	if r.rt.count() != 0 || r.jn.left[SolicitedNode(jailA)] != 1 {
		t.Fatalf("cleanup: routes=%d left=%v", r.rt.count(), r.jn.left)
	}
	if err := r.p.RemoveAddress(context.Background(), jailA); !errors.Is(err, &api.Error{Code: api.CodeNotFound}) {
		t.Fatal(err)
	}
}

func TestSharedGroupRefcount(t *testing.T) {
	r := newRig(t, Config{})
	a, b := netip.MustParseAddr("2001:db8::1:2"), netip.MustParseAddr("2001:db8:0:1::1:2") // same low 24 bits
	r.add(t, a)
	r.add(t, b)
	g := SolicitedNode(a)
	if r.jn.joins(g) != 1 {
		t.Fatalf("joins %d", r.jn.joins(g))
	}
	_ = r.p.RemoveAddress(context.Background(), a)
	if r.jn.left[g] != 0 {
		t.Fatal("left a group still needed")
	}
	_ = r.p.RemoveAddress(context.Background(), b)
	if r.jn.left[g] != 1 {
		t.Fatal("group not left")
	}
}

func TestAddRollback(t *testing.T) {
	r := newRig(t, Config{})
	r.rt.addErr = errors.New("boom")
	if err := r.p.AddAddress(context.Background(), jailA, "jo0"); err == nil || r.p.Table().Has(jailA) {
		t.Fatal("route failure left the address")
	}
	r.rt.addErr = nil
	r.jn.failing = true
	if err := r.p.AddAddress(context.Background(), jailA, "jo0"); err == nil || r.p.Table().Has(jailA) || r.rt.count() != 0 {
		t.Fatal("join failure left state")
	}
}

func TestSync(t *testing.T) {
	r := newRig(t, Config{})
	b := netip.MustParseAddr("2001:db8::b")
	c := netip.MustParseAddr("2001:db8::c")
	ctx := context.Background()
	if err := r.p.Sync(ctx, []Entry{{jailA, "jo0"}, {b, "jo0"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.p.Sync(ctx, []Entry{{b, "jo1"}, {c, "jo0"}}); err != nil {
		t.Fatal(err)
	}
	got := r.p.Table().Addrs()
	if len(got) != 2 || got[0] != b || got[1] != c || r.rt.routes[b] != "jo1" || r.rt.count() != 2 {
		t.Fatalf("%v %v", got, r.rt.routes)
	}
}

func TestFloodBoundedProbeMode(t *testing.T) {
	r := newRig(t, Config{Table: TableConfig{Mode: ModeProbe, MaxPendingPerAddr: 4, MaxPendingTotal: 8}})
	r.add(t, jailA)
	for i := 0; i < 2000; i++ {
		src := netip.AddrFrom16([16]byte{0xfe, 0x80, 14: byte(i >> 8), 15: byte(i)})
		mac := MAC{2, 0, 0, 0, byte(i >> 8), byte(i)}
		r.p.HandleFrame(mkNS(src, jailA, SolicitedNode(jailA), mac, &mac))
	}
	if n := r.p.Table().Pending(); n != 4 {
		t.Fatalf("pending %d", n)
	}
	if m := r.p.Metrics(); m.Floods < 1990 || m.Answered != 0 {
		t.Fatalf("%+v", m)
	}
	if r.pr.n() != 1 {
		t.Fatalf("probes %d", r.pr.n())
	}
}

func TestRateLimit(t *testing.T) {
	r := newRig(t, Config{MaxAnswersPerSecond: 10})
	r.add(t, jailA)
	from := func(i int) []byte {
		return mkNS(netip.AddrFrom16([16]byte{0xfe, 0x80, 15: byte(i + 1)}), jailA, SolicitedNode(jailA), macA, &macA)
	}
	for i := 0; i < 100; i++ {
		r.p.HandleFrame(from(i))
	}
	m := r.p.Metrics()
	if m.Answered != 10 || m.Floods != 90 {
		t.Fatalf("%+v", m)
	}
	r.clk.Advance(time.Second)
	r.p.HandleFrame(from(0))
	if r.p.Metrics().Answered != 11 {
		t.Fatal("bucket did not refill")
	}
}

func TestProbeModeAnswersAfterReply(t *testing.T) {
	r := newRig(t, Config{Table: TableConfig{Mode: ModeProbe, RetransmitTime: time.Second, RetransmitLimit: 2}})
	r.add(t, jailA)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	if len(r.inj.all()) != 0 || r.pr.n() != 1 {
		t.Fatal("must probe first")
	}
	r.clk.Advance(time.Second)
	r.p.Tick()
	if r.pr.n() != 2 {
		t.Fatalf("retransmit: %d", r.pr.n())
	}
	r.p.NotifyReachable(jailA)
	out := r.inj.all()
	if len(out) != 1 || parseOut(t, out[0]).EthDst != macA {
		t.Fatal("queued requester not answered")
	}
	r.clk.Advance(time.Second) // not the same requester's retransmission any more
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	if len(r.inj.all()) != 2 {
		t.Fatal("valid entry must answer at once")
	}
}

func TestProbeModeRemovedWhileQueued(t *testing.T) {
	r := newRig(t, Config{Table: TableConfig{Mode: ModeProbe}})
	r.add(t, jailA)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	_ = r.p.RemoveAddress(context.Background(), jailA)
	r.p.NotifyReachable(jailA)
	if len(r.inj.all()) != 0 {
		t.Fatal("answered for removed address")
	}
}

func TestNewValidation(t *testing.T) {
	d := Deps{Capture: &fakeCapture{}, Injector: &fakeInjector{}, Routes: &fakeRoutes{}, Joiner: &fakeJoiner{}, Clock: newClock()}
	if _, err := New(Config{}, d); err == nil {
		t.Fatal("no uplink")
	}
	if _, err := New(Config{Uplink: "em0", Table: TableConfig{Mode: ModeProbe}}, d); err == nil {
		t.Fatal("probe mode without prober")
	}
	if _, err := New(Config{Uplink: "em0"}, Deps{}); err == nil {
		t.Fatal("no deps")
	}
}

// eventually advances the fake clock while waiting so poll timers fire.
func (r *rig) eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		r.clk.Advance(3 * time.Second)
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func startRun(t *testing.T, r *rig) (cancel func(), errc chan error) {
	t.Helper()
	ctx, c := context.WithCancel(context.Background())
	errc = make(chan error, 1)
	go func() { errc <- r.p.Run(ctx) }()
	return c, errc
}

func stopRun(t *testing.T, cancel func(), errc chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunAnswersAndStops(t *testing.T) {
	r := newRig(t, Config{})
	r.p.hostMAC = MAC{}
	r.add(t, jailA)
	cancel, errc := startRun(t, r)
	r.eventually(t, "open", func() bool { return r.cap.stream(0) != nil })
	r.cap.stream(0).in <- mkNS(router, jailA, SolicitedNode(jailA), macA, &macA)
	r.eventually(t, "answer", func() bool { return len(r.inj.all()) == 1 })
	if na := parseOut(t, r.inj.all()[0]); na.EthSrc != macH {
		t.Fatalf("host MAC %s", na.EthSrc)
	}
	stopRun(t, cancel, errc)
	select {
	case <-r.cap.stream(0).done:
	default:
		t.Fatal("stream left open")
	}
}

func TestRunReopensWhenLinkChanges(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	cancel, errc := startRun(t, r)
	defer stopRun(t, cancel, errc)
	r.eventually(t, "open", func() bool { return r.cap.stream(0) != nil })
	g := SolicitedNode(jailA)

	// Interface disappears.
	r.cap.set(LinkInfo{}, errors.New("no such interface"))
	r.eventually(t, "close", func() bool {
		select {
		case <-r.cap.stream(0).done:
			return true
		default:
			return false
		}
	})
	// It returns with a new index and MAC.
	newMAC := MAC{2, 0, 0, 0, 0, 0xbb}
	r.cap.set(LinkInfo{Index: 9, MAC: newMAC, Up: true}, nil)
	r.eventually(t, "reopen", func() bool { return r.cap.stream(1) != nil })
	r.eventually(t, "rejoin", func() bool { return r.jn.joins(g) >= 2 })
	r.cap.stream(1).in <- mkNS(router, jailA, g, macA, &macA)
	r.eventually(t, "answer", func() bool { return len(r.inj.all()) == 1 })
	if na := parseOut(t, r.inj.all()[0]); na.EthSrc != newMAC || *na.TargetLLA != newMAC {
		t.Fatal("answered with the stale MAC")
	}
	// MAC changes while the interface stays up.
	r.cap.set(LinkInfo{Index: 9, MAC: macH, Up: true}, nil)
	r.eventually(t, "reopen on mac change", func() bool { return r.cap.stream(2) != nil })
	if r.p.Metrics().Reopens != 3 {
		t.Fatalf("%+v", r.p.Metrics())
	}
}

func TestRunReopensOnReconfigure(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	cancel, errc := startRun(t, r)
	defer stopRun(t, cancel, errc)
	r.eventually(t, "open", func() bool { return r.cap.stream(0) != nil })
	if err := r.p.Reconfigure(Config{Uplink: "em0", Promisc: true, Table: TableConfig{Mode: ModeImmediate}}); err != nil {
		t.Fatal(err)
	}
	r.eventually(t, "reopen", func() bool { return r.cap.stream(1) != nil })
	r.cap.mu.Lock()
	pm := append([]bool(nil), r.cap.promisc...)
	r.cap.mu.Unlock()
	if len(pm) != 2 || pm[0] || !pm[1] {
		t.Fatalf("promisc %v", pm)
	}
	if !r.p.Table().Has(jailA) {
		t.Fatal("addresses lost on reconfigure")
	}
}

func TestReconfigureTimingWithoutRestart(t *testing.T) {
	r := newRig(t, Config{Table: TableConfig{Mode: ModeProbe}})
	r.add(t, jailA)
	if err := r.p.Reconfigure(Config{Uplink: "em0", Table: TableConfig{Mode: ModeImmediate}}); err != nil {
		t.Fatal(err)
	}
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	if len(r.inj.all()) != 1 {
		t.Fatal("not answering after switch to immediate")
	}
	if len(r.cap.streams) != 0 {
		t.Fatal("reopened for a timing change")
	}
	if err := r.p.Reconfigure(Config{}); err == nil {
		t.Fatal("empty uplink accepted")
	}
}

func TestRunRefusesBridgeMember(t *testing.T) {
	r := newRig(t, Config{})
	r.rt.member = true
	done := make(chan error, 1)
	go func() { done <- r.p.Run(context.Background()) }()
	select {
	case err := <-done:
		if err == nil || r.cap.opens != 0 {
			t.Fatalf("err=%v opens=%d", err, r.cap.opens)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not refuse")
	}
}

func TestRunTimersDriveProbes(t *testing.T) {
	r := newRig(t, Config{Table: TableConfig{Mode: ModeProbe, RetransmitTime: time.Second, RetransmitLimit: 3}})
	r.add(t, jailA)
	cancel, errc := startRun(t, r)
	defer stopRun(t, cancel, errc)
	r.eventually(t, "open", func() bool { return r.cap.stream(0) != nil })
	r.cap.stream(0).in <- mkNS(router, jailA, SolicitedNode(jailA), macA, &macA)
	r.eventually(t, "retransmits", func() bool { return r.pr.n() >= 3 })
}

// announcedTargets counts the unsolicited advertisements per target.
func announcedTargets(t *testing.T, r *rig) map[netip.Addr]int {
	t.Helper()
	m := map[netip.Addr]int{}
	for _, f := range r.inj.announced() {
		m[parseOut(t, f).Target]++
	}
	return m
}

func TestAnnouncementsAreForTheNewAddressOnly(t *testing.T) {
	jailB := netip.MustParseAddr("2001:db8::1:3")
	r := newRig(t, Config{})
	r.p.mu.Lock()
	r.p.open = true
	r.p.mu.Unlock()
	r.add(t, jailA)
	if next := r.p.Announce(); next.IsZero() {
		t.Fatal("a repeat is due and nothing said so")
	}
	if got := announcedTargets(t, r); got[jailA] != 1 || len(got) != 1 {
		t.Fatalf("%v", got)
	}
	// a second jail: only it is announced now, the first waits for its repeat
	r.add(t, jailB)
	r.p.Announce()
	if got := announcedTargets(t, r); got[jailA] != 1 || got[jailB] != 1 {
		t.Fatalf("an old address was announced again at once: %v", got)
	}
	// RetransTimer later both repeat, MAX_NEIGHBOR_ADVERTISEMENT times in all, then it stops
	for i := 0; i < 4; i++ {
		r.clk.Advance(announceSpacing)
		r.p.Announce()
	}
	if got := announcedTargets(t, r); got[jailA] != announceRepeats || got[jailB] != announceRepeats {
		t.Fatalf("%v", got)
	}
	if next := r.p.Announce(); !next.IsZero() {
		t.Fatal("announcements go on forever")
	}
}

func TestAnnouncementsHaveTheirOwnBudgetAndWaitWhenItIsSpent(t *testing.T) {
	r := newRig(t, Config{MaxAnswersPerSecond: 100})
	r.p.mu.Lock()
	r.p.open = true
	r.p.mu.Unlock()
	n := announceRate * 3
	for i := 0; i < n; i++ {
		r.add(t, netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i + 1)}))
	}
	next := r.p.Announce()
	if got := len(r.inj.announced()); got != announceRate {
		t.Fatalf("%d announced in one go, the budget is %d", got, announceRate)
	}
	if next.IsZero() {
		t.Fatal("what the budget did not cover was forgotten")
	}
	// an answer is still possible: the announcements did not use the answer budget
	r.add(t, jailA)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	if len(r.inj.all()) != 1 {
		t.Fatal("a solicitation was not answered during an announcement burst")
	}
	// the rest follows as the budget refills
	for i := 0; i < 20 && len(r.inj.announced()) < n; i++ {
		r.clk.Advance(time.Second)
		r.p.Announce()
	}
	if len(r.inj.announced()) < n {
		t.Fatalf("only %d of %d announced", len(r.inj.announced()), n)
	}
}

func TestRunAnnouncesAfterReopen(t *testing.T) {
	r := newRig(t, Config{})
	cancel, errc := startRun(t, r)
	defer stopRun(t, cancel, errc)
	r.eventually(t, "open", func() bool { return r.cap.stream(0) != nil })
	r.add(t, jailA)
	r.eventually(t, "announced", func() bool { return len(r.inj.announced()) >= 1 })
	na := parseOut(t, r.inj.announced()[0])
	if na.Target != jailA || na.Dst != allNodes || na.EthDst != MulticastMAC(allNodes) {
		t.Fatalf("%+v", na)
	}
	// Unsolicited: the router must not be told "solicited", only "override".
	if na.Flags&FlagSolicited != 0 || na.Flags&FlagOverride == 0 {
		t.Fatalf("flags %#x", na.Flags)
	}
	// all announcements are done after enough time; a new capture (the link came back) starts them again
	r.eventually(t, "all repeats", func() bool { return len(r.inj.announced()) >= announceRepeats })
	before := len(r.inj.announced())
	r.cap.set(LinkInfo{Index: 9, MAC: MAC{2, 0, 0, 0, 0, 0xbb}, Up: true}, nil)
	r.eventually(t, "announced again", func() bool { return len(r.inj.announced()) > before })
}

func TestARepeatedSolicitationIsAnsweredOnceAndAFloodAtOneTargetSparesTheOthers(t *testing.T) {
	jailB := netip.MustParseAddr("2001:db8::1:3")
	r := newRig(t, Config{MaxAnswersPerSecond: 100})
	r.add(t, jailA)
	r.add(t, jailB)
	ns := mkNS(router, jailA, SolicitedNode(jailA), macA, &macA)
	for i := 0; i < 5; i++ {
		r.p.HandleFrame(ns)
	}
	if len(r.inj.all()) != 1 || r.p.Metrics().Coalesced != 4 {
		t.Fatalf("answers %d, %+v", len(r.inj.all()), r.p.Metrics())
	}
	r.clk.Advance(answerGap)
	r.p.HandleFrame(ns)
	if len(r.inj.all()) != 2 {
		t.Fatal("the router's next retransmission was not answered")
	}
	// forged sources aimed at jail A use up jail A's budget only
	for i := 0; i < 500; i++ {
		src := netip.AddrFrom16([16]byte{0xfe, 0x80, 14: byte(i >> 8), 15: byte(i)})
		r.p.HandleFrame(mkNS(src, jailA, SolicitedNode(jailA), macA, &macA))
	}
	before := len(r.inj.all())
	r.p.HandleFrame(mkNS(router, jailB, SolicitedNode(jailB), macB, &macB))
	if len(r.inj.all()) != before+1 {
		t.Fatal("a flood at one jail starved the answers for another")
	}
}

type failingCapture struct {
	fakeCapture
	fails int
}

func (c *failingCapture) failsLeft() int { c.mu.Lock(); defer c.mu.Unlock(); return c.fails }

func (c *failingCapture) Open(i LinkInfo, promisc bool) (Stream, error) {
	c.mu.Lock()
	if c.fails > 0 {
		c.fails--
		c.mu.Unlock()
		return nil, errors.New("ndp.open refused")
	}
	c.mu.Unlock()
	return c.fakeCapture.Open(i, promisc)
}

func TestAClosedCaptureIsReportedAndRetriedWithBackoff(t *testing.T) {
	var (
		logs   []string
		logsMu sync.Mutex
	)
	allLogs := func() []string { logsMu.Lock(); defer logsMu.Unlock(); return append([]string(nil), logs...) }
	clk := newClock()
	cap := &failingCapture{fakeCapture: fakeCapture{info: LinkInfo{Index: 3, MAC: macH, Up: true}}, fails: 3}
	p, err := New(Config{Uplink: "em0"}, Deps{Capture: cap, Injector: &fakeInjector{}, Routes: &fakeRoutes{}, Joiner: &fakeJoiner{}, Clock: clk,
		Logf: func(f string, a ...any) { logsMu.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); logsMu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && p.Status().Err == "" {
		time.Sleep(time.Millisecond)
	}
	st := p.Status()
	if st.Open || !strings.Contains(st.Err, "ndp.open refused") {
		t.Fatalf("a refused capture is reported as working: %+v", st)
	}
	if l := allLogs(); len(l) != 1 {
		t.Fatalf("the first failure is logged once: %q", l)
	}
	// each retry waits longer than the one before; the third attempt succeeds and clears the report
	gaps := []time.Duration{}
	for i := 0; i < 3 && !p.Status().Open; i++ {
		before := cap.failsLeft()
		var waited time.Duration
		for cap.failsLeft() == before && p.Status().Err != "" && waited < time.Minute {
			clk.Advance(time.Second)
			waited += time.Second
			time.Sleep(time.Millisecond)
		}
		gaps = append(gaps, waited)
	}
	for time.Now().Before(deadline) && !p.Status().Open {
		clk.Advance(time.Second)
		time.Sleep(time.Millisecond)
	}
	if st := p.Status(); !st.Open || st.Err != "" {
		t.Fatalf("not open after the capture works again: %+v", st)
	}
	if l := allLogs(); len(l) != 2 || !strings.Contains(l[1], "open again") {
		t.Fatalf("%q", l)
	}
	if len(gaps) >= 2 && gaps[1] < gaps[0] {
		t.Fatalf("the delay did not grow: %v", gaps)
	}
}

// An announcement that could not be sent does not use up one of its repeats: the helper may refuse an address whose
// host route it has not read yet, and the announcement is tried again.
func TestAnAnnouncementThatFailedKeepsItsRepeats(t *testing.T) {
	r := newRig(t, Config{})
	r.p.mu.Lock()
	r.p.open = true
	r.p.mu.Unlock()
	r.inj.mu.Lock()
	r.inj.fail = 2
	r.inj.mu.Unlock()
	r.add(t, jailA) // queues the announcement
	r.p.Announce()  // refused
	if got := len(r.inj.announced()); got != 0 {
		t.Fatalf("%d announced while the sends fail", got)
	}
	if next := r.p.Announce(); next.IsZero() { // not due yet: waits
		t.Fatal("a failed announcement was forgotten")
	}
	for i := 0; i < 12; i++ {
		r.clk.Advance(announceRetry)
		r.p.Announce()
	}
	if got := len(r.inj.announced()); got != announceRepeats {
		t.Fatalf("%d announced, want all %d repeats after the failures", got, announceRepeats)
	}
	if m := r.p.Metrics(); m.InjectErrors != 2 {
		t.Fatalf("%+v", m)
	}
}

func TestAnAnnouncementThatAlwaysFailsIsGivenUp(t *testing.T) {
	r := newRig(t, Config{})
	r.p.mu.Lock()
	r.p.open = true
	r.p.mu.Unlock()
	r.inj.mu.Lock()
	r.inj.fail = 1000
	r.inj.mu.Unlock()
	r.add(t, jailA)
	for i := 0; i < announceMaxFails+2; i++ {
		r.p.Announce()
		r.clk.Advance(announceRetry)
	}
	if next := r.p.Announce(); !next.IsZero() {
		t.Fatal("kept trying forever")
	}
}

// A flood of solicitations for one target, from many forged source addresses but one attacker MAC, must not drain
// the answer budget a different MAC (the real router, keyed separately) needs for the very same target: see "the
// per-target flood" of design 18.10. The token bucket is keyed by (target, requester MAC), not by target alone.
func TestPerTargetFloodDoesNotStarveAnotherRequestersMAC(t *testing.T) {
	r := newRig(t, Config{}) // MaxAnswersPerSecond unset: only the per-(target, MAC) budget is under test
	r.add(t, jailA)
	flood := func(i int) []byte {
		src := netip.AddrFrom16([16]byte{0xfe, 0x80, 14: byte((i + 100) >> 8), 15: byte(i + 100)}) // away from fe80::1 (router)
		return mkNS(src, jailA, SolicitedNode(jailA), macB, &macB)
	}
	for i := 0; i < answerPerTarget+10; i++ {
		r.p.HandleFrame(flood(i))
	}
	floodedAnswered := r.p.Metrics().Answered
	if floodedAnswered != answerPerTarget {
		t.Fatalf("the flood from macB got %d answers, want exactly its own budget of %d", floodedAnswered, answerPerTarget)
	}
	// the router (macA) solicits the very same target now: its own (target, MAC) budget is untouched by macB's flood
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	if got := r.p.Metrics().Answered; got != floodedAnswered+1 {
		t.Fatalf("the router's solicitation for the flooded target was not answered: %d -> %d", floodedAnswered, got)
	}
}
