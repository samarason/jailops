package ndproxy

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func macN(i int) MAC { return MAC{2, 1, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)} }

var unknownTarget = netip.MustParseAddr("2001:db8::99")

// solicit sends a solicitation of the requester mac for an address the proxy does not hold: it counts only against the
// limits, not against the per-target budget.
func (r *rig) solicit(mac MAC) {
	r.p.HandleFrame(mkNS(router, unknownTarget, SolicitedNode(unknownTarget), mac, nil))
}

func TestNormalSolicitationsAreNeverLimited(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	for i := 0; i < 600; i++ { // ten minutes at a solicitation every second, from three neighbors
		r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
		r.solicit(macB)
		r.solicit(macN(7))
		r.clk.Advance(time.Second)
	}
	if m := r.p.Metrics(); m.Floods != 0 || r.p.FloodsLastHour() != 0 {
		t.Fatalf("a normal rate was limited: %+v", m)
	}
}

func TestAFloodFromOneSourceIsCutAtItsBudget(t *testing.T) {
	r := newRig(t, Config{})
	for i := 0; i < 500; i++ { // all at once: the burst passes, the rest is dropped without an answer
		r.solicit(macB)
	}
	m := r.p.Metrics()
	if m.Unknown != solicitBurst || m.Floods != 500-solicitBurst {
		t.Fatalf("passed %d, dropped %d: %+v", m.Unknown, m.Floods, m)
	}
	// the budget refills with time: a second later the source has solicitPerSource more
	r.clk.Advance(time.Second)
	before := r.p.Metrics().Unknown
	for i := 0; i < 500; i++ {
		r.solicit(macB)
	}
	if got := r.p.Metrics().Unknown - before; got != solicitPerSource {
		t.Fatalf("after a second %d passed, want %d", got, solicitPerSource)
	}
}

func TestSourcesDoNotShareABudget(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	for i := 0; i < 1000; i++ {
		r.solicit(macB)
	}
	// the router has another address: its solicitation is answered while macB floods
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	if m := r.p.Metrics(); m.Answered != 1 {
		t.Fatalf("the router was not answered while another neighbor flooded: %+v", m)
	}
}

func TestAllSolicitationsTogetherHaveABudget(t *testing.T) {
	r := newRig(t, Config{})
	n := solicitGeneralBurst + 1000
	for i := 0; i < n; i++ { // every solicitation from a source of its own, so no source limit applies
		r.solicit(macN(i + 1))
	}
	m := r.p.Metrics()
	if m.Unknown != solicitGeneralBurst || m.Floods != 1000 {
		t.Fatalf("passed %d, dropped %d", m.Unknown, m.Floods)
	}
}

// routerAsks runs the audit's picture: the router asks for the address of a jail ten times a second for five seconds
// while a flood runs alongside (flood is called each tenth of a second); it returns how many advertisements the router got.
func routerAsks(t *testing.T, r *rig, flood func(step int)) uint64 {
	t.Helper()
	if !r.p.table.Has(jailA) {
		r.add(t, jailA)
	}
	before := r.p.Metrics().Answered
	for step := 0; step < 50; step++ {
		if flood != nil {
			flood(step)
		}
		r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
		r.clk.Advance(100 * time.Millisecond)
	}
	return r.p.Metrics().Answered - before
}

// A flood from one MAC at twenty thousand a second spends its own allowance and nothing of the router's: the router
// is answered as often as when nothing floods (the global budget used to be charged before the source's, so the
// flood used it all up).
func TestAFloodFromOneMACDoesNotStarveTheRouter(t *testing.T) {
	quiet := routerAsks(t, newRig(t, Config{}), nil)
	if quiet == 0 {
		t.Fatal("the router was never answered without a flood")
	}
	r := newRig(t, Config{})
	got := routerAsks(t, r, func(int) {
		for i := 0; i < 2000; i++ {
			r.solicit(macB)
		}
	})
	if got != quiet {
		t.Fatalf("the router got %d answers during the flood, %d without it", got, quiet)
	}
	if r.p.Metrics().Floods == 0 {
		t.Fatal("the flood was not counted")
	}
}

// The source link-layer option is the sender's own claim: a sender that puts a different one in every solicitation is
// still one Ethernet source with one allowance.
func TestRotatingTheLinkLayerOptionDoesNotEvadeTheSourceBudget(t *testing.T) {
	r := newRig(t, Config{})
	for i := 0; i < 3000; i++ {
		other := macN(i + 1)
		r.p.HandleFrame(mkNS(router, unknownTarget, SolicitedNode(unknownTarget), macB, &other))
	}
	m := r.p.Metrics()
	if m.Unknown != solicitBurst || m.Floods != 3000-solicitBurst {
		t.Fatalf("passed %d, dropped %d: %+v", m.Unknown, m.Floods, m)
	}
	r.p.mu.Lock()
	n := len(r.p.sources)
	r.p.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d senders held for one Ethernet source", n)
	}
}

// A flood from a new MAC in every frame passes the allowance of each source and uses up the general budget; the router,
// which the proxy has answered over time, keeps the reserved part of it.
func TestAFloodOfManyMACsLeavesTheKnownRouterItsReservedShare(t *testing.T) {
	quiet := routerAsks(t, newRig(t, Config{}), nil)
	r := newRig(t, Config{})
	r.add(t, jailA)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	r.clk.Advance(2 * time.Second)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	r.clk.Advance(time.Second)
	r.p.mu.Lock()
	known := r.p.sources[macA] != nil && r.p.sources[macA].known
	r.p.mu.Unlock()
	if !known {
		t.Fatal("a requester that was answered and asked again a second later is not known")
	}
	n := 0
	got := routerAsks(t, r, func(int) {
		for i := 0; i < 2000; i++ { // twenty thousand a second, every one from a MAC of its own
			n++
			r.solicit(macN(n))
		}
	})
	if got != quiet {
		t.Fatalf("the known router got %d answers during the flood, %d without it", got, quiet)
	}
}

// A sender that changes its MAC every time is never known, however often it is answered, and a full table of known
// senders is not emptied by new ones.
func TestAnUnknownFloodNeverBecomesKnown(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	for i := 0; i < 5000; i++ {
		m := macN(i + 1)
		r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), m, &m))
		if i%100 == 99 {
			r.clk.Advance(time.Second)
		}
	}
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	for m, b := range r.p.sources {
		if b.known {
			t.Fatalf("%v is known after one answer", m)
		}
	}
}

func TestTheTableOfSourcesIsBounded(t *testing.T) {
	r := newRig(t, Config{})
	for i := 0; i < sourceTableMax*3; i++ {
		r.solicit(macN(i + 1))
		if i%1000 == 0 {
			r.clk.Advance(time.Second) // keep the total budget from ending the test early
		}
	}
	r.p.mu.Lock()
	n := len(r.p.sources)
	r.p.mu.Unlock()
	if n > sourceTableMax {
		t.Fatalf("%d sources held, the bound is %d", n, sourceTableMax)
	}
}

func TestDropsOfTheLastHourAreCountedAndLoggedOncePerMinute(t *testing.T) {
	r := newRig(t, Config{})
	var mu sync.Mutex
	var logs []string
	p, err := New(Config{Uplink: "em0"}, Deps{Capture: r.cap, Injector: r.inj, Routes: r.rt, Joiner: r.jn, Prober: r.pr, Clock: r.clk,
		Logf: func(f string, a ...any) { mu.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	p.hostMAC = macH
	flood := func(n int) {
		for i := 0; i < n; i++ {
			p.HandleFrame(mkNS(router, unknownTarget, SolicitedNode(unknownTarget), macB, nil))
		}
	}
	flood(solicitBurst + 50) // 50 dropped
	if got := p.Status().FloodsLastHour; got != 50 {
		t.Fatalf("floods in the last hour: %d, want 50", got)
	}
	flood(100) // inside the same minute: counted, not logged again
	mu.Lock()
	n := len(logs)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("%d log lines inside a minute: %v", n, logs)
	}
	r.clk.Advance(61 * time.Second)
	flood(solicitBurst + 10)
	mu.Lock()
	n = len(logs)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("%d log lines a minute later, want 2: %v", n, logs)
	}
	// after an hour without drops the count is gone
	r.clk.Advance(61 * time.Minute)
	if got := p.Status().FloodsLastHour; got != 0 {
		t.Fatalf("floods an hour later: %d", got)
	}
}

func TestAKnownSenderSurvivesAFloodThatFillsTheTable(t *testing.T) {
	r := newRig(t, Config{})
	r.add(t, jailA)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	r.clk.Advance(2 * time.Second)
	r.p.HandleFrame(mkNS(router, jailA, SolicitedNode(jailA), macA, &macA))
	for i := 0; i < sourceTableMax*3; i++ {
		r.solicit(macN(i + 1))
		if i%1000 == 0 {
			r.clk.Advance(time.Second)
		}
	}
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	if b := r.p.sources[macA]; b == nil || !b.known {
		t.Fatal("a flood of new senders pushed the known router out of the table")
	}
}
