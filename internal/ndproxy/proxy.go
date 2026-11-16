package ndproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"jailops.net/jailops/sdk/api"
)

// LinkInfo describes the uplink as the system currently sees it.
type LinkInfo struct {
	Index int
	MAC   MAC
	Up    bool
}

// Stream delivers captured frames. Next blocks until a frame is available
// or the stream fails; it must return an error promptly after Close.
// The returned slice is only valid until the next call to Next.
type Stream interface {
	Next() ([]byte, error)
	Close() error
}

// Capture reads frames from the uplink.
type Capture interface {
	// Link reports the uplink's current index, MAC and state.
	Link() (LinkInfo, error)
	// Open starts capturing NS/NA frames on the uplink described by info.
	Open(info LinkInfo, promisc bool) (Stream, error)
}

// Injector sends a complete Ethernet frame out of the uplink.
type Injector interface {
	Send(frame []byte) error
}

// Routes manages the host side of the proxy.
type Routes interface {
	// Add installs a /128 host route for addr through iface, the host end of the jail's epair.
	Add(ctx context.Context, addr netip.Addr, iface string) error
	// Remove deletes that route.
	Remove(ctx context.Context, addr netip.Addr, iface string) error
	// EnsureUplinkNotMember fails if uplink is a member of any bridge.
	EnsureUplinkNotMember(ctx context.Context, uplink string) error
}

// Joiner joins and leaves solicited-node multicast groups on an interface.
// Join must be idempotent: the proxy repeats it after the link returns.
type Joiner interface {
	Join(iface string, group netip.Addr) error
	Leave(iface string, group netip.Addr) error
}

// Prober sends a solicitation for addr toward the jail, on iface (the host end of its epair). It is only
// needed in ModeProbe. The reply is reported with Proxy.NotifyReachable.
type Prober interface {
	Probe(addr netip.Addr, iface string) error
}

// Deps are the collaborators of a Proxy.
type Deps struct {
	Capture  Capture
	Injector Injector
	Routes   Routes
	Joiner   Joiner
	Prober   Prober // required in ModeProbe
	Clock    Clock
	// Logf, when set, receives the first failure to open the capture and its recovery.
	Logf func(format string, args ...any)
}

// Config configures the Proxy. Zero values take defaults.
type Config struct {
	Uplink string
	Table  TableConfig
	// Promisc puts the uplink into promiscuous mode. It is off by default:
	// the design expects solicited-node group membership and the host's
	// own MAC to make promiscuous mode unnecessary (UNVERIFIED).
	Promisc bool
	// Router sets the R flag in advertisements.
	Router bool
	// LinkPoll is how often the uplink is checked for changes (default 2s).
	LinkPoll time.Duration
	// MaxAnswersPerSecond bounds advertisements sent; 0 means unlimited.
	MaxAnswersPerSecond int
}

const (
	// announceRepeats is MAX_NEIGHBOR_ADVERTISEMENT of RFC 4861: an unsolicited advertisement may be repeated,
	// RetransTimer apart, in case the first is lost.
	announceRepeats = 3
	announceSpacing = time.Second
	// announceRetry is how long an announcement that could not be sent waits before the next try, and
	// announceMaxFails how many failures end the attempts. The helper refuses an address whose host route it has not
	// read yet (its reading is up to a second old), so the retry is longer than that. A failure does not use up one
	// of the announcement's repeats.
	announceRetry    = 1200 * time.Millisecond
	announceMaxFails = 20
	// announceRate is the proxy's own budget for unsolicited advertisements, so that a rollout of many jails never
	// uses the budget that answers need.
	announceRate = 10
	// answerGap is how soon the same requester may be answered again for the same target; a repeated solicitation
	// inside it is the router's retransmission or a flood.
	answerGap = 100 * time.Millisecond
	// answerPerTarget bounds the advertisements for one address per second, so that a flood aimed at one jail
	// cannot use up the budget of the others.
	answerPerTarget = 20
	openBackoffMin  = 2 * time.Second
	openBackoffMax  = 30 * time.Second
)

// Status says whether the proxy can answer right now.
type Status struct {
	// Open is true while the capture of the uplink is open.
	Open bool
	// Err is the last reason the capture could not be opened; empty while it works.
	Err string
	// Addresses is the number of proxied addresses.
	Addresses int
	// FloodsLastHour is how many solicitations the limits dropped in the last hour.
	FloodsLastHour uint64
	Metrics
}

type announceState struct {
	left  int
	due   time.Time
	fails int
}

// tbKey bounds answerPerTarget per target and per requester MAC, so a flood that forges only its claimed source IP
// (not its MAC, which answerKey already keys the coalescing gap by) cannot drain the budget a different, real
// requester (notably the router) needs.
type tbKey struct {
	target netip.Addr
	mac    MAC
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// take refills the bucket for the time that has passed and takes one token.
func (b *tokenBucket) take(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens += d * rate
		if b.tokens > burst {
			b.tokens = burst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type answerKey struct{ target, requester netip.Addr }

// Metrics is a snapshot of the counters.
type Metrics struct {
	Answered     uint64 // advertisements sent
	Announced    uint64 // unsolicited advertisements sent
	Dropped      uint64 // solicitations not answered for any reason
	Malformed    uint64 // frames that failed validation
	Floods       uint64 // solicitations dropped by a bound or the rate limit
	Coalesced    uint64 // repeated solicitations of one requester for one target, answered once
	DADIgnored   uint64 // DAD probes for addresses that are not proxied, left unanswered
	DADDefended  uint64 // DAD probes of other hosts for a proxied address, answered so that they see the duplicate
	Unknown      uint64 // solicitations for addresses that are not proxied
	Probes       uint64 // probes sent toward the jail
	Reopens      uint64 // times the capture was (re)opened
	InjectErrors uint64
}

type counters struct {
	answered, announced, dropped, malformed, floods, coalesced, dad, defended, unknown, probes, reopens, injectErrors atomic.Uint64
}

// Proxy answers neighbor solicitations on the uplink for allocated jail
// addresses. Routed IPv6 never depends on it.
type Proxy struct {
	deps  Deps
	table *Table
	m     counters

	admin sync.Mutex // serialises Add/Remove/Sync/Reconfigure

	mu      sync.Mutex
	cfg     Config
	hostMAC MAC
	// pending are the addresses still to be announced: new ones, and all of them after the capture is reopened.
	pending map[netip.Addr]*announceState
	abucket tokenBucket
	// answered remembers when a requester was last answered for a target; tbucket bounds the answers per
	// (target, requester MAC): keyed by MAC, not just by target, so a flood of solicitations for one target that
	// varies its claimed source IP (coalescing is keyed by IP) cannot drain the budget that the real router's own
	// MAC needs to keep getting answered (see "the per-target flood" in design 18.10). A requester that also varies
	// its own MAC pays for a new MAC each time, which most switched segments restrict or log (port security); it is
	// not prevented here, which design 18.10 says plainly.
	answered map[answerKey]time.Time
	tbucket  map[tbKey]*tokenBucket
	// sources and total bound the solicitations the proxy looks at (flood.go); floodLog counts the drops of the last hour.
	sources     map[MAC]*sourceBucket
	total       tokenBucket
	reserved    tokenBucket
	floodLog    hourLog
	floodSince  uint64
	floodLogged time.Time
	// openErr, openFails and nextOpen describe failed attempts to open the capture.
	openErr   string
	openFails int
	nextOpen  time.Time
	wake      chan struct{}
	link      LinkInfo
	open      bool
	ifaces    map[netip.Addr]string
	groups    map[netip.Addr]int // solicited-node group -> address count
	bucket    float64
	last      time.Time
	reload    chan struct{}
}

// New builds a Proxy.
func New(cfg Config, deps Deps) (*Proxy, error) {
	if cfg.Uplink == "" {
		return nil, api.Errorf(api.CodeInvalid, "uplink interface is required")
	}
	if deps.Capture == nil || deps.Injector == nil || deps.Routes == nil || deps.Joiner == nil || deps.Clock == nil {
		return nil, api.Errorf(api.CodeInvalid, "capture, injector, routes, joiner and clock are required")
	}
	if cfg.Table.Mode == ModeProbe && deps.Prober == nil {
		return nil, api.Errorf(api.CodeInvalid, "probe mode needs a prober")
	}
	if cfg.LinkPoll <= 0 {
		cfg.LinkPoll = 2 * time.Second
	}
	return &Proxy{
		deps:     deps,
		cfg:      cfg,
		table:    NewTable(cfg.Table, deps.Clock),
		ifaces:   map[netip.Addr]string{},
		groups:   map[netip.Addr]int{},
		reload:   make(chan struct{}, 1),
		wake:     make(chan struct{}, 1),
		pending:  map[netip.Addr]*announceState{},
		answered: map[answerKey]time.Time{},
		tbucket:  map[tbKey]*tokenBucket{},
		sources:  map[MAC]*sourceBucket{},
	}, nil
}

// Table exposes the session table (read-mostly; used by status and tests).
func (p *Proxy) Table() *Table { return p.table }

// Metrics returns a snapshot of the counters.
func (p *Proxy) Metrics() Metrics {
	return Metrics{
		Answered: p.m.answered.Load(), Announced: p.m.announced.Load(), Dropped: p.m.dropped.Load(), Malformed: p.m.malformed.Load(),
		Floods: p.m.floods.Load(), Coalesced: p.m.coalesced.Load(), DADIgnored: p.m.dad.Load(), DADDefended: p.m.defended.Load(), Unknown: p.m.unknown.Load(),
		Probes: p.m.probes.Load(), Reopens: p.m.reopens.Load(), InjectErrors: p.m.injectErrors.Load(),
	}
}

// AddAddress starts proxying addr, routing it through iface. It is safe to call
// while Run is active. On any failure nothing is left behind.
func (p *Proxy) AddAddress(ctx context.Context, addr netip.Addr, iface string) error {
	if iface == "" {
		return api.Errorf(api.CodeInvalid, "interface is required")
	}
	p.admin.Lock()
	defer p.admin.Unlock()
	return p.addLocked(ctx, addr, iface)
}

func (p *Proxy) addLocked(ctx context.Context, addr netip.Addr, iface string) error {
	if err := p.table.Add(addr); err != nil {
		return err
	}
	if err := p.deps.Routes.Add(ctx, addr, iface); err != nil {
		p.table.Remove(addr)
		return fmt.Errorf("ndproxy: route for %s: %w", addr, err)
	}
	g := SolicitedNode(addr)
	p.mu.Lock()
	p.ifaces[addr] = iface
	first := p.groups[g] == 0
	p.groups[g]++
	uplink := p.cfg.Uplink
	p.mu.Unlock()
	if first {
		if err := p.deps.Joiner.Join(uplink, g); err != nil {
			p.dropLocked(ctx, addr)
			return fmt.Errorf("ndproxy: join %s: %w", g, err)
		}
	}
	p.mu.Lock()
	p.pending[addr] = &announceState{left: announceRepeats}
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return nil
}

// RemoveAddress stops proxying addr at once; the route and group are then
// cleaned up. A cleanup error is returned but the address is already gone.
func (p *Proxy) RemoveAddress(ctx context.Context, addr netip.Addr) error {
	p.admin.Lock()
	defer p.admin.Unlock()
	if !p.table.Has(addr) {
		return api.Errorf(api.CodeNotFound, "address %s is not proxied", addr)
	}
	return p.dropLocked(ctx, addr)
}

func (p *Proxy) dropLocked(ctx context.Context, addr netip.Addr) error {
	p.table.Remove(addr) // answers stop before any I/O below
	g := SolicitedNode(addr)
	p.mu.Lock()
	iface := p.ifaces[addr]
	delete(p.ifaces, addr)
	delete(p.pending, addr)
	for k := range p.tbucket {
		if k.target == addr {
			delete(p.tbucket, k)
		}
	}
	last := false
	if p.groups[g] > 0 {
		p.groups[g]--
		if p.groups[g] == 0 {
			delete(p.groups, g)
			last = true
		}
	}
	uplink := p.cfg.Uplink
	p.mu.Unlock()
	var errs []error
	if iface != "" {
		if err := p.deps.Routes.Remove(ctx, addr, iface); err != nil {
			errs = append(errs, err)
		}
	}
	if last {
		if err := p.deps.Joiner.Leave(uplink, g); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Entry is one desired proxied address.
type Entry struct {
	Addr netip.Addr
	// Iface is the host end of the jail's epair.
	Iface string
}

// Sync makes the proxied set equal to entries: missing addresses are added,
// extra ones removed. All errors are collected.
func (p *Proxy) Sync(ctx context.Context, entries []Entry) error {
	p.admin.Lock()
	defer p.admin.Unlock()
	want := map[netip.Addr]string{}
	for _, e := range entries {
		want[e.Addr] = e.Iface
	}
	var errs []error
	for _, a := range p.table.Addrs() {
		b, ok := want[a]
		p.mu.Lock()
		cur := p.ifaces[a]
		p.mu.Unlock()
		if !ok || b != cur {
			errs = append(errs, p.dropLocked(ctx, a))
		}
	}
	for _, e := range entries {
		if !p.table.Has(e.Addr) {
			errs = append(errs, p.addLocked(ctx, e.Addr, e.Iface))
		}
	}
	return errors.Join(errs...)
}

// Reconfigure applies new settings without a restart. Timing, mode, limits
// and flags take effect at once; a changed uplink or promiscuous setting
// makes Run reopen the capture. Proxied addresses are kept.
func (p *Proxy) Reconfigure(cfg Config) error {
	if cfg.Uplink == "" {
		return api.Errorf(api.CodeInvalid, "uplink interface is required")
	}
	if cfg.Table.Mode == ModeProbe && p.deps.Prober == nil {
		return api.Errorf(api.CodeInvalid, "probe mode needs a prober")
	}
	if cfg.LinkPoll <= 0 {
		cfg.LinkPoll = 2 * time.Second
	}
	p.admin.Lock()
	defer p.admin.Unlock()
	p.mu.Lock()
	old := p.cfg
	p.cfg = cfg
	groups := make([]netip.Addr, 0, len(p.groups))
	for g := range p.groups {
		groups = append(groups, g)
	}
	p.mu.Unlock()
	p.table.SetConfig(cfg.Table)
	if old.Uplink != cfg.Uplink {
		for _, g := range groups {
			_ = p.deps.Joiner.Leave(old.Uplink, g) // best effort: old link may be gone
		}
	}
	if old.Uplink != cfg.Uplink || old.Promisc != cfg.Promisc {
		select {
		case p.reload <- struct{}{}:
		default:
		}
	}
	return nil
}

// NotifyReachable reports that the jail answered a probe for addr (ModeProbe);
// queued requesters are answered.
func (p *Proxy) NotifyReachable(addr netip.Addr) {
	for _, r := range p.table.Reachable(addr) {
		p.answer(addr, r)
	}
}

// allow applies the answer rate limit.
func (p *Proxy) allow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	rate := float64(p.cfg.MaxAnswersPerSecond)
	if rate <= 0 {
		return true
	}
	now := p.deps.Clock.Now()
	if p.last.IsZero() {
		p.bucket = rate
	} else if d := now.Sub(p.last).Seconds(); d > 0 {
		p.bucket += d * rate
		if p.bucket > rate {
			p.bucket = rate
		}
	}
	p.last = now
	if p.bucket < 1 {
		return false
	}
	p.bucket--
	return true
}

func (p *Proxy) answer(target netip.Addr, r Requester) {
	if !p.table.Has(target) {
		return // removed while queued: never answer
	}
	now := p.deps.Clock.Now()
	p.mu.Lock()
	key := answerKey{target, r.IP}
	if t, ok := p.answered[key]; ok && now.Sub(t) < answerGap {
		p.mu.Unlock()
		p.m.coalesced.Add(1)
		return
	}
	if len(p.answered) > 4096 { // forged sources: keep the memory bounded whatever the timers do
		for k, t := range p.answered {
			if now.Sub(t) > time.Second {
				delete(p.answered, k)
			}
		}
		if len(p.answered) > 4096 {
			p.answered = map[answerKey]time.Time{}
		}
	}
	tbk := tbKey{target, r.MAC}
	tb := p.tbucket[tbk]
	if tb == nil {
		tb = &tokenBucket{}
		p.tbucket[tbk] = tb
		if len(p.tbucket) > 4096 { // many distinct (target, MAC) pairs: bound the memory, same idea as p.answered
			p.tbucket = map[tbKey]*tokenBucket{tbk: tb}
		}
	}
	if !tb.take(now, answerPerTarget, answerPerTarget) {
		p.mu.Unlock()
		p.flood()
		return
	}
	p.mu.Unlock()
	if !p.allow() {
		p.flood()
		return
	}
	p.mu.Lock()
	p.answered[key] = now
	host, router := p.hostMAC, p.cfg.Router
	p.mu.Unlock()
	flags := uint8(FlagSolicited | FlagOverride)
	if router {
		flags |= FlagRouter
	}
	f := BuildNA(host, r.MAC, target, r.IP, target, flags, &host)
	if err := p.deps.Injector.Send(f); err != nil {
		p.m.injectErrors.Add(1)
		return
	}
	p.m.answered.Add(1)
}

// defend answers another host's duplicate address detection for a proxied address: an advertisement of the target,
// override flag only, to all nodes, rate limited per target and overall like an answer.
func (p *Proxy) defend(target netip.Addr) {
	now := p.deps.Clock.Now()
	p.mu.Lock()
	tbk := tbKey{target, MAC{}} // DAD defence has no requester MAC to key by; it has its own gap below
	tb := p.tbucket[tbk]
	if tb == nil {
		tb = &tokenBucket{}
		p.tbucket[tbk] = tb
	}
	ok := tb.take(now, answerPerTarget, answerPerTarget)
	host, router := p.hostMAC, p.cfg.Router
	p.mu.Unlock()
	if !ok || !p.allow() {
		p.flood()
		return
	}
	flags := uint8(FlagOverride)
	if router {
		flags |= FlagRouter
	}
	if err := p.deps.Injector.Send(BuildNA(host, MulticastMAC(allNodes), target, allNodes, target, flags, &host)); err != nil {
		p.m.injectErrors.Add(1)
		return
	}
	p.m.defended.Add(1)
}

// queueAnnounceAll makes every proxied address due for an announcement, as after the capture was reopened: the
// router may have forgotten them.
func (p *Proxy) queueAnnounceAll() {
	addrs := p.table.Addrs()
	p.mu.Lock()
	for _, a := range addrs {
		p.pending[a] = &announceState{left: announceRepeats}
	}
	p.mu.Unlock()
}

// Announce sends the unsolicited advertisements that are due: addresses that are new, or all of them after the
// capture was reopened, each up to announceRepeats times announceSpacing apart (RFC 4861 7.2.6). It has a budget of
// its own; what the budget does not cover stays pending. It returns when the next one is due, zero when none is.
func (p *Proxy) Announce() time.Time {
	p.mu.Lock()
	host, router, open := p.hostMAC, p.cfg.Router, p.open
	if !open || len(p.pending) == 0 {
		p.mu.Unlock()
		return time.Time{}
	}
	now := p.deps.Clock.Now()
	var due []netip.Addr
	var next time.Time
	for a, st := range p.pending {
		if !st.due.After(now) {
			due = append(due, a)
		} else if next.IsZero() || st.due.Before(next) {
			next = st.due
		}
	}
	p.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].Less(due[j]) })
	flags := uint8(FlagOverride)
	if router {
		flags |= FlagRouter
	}
	for _, a := range due {
		p.mu.Lock()
		st := p.pending[a]
		if st == nil || !p.abucket.take(now, announceRate, announceRate) {
			p.mu.Unlock()
			if st != nil {
				// out of budget: the rest stays due and is tried when the budget has refilled
				retry := now.Add(time.Second / announceRate)
				if next.IsZero() || retry.Before(next) {
					next = retry
				}
				return next
			}
			continue
		}
		p.mu.Unlock()
		f := BuildNA(host, MulticastMAC(allNodes), a, allNodes, a, flags, &host)
		err := p.deps.Injector.Send(f)
		p.mu.Lock()
		if p.pending[a] != st {
			p.mu.Unlock() // removed or restarted while sending
			if err != nil {
				p.m.injectErrors.Add(1)
			} else {
				p.m.announced.Add(1)
			}
			continue
		}
		if err != nil {
			p.m.injectErrors.Add(1)
			st.fails++
			if st.fails >= announceMaxFails {
				delete(p.pending, a)
			} else {
				st.due = now.Add(announceRetry)
				if next.IsZero() || st.due.Before(next) {
					next = st.due
				}
			}
			p.mu.Unlock()
			continue
		}
		p.m.announced.Add(1)
		st.fails = 0
		st.left--
		if st.left <= 0 {
			delete(p.pending, a)
		} else {
			st.due = now.Add(announceSpacing)
			if next.IsZero() || st.due.Before(next) {
				next = st.due
			}
		}
		p.mu.Unlock()
	}
	return next
}

// Status reports whether the capture is open and why not, with the counters.
func (p *Proxy) Status() Status {
	p.mu.Lock()
	st := Status{Open: p.open, Err: p.openErr}
	p.mu.Unlock()
	st.Addresses = p.table.Len()
	st.Metrics = p.Metrics()
	st.FloodsLastHour = p.FloodsLastHour()
	return st
}

// Close releases what the proxy holds outside itself: the multicast memberships and their sockets.
func (p *Proxy) Close() error {
	if c, ok := p.deps.Joiner.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (p *Proxy) probe(addr netip.Addr) {
	p.mu.Lock()
	iface := p.ifaces[addr]
	p.mu.Unlock()
	if iface == "" || p.deps.Prober == nil {
		return
	}
	p.m.probes.Add(1)
	_ = p.deps.Prober.Probe(addr, iface) // retransmission covers a lost probe
}

// HandleFrame processes one captured frame. Run calls it; tests call it
// directly.
func (p *Proxy) HandleFrame(frame []byte) {
	pkt, err := Parse(frame)
	if err != nil {
		if errors.Is(err, ErrMalformed) {
			p.m.malformed.Add(1)
		}
		return
	}
	if pkt.Type != TypeNeighborSolicitation {
		return
	}
	p.mu.Lock()
	host := p.hostMAC
	p.mu.Unlock()
	if pkt.EthSrc == host {
		return // our own transmission
	}
	if pkt.IsDAD() {
		// The capture sees the uplink only: the jails' own duplicate address detection runs on their epairs and
		// never reaches it. A DAD probe here is another host of the segment about to take an address
		// of ours: defend it with an advertisement to all nodes (RFC 4862 5.4.3), which shows it the duplicate.
		if p.table.Has(pkt.Target) {
			p.defend(pkt.Target)
			return
		}
		p.m.dad.Add(1)
		p.m.dropped.Add(1)
		return
	}
	// The answer goes to the source link-layer option when there is one; the budgets are kept by the Ethernet source of
	// the frame, which the sender cannot vary for free.
	mac := pkt.EthSrc
	if pkt.SourceLLA != nil {
		mac = *pkt.SourceLLA
	}
	if mac.IsZero() || mac.IsMulticast() || mac == host || pkt.EthSrc.IsZero() || pkt.EthSrc.IsMulticast() {
		p.m.malformed.Add(1)
		return
	}
	if !p.admit(pkt.EthSrc) {
		p.flood()
		return
	}
	res := p.table.Solicit(pkt.Target, Requester{IP: pkt.Src, MAC: mac})
	if res.Probe {
		p.probe(pkt.Target)
	}
	switch res.Verdict {
	case VerdictAnswer:
		p.answeredTo(pkt.EthSrc)
		p.answer(pkt.Target, Requester{IP: pkt.Src, MAC: mac})
	case VerdictQueued:
	case VerdictUnknown:
		p.m.unknown.Add(1)
		p.m.dropped.Add(1)
	case VerdictFlood:
		p.flood()
	default:
		p.m.dropped.Add(1)
	}
}

// Tick runs table timers. Run calls it; tests call it directly.
func (p *Proxy) Tick() {
	p.mu.Lock()
	now := p.deps.Clock.Now()
	for k, t := range p.answered {
		if now.Sub(t) > time.Second {
			delete(p.answered, k)
		}
	}
	p.mu.Unlock()
	res := p.table.Tick()
	for _, a := range res.Probes {
		p.probe(a)
	}
}

type readResult struct {
	frame []byte
	err   error
}

// Run captures and answers until ctx is cancelled. It returns an error only
// for a precondition failure (the uplink is a bridge member); link loss and
// return are handled inside.
func (p *Proxy) Run(ctx context.Context) error {
	var (
		stream Stream
		frames chan readResult
		done   chan struct{}
		wg     sync.WaitGroup
	)
	closeStream := func() {
		if stream == nil {
			return
		}
		close(done)
		_ = stream.Close()
		wg.Wait()
		stream, frames = nil, nil
		p.mu.Lock()
		p.open = false
		p.mu.Unlock()
	}
	defer closeStream()
	// One timer of each kind lives across the iterations of the loop: a frame wakes the loop, and under a flood of
	// solicitations that is thousands of iterations a second, each of which used to make three timers of its own.
	var announceT, tableT, pollT loopTimer

	for ctx.Err() == nil {
		p.mu.Lock()
		cfg := p.cfg
		p.mu.Unlock()

		if stream == nil && !p.deps.Clock.Now().Before(p.nextOpenAt()) {
			s, err := p.openLink(ctx, cfg)
			if errors.Is(err, errBridgeMember) {
				return err
			}
			if err != nil {
				p.openFailed(err)
			}
			if err == nil {
				p.openSucceeded()
				p.queueAnnounceAll() // a new capture: tell the router again, it may have forgotten
				stream = s
				frames = make(chan readResult, 64)
				done = make(chan struct{})
				wg.Add(1)
				go func(s Stream, out chan<- readResult, done <-chan struct{}) {
					defer wg.Done()
					for {
						f, err := s.Next()
						if err == nil {
							f = append([]byte(nil), f...)
						}
						select {
						case out <- readResult{f, err}:
						case <-done:
							return
						}
						if err != nil {
							return
						}
					}
				}(s, frames, done)
			}
		}

		var announceTimer <-chan time.Time
		if stream != nil {
			if next := p.Announce(); !next.IsZero() {
				announceTimer = announceT.until(p.deps.Clock, next)
			} else {
				announceT.reset()
			}
		}
		var tableTimer <-chan time.Time
		if next, ok := p.table.Next(); ok {
			tableTimer = tableT.until(p.deps.Clock, next)
		} else {
			tableT.reset()
		}
		pollTimer := pollT.after(p.deps.Clock, cfg.LinkPoll)

		select {
		case <-ctx.Done():
		case r := <-frames:
			if r.err != nil {
				closeStream() // reopen on the next iteration
			} else {
				p.HandleFrame(r.frame)
			}
		case <-tableTimer:
			tableT.reset()
			p.Tick()
		case <-p.reload:
			closeStream()
		case <-p.wake:
		case <-announceTimer:
			announceT.reset()
		case <-pollTimer:
			pollT.reset()
			if stream != nil && p.linkChanged() {
				closeStream()
			}
		}
	}
	return nil
}

// loopTimer keeps the channel of a timer until it fires or its deadline changes, so that waking the loop for something
// else does not make a new timer.
type loopTimer struct {
	ch <-chan time.Time
	at time.Time
}

// until returns the channel of a timer that fires at the deadline.
func (t *loopTimer) until(c Clock, at time.Time) <-chan time.Time {
	if t.ch == nil || !t.at.Equal(at) {
		d := at.Sub(c.Now())
		if d < 0 {
			d = 0
		}
		t.ch, t.at = c.After(d), at
	}
	return t.ch
}

// after returns the channel of a timer that fires d from the first call after the last reset.
func (t *loopTimer) after(c Clock, d time.Duration) <-chan time.Time {
	if t.ch == nil {
		t.ch, t.at = c.After(d), time.Time{}
	}
	return t.ch
}

// reset forgets the timer: it fired, or it is not wanted any more.
func (t *loopTimer) reset() { t.ch, t.at = nil, time.Time{} }

func (p *Proxy) nextOpenAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nextOpen
}

// openFailed records a failed attempt and backs off: 2 seconds, doubling to 30. The first failure is logged, once.
func (p *Proxy) openFailed(err error) {
	p.mu.Lock()
	first := p.openErr == ""
	p.openErr = err.Error()
	p.openFails++
	d := openBackoffMin << min(p.openFails-1, 6)
	if d > openBackoffMax {
		d = openBackoffMax
	}
	p.nextOpen = p.deps.Clock.Now().Add(d)
	p.mu.Unlock()
	if first && p.deps.Logf != nil {
		p.deps.Logf("ndproxy: cannot open the capture of %s, retrying with a growing delay: %v", p.cfg.Uplink, err)
	}
}

func (p *Proxy) openSucceeded() {
	p.mu.Lock()
	failed := p.openErr != ""
	p.openErr, p.openFails, p.nextOpen = "", 0, time.Time{}
	p.mu.Unlock()
	if failed && p.deps.Logf != nil {
		p.deps.Logf("ndproxy: the capture of %s is open again", p.cfg.Uplink)
	}
}

var errBridgeMember = errors.New("ndproxy: uplink is a bridge member")

// linkChanged reports whether the uplink vanished or changed identity.
func (p *Proxy) linkChanged() bool {
	info, err := p.deps.Capture.Link()
	p.mu.Lock()
	defer p.mu.Unlock()
	return err != nil || !info.Up || info.Index != p.link.Index || info.MAC != p.link.MAC
}

func (p *Proxy) openLink(ctx context.Context, cfg Config) (Stream, error) {
	info, err := p.deps.Capture.Link()
	if err != nil {
		return nil, err
	}
	if !info.Up {
		return nil, errors.New("ndproxy: uplink is down")
	}
	if err := p.deps.Routes.EnsureUplinkNotMember(ctx, cfg.Uplink); err != nil {
		return nil, fmt.Errorf("%w: %v", errBridgeMember, err)
	}
	s, err := p.deps.Capture.Open(info, cfg.Promisc)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.link, p.hostMAC, p.open = info, info.MAC, true
	groups := make([]netip.Addr, 0, len(p.groups))
	for g := range p.groups {
		groups = append(groups, g)
	}
	p.mu.Unlock()
	for _, g := range groups {
		_ = p.deps.Joiner.Join(cfg.Uplink, g) // memberships do not survive a recreated interface
	}
	p.m.reopens.Add(1)
	return s, nil
}
