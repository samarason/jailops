package ndproxy

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"jailops.net/jailops/sdk/api"
)

// State is the session state of one proxied address.
type State uint8

// Session states.
//
//	Incomplete: a probe is outstanding, solicitations are queued.
//	Valid:      the address is confirmed (or, in ModeImmediate, allocated);
//	            solicitations are answered at once.
//	Stale:      Valid for longer than ValidTTL; solicitations are answered
//	            at once and trigger a refresh probe.
//	Invalid:    probing failed (or, in ModeProbe, nothing is known yet);
//	            solicitations are ignored until InvalidTTL passes.
const (
	StateIncomplete State = iota
	StateValid
	StateStale
	StateInvalid
)

func (s State) String() string {
	switch s {
	case StateIncomplete:
		return "incomplete"
	case StateValid:
		return "valid"
	case StateStale:
		return "stale"
	case StateInvalid:
		return "invalid"
	}
	return "unknown"
}

// Mode selects when the proxy answers.
type Mode uint8

const (
	// ModeImmediate answers at once for every allocated address. JailOps
	// allocates the addresses itself, so this is the default.
	ModeImmediate Mode = iota
	// ModeProbe sends a solicitation toward the jail first and
	// answers only once the jail has replied.
	ModeProbe
)

// Clock abstracts time so tests are deterministic.
type Clock interface {
	Now() time.Time
	// After returns a channel that receives once after d.
	After(d time.Duration) <-chan time.Time
}

// TableConfig tunes the Table. Zero fields take the defaults below.
type TableConfig struct {
	Mode              Mode
	ValidTTL          time.Duration // default 30s (probe mode only)
	InvalidTTL        time.Duration // default 10s (probe mode only)
	RetransmitTime    time.Duration // default 1s
	RetransmitLimit   int           // probes per attempt, default 3
	MaxEntries        int           // proxied addresses, default 4096
	MaxPendingPerAddr int           // queued requesters per address, default 8
	MaxPendingTotal   int           // queued requesters overall, default 256
}

func (c TableConfig) withDefaults() TableConfig {
	if c.ValidTTL <= 0 {
		c.ValidTTL = 30 * time.Second
	}
	if c.InvalidTTL <= 0 {
		c.InvalidTTL = 10 * time.Second
	}
	if c.RetransmitTime <= 0 {
		c.RetransmitTime = time.Second
	}
	if c.RetransmitLimit <= 0 {
		c.RetransmitLimit = 3
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 4096
	}
	if c.MaxPendingPerAddr <= 0 {
		c.MaxPendingPerAddr = 8
	}
	if c.MaxPendingTotal <= 0 {
		c.MaxPendingTotal = 256
	}
	return c
}

// Requester identifies who asked: the IPv6 source and the link-layer
// address an advertisement must be sent to.
type Requester struct {
	IP  netip.Addr
	MAC MAC
}

// Verdict is the outcome of a solicitation.
type Verdict uint8

// Verdicts.
const (
	VerdictUnknown    Verdict = iota // target is not proxied: ignore
	VerdictAnswer                    // answer now
	VerdictQueued                    // answer later, when the probe succeeds
	VerdictSuppressed                // invalid and not yet retried: ignore
	VerdictFlood                     // a queue bound was hit: dropped
)

// Result is returned by Table.Solicit. Probe asks the caller to send the
// first probe for the address now.
type Result struct {
	Verdict Verdict
	Probe   bool
}

// TickResult lists what the caller must do after Table.Tick.
type TickResult struct {
	Probes  []netip.Addr // probes to (re)transmit
	Dropped int          // queued requesters discarded because probing failed
}

type entry struct {
	state   State
	expires time.Time // Valid -> Stale, Invalid -> retryable; zero means never/now
	tries   int       // probes sent in the current attempt, 0 when none
	next    time.Time // next retransmission when tries > 0
	pending []Requester
}

// Table holds the proxied addresses and their session state. It is safe for
// concurrent use and does no I/O.
type Table struct {
	clock Clock
	cfg   TableConfig

	mu      sync.Mutex
	entries map[netip.Addr]*entry
	pending int
}

// NewTable returns an empty Table.
func NewTable(cfg TableConfig, clock Clock) *Table {
	return &Table{clock: clock, cfg: cfg.withDefaults(), entries: map[netip.Addr]*entry{}}
}

// Config returns the effective configuration.
func (t *Table) Config() TableConfig {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg
}

// SetConfig replaces the timing and bound settings without losing entries.
// The Mode applies to entries added afterwards and to re-probing; existing
// entries are converted: switching to ModeImmediate makes all Valid, and
// switching to ModeProbe leaves Valid entries to age into Stale.
func (t *Table) SetConfig(cfg TableConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.cfg
	t.cfg = cfg.withDefaults()
	if old.Mode == t.cfg.Mode {
		return
	}
	now := t.clock.Now()
	for _, e := range t.entries {
		if t.cfg.Mode == ModeImmediate {
			t.pending -= len(e.pending)
			*e = entry{state: StateValid}
		} else if e.state == StateValid {
			e.expires = now.Add(t.cfg.ValidTTL)
		}
	}
}

// ValidAddr reports whether a may be proxied: a global or unique-local
// unicast address (not link-local, loopback, multicast or unspecified).
func ValidAddr(a netip.Addr) bool {
	return a.Is6() && !a.Is4In6() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && a.Zone() == ""
}

// Add starts proxying addr.
func (t *Table) Add(addr netip.Addr) error {
	if !ValidAddr(addr) {
		return api.Errorf(api.CodeInvalid, "address %s cannot be proxied", addr)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.entries[addr]; ok {
		return api.Errorf(api.CodeAlreadyExists, "address %s is already proxied", addr)
	}
	if len(t.entries) >= t.cfg.MaxEntries {
		return api.Errorf(api.CodePoolExhausted, "at most %d proxied addresses", t.cfg.MaxEntries)
	}
	e := &entry{state: StateValid}
	if t.cfg.Mode == ModeProbe {
		e.state = StateInvalid // unverified; zero expiry allows probing at once
	}
	t.entries[addr] = e
	return nil
}

// Remove stops proxying addr and discards its queued requesters. It
// reports whether the address was present.
func (t *Table) Remove(addr netip.Addr) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[addr]
	if !ok {
		return false
	}
	t.pending -= len(e.pending)
	delete(t.entries, addr)
	return true
}

// Has reports whether addr is proxied.
func (t *Table) Has(addr netip.Addr) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.entries[addr]
	return ok
}

// Len returns the number of proxied addresses.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Pending returns the number of queued requesters over all addresses.
func (t *Table) Pending() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pending
}

// State returns the session state of addr after applying any expiry that is
// due.
func (t *Table) State(addr netip.Addr) (State, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[addr]
	if !ok {
		return 0, false
	}
	t.age(e, t.clock.Now())
	return e.state, true
}

// Addrs returns the proxied addresses in order.
func (t *Table) Addrs() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]netip.Addr, 0, len(t.entries))
	for a := range t.entries {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// age applies time based transitions that do not need I/O. Caller holds mu.
func (t *Table) age(e *entry, now time.Time) {
	if t.cfg.Mode == ModeImmediate {
		return
	}
	if e.state == StateValid && !now.Before(e.expires) {
		e.state = StateStale
	}
}

func (t *Table) startProbe(e *entry, now time.Time) {
	e.tries = 1
	e.next = now.Add(t.cfg.RetransmitTime)
}

// Solicit processes a (non-DAD) solicitation for target from req.
func (t *Table) Solicit(target netip.Addr, req Requester) Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[target]
	if !ok {
		return Result{Verdict: VerdictUnknown}
	}
	now := t.clock.Now()
	t.age(e, now)
	switch e.state {
	case StateValid:
		return Result{Verdict: VerdictAnswer}
	case StateStale:
		r := Result{Verdict: VerdictAnswer}
		if e.tries == 0 {
			t.startProbe(e, now)
			r.Probe = true
		}
		return r
	case StateInvalid:
		if now.Before(e.expires) {
			return Result{Verdict: VerdictSuppressed}
		}
		e.state = StateIncomplete
		t.startProbe(e, now)
		if !t.enqueue(e, req) {
			// Probing continues; the requester will retry by itself.
			return Result{Verdict: VerdictFlood, Probe: true}
		}
		return Result{Verdict: VerdictQueued, Probe: true}
	default: // incomplete
		if !t.enqueue(e, req) {
			return Result{Verdict: VerdictFlood}
		}
		return Result{Verdict: VerdictQueued}
	}
}

// enqueue adds req within the bounds. Caller holds mu.
func (t *Table) enqueue(e *entry, req Requester) bool {
	for i := range e.pending {
		if e.pending[i].IP == req.IP {
			e.pending[i] = req // coalesce repeats from one requester
			return true
		}
	}
	if len(e.pending) >= t.cfg.MaxPendingPerAddr || t.pending >= t.cfg.MaxPendingTotal {
		return false
	}
	e.pending = append(e.pending, req)
	t.pending++
	return true
}

// Reachable records that the jail answered a probe for addr. It returns the
// queued requesters that must now be answered.
func (t *Table) Reachable(addr netip.Addr) []Requester {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[addr]
	if !ok {
		return nil
	}
	reqs := e.pending
	t.pending -= len(reqs)
	e.pending = nil
	e.tries = 0
	e.state = StateValid
	e.expires = t.clock.Now().Add(t.cfg.ValidTTL)
	return reqs
}

// Tick applies timers: Valid entries become Stale, probes are retransmitted
// and entries whose probes ran out become Invalid.
func (t *Table) Tick() TickResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	var res TickResult
	now := t.clock.Now()
	for addr, e := range t.entries {
		t.age(e, now)
		if e.tries == 0 || now.Before(e.next) {
			continue
		}
		if e.tries >= t.cfg.RetransmitLimit {
			res.Dropped += len(e.pending)
			t.pending -= len(e.pending)
			e.pending = nil
			e.tries = 0
			e.state = StateInvalid
			e.expires = now.Add(t.cfg.InvalidTTL)
			continue
		}
		e.tries++
		e.next = now.Add(t.cfg.RetransmitTime)
		res.Probes = append(res.Probes, addr)
	}
	sort.Slice(res.Probes, func(i, j int) bool { return res.Probes[i].Less(res.Probes[j]) })
	return res
}

// Next returns the earliest time Tick has work to do.
func (t *Table) Next() (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var best time.Time
	ok := false
	consider := func(x time.Time) {
		if !ok || x.Before(best) {
			best, ok = x, true
		}
	}
	for _, e := range t.entries {
		if e.tries > 0 {
			consider(e.next)
		}
		if t.cfg.Mode == ModeProbe && e.state == StateValid {
			consider(e.expires)
		}
	}
	return best, ok
}
