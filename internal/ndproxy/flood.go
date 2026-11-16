package ndproxy

import (
	"fmt"
	"time"
)

// Bounds on what a neighbor on the uplink can make the proxy spend. They are fixed numbers, not settings: a segment of
// jails needs a few solicitations a second, so these never touch normal use, and a flood meets them whatever the
// operator would have set.
//
// A solicitation is charged to the sender first, by the Ethernet source address of the frame, which a host on the
// segment cannot vary for free (switches restrict or log it). Only a solicitation that passes is charged to the global
// budget, so a flood from one sender spends its own allowance and nothing of anybody else's. The source link-layer
// option and the source address of a solicitation are the sender's own claims and are never keys: the option only
// tells where the answer goes.
//
// The global budget is the last resort against a flood from many senders (many MACs, or a forged source address each
// time). It is split: a part only the requesters the proxy knows may use (the router, which asks again and again and
// was answered), so a flood of new addresses fills the rest and the router still gets its answers.
const (
	// solicitPerSource is how many solicitations one Ethernet source may send per second (and solicitBurst how many
	// at once).
	solicitPerSource = 50
	solicitBurst     = 100
	// solicitGeneral is the global budget every requester may use per second; solicitReserved is the part of the global
	// budget that only a known requester may use, on top of it.
	solicitGeneral       = 1500
	solicitGeneralBurst  = 3000
	solicitReserved      = 500
	solicitReservedBurst = 1000
	// knownAfter is how long after its first answer a requester that asks again counts as known: a sender that changes
	// its MAC for every solicitation never reaches it.
	knownAfter = time.Second
	// knownMax bounds the requesters that are known; a flood of new ones never pushes a known one out of the table.
	knownMax = 256
	// sourceTableMax bounds the table of senders; when it is full the oldest entries go first.
	sourceTableMax = 4096
	// floodLogEvery is the longest rate at which the proxy writes down that it dropped solicitations.
	floodLogEvery = time.Minute
	floodWindow   = time.Hour
)

// sourceBucket is the token bucket of one sender and what the proxy knows of it.
type sourceBucket struct {
	tokenBucket
	// answeredAt is when the sender was first answered; known is set when it asked again knownAfter later.
	answeredAt time.Time
	known      bool
}

// admit applies the budgets to one solicitation: the budget of the Ethernet source of the frame, and only then the
// global budget, the reserved part of it for a known requester first. The source address of the packet is no key: a
// flood that forges the router's address would otherwise use up the router's allowance.
func (p *Proxy) admit(eth MAC) bool {
	now := p.deps.Clock.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.sources[eth]
	if b == nil {
		if len(p.sources) >= sourceTableMax {
			p.evictSources(now)
		}
		b = &sourceBucket{}
		p.sources[eth] = b
	}
	if !b.take(now, solicitPerSource, solicitBurst) {
		return false
	}
	if b.known && p.reserved.take(now, solicitReserved, solicitReservedBurst) {
		return true
	}
	return p.total.take(now, solicitGeneral, solicitGeneralBurst)
}

// answeredTo notes that the sender with this Ethernet source was answered: asking again later makes it known.
func (p *Proxy) answeredTo(eth MAC) {
	now := p.deps.Clock.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.sources[eth]
	if b == nil || b.known {
		return
	}
	if b.answeredAt.IsZero() {
		b.answeredAt = now
		return
	}
	if now.Sub(b.answeredAt) < knownAfter {
		return
	}
	known := 0
	for _, o := range p.sources {
		if o.known {
			known++
		}
	}
	if known < knownMax {
		b.known = true
	}
}

// evictSources makes room in the table of senders in one pass, so that a flood of new senders costs the proxy a scan
// per quarter of the table and not one per frame: the buckets that have filled up again (the sender is quiet) go first,
// then others, and a known sender stays unless every entry is known.
func (p *Proxy) evictSources(now time.Time) {
	want := sourceTableMax / 4
	removed := 0
	for m, b := range p.sources {
		if !b.known && now.Sub(b.last).Seconds()*solicitPerSource >= solicitBurst {
			delete(p.sources, m)
			removed++
		}
	}
	for m, b := range p.sources {
		if removed >= want {
			return
		}
		if !b.known {
			delete(p.sources, m)
			removed++
		}
	}
	for m := range p.sources { // every entry is known: the table is full of the requesters the proxy trusts; drop some
		if removed >= want {
			return
		}
		delete(p.sources, m)
		removed++
	}
}

// flood counts a solicitation that was dropped by a bound or a rate limit, keeps the count of the last hour for
// doctor, and writes it down at most once a minute.
func (p *Proxy) flood() {
	p.m.floods.Add(1)
	p.m.dropped.Add(1)
	now := p.deps.Clock.Now()
	p.mu.Lock()
	p.floodLog.add(now)
	p.floodSince++
	var msg string
	if p.floodLogged.IsZero() || now.Sub(p.floodLogged) >= floodLogEvery {
		msg = fmt.Sprintf("neighbor discovery proxy on %s: dropped %d solicitation(s) over its limits (a neighbor on the uplink is sending too many)", p.cfg.Uplink, p.floodSince)
		p.floodSince, p.floodLogged = 0, now
	}
	p.mu.Unlock()
	if msg != "" && p.deps.Logf != nil {
		p.deps.Logf("%s", msg)
	}
}

// FloodsLastHour is how many solicitations the limits dropped in the last hour.
func (p *Proxy) FloodsLastHour() uint64 {
	now := p.deps.Clock.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.floodLog.sum(now)
}

// hourLog counts events per minute for the last hour.
type hourLog struct {
	minute [60]int64 // the minute (Unix time / 60) each slot holds
	count  [60]uint64
}

func (h *hourLog) add(now time.Time) {
	m := now.Unix() / 60
	i := int(m % 60)
	if h.minute[i] != m {
		h.minute[i], h.count[i] = m, 0
	}
	h.count[i]++
}

func (h *hourLog) sum(now time.Time) uint64 {
	m := now.Unix() / 60
	var n uint64
	for i := range h.minute {
		if h.minute[i] > m-60 && h.minute[i] <= m {
			n += h.count[i]
		}
	}
	return n
}
