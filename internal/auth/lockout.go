package auth

import (
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// LockedError is returned while a key is locked out. The HTTP layer answers
// 429 with a Retry-After header of RetryAfterSeconds.
type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string {
	return fmt.Sprintf("too many failed attempts; retry in %s", e.RetryAfter.Round(time.Second))
}

// HTTPStatus is 429.
func (e *LockedError) HTTPStatus() int { return 429 }

// RetryAfterSeconds is the value for the Retry-After header, at least 1.
func (e *LockedError) RetryAfterSeconds() string {
	s := int(e.RetryAfter.Seconds() + 0.999)
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
}

// LockoutConfig tunes the limiter.
type LockoutConfig struct {
	Threshold  int           // failures before the first lock; default 5
	BaseDelay  time.Duration // first lock; doubles per further failure; default 30s
	MaxDelay   time.Duration // default 15m
	ResetAfter time.Duration // failures are forgotten after this quiet time; default 30m
	MaxEntries int           // bound on tracked keys; default 10000
	Now        func() time.Time
}

// Lockout counts failed logins per key (for example user name plus source
// address) and locks the key with exponential backoff after Threshold failures.
type Lockout struct {
	cfg LockoutConfig
	mu  sync.Mutex
	m   map[string]*lockEntry
}

type lockEntry struct {
	failures    int
	inflight    int
	lockedUntil time.Time
	last        time.Time
}

// NewLockout returns a limiter with defaults filled in.
func NewLockout(cfg LockoutConfig) *Lockout {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 5
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 30 * time.Second
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 15 * time.Minute
	}
	if cfg.ResetAfter <= 0 {
		cfg.ResetAfter = 30 * time.Minute
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Lockout{cfg: cfg, m: map[string]*lockEntry{}}
}

// Check returns a *LockedError while key is locked, nil otherwise. Call it
// before verifying credentials.
func (l *Lockout) Check(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	e := l.m[key]
	if e == nil {
		return nil
	}
	if now.Sub(e.last) > l.cfg.ResetAfter && !now.Before(e.lockedUntil) {
		delete(l.m, key)
		return nil
	}
	if now.Before(e.lockedUntil) {
		return &LockedError{RetryAfter: e.lockedUntil.Sub(now)}
	}
	return nil
}

// Fail records a failed attempt and returns the lock now in force, if any.
func (l *Lockout) Fail(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	e := l.m[key]
	if e == nil {
		if len(l.m) >= l.cfg.MaxEntries {
			l.evict(now)
		}
		e = &lockEntry{}
		l.m[key] = e
	}
	if now.Sub(e.last) > l.cfg.ResetAfter && !now.Before(e.lockedUntil) {
		e.failures = 0
	}
	e.failures++
	e.last = now
	if e.failures >= l.cfg.Threshold {
		d := l.cfg.BaseDelay
		for i := l.cfg.Threshold; i < e.failures && d < l.cfg.MaxDelay; i++ {
			d *= 2
		}
		if d > l.cfg.MaxDelay {
			d = l.cfg.MaxDelay
		}
		e.lockedUntil = now.Add(d)
		return &LockedError{RetryAfter: d}
	}
	return nil
}

// Begin counts an attempt before its credential is checked, so that attempts that run at once cannot pass the
// threshold together: it returns a *LockedError while the key is locked, and also when the failures so far and the
// attempts still in flight reach the threshold (after a lock has run out, one attempt at a time). Every Begin
// that returns nil is followed by End or Abort.
func (l *Lockout) Begin(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	e := l.m[key]
	if e == nil {
		if len(l.m) >= l.cfg.MaxEntries {
			l.evict(now)
		}
		e = &lockEntry{last: now}
		l.m[key] = e
	}
	if e.inflight == 0 && now.Sub(e.last) > l.cfg.ResetAfter && !now.Before(e.lockedUntil) {
		e.failures = 0
	}
	if now.Before(e.lockedUntil) {
		return &LockedError{RetryAfter: e.lockedUntil.Sub(now)}
	}
	if e.failures+e.inflight >= l.cfg.Threshold && (e.failures < l.cfg.Threshold || e.inflight > 0) {
		// the attempts in flight decide first
		return &LockedError{RetryAfter: time.Second}
	}
	e.inflight++
	e.last = now
	return nil
}

// End finishes an attempt begun with Begin: a success clears the key, a failure counts like Fail and returns the
// lock now in force, if any.
func (l *Lockout) End(key string, ok bool) error {
	if ok {
		l.Success(key)
		return nil
	}
	l.mu.Lock()
	if e := l.m[key]; e != nil && e.inflight > 0 {
		e.inflight--
	}
	l.mu.Unlock()
	return l.Fail(key)
}

// Abort finishes an attempt begun with Begin that was not decided (another key refused it).
func (l *Lockout) Abort(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[key]; e != nil && e.inflight > 0 {
		e.inflight--
	}
}

// Success clears the key.
func (l *Lockout) Success(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

// evict drops idle entries, then the oldest if the table is still full.
func (l *Lockout) evict(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, e := range l.m {
		if e.inflight == 0 && now.Sub(e.last) > l.cfg.ResetAfter && !now.Before(e.lockedUntil) {
			delete(l.m, k)
			continue
		}
		if oldestKey == "" || e.last.Before(oldest) {
			oldestKey, oldest = k, e.last
		}
	}
	if len(l.m) >= l.cfg.MaxEntries && oldestKey != "" {
		delete(l.m, oldestKey)
	}
}

// SourceKey is the source of a request as the limiters count it: the address itself for IPv4 and other peers
// ("unix:<uid>"), and the /64 for IPv6, where one host usually holds a whole /64 and could otherwise try from
// another address every time.
func SourceKey(remote string) string {
	a, err := netip.ParseAddr(remote)
	if err != nil || !a.Is6() || a.Is4In6() {
		return remote
	}
	p, err := a.WithZone("").Prefix(64)
	if err != nil {
		return remote
	}
	return p.String()
}
