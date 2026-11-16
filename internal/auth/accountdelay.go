package auth

import (
	"context"
	"sync"
	"time"
)

// AccountDelayConfig tunes AccountDelay.
type AccountDelayConfig struct {
	Free       int           // failures of one account, from any source, before attempts are slowed; default 10
	MaxDelay   time.Duration // the longest wait before an attempt; default 30s
	ResetAfter time.Duration // failures are forgotten after this quiet time; default 30m
	MaxEntries int           // bound on tracked accounts; default 10000
	Now        func() time.Time
	// Sleep waits d or until ctx ends (tests replace it).
	Sleep func(ctx context.Context, d time.Duration) error
}

// AccountDelay slows down password guesses for one account that come from many sources, without locking the
// account: after Free failures every further attempt waits 1s, then 2s, 4s and so on up to MaxDelay before its
// password is checked, and only one such attempt runs at a time (the others are refused at once). A success
// forgets the failures.
type AccountDelay struct {
	cfg AccountDelayConfig
	mu  sync.Mutex
	m   map[string]*acctEntry
}

type acctEntry struct {
	failures int
	inflight int
	last     time.Time
}

// NewAccountDelay returns an AccountDelay with defaults filled in.
func NewAccountDelay(cfg AccountDelayConfig) *AccountDelay {
	if cfg.Free <= 0 {
		cfg.Free = 10
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 30 * time.Second
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
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return &AccountDelay{cfg: cfg, m: map[string]*acctEntry{}}
}

// delay is the wait before the next attempt after failures.
func (a *AccountDelay) delay(failures int) time.Duration {
	if failures < a.cfg.Free {
		return 0
	}
	d := time.Second
	for i := a.cfg.Free; i < failures && d < a.cfg.MaxDelay; i++ {
		d *= 2
	}
	return min(d, a.cfg.MaxDelay)
}

// Begin waits as long as the account's failures ask for and returns the function that records the outcome. It
// returns a *LockedError at once while another slowed attempt for the account is running.
func (a *AccountDelay) Begin(ctx context.Context, account string) (func(ok bool), error) {
	a.mu.Lock()
	now := a.cfg.Now()
	e := a.m[account]
	if e == nil {
		if len(a.m) >= a.cfg.MaxEntries {
			a.evict(now)
		}
		e = &acctEntry{}
		a.m[account] = e
	}
	if e.inflight == 0 && now.Sub(e.last) > a.cfg.ResetAfter {
		e.failures = 0
	}
	d := a.delay(e.failures)
	if e.failures+e.inflight >= a.cfg.Free && e.inflight > 0 {
		a.mu.Unlock()
		return nil, &LockedError{RetryAfter: max(d, time.Second)}
	}
	e.inflight++
	e.last = now
	a.mu.Unlock()
	end := func(ok bool) {
		a.mu.Lock()
		defer a.mu.Unlock()
		e := a.m[account]
		if e == nil {
			return
		}
		e.inflight--
		e.last = a.cfg.Now()
		if ok {
			if e.inflight <= 0 {
				delete(a.m, account)
			} else {
				e.failures = 0
			}
			return
		}
		e.failures++
	}
	if d > 0 {
		if err := a.cfg.Sleep(ctx, d); err != nil {
			a.mu.Lock()
			e.inflight--
			a.mu.Unlock()
			return nil, err
		}
	}
	return end, nil
}

// evict drops idle entries, then the entry with the fewest failures, so that guesses for many names cannot push a
// slowed account out of the table.
func (a *AccountDelay) evict(now time.Time) {
	victim, fewest := "", 0
	for k, e := range a.m {
		if e.inflight > 0 {
			continue
		}
		if now.Sub(e.last) > a.cfg.ResetAfter {
			delete(a.m, k)
			continue
		}
		if victim == "" || e.failures < fewest {
			victim, fewest = k, e.failures
		}
	}
	if len(a.m) >= a.cfg.MaxEntries && victim != "" {
		delete(a.m, victim)
	}
}
