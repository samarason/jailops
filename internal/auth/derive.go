package auth

import (
	"sync"
	"time"
)

// Every argon2id derivation takes the memory of its parameters (64 MiB by default), so the derivations that run at
// once are bounded: DeriveSlots run, the others wait their turn, and when DeriveQueue already wait, a login is
// refused at once instead of joining them (AdmitDerivation).
const (
	DeriveSlots = 4
	DeriveQueue = 32
)

type deriveGate struct {
	mu      sync.Mutex
	cond    *sync.Cond
	running int
	waiting int
	peak    int
	total   int64
}

var derivations = func() *deriveGate {
	g := &deriveGate{}
	g.cond = sync.NewCond(&g.mu)
	return g
}()

func (g *deriveGate) enter() {
	g.mu.Lock()
	g.waiting++
	for g.running >= DeriveSlots {
		g.cond.Wait()
	}
	g.waiting--
	g.running++
	g.total++
	g.peak = max(g.peak, g.running)
	g.mu.Unlock()
}

func (g *deriveGate) leave() {
	g.mu.Lock()
	g.running--
	g.mu.Unlock()
	g.cond.Signal()
}

// derive runs one derivation inside the gate.
func derive[T any](f func() T) T {
	derivations.enter()
	defer derivations.leave()
	return f()
}

// AdmitDerivation tells a request that needs a derivation whether to wait for one: it returns a *LockedError with
// a short Retry-After when DeriveQueue requests already wait.
func AdmitDerivation() error {
	derivations.mu.Lock()
	defer derivations.mu.Unlock()
	if derivations.waiting >= DeriveQueue {
		return &LockedError{RetryAfter: time.Second}
	}
	return nil
}

// DerivationStats returns the largest number of derivations that ran at once and the number of derivations since
// the process started (for tests).
func DerivationStats() (peak int, total int64) {
	derivations.mu.Lock()
	defer derivations.mu.Unlock()
	return derivations.peak, derivations.total
}
