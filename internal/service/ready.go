package service

import (
	"context"
	"sync"
	"time"
)

// Reasons GET /readyz gives for "not ready": fixed classes, the only detail an
// unauthenticated caller learns.
const (
	NotReadyStarting = "starting" // start-up has not finished
	NotReadyStopping = "stopping" // the daemon is shutting down
	NotReadyHelper   = "helper"   // the privileged helper did not answer
	NotReadyStorage  = "storage"  // the helper answered, the JailOps dataset is missing
	NotReadyStore    = "store"    // the state store did not answer
)

// ReadyCacheTTL is how long a readiness answer is reused: a flood of probes
// reaches the helper and the store at most once per period.
const ReadyCacheTTL = 2 * time.Second

// readyProbeTimeout bounds each check of a readiness probe.
const readyProbeTimeout = 2 * time.Second

type readyState struct {
	mu       sync.Mutex
	started  bool
	stopping bool
	at       time.Time // when reason was found; zero: nothing cached
	reason   string    // "" is ready
}

// MarkStarted records that start-up finished; Ready answers from then on.
func (s *Service) MarkStarted() {
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	s.ready.started, s.ready.at = true, time.Time{}
}

// MarkStopping makes Ready answer "stopping" from now on, so a load balancer
// takes the host out before its listeners close.
func (s *Service) MarkStopping() {
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	s.ready.stopping = true
}

// Ready reports whether the daemon can serve requests: start-up finished, the
// helper answers a read-only call (whether the JailOps dataset exists) and the
// state store answers a query. It returns "" when ready, else one of the
// NotReady classes. The answer is cached for ReadyCacheTTL; concurrent callers
// wait for the one probe that runs.
func (s *Service) Ready(ctx context.Context) string {
	r := &s.ready
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.stopping:
		return NotReadyStopping
	case !r.started:
		return NotReadyStarting
	}
	now := s.now()
	if !r.at.IsZero() && now.Sub(r.at) < ReadyCacheTTL && !now.Before(r.at) {
		return r.reason
	}
	// a caller that hangs up does not make the host look unready to the next one
	ctx = context.WithoutCancel(ctx)
	r.reason, r.at = s.probeReady(ctx), now
	return r.reason
}

func (s *Service) probeReady(ctx context.Context) string {
	if s.d.ZFS == nil {
		return NotReadyHelper
	}
	hctx, cancel := context.WithTimeout(ctx, readyProbeTimeout)
	ok, err := s.d.ZFS.Exists(hctx, s.d.Root)
	cancel()
	switch {
	case err != nil:
		return NotReadyHelper
	case !ok:
		return NotReadyStorage
	}
	sctx, cancel := context.WithTimeout(ctx, readyProbeTimeout)
	defer cancel()
	if _, err := s.d.DB.Version(sctx); err != nil {
		return NotReadyStore
	}
	return ""
}
