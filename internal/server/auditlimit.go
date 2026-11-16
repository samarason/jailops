package server

import (
	"context"
	"strconv"
	"sync"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/store"
)

// While a source is locked out it can still send requests as fast as it likes. Each refusal costs the daemon no
// password derivation, and it should not cost an audit row either: the first refusal of a source in a window is
// written as usual, the others are counted and written as one entry when the window ends.

const (
	lockedAuditWindow = time.Minute
	lockedAuditKeys   = 10000
)

type lockedWindow struct {
	start   time.Time
	refused int
	last    store.AuditEntry
}

type lockedAudit struct {
	mu sync.Mutex
	m  map[string]*lockedWindow
}

// writeAudit appends an entry, folding the refusals of a locked-out anonymous source into one entry per window.
func (s *Server) writeAudit(ctx context.Context, e store.AuditEntry) {
	if e.Status != 429 || e.ActorKind != "anonymous" {
		s.svc.Audit(ctx, e)
		return
	}
	key := auth.SourceKey(e.Remote)
	la := &s.lockedAud
	la.mu.Lock()
	if la.m == nil {
		la.m = map[string]*lockedWindow{}
	}
	if len(la.m) >= lockedAuditKeys && la.m[key] == nil {
		key = "*" // the table is full: one shared window for the rest
	}
	if w := la.m[key]; w != nil {
		w.refused++
		w.last = e
		la.mu.Unlock()
		return
	}
	w := &lockedWindow{start: s.svc.Clock()}
	la.m[key] = w
	la.mu.Unlock()
	s.svc.Audit(ctx, e)
	time.AfterFunc(lockedAuditWindow, func() {
		la.mu.Lock()
		delete(la.m, key)
		n, last := w.refused, w.last
		la.mu.Unlock()
		if n == 0 {
			return
		}
		last.Time = time.Time{}
		last.Detail = "authentication failed: rate_limited; " + strconv.Itoa(n) + " more requests refused while locked out since " +
			w.start.UTC().Format(time.RFC3339)
		s.svc.Audit(context.Background(), last)
	})
}
