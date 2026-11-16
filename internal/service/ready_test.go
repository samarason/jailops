package service

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/state"
	"jailops.net/jailops/internal/store"
)

// probeZFS answers Exists for the readiness probe and counts the calls.
type probeZFS struct {
	lifecycle.ZFS
	mu     sync.Mutex
	err    error
	exists bool
	calls  int
}

func (z *probeZFS) Exists(ctx context.Context, _ string) (bool, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.calls++
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return z.exists, z.err
}

func (z *probeZFS) set(exists bool, err error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.exists, z.err = exists, err
}

func (z *probeZFS) n() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.calls
}

func readySvc(t *testing.T) (*Service, *probeZFS, *store.Store, *time.Time) {
	t.Helper()
	st, err := state.Open(t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := &probeZFS{exists: true}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s, err := New(Deps{State: st, DB: db, JournalDir: t.TempDir(), HostUUID: "h", ZFS: z, Root: "tank/jailops",
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); db.Close(); st.Close() })
	return s, z, db, &now
}

func TestReadyFollowsStartupHelperAndStore(t *testing.T) {
	s, z, db, now := readySvc(t)
	if r := s.Ready(bg); r != NotReadyStarting {
		t.Fatalf("before start-up finished: %q", r)
	}
	if z.n() != 0 {
		t.Error("the helper was asked before start-up finished")
	}
	s.MarkStarted()
	if r := s.Ready(bg); r != "" {
		t.Fatalf("healthy: %q", r)
	}
	// cached: a flood of probes is one helper call per period
	z.set(false, errors.New("connection refused"))
	for i := 0; i < 100; i++ {
		if r := s.Ready(bg); r != "" {
			t.Fatalf("cached answer changed: %q", r)
		}
	}
	if z.n() != 1 {
		t.Errorf("%d helper calls for 101 probes within the cache period, want 1", z.n())
	}
	*now = now.Add(ReadyCacheTTL)
	if r := s.Ready(bg); r != NotReadyHelper {
		t.Errorf("helper down: %q", r)
	}
	*now = now.Add(ReadyCacheTTL)
	z.set(false, nil)
	if r := s.Ready(bg); r != NotReadyStorage {
		t.Errorf("dataset missing: %q", r)
	}
	*now = now.Add(ReadyCacheTTL)
	z.set(true, nil)
	if r := s.Ready(bg); r != "" {
		t.Errorf("helper back: %q", r)
	}
	*now = now.Add(ReadyCacheTTL)
	db.Close()
	if r := s.Ready(bg); r != NotReadyStore {
		t.Errorf("store failing: %q", r)
	}
	s.MarkStopping()
	if r := s.Ready(bg); r != NotReadyStopping {
		t.Errorf("stopping: %q", r)
	}
}

func TestReadyIgnoresTheCallersCancellation(t *testing.T) {
	s, _, _, _ := readySvc(t)
	s.MarkStarted()
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if r := s.Ready(ctx); r != "" {
		t.Errorf("a caller that hung up made the host unready: %q", r)
	}
}
