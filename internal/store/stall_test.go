package store

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

// The database copy of the housekeeping (VACUUM INTO) must not hold up the writes of the daemon (operation steps, events,
// the audit entry of each request). This measures how long a write waits meanwhile, for a database
// with JAILOPS_STALL_ROWS audit rows (default 3000): it reports the copy time and the longest wait of a write made
// meanwhile, and fails when a write waited for a long copy. The copy runs on a reader connection since.
func TestVacuumIntoStallsWrites(t *testing.T) {
	rows := 3000
	if v, err := strconv.Atoi(os.Getenv("JAILOPS_STALL_ROWS")); err == nil && v > 0 {
		rows = v
	}
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < rows; i++ {
		_, err := s.Audit.Append(ctx, AuditEntry{Time: time.Now().UTC(), Actor: "admin", ActorKind: "user", Method: "POST",
			Route: "/api/v1/jails/{name}/start", Object: "/api/v1/jails/web" + strconv.Itoa(i%50), Result: "ok", Status: 200, Remote: "192.0.2.1",
			Detail: "a typical entry of the audit log, with some text in it so that the row is not tiny at all"})
		if err != nil {
			t.Fatal(err)
		}
	}
	var (
		mu      sync.Mutex
		longest time.Duration
		count   int
		stop    = make(chan struct{})
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			t0 := time.Now()
			if _, err := s.Events.Append(ctx, api.Event{Type: api.EventLifecycle, Timestamp: time.Now()}); err != nil {
				t.Error(err)
				return
			}
			d := time.Since(t0)
			mu.Lock()
			count++
			if d > longest {
				longest = d
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	t0 := time.Now()
	copyDir := t.TempDir()
	if err := s.VacuumInto(ctx, filepath.Join(copyDir, "copy.db")); err != nil {
		t.Fatal(err)
	}
	copyTime := time.Since(t0)
	close(stop)
	wg.Wait()
	fi, _ := os.Stat(s.path)
	t.Logf("%d audit rows (database %.1f MiB): the copy took %v; %d event appends meanwhile, the longest waited %v", rows, float64(fi.Size())/(1<<20), copyTime.Round(time.Millisecond), count, longest.Round(time.Millisecond))
	// The copy runs on a reader connection: a write made meanwhile does not wait for it. (On the writer connection the
	// longest wait was the whole copy.)
	// (Under the race detector on a loaded machine a write waits a good part of a short copy anyway: the writer held
	// by the whole copy is the failure, and that is a wait of about the copy time.)
	if copyTime > 100*time.Millisecond && longest > copyTime*3/4 {
		t.Errorf("a write waited %v for a database copy that took %v: the copy must not hold the writer", longest, copyTime)
	}
	if v, problems, err := OpenReadOnlyCheck(ctx, filepath.Join(copyDir, "copy.db")); err != nil || len(problems) > 0 || v == 0 {
		t.Fatalf("the copy: version %d problems %v err %v", v, problems, err)
	}
}
