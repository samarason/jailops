package node_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/internal/node"
	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/node/nodetest"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/sdk/api"
)

// spy counts what the node does to the backend and can hook a listing.
type spy struct {
	datastore.Backend
	mu      sync.Mutex
	puts    int
	deletes []string
	gets    map[string]int
	onList  func(prefix string)
}

func newSpy(b datastore.Backend) *spy { return &spy{Backend: b, gets: map[string]int{}} }

func (s *spy) Put(ctx context.Context, key string, r io.Reader, size int64, o datastore.PutOptions) error {
	s.mu.Lock()
	s.puts++
	s.mu.Unlock()
	return s.Backend.Put(ctx, key, r, size, o)
}
func (s *spy) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	s.deletes = append(s.deletes, key)
	s.mu.Unlock()
	return s.Backend.Delete(ctx, key)
}
func (s *spy) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	s.mu.Lock()
	s.gets[key]++
	s.mu.Unlock()
	return s.Backend.Get(ctx, key)
}
func (s *spy) List(ctx context.Context, prefix string, fn func(datastore.ObjectInfo) error) error {
	if s.onList != nil {
		s.onList(prefix)
	}
	return s.Backend.List(ctx, prefix, fn)
}
func (s *spy) reset() {
	s.mu.Lock()
	s.puts, s.deletes, s.gets = 0, nil, map[string]int{}
	s.mu.Unlock()
}

// env with a spy over a memory backend that follows the test clock.
func spyEnv(t *testing.T, conf func(*node.Config)) (*nodetest.Env, *spy) {
	t.Helper()
	clock := nodetest.NewClock()
	mem := datastore.NewMemBackend()
	mem.SetClock(clock.Now)
	sp := newSpy(mem)
	e := nodetest.NewEnv(t, nodetest.Options{Backend: sp, Configure: conf})
	e.Clock.Advance(0)
	// the env made its own clock; re-point the memory backend at it
	mem.SetClock(e.Clock.Now)
	e.Mem = mem
	return e, sp
}

func orphanChunk(t *testing.T, e *nodetest.Env, f *nodetest.Fixture, h node.Host, group string, n int) nodetest.Chunk {
	t.Helper()
	c := f.NewChunk(t)
	si, err := e.Node.Begin(ctx, h, group, snapID(e, n), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Node.PutChunk(ctx, h, si.ID, c.ID, bytes.NewReader(c.Blob), int64(len(c.Blob))); err != nil {
		t.Fatal(err)
	}
	if err := e.Node.Abort(ctx, h, si.ID); err != nil { // the session ends: its pins go
		t.Fatal(err)
	}
	return c
}

func exists(e *nodetest.Env, id format.ID) bool {
	_, err := e.Raw.Head(ctx, chunkKey(id))
	return err == nil
}

func TestGCSweepsOnlyUnreferencedOldChunks(t *testing.T) {
	e, sp := spyEnv(t, nil)
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 10)
	g := f.Group("h", "j")
	live := []nodetest.Chunk{f.NewChunk(t), f.NewChunk(t)}
	f.NewBackup(t, g, snapID(e, 1), live).Upload(t, e.Node, h, "")
	old := orphanChunk(t, e, f, h, g, 2)
	e.Clock.Advance(2 * time.Hour) // grace is 1 h
	young := orphanChunk(t, e, f, h, g, 3)

	// a dry run reports and removes nothing
	sp.reset()
	st, _, err := e.Node.GC(ctx, node.GCOptions{DryRun: true}, "admin")
	if err != nil || st.Removed != 1 || !exists(e, old.ID) || len(sp.deletes) != 0 || sp.puts != 0 {
		t.Fatalf("dry run: %+v %v deletes=%v puts=%d", st, err, sp.deletes, sp.puts)
	}
	sp.reset()
	st, job, err := e.Node.GC(ctx, node.GCOptions{}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if st.Removed != 1 || st.Live != 2 || st.KeptYoung != 1 || st.BytesReclaimed != int64(len(old.Blob)) || st.Snapshots != 1 {
		t.Fatalf("%+v", st)
	}
	if exists(e, old.ID) || !exists(e, young.ID) || !exists(e, live[0].ID) || !exists(e, live[1].ID) {
		t.Fatal("wrong chunks swept")
	}
	// nothing is touched to keep it alive: GC wrote nothing and deleted exactly the one chunk
	if sp.puts != 0 || len(sp.deletes) != 1 || sp.deletes[0] != chunkKey(old.ID) {
		t.Fatalf("puts=%d deletes=%v", sp.puts, sp.deletes)
	}
	j, _ := e.DB.Job(ctx, job.ID)
	if j.State != ctl.JobSucceeded || !strings.Contains(string(j.Result), `"removed": 1`) {
		t.Fatalf("%+v %s", j, j.Result)
	}
	// the grace period is a floor
	if _, _, err := e.Node.GC(ctx, node.GCOptions{Grace: time.Second}, "admin"); code(err) != api.CodeInvalid {
		t.Fatalf("grace under the minimum: %v", err)
	}
	// later, the young one goes too
	e.Clock.Advance(2 * time.Hour)
	if st, _, err := e.Node.GC(ctx, node.GCOptions{}, "admin"); err != nil || st.Removed != 1 || exists(e, young.ID) {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestGCNeverSweepsWhatAnOpenSessionRelies(t *testing.T) {
	// the lease runs on the clock of the node, which this test moves by five hours: the session must outlive that
	e, _ := spyEnv(t, func(c *node.Config) { c.Lease = 24 * time.Hour })
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 11)
	g := f.Group("h", "j")
	// a long upload: a session uploaded a chunk, then two hours pass
	si, err := e.Node.Begin(ctx, h, g, snapID(e, 1), "")
	if err != nil {
		t.Fatal(err)
	}
	up := f.NewChunk(t)
	if _, err := e.Node.PutChunk(ctx, h, si.ID, up.ID, bytes.NewReader(up.Blob), int64(len(up.Blob))); err != nil {
		t.Fatal(err)
	}
	// and a chunk another backup left, which this session saw present
	other := orphanChunk(t, e, f, e.Host(t, "h2"), f.Group("h2", "x"), 9)
	if miss, err := e.Node.Missing(ctx, h, si.ID, []format.ID{other.ID}); err != nil || len(miss) != 0 {
		t.Fatalf("%v %v", miss, err)
	}
	e.Clock.Advance(5 * time.Hour)
	st, _, err := e.Node.GC(ctx, node.GCOptions{}, "admin")
	if err != nil || st.Removed != 0 || st.KeptPinned != 2 || !exists(e, up.ID) || !exists(e, other.ID) {
		t.Fatalf("a chunk of an open session was swept: %+v %v", st, err)
	}
}

func TestGCCommitDuringTheRun(t *testing.T) {
	e, sp := spyEnv(t, nil)
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 12)
	g := f.Group("h", "j")
	f.NewBackup(t, g, snapID(e, 1), []nodetest.Chunk{f.NewChunk(t)}).Upload(t, e.Node, h, "")
	old := orphanChunk(t, e, f, h, g, 2)
	e.Clock.Advance(5 * time.Hour)
	// After the mark phase (at the listing of chunks/), a backup that reuses the old orphan commits.
	var done atomic.Bool
	var commitErr error
	b := f.NewBackup(t, g, snapID(e, 3), []nodetest.Chunk{old})
	sp.onList = func(prefix string) {
		if prefix != "chunks/" || !done.CompareAndSwap(false, true) {
			return
		}
		si, err := e.Node.Begin(ctx, h, g, b.Snapshot, "")
		if err != nil {
			commitErr = err
			return
		}
		if miss, err := e.Node.Missing(ctx, h, si.ID, b.IDs()); err != nil || len(miss) != 0 {
			commitErr = fmt.Errorf("missing %v %v", miss, err)
			return
		}
		_, _, _ = e.Node.PutIndex(ctx, h, si.ID, bytes.NewReader(b.Index), int64(len(b.Index)))
		_, _ = e.Node.PutManifest(ctx, h, si.ID, bytes.NewReader(b.Manifest), int64(len(b.Manifest)))
		_, commitErr = e.Node.Commit(ctx, h, si.ID, node.CommitRequest{})
	}
	st, _, err := e.Node.GC(ctx, node.GCOptions{}, "admin")
	if err != nil || commitErr != nil {
		t.Fatalf("%v %v", err, commitErr)
	}
	if !exists(e, old.ID) || st.KeptPinned != 1 {
		t.Fatalf("a chunk of a snapshot committed during the GC was swept: %+v", st)
	}
	vs, _, err := e.Node.Verify(ctx, node.VerifyOptions{Mode: "all"}, "admin")
	if err != nil || vs.Failed != 0 {
		t.Fatalf("%+v %v", vs, err)
	}
}

func TestGCAbortsOnUnreadableIndex(t *testing.T) {
	for _, damage := range []string{"corrupt", "missing"} {
		t.Run(damage, func(t *testing.T) {
			e, sp := spyEnv(t, nil)
			h := e.Host(t, "h")
			f := nodetest.NewFixture(t, 13)
			g := f.Group("h", "j")
			f.NewBackup(t, g, snapID(e, 1), []nodetest.Chunk{f.NewChunk(t)}).Upload(t, e.Node, h, "")
			b2 := f.NewBackup(t, g, snapID(e, 2), []nodetest.Chunk{f.NewChunk(t), f.NewChunk(t)})
			b2.Upload(t, e.Node, h, "")
			orphan := orphanChunk(t, e, f, h, g, 3)
			e.Clock.Advance(5 * time.Hour)
			key := "groups/" + g + "/" + b2.Snapshot + "/index"
			if damage == "corrupt" {
				e.Mem.Corrupt(key, 20)
			} else {
				_ = e.Raw.Delete(ctx, key)
			}
			sp.reset()
			_, job, err := e.Node.GC(ctx, node.GCOptions{}, "admin")
			if err == nil || !strings.Contains(err.Error(), "gc aborted") {
				t.Fatalf("GC with a %s index: %v", damage, err)
			}
			if len(sp.deletes) != 0 || !exists(e, orphan.ID) {
				t.Fatalf("GC swept on a guess: %v", sp.deletes)
			}
			j, _ := e.DB.Job(ctx, job.ID)
			if j.State != ctl.JobFailed || !strings.Contains(j.Error, "gc aborted") {
				t.Fatalf("%+v", j)
			}
		})
	}
}

func TestGCExclusiveJob(t *testing.T) {
	e, sp := spyEnv(t, nil)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	sp.onList = func(prefix string) {
		if prefix == "groups/" {
			once.Do(func() { close(started); <-release })
		}
	}
	j, err := e.Node.StartGC(node.GCOptions{}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := e.Node.StartGC(node.GCOptions{}, "admin"); code(err) != api.CodeBusy {
		t.Fatalf("a second GC: %v", err)
	}
	if _, _, err := e.Node.Verify(ctx, node.VerifyOptions{Mode: "all"}, "admin"); code(err) != api.CodeBusy {
		t.Fatalf("verify while GC runs: %v", err)
	}
	close(release)
	if fin, err := e.Node.WaitJob(ctx, j.ID); err != nil || fin.State != ctl.JobSucceeded {
		t.Fatalf("%+v %v", fin, err)
	}
}

func TestVerifyQuarantineHeal(t *testing.T) {
	e, sp := spyEnv(t, nil)
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 14)
	g := f.Group("h", "j")
	shared := f.NewChunk(t)
	own1, own2, unrelated := f.NewChunk(t), f.NewChunk(t), f.NewChunk(t)
	b1 := f.NewBackup(t, g, snapID(e, 1), []nodetest.Chunk{shared, own1})
	b1.Upload(t, e.Node, h, "")
	e.Clock.Advance(time.Hour)
	b2 := f.NewBackup(t, g, snapID(e, 2), []nodetest.Chunk{shared, own2})
	b2.Upload(t, e.Node, h, "")
	e.Clock.Advance(time.Hour)
	b3 := f.NewBackup(t, g, snapID(e, 3), []nodetest.Chunk{unrelated})
	b3.Upload(t, e.Node, h, "")

	sp.reset()
	vs, _, err := e.Node.Verify(ctx, node.VerifyOptions{Mode: "all"}, "admin")
	if err != nil || vs.Failed != 0 || vs.Snapshots != 3 {
		t.Fatalf("%+v %v", vs, err)
	}
	// each chunk object is read once per job, however many snapshots share it
	for k, n := range sp.gets {
		if strings.HasPrefix(k, "chunks/") && n != 1 {
			t.Fatalf("%s was read %d times in one job", k, n)
		}
	}
	snaps, _ := e.DB.Snapshots(ctx, g)
	for _, s := range snaps {
		if s.VerifyState != "ok" || s.VerifiedAt == nil {
			t.Fatalf("%+v", s)
		}
	}
	// verify.json is in the repository
	var rec node.VerifyRecord
	if d := mustRead(t, e.Raw, "groups/"+g+"/"+b1.Snapshot+"/verify.json"); !strings.Contains(string(d), `"state":"ok"`) {
		t.Fatal(string(d))
	}
	_ = rec

	// bit rot in the shared chunk; only the newest snapshot is selected, but every referencing snapshot must fail
	e.Mem.Corrupt(chunkKey(shared.ID), 40)
	e.Clock.Advance(time.Minute)
	if err := e.DB.SetVerify(ctx, g, b3.Snapshot, "", e.Clock.Now(), nil); err != nil { // b3 looks never verified: only it is selected
		t.Fatal(err)
	}
	vs, _, err = e.Node.Verify(ctx, node.VerifyOptions{Mode: "new", Quarantine: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_ = vs
	// the unrelated snapshot is selected and fine; the shared chunk is only found through a full scrub
	vs, _, err = e.Node.Verify(ctx, node.VerifyOptions{Mode: "all", Quarantine: true}, "admin")
	if err != nil || vs.Quarantined != 1 {
		t.Fatalf("%+v %v", vs, err)
	}
	snaps, _ = e.DB.Snapshots(ctx, g)
	state := map[string]string{}
	for _, s := range snaps {
		state[s.SnapshotID] = s.VerifyState
	}
	if state[b1.Snapshot] != "failed" || state[b2.Snapshot] != "failed" || state[b3.Snapshot] != "ok" {
		t.Fatalf("a corrupt chunk must fail every snapshot that references it: %v", state)
	}
	// quarantined: out of chunks/, kept for inspection; a host's presence check now says missing
	if exists(e, shared.ID) {
		t.Fatal("the corrupt chunk is still in chunks/")
	}
	q, err := e.Node.ListQuarantine(ctx)
	if err != nil || len(q) != 1 || q[0].ID != shared.ID.String() || q[0].Healed {
		t.Fatalf("%+v %v", q, err)
	}
	si, _ := e.Node.Begin(ctx, h, g, snapID(e, 4), b3.Snapshot)
	miss, err := e.Node.Missing(ctx, h, si.ID, []format.ID{shared.ID, own1.ID})
	if err != nil || len(miss) != 1 || miss[0] != shared.ID {
		t.Fatalf("%v %v", miss, err)
	}
	// the next upload heals it
	if r, err := e.Node.PutChunk(ctx, h, si.ID, shared.ID, bytes.NewReader(shared.Blob), int64(len(shared.Blob))); err != nil || !r.Created {
		t.Fatalf("%+v %v", r, err)
	}
	_ = e.Node.Abort(ctx, h, si.ID)
	q, _ = e.Node.ListQuarantine(ctx)
	if len(q) != 1 || !q[0].Healed {
		t.Fatalf("%+v", q)
	}
	// verify again: the old snapshots are healthy again; the healed quarantine entry is purged by GC after 24 h
	vs, _, err = e.Node.Verify(ctx, node.VerifyOptions{Mode: "all"}, "admin")
	if err != nil || vs.Failed != 0 {
		t.Fatalf("%+v %v", vs, err)
	}
	snaps, _ = e.DB.Snapshots(ctx, g)
	for _, s := range snaps {
		if s.VerifyState != "ok" {
			t.Fatalf("%+v", s)
		}
	}
	e.Clock.Advance(30 * time.Hour)
	st, _, err := e.Node.GC(ctx, node.GCOptions{}, "admin")
	if err != nil || st.QuarantinePurged != 1 {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestVerifyFindsTheOtherDamage(t *testing.T) {
	e, _ := spyEnv(t, nil)
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 15)
	g := f.Group("h", "j")
	var bs []*nodetest.Backup
	for i := range 4 {
		b := f.NewBackup(t, g, snapID(e, i+1), []nodetest.Chunk{f.NewChunk(t), f.NewChunk(t)})
		b.Upload(t, e.Node, h, "")
		bs = append(bs, b)
		e.Clock.Advance(time.Minute)
	}
	p := func(i int, f string) string { return "groups/" + g + "/" + bs[i].Snapshot + "/" + f }
	e.Mem.Corrupt(p(0, "index"), 30)                    // index differs from the receipt
	e.Mem.Corrupt(p(1, "manifest"), 30)                 // manifest differs from the receipt
	_ = e.Raw.Delete(ctx, chunkKey(bs[2].Chunks[0].ID)) // a chunk is gone
	vs, _, err := e.Node.Verify(ctx, node.VerifyOptions{Mode: "all"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, p := range vs.Problems {
		kinds[p.Kind] = true
	}
	for _, k := range []string{"index-corrupt", "manifest-corrupt", "chunk-missing"} {
		if !kinds[k] {
			t.Errorf("no %s problem: %+v", k, vs.Problems)
		}
	}
	if vs.Failed != 3 {
		t.Fatalf("%d failed: %+v", vs.Failed, vs.Results)
	}
	snaps, _ := e.DB.Snapshots(ctx, g)
	failed := 0
	for _, s := range snaps {
		if s.VerifyState == "failed" {
			failed++
		}
	}
	if failed != 3 {
		t.Fatalf("%d rows failed", failed)
	}
	// modes: new skips what was verified, stale picks it up again after the age
	vs, _, _ = e.Node.Verify(ctx, node.VerifyOptions{Mode: "new"}, "admin")
	if vs.Snapshots != 0 || vs.Skipped != 4 {
		t.Fatalf("new: %+v", vs)
	}
	vs, _, _ = e.Node.Verify(ctx, node.VerifyOptions{Mode: "stale"}, "admin")
	if vs.Snapshots != 0 {
		t.Fatalf("stale: %+v", vs)
	}
	e.Clock.Advance(40 * 24 * time.Hour)
	vs, _, _ = e.Node.Verify(ctx, node.VerifyOptions{Mode: "stale"}, "admin")
	if vs.Snapshots != 4 {
		t.Fatalf("stale after 40 days: %+v", vs)
	}
}

func TestRetentionProtectionAndPins(t *testing.T) {
	e, _ := spyEnv(t, nil)
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 16)
	g := f.Group("h", "j")
	var bs []*nodetest.Backup
	for i := range 6 {
		b := f.NewBackup(t, g, snapID(e, i+1), []nodetest.Chunk{f.NewChunk(t)})
		b.Upload(t, e.Node, h, "")
		bs = append(bs, b)
		e.Clock.Advance(time.Hour)
	}
	if err := e.DB.SetRetentionPolicy(ctx, "default", api.RetentionPolicy{Last: 2}, "UTC", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.Node.SetProtected(ctx, g, bs[1].Snapshot, true, "admin"); err != nil {
		t.Fatal(err)
	}
	// an open session pins its previous snapshot
	si, err := e.Node.Begin(ctx, h, g, snapID(e, 20), bs[2].Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := e.Node.Retention(ctx, node.RetentionOptions{DryRun: true}, "admin")
	if err != nil || len(res.Groups) != 1 || len(res.Groups[0].Delete) != 2 || res.Deleted != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if n, _ := e.DB.Snapshots(ctx, g); len(n) != 6 {
		t.Fatal("a dry run deleted")
	}
	res, _, err = e.Node.Retention(ctx, node.RetentionOptions{}, "admin")
	if err != nil || res.Deleted != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	left, _ := e.DB.Snapshots(ctx, g)
	var names []string
	for _, s := range left {
		names = append(names, s.SnapshotID)
	}
	want := []string{bs[1].Snapshot, bs[2].Snapshot, bs[4].Snapshot, bs[5].Snapshot} // protected, pinned, last 2
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("kept %v, want %v", names, want)
	}
	for _, d := range []int{0, 3} {
		if _, err := e.Raw.Head(ctx, "groups/"+g+"/"+bs[d].Snapshot+"/commit.json"); !errors.Is(err, datastore.ErrNotFound) {
			t.Fatalf("snapshot %d survived", d)
		}
	}
	_ = e.Node.Abort(ctx, h, si.ID)
	// a policy with an unknown time zone keeps everything
	_ = e.DB.SetRetentionPolicy(ctx, g, api.RetentionPolicy{Last: 1}, "Mars/Olympus", "admin")
	res, _, err = e.Node.Retention(ctx, node.RetentionOptions{}, "admin")
	if err != nil || res.Deleted != 0 || res.Groups[0].Error == "" {
		t.Fatalf("%+v %v", res, err)
	}
	// the newest snapshot is never removed, whatever the policy
	_ = e.DB.SetRetentionPolicy(ctx, g, api.RetentionPolicy{Hourly: 1}, "UTC", "admin")
	_ = e.Node.SetProtected(ctx, g, bs[1].Snapshot, false, "admin")
	res, _, _ = e.Node.Retention(ctx, node.RetentionOptions{}, "admin")
	left, _ = e.DB.Snapshots(ctx, g)
	if len(left) != 1 || left[0].SnapshotID != bs[5].Snapshot {
		t.Fatalf("%+v", left)
	}
}

func TestTwoStepDeletion(t *testing.T) {
	var events []node.AuditEvent
	var mu sync.Mutex
	e, _ := spyEnv(t, func(c *node.Config) {
		c.DeletionDelay = 48 * time.Hour
		c.Audit = func(ev node.AuditEvent) { mu.Lock(); events = append(events, ev); mu.Unlock() }
	})
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 17)
	g := f.Group("h", "j")
	b := f.NewBackup(t, g, snapID(e, 1), []nodetest.Chunk{f.NewChunk(t)})
	b.Upload(t, e.Node, h, "")
	if err := e.Node.ExecuteDeletion(ctx, g, b.Snapshot, "root"); code(err) != api.CodeInvalid {
		t.Fatalf("execute without a request: %v", err)
	}
	d, err := e.Node.RequestDeletion(ctx, g, b.Snapshot, "alice", 0)
	if err != nil || !d.After.Equal(e.Clock.Now().Add(48*time.Hour)) {
		t.Fatalf("%+v %v", d, err)
	}
	s, _ := e.DB.Snapshot(ctx, g, b.Snapshot)
	if s.PendingDeletionAfter == nil || s.PendingDeletionBy != "alice" {
		t.Fatalf("%+v", s)
	}
	if err := e.Node.ExecuteDeletion(ctx, g, b.Snapshot, "root"); code(err) != api.CodeBusy {
		t.Fatalf("too early: %v", err)
	}
	// protected snapshots cannot be executed even after the delay
	e.Clock.Advance(49 * time.Hour)
	_ = e.Node.SetProtected(ctx, g, b.Snapshot, true, "root")
	if err := e.Node.ExecuteDeletion(ctx, g, b.Snapshot, "root"); err == nil {
		t.Fatal("a protected snapshot was deleted")
	}
	if _, err := e.Node.RequestDeletion(ctx, g, b.Snapshot, "alice", 0); code(err) != api.CodeBusy {
		t.Fatalf("request for a protected snapshot: %v", err)
	}
	_ = e.Node.SetProtected(ctx, g, b.Snapshot, false, "root")
	// cancel and request again
	if err := e.Node.CancelDeletion(ctx, g, b.Snapshot, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := e.Node.ExecuteDeletion(ctx, g, b.Snapshot, "root"); code(err) != api.CodeInvalid {
		t.Fatalf("execute after cancel: %v", err)
	}
	if _, err := e.Node.RequestDeletion(ctx, g, b.Snapshot, "alice", time.Hour); code(err) != api.CodeInvalid {
		t.Fatalf("a delay below the configured one was accepted: %v", err)
	}
	if _, err := e.Node.RequestDeletion(ctx, g, b.Snapshot, "alice", 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	e.Clock.Advance(49 * time.Hour)
	if err := e.Node.ExecuteDeletion(ctx, g, b.Snapshot, "root"); err != nil {
		t.Fatal(err)
	}
	if s, _ := e.DB.Snapshots(ctx, g); len(s) != 0 {
		t.Fatal("row survived")
	}
	for _, k := range e.Mem.Keys() {
		if strings.HasPrefix(k, "groups/") && !strings.HasSuffix(k, "/owner.json") { // the group's owner marker stays
			t.Fatalf("%s survived the deletion", k)
		}
	}
	var actions []string
	mu.Lock()
	for _, ev := range events {
		actions = append(actions, ev.Action)
	}
	mu.Unlock()
	for _, want := range []string{"snapshot.delete.request", "snapshot.delete.cancel", "snapshot.delete.execute", "snapshot.protect"} {
		found := false
		for _, a := range actions {
			found = found || a == want
		}
		if !found {
			t.Errorf("no audit callback for %s in %v", want, actions)
		}
	}
	if l, _ := e.DB.AuditLog(ctx, "snapshot.delete.", 20, 0); len(l) != 4 {
		t.Fatalf("%d audit rows", len(l))
	}
}

func TestReconcileRebuildsTheIndex(t *testing.T) {
	e, _ := spyEnv(t, nil)
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 18)
	g1, g2 := f.Group("h", "a"), f.Group("h", "b")
	var all []*nodetest.Backup
	for i, g := range []string{g1, g1, g2} {
		b := f.NewBackup(t, g, snapID(e, i+1), []nodetest.Chunk{f.NewChunk(t), f.NewChunk(t)})
		b.Upload(t, e.Node, h, "")
		all = append(all, b)
		e.Clock.Advance(time.Minute)
	}
	// state that lives in marker objects
	_ = e.Node.SetProtected(ctx, g1, all[0].Snapshot, true, "root")
	if _, err := e.Node.RequestDeletion(ctx, g2, all[2].Snapshot, "alice", 0); err != nil {
		t.Fatal(err)
	}
	e.Mem.Corrupt(chunkKey(all[1].Chunks[0].ID), 33)
	if _, _, err := e.Node.Verify(ctx, node.VerifyOptions{Mode: "all"}, "root"); err != nil {
		t.Fatal(err)
	}
	// an uncommitted upload's debris is not a snapshot
	e.Mem.Overwrite("groups/"+g1+"/20260101000000-deadbeef/index", []byte("debris"))
	before, _ := e.DB.Snapshots(ctx, "")
	if len(before) != 3 {
		t.Fatal(len(before))
	}
	// the control plane loses its index; reconcile gets it back from the repository alone
	if err := e.DB.ClearIndex(ctx); err != nil {
		t.Fatal(err)
	}
	st, _, err := e.Node.Reconcile(ctx, "root")
	if err != nil || st.Added != 3 || st.Groups != 2 || st.Removed != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	after, _ := e.DB.Snapshots(ctx, "")
	if len(after) != 3 {
		t.Fatalf("%d snapshots", len(after))
	}
	for i := range before {
		b, a := before[i], after[i]
		if b.GroupID != a.GroupID || b.SnapshotID != a.SnapshotID || !b.CommittedAt.Equal(a.CommittedAt) || b.IndexDigest != a.IndexDigest ||
			b.ManifestDigest != a.ManifestDigest || b.ChunkCount != a.ChunkCount || b.Protected != a.Protected || b.VerifyState != a.VerifyState ||
			(b.PendingDeletionAfter == nil) != (a.PendingDeletionAfter == nil) || b.PendingDeletionBy != a.PendingDeletionBy {
			t.Fatalf("row %d differs:\n before %+v\n after  %+v", i, b, a)
		}
	}
	// rows of snapshots that vanished from the repository are removed
	_ = e.Raw.Delete(ctx, "groups/"+g1+"/"+all[0].Snapshot+"/commit.json")
	st, _, err = e.Node.Reconcile(ctx, "root")
	if err != nil || st.Removed != 1 || st.Updated != 2 {
		t.Fatalf("%+v %v", st, err)
	}
}

// The pins of a session that was abandoned (its lease ran out) must not keep chunks from GC for ever.
func TestAbandonedSessionPinsAreReleased(t *testing.T) {
	// The lease runs on the clock of the node, which the test moves by hand: ten hours of lease, five hours pass (the
	// session is alive), six more pass (it is not).
	e, _ := spyEnv(t, func(c *node.Config) { c.Lease = 10 * time.Hour })
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 30)
	g := f.Group("h", "j")
	si, err := e.Node.Begin(ctx, h, g, snapID(e, 1), "")
	if err != nil {
		t.Fatal(err)
	}
	c := f.NewChunk(t)
	if _, err := e.Node.PutChunk(ctx, h, si.ID, c.ID, bytes.NewReader(c.Blob), int64(len(c.Blob))); err != nil {
		t.Fatal(err)
	}
	e.Clock.Advance(5 * time.Hour)
	st, _, err := e.Node.GC(ctx, node.GCOptions{}, "admin")
	if err != nil || st.KeptPinned != 1 || !exists(e, c.ID) {
		t.Fatalf("while the lease is alive: %+v %v", st, err)
	}
	e.Clock.Advance(6 * time.Hour) // the host went away; nobody heartbeats
	st, _, err = e.Node.GC(ctx, node.GCOptions{}, "admin")
	if err != nil || st.Removed != 1 || exists(e, c.ID) {
		t.Fatalf("after the lease ran out: %+v %v", st, err)
	}
}

func TestAnEmptyRetentionPolicyIsRefused(t *testing.T) {
	e, _ := spyEnv(t, nil)
	if err := e.Node.SetRetentionPolicy(context.Background(), "default", api.RetentionPolicy{}, "UTC", "alice"); code(err) != api.CodeInvalid {
		t.Fatalf("%v", err)
	}
}
