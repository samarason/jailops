package node_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/node"
	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/node/nodetest"
	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/internal/testdb"
	"jailops.net/jailops/sdk/api"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var ctx = context.Background()

func code(err error) api.Code {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func snapID(e *nodetest.Env, n int) string { return nodetest.SnapshotID(e.Clock.Now(), n) }

func TestBackupRoundTrip(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	h := e.Host(t, "h1")
	f := nodetest.NewFixture(t, 1)
	group := f.Group("h1", "web")
	var chunks []nodetest.Chunk
	for range 12 {
		chunks = append(chunks, f.NewChunk(t))
	}
	b1 := f.NewBackup(t, group, snapID(e, 1), chunks)
	rc := b1.Upload(t, e.Node, h, "")
	if rc.ChunkCount != 12 || rc.IndexDigest != b1.IndexDigest || rc.ManifestDigest != b1.ManifestDigest || !rc.Committed.Equal(e.Clock.Now()) {
		t.Fatalf("receipt %+v", rc)
	}
	// the repository holds exactly the snapshot objects, the node wrote the receipt last
	p := "groups/" + group + "/" + b1.Snapshot + "/"
	for _, k := range []string{"index", "manifest", "commit.json"} {
		if _, err := e.Raw.Head(ctx, p+k); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	snaps, err := e.Node.Snapshots(ctx, group)
	if err != nil || len(snaps) != 1 || snaps[0].ChunkCount != 12 {
		t.Fatalf("%+v %v", snaps, err)
	}
	// a second backup uploads only what is new
	e.Clock.Advance(time.Hour)
	newChunk := f.NewChunk(t)
	b2 := f.NewBackup(t, group, snapID(e, 2), append(append([]nodetest.Chunk(nil), chunks[:10]...), newChunk))
	si, err := e.Node.Begin(ctx, h, group, b2.Snapshot, b1.Snapshot)
	if err != nil || si.Previous != b1.Snapshot {
		t.Fatalf("begin: %+v %v", si, err)
	}
	missing, err := e.Node.Missing(ctx, h, si.ID, b2.IDs())
	if err != nil || len(missing) != 1 || missing[0] != newChunk.ID {
		t.Fatalf("missing: %v %v", missing, err)
	}
	if err := e.Node.Abort(ctx, h, si.ID); err != nil {
		t.Fatal(err)
	}
	b2.Upload(t, e.Node, h, b1.Snapshot)
	// reads
	obj, err := e.Node.OpenChunk(ctx, chunks[0].ID, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(obj)
	obj.Close()
	if !bytes.Equal(got, chunks[0].Blob) {
		t.Fatal("chunk differs")
	}
	obj, err = e.Node.OpenSnapshotFile(ctx, group, b1.Snapshot, node.FileIndex, 8, 16)
	if err != nil {
		t.Fatal(err)
	}
	part, _ := io.ReadAll(obj)
	obj.Close()
	if !bytes.Equal(part, b1.Index[8:24]) || obj.Size != int64(len(b1.Index)) {
		t.Fatal("index range differs")
	}
	if _, err := e.Node.OpenSnapshotFile(ctx, group, "20200101000000-00000000", node.FileIndex, 0, -1); code(err) != api.CodeNotFound {
		t.Fatalf("an uncommitted snapshot must not exist: %v", err)
	}
}

func TestHostileHost(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	good, evil := e.Host(t, "good"), e.Host(t, "evil")
	f := nodetest.NewFixture(t, 2)
	gGood, gEvil := f.Group("good", "web"), f.Group("evil", "x")
	c0, c1 := f.NewChunk(t), f.NewChunk(t)
	b := f.NewBackup(t, gGood, snapID(e, 1), []nodetest.Chunk{c0, c1})
	b.Upload(t, e.Node, good, "")

	si, err := e.Node.Begin(ctx, evil, gEvil, snapID(e, 5), "")
	if err != nil {
		t.Fatal(err)
	}
	// overwrite an existing chunk with other (valid) bytes under the same id: refused, the original stays
	other := f.NewChunk(t)
	_, err = e.Node.PutChunk(ctx, evil, si.ID, c0.ID, bytes.NewReader(other.Blob), int64(len(other.Blob)))
	if code(err) != api.CodeAlreadyExists {
		t.Fatalf("overwriting a chunk: %v", err)
	}
	if got := mustRead(t, e.Raw, chunkKey(c0.ID)); !bytes.Equal(got, c0.Blob) {
		t.Fatal("a hostile upload replaced a stored chunk")
	}
	// the same bytes again are a harmless retry
	if r, err := e.Node.PutChunk(ctx, evil, si.ID, c0.ID, bytes.NewReader(c0.Blob), int64(len(c0.Blob))); err != nil || r.Created {
		t.Fatalf("identical retry: %+v %v", r, err)
	}
	// corrupt and truncated blobs
	bad := append([]byte(nil), other.Blob...)
	bad[10] ^= 1
	if _, err := e.Node.PutChunk(ctx, evil, si.ID, other.ID, bytes.NewReader(bad), int64(len(bad))); code(err) != api.CodeInvalid {
		t.Fatalf("corrupt blob: %v", err)
	}
	if _, err := e.Node.PutChunk(ctx, evil, si.ID, other.ID, bytes.NewReader(other.Blob[:50]), int64(len(other.Blob))); code(err) != api.CodeInvalid {
		t.Fatalf("short body: %v", err)
	}
	if _, err := e.Node.PutChunk(ctx, evil, si.ID, other.ID, bytes.NewReader(append(append([]byte(nil), other.Blob...), 1)), int64(len(other.Blob))); code(err) != api.CodeInvalid {
		t.Fatalf("long body: %v", err)
	}
	if _, err := e.Raw.Head(ctx, chunkKey(other.ID)); !errors.Is(err, datastore.ErrNotFound) {
		t.Fatal("a refused blob was stored")
	}
	// commit with a chunk that is not there
	bm := f.NewBackup(t, gEvil, snapID(e, 5), []nodetest.Chunk{c0, other})
	if _, _, err := e.Node.PutIndex(ctx, evil, si.ID, bytes.NewReader(bm.Index), int64(len(bm.Index))); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Node.PutManifest(ctx, evil, si.ID, bytes.NewReader(bm.Manifest), int64(len(bm.Manifest))); err != nil {
		t.Fatal(err)
	}
	_, err = e.Node.Commit(ctx, evil, si.ID, node.CommitRequest{})
	var ae *api.Error
	if code(err) != api.CodeMissingChunks || !errors.As(err, &ae) || !strings.Contains(ae.Detail["first"], other.ID.String()) {
		t.Fatalf("commit with a missing chunk: %v", err)
	}
	if _, err := e.Raw.Head(ctx, "groups/"+gEvil+"/"+bm.Snapshot+"/commit.json"); !errors.Is(err, datastore.ErrNotFound) {
		t.Fatal("a refused commit left a receipt")
	}
	// the session stays open: upload and retry
	if _, err := e.Node.PutChunk(ctx, evil, si.ID, other.ID, bytes.NewReader(other.Blob), int64(len(other.Blob))); err != nil {
		t.Fatal(err)
	}
	rc, err := e.Node.Commit(ctx, evil, si.ID, node.CommitRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// replaying the commit is idempotent and returns the same receipt; a different digest is refused
	rc2, err := e.Node.Commit(ctx, evil, si.ID, node.CommitRequest{IndexDigest: bm.IndexDigest, ManifestDigest: bm.ManifestDigest})
	if err != nil || rc2.Committed != rc.Committed {
		t.Fatalf("replay: %+v %v", rc2, err)
	}
	if _, err := e.Node.Commit(ctx, evil, si.ID, node.CommitRequest{IndexDigest: strings.Repeat("0", 64)}); code(err) != api.CodeInvalid {
		t.Fatalf("replay with other digests: %v", err)
	}
	// the replay of another host's session id
	if _, err := e.Node.Commit(ctx, good, si.ID, node.CommitRequest{}); code(err) != api.CodeLeaseExpired {
		t.Fatalf("another host replaying a session: %v", err)
	}
	// a second snapshot with the committed id is refused at the start
	if _, err := e.Node.Begin(ctx, evil, gEvil, bm.Snapshot, ""); code(err) != api.CodeAlreadyExists {
		t.Fatalf("begin of a committed snapshot: %v", err)
	}
	// a group of another host
	if _, err := e.Node.Begin(ctx, evil, gGood, snapID(e, 9), ""); code(err) != api.CodeForbidden {
		t.Fatalf("a group of another host: %v", err)
	}
	// one open session per group
	s1, err := e.Node.Begin(ctx, good, gGood, snapID(e, 10), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Node.Begin(ctx, good, gGood, snapID(e, 11), ""); code(err) != api.CodeBusy {
		t.Fatalf("second session: %v", err)
	}
	// another host cannot use a session it does not own
	if _, err := e.Node.Missing(ctx, evil, s1.ID, []format.ID{c0.ID}); code(err) != api.CodeLeaseExpired {
		t.Fatalf("a foreign session: %v", err)
	}
	// a snapshot id from the future
	if _, err := e.Node.Begin(ctx, evil, gEvil, nodetest.SnapshotID(e.Clock.Now().Add(time.Hour), 3), ""); code(err) != api.CodeInvalid {
		t.Fatalf("future snapshot: %v", err)
	}
	// more than 2000 ids
	many := make([]format.ID, 2001)
	for i := range many {
		many[i][0], many[i][1] = byte(i), byte(i>>8)
	}
	if _, err := e.Node.Missing(ctx, good, s1.ID, many); code(err) != api.CodeInvalid {
		t.Fatalf("2001 ids: %v", err)
	}
}

func TestLeaseExpiry(t *testing.T) {
	// The lease runs on the clock of the node (Config.Now), which the test moves by hand: nothing here waits for time.
	var lease = 600 * time.Millisecond
	e := nodetest.NewEnv(t, nodetest.Options{Configure: func(c *node.Config) { c.Lease = lease }})
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 3)
	g := f.Group("h", "j")
	si, err := e.Node.Begin(ctx, h, g, snapID(e, 1), "")
	if err != nil {
		t.Fatal(err)
	}
	// activity renews
	for range 4 { // 800ms in all: longer than one lease, so only the renewals keep the session alive
		e.Clock.Advance(lease / 3)
		if _, err := e.Node.Heartbeat(ctx, h, si.ID); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
	}
	e.Clock.Advance(lease + 100*time.Millisecond)
	c := f.NewChunk(t)
	if _, err := e.Node.PutChunk(ctx, h, si.ID, c.ID, bytes.NewReader(c.Blob), int64(len(c.Blob))); code(err) != api.CodeLeaseExpired {
		t.Fatalf("a chunk after the lease ran out: %v", err)
	}
	// the group is free again
	si2, err := e.Node.Begin(ctx, h, g, snapID(e, 2), "")
	if err != nil {
		t.Fatalf("a new session after expiry: %v", err)
	}
	// the old session cannot commit
	if _, err := e.Node.Commit(ctx, h, si.ID, node.CommitRequest{}); code(err) != api.CodeLeaseExpired {
		t.Fatalf("commit of an expired session: %v", err)
	}
	if err := e.Node.Abort(ctx, h, si2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Node.Heartbeat(ctx, h, si2.ID); code(err) != api.CodeLeaseExpired {
		t.Fatalf("heartbeat after abort: %v", err)
	}
}

func TestRestartClosesSessions(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 4)
	g := f.Group("h", "j")
	si, _ := e.Node.Begin(ctx, h, g, snapID(e, 1), "")
	e.Reopen(t)
	if _, err := e.Node.Heartbeat(ctx, h, si.ID); code(err) != api.CodeLeaseExpired {
		t.Fatalf("after a restart: %v", err)
	}
	if _, err := e.Node.Begin(ctx, h, g, snapID(e, 2), ""); err != nil {
		t.Fatalf("the group must be free after a restart: %v", err)
	}
}

func TestCommitRetryAfterRestart(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 5)
	g := f.Group("h", "j")
	b := f.NewBackup(t, g, snapID(e, 1), []nodetest.Chunk{f.NewChunk(t)})
	si, _ := e.Node.Begin(ctx, h, g, b.Snapshot, "")
	for _, c := range b.Chunks {
		_, _ = e.Node.PutChunk(ctx, h, si.ID, c.ID, bytes.NewReader(c.Blob), int64(len(c.Blob)))
	}
	_, _, _ = e.Node.PutIndex(ctx, h, si.ID, bytes.NewReader(b.Index), int64(len(b.Index)))
	_, _ = e.Node.PutManifest(ctx, h, si.ID, bytes.NewReader(b.Manifest), int64(len(b.Manifest)))
	rc, err := e.Node.Commit(ctx, h, si.ID, node.CommitRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// the answer was lost and the node restarted: the host retries with its digests
	e.Reopen(t)
	rc2, err := e.Node.Commit(ctx, h, si.ID, node.CommitRequest{IndexDigest: b.IndexDigest, ManifestDigest: b.ManifestDigest})
	if err != nil || rc2.Committed != rc.Committed {
		t.Fatalf("retry after restart: %+v %v", rc2, err)
	}
	if _, err := e.Node.Commit(ctx, h, si.ID, node.CommitRequest{}); err == nil {
		t.Fatalf("a retry without digests after a restart must not be guessed: %v", err)
	}
}

func TestMaintenanceModes(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 6)
	g := f.Group("h", "j")
	c := f.NewChunk(t)
	b := f.NewBackup(t, g, snapID(e, 1), []nodetest.Chunk{c})
	b.Upload(t, e.Node, h, "")

	si, err := e.Node.Begin(ctx, h, g, snapID(e, 2), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Node.SetMode(ctx, datastore.ModeReadOnly, "admin"); err != nil {
		t.Fatal(err)
	}
	// reads continue; every write is refused with the maintenance code
	if o, err := e.Node.OpenChunk(ctx, c.ID, 0, -1); err != nil {
		t.Fatalf("read in read-only: %v", err)
	} else {
		o.Close()
	}
	c2 := f.NewChunk(t)
	if _, err := e.Node.PutChunk(ctx, h, si.ID, c2.ID, bytes.NewReader(c2.Blob), int64(len(c2.Blob))); code(err) != api.CodeMaintenance {
		t.Fatalf("put chunk in read-only: %v", err)
	}
	if _, err := e.Node.Begin(ctx, h, f.Group("h", "other"), snapID(e, 3), ""); code(err) != api.CodeMaintenance {
		t.Fatalf("begin in read-only: %v", err)
	}
	if _, _, err := e.Node.GC(ctx, node.GCOptions{Grace: time.Hour}, "admin"); code(err) != api.CodeMaintenance {
		t.Fatalf("gc in read-only: %v", err)
	}
	if err := e.Node.SetProtected(ctx, g, b.Snapshot, true, "admin"); code(err) != api.CodeMaintenance {
		t.Fatalf("protect in read-only: %v", err)
	}
	if _, _, err := e.Node.Verify(ctx, node.VerifyOptions{Mode: "all"}, "admin"); code(err) != api.CodeMaintenance {
		t.Fatalf("verify in read-only: %v", err)
	}
	// a dry-run GC and a retention plan only read
	if _, _, err := e.Node.GC(ctx, node.GCOptions{Grace: time.Hour, DryRun: true}, "admin"); err != nil {
		t.Fatalf("dry-run gc in read-only: %v", err)
	}
	if _, _, err := e.Node.Retention(ctx, node.RetentionOptions{DryRun: true}, "admin"); err != nil {
		t.Fatalf("retention plan in read-only: %v", err)
	}
	if err := e.Node.SetMode(ctx, datastore.ModeOffline, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Node.OpenChunk(ctx, c.ID, 0, -1); code(err) != api.CodeMaintenance {
		t.Fatalf("read when offline: %v", err)
	}
	// the mode survives a restart
	e.Reopen(t)
	if e.Node.Mode() != datastore.ModeOffline {
		t.Fatalf("mode after restart: %v", e.Node.Mode())
	}
	if err := e.Node.SetMode(ctx, datastore.ModeOnline, "admin"); err != nil {
		t.Fatal(err)
	}
	si, err = e.Node.Begin(ctx, h, g, snapID(e, 4), "")
	if err != nil {
		t.Fatalf("begin online again: %v", err)
	}
	if _, err := e.Node.PutChunk(ctx, h, si.ID, c2.ID, bytes.NewReader(c2.Blob), int64(len(c2.Blob))); err != nil {
		t.Fatal(err)
	}
	l, _ := e.DB.AuditLog(ctx, "maintenance.", 10, 0)
	if len(l) != 3 {
		t.Fatalf("%d maintenance audit entries", len(l))
	}
}

func TestOwnerJSON(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	o, err := node.ReadOwner(ctx, e.Raw)
	if err != nil || o == nil || o.ServerID != "node-test" {
		t.Fatalf("%+v %v", o, err)
	}
	// a second node on the same repository is refused
	cfg := e.Cfg
	cfg.ServerID = "another-node"
	if _, err := node.Open(ctx, cfg); !errors.Is(err, node.ErrForeignOwner) {
		t.Fatalf("a foreign node: %v", err)
	}
	// unless it adopts it
	cfg.Adopt = true
	n2, err := node.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	defer n2.Close()
	o, _ = node.ReadOwner(ctx, e.Raw)
	if o.ServerID != "another-node" || o.Previous != "node-test" {
		t.Fatalf("%+v", o)
	}
	// init refuses an initialised datastore; open refuses an empty one
	if _, err := node.Init(ctx, e.Raw, node.InitOptions{ServerID: "x", Host: "h"}); err == nil {
		t.Fatal("init over a repository")
	}
	cfg.Backend = datastore.NewMemBackend()
	if _, err := node.Open(ctx, cfg); !errors.Is(err, node.ErrNotRepository) {
		t.Fatalf("open of an empty datastore: %v", err)
	}
	// concurrent claim: exactly one wins
	b := datastore.NewMemBackend()
	errs := make(chan error, 8)
	for i := range 8 {
		go func() { errs <- node.ClaimOwner(ctx, b, string(rune('a'+i)), "h", false) }()
	}
	won := 0
	for range 8 {
		if err := <-errs; err == nil {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d nodes claimed the repository", won)
	}
}

func chunkKey(id format.ID) string {
	h := id.String()
	return "chunks/" + h[:2] + "/" + h[2:4] + "/" + h
}

func mustRead(t *testing.T, b datastore.Backend, key string) []byte {
	t.Helper()
	d, err := datastore.ReadAll(ctx, b, key, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var _ = ctl.JobGC

func TestKeyDomainAndEscrow(t *testing.T) {
	clock := nodetest.NewClock()
	mem := datastore.NewMemBackend()
	mem.SetClock(clock.Now)
	if _, err := node.Init(ctx, mem, node.InitOptions{ServerID: "node-test", Host: "h", KeyDomain: "0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Init(ctx, datastore.NewMemBackend(), node.InitOptions{ServerID: "x", KeyDomain: "nonsense"}); err == nil {
		t.Fatal("a malformed key domain")
	}
	e := nodetest.NewEnv(t, nodetest.Options{Backend: mem, NoInit: true})
	h := e.Host(t, "h")
	f := nodetest.NewFixture(t, 40)
	g := f.Group("h", "j")
	if _, err := e.Node.BeginWith(ctx, h, wire.BeginRequest{Group: g, Snapshot: snapID(e, 1), KeyDomain: "fedcba9876543210"}); code(err) != api.CodeForbidden {
		t.Fatalf("another key domain: %v", err)
	}
	if _, err := e.Node.BeginWith(ctx, h, wire.BeginRequest{Group: g, Snapshot: snapID(e, 1)}); code(err) != api.CodeForbidden {
		t.Fatalf("no key domain at all: %v", err)
	}
	si, err := e.Node.BeginWith(ctx, h, wire.BeginRequest{Group: g, Snapshot: snapID(e, 1), KeyDomain: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.Node.Abort(ctx, h, si.ID)
	if e.Node.Info().KeyDomain != "0123456789abcdef" {
		t.Fatal("the key domain is not reported")
	}
	// escrow: create-only, same bytes again is fine, other bytes are refused, other domains are refused
	blob := []byte("age-encryption.org/v1\n-> X25519 stanza\nwrapped key")
	if err := e.Node.PutEscrow(ctx, h, "0123456789abcdef", bytes.NewReader(blob), int64(len(blob))); err != nil {
		t.Fatal(err)
	}
	if err := e.Node.PutEscrow(ctx, h, "0123456789abcdef", bytes.NewReader(blob), int64(len(blob))); err != nil {
		t.Fatalf("the same bytes again: %v", err)
	}
	other := []byte("age-encryption.org/v1\n-> X25519 stanza\na different wrapped key")
	if err := e.Node.PutEscrow(ctx, h, "0123456789abcdef", bytes.NewReader(other), int64(len(other))); code(err) != api.CodeAlreadyExists {
		t.Fatalf("replacing an escrow blob: %v", err)
	}
	if err := e.Node.PutEscrow(ctx, h, "fedcba9876543210", bytes.NewReader(blob), int64(len(blob))); code(err) != api.CodeForbidden {
		t.Fatalf("an escrow blob for another domain: %v", err)
	}
	if err := e.Node.PutEscrow(ctx, h, "0123456789abcdef", bytes.NewReader(nil), 0); code(err) == "" {
		t.Fatal("an empty escrow blob")
	}
	if got, err := e.Node.GetEscrow(ctx, "0123456789abcdef"); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("%q %v", got, err)
	}
	if l, err := e.Node.ListEscrow(ctx); err != nil || len(l) != 1 || l[0] != "0123456789abcdef" {
		t.Fatalf("%v %v", l, err)
	}
	if _, err := e.Node.GetEscrow(ctx, "../../etc/passwd"); code(err) != api.CodeInvalid {
		t.Fatalf("%v", err)
	}
}
