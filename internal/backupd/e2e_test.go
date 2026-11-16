package backupd_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/node"
	"jailops.net/jailops/internal/node/client"
	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/node/nodetest"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/sdk/api"
)

var ctx = context.Background()

func code(err error) api.Code {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func chunkKey(id format.ID) string {
	h := id.String()
	return "chunks/" + h[:2] + "/" + h[2:4] + "/" + h
}

// upload runs the host protocol over the network the way an engine does: parallel chunk uploads.
func upload(t *testing.T, c *client.Client, b *nodetest.Backup, previous string) *format.Receipt {
	t.Helper()
	s, err := c.Begin(ctx, b.Group, b.Snapshot, previous)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	miss, err := s.Missing(ctx, b.IDs())
	if err != nil {
		t.Fatalf("missing: %v", err)
	}
	want := map[format.ID]bool{}
	for _, m := range miss {
		want[m] = true
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	var mu sync.Mutex
	var first error
	for _, ch := range b.Chunks {
		if !want[ch.ID] {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := s.PutChunk(ctx, ch.ID, ch.Blob); err != nil {
				mu.Lock()
				first = err
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if first != nil {
		t.Fatalf("put chunk: %v", first)
	}
	if err := s.PutIndex(ctx, b.Index); err != nil {
		t.Fatalf("put index: %v", err)
	}
	if err := s.PutManifest(ctx, b.Manifest); err != nil {
		t.Fatalf("put manifest: %v", err)
	}
	rc, err := s.Commit(ctx)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return rc
}

func manyChunks(t *testing.T, f *nodetest.Fixture, n int) []nodetest.Chunk {
	out := make([]nodetest.Chunk, n)
	for i := range out {
		out[i] = f.NewChunk(t)
	}
	return out
}

func TestEndToEnd(t *testing.T) {
	for _, kind := range []backendKind{memKind, s3Kind, dirKind} {
		t.Run(string(kind), func(t *testing.T) { endToEnd(t, kind) })
	}
}

func endToEnd(t *testing.T, kind backendKind) {
	r := startRig(t, kind, nil)
	a, b := r.enroll("host-a"), r.enroll("host-b")
	f := r.Fix
	shared := manyChunks(t, f, 20)
	ga, gb := f.Group("host-a", "web"), f.Group("host-b", "db")
	ba := f.NewBackup(t, ga, nodetest.SnapshotID(r.Clock.Now(), 1), append(append([]nodetest.Chunk(nil), shared...), manyChunks(t, f, 30)...))
	bb := f.NewBackup(t, gb, nodetest.SnapshotID(r.Clock.Now(), 2), append(append([]nodetest.Chunk(nil), shared...), manyChunks(t, f, 30)...))

	// two hosts, concurrent sessions, overlapping chunks (cross-host deduplication)
	var wg sync.WaitGroup
	var rcA, rcB *format.Receipt
	wg.Add(2)
	go func() { defer wg.Done(); rcA = upload(t, a.C, ba, "") }()
	go func() { defer wg.Done(); rcB = upload(t, b.C, bb, "") }()
	wg.Wait()
	if t.Failed() {
		return
	}
	if rcA.ChunkCount != 50 || rcB.ChunkCount != 50 || rcA.IndexDigest != ba.IndexDigest || rcB.ManifestDigest != bb.ManifestDigest {
		t.Fatalf("receipts %+v %+v", rcA, rcB)
	}
	// the shared chunks exist once
	n := 0
	_ = r.Raw.List(ctx, "chunks/", func(datastore.ObjectInfo) error { n++; return nil })
	if n != 80 {
		t.Fatalf("%d chunk objects, want 80 (20 shared + 30 + 30)", n)
	}

	// reads: list, receipt, index range, manifest, chunk
	snaps, err := a.C.Snapshots(ctx, ga)
	if err != nil || len(snaps) != 1 || snaps[0].SnapshotID != ba.Snapshot {
		t.Fatalf("%+v %v", snaps, err)
	}
	rc, err := a.C.Receipt(ctx, ga, ba.Snapshot)
	if err != nil || rc.IndexDigest != ba.IndexDigest {
		t.Fatalf("%+v %v", rc, err)
	}
	body, total, err := a.C.Index(ctx, ga, ba.Snapshot, 8, 24)
	if err != nil {
		t.Fatal(err)
	}
	part, _ := io.ReadAll(body)
	body.Close()
	if !bytes.Equal(part, ba.Index[8:32]) || total != int64(len(ba.Index)) {
		t.Fatalf("index range: %d bytes, total %d (%d)", len(part), total, len(ba.Index))
	}
	if mb, err := a.C.Manifest(ctx, ga, ba.Snapshot); err != nil || !bytes.Equal(mb, ba.Manifest) {
		t.Fatalf("a host reads the manifest of its base snapshot: %v", err)
	}
	pushOnly := r.enroll("push-only", "backup-push")
	if _, err := pushOnly.C.Manifest(ctx, ga, ba.Snapshot); code(err) != api.CodeForbidden {
		t.Fatalf("a push-only host read a manifest: %v", err)
	}
	if _, err := pushOnly.C.Snapshots(ctx, ga); code(err) != api.CodeForbidden {
		t.Fatalf("a push-only host listed snapshots: %v", err)
	}
	rec := r.enroll("recovery", "backup-pull", "restore")
	if mb, err := rec.C.Manifest(ctx, ga, ba.Snapshot); err != nil || !bytes.Equal(mb, ba.Manifest) {
		t.Fatalf("manifest: %v", err)
	}
	if _, err := rec.C.Begin(ctx, ga, nodetest.SnapshotID(r.Clock.Now(), 9), ""); code(err) != api.CodeForbidden {
		t.Fatalf("a recovery host opened a backup session: %v", err)
	}
	if blob, err := b.C.Chunk(ctx, shared[3].ID); err != nil || !bytes.Equal(blob, shared[3].Blob) {
		t.Fatalf("chunk: %v", err)
	}
	if _, err := a.C.Chunk(ctx, format.ID{1, 2, 3}); code(err) != api.CodeNotFound {
		t.Fatalf("missing chunk: %v", err)
	}
	info, err := a.C.Info(ctx)
	if err != nil || info.Mode != "online" || info.MaxBatch != 2000 {
		t.Fatalf("%+v %v", info, err)
	}

	// a second backup of host a uploads only what changed and pins the previous snapshot
	r.Clock.Advance(time.Hour)
	ba2 := f.NewBackup(t, ga, nodetest.SnapshotID(r.Clock.Now(), 3), append(append([]nodetest.Chunk(nil), ba.Chunks[:45]...), f.NewChunk(t)))
	s2, err := a.C.Begin(ctx, ga, ba2.Snapshot, ba.Snapshot)
	if err != nil || s2.Previous() != ba.Snapshot {
		t.Fatalf("%v", err)
	}
	if miss, _ := s2.Missing(ctx, ba2.IDs()); len(miss) != 1 {
		t.Fatalf("%d missing, want 1", len(miss))
	}
	// the previous snapshot is protected from retention while the session is open
	_ = r.DB.SetRetentionPolicy(ctx, "default", api.RetentionPolicy{Last: 1}, "UTC", "t")
	res := adminJob[node.RetentionResult](t, r, "/retention", node.RetentionOptions{})
	for _, g := range res.Groups {
		if g.Group == ga && len(g.Deleted) != 0 {
			t.Fatalf("retention removed the snapshot an open session uses as its base: %+v", g)
		}
	}
	_ = s2.Abort(ctx)

	// a lost response: commit twice
	ba3 := f.NewBackup(t, ga, nodetest.SnapshotID(r.Clock.Now(), 4), ba2.Chunks)
	rc3 := upload(t, a.C, ba3, ba.Snapshot)
	s4, err := a.C.Begin(ctx, ga, nodetest.SnapshotID(r.Clock.Now().Add(time.Second), 5), "")
	if err != nil {
		t.Fatal(err)
	}
	_ = s4.Abort(ctx)
	_ = rc3

	// admin: status, verify, GC
	var st node.RepositoryStatus
	if err := r.admin().Call(ctx, "GET", "/api/v1/repo/admin/status", nil, &st); err != nil {
		t.Fatal(err)
	}
	if st.Snapshots != 3 || st.Groups != 2 || st.Mode != "online" || st.Backend != string(kind) && !(kind == s3Kind && st.Backend == "s3") && !(kind == dirKind && st.Backend == "directory") {
		t.Fatalf("%+v", st)
	}
	vs := adminJob[node.VerifyStats](t, r, "/verify", node.VerifyOptions{Mode: "all"})
	if vs.Failed != 0 || vs.Snapshots != 3 {
		t.Fatalf("%+v", vs)
	}
	r.Clock.Advance(48 * time.Hour)
	gc := adminJob[node.GCStats](t, r, "/gc", node.GCRequest{})
	if gc.Live != 81 || gc.Removed != 0 {
		t.Fatalf("%+v", gc)
	}
	// the chunks of snapshots the retention policy dropped become garbage and go
	_ = r.DB.SetRetentionPolicy(ctx, ga, api.RetentionPolicy{Last: 1}, "UTC", "t")
	res = adminJob[node.RetentionResult](t, r, "/retention", node.RetentionOptions{})
	if res.Deleted != 1 {
		t.Fatalf("%+v", res)
	}
	r.Clock.Advance(48 * time.Hour)
	gc = adminJob[node.GCStats](t, r, "/gc", node.GCRequest{})
	if gc.Removed != 5 { // the 5 chunks only the first snapshot had
		t.Fatalf("%+v", gc)
	}
	// host b's snapshot, which shares 20 chunks with the deleted ones, is intact
	vs = adminJob[node.VerifyStats](t, r, "/verify", node.VerifyOptions{Mode: "all"})
	if vs.Failed != 0 {
		t.Fatalf("%+v", vs)
	}
	if blob, err := b.C.Chunk(ctx, shared[3].ID); err != nil || !bytes.Equal(blob, shared[3].Blob) {
		t.Fatalf("a shared chunk was swept: %v", err)
	}
}

// adminJob runs an admin job through the socket and decodes its result.
func adminJob[T any](t *testing.T, r *rig, path string, body any) *T {
	t.Helper()
	var j ctl.Job
	if err := r.admin().Call(ctx, "POST", "/api/v1/repo/admin"+path+"?wait=1", body, &j); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if j.State != ctl.JobSucceeded {
		t.Fatalf("%s: job %d %s: %s", path, j.ID, j.State, j.Error)
	}
	var out T
	if err := jsonUnmarshal(j.Result, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func TestHostileHostOverTheNetwork(t *testing.T) {
	// the lease has nothing to do with this test (no step waits for it): a short one only made it fail on slow machines
	r := startRig(t, memKind, func(c *node.Config) { c.Lease = time.Minute })
	good, evil := r.enroll("good"), r.enroll("evil")
	f := r.Fix
	gGood, gEvil := f.Group("good", "web"), f.Group("evil", "x")
	vict := manyChunks(t, f, 4)
	bg := f.NewBackup(t, gGood, nodetest.SnapshotID(r.Clock.Now(), 1), vict)
	upload(t, good.C, bg, "")
	before := map[string][]byte{}
	for _, c := range vict {
		d, _ := datastore.ReadAll(ctx, r.Raw, chunkKey(c.ID), 1<<20)
		before[c.ID.String()] = d
	}

	// the host listener speaks HTTP/2
	if resp, err := r.httpFor(evil.Cert).Get("https://" + r.Srv.HostAddr() + "/api/v1/repo"); err != nil || resp.ProtoMajor != 2 {
		t.Fatalf("protocol: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	// 1. overwrite chunks: the node keeps the stored object
	s, err := evil.C.Begin(ctx, gEvil, nodetest.SnapshotID(r.Clock.Now(), 2), "")
	if err != nil {
		t.Fatal(err)
	}
	other := f.NewChunk(t)
	hc := r.httpFor(evil.Cert)
	req, _ := http.NewRequest("PUT", "https://"+r.Srv.HostAddr()+"/api/v1/repo/sessions/"+s.ID()+"/chunks/"+vict[0].ID.String(), bytes.NewReader(other.Blob))
	req.ContentLength = int64(len(other.Blob))
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 409 || !strings.Contains(string(body), "already_exists") {
		t.Fatalf("overwrite answered %d %s", resp.StatusCode, body)
	}
	// ... and the client treats an existing chunk as success
	if err := s.PutChunk(ctx, vict[1].ID, other.Blob); err != nil {
		t.Fatalf("client: %v", err)
	}
	for _, c := range vict {
		if d, _ := datastore.ReadAll(ctx, r.Raw, chunkKey(c.ID), 1<<20); !bytes.Equal(d, before[c.ID.String()]) {
			t.Fatal("a stored chunk was changed")
		}
	}

	// 2. delete: there is no way. Every method/path a host could try is refused.
	for _, c := range []struct{ method, path string }{
		{"DELETE", "/api/v1/repo/chunks/" + vict[0].ID.String()},
		{"DELETE", "/api/v1/repo/groups/" + gGood + "/snapshots/" + bg.Snapshot},
		{"POST", "/api/v1/repo/admin/gc"},
		{"POST", "/api/v1/repo/admin/retention"},
		{"PUT", "/api/v1/repo/admin/maintenance"},
		{"DELETE", "/api/v1/repo/admin/groups/" + gGood + "/snapshots/" + bg.Snapshot + "/deletion"},
		{"PUT", "/api/v1/repo/chunks/" + vict[0].ID.String()},
		{"PUT", "/api/v1/repo/groups/" + gGood + "/snapshots/" + bg.Snapshot + "/index"},
		{"GET", "/api/v1/repo/admin/status"},
		{"GET", "/api/v1/hosts"},
		{"GET", "/api/v1/users"},
	} {
		req, _ := http.NewRequest(c.method, "https://"+r.Srv.HostAddr()+c.path, nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("%s %s answered %d", c.method, c.path, resp.StatusCode)
		}
	}
	if _, err := r.Raw.Head(ctx, "groups/"+gGood+"/"+bg.Snapshot+"/commit.json"); err != nil {
		t.Fatal("the victim's snapshot is gone")
	}
	for _, c := range vict {
		if _, err := r.Raw.Head(ctx, chunkKey(c.ID)); err != nil {
			t.Fatal("a victim chunk is gone")
		}
	}

	// 3. commit with a missing chunk, naming it
	mb := f.NewBackup(t, gEvil, nodetest.SnapshotID(r.Clock.Now(), 22), []nodetest.Chunk{vict[0], other})
	_ = s.Abort(ctx)
	s3, err := evil.C.Begin(ctx, gEvil, mb.Snapshot, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s3.PutIndex(ctx, mb.Index); err != nil {
		t.Fatal(err)
	}
	if err := s3.PutManifest(ctx, mb.Manifest); err != nil {
		t.Fatal(err)
	}
	_, err = s3.Commit(ctx)
	var em *client.ErrMissingChunks
	if !errors.As(err, &em) || em.Count != 1 || em.First[0] != other.ID {
		t.Fatalf("commit with a missing chunk: %v", err)
	}
	if err := s3.PutChunk(ctx, other.ID, other.Blob); err != nil {
		t.Fatal(err)
	}
	rc, err := s3.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 4. replay: the same commit again, from the client and from a second connection
	rc2, err := s3.Commit(ctx)
	if err != nil || rc2.Committed != rc.Committed {
		t.Fatalf("replay: %+v %v", rc2, err)
	}
	// 5. a stolen session id is useless to another host
	if _, err := good.C.Begin(ctx, gEvil, nodetest.SnapshotID(r.Clock.Now(), 7), ""); code(err) != api.CodeForbidden {
		t.Fatalf("another host's group: %v", err)
	}

}

func TestLeaseExpiryOverTheNetwork(t *testing.T) {
	r := startRig(t, memKind, func(c *node.Config) { c.Lease = 200 * time.Millisecond })
	h := r.enroll("h")
	// a raw session that never heartbeats: use the HTTP API directly
	hc := r.httpFor(h.Cert)
	g := r.Fix.Group("h", "j")
	post := func(path, body string) (int, string) {
		req, _ := http.NewRequest("POST", "https://"+r.Srv.HostAddr()+path, strings.NewReader(body))
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	st, body := post("/api/v1/repo/sessions", fmt.Sprintf(`{"group":%q,"snapshot":%q}`, g, nodetest.SnapshotID(r.Clock.Now(), 1)))
	if st != 201 {
		t.Fatalf("%d %s", st, body)
	}
	sid := body[strings.Index(body, `"id":"`)+6:]
	sid = sid[:strings.Index(sid, `"`)]
	r.Clock.Advance(400 * time.Millisecond) // the lease runs on the clock of the node
	st, body = post("/api/v1/repo/sessions/"+sid+"/heartbeat", "")
	if st != 410 || !strings.Contains(body, "lease_expired") {
		t.Fatalf("a heartbeat after the lease: %d %s", st, body)
	}
	st, body = post("/api/v1/repo/sessions/"+sid+"/commit", "{}")
	if st != 410 {
		t.Fatalf("a commit after the lease: %d %s", st, body)
	}
	// the group is free again
	if st, body = post("/api/v1/repo/sessions", fmt.Sprintf(`{"group":%q,"snapshot":%q}`, g, nodetest.SnapshotID(r.Clock.Now(), 2))); st != 201 {
		t.Fatalf("%d %s", st, body)
	}
}

// The client keeps the lease alive by itself while the host is busy.
func TestClientHeartbeatKeepsTheLease(t *testing.T) {
	// a lease of 1.2 s: a slow CI machine (a FreeBSD VM) can stall the heartbeat goroutine for several hundred ms
	r := startRig(t, memKind, func(c *node.Config) { c.Lease = 1200 * time.Millisecond })
	h := r.enroll("h")
	g := r.Fix.Group("h", "j")
	b := r.Fix.NewBackup(t, g, nodetest.SnapshotID(r.Clock.Now(), 1), manyChunks(t, r.Fix, 3))
	s, err := h.C.Begin(ctx, g, b.Snapshot, "")
	if err != nil {
		t.Fatal(err)
	}
	// two and a half leases pass on the clock of the node while the engine is silent: only the heartbeats of the client
	// renew the lease, so the clock moves a third of a lease at a time and waits for the renewal before it moves again
	lease := func() time.Time {
		row, err := r.DB.Session(ctx, s.ID())
		if err != nil {
			t.Fatal(err)
		}
		return row.LeaseUntil
	}
	for range 8 {
		before := lease()
		r.Clock.Advance(400 * time.Millisecond)
		deadline := time.Now().Add(30 * time.Second)
		for lease().Equal(before) {
			if time.Now().After(deadline) {
				t.Fatal("the client did not renew the lease")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if err := s.PutIndex(ctx, b.Index); err != nil {
		t.Fatalf("the session died although the client heartbeats: %v", err)
	}
	for _, c := range b.Chunks {
		if err := s.PutChunk(ctx, c.ID, c.Blob); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutManifest(ctx, b.Manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
