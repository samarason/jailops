package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/sdk/api"
)

// Host identifies the enrolled host a request comes from.
type Host struct {
	ID     string
	Name   string
	Scopes []string
}

// session is the in-memory half of a session lease: the buffers of the index
// and the manifest (nothing of the snapshot is written to the repository
// before the commit) and the pins on chunks. The lease itself is a row in the
// control plane.
type session struct {
	id, group, snap, host string

	// commitMu is held while a commit writes, and taken first by abort: an
	// abort waits for the writes, and a commit that starts after the abort
	// sees closed and writes nothing.
	commitMu sync.Mutex

	mu       sync.Mutex
	pins     map[uint64]struct{}
	index    []byte
	idx      *format.Index
	manifest []byte
	closed   bool
	receipt  []byte // set once committed
}

// SessionInfo is what a host learns when it opens a session.
type SessionInfo = wire.SessionInfo

// Begin opens the one session of a group.
func (n *Node) Begin(ctx context.Context, h Host, group, snapshot, previous string) (*SessionInfo, error) {
	return n.BeginWith(ctx, h, wire.BeginRequest{Group: group, Snapshot: snapshot, Previous: previous})
}

// BeginWith is Begin with the whole request, including the key domain of the host.
func (n *Node) BeginWith(ctx context.Context, h Host, req wire.BeginRequest) (*SessionInfo, error) {
	group, snapshot, previous := req.Group, req.Snapshot, req.Previous
	if err := n.requireOnline(); err != nil {
		return nil, err
	}
	if d := n.keyDomain(); d != "" && req.KeyDomain != d {
		return nil, errf(api.CodeForbidden, "the repository belongs to key domain %s; the host's key is %q", d, req.KeyDomain)
	}
	if req.KeyDomain != "" && !format.ValidDomainID(req.KeyDomain) {
		return nil, errf(api.CodeInvalid, "malformed key domain id")
	}
	if !format.ValidGroupID(group) {
		return nil, errf(api.CodeInvalid, "malformed group id")
	}
	if !format.ValidSnapshotID(snapshot) {
		return nil, errf(api.CodeInvalid, "malformed snapshot id")
	}
	if t, err := format.SnapshotIDTime(snapshot); err != nil || t.After(n.now().Add(MaxClockSkew)) {
		return nil, errf(api.CodeInvalid, "the snapshot id is dated in the future: check the host clock")
	}
	if previous != "" && !format.ValidSnapshotID(previous) {
		return nil, errf(api.CodeInvalid, "malformed previous snapshot id")
	}
	if req.KeyDomain != "" {
		// The first host that backs up binds a repository that records no domain yet, as the first escrow does:
		// from then on a host with another key is refused before it can store a chunk.
		if err := n.bindDomain(ctx, req.KeyDomain); err != nil {
			return nil, err
		}
	}
	n.pinMu.Lock()
	open := len(n.sessions)
	n.pinMu.Unlock()
	if open >= n.cfg.MaxOpenSessions {
		return nil, errf(api.CodeBusy, "the node has too many open sessions").WithHint("retry later")
	}
	if _, err := n.be.Head(ctx, snapPrefix(group, snapshot)+fileCommit); err == nil {
		return nil, errf(api.CodeAlreadyExists, "snapshot %s is already committed", snapshot)
	} else if !errors.Is(err, datastore.ErrNotFound) {
		return nil, asAPIError(err)
	}
	if previous != "" {
		if _, err := n.be.Head(ctx, snapPrefix(group, previous)+fileCommit); errors.Is(err, datastore.ErrNotFound) {
			previous = ""
		} else if err != nil {
			return nil, asAPIError(err)
		}
	}
	if err := n.claimGroupMarker(ctx, group, h); err != nil {
		return nil, err
	}
	if err := n.db.ClaimGroup(ctx, group, h.ID); err != nil {
		if errors.Is(err, ctl.ErrGroupOwned) {
			return nil, errf(api.CodeForbidden, "the group belongs to another host")
		}
		return nil, err
	}
	row, err := n.db.OpenSession(ctx, group, h.ID, snapshot, previous, n.cfg.Lease)
	if err != nil {
		if errors.Is(err, ctl.ErrConflict) {
			return nil, errf(api.CodeBusy, "the jail already has an open backup session").WithHint("wait for it to finish or for its lease to expire")
		}
		return nil, err
	}
	s := &session{id: row.ID, group: group, snap: snapshot, host: h.ID, pins: map[uint64]struct{}{}}
	n.pinMu.Lock()
	n.sessions[row.ID] = s
	n.pinMu.Unlock()
	return &SessionInfo{ID: row.ID, Group: group, Snapshot: snapshot, Lease: int(n.cfg.Lease / time.Second), LeaseMs: n.cfg.Lease.Milliseconds(), LeaseUntil: row.LeaseUntil, Previous: previous}, nil
}

// get finds the open session of host. A session of another host is not found.
func (n *Node) get(ctx context.Context, h Host, sid string) (*session, error) {
	n.pinMu.Lock()
	s := n.sessions[sid]
	n.pinMu.Unlock()
	if s == nil || s.host != h.ID {
		return nil, errf(api.CodeLeaseExpired, "no such open session: it expired, was aborted or never existed").WithHint("start a new session")
	}
	return s, nil
}

// touch renews the lease and counts uploads; an expired lease closes the session.
func (n *Node) touch(ctx context.Context, s *session, chunks, bytes int64) error {
	if _, err := n.db.RenewSession(ctx, s.id, n.cfg.Lease, chunks, bytes); err != nil {
		if errors.Is(err, ctl.ErrNotFound) {
			n.closeMem(s)
			return errf(api.CodeLeaseExpired, "the session lease ran out").WithHint("start a new session")
		}
		return err
	}
	return nil
}

func (s *session) pin(ids []format.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errf(api.CodeLeaseExpired, "the session is closed")
	}
	for _, id := range ids {
		if !id.IsZero() {
			s.pins[liveKey(id)] = struct{}{}
		}
	}
	return nil
}

// closeMem ends the in-memory session. While a GC runs, its pins move to the
// shadow set so that a sweep that began earlier still honours them.
func (n *Node) closeMem(s *session) {
	n.pinMu.Lock()
	defer n.pinMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if n.gcActive {
		if n.shadow == nil {
			n.shadow = map[uint64]struct{}{}
		}
		for k := range s.pins {
			n.shadow[k] = struct{}{}
		}
	}
	s.pins = nil
	s.index, s.manifest, s.idx = nil, nil, nil
	delete(n.sessions, s.id)
}

// pinned reports whether an open session relies on the chunk, or a session that
// ended since the running GC started did. The caller holds gcMu for writing.
func (n *Node) pinned(id format.ID) bool {
	key := liveKey(id)
	n.pinMu.Lock()
	defer n.pinMu.Unlock()
	if _, ok := n.shadow[key]; ok {
		return true
	}
	for _, s := range n.sessions {
		s.mu.Lock()
		_, ok := s.pins[key]
		s.mu.Unlock()
		if ok {
			return true
		}
	}
	return false
}

// Heartbeat renews the lease.
func (n *Node) Heartbeat(ctx context.Context, h Host, sid string) (time.Time, error) {
	s, err := n.get(ctx, h, sid)
	if err != nil {
		return time.Time{}, err
	}
	row, err := n.db.RenewSession(ctx, s.id, n.cfg.Lease, 0, 0)
	if err != nil {
		if errors.Is(err, ctl.ErrNotFound) {
			n.closeMem(s)
			return time.Time{}, errf(api.CodeLeaseExpired, "the session lease ran out")
		}
		return time.Time{}, err
	}
	return row.LeaseUntil, nil
}

// Abort closes the session; nothing of the snapshot was written.
func (n *Node) Abort(ctx context.Context, h Host, sid string) error {
	s, err := n.get(ctx, h, sid)
	if err != nil {
		return err
	}
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	n.closeMem(s)
	return n.db.CloseSession(ctx, s.id, ctl.SessionAborted)
}

// Missing returns the ids the repository lacks. The ones it has are pinned for
// the life of the session. Every id is asked of the backend; the node keeps
// no cache that could answer "present" for a chunk deleted behind its back.
func (n *Node) Missing(ctx context.Context, h Host, sid string, ids []format.ID) ([]format.ID, error) {
	if len(ids) > MaxMissingBatch {
		return nil, errf(api.CodeInvalid, "at most %d ids per request", MaxMissingBatch)
	}
	s, err := n.get(ctx, h, sid)
	if err != nil {
		return nil, err
	}
	if err := n.touch(ctx, s, 0, 0); err != nil {
		return nil, err
	}
	n.gcMu.RLock()
	defer n.gcMu.RUnlock()
	uniq := uniqueIDs(ids)
	present := make([]bool, len(uniq))
	err = forEach(ctx, n.cfg.Parallelism, len(uniq), func(i int) error {
		_, err := n.be.Head(ctx, chunkKey(uniq[i]))
		switch {
		case err == nil:
			present[i] = true
		case !errors.Is(err, datastore.ErrNotFound):
			return err
		}
		return nil
	})
	if err != nil {
		return nil, asAPIError(err)
	}
	have := make(map[format.ID]bool, len(uniq))
	var found []format.ID
	for i, id := range uniq {
		have[id] = present[i]
		if present[i] {
			found = append(found, id)
		}
	}
	if err := s.pin(found); err != nil {
		return nil, err
	}
	var missing []format.ID
	seen := map[format.ID]bool{}
	for _, id := range ids {
		if !id.IsZero() && !have[id] && !seen[id] {
			seen[id] = true
			missing = append(missing, id)
		}
	}
	return missing, nil
}

// PutChunkResult says what a chunk upload did.
type PutChunkResult = wire.PutChunkResult

// PutChunk stores a chunk blob create-only. It verifies the size and the
// SHA-256 trailer, which needs no key. If the chunk exists already the stored
// object is never touched: an upload with the same bytes is a success, an
// upload with other bytes is refused with CodeAlreadyExists (the chunk is
// present either way and the session pins it, so the client treats that as
// success too).
func (n *Node) PutChunk(ctx context.Context, h Host, sid string, id format.ID, r io.Reader, size int64) (*PutChunkResult, error) {
	if id.IsZero() {
		return nil, errf(api.CodeInvalid, "the zero chunk id has no blob")
	}
	if size < 0 || size > format.MaxBlobSize {
		return nil, errf(api.CodeInvalid, "the blob must be between 0 and %d bytes", format.MaxBlobSize)
	}
	s, err := n.get(ctx, h, sid)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, size)
	if _, err := io.ReadFull(r, blob); err != nil {
		return nil, errf(api.CodeInvalid, "the body is shorter than its declared size")
	}
	var one [1]byte
	if m, _ := r.Read(one[:]); m > 0 {
		return nil, errf(api.CodeInvalid, "the body is longer than its declared size")
	}
	if err := format.VerifyBlob(blob); err != nil {
		return nil, errf(api.CodeInvalid, "rejecting blob %s: %v", id, err)
	}
	if err := n.touch(ctx, s, 0, 0); err != nil {
		return nil, err
	}
	n.gcMu.RLock()
	defer n.gcMu.RUnlock()
	key := chunkKey(id)
	err = n.be.Put(ctx, key, bytes.NewReader(blob), size, datastore.PutOptions{IfAbsent: true})
	switch {
	case err == nil:
		if perr := s.pin([]format.ID{id}); perr != nil {
			return nil, perr
		}
		_, _ = n.db.RenewSession(ctx, s.id, n.cfg.Lease, 1, size)
		return &PutChunkResult{Created: true}, nil
	case errors.Is(err, datastore.ErrExists):
		if perr := s.pin([]format.ID{id}); perr != nil {
			return nil, perr
		}
		same, serr := n.sameTrailer(ctx, key, blob)
		if serr != nil {
			return nil, asAPIError(serr)
		}
		if !same {
			return nil, errf(api.CodeAlreadyExists, "chunk %s exists with other bytes; the stored object was kept", id).WithDetail("chunk", id.String())
		}
		return &PutChunkResult{Created: false}, nil
	}
	return nil, asAPIError(err)
}

// sameTrailer compares the SHA-256 trailer of the stored object with the one of
// blob: identical blobs have identical trailers, and the trailer is the last 32
// bytes, so this takes one small range read.
func (n *Node) sameTrailer(ctx context.Context, key string, blob []byte) (bool, error) {
	info, err := n.be.Head(ctx, key)
	if err != nil {
		if errors.Is(err, datastore.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if info.Size != int64(len(blob)) {
		return false, nil
	}
	rc, err := n.be.GetRange(ctx, key, info.Size-32, 32)
	if err != nil {
		return false, err
	}
	defer rc.Close()
	var tr [32]byte
	if _, err := io.ReadFull(rc, tr[:]); err != nil {
		return false, err
	}
	return bytes.Equal(tr[:], blob[len(blob)-32:]), nil
}

// PutIndex checks and keeps the index of the snapshot until the commit.
func (n *Node) PutIndex(ctx context.Context, h Host, sid string, r io.Reader, size int64) (digest string, chunks int, err error) {
	s, err := n.get(ctx, h, sid)
	if err != nil {
		return "", 0, err
	}
	b, err := readBounded(r, size, format.MaxIndexSize)
	if err != nil {
		return "", 0, err
	}
	idx, perr := format.ParseIndex(b)
	if perr != nil {
		return "", 0, errf(api.CodeInvalid, "rejecting the index: %v", perr)
	}
	if err := n.touch(ctx, s, 0, 0); err != nil {
		return "", 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", 0, errf(api.CodeLeaseExpired, "the session is closed")
	}
	s.index, s.idx = b, idx
	return format.FileDigest(b), len(idx.ChunkIDs()), nil
}

// PutManifest checks the manifest's trailer (it is encrypted; nothing else can
// be checked) and keeps it until the commit.
func (n *Node) PutManifest(ctx context.Context, h Host, sid string, r io.Reader, size int64) (string, error) {
	s, err := n.get(ctx, h, sid)
	if err != nil {
		return "", err
	}
	b, err := readBounded(r, size, format.MaxManifestSize)
	if err != nil {
		return "", err
	}
	if verr := format.VerifyManifestBlob(b); verr != nil {
		return "", errf(api.CodeInvalid, "rejecting the manifest: %v", verr)
	}
	if err := n.touch(ctx, s, 0, 0); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", errf(api.CodeLeaseExpired, "the session is closed")
	}
	s.manifest = b
	return format.FileDigest(b), nil
}

func readBounded(r io.Reader, size, limit int64) ([]byte, error) {
	if size < 0 || size > limit {
		return nil, errf(api.CodeInvalid, "the body must be between 0 and %d bytes", limit)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, errf(api.CodeInvalid, "the body is shorter than its declared size")
	}
	var one [1]byte
	if m, _ := r.Read(one[:]); m > 0 {
		return nil, errf(api.CodeInvalid, "the body is longer than its declared size")
	}
	return b, nil
}

// CommitRequest carries the digests the host computed of what it uploaded.
type CommitRequest = wire.CommitRequest

// Commit makes the snapshot visible.
//
// Order: pin every chunk of the index, HEAD every distinct chunk on the
// backend itself (never from a cache), then write the index, the manifest and,
// last and create-only, commit.json. A retried commit is a success when the
// snapshot is committed with the same digests.
func (n *Node) Commit(ctx context.Context, h Host, sid string, req CommitRequest) (*format.Receipt, error) {
	s, err := n.get(ctx, h, sid)
	if err != nil {
		return n.commitRetry(ctx, h, sid, req)
	}
	if err := n.requireOnline(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	index, manifest, idx := s.index, s.manifest, s.idx
	s.mu.Unlock()
	if index == nil || manifest == nil {
		return nil, errf(api.CodeInvalid, "the index and the manifest must be uploaded before the commit")
	}
	idxDigest, manDigest := format.FileDigest(index), format.FileDigest(manifest)
	if req.IndexDigest != "" && req.IndexDigest != idxDigest || req.ManifestDigest != "" && req.ManifestDigest != manDigest {
		return nil, errf(api.CodeInvalid, "the uploaded index or manifest differs from what the host sent: upload them again")
	}
	if err := n.touch(ctx, s, 0, 0); err != nil {
		return nil, err
	}
	ids := idx.ChunkIDs()
	// 1. PIN every chunk before looking at any of them. From here until the session closes no GC
	// sweeps them; a GC that checked earlier is caught by step 2 (the chunk is gone, the commit refused).
	n.gcMu.RLock()
	err = s.pin(ids)
	n.gcMu.RUnlock()
	if err != nil {
		return nil, err
	}
	// 2. every chunk must exist, asked of the backend, in parallel, without holding a lock.
	present := make([]bool, len(ids))
	err = forEach(ctx, 2*n.cfg.Parallelism, len(ids), func(i int) error {
		_, err := n.be.Head(ctx, chunkKey(ids[i]))
		switch {
		case err == nil:
			present[i] = true
		case !errors.Is(err, datastore.ErrNotFound):
			return err
		}
		return nil
	})
	if err != nil {
		return nil, asAPIError(err)
	}
	var missing []string
	for i, id := range ids {
		if !present[i] {
			missing = append(missing, id.String())
		}
	}
	if len(missing) > 0 {
		_ = n.touch(ctx, s, 0, 0)
		e := errf(api.CodeMissingChunks, "%d chunk(s) the index references are missing from the repository", len(missing)).
			WithHint("upload them and commit again")
		e = e.WithDetail("count", fmt.Sprint(len(missing))).WithDetail("first", strings.Join(missing[:min(len(missing), 20)], ","))
		return nil, e
	}
	// 3. write, under the snapshot lock and the session's commit lock.
	prefix := snapPrefix(s.group, s.snap)
	l := n.snapLock(s.group, s.snap)
	l.Lock()
	defer l.Unlock()
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, errf(api.CodeLeaseExpired, "the session was aborted")
	}
	if rc, rerr := n.readReceipt(ctx, prefix); rerr == nil {
		if rc.IndexDigest == idxDigest && rc.ManifestDigest == manDigest {
			return n.finishCommitted(ctx, s, rc, nil)
		}
		return nil, errf(api.CodeAlreadyExists, "snapshot %s is already committed with other content", s.snap)
	} else if !errors.Is(rerr, datastore.ErrNotFound) {
		return nil, asAPIError(rerr)
	}
	// index and manifest may overwrite debris of an earlier failed attempt: without a receipt they are not visible
	if err := datastore.PutBytes(ctx, n.be, prefix+fileIndex, index, datastore.PutOptions{}); err != nil {
		return nil, asAPIError(err)
	}
	if err := datastore.PutBytes(ctx, n.be, prefix+fileManif, manifest, datastore.PutOptions{}); err != nil {
		return nil, asAPIError(err)
	}
	rc := &format.Receipt{Format: 1, Committed: n.now().UTC().Truncate(time.Microsecond), ChunkCount: len(ids), IndexBytes: len(index),
		IndexDigest: idxDigest, ManifestDigest: manDigest, Source: "client"}
	rb, err := rc.Marshal()
	if err != nil {
		return nil, err
	}
	if err := datastore.PutBytes(ctx, n.be, prefix+fileCommit, rb, datastore.PutOptions{IfAbsent: true}); err != nil {
		if !errors.Is(err, datastore.ErrExists) {
			return nil, asAPIError(err)
		}
		// someone wrote a receipt between our check and our write
		cur, rerr := n.readReceipt(ctx, prefix)
		if rerr != nil || cur.IndexDigest != idxDigest || cur.ManifestDigest != manDigest {
			return nil, errf(api.CodeAlreadyExists, "snapshot %s is already committed with other content", s.snap)
		}
		rc, rb = cur, nil
	}
	return n.finishCommitted(ctx, s, rc, rb)
}

func (n *Node) finishCommitted(ctx context.Context, s *session, rc *format.Receipt, raw []byte) (*format.Receipt, error) {
	snap := ctl.Snapshot{GroupID: s.group, SnapshotID: s.snap, CommittedAt: rc.Committed, ChunkCount: rc.ChunkCount, IndexBytes: rc.IndexBytes,
		IndexDigest: rc.IndexDigest, ManifestDigest: rc.ManifestDigest, Source: rc.Source}
	if err := n.db.UpsertSnapshot(context.WithoutCancel(ctx), snap); err != nil {
		// the snapshot IS committed (commit.json exists); reconcile repairs the index row
		return rc, nil
	}
	_ = n.db.CloseSession(context.WithoutCancel(ctx), s.id, ctl.SessionCommitted)
	n.closeMem(s)
	n.remember(s, rc)
	return rc, nil
}

// remember keeps the receipt of a committed session for retries whose answer was lost.
func (n *Node) remember(s *session, rc *format.Receipt) {
	n.recentMu.Lock()
	defer n.recentMu.Unlock()
	if n.recent == nil {
		n.recent = map[string]recentCommit{}
	}
	now := n.now()
	for k, v := range n.recent {
		if now.After(v.until) {
			delete(n.recent, k)
		}
	}
	n.recent[s.id] = recentCommit{host: s.host, rc: rc, until: now.Add(2 * n.cfg.Lease)}
}

type recentCommit struct {
	host  string
	rc    *format.Receipt
	until time.Time
}

// commitRetry answers a commit for a session that is no longer open: success if
// it was committed (with the digests the host names), an error otherwise.
func (n *Node) commitRetry(ctx context.Context, h Host, sid string, req CommitRequest) (*format.Receipt, error) {
	n.recentMu.Lock()
	rec, ok := n.recent[sid]
	n.recentMu.Unlock()
	if ok && rec.host == h.ID {
		if (req.IndexDigest == "" || req.IndexDigest == rec.rc.IndexDigest) && (req.ManifestDigest == "" || req.ManifestDigest == rec.rc.ManifestDigest) {
			return rec.rc, nil
		}
		return nil, errf(api.CodeInvalid, "the session committed other content")
	}
	row, err := n.db.Session(ctx, sid)
	if err != nil || row.HostID != h.ID || row.State != ctl.SessionCommitted {
		return nil, errf(api.CodeLeaseExpired, "no such open session: it expired, was aborted or never existed").WithHint("start a new session")
	}
	// committed by an earlier process: the receipt in the repository decides
	rc, err := n.readReceipt(ctx, snapPrefix(row.GroupID, row.SnapshotID))
	if err != nil {
		return nil, asAPIError(err)
	}
	if req.IndexDigest == "" || req.ManifestDigest == "" || req.IndexDigest != rc.IndexDigest || req.ManifestDigest != rc.ManifestDigest {
		return nil, errf(api.CodeInvalid, "the session committed other content")
	}
	return rc, nil
}

func (n *Node) readReceipt(ctx context.Context, prefix string) (*format.Receipt, error) {
	b, err := datastore.ReadAll(ctx, n.be, prefix+fileCommit, 64<<10)
	if err != nil {
		return nil, err
	}
	return format.ParseReceipt(b)
}

// Sweep closes sessions whose lease ran out: the row in the control plane and
// the in-memory buffers and pins. Without it the pins of an abandoned session
// would keep its chunks from garbage collection until the process restarts.
// The scheduler calls it every half minute, and GC calls it before it starts.
func (n *Node) Sweep(ctx context.Context) (int, error) {
	if _, err := n.db.ExpireSessions(ctx); err != nil {
		return 0, err
	}
	open, err := n.db.OpenSessions(ctx)
	if err != nil {
		return 0, err
	}
	live := make(map[string]bool, len(open))
	for _, s := range open {
		live[s.ID] = true
	}
	n.pinMu.Lock()
	var stale []*session
	for id, s := range n.sessions {
		if !live[id] {
			stale = append(stale, s)
		}
	}
	n.pinMu.Unlock()
	for _, s := range stale {
		n.closeMem(s)
	}
	return len(stale), nil
}

// GroupOwner is groups/<group>/owner.json: which enrolled host (by its name,
// which survives a certificate renewal) owns a group. It lives in the
// repository, so the ownership survives the loss of the control plane: after a
// reconcile only the host that made the group can write to it again.
type GroupOwner struct {
	Host  string    `json:"host"`
	Since time.Time `json:"since"`
}

func groupOwnerKey(group string) string { return groupsDir + group + "/owner.json" }

// claimGroupMarker creates the owner marker of a new group, or checks the marker
// of an existing one against the host.
func (n *Node) claimGroupMarker(ctx context.Context, group string, h Host) error {
	for range 3 {
		var o GroupOwner
		err := readJSON(ctx, n.be, groupOwnerKey(group), &o)
		switch {
		case err == nil:
			if o.Host != h.Name {
				return errf(api.CodeForbidden, "the group belongs to another host")
			}
			return nil
		case !errors.Is(err, datastore.ErrNotFound):
			return asAPIError(err)
		}
		err = putJSON(ctx, n.be, groupOwnerKey(group), GroupOwner{Host: h.Name, Since: n.now().UTC().Truncate(time.Second)}, true)
		if err == nil {
			return nil
		}
		if !errors.Is(err, datastore.ErrExists) {
			return asAPIError(err)
		}
	}
	return errf(api.CodeBusy, "the group is being claimed by another host")
}
