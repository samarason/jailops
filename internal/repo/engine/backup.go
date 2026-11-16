package engine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"jailops.net/jailops/internal/repo/catalog"
	"jailops.net/jailops/internal/repo/chunker"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/internal/repo/keys"
	"jailops.net/jailops/internal/repo/store"
)

// errReusedMissing: a chunk the incremental run reused is gone from the
// repository (pruned, quarantined or never there). The run is repeated reading
// every file; deduplication keeps the upload small and the repository heals.
var errReusedMissing = errors.New("a reused chunk is missing from the repository")

type run struct {
	o         BackupOptions
	keys      *format.Keys
	group     string
	snapshot  string
	created   time.Time
	workers   int
	window    int
	fullEvery time.Duration
	now       func() time.Time
	open      func(string) (io.ReadCloser, error)
}

// Backup backs up the streams of one jail into a new snapshot and returns what
// was committed. See BackupOptions.
func Backup(ctx context.Context, o BackupOptions) (*BackupResult, error) {
	start := time.Now()
	if o.Key == nil {
		return nil, ErrNoKey
	}
	if o.Repo == nil || o.NewUploader == nil {
		return nil, errors.New("engine: Repo and NewUploader are required")
	}
	if len(o.Streams) == 0 {
		return nil, errors.New("engine: no streams to back up")
	}
	seen := map[string]bool{}
	for _, s := range o.Streams {
		if s.Name == "" || s.Root == "" || seen[s.Name] {
			return nil, fmt.Errorf("engine: stream %q needs a unique name and a root", s.Name)
		}
		seen[s.Name] = true
	}
	r := &run{o: o, keys: o.Key.Keys, workers: o.Workers, window: o.Window, fullEvery: o.FullEvery, now: o.Now, open: o.OpenFile}
	if r.workers <= 0 {
		r.workers = DefaultWorkers
	}
	if r.window <= 0 {
		r.window = DefaultWindow
	}
	if r.fullEvery <= 0 {
		r.fullEvery = DefaultFullEvery
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.open == nil {
		r.open = func(p string) (io.ReadCloser, error) { return os.Open(p) }
	}
	res := &BackupResult{}

	// the key and its escrow, before a first byte is read
	status, err := keys.StatusOf(ctx, o.Key, o.Escrow)
	if err != nil {
		return nil, fmt.Errorf("checking the key escrow: %w", err)
	}
	res.KeyStatus = status
	if status != keys.StatusEscrowed {
		if o.RequireEscrow {
			return nil, ErrNotEscrowed
		}
		res.Warnings = append(res.Warnings, "the master key is not escrowed: losing this host and the recovery key loses every backup")
	}
	if d := o.Repo.KeyDomain(); d != "" && d != o.Key.DomainID() {
		return nil, fmt.Errorf("%w: the repository belongs to key domain %s, the key is %s", ErrWrongKey, d, o.Key.DomainID())
	}

	r.group = r.keys.GroupID(o.Host, o.Jail)
	r.created = r.now().UTC()
	r.snapshot, err = format.NewSnapshotID(r.created, nil)
	if err != nil {
		return nil, err
	}
	baseSnap, why, err := r.chooseBase(ctx)
	if err != nil {
		return nil, err
	}
	previous := ""
	if baseSnap != nil {
		previous = baseSnap.ID
	}
	up, err := o.NewUploader(ctx, r.group, r.snapshot, previous)
	if err != nil {
		return nil, err
	}
	defer up.Close()

	forceFull := o.ForceFull
	reason := why
	var out *attemptOut
	for attempt := 0; ; attempt++ {
		out, err = r.attempt(ctx, up, baseSnap, reason, forceFull)
		if err == nil {
			var rc *format.Receipt
			rc, err = up.Commit(ctx)
			if err == nil {
				out.receipt = rc
				break
			}
			if errors.Is(err, store.ErrMissingChunks) {
				err = fmt.Errorf("%w: %v", errReusedMissing, err)
			}
		}
		if errors.Is(err, errReusedMissing) && !forceFull && attempt == 0 {
			res.Warnings = append(res.Warnings, "a chunk reused from the previous snapshot is missing from the repository; every file was read again")
			forceFull, reason = true, "a reused chunk was missing from the repository"
			continue
		}
		return nil, err
	}
	res.Group, res.Snapshot, res.Previous, res.Receipt = r.group, r.snapshot, previous, out.receipt
	res.Streams = out.streams
	for _, s := range out.streams {
		res.LogicalBytes += s.LogicalBytes
		res.ReadBytes += s.ReadBytes
		res.ReusedBytes += s.ReusedBytes
		res.UploadedBytes += s.UploadedBytes
		res.NewChunks += s.NewChunks
		res.Full = res.Full || s.Mode == "full"
	}
	res.Duration = time.Since(start)
	return res, nil
}

type attemptOut struct {
	streams []StreamResult
	receipt *format.Receipt
}

// attempt scans and uploads everything and writes index and manifest (not the
// commit).
func (r *run) attempt(ctx context.Context, up Uploader, baseSnap *Snapshot, reason string, forceFull bool) (*attemptOut, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pl := newPipeline(ctx, cancel, r.keys, up, r.workers, r.window)
	finished := false
	defer func() {
		if !finished {
			cancel()
			_ = pl.finish()
		}
	}()

	var all []slot
	var reusedIDs []format.ID
	var cts []*counters
	out := &attemptOut{}
	man := &format.Manifest{
		SnapshotID: r.snapshot, Created: r.created, Host: r.o.Host, Jail: r.o.Jail, JailName: r.o.JailName,
		Policy: r.o.Policy, Bundle: r.o.Bundle, Meta: r.o.Meta,
	}
	if baseSnap != nil {
		man.PreviousID = baseSnap.ID
	}
	var offset uint64
	for _, st := range r.o.Streams {
		ct := &counters{}
		sr, slots, ms, reused, err := r.streamOpened(ctx, pl, baseSnap, st, offset, reason, forceFull, ct)
		if err != nil {
			return nil, err
		}
		cts = append(cts, ct)
		all = append(all, slots...)
		reusedIDs = append(reusedIDs, reused...)
		offset = ms.Offset + ms.PayloadSize + ms.CatalogSize
		sr.Name = st.Name
		man.Streams = append(man.Streams, ms)
		out.streams = append(out.streams, sr)
	}
	finished = true
	if err := pl.finish(); err != nil {
		return nil, err
	}
	// every chunk of a reused run must still exist
	if err := r.checkReused(ctx, up, reusedIDs); err != nil {
		return nil, err
	}
	idx := &format.Index{Size: offset}
	var end uint64
	for i := range all {
		end += all[i].size
		idx.Entries = append(idx.Entries, format.Entry{End: end, ID: all[i].resolve()})
	}
	if end != offset {
		return nil, fmt.Errorf("engine: internal error: the index covers %d bytes, the streams %d", end, offset)
	}
	for i, ct := range cts {
		out.streams[i].UploadedBytes, out.streams[i].NewChunks = ct.uploadedBytes.Load(), int(ct.newChunks.Load())
	}
	for i := range man.Streams {
		man.Streams[i].Stats = format.Stats{LogicalBytes: out.streams[i].LogicalBytes, ReadBytes: out.streams[i].ReadBytes,
			ReusedBytes: out.streams[i].ReusedBytes, UploadedBytes: out.streams[i].UploadedBytes, NewChunks: out.streams[i].NewChunks,
			Files: out.streams[i].Files, FullRead: out.streams[i].Mode == "full"}
		man.Stats.LogicalBytes += man.Streams[i].Stats.LogicalBytes
		man.Stats.ReadBytes += man.Streams[i].Stats.ReadBytes
		man.Stats.ReusedBytes += man.Streams[i].Stats.ReusedBytes
		man.Stats.UploadedBytes += man.Streams[i].Stats.UploadedBytes
		man.Stats.NewChunks += man.Streams[i].Stats.NewChunks
		man.Stats.Files += man.Streams[i].Stats.Files
		if out.streams[i].Mode == "full" {
			man.Stats.FullRead = true
		}
	}
	man.Stats.DurationMs = r.now().Sub(r.created).Milliseconds()
	ib, err := idx.Marshal()
	if err != nil {
		return nil, err
	}
	man.IndexDigest = format.FileDigest(ib)
	mb, err := r.keys.SealManifest(man, r.group, nil)
	if err != nil {
		return nil, err
	}
	if err := up.PutIndex(ctx, ib); err != nil {
		return nil, err
	}
	if err := up.PutManifest(ctx, mb); err != nil {
		return nil, err
	}
	return out, nil
}

// streamOpened is stream with the stream's own reader opened for it and closed again as soon as it has been read: every
// file of the stream is read inside r.stream, what is left for the pipeline is chunks in memory.
func (r *run) streamOpened(ctx context.Context, pl *pipeline, baseSnap *Snapshot, st Stream, offset uint64, reason string, forceFull bool, ct *counters) (sr StreamResult, slots []slot, ms format.Stream, reused []format.ID, err error) {
	if st.OpenFS != nil {
		fsys, closeFS, err := st.OpenFS(ctx)
		if err != nil {
			return sr, nil, ms, nil, fmt.Errorf("opening %s: %w", st.Name, err)
		}
		if closeFS != nil {
			defer closeFS()
		}
		st.FS = fsys
	}
	return r.stream(ctx, pl, baseSnap, st, offset, reason, forceFull, ct)
}

// checkReused asks the repository about every distinct reused chunk, in batches,
// which also pins them for the snapshot.
func (r *run) checkReused(ctx context.Context, up Uploader, ids []format.ID) error {
	seen := make(map[format.ID]struct{}, len(ids))
	var batch []format.ID
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		miss, err := up.Missing(ctx, batch)
		if err != nil {
			return err
		}
		if len(miss) > 0 {
			return fmt.Errorf("%w (%d chunks, first %s)", errReusedMissing, len(miss), miss[0])
		}
		batch = batch[:0]
		return nil
	}
	for _, id := range ids {
		if id.IsZero() {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		batch = append(batch, id)
		if len(batch) >= 1000 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// stream scans one dataset, reads what changed and queues its chunks. It
// returns its slots in index order.
func (r *run) stream(ctx context.Context, pl *pipeline, baseSnap *Snapshot, st Stream, offset uint64, reason string, forceFull bool, ct *counters) (sr StreamResult, slots []slot, ms format.Stream, reused []format.ID, err error) {
	var b *base
	full := true
	why := reason
	switch {
	case forceFull:
		why = firstNonEmpty(reason, "a full read was requested")
	case baseSnap == nil:
		why = firstNonEmpty(reason, "there is no previous snapshot")
	default:
		var w string
		if b, w = r.streamBase(ctx, baseSnap, st.Name, r.created); b != nil {
			full, why = false, ""
		} else {
			why = w
		}
	}
	var prevTree *catalog.Tree
	if !full {
		prevTree = b.tree
	}

	// The stream's own file system (an agent reading a snapshot for an unprivileged daemon), else the
	// options' opener.
	var open openFunc = r.open
	if st.FS != nil {
		open = st.FS.Open
	}
	var readBytes, reusedBytes uint64
	onRun := func(run *catalog.Run) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !full && run.Reusable {
			if sl, ok := b.reuseSlots(run); ok {
				slots = append(slots, sl...)
				for _, s := range sl {
					if !s.id.IsZero() {
						reused = append(reused, s.id)
					}
				}
				reusedBytes += run.End - run.Start
				return nil
			}
		}
		readBytes += run.End - run.Start
		if run.Large {
			sl, err := r.readLarge(ctx, pl, open, run.Files[0], ct)
			slots = append(slots, sl...)
			if err != nil {
				return err
			}
		} else {
			s, err := r.readPack(ctx, pl, open, run, ct)
			if err != nil {
				return err
			}
			slots = append(slots, s)
		}
		if r.o.Progress != nil {
			r.o.Progress(st.Name, readBytes)
		}
		return nil
	}
	scan, err := catalog.Scan(st.Root, catalog.ScanOptions{Prev: prevTree, TrustCtimeInode: !r.o.NoTrustCtime, NoReuse: full, OnRun: onRun, Attrs: r.o.Attrs, FS: st.FS})
	if err != nil {
		if perr := pl.err(); perr != nil {
			err = perr
		}
		return sr, nil, ms, nil, fmt.Errorf("scanning %s: %w", st.Name, err)
	}
	prevTree = nil
	if b != nil {
		b.tree = nil
	}
	// the catalog, encoded straight into the chunker: never held whole
	catLen, catSlots, err := r.catalogChunks(ctx, pl, scan.Tree, ct)
	if err != nil {
		return sr, nil, ms, nil, err
	}
	slots = append(slots, catSlots...)

	mode := "full"
	lastFull := r.created
	baseID := ""
	if !full {
		mode, baseID, lastFull = "incremental", baseSnap.ID, b.st.LastFull
	}
	ms = format.Stream{
		Name: st.Name, Kind: format.StreamFiles, Offset: offset, PayloadSize: scan.PayloadSize, CatalogSize: uint64(catLen),
		Entries: scan.Tree.Count, Mode: mode, Base: baseID, LastFull: lastFull, TrustCtime: !r.o.NoTrustCtime,
		ZFSSnapshot: st.ZFSSnapshot, GUID: st.GUID, CreateTxg: st.CreateTxg, Props: st.Props,
	}
	sr = StreamResult{Mode: mode, WhyFull: why, Files: int64(scan.Files), LogicalBytes: scan.PayloadSize + uint64(catLen),
		ReadBytes: readBytes, ReusedBytes: reusedBytes}
	if mode == "incremental" {
		sr.WhyFull = ""
	}
	return sr, slots, ms, reused, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type openFunc = func(path string) (io.ReadCloser, error)

// readPack reads the files of a pack straight into one buffer: one chunk.
func (r *run) readPack(ctx context.Context, pl *pipeline, open openFunc, run *catalog.Run, ct *counters) (slot, error) {
	buf := make([]byte, run.End-run.Start)
	var pos uint64
	for _, f := range run.Files {
		if err := r.readWhole(open, f, buf[pos:pos+f.Entry.Size]); err != nil {
			return slot{}, err
		}
		pos += f.Entry.Size
	}
	return pl.emit(ctx, buf, ct)
}

func (r *run) readWhole(open openFunc, f catalog.RunFile, b []byte) error {
	fh, err := open(f.Path)
	if err != nil {
		return err
	}
	defer fh.Close()
	if _, err := io.ReadFull(fh, b); err != nil {
		return fmt.Errorf("%s: %w (file changed while it was being read?)", f.Rel, err)
	}
	var one [1]byte
	if n, _ := fh.Read(one[:]); n > 0 {
		return fmt.Errorf("%s: the file grew while it was being read", f.Rel)
	}
	f.Entry.Sum = sha256.Sum256(b)
	return nil
}

// readLarge reads one large file through content-defined chunking.
func (r *run) readLarge(ctx context.Context, pl *pipeline, open openFunc, f catalog.RunFile, ct *counters) ([]slot, error) {
	fh, err := open(f.Path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	h := sha256.New()
	rd := io.TeeReader(io.LimitReader(fh, int64(f.Entry.Size)), h)
	sp, err := chunker.NewSplitter(rd, chunker.Default)
	if err != nil {
		return nil, err
	}
	var out []slot
	var n uint64
	for {
		c, err := sp.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, fmt.Errorf("%s: %w", f.Rel, err)
		}
		n += uint64(len(c))
		s, err := pl.emit(ctx, c, ct)
		if err != nil {
			return out, err
		}
		out = append(out, s)
	}
	if n != f.Entry.Size {
		return out, fmt.Errorf("%s: read %d bytes, expected %d (file changed while it was being read?)", f.Rel, n, f.Entry.Size)
	}
	copy(f.Entry.Sum[:], h.Sum(nil))
	return out, nil
}

// catalogChunks encodes the catalog into the chunker without holding it whole.
func (r *run) catalogChunks(ctx context.Context, pl *pipeline, tree *catalog.Tree, ct *counters) (int64, []slot, error) {
	pr, pw := io.Pipe()
	var n atomic.Int64
	encErr := make(chan error, 1)
	go func() {
		err := tree.Encode(&countingWriter{w: pw, n: &n})
		_ = pw.CloseWithError(err)
		encErr <- err
	}()
	var out []slot
	sp, err := chunker.NewSplitter(pr, chunker.Default)
	if err != nil {
		_ = pr.CloseWithError(err)
		return 0, nil, err
	}
	var perr error
	for {
		c, err := sp.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			perr = err
			break
		}
		s, err := pl.emit(ctx, c, ct)
		if err != nil {
			perr = err
			break
		}
		out = append(out, s)
	}
	_ = pr.CloseWithError(errors.New("catalog encoding abandoned")) // unblocks the encoder on an early exit
	if eerr := <-encErr; perr == nil && eerr != nil && !errors.Is(eerr, io.ErrClosedPipe) {
		perr = eerr
	}
	if perr != nil {
		return 0, nil, perr
	}
	return n.Load(), out, nil
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}
