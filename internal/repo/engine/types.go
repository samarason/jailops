// Package engine is the in-process backup and restore engine over a repository.
//
// Backup walks a directory tree per dataset (a read-only mounted ZFS snapshot
// is just a directory), compares it with the previous snapshot's catalog,
// reads only what changed, cuts it into chunks, uploads the chunks the
// repository does not have and commits one snapshot with one index and one
// manifest. Restore reads chunks through a read-ahead window, decrypts them,
// recomputes their ids and verifies every file's SHA-256.
//
// The engine talks to the repository through two small interfaces: Uploader,
// the write side of one snapshot, and Repository, the read side. The Store
// implements them in process; the HTTP client of the backup node implements them
// remotely. The engine never holds a whole object in memory: chunks are at most
// 8 MiB and at most a read-ahead window of them are in flight.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"jailops.net/jailops/internal/repo/catalog"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/internal/repo/keys"
)

// Defaults.
const (
	// DefaultWorkers is how many chunks are encoded and uploaded (or fetched and
	// decoded) at once.
	DefaultWorkers = 4
	// DefaultWindow is the read-ahead window of restore and the bound on chunks
	// queued between the reader and the workers of a backup.
	DefaultWindow = 8
	// DefaultFullEvery forces a full read when the last full read is older.
	DefaultFullEvery = 7 * 24 * time.Hour
)

// Errors.
var (
	// ErrNoKey: no key is available, so nothing can be backed up or restored.
	ErrNoKey = errors.New("engine: no master key")
	// ErrNotEscrowed: the master key has not been escrowed and the options require it.
	ErrNotEscrowed = errors.New("engine: the master key is not escrowed to an offline recovery recipient")
	// ErrWrongKey: the repository holds snapshots this key cannot open.
	ErrWrongKey = errors.New("engine: the key does not open this repository's snapshots (wrong key or key domain)")
	// ErrNoSnapshot: there is no such snapshot.
	ErrNoSnapshot = errors.New("engine: no such snapshot")
	// ErrCorrupt: the repository returned data that does not verify.
	ErrCorrupt = errors.New("engine: the repository returned damaged data")
)

// Uploader is the write side of ONE snapshot. *store.Session implements it in
// process; the backup node's client implements it over HTTP.
type Uploader interface {
	// Missing returns the ids the repository does not hold, and pins the ones it
	// does for the lifetime of the snapshot.
	Missing(ctx context.Context, ids []format.ID) ([]format.ID, error)
	// PutChunk stores a chunk blob under its id. Idempotent.
	PutChunk(ctx context.Context, id format.ID, blob []byte) error
	PutIndex(ctx context.Context, data []byte) error
	PutManifest(ctx context.Context, data []byte) error
	// Commit makes the snapshot visible. It returns an error wrapping
	// store.ErrMissingChunks when chunks are missing.
	Commit(ctx context.Context) (*format.Receipt, error)
	// Close releases the session (after Commit or instead of it).
	Close()
}

// SnapshotMeta is a committed snapshot as listed.
type SnapshotMeta struct {
	ID        string
	Committed time.Time
	// Failed is set when verification found the snapshot damaged: it is never a base.
	Failed bool
}

// Repository is the read side of the repository.
type Repository interface {
	// ListSnapshots returns the committed snapshots of a group, oldest first.
	ListSnapshots(ctx context.Context, group string) ([]SnapshotMeta, error)
	// ReadIndex, ReadManifest and ReadReceipt return an error wrapping
	// ErrNoSnapshot for a snapshot that is not committed.
	ReadIndex(ctx context.Context, group, snapshot string) ([]byte, error)
	ReadManifest(ctx context.Context, group, snapshot string) ([]byte, error)
	ReadReceipt(ctx context.Context, group, snapshot string) (*format.Receipt, error)
	GetChunk(ctx context.Context, id format.ID) ([]byte, error)
	// KeyDomain is the domain id the repository was initialised with, "" if unknown.
	KeyDomain() string
}

// Stream is one dataset to back up.
type Stream struct {
	// Name is the dataset name; it identifies the stream across snapshots.
	Name string
	// Root is the directory to read (a mounted read-only snapshot).
	Root string
	// FS reads the tree (nil = the local file system). An unprivileged daemon reads a snapshot through
	// an agent that holds the privileges; Root is then a path in the agent's view.
	FS catalog.ScanFS
	// OpenFS, when set, is called when the engine starts this stream and gives its file system (FS is then ignored);
	// the returned func is called as soon as the stream has been read, also when it failed. A reader that is a process
	// of its own (an agent) lives for one stream and not for the whole backup.
	OpenFS func(ctx context.Context) (catalog.ScanFS, func(), error)
	// ZFSSnapshot, GUID, CreateTxg and Props identify the consistent ZFS
	// snapshot that was read and are recorded in the manifest.
	ZFSSnapshot string
	GUID        uint64
	CreateTxg   uint64
	Props       map[string]string
}

// BackupOptions describe one backup of one jail.
type BackupOptions struct {
	// Key is the master key. Nil is ErrNoKey.
	Key *keys.Key
	// Escrow, if set, is asked whether the key is escrowed (the Store).
	Escrow keys.EscrowChecker
	// RequireEscrow refuses a backup whose key is not escrowed. Without it the
	// result carries a warning.
	RequireEscrow bool

	// Host and Jail are the identities (uuids) that form the group id.
	Host, Jail string
	JailName   string
	Policy     string
	Streams    []Stream
	// Bundle is the restore closure, recorded in the manifest as is.
	Bundle json.RawMessage
	Meta   map[string]string

	// Repo is the read side (base lookup); NewUploader opens the write side of
	// the snapshot. Both are required.
	Repo        Repository
	NewUploader func(ctx context.Context, group, snapshot, previous string) (Uploader, error)

	// Previous names the snapshot to use as the base ("" = the latest committed
	// one). NoPrevious reads everything.
	Previous   string
	NoPrevious bool
	// ForceFull reads every file (still deduplicated).
	ForceFull bool
	// FullEvery is how old the last full read may get before another is forced
	// (0 = DefaultFullEvery).
	FullEvery time.Duration
	// NoTrustCtime compares neither ctime nor inode numbers (sources where they
	// are not stable).
	NoTrustCtime bool

	Workers int // 0 = DefaultWorkers
	Window  int // 0 = DefaultWindow

	// Now is the clock (tests).
	Now func() time.Time
	// OpenFile opens a file for reading (nil = os.Open). Tests count reads
	// through it.
	OpenFile func(path string) (io.ReadCloser, error)
	// Attrs collects extended attributes and ACLs (nil = the platform's).
	Attrs catalog.Attrs
	// Progress, if set, is called with the bytes read so far and the stream name.
	Progress func(stream string, readBytes uint64)
}

// BackupResult reports a committed backup.
type BackupResult struct {
	Group     string
	Snapshot  string
	Previous  string
	Receipt   *format.Receipt
	Streams   []StreamResult
	Warnings  []string
	KeyStatus keys.Status
	Duration  time.Duration
	// Totals over all streams.
	LogicalBytes  uint64
	ReadBytes     uint64
	ReusedBytes   uint64
	UploadedBytes uint64
	NewChunks     int
	// Full is true when any stream read every file.
	Full bool
}

// StreamResult reports one dataset.
type StreamResult struct {
	Name          string
	Mode          string // "full" or "incremental"
	WhyFull       string // the reason a full read was done ("" when incremental)
	Files         int64
	LogicalBytes  uint64
	ReadBytes     uint64
	ReusedBytes   uint64
	UploadedBytes uint64
	NewChunks     int
}
