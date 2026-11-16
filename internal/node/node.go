package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/internal/retention"
	"jailops.net/jailops/sdk/api"
)

// Defaults and limits.
const (
	// DefaultLease is how long a session lives without activity.
	DefaultLease = 15 * time.Minute
	// DefaultGrace is how old an unreferenced chunk must be before GC may sweep it.
	DefaultGrace = 24 * time.Hour
	// MinGrace is the smallest grace period GC accepts.
	MinGrace = 12 * time.Hour
	// DefaultDeletionDelay is the wait between a deletion request and its execution.
	DefaultDeletionDelay = 72 * time.Hour
	// MaxMissingBatch is the most ids one Missing call accepts.
	MaxMissingBatch = wire.MaxMissingBatch
	// MaxClockSkew is how far in the future a snapshot id may be dated.
	MaxClockSkew = 5 * time.Minute
)

// AuditEvent is what the node reports about an administrative action.
type AuditEvent struct {
	Actor  string
	Action string
	Target string
	Detail map[string]any
	Remote string
}

// Config configures a Node.
type Config struct {
	// Backend is the repository storage. The node wraps it in the maintenance
	// mode wrapper, beneath every code path.
	Backend datastore.Backend
	// DB is the PostgreSQL control plane, migrated.
	DB *ctl.DB
	// ServerID identifies this node in owner.json. Empty means the id stored in the control plane
	// (generated on first use).
	ServerID string
	// Hostname is informational (owner.json, server info).
	Hostname string
	// Adopt takes over a repository owned by another node.
	Adopt bool
	// Lease is the session lease (default DefaultLease).
	Lease time.Duration
	// Grace is the default GC grace period (default DefaultGrace).
	Grace time.Duration
	// MinGrace overrides the minimum grace period. It exists for tests only;
	// production leaves it at the default.
	MinGrace time.Duration
	// DeletionDelay is the default delay of a deletion request.
	DeletionDelay time.Duration
	// RetentionDefault applies to groups without a stored policy. The zero
	// value keeps everything.
	RetentionDefault api.RetentionPolicy
	// RetentionTimezone defines the periods of RetentionDefault (default UTC).
	RetentionTimezone string
	// RetentionSafety protects snapshots committed less than this long ago.
	RetentionSafety time.Duration
	// MaxOpenSessions bounds the memory held by sessions (default 64).
	MaxOpenSessions int
	// Parallelism bounds concurrent backend requests of one operation (default 32).
	Parallelism int
	// Audit is called after every administrative action, in addition to the audit table.
	Audit func(AuditEvent)
	// Now replaces the clock (tests).
	Now func() time.Time
}

// Node is the backup node.
type Node struct {
	cfg  Config
	db   *ctl.DB
	raw  datastore.Backend
	be   *datastore.ModeBackend
	now  func() time.Time
	meta Meta
	// domainMu guards meta.KeyDomain, which is bound once by the first escrow.
	domainMu sync.Mutex
	sid      string

	// gcMu serialises the final check and delete of GC against the claims
	// sessions make on chunks: Missing, PutChunk and Commit hold the read side
	// while they look at a chunk and record their pin, GC holds the write side
	// for each sweep batch.
	//
	// Lock order (outermost first): session.commitMu -> gcMu -> pinMu -> session.mu.
	gcMu sync.RWMutex
	// pinMu guards sessions, shadow and gcActive.
	pinMu    sync.Mutex
	sessions map[string]*session
	gcActive bool
	shadow   map[uint64]struct{} // pins of sessions that ended while a GC runs

	snapLocks [64]sync.Mutex

	recentMu sync.Mutex
	recent   map[string]recentCommit

	bgMu     sync.Mutex
	cancels  map[int64]context.CancelFunc
	closed   atomic.Bool
	jobsDone sync.WaitGroup
}

// InitOptions describe a new repository.
type InitOptions struct {
	// ServerID claims owner.json for this node.
	ServerID string
	Host     string
	// KeyDomain, if set, is recorded: hosts holding another key are refused.
	KeyDomain string
}

// ErrInitialised is returned by Init when the datastore already holds a repository.
var ErrInitialised = errors.New("node: the datastore already holds a repository")

// Init creates a repository on the backend (which must not hold one) and claims it.
func Init(ctx context.Context, b datastore.Backend, o InitOptions) (*Meta, error) {
	if o.KeyDomain != "" && !format.ValidDomainID(o.KeyDomain) {
		return nil, errors.New("node: malformed key domain id")
	}
	var r [8]byte
	_, _ = rand.Read(r[:])
	m := &Meta{Format: 1, ID: hex.EncodeToString(r[:]), Created: time.Now().UTC().Truncate(time.Second), KeyDomain: o.KeyDomain}
	if err := putJSON(ctx, b, metaKey, m, true); err != nil {
		if errors.Is(err, datastore.ErrExists) {
			return nil, ErrInitialised
		}
		return nil, err
	}
	if err := ClaimOwner(ctx, b, o.ServerID, o.Host, false); err != nil {
		return nil, err
	}
	return m, nil
}

// Open opens an existing repository, claims it (or refuses it when another node
// owns it), restores the maintenance mode, and closes sessions left open by a
// previous process: their uploaded index and manifest were in memory.
func Open(ctx context.Context, cfg Config) (*Node, error) {
	if cfg.Backend == nil || cfg.DB == nil {
		return nil, errors.New("node: Backend and DB are required")
	}
	n := &Node{cfg: cfg, db: cfg.DB, raw: cfg.Backend, now: cfg.Now, sessions: map[string]*session{}, cancels: map[int64]context.CancelFunc{}}
	if n.now == nil {
		n.now = time.Now
	}
	if n.db != nil {
		n.db.SetClock(n.now) // the leases of the sessions run on the clock of the node
	}
	if n.cfg.Lease <= 0 {
		n.cfg.Lease = DefaultLease
	}
	if n.cfg.Grace <= 0 {
		n.cfg.Grace = DefaultGrace
	}
	if n.cfg.MinGrace <= 0 {
		n.cfg.MinGrace = MinGrace
	}
	if n.cfg.DeletionDelay <= 0 {
		n.cfg.DeletionDelay = DefaultDeletionDelay
	}
	if n.cfg.MaxOpenSessions <= 0 {
		n.cfg.MaxOpenSessions = 64
	}
	if n.cfg.Parallelism <= 0 {
		n.cfg.Parallelism = 32
	}
	if n.cfg.Grace < n.cfg.MinGrace {
		return nil, fmt.Errorf("node: the grace period %v is shorter than the minimum %v", n.cfg.Grace, n.cfg.MinGrace)
	}
	mode := datastore.ModeOnline
	var ms string
	if err := n.db.Setting(ctx, "maintenance", &ms); err == nil {
		if m, ok := datastore.ParseMode(ms); ok {
			mode = m
		}
	}
	n.be = datastore.NewModeBackend(cfg.Backend, mode)
	if err := readJSON(ctx, cfg.Backend, metaKey, &n.meta); err != nil {
		if errors.Is(err, datastore.ErrNotFound) {
			return nil, ErrNotRepository
		}
		return nil, fmt.Errorf("node: reading %s: %w", metaKey, err)
	}
	if n.meta.Format != 1 {
		return nil, fmt.Errorf("node: unsupported repository format %d", n.meta.Format)
	}
	sid, err := n.serverID(ctx)
	if err != nil {
		return nil, err
	}
	n.sid = sid
	if err := ClaimOwner(ctx, cfg.Backend, sid, cfg.Hostname, cfg.Adopt); err != nil {
		return nil, err
	}
	if _, err := n.db.AbandonJobs(ctx); err != nil {
		return nil, err
	}
	// Buffers and pins of sessions of an earlier process are gone; the grace
	// period protects whatever they had uploaded. Their hosts get lease_expired and start over.
	if _, err := n.db.Pool().Exec(ctx, `UPDATE sessions SET state='expired', closed_at=now() WHERE state='open'`); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *Node) serverID(ctx context.Context) (string, error) {
	if n.cfg.ServerID != "" {
		return n.cfg.ServerID, nil
	}
	var id string
	if err := n.db.Setting(ctx, "server_id", &id); err == nil && id != "" {
		return id, nil
	} else if err != nil && !errors.Is(err, ctl.ErrNotFound) {
		return "", err
	}
	var r [8]byte
	_, _ = rand.Read(r[:])
	id = "node-" + hex.EncodeToString(r[:])
	return id, n.db.SetSetting(ctx, "server_id", id)
}

// Close cancels running jobs and waits for them.
func (n *Node) Close() {
	if n.closed.Swap(true) {
		return
	}
	n.bgMu.Lock()
	for _, c := range n.cancels {
		c()
	}
	n.bgMu.Unlock()
	n.jobsDone.Wait()
}

// Meta returns datastore.json.
func (n *Node) Meta() Meta { return n.meta }

// ServerID is the id this node is recorded under in owner.json.
func (n *Node) ServerID() string { return n.sid }

// Backend returns the repository storage, behind the maintenance wrapper.
func (n *Node) Backend() datastore.Backend { return n.be }

// DB returns the control plane.
func (n *Node) DB() *ctl.DB { return n.db }

// Now is the node's clock.
func (n *Node) Now() time.Time { return n.now() }

// Mode returns the maintenance mode.
func (n *Node) Mode() datastore.Mode { return n.be.Mode() }

// SetMode switches the maintenance mode, persists it and audits it.
func (n *Node) SetMode(ctx context.Context, m datastore.Mode, actor string) error {
	if err := n.db.SetSetting(ctx, "maintenance", m.String()); err != nil {
		return err
	}
	n.be.SetMode(m)
	n.audit(ctx, actor, "maintenance.set", "", map[string]any{"mode": m.String()}, "")
	return nil
}

// requireOnline refuses work that writes while the repository is in maintenance.
func (n *Node) requireOnline() error {
	switch n.be.Mode() {
	case datastore.ModeReadOnly:
		return errf(api.CodeMaintenance, "the repository is in read-only maintenance mode").WithHint("retry later")
	case datastore.ModeOffline:
		return errf(api.CodeMaintenance, "the repository is offline for maintenance").WithHint("retry later")
	}
	return nil
}

func (n *Node) audit(ctx context.Context, actor, action, target string, detail map[string]any, remote string) {
	if actor == "" {
		actor = "system"
	}
	_ = n.db.Audit(context.WithoutCancel(ctx), actor, action, target, detail, remote)
	if n.cfg.Audit != nil {
		n.cfg.Audit(AuditEvent{Actor: actor, Action: action, Target: target, Detail: detail, Remote: remote})
	}
}

func (n *Node) snapLock(group, snap string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(group + "/" + snap))
	return &n.snapLocks[h.Sum32()%uint32(len(n.snapLocks))]
}

// retentionOptions are the options of every retention evaluation.
func (n *Node) retentionOptions(loc *time.Location) retention.Options {
	return retention.Options{SafetyWindow: n.cfg.RetentionSafety, Loc: loc}
}
