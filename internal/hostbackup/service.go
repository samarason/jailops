package hostbackup

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"jailops.net/jailops/internal/backup"
	"jailops.net/jailops/internal/repo/keys"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// Deps are the collaborators of a Service. ZFS is required; everything else
// is optional or has a default, but a missing collaborator makes the
// operations that need it answer api.CodeUnsupported.
type Deps struct {
	ZFS zfs.Client
	// Mounter defaults to OSMounter over ZFS.
	Mounter Mounter
	// Datasets mounts the datasets a capture finds unmounted (a jail that is not running). Without it such a capture
	// fails and says so.
	Datasets DatasetMounter
	// Agents, when set, reads snapshots and writes restored jails through file agents (see Agents).
	Agents Agents
	Jails  JailSource
	// Volumes lists the volumes as records; optional (see VolumeSource).
	Volumes VolumeSource
	// Objects resolves networks, policies and address sets for the bundle.
	Objects  backup.ObjectSource
	Policies PolicySource
	State    StateSource
	Hooks    Hooks
	// Host and Images serve restore.
	Host   Host
	Images Images
	// Drill runs the jail of full restore tests.
	Drill    DrillRunner
	Catalog  Catalog
	Observer Observer
	// Remote, when set, is the repository of every target (tests, and a host
	// with a single repository). Otherwise targets are resolved from
	// Config.Node and the BackupTarget objects.
	Remote Remote
}

// Service is the host side of backups: key management, capture, schedule,
// restore and restore tests. It satisfies the daemon's Backups interface
// (see Backups in adapter.go). Safe for concurrent use.
type Service struct {
	cfg  Config
	zfs  zfs.Client
	deps Deps

	mu      sync.Mutex
	key     *keys.Key
	remotes map[string]Remote
	busy    map[string]bool // jail uuid -> a job runs
	sched   map[string]*jobState
	wg      sync.WaitGroup
	sem     chan struct{}

	// fault injects a failure at a named point (in-package tests).
	fault func(point string) error
}

// New builds a Service. It loads the key file when one exists (a missing key
// file is not an error: Status reports none until CreateKey or ImportKey).
func New(cfg Config, deps Deps) (*Service, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if deps.ZFS == nil {
		return nil, api.Errorf(api.CodeInvalid, "hostbackup: Deps.ZFS is required")
	}
	if deps.Mounter == nil {
		deps.Mounter = &OSMounter{ZFS: deps.ZFS, Remote: deps.Agents != nil}
	}
	if deps.Catalog == nil {
		deps.Catalog = NewMemCatalog()
	}
	s := &Service{cfg: cfg, zfs: deps.ZFS, deps: deps, busy: map[string]bool{}, sched: map[string]*jobState{},
		sem: make(chan struct{}, cfg.Concurrency)}
	if err := s.LoadKey(); err != nil && !isNoKeyFile(err) {
		return nil, err
	}
	return s, nil
}

// Close releases the connections.
func (s *Service) Close() {
	s.Wait()
	s.dropRemotes()
}

func (s *Service) now() time.Time { return s.cfg.Clock().UTC() }

func (s *Service) fail(point string) error {
	if s.fault != nil {
		return s.fault(point)
	}
	return nil
}

// acquire marks a jail as busy; it returns false when a job already runs.
func (s *Service) acquire(uuid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy[uuid] {
		return false
	}
	s.busy[uuid] = true
	return true
}

func (s *Service) release(uuid string) {
	s.mu.Lock()
	delete(s.busy, uuid)
	s.mu.Unlock()
}

func (s *Service) isBusy(uuid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.busy[uuid]
}

// Busy says whether a backup of the jail or volume with this UUID is being taken or restored now (the delete of a
// jail or volume asks before it starts).
func (s *Service) Busy(uuid string) bool { return s.isBusy(uuid) }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Service) newID(prefix string) string {
	return fmt.Sprintf("%s-%s-%s", prefix, s.now().Format("20060102T150405"), randHex(3))
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
