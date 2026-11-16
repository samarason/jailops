package state

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"jailops.net/jailops/sdk/api"
)

// Hooks are callbacks into the rest of the daemon.
type Hooks struct {
	// BeforeDestructive runs, with the store locked, before a delete is
	// written. The daemon uses it to snapshot the state dataset. If it
	// returns an error the delete is not performed. It must not call back
	// into the Store.
	BeforeDestructive func(kind api.Kind, name string) error
}

// Options configures Open.
type Options struct {
	Hooks      Hooks
	Migrations []Migration
	// Committer replaces the single-node committer (for example a Raft one).
	Committer Committer
	// Fault is a crash-injection hook for tests, see the Fault* constants.
	Fault func(point string) error
	// AllowUnrecoverable lets Open succeed when a file is corrupt and has no
	// usable .previous. The file is quarantined and reported. Default: Open fails.
	AllowUnrecoverable bool
}

// Recovery reports a file that was damaged and what was done about it.
type Recovery struct {
	Path   string
	Reason string
	// Action is "restored-previous", "quarantined" or "dropped-temp".
	Action string
}

// Committer decides how a command becomes durable. The single-node committer
// applies directly; a Raft committer replicates first and applies on commit.
type Committer interface {
	Commit(cmd Command) (Result, error)
}

// Applier is the FSM side: it applies an already-committed command.
type Applier interface {
	ApplyCommitted(cmd Command) (Result, error)
}

type directCommitter struct{ a Applier }

func (d directCommitter) Commit(cmd Command) (Result, error) { return d.a.ApplyCommitted(cmd) }

// NewDirectCommitter returns the single-node committer.
func NewDirectCommitter(a Applier) Committer { return directCommitter{a} }

// Store is the object store of one state directory.
type Store struct {
	dir  string
	opts Options

	lockFile *os.File

	mu         sync.RWMutex
	closed     bool
	objs       map[api.Kind]map[string]*Object // kind -> uuid -> object
	names      map[api.Kind]map[string]string  // kind -> scope/name -> uuid
	recoveries []Recovery

	committer Committer
	watchers  watchers
}

func nameKey(scope api.Scope, project, name string) string {
	return string(scope) + "/" + project + "/" + name
}

// Open locks dir (creating it), loads every object and builds the indexes.
func Open(dir string, opts Options) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0o750); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lf.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, api.Errorf(api.CodeBusy, "state directory %s is locked by another process", dir)
		}
		return nil, err
	}
	s := &Store{
		dir:      dir,
		opts:     opts,
		lockFile: lf,
		objs:     map[api.Kind]map[string]*Object{},
		names:    map[api.Kind]map[string]string{},
	}
	s.committer = opts.Committer
	if s.committer == nil {
		s.committer = NewDirectCommitter(s)
	}
	if err := s.load(); err != nil {
		s.release()
		return nil, err
	}
	return s, nil
}

func (s *Store) release() {
	if s.lockFile != nil {
		unix.Flock(int(s.lockFile.Fd()), unix.LOCK_UN)
		s.lockFile.Close()
		s.lockFile = nil
	}
}

// Close releases the directory lock and closes watch channels.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.watchers.closeAll()
	s.release()
	return nil
}

// SetCommitter swaps the committer (for example when cluster mode starts).
func (s *Store) SetCommitter(c Committer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.committer = c
}

// Recoveries returns what Open repaired.
func (s *Store) Recoveries() []Recovery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Recovery(nil), s.recoveries...)
}

func (s *Store) objectPath(kind api.Kind, uuid string) string {
	return filepath.Join(s.dir, "objects", string(kind), uuid+".json")
}

func (s *Store) load() error {
	root := filepath.Join(s.dir, "objects")
	kinds, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, kd := range kinds {
		if !kd.IsDir() || !kindRe.MatchString(kd.Name()) {
			continue
		}
		kind := api.Kind(kd.Name())
		kdir := filepath.Join(root, kd.Name())
		ents, err := os.ReadDir(kdir)
		if err != nil {
			return err
		}
		// Collect base names (<uuid>.json), including ones that only have a .previous.
		bases := map[string]bool{}
		for _, e := range ents {
			n := e.Name()
			switch {
			case strings.HasSuffix(n, tempSuffix):
				p := filepath.Join(kdir, n)
				if err := os.Remove(p); err == nil {
					s.recoveries = append(s.recoveries, Recovery{Path: p, Reason: "leftover temporary file from an interrupted write", Action: "dropped-temp"})
				}
			case strings.HasSuffix(n, ".json"):
				bases[n] = true
			case strings.HasSuffix(n, ".json"+previousSuffix):
				bases[strings.TrimSuffix(n, previousSuffix)] = true
			}
		}
		names := make([]string, 0, len(bases))
		for n := range bases {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			obj, err := s.loadOne(kind, filepath.Join(kdir, n))
			if err != nil {
				return err
			}
			if obj == nil {
				continue
			}
			if err := s.index(obj); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadOne reads path, falling back to path.previous when the main file is
// missing or damaged. A nil object with nil error means quarantined.
func (s *Store) loadOne(kind api.Kind, path string) (*Object, error) {
	uuid := strings.TrimSuffix(filepath.Base(path), ".json")
	try := func(p string) (*Object, error) {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		o, migrated, err := decodeObject(data, s.opts.Migrations)
		if err != nil {
			return nil, err
		}
		if o.Kind != kind || o.Metadata.UUID != uuid {
			return nil, fmt.Errorf("document identity %s/%s does not match its path", o.Kind, o.Metadata.UUID)
		}
		if err := validName(o.Metadata.Name); err != nil {
			return nil, err
		}
		if migrated {
			b, err := encodeObject(o)
			if err != nil {
				return nil, err
			}
			if err := atomicWrite(path, b, nil); err != nil {
				return nil, fmt.Errorf("write migrated document: %w", err)
			}
		}
		return o, nil
	}
	o, err := try(path)
	if err == nil {
		return o, nil
	}
	var ae *api.Error
	if errors.As(err, &ae) && (ae.Code == api.CodeVersionSkew) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	reason := err.Error()
	po, perr := try(path + previousSuffix)
	if perr != nil {
		if errors.As(perr, &ae) && ae.Code == api.CodeVersionSkew {
			return nil, fmt.Errorf("%s: %w", path+previousSuffix, perr)
		}
		if errors.Is(err, os.ErrNotExist) && errors.Is(perr, os.ErrNotExist) {
			return nil, nil
		}
		if !s.opts.AllowUnrecoverable {
			return nil, api.Errorf(api.CodeInternal, "state file %s is damaged (%s) and has no usable %s (%v)", path, reason, previousSuffix, perr)
		}
		q := path + corruptSuffix
		if _, serr := os.Stat(path); serr == nil {
			os.Rename(path, q)
		}
		s.recoveries = append(s.recoveries, Recovery{Path: path, Reason: reason, Action: "quarantined"})
		return nil, nil
	}
	// Restore: keep the damaged file for forensics, write the previous copy back.
	if _, serr := os.Stat(path); serr == nil {
		os.Rename(path, path+corruptSuffix)
	}
	b, err := encodeObject(po)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(path, b, nil); err != nil {
		return nil, fmt.Errorf("restore %s: %w", path, err)
	}
	s.recoveries = append(s.recoveries, Recovery{Path: path, Reason: reason, Action: "restored-previous"})
	return po, nil
}

func (s *Store) index(o *Object) error {
	km := s.objs[o.Kind]
	if km == nil {
		km = map[string]*Object{}
		s.objs[o.Kind] = km
		s.names[o.Kind] = map[string]string{}
	}
	nk := nameKey(o.Metadata.Scope, o.Metadata.Project, o.Metadata.Name)
	if other, dup := s.names[o.Kind][nk]; dup && other != o.Metadata.UUID {
		return api.Errorf(api.CodeInternal, "duplicate name %s %q in project %q in state (uuids %s and %s)", o.Kind, o.Metadata.Name, o.Metadata.Project, other, o.Metadata.UUID)
	}
	km[o.Metadata.UUID] = o
	s.names[o.Kind][nk] = o.Metadata.UUID
	return nil
}

func (s *Store) unindex(o *Object) {
	delete(s.objs[o.Kind], o.Metadata.UUID)
	delete(s.names[o.Kind], nameKey(o.Metadata.Scope, o.Metadata.Project, o.Metadata.Name))
}

// Apply is the only mutation path. It hands the command to the committer.
func (s *Store) Apply(cmd Command) (Result, error) {
	if err := cmd.Validate(); err != nil {
		return Result{}, err
	}
	s.mu.RLock()
	c := s.committer
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return Result{}, api.Errorf(api.CodeInternal, "state store is closed")
	}
	return c.Commit(cmd)
}

// ApplyCommitted applies a committed command to the local files. It is the
// FSM entry point used by committers; callers use Apply.
func (s *Store) ApplyCommitted(cmd Command) (Result, error) {
	if err := cmd.Validate(); err != nil {
		return Result{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Result{}, api.Errorf(api.CodeInternal, "state store is closed")
	}
	var (
		res Result
		ev  *Event
		err error
	)
	switch cmd.Op {
	case OpPut:
		res, ev, err = s.applyPut(cmd)
	case OpDelete:
		res, ev, err = s.applyDelete(cmd)
	}
	if err != nil {
		return Result{}, err
	}
	res.CommandID = cmd.ID
	s.watchers.publish(*ev)
	if res.Object != nil {
		res.Object = res.Object.clone()
	}
	return res, nil
}

func (s *Store) resolve(cmd Command) *Object {
	if cmd.UUID != "" {
		return s.objs[cmd.Kind][cmd.UUID]
	}
	if cmd.Scope != "" {
		if u, ok := s.names[cmd.Kind][nameKey(cmd.Scope, cmd.Project, cmd.Name)]; ok {
			return s.objs[cmd.Kind][u]
		}
		return nil
	}
	// Scope unspecified: match by name in any scope, lowest scope string first for determinism.
	var found *Object
	for _, sc := range []api.Scope{api.ScopeFleet, api.ScopeHost} {
		if u, ok := s.names[cmd.Kind][nameKey(sc, cmd.Project, cmd.Name)]; ok {
			found = s.objs[cmd.Kind][u]
			break
		}
	}
	return found
}

func (s *Store) applyPut(cmd Command) (Result, *Event, error) {
	old := s.resolve(cmd)
	if old == nil && cmd.UUID == "" {
		return Result{}, nil, api.Errorf(api.CodeInvalid, "creating %s %q needs a proposer-supplied uuid", cmd.Kind, cmd.Name)
	}
	switch {
	case old == nil && cmd.ExpectGeneration > 0:
		return Result{}, nil, api.Errorf(api.CodeConflict, "%s %q does not exist at generation %d", cmd.Kind, cmd.Name, cmd.ExpectGeneration)
	case old != nil && cmd.ExpectGeneration == 0:
		return Result{}, nil, api.Errorf(api.CodeAlreadyExists, "%s %q already exists", cmd.Kind, cmd.Name)
	case old != nil && cmd.ExpectGeneration > 0 && cmd.ExpectGeneration != old.Metadata.Generation:
		return Result{}, nil, api.Errorf(api.CodeConflict, "%s %q is at generation %d, not %d", cmd.Kind, cmd.Name, old.Metadata.Generation, cmd.ExpectGeneration).
			WithDetail("generation", fmt.Sprint(old.Metadata.Generation))
	case cmd.ExpectGeneration < AnyGeneration:
		return Result{}, nil, api.Errorf(api.CodeInvalid, "invalid expect_generation %d", cmd.ExpectGeneration)
	}
	scope := cmd.Scope
	if old != nil {
		if scope == "" {
			scope = old.Metadata.Scope
		} else if scope != old.Metadata.Scope {
			return Result{}, nil, api.Errorf(api.CodeInvalid, "scope of %s %q cannot change", cmd.Kind, cmd.Name)
		}
	} else if scope == "" {
		scope = api.ScopeHost
	}
	uuid := cmd.UUID
	if old != nil {
		uuid = old.Metadata.UUID
	}
	project := cmd.Project
	if old != nil {
		switch {
		case cmd.Project == old.Metadata.Project:
		case old.Metadata.Project == "" && cmd.UUID == old.Metadata.UUID:
			// An object written before projects existed joins a project once.
		case cmd.MoveProject && cmd.UUID == old.Metadata.UUID:
			// a project rename moves the objects of the project
		default:
			return Result{}, nil, api.Errorf(api.CodeInvalid, "project of %s %q cannot change", cmd.Kind, cmd.Name)
		}
		project = cmd.Project
	}
	if other, ok := s.names[cmd.Kind][nameKey(scope, project, cmd.Name)]; ok && other != uuid {
		return Result{}, nil, api.Errorf(api.CodeAlreadyExists, "%s named %q already exists", cmd.Kind, cmd.Name)
	}
	obj := &Object{
		APIVersion: api.APIVersion,
		Kind:       cmd.Kind,
		Spec:       append([]byte(nil), cmd.Spec...),
		Metadata: api.ObjectMeta{
			Name:       cmd.Name,
			UUID:       uuid,
			Host:       cmd.Host,
			Project:    project,
			Scope:      scope,
			Generation: 1,
			Labels:     cloneLabels(cmd.Labels),
			ManagedBy:  cmd.ManagedBy,
			CreatedAt:  cmd.Time.UTC(),
			UpdatedAt:  cmd.Time.UTC(),
		},
	}
	typ := EventAdded
	if old != nil {
		typ = EventModified
		obj.Metadata.Generation = old.Metadata.Generation + 1
		obj.Metadata.CreatedAt = old.Metadata.CreatedAt
		if obj.Metadata.Host == "" {
			obj.Metadata.Host = old.Metadata.Host
		}
	}
	b, err := encodeObject(obj)
	if err != nil {
		return Result{}, nil, api.Errorf(api.CodeInternal, "encode: %v", err)
	}
	path := s.objectPath(cmd.Kind, uuid)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return Result{}, nil, api.Errorf(api.CodeInternal, "%v", err)
	}
	if err := atomicWrite(path, b, s.opts.Fault); err != nil {
		return Result{}, nil, api.Errorf(api.CodeInternal, "write %s: %v", path, err)
	}
	if old != nil {
		s.unindex(old)
	}
	if s.objs[cmd.Kind] == nil {
		s.objs[cmd.Kind] = map[string]*Object{}
		s.names[cmd.Kind] = map[string]string{}
	}
	s.objs[cmd.Kind][uuid] = obj
	s.names[cmd.Kind][nameKey(scope, project, cmd.Name)] = uuid
	return Result{Object: obj, Created: old == nil},
		&Event{Type: typ, Kind: cmd.Kind, UUID: uuid, Name: cmd.Name, Project: project, Generation: obj.Metadata.Generation}, nil
}

func (s *Store) applyDelete(cmd Command) (Result, *Event, error) {
	old := s.resolve(cmd)
	if old == nil {
		return Result{}, nil, api.Errorf(api.CodeNotFound, "%s %q not found", cmd.Kind, firstNonEmpty(cmd.Name, cmd.UUID))
	}
	if cmd.ExpectGeneration > 0 && cmd.ExpectGeneration != old.Metadata.Generation {
		return Result{}, nil, api.Errorf(api.CodeConflict, "%s %q is at generation %d, not %d", cmd.Kind, old.Metadata.Name, old.Metadata.Generation, cmd.ExpectGeneration).
			WithDetail("generation", fmt.Sprint(old.Metadata.Generation))
	}
	if cmd.ExpectGeneration < AnyGeneration {
		return Result{}, nil, api.Errorf(api.CodeInvalid, "invalid expect_generation %d", cmd.ExpectGeneration)
	}
	if h := s.opts.Hooks.BeforeDestructive; h != nil {
		if err := h(old.Kind, old.Metadata.Name); err != nil {
			return Result{}, nil, fmt.Errorf("before destructive hook: %w", err)
		}
	}
	if err := removeObjectFiles(s.objectPath(old.Kind, old.Metadata.UUID), s.opts.Fault); err != nil {
		return Result{}, nil, api.Errorf(api.CodeInternal, "delete: %v", err)
	}
	s.unindex(old)
	return Result{Object: old, Deleted: true},
		&Event{Type: EventDeleted, Kind: old.Kind, UUID: old.Metadata.UUID, Name: old.Metadata.Name, Project: old.Metadata.Project, Generation: old.Metadata.Generation}, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func cloneLabels(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// Get returns a copy of the object with the given kind and uuid.
func (s *Store) Get(kind api.Kind, uuid string) (*Object, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o := s.objs[kind][uuid]
	if o == nil {
		return nil, api.Errorf(api.CodeNotFound, "%s %s not found", kind, uuid)
	}
	return o.clone(), nil
}

// GetByName looks an object up by name. An empty scope matches any scope.
func (s *Store) GetByName(kind api.Kind, scope api.Scope, name string) (*Object, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o := s.resolve(Command{Kind: kind, Scope: scope, Name: name})
	if o == nil {
		return nil, api.Errorf(api.CodeNotFound, "%s %q not found", kind, name)
	}
	return o.clone(), nil
}

// GetByNameIn looks an object up by name within a project. An empty scope
// matches any scope.
func (s *Store) GetByNameIn(kind api.Kind, scope api.Scope, project, name string) (*Object, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o := s.resolve(Command{Kind: kind, Scope: scope, Project: project, Name: name})
	if o == nil {
		return nil, api.Errorf(api.CodeNotFound, "%s %q not found", kind, name)
	}
	return o.clone(), nil
}

// ListIn is List restricted to one project.
func (s *Store) ListIn(kind api.Kind, project, selector string) ([]*Object, error) {
	all, err := s.List(kind, selector)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, o := range all {
		if o.Metadata.Project == project {
			out = append(out, o)
		}
	}
	return out, nil
}

// List returns copies of all objects of a kind whose labels match the
// selector (empty selector matches all), sorted by name.
func (s *Store) List(kind api.Kind, selector string) ([]*Object, error) {
	sel, err := ParseSelector(selector)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Object
	for _, o := range s.objs[kind] {
		if sel.Matches(o.Metadata.Labels) {
			out = append(out, o.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Metadata.Name != out[j].Metadata.Name {
			return out[i].Metadata.Name < out[j].Metadata.Name
		}
		return out[i].Metadata.UUID < out[j].Metadata.UUID
	})
	return out, nil
}

// NewUUID returns a random version 4 UUID for proposers to put in commands.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("state: no entropy: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
