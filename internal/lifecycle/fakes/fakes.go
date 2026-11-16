// Package fakes holds in-memory fakes of the non-ZFS collaborators of the
// lifecycle and image generation code: command execution, files, the jail
// runtime and render hooks. Every mutating call goes through the shared fault
// injector so tests can fail each step in turn.
package fakes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"jailops.net/jailops/internal/hostdir"
	"jailops.net/jailops/internal/lifecycle/fault"
	"jailops.net/jailops/internal/mounts"
)

// Exec is a scripted command runner.
type Exec struct {
	F *fault.Injector
	// Handler answers a command. Nil handler returns empty output.
	Handler func(argv []string) ([]byte, error)
	mu      sync.Mutex
	Calls   [][]string
}

func (e *Exec) Run(_ context.Context, argv []string) ([]byte, error) {
	if err := e.F.Hit("exec " + strings.Join(argv, " ")); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.Calls = append(e.Calls, append([]string(nil), argv...))
	h := e.Handler
	e.mu.Unlock()
	if h == nil {
		return nil, nil
	}
	return h(argv)
}

// Commands returns the joined command lines run so far.
func (e *Exec) Commands() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, c := range e.Calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// Files is an in-memory file store with atomic writes.
type Files struct {
	F      *fault.Injector
	mu     sync.Mutex
	Data   map[string][]byte
	Dirs   map[string]bool
	Trees  map[string][]string // CopyTree: src -> file paths relative to src to copy
	Owners map[string]string   // SetOwner: path -> uid:gid:mode
	// Stale are the leftover mounts StaleMounts reports.
	Stale []mounts.Stale
	// Sources are the directories of the host that are mounts, and ReadOnlySources those that take no file: what
	// ProbeSource answers from.
	Sources         map[string]bool
	ReadOnlySources map[string]bool
	// ProbeHold, when set, makes ProbeSource block until it is closed (a share that does not answer), and ProbeCalls
	// counts the probes that reached the fake.
	ProbeHold  chan struct{}
	ProbeCalls int
}

func NewFiles(f *fault.Injector) *Files {
	return &Files{F: f, Data: map[string][]byte{}, Dirs: map[string]bool{}, Trees: map[string][]string{}, Sources: map[string]bool{}, ReadOnlySources: map[string]bool{}}
}

func (f *Files) WriteAtomic(_ context.Context, p string, data []byte) error {
	if err := f.F.Hit("write " + p); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.Data[p]; ok {
		f.Data[p+".previous"] = old
	}
	f.Data[p] = append([]byte(nil), data...)
	return nil
}

func (f *Files) ReadFile(_ context.Context, p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.Data[p]
	if !ok {
		return nil, fmt.Errorf("%s: %w", p, os.ErrNotExist)
	}
	return append([]byte(nil), d...), nil
}

func (f *Files) Exists(_ context.Context, p string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.Data[p]
	return ok || f.Dirs[p], nil
}

// SetOwner records the owner and the mode set on a path.
func (f *Files) SetOwner(_ context.Context, p string, uid, gid int, mode uint32) error {
	if err := f.F.Hit("setowner " + p); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Owners == nil {
		f.Owners = map[string]string{}
	}
	f.Owners[p] = fmt.Sprintf("%d:%d:%04o", uid, gid, mode)
	return nil
}

// Probes is how many probes of a source reached the fake.
func (f *Files) Probes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ProbeCalls
}

// StaleMounts are the leftover mounts the fake reports; HealJail takes the ones of a jail off the list.
func (f *Files) StaleMounts(context.Context) ([]mounts.Stale, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mounts.Stale(nil), f.Stale...), nil
}

func (f *Files) HealJail(_ context.Context, jail string) (mounts.Healed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var res mounts.Healed
	keep := f.Stale[:0:0]
	for _, m := range f.Stale {
		if m.Jail == jail {
			res.Unmounted = append(res.Unmounted, m.Path)
			continue
		}
		keep = append(keep, m)
	}
	f.Stale = keep
	return res, nil
}

// Sources are the directories of the host the fake knows as mounts; ProbeSource answers from it.
// ProbeSource says whether a path is in Sources (a mount) and, with write, whether it is not in Readonly.
func (f *Files) ProbeSource(_ context.Context, p string, write bool) (hostdir.Probe, error) {
	if err := f.F.Hit("probe " + p); err != nil {
		return hostdir.Probe{}, err
	}
	f.mu.Lock()
	f.ProbeCalls++
	hold := f.ProbeHold
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Sources[p] {
		return hostdir.Probe{Detail: "the directory is not on a mount"}, nil
	}
	out := hostdir.Probe{Mounted: true, Writable: !f.ReadOnlySources[p]}
	if write && !out.Writable {
		out.Detail = "no file can be created in the directory"
	}
	return out, nil
}

func (f *Files) MkdirAll(_ context.Context, p string) error {
	if err := f.F.Hit("mkdir " + p); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Dirs[p] = true
	return nil
}

func (f *Files) RemoveAll(_ context.Context, p string) error {
	if err := f.F.Hit("rm -r " + p); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Dirs, p)
	for k := range f.Data {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(f.Data, k)
		}
	}
	return nil
}

func (f *Files) CopyTree(_ context.Context, src, dst string) error {
	if err := f.F.Hit("copytree " + src + " " + dst); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Dirs[dst] = true
	for _, rel := range f.Trees[src] {
		f.Data[path.Join(dst, rel)] = []byte("seed:" + path.Join(src, rel))
	}
	return nil
}

func (f *Files) SHA256(_ context.Context, p string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.Data[p]
	if !ok {
		return "", fmt.Errorf("%s: %w", p, os.ErrNotExist)
	}
	h := sha256.Sum256(d)
	return hex.EncodeToString(h[:]), nil
}

// Put stores a file the way a scripted tool does, under the lock the daemon's
// goroutines take.
func (f *Files) Put(p string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Data[p] = append([]byte(nil), data...)
}

// Get reads a stored file.
func (f *Files) Get(p string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.Data[p]
	return append([]byte(nil), d...), ok
}

// Paths lists stored file paths, sorted.
func (f *Files) Paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.Data {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Jails is a fake jail runtime.
type Jails struct {
	F       *fault.Injector
	mu      sync.Mutex
	Up      map[string]bool
	Release string
	// OnStart runs before a start succeeds, to let tests check the pool.
	OnStart func(name string) error
	// OnStop runs before a stop succeeds; an error from it is the stop's (jail(8) refusing to remove the jail).
	OnStop func(name string) error
	// ExecFn answers commands run inside a jail (health checks).
	ExecFn func(name string, argv []string) ([]byte, error)
	// Never makes Running report false after Start (readiness timeout).
	Never bool
}

func NewJails(f *fault.Injector) *Jails {
	return &Jails{F: f, Up: map[string]bool{}, Release: "15.0-RELEASE"}
}

func (j *Jails) Start(_ context.Context, name string) error {
	if err := j.F.Hit("jail start " + name); err != nil {
		return err
	}
	if j.OnStart != nil {
		if err := j.OnStart(name); err != nil {
			return err
		}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Up[name] {
		return errors.New("jail already running")
	}
	j.Up[name] = true
	return nil
}

func (j *Jails) Stop(_ context.Context, name string) error {
	if err := j.F.Hit("jail stop " + name); err != nil {
		return err
	}
	if j.OnStop != nil {
		if err := j.OnStop(name); err != nil {
			return err
		}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.Up, name)
	return nil
}

func (j *Jails) Running(_ context.Context, name string) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Up[name] && !j.Never, nil
}

func (j *Jails) Exec(_ context.Context, name string, argv []string) ([]byte, error) {
	if err := j.F.Hit("jexec " + name + " " + strings.Join(argv, " ")); err != nil {
		return nil, err
	}
	if j.ExecFn != nil {
		return j.ExecFn(name, argv)
	}
	return nil, nil
}

func (j *Jails) HostRelease(context.Context) (string, error) { return j.Release, nil }

// IsUp reports the raw running flag.
func (j *Jails) IsUp(name string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Up[name]
}

// Hooks records render hook calls. The parameter type is generic so the same
// fake serves the lifecycle Hooks interface (see Hooks adapters in tests).
type Hooks struct {
	F   *fault.Injector
	Log []string
	mu  sync.Mutex
}

func (h *Hooks) rec(s string) error {
	if err := h.F.Hit(s); err != nil {
		return err
	}
	h.mu.Lock()
	h.Log = append(h.Log, s)
	h.mu.Unlock()
	return nil
}
func (h *Hooks) PreStart(_ context.Context, name string) error { return h.rec("prestart " + name) }
func (h *Hooks) PostStop(_ context.Context, name string) error { return h.rec("poststop " + name) }
func (h *Hooks) Remove(_ context.Context, name string) error   { return h.rec("remove " + name) }

// SeedKeys records the copy of the host keys into an image root.
func (f *Files) SeedKeys(_ context.Context, root string) error {
	if err := f.F.Hit("seedkeys " + root); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Dirs[path.Join(root, "usr/share/keys")] = true
	return nil
}

// DNSUnbound is off in the fake: no helper, no unbound.
func (f *Files) DNSUnbound(context.Context, bool) (mounts.UnboundState, error) {
	return mounts.UnboundState{}, nil
}

// HealNetwork destroys nothing: the fake has no interfaces.
func (f *Files) HealNetwork(context.Context) (mounts.NetHealed, error) {
	return mounts.NetHealed{}, nil
}
