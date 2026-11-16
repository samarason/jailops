package service

import (
	"context"
	"encoding/json"
	"jailops.net/jailops/internal/supervise"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"jailops.net/jailops/internal/hostdir"
	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// A volume with a path is a directory of the host: a mount (a storage box, a share, a disk of its own) that the host
// operator allows with admin-host-mount in priv.conf and that jails attach with nullfs like any volume. JailOps makes
// no dataset for it and keeps nothing of its files: it is not snapshotted, rolled back, resized, encrypted or backed
// up. What it adds is to know when the mount is gone (docs/storage.md, "Host directories").

// refuseHostDir is what an operation that needs a dataset answers for a volume of a host directory.
func refuseHostDir(name, what string) error {
	return invalid("volume %q is a directory of the host: %s", name, what).
		WithHint("its files are the host's; snapshot, copy or back them up there")
}

// requireGlobalAdminFor refuses an actor that is not a global administrator.
func requireGlobalAdminFor(ctx context.Context, what string) error {
	if isGlobalAdmin(ActorFrom(ctx)) {
		return nil
	}
	return api.Errorf(api.CodeForbidden, "%s is granted by a global administrator only", what).
		WithHint("the host operator also lists the allowed directories with admin-host-mount in priv.conf")
}

// hostDirProbes lets one probe of a path be on its way at a time. A mount that hangs holds the helper request of its
// probe until it answers (the syscall cannot be interrupted), and the helper has a fixed number of requests: a second
// look at the same path joins the wait of the first one and sends no new request, so a dead share costs one request, not
// one per look.
type hostDirProbes struct {
	mu     sync.Mutex
	flight map[string]*hostDirFlight
}

type hostDirFlight struct {
	done chan struct{}
	p    hostdir.Probe
	err  error
}

// ReadTimeout is how long a read (a list, a show, doctor) waits for a probe: the answer of the watch is used when it is
// fresh, and a directory that does not answer in this time is reported lost, as the watch does.
// the waits are atomic: a test shortens them while the watch of a daemon it started earlier may still be looking
var (
	hostDirReadTimeout  atomic.Int64
	hostDirProbeTimeout atomic.Int64
)

func init() {
	hostDirReadTimeout.Store(int64(3 * time.Second))
	hostDirProbeTimeout.Store(int64(hostdir.Timeout))
}

// probeHostDir looks at the directory of a host-directory volume through the helper, waiting at most hostdir.Timeout.
func (s *Service) probeHostDir(ctx context.Context, spec api.VolumeSpec) (usable bool, detail string, err error) {
	return s.probeHostDirWithin(ctx, spec, time.Duration(hostDirProbeTimeout.Load()))
}

func (s *Service) probeHostDirWithin(ctx context.Context, spec api.VolumeSpec, wait time.Duration) (usable bool, detail string, err error) {
	if s.d.Files == nil {
		return false, "", api.Errorf(api.CodeUnsupported, "host directories are not available on this host")
	}
	write := spec.Watch && spec.Probe == api.VolumeProbeWrite
	key := spec.Path
	if write {
		key += "\x00write"
	}
	pr := &s.hostDirProbes
	pr.mu.Lock()
	f, running := pr.flight[key]
	if !running {
		f = &hostDirFlight{done: make(chan struct{})}
		if pr.flight == nil {
			pr.flight = map[string]*hostDirFlight{}
		}
		pr.flight[key] = f
		// the probe outlives the caller that started it: the next look joins it
		pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		go func() {
			defer cancel()
			if err := supervise.Guard(s.log, "host-directory-probe", func() { f.p, f.err = s.d.Files.ProbeSource(pctx, spec.Path, write) }); err != nil {
				f.err = err
			}
			pr.mu.Lock()
			delete(pr.flight, key)
			pr.mu.Unlock()
			close(f.done)
		}()
	}
	pr.mu.Unlock()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-f.done:
		if f.err != nil {
			return false, "", f.err
		}
		return f.p.Usable(write), f.p.Lost(write), nil
	case <-t.C:
		return false, "the directory does not answer", nil
	case <-ctx.Done():
		return false, "", ctx.Err()
	}
}

// hostDirState is the state a volume's directory is in now: "ok" or "lost" and, when it is lost, why. A directory the
// helper will not look at (it is not below an admin-host-mount directory any more) is lost, with that as the reason.
func (s *Service) hostDirState(ctx context.Context, spec api.VolumeSpec) (state, detail string) {
	ok, detail, err := s.probeHostDir(ctx, spec)
	switch {
	case err != nil:
		return api.VolumeStateLost, err.Error()
	case ok:
		return api.VolumeStateOK, ""
	}
	return api.VolumeStateLost, detail
}

// hostDirStateRead is hostDirState for the reads (a list, a show, doctor): the answer of the watch when it is fresh,
// else one short look. A list never waits for every directory in turn.
func (s *Service) hostDirStateRead(ctx context.Context, o object[api.VolumeSpec]) (state, detail string) {
	if o.Spec.Watch {
		s.hostDirs.mu.Lock()
		seen, ok := s.hostDirs.last[o.Meta.Project+"/"+o.Meta.Name]
		s.hostDirs.mu.Unlock()
		if ok && time.Since(seen.at) < 3*s.hostDirTick()+hostdir.Timeout {
			return seen.state, seen.detail
		}
	}
	ok, detail, err := s.probeHostDirWithin(ctx, o.Spec, time.Duration(hostDirReadTimeout.Load()))
	switch {
	case err != nil:
		return api.VolumeStateLost, err.Error()
	case ok:
		return api.VolumeStateOK, ""
	}
	return api.VolumeStateLost, detail
}

func (s *Service) hostDirTick() time.Duration {
	if s.d.VolumeWatchTick > 0 {
		return s.d.VolumeWatchTick
	}
	return defaultHostDirWatchTick
}

// hostDirUsers lists the jails of a project that attach a volume, with the way they attach it.
func (s *Service) hostDirUsers(project, volume string) []string {
	var out []string
	for _, u := range s.volumeUses(project, volume) {
		out = append(out, u.Jail)
	}
	return out
}

// ---- the watch ----

// hostDirSeen is what the watch saw of a volume last.
type hostDirSeen struct {
	state, detail string
	at            time.Time
}

// hostDirWatch remembers the state the watch saw last, to act on a change and not on a state, and the volumes whose
// jails still have to be given their mount again.
type hostDirWatch struct {
	mu      sync.Mutex
	last    map[string]hostDirSeen // project/volume -> what was seen
	remount map[string]bool        // project/volume -> the users of the volume are not on the mount yet
	started bool                   // the first round has run
}

const defaultHostDirWatchTick = 15 * time.Second

// hostDirLoop checks every watched volume of a host directory every few seconds.
func (s *Service) hostDirLoop(ctx context.Context) {
	tick := s.hostDirTick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(tick):
		}
		s.WatchHostDirs(ctx)
	}
}

// hostDirLostFile is where the watch keeps the volumes that were lost when it last looked, so that a daemon that
// starts after a box was lost and came back (a restart takes seconds, an upgrade longer) still gives the jails on the
// stale mount the new one.
func (s *Service) hostDirLostFile() string {
	if s.d.StateDir == "" {
		return ""
	}
	return filepath.Join(s.d.StateDir, "host-dir-lost.json")
}

func (s *Service) loadHostDirLost() map[string]bool {
	out := map[string]bool{}
	f := s.hostDirLostFile()
	if f == "" {
		return out
	}
	raw, err := os.ReadFile(f)
	if err != nil {
		return out
	}
	var keys []string
	if json.Unmarshal(raw, &keys) == nil {
		for _, k := range keys {
			out[k] = true
		}
	}
	return out
}

func (s *Service) saveHostDirLost(lost map[string]bool) {
	f := s.hostDirLostFile()
	if f == "" {
		return
	}
	keys := make([]string, 0, len(lost))
	for k := range lost {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	raw, _ := json.Marshal(keys)
	tmp := f + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, f)
	}
}

// WatchHostDirs is one round of the watch (the loop runs it; tests call it): it looks at every watched volume of a host
// directory, at most a few at a time, and acts on the ones whose state changed since the last round. A directory that
// came back gives its jails their mount again, and a remount that failed is tried again every round.
func (s *Service) WatchHostDirs(ctx context.Context) {
	if s.requireHost("volumes") != nil {
		return
	}
	objs, err := s.volKind.listAll()
	if err != nil {
		return
	}
	sys := WithActor(ctx, Actor{Name: "volume-watch", Kind: "system", Perm: api.PermAdmin, Global: true})
	type look struct {
		o             object[api.VolumeSpec]
		key           string
		state, detail string
	}
	var looks []*look
	for _, o := range objs {
		if o.Spec.IsHostDir() && o.Spec.Watch {
			looks = append(looks, &look{o: o, key: o.Meta.Project + "/" + o.Meta.Name})
		}
	}
	// the looks run side by side: a share that does not answer holds its own look for the time out, not the others'
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, l := range looks {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			defer func() { supervise.Report(s.log, "host-directory-look", recover()) }()
			l.state, l.detail = s.hostDirState(sys, l.o.Spec)
		}()
	}
	wg.Wait()

	s.hostDirs.mu.Lock()
	first := !s.hostDirs.started
	s.hostDirs.started = true
	s.hostDirs.mu.Unlock()
	var lostBefore map[string]bool
	if first {
		lostBefore = s.loadHostDirLost()
	}
	seen := map[string]bool{}
	nowLost := map[string]bool{}
	for _, l := range looks {
		o, key, state, detail := l.o, l.key, l.state, l.detail
		seen[key] = true
		if state == api.VolumeStateLost {
			nowLost[key] = true
		}
		s.hostDirs.mu.Lock()
		if s.hostDirs.last == nil {
			s.hostDirs.last = map[string]hostDirSeen{}
		}
		prev, known := s.hostDirs.last[key]
		s.hostDirs.last[key] = hostDirSeen{state: state, detail: detail, at: time.Now()}
		pending := s.hostDirs.remount[key]
		s.hostDirs.mu.Unlock()
		switch {
		case state == api.VolumeStateLost && !(known && prev.state == state):
			s.log.Warn("the mount of a volume is lost", "project", o.Meta.Project, "volume", o.Meta.Name, "path", o.Spec.Path, "detail", detail)
			s.emitIn(sys, o.Meta.Project, "volume-lost", "/api/v1/volumes/"+o.Meta.Name)
			if o.Spec.OnLoss == api.VolumeOnLossStop {
				s.stopHostDirUsers(sys, o)
			}
		case state == api.VolumeStateOK && known && prev.state != state:
			s.log.Info("the mount of a volume is back", "project", o.Meta.Project, "volume", o.Meta.Name, "path", o.Spec.Path)
			s.emitIn(sys, o.Meta.Project, "volume-restored", "/api/v1/volumes/"+o.Meta.Name)
			s.setRemount(key, !s.remountHostDirUsers(sys, o))
		case state == api.VolumeStateOK && !known && lostBefore[key]:
			// lost when the last daemon looked, and back now: the jails that run are on the stale mount
			s.log.Info("the mount of a volume is back since the daemon last looked", "project", o.Meta.Project, "volume", o.Meta.Name, "path", o.Spec.Path)
			s.emitIn(sys, o.Meta.Project, "volume-restored", "/api/v1/volumes/"+o.Meta.Name)
			s.setRemount(key, !s.remountHostDirUsers(sys, o))
		case state == api.VolumeStateOK && pending:
			s.setRemount(key, !s.remountHostDirUsers(sys, o))
		}
	}
	s.hostDirs.mu.Lock()
	for k := range s.hostDirs.last {
		if !seen[k] {
			delete(s.hostDirs.last, k)
			delete(s.hostDirs.remount, k)
		}
	}
	s.hostDirs.mu.Unlock()
	if first || len(nowLost) != len(lostBefore) || !s.sameLost(nowLost, lostBefore) {
		s.saveHostDirLost(nowLost)
	}
}

func (s *Service) sameLost(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// setRemount remembers that the users of a volume still have to be given their mount (or that they have it now).
func (s *Service) setRemount(key string, needed bool) {
	s.hostDirs.mu.Lock()
	defer s.hostDirs.mu.Unlock()
	if needed {
		if s.hostDirs.remount == nil {
			s.hostDirs.remount = map[string]bool{}
		}
		s.hostDirs.remount[key] = true
		return
	}
	delete(s.hostDirs.remount, key)
}

// runningUsers lists the keys of the running jails of a project that attach a volume.
func (s *Service) runningHostDirUsers(ctx context.Context, project, volume string) []string {
	var keys []string
	for _, jail := range s.hostDirUsers(project, volume) {
		k, _ := validate.QualifiedName(project, jail)
		if j, err := s.getByKey(ctx, k); err == nil && j.Status.Power == api.PowerRunning {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// stopHostDirUsers stops the running jails that attach a volume whose mount is lost. They stay stopped: a start is
// refused while the mount is lost, and the operator starts them when it is back.
func (s *Service) stopHostDirUsers(ctx context.Context, o object[api.VolumeSpec]) {
	for _, key := range s.runningHostDirUsers(ctx, o.Meta.Project, o.Meta.Name) {
		_, jail := validate.SplitQualified(key)
		if err := s.stopForLoss(ctx, o.Meta.Project, jail); err != nil {
			s.log.Warn("stopping a jail whose volume lost its mount failed", "project", o.Meta.Project, "jail", jail, "volume", o.Meta.Name, "err", err)
			continue
		}
		s.log.Warn("a jail was stopped: its volume lost its mount", "project", o.Meta.Project, "jail", jail, "volume", o.Meta.Name)
	}
}

// remountHostDirUsers gives the running jails that attach a volume their mount again once the directory is back: a
// nullfs mount over a mount that went away does not see the new one, so the old mount is removed and made again. It
// says whether every jail has its mount.
func (s *Service) remountHostDirUsers(ctx context.Context, o object[api.VolumeSpec]) bool {
	all := true
	for _, key := range s.runningHostDirUsers(ctx, o.Meta.Project, o.Meta.Name) {
		_, jail := validate.SplitQualified(key)
		j, err := s.jailSnapshot(key)
		if err != nil {
			continue
		}
		for _, v := range s.effective(j).Volumes {
			if v.Name != o.Meta.Name {
				continue
			}
			if err := s.life.RemountHostDir(ctx, key, lifecycle.Attached{Name: v.Name, HostDir: true, Mountpoint: o.Spec.Path, Path: v.Mount, ReadOnly: v.ReadOnly}); err != nil {
				s.log.Warn("giving a jail its host directory again failed", "project", o.Meta.Project, "jail", jail, "volume", o.Meta.Name, "err", err)
				all = false
				continue
			}
			s.emitIn(ctx, o.Meta.Project, "volume-remounted", "/api/v1/jails/"+jail)
		}
	}
	return all
}

// hostDirAdmission refuses a project operator that attaches a volume of a host directory the jail did not have: only a
// global administrator gives jails the host's directories. The volumes already attached stay.
func (s *Service) hostDirAdmission(ctx context.Context, project string, now, was []api.VolumeAttach) error {
	if isGlobalAdmin(ActorFrom(ctx)) {
		return nil
	}
	for _, v := range now {
		if slices.ContainsFunc(was, func(w api.VolumeAttach) bool { return w.Name == v.Name }) {
			continue
		}
		if o, err := s.volKind.p(project).get(v.Name); err == nil && o.Spec.IsHostDir() {
			return api.Errorf(api.CodeForbidden, "volume %q is a directory of the host: attaching it is granted by a global administrator only", v.Name).
				WithHint("the volume's files are the host's, outside the project's storage")
		}
	}
	return nil
}

// stopForLoss stops a jail the way an operator's stop does, and waits for it.
func (s *Service) stopForLoss(ctx context.Context, project, jail string) error {
	ctx = WithProject(ctx, project)
	op, err := s.JailAction(ctx, jail, api.JailAction{Action: "stop"})
	if err != nil {
		return err
	}
	return s.waitOp(ctx, op, "stopping "+jail)
}

// createHostDirVolume makes a volume of a host directory, as an operation whose result is the Volume. Only a global
// administrator does, and only for a directory that is on a mount now: a volume of a lost mount is a mistake.
func (s *Service) createHostDirVolume(ctx context.Context, p project, in api.VolumeCreate, spec api.VolumeSpec) (api.Operation, error) {
	if in.Passphrase != "" {
		return api.Operation{}, invalid("a volume of a host directory is not encrypted: it has no passphrase")
	}
	if err := requireGlobalAdminFor(ctx, "a volume that is a directory of the host"); err != nil {
		return api.Operation{}, err
	}
	proj, name := p.Meta.Name, in.Metadata.Name
	ks := s.volKind.p(proj)
	if err := ks.notTaken(name); err != nil {
		return api.Operation{}, err
	}
	meta := api.ObjectMeta{Name: name, Project: proj, Labels: in.Metadata.Labels, ManagedBy: in.Metadata.ManagedBy}
	return s.Submit(ctx, OpSpec{
		Description: "Create volume " + name, Locks: []string{volumeLock(proj, name)}, Project: proj,
		Resources: map[string][]string{"volumes": {"/api/v1/volumes/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			ok, detail, err := s.probeHostDir(ctx, spec)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, invalid("%s is not usable: %s", spec.Path, detail).
					WithHint("mount it first; the mount point has to lie below a directory of admin-host-mount in priv.conf")
			}
			o, err := ks.create(ctx, meta, spec)
			if err != nil {
				return nil, err
			}
			return s.volumeView(ctx, proj, o), nil
		},
	})
}
