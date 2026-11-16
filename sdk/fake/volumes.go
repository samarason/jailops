package fake

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

// Volumes (extension volumes): objects of a project that jails attach by name. The fake keeps the passphrase of each
// encrypted volume, starts it unlocked, and locks it again on RebootHost; a jail with a locked volume attached is
// locked. Five wrong passphrases in a row lock unlocks out for 30 seconds of the fake's clock, as the daemon does.
// The request log never holds a passphrase: secretFields are replaced before a body is recorded.
type fakeVolumes struct {
	pass   map[string]string // by volume key "<project>/<name>"
	locked map[string]bool
	fails  map[string]int
	until  map[string]time.Time
	// lostDirs are the directories of the host whose mount is gone (LoseHostDir): a volume of a host directory is lost
	// while its path is in it.
	lostDirs map[string]bool
}

func (v *fakeVolumes) init() {
	if v.pass == nil {
		v.pass, v.locked, v.fails, v.until = map[string]string{}, map[string]bool{}, map[string]int{}, map[string]time.Time{}
	}
	if v.lostDirs == nil {
		v.lostDirs = map[string]bool{}
	}
}

// secretFields are the request fields that carry a passphrase.
var secretFields = []string{"passphrase", "old_passphrase", "new_passphrase"}

// redactBody replaces the passphrases of a JSON request body.
func redactBody(b []byte) []byte {
	if len(b) == 0 || !strings.Contains(string(b), "passphrase") {
		return b
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return []byte(`"unreadable body withheld"`)
	}
	for _, f := range secretFields {
		if _, ok := m[f]; ok {
			m[f] = json.RawMessage(`"redacted"`)
		}
	}
	out, _ := json.Marshal(m)
	return out
}

func (s *Server) setupVolumes() {
	k := s.volumes
	k.scoped = true
	k.asyncCreate, k.asyncDelete = true, true
	k.noCreate = true // POST is volumeCreate: the body may carry a passphrase
	k.validate = func(v, old *api.Volume) *api.Error {
		spec, e := s.checkVolumeSpec(v.Metadata.Project, v.Metadata.Name, v.Spec)
		if e != nil {
			return e
		}
		if old != nil {
			for _, f := range []struct {
				what    string
				changed bool
			}{{"path", spec.Path != old.Spec.Path}, {"storage", spec.Storage != old.Spec.Storage}, {"uid", spec.UID != old.Spec.UID}, {"gid", spec.GID != old.Spec.GID},
				{"mode", spec.Mode != old.Spec.Mode}, {"encrypted", spec.Encrypted != old.Spec.Encrypted}} {
				if f.changed {
					return api.Errorf(api.CodeInvalid, "the %s of a volume cannot change", f.what)
				}
			}
		}
		v.Spec = spec
		return nil
	}
	k.beforeDelete = func(v *api.Volume) *api.Error {
		if uses := s.volumeUses(v.Metadata.Project, v.Metadata.Name); len(uses) > 0 {
			return api.Errorf(api.CodeBusy, "volume %q is attached to %s: detach it before it is deleted", v.Metadata.Name, uses[0].Jail).
				WithHint("jailops volume detach " + uses[0].Jail + " " + v.Metadata.Name)
		}
		return nil
	}
	k.onDelete = func(v *api.Volume) {
		key := v.Metadata.Project + "/" + v.Metadata.Name
		delete(s.volSnaps, key)
		s.vol.init()
		delete(s.vol.pass, key)
		delete(s.vol.locked, key)
	}
	k.decorate = func(v *api.Volume) {
		key := v.Metadata.Project + "/" + v.Metadata.Name
		if v.Spec.IsHostDir() {
			v.Status.Mountpoint = v.Spec.Path
			v.Status.State = api.VolumeStateOK
			if s.vol.lostDirs[v.Spec.Path] {
				v.Status.State, v.Status.Detail = api.VolumeStateLost, "the directory is not on a mount"
			}
			v.Status.AttachedTo = s.volumeUses(v.Metadata.Project, v.Metadata.Name)
			return
		}
		v.Status.Dataset = "tank/jailops/projects/" + v.Metadata.Project + "/volumes/" + v.Metadata.Name
		v.Status.Mountpoint = "/jailops/projects/" + v.Metadata.Project + "/volumes/" + v.Metadata.Name
		v.Status.AttachedTo = s.volumeUses(v.Metadata.Project, v.Metadata.Name)
		v.Status.Locked = s.vol.locked[key]
		var rw []string
		for _, u := range v.Status.AttachedTo {
			if !u.ReadOnly {
				rw = append(rw, u.Jail)
			}
		}
		if len(rw) > 1 {
			v.Status.Warnings = append(v.Status.Warnings, "writable in more than one jail ("+strings.Join(rw, ", ")+"): the jails share the files and their locking")
		}
	}
}

// hostDirRoot is the directory the fake host allows jails to be given directories below (admin-host-mount).
const hostDirRoot = "/mnt"

// LoseHostDir takes the mount of a directory of the host away, as a storage box going away does: the volumes with that
// path are lost, the daemon's watch says so, a volume with on-loss stop stops the running jails that attach it.
func (s *Server) LoseHostDir(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vol.init()
	if s.vol.lostDirs[path] {
		return
	}
	s.vol.lostDirs[path] = true
	for _, k := range slices.Sorted(maps.Keys(s.volumes.items)) {
		v := s.volumes.items[k]
		if v.Spec.Path != path || !v.Spec.Watch {
			continue
		}
		s.emitIn(v.Metadata.Project, "volume-lost", "/api/v1/volumes/"+v.Metadata.Name)
		if v.Spec.OnLoss != api.VolumeOnLossStop {
			continue
		}
		for _, u := range s.volumeUses(v.Metadata.Project, v.Metadata.Name) {
			if j := s.jails.items[v.Metadata.Project+"/"+u.Jail]; j != nil && j.Status.Power == api.PowerRunning {
				j.Status.Power, j.Status.JID, j.Status.StartedAt, j.Status.Addresses = api.PowerStopped, 0, time.Time{}, nil
				s.emitIn(v.Metadata.Project, "jail-stopped", "/api/v1/jails/"+u.Jail)
			}
		}
	}
}

// RestoreHostDir mounts a directory of the host again: the watch says so, and the running jails that kept running get
// their mount again.
func (s *Server) RestoreHostDir(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vol.init()
	if !s.vol.lostDirs[path] {
		return
	}
	delete(s.vol.lostDirs, path)
	for _, k := range slices.Sorted(maps.Keys(s.volumes.items)) {
		v := s.volumes.items[k]
		if v.Spec.Path != path || !v.Spec.Watch {
			continue
		}
		s.emitIn(v.Metadata.Project, "volume-restored", "/api/v1/volumes/"+v.Metadata.Name)
		for _, u := range s.volumeUses(v.Metadata.Project, v.Metadata.Name) {
			if j := s.jails.items[v.Metadata.Project+"/"+u.Jail]; j != nil && j.Status.Power == api.PowerRunning {
				s.emitIn(v.Metadata.Project, "volume-remounted", "/api/v1/jails/"+u.Jail)
			}
		}
	}
}

func parseVolumeMode(m string) (uint32, *api.Error) {
	if m == "" {
		return 0o755, nil
	}
	v, err := strconv.ParseUint(m, 8, 32)
	if err != nil || v > 0o777 {
		return 0, api.Errorf(api.CodeInvalid, "mode %q is not an octal mode up to 0777", m)
	}
	return uint32(v), nil
}

// checkVolumeSpec resolves the storage and the mode of a volume. s.mu is held.
func (s *Server) checkVolumeSpec(project, name string, spec api.VolumeSpec) (api.VolumeSpec, *api.Error) {
	if !validName(name) || len(name) > 32 {
		return spec, api.Errorf(api.CodeInvalid, "invalid volume name %q", name)
	}
	if spec.IsHostDir() || spec.Watch || spec.Probe != "" || spec.OnLoss != "" {
		out, err := api.CheckHostDirVolume(spec)
		if err != nil {
			return spec, err.(*api.Error)
		}
		if !strings.HasPrefix(out.Path, hostDirRoot+"/") {
			return out, api.Errorf(api.CodeForbidden, "%q is not below a directory of admin-host-mount in priv.conf", out.Path)
		}
		return out, nil
	}
	if spec.UID < 0 || spec.GID < 0 {
		return spec, api.Errorf(api.CodeInvalid, "uid and gid are numbers from 0")
	}
	mode, e := parseVolumeMode(spec.Mode)
	if e != nil {
		return spec, e
	}
	spec.Mode = strconv.FormatUint(uint64(mode)+0o10000, 8)[1:]
	if spec.Size != "" {
		if _, err := strconv.ParseUint(strings.TrimRight(spec.Size, "KMGTkmgt"), 10, 64); err != nil {
			return spec, api.Errorf(api.CodeInvalid, "bad volume size %q", spec.Size)
		}
	}
	p := s.project(project)
	if p == nil {
		return spec, notFound("project", project)
	}
	if spec.Storage == "" {
		if spec.Storage = p.Spec.SoleStorage(); spec.Storage == "" {
			return spec, api.Errorf(api.CodeInvalid, "a volume needs a storage: name one with --storage NAME")
		}
	}
	if !granted(s.storGrants(p), spec.Storage) {
		return spec, api.Errorf(api.CodeForbidden, "storage %q is not granted to project %q", spec.Storage, project)
	}
	if s.storages.items[spec.Storage] == nil {
		return spec, notFound("storage", spec.Storage)
	}
	return spec, nil
}

// volumeUses lists the jails of a project that attach a volume. s.mu is held.
func (s *Server) volumeUses(project, name string) []api.VolumeUse {
	var out []api.VolumeUse
	for _, k := range slices.Sorted(maps.Keys(s.jails.items)) {
		j := s.jails.items[k]
		if j.Metadata.Project != project {
			continue
		}
		for _, v := range j.Spec.Volumes {
			if v.Name == name {
				out = append(out, api.VolumeUse{Jail: j.Metadata.Name, Mount: v.Mount, ReadOnly: v.ReadOnly})
			}
		}
	}
	return out
}

// checkAttachments checks the volumes of a jail the way the daemon does. s.mu is held.
func (s *Server) checkAttachments(j, old *api.Jail) *api.Error {
	if old != nil && sameVolumes(j.Spec.Volumes, old.Spec.Volumes) {
		return nil
	}
	if old != nil && old.Status.Power == api.PowerRunning {
		return api.Errorf(api.CodeBusy, "jail %q is running: volumes are attached and detached while it is stopped", j.Metadata.Name).WithHint("jailops stop " + j.Metadata.Name)
	}
	seenName, seenMount := map[string]bool{}, map[string]bool{}
	for _, a := range j.Spec.Volumes {
		switch {
		case !strings.HasPrefix(a.Mount, "/") || a.Mount == "/" || strings.Contains(a.Mount, ".."):
			return api.Errorf(api.CodeInvalid, "volume %q has a bad mount path %q", a.Name, a.Mount)
		case seenName[a.Name]:
			return api.Errorf(api.CodeInvalid, "volume %q is attached twice", a.Name)
		case seenMount[a.Mount]:
			return api.Errorf(api.CodeInvalid, "duplicate mount point %q", a.Mount)
		}
		seenName[a.Name], seenMount[a.Mount] = true, true
		v := s.volumes.items[j.Metadata.Project+"/"+a.Name]
		if v == nil {
			return api.Errorf(api.CodeNotFound, "volume %q does not exist in project %q", a.Name, j.Metadata.Project).WithHint("jailops volume create " + a.Name)
		}
		if v.Spec.Encrypted {
			for _, u := range s.volumeUses(j.Metadata.Project, a.Name) {
				if u.Jail != j.Metadata.Name {
					return api.Errorf(api.CodeConflict, "volume %q is encrypted and attached to jail %q already: an encrypted volume is attached to one jail", a.Name, u.Jail)
				}
			}
		}
	}
	return nil
}

// sameVolumes compares two lists of attachments; nil and empty are the same.
func sameVolumes(a, b []api.VolumeAttach) bool {
	return (len(a) == 0 && len(b) == 0) || jsonSame(a, b)
}

// refreshLocked sets what the jails say about the locked volumes they attach. s.mu is held.
func (s *Server) refreshLocked() {
	s.vol.init()
	for _, j := range s.jails.items {
		var locked []string
		for _, a := range j.Spec.Volumes {
			if s.vol.locked[j.Metadata.Project+"/"+a.Name] {
				locked = append(locked, a.Name)
			}
		}
		j.Status.Locked = locked
		switch {
		case len(locked) > 0 && j.Status.Power != api.PowerRunning:
			j.Status.Power = api.PowerLocked
		case len(locked) == 0 && j.Status.Power == api.PowerLocked:
			j.Status.Power = api.PowerStopped
		}
	}
}

// volumeCreate is POST /api/v1/volumes: a Volume with the passphrase of an encrypted one.
func (s *Server) volumeCreate(w http.ResponseWriter, r *http.Request) {
	in, e := decode[api.VolumeCreate](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	v := api.Volume{Metadata: in.Metadata, Spec: in.Spec}
	switch {
	case !v.Spec.Encrypted && in.Passphrase != "":
		writeErr(w, api.Errorf(api.CodeInvalid, "a passphrase was given but the volume is not encrypted"))
		return
	case v.Spec.Encrypted && in.Passphrase == "":
		writeErr(w, api.Errorf(api.CodeInvalid, "an encrypted volume needs a passphrase"))
		return
	case v.Spec.Encrypted:
		if err := api.CheckPassphrase(in.Passphrase); err != nil {
			writeErr(w, err.(*api.Error))
			return
		}
	}
	rp := s.volumes.doCreate(r, &v)
	if rp.err == nil && v.Spec.Encrypted {
		s.mu.Lock()
		s.vol.init()
		s.vol.pass[s.volumes.key(r, v.Metadata.Name)] = in.Passphrase
		s.vol.locked[s.volumes.key(r, v.Metadata.Name)] = false
		s.mu.Unlock()
	}
	s.respond(w, rp)
}

// RebootHost stops every jail and locks the encrypted volumes, as a host boot leaves them.
func (s *Server) RebootHost() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vol.init()
	for _, j := range s.jails.items {
		j.Status.Power, j.Status.JID, j.Status.StartedAt, j.Status.Addresses = api.PowerStopped, 0, time.Time{}, nil
	}
	for k, v := range s.volumes.items {
		if v.Spec.Encrypted {
			s.vol.locked[k] = true
		}
	}
	s.refreshLocked()
}

func (s *Server) volLockedOut(key string) *api.Error {
	s.vol.init()
	if t, ok := s.vol.until[key]; ok {
		if s.now().Before(t) {
			return api.Errorf(api.CodeRateLimited, "too many wrong passphrases for this volume").WithHint("wait 30s and try again")
		}
		delete(s.vol.until, key)
	}
	return nil
}

func (s *Server) volResult(key string, ok bool) {
	if ok {
		delete(s.vol.fails, key)
		return
	}
	s.vol.fails[key]++
	if s.vol.fails[key] >= 5 {
		delete(s.vol.fails, key)
		s.vol.until[key] = s.now().Add(30 * time.Second)
	}
}

// keyedVolume finds an encrypted volume for a key request. s.mu is held.
func (s *Server) keyedVolume(r *http.Request, name string) (string, *api.Volume, *api.Error) {
	key, v := s.volumes.find(r, name)
	if v == nil {
		return "", nil, notFound("volume", name)
	}
	if !v.Spec.Encrypted {
		return "", nil, api.Errorf(api.CodeInvalid, "volume %q is not encrypted", name)
	}
	return key, v, nil
}

func (s *Server) volumeUnlock(w http.ResponseWriter, r *http.Request) {
	u, e := decode[api.VolumeUnlock](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name, rc := r.PathValue("name"), s.info(r)
	s.mu.Lock()
	rp := func() reply {
		key, _, e := s.keyedVolume(r, name)
		if e != nil {
			return reply{err: e}
		}
		if u.Passphrase == "" {
			return reply{err: api.Errorf(api.CodeInvalid, "passphrase must be 1 to 512 bytes without a line break")}
		}
		if e := s.volLockedOut(key); e != nil {
			return reply{err: e}
		}
		op := s.startOp(rc.project, "volumes.unlock", "Unlock volume "+name, map[string][]string{"volumes": {"/api/v1/volumes/" + name}}, func() (any, *api.Error) {
			v := s.volumes.items[key]
			if v == nil {
				return nil, notFound("volume", name)
			}
			ok := s.vol.pass[key] == u.Passphrase
			s.volResult(key, ok)
			if !ok {
				return nil, api.Errorf(api.CodeBadPassphrase, "the passphrase is not correct")
			}
			s.vol.locked[key] = false
			s.refreshLocked()
			s.emitIn(rc.project, "volume-unlocked", "/api/v1/volumes/"+name)
			if u.Start {
				for _, use := range s.volumeUses(rc.project, name) {
					if j := s.jails.items[rc.project+"/"+use.Jail]; j != nil && j.Status.Power != api.PowerRunning {
						s.nextJID++
						j.Status.Power, j.Status.JID, j.Status.StartedAt = api.PowerRunning, s.nextJID, s.now()
						s.emitIn(rc.project, "jail-started", "/api/v1/jails/"+use.Jail)
					}
				}
			}
			c := clone(v)
			s.volumes.decorate(&c)
			return c, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) volumeLock(w http.ResponseWriter, r *http.Request) {
	name, rc := r.PathValue("name"), s.info(r)
	s.mu.Lock()
	rp := func() reply {
		key, _, e := s.keyedVolume(r, name)
		if e != nil {
			return reply{err: e}
		}
		op := s.startOp(rc.project, "volumes.lock", "Lock volume "+name, map[string][]string{"volumes": {"/api/v1/volumes/" + name}}, func() (any, *api.Error) {
			v := s.volumes.items[key]
			if v == nil {
				return nil, notFound("volume", name)
			}
			for _, use := range s.volumeUses(rc.project, name) {
				if j := s.jails.items[rc.project+"/"+use.Jail]; j != nil {
					j.Status.JID, j.Status.StartedAt, j.Status.Addresses, j.Status.Power = 0, time.Time{}, nil, api.PowerStopped
				}
			}
			s.vol.init()
			s.vol.locked[key] = true
			s.refreshLocked()
			s.emitIn(rc.project, "volume-locked", "/api/v1/volumes/"+name)
			c := clone(v)
			s.volumes.decorate(&c)
			return c, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) volumePassphrase(w http.ResponseWriter, r *http.Request) {
	pc, e := decode[api.VolumePassphraseChange](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name, rc := r.PathValue("name"), s.info(r)
	s.mu.Lock()
	rp := func() reply {
		key, v, e := s.keyedVolume(r, name)
		if e != nil {
			return reply{err: e}
		}
		if err := api.CheckPassphrase(pc.New); err != nil {
			return reply{err: err.(*api.Error)}
		}
		if s.vol.locked[key] {
			return reply{err: api.Errorf(api.CodeLocked, "volume %q is locked", name).WithHint("jailops volume unlock " + name)}
		}
		if e := s.volLockedOut(key); e != nil {
			return reply{err: e}
		}
		op := s.startOp(rc.project, "volumes.passphrase", "Change the passphrase of volume "+name, map[string][]string{"volumes": {"/api/v1/volumes/" + name}}, func() (any, *api.Error) {
			ok := s.vol.pass[key] == pc.Old
			s.volResult(key, ok)
			if !ok {
				return nil, api.Errorf(api.CodeBadPassphrase, "the passphrase is not correct")
			}
			s.vol.pass[key] = pc.New
			c := clone(v)
			s.volumes.decorate(&c)
			return c, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// ---- snapshots ----

func (s *Server) volSnapList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	key, v := s.volumes.find(r, name)
	if v != nil && v.Spec.IsHostDir() {
		s.mu.Unlock()
		writeErr(w, hostDirRefusal(name))
		return
	}
	out := []api.VolumeSnapshot{}
	for _, sn := range s.volSnaps[key] {
		out = append(out, clone(sn))
	}
	s.mu.Unlock()
	if v == nil {
		writeErr(w, notFound("volume", name))
		return
	}
	writeSync(w, 200, out)
}

func (s *Server) volSnapCreate(w http.ResponseWriter, r *http.Request) {
	req, e := decode[api.VolumeSnapshot](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name, rc := r.PathValue("name"), s.info(r)
	s.mu.Lock()
	rp := func() reply {
		key, v := s.volumes.find(r, name)
		if v == nil {
			return reply{err: notFound("volume", name)}
		}
		if v.Spec.IsHostDir() {
			return reply{err: hostDirRefusal(name)}
		}
		snap := req.Metadata.Name
		if snap == "" {
			snap = "snap-" + randHex(3)
		}
		if !validName(snap) {
			return reply{err: api.Errorf(api.CodeInvalid, "invalid snapshot name %q", snap)}
		}
		if slices.ContainsFunc(s.volSnaps[key], func(x *api.VolumeSnapshot) bool { return x.Metadata.Name == snap }) {
			return reply{err: api.Errorf(api.CodeAlreadyExists, "snapshot %q already exists", snap)}
		}
		op := s.startOp(rc.project, "volumes.snapshot", "Snapshot volume "+name, map[string][]string{"volumes": {"/api/v1/volumes/" + name}}, func() (any, *api.Error) {
			sn := &api.VolumeSnapshot{Metadata: api.ObjectMeta{Name: snap, Project: rc.project, Scope: api.ScopeHost, Host: s.uuid, Generation: 1, CreatedAt: s.now(), UpdatedAt: s.now()},
				Spec: api.VolumeSnapshotSpec{Volume: name, Comment: req.Spec.Comment}}
			s.volSnaps[key] = append(s.volSnaps[key], sn)
			s.emitIn(rc.project, "volume-snapshot-created", "/api/v1/volumes/"+name+"/snapshots/"+snap)
			return clone(sn), nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) volSnapDelete(w http.ResponseWriter, r *http.Request) {
	name, snap, rc := r.PathValue("name"), r.PathValue("snap"), s.info(r)
	s.mu.Lock()
	rp := func() reply {
		key, v := s.volumes.find(r, name)
		if v == nil {
			return reply{err: notFound("volume", name)}
		}
		if v.Spec.IsHostDir() {
			return reply{err: hostDirRefusal(name)}
		}
		if !slices.ContainsFunc(s.volSnaps[key], func(x *api.VolumeSnapshot) bool { return x.Metadata.Name == snap }) {
			return reply{err: notFound("snapshot", snap)}
		}
		op := s.startOp(rc.project, "volumes.snapshot-delete", "Delete snapshot "+snap, nil, func() (any, *api.Error) {
			s.volSnaps[key] = slices.DeleteFunc(s.volSnaps[key], func(x *api.VolumeSnapshot) bool { return x.Metadata.Name == snap })
			s.emitIn(rc.project, "volume-snapshot-deleted", "/api/v1/volumes/"+name+"/snapshots/"+snap)
			return nil, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) volRollback(w http.ResponseWriter, r *http.Request) {
	rb, e := decode[api.VolumeRollback](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name, rc := r.PathValue("name"), s.info(r)
	s.mu.Lock()
	rp := func() reply {
		key, v := s.volumes.find(r, name)
		if v == nil {
			return reply{err: notFound("volume", name)}
		}
		if v.Spec.IsHostDir() {
			return reply{err: hostDirRefusal(name)}
		}
		i := slices.IndexFunc(s.volSnaps[key], func(x *api.VolumeSnapshot) bool { return x.Metadata.Name == rb.Snapshot })
		switch {
		case rb.Snapshot == "":
			return reply{err: api.Errorf(api.CodeInvalid, "name the snapshot to roll back to")}
		case !rb.ConfirmDataLoss:
			return reply{err: api.Errorf(api.CodeInvalid, "a rollback discards what was written to the volume since the snapshot")}
		case i < 0:
			return reply{err: notFound("snapshot", rb.Snapshot)}
		}
		for _, u := range s.volumeUses(rc.project, name) {
			if j := s.jails.items[rc.project+"/"+u.Jail]; j != nil && j.Status.Power == api.PowerRunning {
				return reply{err: api.Errorf(api.CodeBusy, "jail %q has volume %q attached and is running: stop it before the volume is rolled back", u.Jail, name)}
			}
		}
		op := s.startOp(rc.project, "volumes.rollback", "Roll volume "+name+" back to "+rb.Snapshot, map[string][]string{"volumes": {"/api/v1/volumes/" + name}}, func() (any, *api.Error) {
			s.volSnaps[key] = s.volSnaps[key][:i+1]
			s.emitIn(rc.project, "volume-rolled-back", "/api/v1/volumes/"+name)
			c := clone(v)
			s.volumes.decorate(&c)
			return c, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// ---- what a jail attaches ----

func (s *Server) jailVolumes(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	_, j := s.jails.find(r, name)
	var out []api.VolumeAttach
	if j != nil {
		out = slices.Clone(j.Spec.Volumes)
	}
	s.mu.Unlock()
	if j == nil {
		writeErr(w, notFound("jail", name))
		return
	}
	if out == nil {
		out = []api.VolumeAttach{}
	}
	writeSync(w, 200, out)
}

func (s *Server) jailAttach(w http.ResponseWriter, r *http.Request) {
	req, e := decode[api.VolumeAttachRequest](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	s.changeAttachments(w, r, "Attach volume "+req.Volume+" to", func(j *api.Jail) *api.Error {
		if v := s.volumes.items[j.Metadata.Project+"/"+req.Volume]; v != nil && v.Spec.IsHostDir() && req.CopyExisting {
			return api.Errorf(api.CodeInvalid, "volume %q is a directory of the host: the files a jail has at the path are not copied into it", req.Volume)
		}
		if slices.ContainsFunc(j.Spec.Volumes, func(a api.VolumeAttach) bool { return a.Name == req.Volume }) {
			return api.Errorf(api.CodeAlreadyExists, "volume %q is attached to jail %q already", req.Volume, j.Metadata.Name)
		}
		j.Spec.Volumes = append(j.Spec.Volumes, api.VolumeAttach{Name: req.Volume, Mount: req.Mount, ReadOnly: req.ReadOnly})
		return nil
	})
}

func (s *Server) jailDetach(w http.ResponseWriter, r *http.Request) {
	volume := r.PathValue("volume")
	s.changeAttachments(w, r, "Detach volume "+volume+" from", func(j *api.Jail) *api.Error {
		i := slices.IndexFunc(j.Spec.Volumes, func(a api.VolumeAttach) bool { return a.Name == volume })
		if i < 0 {
			return notFound("volume attachment", volume)
		}
		j.Spec.Volumes = slices.Delete(j.Spec.Volumes, i, i+1)
		if len(j.Spec.Volumes) == 0 {
			j.Spec.Volumes = nil
		}
		return nil
	})
}

func (s *Server) changeAttachments(w http.ResponseWriter, r *http.Request, what string, change func(*api.Jail) *api.Error) {
	name, rc := r.PathValue("name"), s.info(r)
	s.mu.Lock()
	rp := func() reply {
		key, j := s.jails.find(r, name)
		if j == nil {
			return reply{err: notFound("jail", name)}
		}
		// the checks of the request itself: the same refusals come at once, not from the operation
		nj := clone(j)
		nj.Spec.Volumes = slices.Clone(j.Spec.Volumes)
		if e := change(&nj); e != nil {
			return reply{err: e}
		}
		if e := s.checkAttachments(&nj, j); e != nil {
			return reply{err: e}
		}
		op := s.startOp(rc.project, "jails.volumes", what+" jail "+name, map[string][]string{"jails": {"/api/v1/jails/" + name}}, func() (any, *api.Error) {
			cur := s.jails.items[key]
			if cur == nil {
				return nil, notFound("jail", name)
			}
			nj := clone(cur)
			nj.Spec.Volumes = slices.Clone(cur.Spec.Volumes)
			if e := change(&nj); e != nil {
				return nil, e
			}
			if e := s.checkAttachments(&nj, cur); e != nil {
				return nil, e
			}
			cur.Spec.Volumes = nj.Spec.Volumes
			cur.Metadata.Generation++
			cur.Metadata.UpdatedAt = s.now()
			s.refreshLocked()
			s.emitIn(cur.Metadata.Project, "jail-updated", "/api/v1/jails/"+name)
			return clone(cur), nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func hostDirRefusal(name string) *api.Error {
	return api.Errorf(api.CodeInvalid, "volume %q is a directory of the host: it has no snapshots, no key and no size of its own", name).
		WithHint("its files are the host's; snapshot, copy or back them up there")
}
