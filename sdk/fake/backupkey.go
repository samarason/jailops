package fake

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"

	"jailops.net/jailops/sdk/api"
)

// The fake's backup key: none until created, then escrowed when recipients
// are given. The recovery key is returned once and kept nowhere.

func (s *Server) handleBackupKeyStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	st := api.BackupKeyStatus{Status: "none"}
	if s.bkStatus != "" {
		st = api.BackupKeyStatus{Status: s.bkStatus, Domain: s.bkDomain, Path: "/var/db/jailops/backup.key"}
	}
	s.mu.Unlock()
	writeSync(w, 200, st)
}

func (s *Server) handleBackupKeyCreate(w http.ResponseWriter, r *http.Request) {
	in, e := decodeOptional[api.BackupKeyCreate](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	s.mu.Lock()
	rp := func() reply {
		if s.bkStatus != "" {
			return reply{err: api.Errorf(api.CodeAlreadyExists, "a backup key already exists").WithHint("rotating the key means a new repository")}
		}
		s.bkStatus, s.bkDomain = "present", "dom-"+randHex(4)
		out := api.BackupKeyCreated{Domain: s.bkDomain, RecoveryKey: "recovery-" + randHex(16)}
		if len(in.Recipients) > 0 {
			s.bkStatus, out.Escrowed = "escrowed", true
		}
		return reply{status: 201, meta: out, hdr: map[string]string{"Cache-Control": "no-store"}}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) handleBackupKeyEscrow(w http.ResponseWriter, r *http.Request) {
	in, e := decodeOptional[api.BackupKeyEscrow](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	s.mu.Lock()
	rp := func() reply {
		if s.bkStatus == "" {
			return reply{err: api.Errorf(api.CodeNotFound, "this host has no backup key").WithHint("create it with POST /api/v1/backup/key")}
		}
		if len(in.Recipients) == 0 {
			return reply{err: api.Errorf(api.CodeInvalid, "escrow needs at least one recovery recipient (an age public key)")}
		}
		s.bkStatus = "escrowed"
		return reply{status: 200, meta: api.BackupKeyStatus{Status: s.bkStatus, Domain: s.bkDomain, Path: "/var/db/jailops/backup.key"}}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// handleBackupRun runs a policy: one backup per selected jail of the policy's
// project, stored so that restore and list work against the fake.
func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	req, e := decode[api.BackupRunRequest](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	rc := s.info(r)
	s.mu.Lock()
	rp := func() reply {
		var pol *api.BackupPolicy
		for _, p := range s.bpolicies.items {
			if p.Metadata.Name == req.Policy {
				pol = p
			}
		}
		if pol == nil {
			return reply{err: notFound("backup policy", req.Policy)}
		}
		op := s.startOp("", "backups.run", "Run backup policy "+req.Policy, map[string][]string{"backup-policies": {"/api/v1/backup-policies/" + req.Policy}}, func() (any, *api.Error) {
			// Like the daemon: a missing or unescrowed key fails the run, not the request.
			if s.bkStatus == "" {
				return nil, api.Errorf(api.CodePlaintextDenied, "this host holds no backup key; nothing leaves the host unencrypted")
			}
			if s.bkStatus != "escrowed" {
				return nil, api.Errorf(api.CodeKeyNotEscrowed, "the backup key is not escrowed")
			}
			runs := []api.BackupRun{}
			var keys []string
			for k := range s.jails.items {
				keys = append(keys, k)
			}
			sortStrings(keys)
			for _, k := range keys {
				j := s.jails.items[k]
				if j.Metadata.Project != pol.Metadata.Project {
					continue
				}
				if !fakeSelects(pol.Spec.Selector, j.Metadata.Labels) {
					continue
				}
				now := s.now()
				snap := now.Format("20060102150405") + "-" + randHex(4)
				b := &api.Backup{Metadata: api.ObjectMeta{Name: snap, Project: j.Metadata.Project},
					Spec: api.BackupSpec{Jail: j.Metadata.Name, JailUUID: j.Metadata.UUID, HostUUID: s.uuid, Policy: req.Policy, Snapshot: snap, KeyDomain: s.bkDomain,
						Bundle: api.RestoreBundle{Spec: j.Spec, ImageGeneration: imageName(j.Spec.Image) + "#g1"}}}
				if len(pol.Spec.Targets) > 0 {
					b.Spec.Target = pol.Spec.Targets[0]
				}
				s.backups.insert(b, true)
				runs = append(runs, api.BackupRun{ID: "run-" + snap, Kind: "backup", Policy: req.Policy, Target: b.Spec.Target, Project: j.Metadata.Project, Jail: j.Metadata.Name,
					JailUUID: j.Metadata.UUID, Started: now, Finished: now, OK: true, Snapshot: snap})
			}
			runs = append(runs, s.backupVolumes(pol, *req, runs)...)
			return runs, nil
		})
		_ = rc
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func fakeSelects(sel, labels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	if _, all := sel["all"]; all {
		return true
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func sortStrings(l []string) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j] < l[j-1]; j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

// handleBackupVerify marks a backup verified.
func (s *Server) handleBackupVerify(w http.ResponseWriter, r *http.Request) {
	req, e := decodeOptional[api.BackupVerifyRequest](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	id := r.PathValue("id")
	s.mu.Lock()
	rp := func() reply {
		b := s.backups.items[id]
		if b == nil {
			return reply{err: notFound("backup", id)}
		}
		depth := req.Depth
		switch depth {
		case "":
			depth = "deep"
		case "deep", "extract", "full":
		default:
			return reply{err: api.Errorf(api.CodeInvalid, "depth must be deep, extract or full")}
		}
		op := s.startOp(b.Metadata.Project, "backups.verify", "Verify backup "+id, map[string][]string{"backups": {"/api/v1/backups/" + id}}, func() (any, *api.Error) {
			now := s.now()
			b.Status.Verified, b.Status.VerifiedAt = true, now
			return api.BackupRun{ID: "drill-" + id, Kind: "drill", Jail: b.Spec.Jail, JailUUID: b.Spec.JailUUID, Started: now, Finished: now, OK: true, Snapshot: b.Spec.Snapshot, Depth: depth}, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// decodeOptional decodes a body that may be empty.
func decodeOptional[T any](r *http.Request) (T, *api.Error) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil && !errors.Is(err, io.EOF) {
		return v, api.Errorf(api.CodeInvalid, "invalid request body: %v", err)
	}
	return v, nil
}

// backupVolumes backs up the volumes of a policy run like the daemon does: the volumes the selected jails attach and
// the volumes whose labels match the selector, each once, unless the policy or the run leaves them out. The runs of the
// jails are given to find the selected ones. s.mu is held.
func (s *Server) backupVolumes(pol *api.BackupPolicy, req api.BackupRunRequest, jailRuns []api.BackupRun) []api.BackupRun {
	if pol.Spec.ExcludeVolumes || req.NoVolumes {
		return nil
	}
	attached := map[string]bool{}
	for _, r := range jailRuns {
		if j := s.jails.items[s.jails.keyIn(r.Project, r.Jail)]; j != nil {
			for _, v := range j.Spec.Volumes {
				attached[r.Project+"/"+v.Name] = true
			}
		}
	}
	var out []api.BackupRun
	for _, k := range slices.Sorted(maps.Keys(s.volumes.items)) {
		v := s.volumes.items[k]
		if v.Metadata.Project != pol.Metadata.Project {
			continue
		}
		if !attached[k] && !fakeSelects(pol.Spec.Selector, v.Metadata.Labels) {
			continue
		}
		now := s.now()
		snap := now.Format("20060102150405") + "-" + randHex(4)
		spec := v.Spec
		b := &api.Backup{Metadata: api.ObjectMeta{Name: snap, Project: v.Metadata.Project},
			Spec: api.BackupSpec{Kind: "volume", Volume: &spec, Jail: v.Metadata.Name, JailUUID: v.Metadata.UUID, HostUUID: s.uuid, Policy: req.Policy,
				Snapshot: snap, KeyDomain: s.bkDomain}}
		if len(pol.Spec.Targets) > 0 {
			b.Spec.Target = pol.Spec.Targets[0]
		}
		s.backups.insert(b, true)
		out = append(out, api.BackupRun{ID: "run-" + snap, Kind: "backup", Policy: req.Policy, Target: b.Spec.Target, Project: v.Metadata.Project, Jail: v.Metadata.Name,
			JailUUID: v.Metadata.UUID, Started: now, Finished: now, OK: true, Snapshot: snap})
	}
	return out
}
