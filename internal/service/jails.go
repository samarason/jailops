package service

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// ---- registry ----
//
// The registry is keyed by the project-qualified jail key (validate.QualifiedName):
// "<project>_<name>" (a jail always belongs to a project). The
// key is what the OS, the datasets, the lifecycle and the reconciler know; the
// API speaks (project, name) and converts at the edge.

// RefreshJails rebuilds the in-memory registry from the jails' own datasets
// (ZFS is authoritative for host-scope jails), on every storage.
func (s *Service) RefreshJails(ctx context.Context) error {
	if s.life == nil {
		return nil
	}
	found, err := s.life.Discover(ctx)
	if err != nil {
		return err
	}
	m := map[string]*jailEntry{}
	for _, f := range found {
		project, name := validate.SplitQualified(f.Key)
		r, err := s.life.RebuildOn(ctx, f)
		if err != nil {
			s.log.Warn("jail cannot be rebuilt", "jail", f.Key, "err", err)
			m[f.Key] = &jailEntry{jail: api.Jail{Metadata: api.ObjectMeta{Name: name, Project: project, Scope: api.ScopeHost, Host: s.d.HostUUID},
				Spec: api.JailSpec{Storage: f.Storage.Name}}, problems: []string{err.Error()}}
			continue
		}
		j := r.Jail
		j.Metadata.Host = s.d.HostUUID
		if j.Spec.Storage == "" {
			j.Spec.Storage = f.Storage.Name
		}
		m[f.Key] = &jailEntry{jail: j, problems: r.Problems, locked: r.Locked}
	}
	s.mu.Lock()
	s.jails = m
	s.mu.Unlock()
	return nil
}

func (s *Service) refreshJail(ctx context.Context, key string) error {
	r, err := s.life.Rebuild(ctx, key)
	if err != nil {
		return err
	}
	j := r.Jail
	j.Metadata.Host = s.d.HostUUID
	if j.Spec.Storage == "" {
		if si, ok := s.storageOfJail(key); ok {
			j.Spec.Storage = si.Name
		}
	}
	s.mu.Lock()
	s.jails[key] = &jailEntry{jail: j, problems: r.Problems, locked: r.Locked}
	s.mu.Unlock()
	s.unplace(key)
	return nil
}

func (s *Service) jailSnapshot(key string) (api.Jail, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.jails[key]
	if !ok {
		return api.Jail{}, notFound("jail", key)
	}
	return cloneJail(e.jail), nil
}

// jailRef resolves a jail named in a request: the project of the request
// (checked: a project the caller may not use is not_found) and the key.
func (s *Service) jailRef(ctx context.Context, name string) (p project, key string, err error) {
	p, err = s.access(ctx)
	if err != nil {
		return p, "", err
	}
	key, err = validate.QualifiedName(p.Meta.Name, name)
	if err != nil {
		// a name that cannot be a jail is not a jail of this project
		return p, "", notFound("jail", name)
	}
	return p, key, nil
}

func cloneJail(j api.Jail) api.Jail {
	b, _ := json.Marshal(j)
	var out api.Jail
	_ = json.Unmarshal(b, &out)
	return out
}

func (s *Service) markStarted(name string) {
	s.mu.Lock()
	rt := s.status[name]
	rt.startedAt = s.now().UTC()
	s.status[name] = rt
	s.mu.Unlock()
}

func (s *Service) markStopped(name string) {
	s.mu.Lock()
	rt := s.status[name]
	rt.startedAt = time.Time{}
	s.status[name] = rt
	s.mu.Unlock()
}

// view builds the API form of a jail with its observed status. running is
// the observed set (nil means ask).
func (s *Service) view(ctx context.Context, e *jailEntry, running map[string]int) api.Jail {
	j := cloneJail(e.jail)
	name := jailKey(j)
	st := api.JailStatus{Power: api.PowerStopped, Generation: e.jail.Status.Generation}
	st.FreeBSDVersion = s.generationFreeBSD(ctx, st.Generation)
	jid, up := 0, false
	if running != nil {
		jid, up = running[name], false
		_, up = running[name]
	} else if s.d.Jails != nil {
		if o, ok, err := s.d.Jails.Get(ctx, name); err == nil && ok {
			jid, up = o.JID, true
		}
	}
	s.mu.RLock()
	rt := s.status[name]
	s.mu.RUnlock()
	if up {
		st.Power, st.JID = api.PowerRunning, jid
		st.StartedAt = rt.startedAt
		for _, a := range jailAddrs(j.Spec) {
			st.Addresses = append(st.Addresses, a.String())
		}
	}
	if up {
		if c, w, ok := s.limitsCondition(ctx, j); ok {
			st.Conditions = append(st.Conditions, c)
			st.Warnings = append(st.Warnings, w)
		}
	}
	st.Drift = rt.drift
	st.ProvisionedAt = s.provisionedAt(name)
	st.Conditions = append(st.Conditions, rt.conditions...)
	st.Conditions = append(st.Conditions, s.shellCondition(name)...)
	if len(e.problems) > 0 {
		st.Conditions = append(st.Conditions, api.Condition{Type: "Healthy", Status: api.ConditionFalse, Reason: "Degraded",
			Message: strings.Join(e.problems, "; "), Since: s.now().UTC()})
		if !up {
			st.Power = api.PowerError
		}
	}
	s.mu.RLock()
	locked := append([]string(nil), e.locked...)
	s.mu.RUnlock()
	if !up && len(locked) > 0 {
		st.Locked = locked
		if st.Power == api.PowerStopped {
			st.Power = api.PowerLocked
		}
	}
	j.Status = st
	return j
}

func (s *Service) runningJails(ctx context.Context) map[string]int {
	out := map[string]int{}
	if s.d.Jails == nil {
		return out
	}
	list, err := s.d.Jails.List(ctx)
	if err != nil {
		return out
	}
	for _, j := range list {
		if !j.Dying {
			out[j.Name] = j.JID
		}
	}
	return out
}

// ---- reads ----

// ListJails returns the jails of the request's project.
func (s *Service) ListJails(ctx context.Context, labels map[string]string) ([]api.Jail, error) {
	p, err := s.access(ctx)
	if err != nil {
		return nil, err
	}
	run := s.runningJails(ctx)
	s.mu.RLock()
	names := sortedKeys(s.jails)
	entries := make([]*jailEntry, 0, len(names))
	for _, n := range names {
		if e := s.jails[n]; e.jail.Metadata.Project == p.Meta.Name {
			entries = append(entries, e)
		}
	}
	s.mu.RUnlock()
	out := []api.Jail{}
	for _, e := range entries {
		if MatchLabels(e.jail.Metadata.Labels, labels) {
			out = append(out, s.view(ctx, e, run))
		}
	}
	return out, nil
}

// GetJail returns one jail of the request's project.
func (s *Service) GetJail(ctx context.Context, name string) (api.Jail, error) {
	_, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.Jail{}, err
	}
	return s.getByKey(ctx, key)
}

func (s *Service) getByKey(ctx context.Context, key string) (api.Jail, error) {
	s.mu.RLock()
	e, ok := s.jails[key]
	s.mu.RUnlock()
	if !ok {
		_, plain := validate.SplitQualified(key)
		return api.Jail{}, notFound("jail", plain)
	}
	return s.view(ctx, e, nil), nil
}

// JailState returns the observed status.
func (s *Service) JailState(ctx context.Context, name string) (api.JailStatus, error) {
	j, err := s.GetJail(ctx, name)
	return j.Status, err
}

// ---- create ----

func (s *Service) imageFor(spec api.JailSpec) (object[api.ImageSpec], validate.ImageRef, error) {
	ref, err := validate.ParseImageRef(spec.Image)
	if err != nil {
		return object[api.ImageSpec]{}, ref, err
	}
	im, err := s.imgKind.get(ref.Name)
	if err != nil {
		return im, ref, api.Errorf(api.CodeNotFound, "image %q not found", ref.Name).WithHint(api.ImageCreateHint("it", ref.Name, ref.Alias, s.hostBaseRelease()))
	}
	return im, ref, nil
}

// checkJailRefs checks what a jail of a project refers to: its networks, and
// its firewall policy in the same project. Grants were checked before.
func (s *Service) checkJailRefs(project string, spec api.JailSpec) error {
	for _, a := range spec.Network {
		if !s.netKind.exists(a.Network) {
			return notFound("network", a.Network)
		}
	}
	pr, perr := s.projKind.get(project)
	for _, p := range spec.Firewall.Policies {
		o, err := s.polKind.p(project).get(p)
		if err != nil {
			if api.IsCode(err, api.CodeNotFound) {
				return notFound("firewall-policy", p)
			}
			return err
		}
		if o.Meta.ManagedBy != "" {
			return invalid("firewall policy %q is managed by %s: it belongs to its own jail and is not a policy to attach", p, o.Meta.ManagedBy).
				WithHint("write a policy of your own (jailops firewall policy create); app access keeps app-JAIL")
		}
		if perr == nil && slices.Contains(pr.Spec.FirewallPolicies, p) {
			return invalid("firewall policy %q is a mandatory policy of project %s: it is rendered for every jail already", p, project).
				WithHint("name policies of the jail's own, which add to it")
		}
	}
	return nil
}

func netLocks(spec api.JailSpec) []string {
	var out []string
	for _, a := range spec.Network {
		out = append(out, networkLock(a.Network))
	}
	return out
}

// imageLocks serialises the first use of an image on a pool: the generation
// is built or received there.
func (s *Service) imageLocks(ctx context.Context, ref validate.ImageRef, storage string) []string {
	si, ok := s.storage(storage)
	if !ok || si.Images == nil {
		return nil
	}
	if obs, err := si.Images.Observe(ctx, ref.Name); err != nil || len(obs.Status.Generations) == 0 {
		return []string{imageLock(ref.Name)}
	}
	return nil
}

// CreateJail creates a jail in the request's project as an operation whose
// result is the Jail. Grants, the image allow-list and the quotas are checked
// before anything is created.
func (s *Service) CreateJail(ctx context.Context, j api.Jail) (api.Operation, error) {
	if err := s.requireHost("jails"); err != nil {
		return api.Operation{}, err
	}
	j.Spec.Shell = api.ShellPath(j.Spec.Shell) // the names bash and sh
	p, err := s.access(ctx)
	if err != nil {
		return api.Operation{}, err
	}
	if err := bodyProject(p.Meta.Name, j.Metadata.Project); err != nil {
		return api.Operation{}, err
	}
	name, proj := j.Metadata.Name, p.Meta.Name
	if err := s.validateJail(proj, name, j.Spec); err != nil {
		return api.Operation{}, err
	}
	if err := api.ValidLabels(j.Metadata.Labels); err != nil {
		return api.Operation{}, err
	}
	key, err := validate.QualifiedName(proj, name)
	if err != nil {
		return api.Operation{}, err
	}
	s.mu.RLock()
	_, exists := s.jails[key]
	s.mu.RUnlock()
	if exists {
		return api.Operation{}, api.Errorf(api.CodeAlreadyExists, "jail %q already exists", name)
	}
	spec := j.Spec
	spec.Network = append([]api.NetworkAttach(nil), spec.Network...)
	im, ref, err := s.imageFor(spec)
	if err != nil {
		return api.Operation{}, err
	}
	release, err := s.admit(ctx, p, key, &spec, nil)
	if err != nil {
		return api.Operation{}, err
	}
	submitted := false
	defer func() {
		if !submitted {
			release()
		}
	}()
	if err := s.validateJail(proj, name, spec); err != nil {
		return api.Operation{}, err
	}
	if err := canonicalJailSizes(&spec); err != nil {
		return api.Operation{}, err
	}
	if err := s.checkNewJail(proj, name, spec); err != nil {
		return api.Operation{}, err
	}
	if spec.Volumes, err = s.checkAttachments(proj, key, spec.Volumes); err != nil {
		return api.Operation{}, err
	}
	spec.OS = im.Spec.OS
	if spec.Layout == "" {
		spec.Layout = api.LayoutThin
		if spec.OS == api.OSLinux {
			spec.Layout = api.LayoutThick
		}
	}
	if spec.OS == api.OSLinux && spec.Prompt != "" {
		return api.Operation{}, invalid("the prompt key is for FreeBSD jails; a Linux jail keeps the prompt of its distribution")
	}
	profs, _ := s.resolveProfiles(proj, spec.Profiles)
	shellSetup := s.shellDefaults(&spec, profs)
	if spec.Hostname == "" {
		spec.Hostname = name
	}
	meta := api.ObjectMeta{Name: name, Project: proj, UUID: state_uuid(), Scope: api.ScopeHost, Host: s.d.HostUUID, Generation: 1,
		Labels: j.Metadata.Labels, ManagedBy: j.Metadata.ManagedBy, CreatedAt: s.now().UTC(), UpdatedAt: s.now().UTC()}
	locks := append([]string{jailLock(key)}, s.netLocksEff(proj, spec)...)
	locks = append(locks, s.imageLocks(ctx, ref, spec.Storage)...)
	op, err := s.Submit(ctx, OpSpec{
		Description: "Create jail " + name, Locks: locks, Project: proj,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			defer release()
			s.place(key, spec.Storage)
			ok := false
			defer func() {
				if !ok {
					s.unplace(key)
				}
			}()
			si, _ := s.storage(spec.Storage)
			g, _ := specStorageGrant(p.Spec, spec.Storage)
			if err := s.ensureProjectDatasets(ctx, proj, si, g); err != nil {
				return nil, err
			}
			if err := s.assignOwn(proj, key, &spec); err != nil {
				return nil, err
			}
			nj := api.Jail{Metadata: meta, Spec: spec}
			if err := h.Bind("create/"+key, &opRequest{Kind: "create", Jail: key, Create: &nj}); err != nil {
				return nil, err
			}
			if _, err := s.life.CreateJail(ctx, nj, false); err != nil {
				return nil, err
			}
			if shellSetup {
				// bash and the prompt are set up at the first start, when the root is mounted
				s.setShellMark(key, shellMark{Pending: true})
			}
			if err := s.refreshJail(ctx, key); err != nil {
				return nil, err
			}
			ok = true
			s.emitIn(ctx, proj, "jail-created", "/api/v1/jails/"+name)
			s.kick()
			return s.getByKey(ctx, key)
		},
	})
	if err == nil {
		submitted = true
	}
	return op, err
}

// ---- update ----

func (s *Service) writeJailRecord(ctx context.Context, j api.Jail) error {
	rec := lifecycle.Record{Version: 1, Metadata: j.Metadata, Spec: j.Spec}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	f := s.d.Files
	key := jailKey(j)
	sp := path.Join(s.jailMount(key), "spec.json")
	if err := f.WriteAtomic(ctx, sp, append(b, '\n')); err != nil {
		return err
	}
	bp := path.Join(s.jailMount(key), "bundle.json")
	var bd lifecycle.Bundle
	if raw, err := f.ReadFile(ctx, bp); err == nil {
		_ = json.Unmarshal(raw, &bd)
	}
	bd.Version, bd.Metadata, bd.Spec, bd.Volumes, bd.Written = 1, j.Metadata, j.Spec, j.Spec.Volumes, s.now().UTC()
	nb, err := json.MarshalIndent(bd, "", "  ")
	if err != nil {
		return err
	}
	return f.WriteAtomic(ctx, bp, append(nb, '\n'))
}

// UpdateJail replaces a jail's metadata labels and spec. Identity, scope,
// host and status are server-owned. Image, layout, OS, storage, encryption and
// volumes cannot change here: use upgrade for the image generation.
func (s *Service) UpdateJail(ctx context.Context, name string, in api.Jail, expect int64) (api.Jail, error) {
	if err := s.requireHost("jails"); err != nil {
		return api.Jail{}, err
	}
	p, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.Jail{}, err
	}
	return s.updateJail(ctx, p, key, name, in, expect, false)
}

// updateLocked is UpdateJail for a caller that holds the locks of the jail
// and of its networks (an operation).
func (s *Service) updateLocked(ctx context.Context, p project, key, name string, in api.Jail, expect int64) (api.Jail, error) {
	return s.updateJail(ctx, p, key, name, in, expect, true)
}

func (s *Service) updateJail(ctx context.Context, p project, key, name string, in api.Jail, expect int64, locked bool) (api.Jail, error) {
	if in.Metadata.Name != "" && in.Metadata.Name != name {
		return api.Jail{}, renameByAction("jail", "jails")
	}
	if err := bodyProject(p.Meta.Name, in.Metadata.Project); err != nil {
		return api.Jail{}, err
	}
	old, err := s.jailSnapshot(key)
	if err != nil {
		return api.Jail{}, notFound("jail", name)
	}
	spec := in.Spec
	spec.Network = append([]api.NetworkAttach(nil), spec.Network...)
	spec.Shell = api.ShellPath(spec.Shell) // the names bash and sh
	if spec.OS == "" {
		spec.OS = old.Spec.OS
	}
	if spec.Layout == "" {
		spec.Layout = old.Spec.Layout
	}
	if spec.Hostname == "" {
		spec.Hostname = old.Spec.Hostname
	}
	if spec.Storage == "" {
		spec.Storage = old.Spec.Storage
	}
	if err := s.validateJail(p.Meta.Name, name, spec); err != nil {
		return api.Jail{}, err
	}
	if err := canonicalJailSizes(&spec); err != nil {
		return api.Jail{}, err
	}
	oref, _ := validate.ParseImageRef(old.Spec.Image)
	nref, _ := validate.ParseImageRef(spec.Image)
	switch {
	case nref.Name != oref.Name:
		return api.Jail{}, invalid("the image of a jail cannot change").WithHint("create a new jail from the other image")
	case spec.Layout != old.Spec.Layout, spec.OS != old.Spec.OS:
		return api.Jail{}, invalid("layout and os cannot change")
	case spec.Encrypted != old.Spec.Encrypted:
		return api.Jail{}, invalid("encryption cannot change")
	case spec.Storage != old.Spec.Storage:
		return api.Jail{}, invalid("the storage of a jail cannot change").WithHint("copy the jail to move it")
	case spec.OS == api.OSLinux && spec.Prompt != "":
		return api.Jail{}, invalid("the prompt key is for FreeBSD jails; a Linux jail keeps the prompt of its distribution")
	}
	if !volumesEqual(spec.Volumes, old.Spec.Volumes) {
		if spec.Volumes, err = s.attachmentsChanged(ctx, p.Meta.Name, key, spec.Volumes); err != nil {
			return api.Jail{}, err
		}
	}
	oldSpec := old.Spec
	if _, err := s.admit(ctx, p, key, &spec, &oldSpec); err != nil {
		return api.Jail{}, err
	}
	if !locked {
		locks := append([]string{jailLock(key)}, s.netLocksEff(p.Meta.Name, spec)...)
		unlock, err := s.locks.lockPatient(ctx, "update jail "+name, locks...)
		if err != nil {
			return api.Jail{}, err
		}
		defer unlock()
	}
	// Re-read under the lock: the generation check must see the latest state.
	old, err = s.jailSnapshot(key)
	if err != nil {
		return api.Jail{}, notFound("jail", name)
	}
	if expect != AnyGeneration && expect != old.Metadata.Generation {
		return api.Jail{}, api.Errorf(api.CodeConflict, "jail %q changed: current generation is %d", name, old.Metadata.Generation).
			WithHint("read it again and re-apply your change").WithDetail("generation", strconv.FormatInt(old.Metadata.Generation, 10))
	}
	// "auto" keeps the address the attachment already has.
	for i := range spec.Network {
		if i < len(old.Spec.Network) && old.Spec.Network[i].Network == spec.Network[i].Network {
			if spec.Network[i].IPv4 == "auto" && old.Spec.Network[i].IPv4 != "" {
				spec.Network[i].IPv4 = old.Spec.Network[i].IPv4
			}
			if spec.Network[i].IPv6 == "auto" && old.Spec.Network[i].IPv6 != "" {
				spec.Network[i].IPv6 = old.Spec.Network[i].IPv6
			}
		}
	}
	if err := s.assignOwn(p.Meta.Name, key, &spec); err != nil {
		return api.Jail{}, err
	}
	mb := old.Metadata.ManagedBy
	if in.Metadata.ManagedBy != "" {
		mb = in.Metadata.ManagedBy
	}
	if jsonEq(spec, old.Spec) && labelsEqual(in.Metadata.Labels, old.Metadata.Labels) && mb == old.Metadata.ManagedBy {
		return s.getByKey(ctx, key)
	}
	if !labelsEqual(in.Metadata.Labels, old.Metadata.Labels) {
		if err := api.ValidLabels(in.Metadata.Labels); err != nil {
			return api.Jail{}, err
		}
	}
	if err := s.applyDiskLimits(ctx, key, old.Spec, spec); err != nil {
		return api.Jail{}, err
	}
	if spec.Delegate != old.Spec.Delegate {
		// the dataset is made and given the jailed property (or the property cleared) in the request of the global
		// administrator who changed it; the jail attaches it at its next start
		if err := s.life.SetDelegation(ctx, key, spec.Delegate); err != nil {
			return api.Jail{}, err
		}
	}
	nj := old
	nj.Spec, nj.Status = spec, api.JailStatus{}
	nj.Metadata.Labels, nj.Metadata.ManagedBy = in.Metadata.Labels, mb
	nj.Metadata.Generation = old.Metadata.Generation + 1
	nj.Metadata.UpdatedAt = s.now().UTC()
	if err := s.writeJailRecord(ctx, nj); err != nil {
		return api.Jail{}, internal(err)
	}
	s.mu.Lock()
	if e := s.jails[key]; e != nil {
		nj.Status.Generation = e.jail.Status.Generation
		e.jail = nj
	}
	s.mu.Unlock()
	s.promptChanged(ctx, key, old, nj)
	s.emitIn(ctx, p.Meta.Name, "jail-updated", "/api/v1/jails/"+name)
	s.kick()
	return s.getByKey(ctx, key)
}

func volumesEqual(a, b []api.VolumeAttach) bool {
	return jsonEq(a, b) || (len(a) == 0 && len(b) == 0)
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// PatchJail applies a merge patch to metadata labels and spec.
func (s *Service) PatchJail(ctx context.Context, name string, patch map[string]any, expect int64) (api.Jail, error) {
	cur, err := s.GetJail(ctx, name)
	if err != nil {
		return api.Jail{}, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return api.Jail{}, api.Errorf(api.CodeConflict, "jail %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	var out api.Jail
	if err := MergePatch(cur, patch, &out); err != nil {
		return api.Jail{}, err
	}
	return s.UpdateJail(ctx, name, out, cur.Metadata.Generation)
}

// ---- delete and power ----

// DeleteJail destroys a stopped jail as an operation.
func (s *Service) DeleteJail(ctx context.Context, name string) (api.Operation, error) {
	if err := s.requireHost("jails"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.Operation{}, err
	}
	j, err := s.getByKey(ctx, key)
	if err != nil {
		return api.Operation{}, err
	}
	if j.Status.Power == api.PowerRunning {
		return api.Operation{}, api.Errorf(api.CodeBusy, "jail %q is running", name).WithHint("stop it first")
	}
	if err := s.noRuleNamesJail(p.Meta.Name, name, true); err != nil {
		return api.Operation{}, err
	}
	if err := s.backupRunning("jail", name, j.Metadata.UUID); err != nil {
		return api.Operation{}, err
	}
	return s.Submit(ctx, OpSpec{
		Description: "Delete jail " + name, Locks: []string{jailLock(key), anchorLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			_ = h.Bind("destroy/"+key, &opRequest{Kind: "destroy", Jail: key})
			if _, err := s.life.DestroyJail(ctx, key, false, false); err != nil {
				return nil, err
			}
			s.mu.Lock()
			delete(s.jails, key)
			s.forgetProvisioned(key)
			delete(s.status, key)
			s.mu.Unlock()
			s.forgetKeys(key)
			s.emitIn(ctx, p.Meta.Name, "jail-deleted", "/api/v1/jails/"+name)
			s.accessJailGone(ctx, p.Meta.Name, name)
			s.kick()
			return nil, nil
		},
	})
}

// JailAction starts, stops or restarts a jail as an operation.
func (s *Service) JailAction(ctx context.Context, name string, a api.JailAction) (api.Operation, error) {
	if err := s.requireHost("jails"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.Operation{}, err
	}
	if _, err := s.getByKey(ctx, key); err != nil {
		return api.Operation{}, err
	}
	switch a.Action {
	case "start", "stop", "restart":
	default:
		return api.Operation{}, invalid("unknown action %q (start, stop or restart)", a.Action)
	}
	if a.Timeout < 0 {
		return api.Operation{}, invalid("timeout must not be negative")
	}
	if l := s.lockedOf(key); a.Action != "stop" && len(l) > 0 {
		return api.Operation{}, lifecycle.LockedError(key, l)
	}
	done := map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"}[a.Action]
	return s.Submit(ctx, OpSpec{
		Description: strings.ToUpper(a.Action[:1]) + a.Action[1:] + " jail " + name, Locks: []string{jailLock(key), anchorLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			if a.Timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(a.Timeout)*time.Second)
				defer cancel()
			}
			if a.Action != "start" {
				_ = h.Bind("stop/"+key, &opRequest{Kind: "stop", Jail: key})
				if err := s.life.StopJail(ctx, key); err != nil {
					return nil, err
				}
			}
			if a.Action != "stop" {
				_ = h.Bind("start/"+key, &opRequest{Kind: "start", Jail: key})
				_ = h.Timed("bash-from-the-host", func() error { s.installBashBeforeFirstStart(ctx, key); return nil })
				if err := s.life.StartJail(ctx, key); err != nil {
					if api.IsCode(err, api.CodeLocked) {
						s.observeLocked(ctx, key)
					}
					return nil, err
				}
				s.setLocked(key, nil)
				s.markStartDue(key, false)
				// A new jail gets its shell and prompt at its first start, before its own provisioning.
				_ = h.Timed("shell-setup", func() error { s.shellAtStart(ctx, key); return nil })
				// A jail that declares provisioning is provisioned at its first start.
				if err := h.Timed("provisioning", func() error { return s.provisionPending(ctx, key) }); err != nil {
					s.kick()
					return nil, err
				}
			}
			s.emitIn(ctx, p.Meta.Name, "jail-"+done, "/api/v1/jails/"+name)
			s.kick()
			return s.getByKey(ctx, key)
		},
	})
}

// StartJail starts a jail synchronously the way an operator's start does. The
// reconciler uses it for autostart; key is the project-qualified jail key.
func (s *Service) StartJail(ctx context.Context, key string) error {
	unlock, err := s.locks.tryLock("autostart "+key, jailLock(key), anchorLock(key))
	if err != nil {
		return err
	}
	defer unlock()
	project, name := validate.SplitQualified(key)
	s.installBashBeforeFirstStart(ctx, key)
	err = s.life.StartJail(ctx, key)
	if api.IsCode(err, api.CodeLocked) {
		// Skipped, not failed: the unlock starts it (volkeys.go).
		s.observeLocked(ctx, key)
		s.bootLocked(ctx, key, err)
		return err
	}
	if err == nil {
		s.setLocked(key, nil)
		s.shellAtStart(ctx, key)
	}
	res := "ok"
	if err != nil {
		res = "error"
	}
	s.Audit(ctx, store.AuditEntry{Actor: ActorFrom(ctx).Name, ActorKind: ActorFrom(ctx).Kind, Method: "AUTOSTART", Route: "reconcile",
		Object: "/api/v1/jails/" + name, Project: project, Result: res, Detail: "start at boot"})
	if err != nil {
		return err
	}
	s.emitIn(ctx, project, "jail-started", "/api/v1/jails/"+name)
	return nil
}

// Housekeeping does the periodic chores: it destroys root.old datasets whose
// retention has passed. Jails with a running operation are skipped.
func (s *Service) Housekeeping(ctx context.Context) {
	if s.life == nil {
		return
	}
	s.mu.RLock()
	names := sortedKeys(s.jails)
	s.mu.RUnlock()
	for _, n := range names {
		unlock, err := s.locks.tryLock("housekeeping "+n, jailLock(n))
		if err != nil {
			continue
		}
		if done, err := s.life.CleanupRootOld(ctx, n); err != nil {
			s.log.Warn("cleaning up root.old failed", "jail", n, "err", err)
		} else if done {
			s.log.Info("removed root.old", "jail", n)
		}
		unlock()
	}
	s.PruneTrust(ctx)
}

// TryLock and IsLocked let the reconciler share the lock set.
func (s *Service) TryLock(holder string, keys ...string) (func(), error) {
	return s.locks.tryLock(holder, keys...)
}

// IsLocked reports whether a lock key is held.
func (s *Service) IsLocked(key string) bool { return s.locks.isHeld(key) }

// ---- snapshots ----

func (s *Service) snapToAPI(ctx context.Context, project, key string, r lifecycle.SnapshotResult) api.JailSnapshot {
	_, jail := validate.SplitQualified(key)
	sn := api.JailSnapshot{
		Metadata: api.ObjectMeta{Name: r.Name, Project: project, Scope: api.ScopeHost, Host: s.d.HostUUID, Generation: 1},
		Spec:     api.JailSnapshotSpec{Jail: jail},
		Status:   api.JailSnapshotStatus{Written: r.TotalWritten},
	}
	sn.Metadata.CreatedAt = r.Created
	if c, err := s.d.ZFS.Get(ctx, s.lcfg.ContainerDS(key)+"@"+r.Name, lifecycle.PropComment); err == nil {
		sn.Spec.Comment = c
	}
	return sn
}

// ListSnapshots lists the snapshots of a jail.
func (s *Service) ListSnapshots(ctx context.Context, jail string) ([]api.JailSnapshot, error) {
	p, key, err := s.jailRef(ctx, jail)
	if err != nil {
		return nil, err
	}
	if _, err := s.getByKey(ctx, key); err != nil {
		return nil, err
	}
	rs, err := s.life.ListSnapshots(ctx, key)
	if err != nil {
		return nil, err
	}
	out := []api.JailSnapshot{}
	for _, r := range rs {
		out = append(out, s.snapToAPI(ctx, p.Meta.Name, key, r))
	}
	return out, nil
}

// GetSnapshot returns one snapshot.
func (s *Service) GetSnapshot(ctx context.Context, jail, snap string) (api.JailSnapshot, error) {
	l, err := s.ListSnapshots(ctx, jail)
	if err != nil {
		return api.JailSnapshot{}, err
	}
	for _, x := range l {
		if x.Metadata.Name == snap {
			return x, nil
		}
	}
	return api.JailSnapshot{}, notFound("snapshot", snap)
}

// CreateSnapshot snapshots every dataset of a jail atomically, as an operation.
func (s *Service) CreateSnapshot(ctx context.Context, jail string, req api.JailSnapshot) (api.Operation, error) {
	if err := s.requireHost("snapshots"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, jail)
	if err != nil {
		return api.Operation{}, err
	}
	if _, err := s.getByKey(ctx, key); err != nil {
		return api.Operation{}, err
	}
	if err := api.ValidFreeText("comment", req.Spec.Comment, false); err != nil {
		return api.Operation{}, err
	}
	name := req.Metadata.Name
	if name != "" {
		if err := validate.SnapshotName("name", name); err != nil {
			return api.Operation{}, err
		}
		if err := s.checkSnapshotBudget(key, name); err != nil {
			return api.Operation{}, err
		}
		if _, err := s.GetSnapshot(ctx, jail, name); err == nil {
			return api.Operation{}, api.Errorf(api.CodeAlreadyExists, "snapshot %q already exists", name)
		}
	}
	return s.Submit(ctx, OpSpec{
		Description: "Snapshot jail " + jail, Locks: []string{jailLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + jail}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			r, err := s.life.SnapshotJail(ctx, key, name, req.Spec.Comment)
			if err != nil {
				return nil, err
			}
			s.emitIn(ctx, p.Meta.Name, "jail-snapshot-created", "/api/v1/jails/"+jail+"/snapshots/"+r.Name)
			return s.snapToAPI(ctx, p.Meta.Name, key, r), nil
		},
	})
}

// DeleteSnapshot destroys a snapshot on every dataset of the jail.
func (s *Service) DeleteSnapshot(ctx context.Context, jail, snap string) (api.Operation, error) {
	if err := s.requireHost("snapshots"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, jail)
	if err != nil {
		return api.Operation{}, err
	}
	if _, err := s.GetSnapshot(ctx, jail, snap); err != nil {
		return api.Operation{}, err
	}
	return s.Submit(ctx, OpSpec{
		Description: "Delete snapshot " + snap, Locks: []string{jailLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + jail}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			container := s.lcfg.ContainerDS(key)
			ds, err := s.d.ZFS.Descendants(ctx, container)
			if err != nil {
				return nil, err
			}
			for _, d := range append([]string{container}, ds...) {
				ok, err := s.d.ZFS.Exists(ctx, d+"@"+snap)
				if err != nil {
					return nil, err
				}
				if ok {
					if err := s.d.ZFS.Destroy(ctx, d+"@"+snap); err != nil {
						return nil, err
					}
				}
			}
			s.emitIn(ctx, p.Meta.Name, "jail-snapshot-deleted", "/api/v1/jails/"+jail+"/snapshots/"+snap)
			return nil, nil
		},
	})
}

// ---- rollback, upgrade, copy ----

// ActionResult is an operation result that is a Jail plus what a plan did.
type ActionResult struct {
	api.Jail
	Plan     []string `json:"plan,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	DryRun   bool     `json:"dry_run,omitempty"`
}

func (s *Service) stamp() string { return strconv.FormatInt(s.now().Unix(), 10) }

// RollbackJail rolls a jail back as an operation.
func (s *Service) RollbackJail(ctx context.Context, name string, rb api.JailRollback) (api.Operation, error) {
	if err := s.requireHost("rollback"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.Operation{}, err
	}
	if _, err := s.getByKey(ctx, key); err != nil {
		return api.Operation{}, err
	}
	switch rb.Scope {
	case "":
		rb.Scope = api.RollbackRoot
	case api.RollbackRoot, api.RollbackData, api.RollbackAll:
	default:
		return api.Operation{}, invalid("unknown rollback scope %q", rb.Scope)
	}
	if rb.Scope != api.RollbackRoot && !rb.ConfirmDataLoss {
		return api.Operation{}, api.Errorf(api.CodeDataLoss, "scope %q discards data written since the snapshot", rb.Scope).
			WithHint("check what was written, then set confirm_data_loss")
	}
	opts := lifecycle.RollbackOptions{JailRollback: rb, Stamp: s.stamp()}
	return s.Submit(ctx, OpSpec{
		Description: "Rollback jail " + name, Locks: []string{jailLock(key), anchorLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			var ar ActionResult
			if opts.Scope == api.RollbackRoot {
				pl, ur, err := s.life.PlanRollbackRoot(ctx, key, opts, 0)
				if err != nil {
					return nil, err
				}
				if pl != nil {
					st := ur.State
					target := 0
					if _, rest, ok := cutImage(ur.To); ok {
						target, _ = strconv.Atoi(strings.TrimPrefix(rest, "g"))
					}
					if err := h.Bind("rollback/"+key, &opRequest{Kind: "rollback", Jail: key, Stamp: opts.Stamp, Rollback: &opts, State: &st, TargetGen: target}); err != nil {
						return nil, err
					}
					if err := s.life.Executor.Run(ctx, "rollback/"+key, pl); err != nil {
						return nil, err
					}
					s.life.FinishSwitch(ctx, key, ur)
					ar.Plan, ar.Warnings = ur.Plan, ur.Warnings
				}
			} else {
				_ = h.Bind("rollback/"+key, &opRequest{Kind: "rollback", Jail: key, Stamp: opts.Stamp, Rollback: &opts})
				res, err := s.life.RollbackJail(ctx, key, opts, false)
				if err != nil {
					return nil, err
				}
				ar.Plan = res.Plan
			}
			if err := s.refreshJail(ctx, key); err != nil {
				s.log.Warn("refresh after rollback", "jail", key, "err", err)
			}
			s.emitIn(ctx, p.Meta.Name, "jail-rolled-back", "/api/v1/jails/"+name)
			ar.Jail, _ = s.getByKey(ctx, key)
			return ar, nil
		},
	})
}

// UpgradeJail moves a jail to a newer generation of its image as an operation.
// With DryRun the operation returns the plan and changes nothing.
func (s *Service) UpgradeJail(ctx context.Context, name string, up api.JailUpgrade) (api.Operation, error) {
	if err := s.requireHost("upgrade"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.Operation{}, err
	}
	if _, err := s.getByKey(ctx, key); err != nil {
		return api.Operation{}, err
	}
	req := lifecycle.UpgradeRequest{JailUpgrade: up, Stamp: s.stamp()}
	return s.Submit(ctx, OpSpec{
		Description: "Upgrade jail " + name, Locks: []string{jailLock(key), anchorLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			return s.upgradeBody(ctx, h, p.Meta.Name, name, key, up, req)
		},
	})
}

// upgradeBody plans, journals and runs a root swap of a thin jail. It is the
// body of the upgrade operation and of the OS update of the update pipeline;
// the caller holds the jail and anchor locks.
func (s *Service) upgradeBody(ctx context.Context, h *OpHandle, project, name, key string, up api.JailUpgrade, req lifecycle.UpgradeRequest) (any, error) {
	pl, res, err := s.life.PlanUpgrade(ctx, key, req)
	if err != nil {
		return nil, err
	}
	j, _ := s.getByKey(ctx, key)
	if pl == nil || up.DryRun {
		ar := ActionResult{Jail: j, Warnings: res.Warnings, DryRun: up.DryRun}
		if pl != nil {
			ar.Plan = pl.Describe()
		}
		return ar, nil
	}
	st := res.State
	if err := h.Bind("upgrade/"+key, &opRequest{Kind: "upgrade", Jail: key, Stamp: req.Stamp, Upgrade: &req, State: &st}); err != nil {
		return nil, err
	}
	if err := s.life.Executor.Run(ctx, "upgrade/"+key, pl); err != nil {
		return nil, err
	}
	s.life.FinishSwitch(ctx, key, res)
	if err := s.refreshJail(ctx, key); err != nil {
		s.log.Warn("refresh after upgrade", "jail", key, "err", err)
	}
	s.emitIn(ctx, project, "jail-upgraded", "/api/v1/jails/"+name)
	s.kick()
	j, _ = s.getByKey(ctx, key)
	return ActionResult{Jail: j, Plan: res.Plan, Warnings: res.Warnings}, nil
}

// CopyJail makes an independent copy (send and receive, never a clone) in the
// same project and on the same storage.
func (s *Service) CopyJail(ctx context.Context, src string, dst api.Jail) (api.Operation, error) {
	if err := s.requireHost("copy"); err != nil {
		return api.Operation{}, err
	}
	p, srcKey, err := s.jailRef(ctx, src)
	if err != nil {
		return api.Operation{}, err
	}
	if err := bodyProject(p.Meta.Name, dst.Metadata.Project); err != nil {
		return api.Operation{}, err
	}
	if err := api.ValidLabels(dst.Metadata.Labels); err != nil {
		return api.Operation{}, err
	}
	j, err := s.jailSnapshot(srcKey)
	if err != nil {
		return api.Operation{}, notFound("jail", src)
	}
	name := dst.Metadata.Name
	if err := validate.JailName(name); err != nil {
		return api.Operation{}, err
	}
	key, err := validate.QualifiedName(p.Meta.Name, name)
	if err != nil {
		return api.Operation{}, err
	}
	s.mu.RLock()
	_, exists := s.jails[key]
	s.mu.RUnlock()
	if exists {
		return api.Operation{}, api.Errorf(api.CodeAlreadyExists, "jail %q already exists", name)
	}
	cspec := j.Spec
	// A copy attaches no volume: a volume belongs to the jails it is attached to, and two jails writing one by
	// accident is not what a copy is for.
	cspec.Volumes = nil
	cspec.Network = append([]api.NetworkAttach(nil), cspec.Network...)
	for i := range cspec.Network {
		if cspec.Network[i].IPv4 != "none" && cspec.Network[i].IPv4 != "" {
			cspec.Network[i].IPv4 = "auto"
		}
		if cspec.Network[i].IPv6 != "none" && cspec.Network[i].IPv6 != "" {
			cspec.Network[i].IPv6 = "auto"
		}
	}
	release, err := s.admit(ctx, p, key, &cspec, nil)
	if err != nil {
		return api.Operation{}, err
	}
	if err := s.checkNewJail(p.Meta.Name, name, cspec); err != nil {
		release()
		return api.Operation{}, err
	}
	submitted := false
	defer func() {
		if !submitted {
			release()
		}
	}()
	newID := state_uuid()
	stamp := s.stamp()
	locks := append([]string{jailLock(srcKey), jailLock(key)}, s.netLocksEff(p.Meta.Name, j.Spec)...)
	op, err := s.Submit(ctx, OpSpec{
		Description: "Copy jail " + src + " to " + name, Locks: locks, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + src, "/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			defer release()
			s.place(key, j.Spec.Storage)
			ok := false
			defer func() {
				if !ok {
					s.unplace(key)
				}
			}()
			_ = h.Bind("copy/"+key, &opRequest{Kind: "copy", Jail: key, Stamp: stamp, Copy: &copyRequest{Src: srcKey, Dst: key, UUID: newID}})
			if _, err := s.life.CopyJail(ctx, srcKey, key, newID, stamp, false); err != nil {
				return nil, err
			}
			if err := s.refreshJail(ctx, key); err != nil {
				return nil, err
			}
			// The copy's addresses were reset to "auto": allocate them now.
			nj, _ := s.jailSnapshot(key)
			if err := s.assignOwn(p.Meta.Name, key, &nj.Spec); err != nil {
				return nil, fmt.Errorf("copy created, but allocating addresses failed: %w", err)
			}
			if len(dst.Metadata.Labels) > 0 {
				nj.Metadata.Labels = dst.Metadata.Labels
			}
			nj.Metadata.Generation++
			nj.Metadata.UpdatedAt = s.now().UTC()
			if err := s.writeJailRecord(ctx, nj); err != nil {
				return nil, err
			}
			s.mu.Lock()
			if e := s.jails[key]; e != nil {
				nj.Status.Generation = e.jail.Status.Generation
				e.jail = nj
			}
			s.mu.Unlock()
			ok = true
			s.emitIn(ctx, p.Meta.Name, "jail-created", "/api/v1/jails/"+name)
			s.kick()
			return s.getByKey(ctx, key)
		},
	})
	if err == nil {
		submitted = true
	}
	return op, err
}
