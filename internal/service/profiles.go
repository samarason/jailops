package service

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Profiles (design 8.3) are reusable sets of configuration keys and devices.
// A project's profiles live in the project; the profiles of the reserved
// project "host" are visible from every project and written by global
// administrators only. A jail names profiles in order; ExpandedConfig merges
// them with the jail's own keys.

func profToAPI(o object[api.ProfileSpec]) api.Profile {
	return api.Profile{Metadata: o.Meta, Spec: o.Spec}
}

// profileProject resolves the project of a profile request: an ordinary
// project the caller may use, or the host-level pseudo project, which anyone
// with a scope may read and only a global admin may write.
func (s *Service) profileProject(ctx context.Context, write bool) (string, error) {
	a := ActorFrom(ctx)
	if !a.HasScope() {
		return "", api.Errorf(api.CodeForbidden, "this identity has no projects and is not global")
	}
	if ProjectFrom(ctx) == api.HostProfileProject {
		if write && !a.Global {
			return "", api.Errorf(api.CodeForbidden, "host-level profiles are managed by a global administrator")
		}
		return api.HostProfileProject, nil
	}
	p, err := s.access(ctx)
	if err != nil {
		return "", err
	}
	return p.Meta.Name, nil
}

func (s *Service) checkProfile(name string, spec api.ProfileSpec) error {
	if err := validate.Name("name", name); err != nil {
		return err
	}
	return api.ValidateProfile(spec)
}

// ListProfiles lists the profiles of the request's project.
func (s *Service) ListProfiles(ctx context.Context, labels map[string]string) ([]api.Profile, error) {
	proj, err := s.profileProject(ctx, false)
	if err != nil {
		return nil, err
	}
	objs, err := s.profKind.p(proj).list()
	if err != nil {
		return nil, err
	}
	out := []api.Profile{}
	for _, o := range objs {
		if MatchLabels(o.Meta.Labels, labels) {
			out = append(out, profToAPI(o))
		}
	}
	return out, nil
}

// GetProfile returns one profile.
func (s *Service) GetProfile(ctx context.Context, name string) (api.Profile, error) {
	proj, err := s.profileProject(ctx, false)
	if err != nil {
		return api.Profile{}, err
	}
	o, err := s.profKind.p(proj).get(name)
	return profToAPI(o), err
}

// CreateProfile stores a profile.
func (s *Service) CreateProfile(ctx context.Context, in api.Profile) (api.Profile, error) {
	proj, err := s.profileProject(ctx, true)
	if err != nil {
		return api.Profile{}, err
	}
	if err := bodyProject(proj, in.Metadata.Project); err != nil {
		return api.Profile{}, err
	}
	ks := s.profKind.p(proj)
	if err := ks.notTaken(in.Metadata.Name); err != nil {
		return api.Profile{}, err
	}
	if err := s.noShadow(proj, in.Metadata.Name); err != nil {
		return api.Profile{}, err
	}
	if err := s.checkProfile(in.Metadata.Name, in.Spec); err != nil {
		return api.Profile{}, err
	}
	if err := s.profileAdmin(ctx, in.Spec); err != nil {
		return api.Profile{}, err
	}
	o, err := ks.create(ctx, in.Metadata, in.Spec)
	return profToAPI(o), err
}

// profileAdmin refuses admin-only keys (device nodes) to a caller below the admin role.
func (s *Service) profileAdmin(ctx context.Context, spec api.ProfileSpec) error {
	for k := range spec.Config {
		if ck, _, ok := api.ConfigKeyFor(k); ok && ck.Admin && !ActorFrom(ctx).Perm.Satisfies(api.PermAdmin) {
			return api.Errorf(api.CodeForbidden, "%s needs the admin role", k)
		} else if ok && ck.Global {
			if err := requireGlobalForForward(ctx, k); err != nil {
				return err
			}
		}
	}
	return nil
}

// UpdateProfile replaces a profile.
func (s *Service) UpdateProfile(ctx context.Context, name string, in api.Profile, expect int64) (api.Profile, error) {
	proj, err := s.profileProject(ctx, true)
	if err != nil {
		return api.Profile{}, err
	}
	if in.Metadata.Name != "" && in.Metadata.Name != name {
		return api.Profile{}, renameByAction("profile", "profiles")
	}
	if err := bodyProject(proj, in.Metadata.Project); err != nil {
		return api.Profile{}, err
	}
	ks := s.profKind.p(proj)
	if !ks.exists(name) {
		return api.Profile{}, notFound("profile", name)
	}
	if err := s.checkProfile(name, in.Spec); err != nil {
		return api.Profile{}, err
	}
	if err := s.profileAdmin(ctx, in.Spec); err != nil {
		return api.Profile{}, err
	}
	if err := s.readmitProfile(ctx, proj, name, in.Spec); err != nil {
		return api.Profile{}, err
	}
	o, err := ks.update(ctx, name, expect, in.Metadata.Labels, &in.Metadata.ManagedBy, in.Spec)
	if err == nil {
		s.kick()
	}
	return profToAPI(o), err
}

// PatchProfile applies a merge patch.
func (s *Service) PatchProfile(ctx context.Context, name string, patch map[string]any, expect int64) (api.Profile, error) {
	cur, err := s.GetProfile(ctx, name)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return cur, api.Errorf(api.CodeConflict, "profile %q changed: current generation is %d", name, cur.Metadata.Generation)
	}
	var out api.Profile
	if err := MergePatch(cur, patch, &out); err != nil {
		return out, err
	}
	return s.UpdateProfile(ctx, name, out, cur.Metadata.Generation)
}

// DeleteProfile removes a profile no jail uses.
func (s *Service) DeleteProfile(ctx context.Context, name string, expect int64) error {
	proj, err := s.profileProject(ctx, true)
	if err != nil {
		return err
	}
	ks := s.profKind.p(proj)
	if !ks.exists(name) {
		return notFound("profile", name)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.jails {
		if (proj == api.HostProfileProject || e.jail.Metadata.Project == proj) && slices.Contains(e.jail.Spec.Profiles, name) {
			return api.Errorf(api.CodeBusy, "profile %q is used by jail %q", name, jailDisplay(e.jail.Metadata.Project, e.jail.Metadata.Name))
		}
	}
	return ks.delete(ctx, name, expect)
}

// noShadow refuses a project profile that carries the name of a host-level one: the project's own profile is
// resolved first, so it would silently replace what the administrator defined for every project.
func (s *Service) noShadow(project, name string) error {
	if project != api.HostProfileProject && s.profKind.p(api.HostProfileProject).exists(name) {
		return api.Errorf(api.CodeAlreadyExists, "a host-level profile %q exists; a project profile cannot take its name", name)
	}
	return nil
}

// readmitProfile runs the checks a jail passes at creation again for every jail that uses the profile being
// changed, with the new contents: a profile edit must not give a jail what its project was never granted
// (a network, device nodes, a published port) nor a spec that no longer validates.
func (s *Service) readmitProfile(ctx context.Context, proj, name string, spec api.ProfileSpec) error {
	s.mu.RLock()
	type user struct {
		key  string
		jail api.Jail
	}
	var users []user
	for k, e := range s.jails {
		if (proj == api.HostProfileProject || e.jail.Metadata.Project == proj) && slices.Contains(e.jail.Spec.Profiles, name) {
			users = append(users, user{k, e.jail})
		}
	}
	s.mu.RUnlock()
	newEff := map[string]api.JailSpec{} // what each jail would run with, for the checks that look at them together
	for _, u := range users {
		j := u.jail
		var profs []api.Profile
		for _, n := range j.Spec.Profiles {
			if n == name {
				profs = append(profs, api.Profile{Metadata: api.ObjectMeta{Name: n}, Spec: spec})
				continue
			}
			ps, err := s.resolveProfiles(j.Metadata.Project, []string{n})
			if err != nil {
				return err
			}
			profs = append(profs, ps...)
		}
		own := j.Spec
		own.Network = append([]api.NetworkAttach(nil), own.Network...)
		eff, _ := api.ExpandedConfig(own, profs)
		who := jailDisplay(j.Metadata.Project, j.Metadata.Name)
		if err := validate.JailSpec(j.Metadata.Name, eff); err != nil {
			return api.Errorf(api.CodeInvalid, "jail %q would no longer be valid: %v", who, err)
		}
		po, err := s.projKind.get(j.Metadata.Project)
		if err != nil {
			return err
		}
		for _, nd := range eff.Network {
			if _, ok := specGrantsNetwork(po.Spec, nd.Network); !ok && nd.Network != "" {
				return api.Errorf(api.CodeForbidden, "jail %q would attach network %q, which project %q was not granted", who, nd.Network, j.Metadata.Project).
					WithHint(fmt.Sprintf("a global admin grants it: jailops network grant %s --project %s", nd.Network, j.Metadata.Project))
			}
		}
		if len(eff.Devfs) > 0 && len(j.Spec.Devfs) == 0 && !ActorFrom(ctx).Perm.Satisfies(api.PermAdmin) {
			return api.Errorf(api.CodeForbidden, "jail %q would gain device nodes, which needs the admin role", who)
		}
		if len(eff.Proxy) > 0 {
			// a published port that the edit adds or changes is a global administrator's to give
			var before []api.ProxyDevice
			if stored, err := s.resolveProfiles(j.Metadata.Project, j.Spec.Profiles); err == nil {
				oldEff, _ := api.ExpandedConfig(j.Spec, stored)
				before = oldEff.Proxy
			}
			if !slices.Equal(eff.Proxy, before) {
				if err := requireGlobalForForward(ctx, "a profile that forwards a host port into a jail"); err != nil {
					return err
				}
			}
			if err := s.checkProxyDevices(ctx, "jail "+who, eff.Proxy); err != nil {
				return err
			}
			up := false
			for _, nd := range eff.Network {
				if n, err := s.netKind.get(nd.Network); err == nil && n.Spec.Uplink != "" {
					up = true
				}
			}
			if !up {
				return api.Errorf(api.CodeInvalid, "jail %q would forward host ports but has no network with an uplink", who)
			}
		}
		if err := s.checkProxyConflicts(u.key, eff); err != nil {
			return err
		}
		// the volumes the profile gives the jail pass what a volume attached to the jail itself passes
		was := s.effective(j).Volumes
		if err := s.hostDirAdmission(ctx, j.Metadata.Project, eff.Volumes, was); err != nil {
			return err
		}
		for _, v := range eff.Volumes {
			if slices.ContainsFunc(was, func(w api.VolumeAttach) bool { return w.Name == v.Name }) {
				continue
			}
			if _, err := s.volKind.p(j.Metadata.Project).get(v.Name); err != nil {
				return api.Errorf(api.CodeNotFound, "jail %q would attach volume %q, which does not exist in project %q", who, v.Name, j.Metadata.Project).
					WithHint("jailops volume create " + v.Name)
			}
		}
		newEff[u.key] = eff
	}
	return s.checkProfileTogether(newEff)
}

// checkProfileTogether runs the checks that depend on all the jails a profile edit changes at once: an encrypted
// volume the profile gives to two jails is shared, and the limits it gives them together can pass the project's quotas.
func (s *Service) checkProfileTogether(newEff map[string]api.JailSpec) error {
	keys := make([]string, 0, len(newEff))
	for k := range newEff {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	usages := map[string]usage{}
	for _, k := range keys {
		proj, _ := validate.SplitQualified(k)
		eff := newEff[k]
		for _, v := range eff.Volumes {
			if o, err := s.volKind.p(proj).get(v.Name); err == nil && o.Spec.Encrypted {
				if other := s.otherUserOfVolume(proj, k, v.Name, newEff); other != "" {
					return encryptedSharedErr(v.Name, other)
				}
			}
		}
		po, err := s.projKind.get(proj)
		if err != nil {
			return err
		}
		u, ok := usages[proj]
		if !ok {
			u = s.usageWithoutLocked(proj, newEff)
		}
		if err := s.checkQuota(po, eff, u, false); err != nil {
			return err
		}
		u.add(eff)
		usages[proj] = u
	}
	return nil
}

// resolveProfiles loads the named profiles of a project, the project's own
// before the host-level one of the same name.
func (s *Service) resolveProfiles(project string, names []string) ([]api.Profile, error) {
	var out []api.Profile
	for _, n := range names {
		o, err := s.profKind.p(project).get(n)
		if err != nil {
			if o, err = s.profKind.p(api.HostProfileProject).get(n); err != nil {
				return nil, notFound("profile", n)
			}
		}
		out = append(out, profToAPI(o))
	}
	return out, nil
}

// effective returns the spec a jail runs with: its own, merged with its
// profiles. A profile that has disappeared is skipped (the jail keeps
// running; a doctor check reports it).
func (s *Service) effective(j api.Jail) api.JailSpec {
	var profs []api.Profile
	for _, n := range j.Spec.Profiles {
		if o, err := s.profKind.p(j.Metadata.Project).get(n); err == nil {
			profs = append(profs, profToAPI(o))
		} else if o, err := s.profKind.p(api.HostProfileProject).get(n); err == nil {
			profs = append(profs, profToAPI(o))
		}
	}
	eff, _ := api.ExpandedConfig(j.Spec, profs)
	return eff
}

// validateJail validates the effective spec of a jail, so a device that a
// profile completes (a network name) is judged as the jail will run.
func (s *Service) validateJail(project, name string, own api.JailSpec) error {
	profs, err := s.resolveProfiles(project, own.Profiles)
	if err != nil {
		return err
	}
	own.Network = append([]api.NetworkAttach(nil), own.Network...)
	api.NormalizeDevices(&own)
	eff, _ := api.ExpandedConfig(own, profs)
	for i := range eff.Network {
		if eff.Network[i].Network == "" {
			eff.Network[i].Network = "profile-network" // a profile that names no network is checked as if it did; admission of a jail refuses one without a network
		}
	}
	return validate.JailSpec(name, eff)
}

// proxyKey identifies a forwarded port on the host.
func proxyKey(listen, proto string) (string, error) {
	host, port, err := validate.ParseListen(listen)
	if err != nil {
		return "", err
	}
	if proto == "" {
		proto = "tcp"
	}
	return proto + "/" + host + "/" + strconv.Itoa(port), nil
}

// checkProxyConflicts rejects a jail whose published host port another jail, of any project, already forwards: a proxy
// device of the jail or a redirect rule of one of its policies, against the proxy devices and the redirect rules of
// the others.
func (s *Service) checkProxyConflicts(self string, eff api.JailSpec) error {
	if err := s.checkProxyDeviceConflicts(self, eff); err != nil {
		return err
	}
	project, _ := validate.SplitQualified(self)
	return s.checkForwardClash(project, self, eff)
}

// checkProxyDeviceConflicts rejects two proxy devices of one jail that listen in the same place (the clash with another jail
// is checkForwardClash, which also counts the redirect rules of policies). A listener on every address conflicts with one
// on a specific address.
func (s *Service) checkProxyDeviceConflicts(self string, eff api.JailSpec) error {
	mine := map[string]string{}
	for _, p := range eff.Proxy {
		k, err := proxyKey(p.Listen, p.Proto)
		if err != nil {
			return invalid("proxy %q: %v", p.Name, err)
		}
		if _, dup := mine[k]; dup {
			return api.Errorf(api.CodeAlreadyExists, "proxy %q listens where another proxy of the jail does", p.Name)
		}
		mine[k] = p.Name
	}
	return nil
}

// portClash reports whether two keys proto/host/port overlap.
func portClash(a, b string) bool {
	var pa, ha, na, pb, hb, nb string
	if _, err := fmt.Sscanf(a, "%s", &pa); err != nil {
		return false
	}
	split := func(k string) (p, h, n string) {
		first := indexByte(k, '/')
		last := lastIndexByte(k, '/')
		return k[:first], k[first+1 : last], k[last+1:]
	}
	pa, ha, na = split(a)
	pb, hb, nb = split(b)
	return pa == pb && na == nb && (ha == hb || ha == "" || hb == "")
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ---- expanded view and config changes ----

// ExpandedJail is a jail with its profiles merged and where each key came from.
func (s *Service) ExpandedJail(ctx context.Context, name string) (api.JailExpanded, error) {
	j, err := s.GetJail(ctx, name)
	if err != nil {
		return api.JailExpanded{}, err
	}
	profs, _ := s.resolveProfiles(j.Metadata.Project, j.Spec.Profiles)
	eff, src := api.ExpandedConfig(j.Spec, profs)
	out := j
	out.Spec = eff
	return api.JailExpanded{Jail: out, Sources: src}, nil
}

// ConfigResult is the result of a configuration change.
type ConfigResult struct {
	api.Jail
	// RestartRequired lists the keys whose change takes effect at the next
	// start. The daemon never restarts a jail on its own.
	RestartRequired []string `json:"restart_required"`
	// Restarted is true when the request asked for the restart and it was done.
	Restarted bool `json:"restarted,omitempty"`
}

// ConfigureJail applies keys to a jail's own spec as an operation. A change
// that needs a restart is reported in the result; restart is an explicit
// request and only then is a running jail restarted.
func (s *Service) ConfigureJail(ctx context.Context, name string, ch api.ConfigChange, restart bool) (api.Operation, error) {
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
	for k := range ch.Set {
		if ck, _, ok := api.ConfigKeyFor(k); ok && ck.Admin && !ActorFrom(ctx).Perm.Satisfies(api.PermAdmin) {
			return api.Operation{}, api.Errorf(api.CodeForbidden, "%s needs the admin role", k)
		} else if ok && ck.Global {
			if err := requireGlobalForForward(ctx, k); err != nil {
				return api.Operation{}, err
			}
		}
	}
	pre, err := s.jailSnapshot(key)
	if err != nil {
		return api.Operation{}, notFound("jail", name)
	}
	if _, err := api.ApplyConfig(&pre.Spec, ch.Set, ch.Unset); err != nil {
		return api.Operation{}, err
	}
	nlocks := s.netLocksEff(p.Meta.Name, pre.Spec)
	return s.Submit(ctx, OpSpec{
		Description: "Configure jail " + name, Locks: []string{jailLock(key), anchorLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			cur, err := s.jailSnapshot(key)
			if err != nil {
				return nil, notFound("jail", name)
			}
			spec := cur.Spec
			keys, err := api.ApplyConfig(&spec, ch.Set, ch.Unset)
			if err != nil {
				return nil, err
			}
			cur.Spec = spec
			// The update path validates, admits and writes the record. Its own
			// jail lock was taken by this operation, so call the unlocked part.
			unlockNets, err := s.locks.lockPatient(ctx, "configure "+name, nlocks...)
			if err != nil {
				return nil, err
			}
			_, err = s.updateLocked(ctx, p, key, name, cur, AnyGeneration)
			unlockNets()
			if err != nil {
				return nil, err
			}
			res := ConfigResult{RestartRequired: keys}
			if res.RestartRequired == nil {
				res.RestartRequired = []string{}
			}
			now, _ := s.getByKey(ctx, key)
			if restart && len(keys) > 0 && now.Status.Power == api.PowerRunning {
				_ = h.Bind("stop/"+key, &opRequest{Kind: "stop", Jail: key})
				if err := s.life.StopJail(ctx, key); err != nil {
					return nil, err
				}
				_ = h.Bind("start/"+key, &opRequest{Kind: "start", Jail: key})
				if err := s.life.StartJail(ctx, key); err != nil {
					return nil, err
				}
				res.Restarted = true
				s.emitIn(ctx, p.Meta.Name, "jail-restarted", "/api/v1/jails/"+name)
			}
			res.Jail, _ = s.getByKey(ctx, key)
			return res, nil
		},
	})
}

// netLocksEff locks the networks of the effective spec of a jail.
func (s *Service) netLocksEff(project string, own api.JailSpec) []string {
	profs, _ := s.resolveProfiles(project, own.Profiles)
	own.Network = append([]api.NetworkAttach(nil), own.Network...)
	eff, _ := api.ExpandedConfig(own, profs)
	return netLocks(eff)
}
