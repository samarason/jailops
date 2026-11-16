package fake

import (
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

func (s *Server) routes() {
	s.jails = newKind(s, "jails", "jail", api.ScopeHost, func(j *api.Jail) *api.ObjectMeta { return &j.Metadata })
	s.jails.scoped = true
	s.images = newKind(s, "images", "image", api.ScopeFleet, func(v *api.Image) *api.ObjectMeta { return &v.Metadata })
	s.networks = newKind(s, "networks", "network", api.ScopeFleet, func(v *api.Network) *api.ObjectMeta { return &v.Metadata })
	s.policies = newKind(s, "firewall/policies", "firewall-policy", api.ScopeFleet, func(v *api.FirewallPolicy) *api.ObjectMeta { return &v.Metadata })
	s.addrsets = newKind(s, "firewall/address-sets", "address-set", api.ScopeFleet, func(v *api.AddressSet) *api.ObjectMeta { return &v.Metadata })
	s.targets = newKind(s, "backup-targets", "backup-target", api.ScopeFleet, func(v *api.BackupTarget) *api.ObjectMeta { return &v.Metadata })
	s.bpolicies = newKind(s, "backup-policies", "backup-policy", api.ScopeFleet, func(v *api.BackupPolicy) *api.ObjectMeta { return &v.Metadata })
	s.backups = newKind(s, "backups", "backup", api.ScopeHost, func(v *api.Backup) *api.ObjectMeta { return &v.Metadata })
	s.remotes = newKind(s, "remotes", "remote", api.ScopeFleet, func(v *api.Remote) *api.ObjectMeta { return &v.Metadata })
	s.tokens = newKind(s, "tokens", "token", api.ScopeFleet, func(v *api.Token) *api.ObjectMeta { return &v.Metadata })
	s.certs = newKind(s, "certificates", "certificate", api.ScopeFleet, func(v *api.Certificate) *api.ObjectMeta { return &v.Metadata })
	s.projects = newKind(s, "projects", "project", api.ScopeHost, func(v *api.Project) *api.ObjectMeta { return &v.Metadata })
	s.storages = newKind(s, "storage", "storage", api.ScopeHost, func(v *api.Storage) *api.ObjectMeta { return &v.Metadata })
	s.users = newKind(s, "users", "user", api.ScopeFleet, func(v *api.User) *api.ObjectMeta { return &v.Metadata })
	s.wireguard = newKind(s, "wireguard", "wireguard", api.ScopeFleet, func(v *api.WireGuard) *api.ObjectMeta { return &v.Metadata })

	s.volumes = newKind(s, "volumes", "volume", api.ScopeHost, func(v *api.Volume) *api.ObjectMeta { return &v.Metadata })
	s.profiles = newKind(s, "profiles", "profile", api.ScopeFleet, func(v *api.Profile) *api.ObjectMeta { return &v.Metadata })
	s.profiles.scoped = true
	s.setupProfiles()
	s.policies.scoped, s.addrsets.scoped, s.bpolicies.scoped = true, true, true
	s.backups.crossProject = true
	s.setupProjects()
	s.setupStorage()
	s.setupAccess()
	s.setupJails()
	s.setupVolumes()
	s.setupImages()
	s.setupNetworks()
	s.setupWireGuard()
	s.backups.readonly = true
	s.tokens.noCreate = true
	s.tokens.noUpdate = true
	s.users.noCreate = true
	s.targets.validate = func(o, _ *api.BackupTarget) *api.Error {
		if o.Spec.Kind != "node" && o.Spec.Kind != "pool" {
			return api.Errorf(api.CodeInvalid, "backup target kind must be node or pool")
		}
		return nil
	}

	m := muxer(func(pattern string, h http.HandlerFunc) {
		s.patterns = append(s.patterns, pattern)
		s.mux.HandleFunc(pattern, h)
	})
	m("GET /api/v1", s.handleInfo)
	m("GET /api/v1/events", s.handleEvents)
	m("GET /api/v1/operations", s.handleOpList)
	m("GET /api/v1/operations/{id}", s.handleOpGet)
	m("GET /api/v1/operations/{id}/wait", s.handleOpWait)
	m("DELETE /api/v1/operations/{id}", s.handleOpCancel)
	m("POST /api/v1/restores", s.handleRestore)
	m("POST /api/v1/tokens", s.createToken)
	m("POST /api/v1/users", s.createUser)
	m("POST /api/v1/users/{name}/password", s.setUserPassword)
	for _, reg := range []func(muxer){
		s.jails.register, s.volumes.register, s.images.register, s.networks.register, s.policies.register, s.addrsets.register,
		s.targets.register, s.bpolicies.register, s.backups.register, s.remotes.register,
		s.profiles.register, s.tokens.register, s.certs.register, s.users.register, s.projects.register, s.storages.register,
		s.wireguard.register,
	} {
		reg(m)
	}
	s.registerRenames(m)
	m("POST /api/v1/trust/tokens", s.createTrustToken)
	m("POST /api/v1/trust/clients", s.redeemTrustToken)
	m("GET /api/v1/sessions", s.listSessions)
	m("DELETE /api/v1/sessions/{id}", s.revokeSession)
	m("GET /api/v1/auth/session", s.handleWhoami)
	m("GET /api/v1/config-keys", s.handleConfigKeys)
	s.seedApps()
	m("GET /api/v1/apps", s.handleAppsList)
	m("GET /api/v1/apps/{name}", s.handleAppGet)
	m("POST /api/v1/apps/{name}/install", s.handleAppInstall)
	m("POST /api/v1/jails/{name}/config", s.jailConfig)
	m("POST /api/v1/jails/{name}/exec", s.jailExec)
	m("POST /api/v1/jails/{name}/console", s.consoleOpen)
	m("GET /api/v1/jails/{name}/console/{id}/output", s.consoleOutput)
	m("POST /api/v1/jails/{name}/console/{id}/input", s.consoleInput)
	m("POST /api/v1/jails/{name}/console/{id}/resize", s.consoleResize)
	m("DELETE /api/v1/jails/{name}/console/{id}", s.consoleClose)
	m("GET /api/v1/updates", s.handleUpdatesList)
	m("POST /api/v1/updates/check", s.handleUpdatesCheck)
	m("POST /api/v1/updates/apply", s.handleUpdatesApply)
	m("GET /api/v1/jails/{name}/updates", s.handleUpdateHistory)
	m("POST /api/v1/jails/{name}/provision", s.handleProvision)
	m("POST /api/v1/jails/{name}/shell-setup", s.handleShellSetup)
	m("GET /api/v1/host/identity", s.handleHostIdentity)
	m("PUT /api/v1/host/identity", s.handleHostIdentityPut)
	m("GET /api/v1/host/snapshots", s.handleHostSnapshots)
	m("POST /api/v1/host/snapshots/{name}/restore", s.handleHostRestore)
	m("GET /api/v1/host/firewall", s.handleHostFirewall)
	m("PUT /api/v1/host/firewall", s.handleHostFirewallPut)
	m("GET /api/v1/host/certificate", s.handleHostCertificate)
	m("PUT /api/v1/host/certificate", s.handleHostCertificateUpload)
	m("POST /api/v1/host/certificate/acme", s.handleHostCertificateACME)
	m("POST /api/v1/host/certificate/self-signed", s.handleHostCertificateSelfSigned)
	m("GET /api/v1/host/pending", s.handleHostPending)
	m("POST /api/v1/host/pending/confirm", s.handleHostPendingAction(true))
	m("POST /api/v1/host/pending/revert", s.handleHostPendingAction(false))
	m("GET /api/v1/backup/key", s.handleBackupKeyStatus)
	m("POST /api/v1/backup/key", s.handleBackupKeyCreate)
	m("POST /api/v1/backup/key/escrow", s.handleBackupKeyEscrow)
	m("POST /api/v1/backups/run", s.handleBackupRun)
	m("POST /api/v1/backups/{id}/verify", s.handleBackupVerify)
	m("GET /api/v1/jails/{name}/state", s.jailState)
	m("GET /api/v1/jails/{name}/usage", s.jailUsage)
	m("GET /api/v1/jails/{name}/logs", s.jailLogs)
	m("GET /api/v1/jails/{name}/logs/{file...}", s.jailLog)
	m("GET /api/v1/logs", s.handleLogs)
	m("GET /api/v1/boot", s.handleBoot)
	m("POST /api/v1/firewall/test", s.handleFirewallTest)
	m("GET /api/v1/logs/forward", s.handleLogForward)
	m("PUT /api/v1/logs/forward", s.handleLogForwardPut)
	m("DELETE /api/v1/logs/forward", s.handleLogForwardDelete)
	m("POST /api/v1/logs/forward/test", s.handleLogForwardTest)
	m("GET /api/v1/jails/{name}/app-draft", s.handleAppDraft)
	m("GET /api/v1/jails/{name}/access", s.handleAppAccess)
	m("POST /api/v1/jails/{name}/access", s.handleAppAllow)
	m("POST /api/v1/jails/{name}/access/deny", s.handleAppDeny)
	m("PUT /api/v1/jails/{name}/state", s.jailAction)
	m("POST /api/v1/volumes", s.volumeCreate)
	m("POST /api/v1/volumes/{name}/unlock", s.volumeUnlock)
	m("POST /api/v1/volumes/{name}/lock", s.volumeLock)
	m("POST /api/v1/volumes/{name}/passphrase", s.volumePassphrase)
	m("GET /api/v1/volumes/{name}/snapshots", s.volSnapList)
	m("POST /api/v1/volumes/{name}/snapshots", s.volSnapCreate)
	m("DELETE /api/v1/volumes/{name}/snapshots/{snap}", s.volSnapDelete)
	m("POST /api/v1/volumes/{name}/rollback", s.volRollback)
	m("GET /api/v1/jails/{name}/volumes", s.jailVolumes)
	m("POST /api/v1/jails/{name}/volumes", s.jailAttach)
	m("DELETE /api/v1/jails/{name}/volumes/{volume}", s.jailDetach)
	m("GET /api/v1/jails/{name}/snapshots", s.snapList)
	m("POST /api/v1/jails/{name}/snapshots", s.snapCreate)
	m("GET /api/v1/jails/{name}/snapshots/{snap}", s.snapGet)
	m("DELETE /api/v1/jails/{name}/snapshots/{snap}", s.snapDelete)
	m("POST /api/v1/jails/{name}/rollback", s.jailRollback)
	m("POST /api/v1/jails/{name}/upgrade", s.jailUpgrade)
	m("GET /api/v1/images/{name}/generations", s.genList)
	m("POST /api/v1/images/{name}/generations", s.genBuild)
	m("DELETE /api/v1/images/{name}/generations/{n}", s.genDelete)
	m("POST /api/v1/images/{name}/upgrade", s.imageUpgrade)
	m("PUT /api/v1/images/{name}/aliases/{alias}", s.aliasSet)
	m("DELETE /api/v1/images/{name}/aliases/{alias}", s.aliasDelete)
	m("GET /api/v1/networks/{name}/leases", s.leases)
	m("POST /api/v1/wireguard/join", s.wgJoin)
	m("POST /api/v1/wireguard/{name}/peers", s.wgPeerAdd)
	m("DELETE /api/v1/wireguard/{name}/peers/{peer}", s.wgPeerRemove)
	m("POST /api/v1/wireguard/{name}/up", s.wgSetDown(false))
	m("POST /api/v1/wireguard/{name}/down", s.wgSetDown(true))
	m("POST /api/v1/wireguard/{name}/rotate-keys", s.wgRotate)
	m("/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, api.Errorf(api.CodeNotFound, "no such route %s %s", r.Method, r.URL.Path))
	})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	auth := "trusted"
	if rc, aerr := s.authenticate(r); aerr != nil || !rc.authed {
		auth = "untrusted"
	}
	s.mu.Lock()
	info := api.ServerInfo{
		APIVersion: api.Version, APIExtensions: slices.Clone(s.extensions), Version: "fake",
		HostUUID: s.uuid, Hostname: s.hostname, Role: api.RoleHost, Hub: s.hub, Auth: auth,
		Environment: api.Environment{OS: "FreeBSD", KernelVersion: s.release, Arch: s.arch, Pool: "tank"}, SecretsRecipient: s.secretsRec,
	}
	s.mu.Unlock()
	if auth == "untrusted" {
		// as the daemon: a caller that proved nothing learns what a client negotiates with, nothing about the host
		info = api.ServerInfo{APIVersion: info.APIVersion, APIExtensions: info.APIExtensions, Role: info.Role, Auth: auth}
	}
	writeSync(w, 200, info)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	t, e := decode[api.Token](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	s.mu.Lock()
	rp := func() reply {
		if t.Spec.Permission == "" {
			return reply{err: api.Errorf(api.CodeInvalid, "token permission is required")}
		}
		if e := validIdentityScope(t.Spec.Projects, t.Spec.Global); e != nil {
			return reply{err: e}
		}
		if e := s.checkProjectsExist(t.Spec.Projects); e != nil {
			return reply{err: e}
		}
		if t.Metadata.Name == "" {
			t.Metadata.Name = "token-" + randHex(4)
		}
		if !validName(t.Metadata.Name) {
			return reply{err: api.Errorf(api.CodeInvalid, "invalid name %q", t.Metadata.Name)}
		}
		if s.tokens.items[t.Metadata.Name] != nil {
			return reply{err: api.Errorf(api.CodeAlreadyExists, "token %q already exists", t.Metadata.Name)}
		}
		t.Secret = ""
		s.tokens.insert(t, false)
		out := clone(t)
		out.Secret = "jot_" + randHex(16) // shown once, never stored
		return reply{status: 201, meta: out}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	req, e := decode[api.UserCreate](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	s.mu.Lock()
	rp := func() reply {
		name := req.Metadata.Name
		if !validName(name) {
			return reply{err: api.Errorf(api.CodeInvalid, "invalid name %q", name)}
		}
		if e := validIdentityScope(req.Spec.Projects, req.Spec.Global); e != nil {
			return reply{err: e}
		}
		if s.users.items[name] != nil {
			return reply{err: api.Errorf(api.CodeAlreadyExists, "user %q already exists", name)}
		}
		u := &api.User{Metadata: req.Metadata, Spec: req.Spec}
		s.users.insert(u, false)
		out := api.UserCreated{User: clone(u)}
		if req.Password == "" {
			out.Password = randHex(10)
		}
		return reply{status: 201, meta: out}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// setUserPassword implements POST /api/v1/users/{name}/password.
func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	req, e := decodeOptional[api.PasswordSet](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	s.mu.Lock()
	rp := func() reply {
		name := r.PathValue("name")
		if s.users.items[name] == nil {
			return reply{err: api.Errorf(api.CodeNotFound, "user %q not found", name)}
		}
		var out api.PasswordSet
		if req.Password == "" {
			out.Password = randHex(10)
		}
		return reply{status: 200, meta: out}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// handleRestore implements POST /api/v1/restores.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	req, e := decode[api.RestoreRequest](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	rc := s.info(r)
	s.mu.Lock()
	rp := func() reply {
		if req.Host != "" && req.Host != s.uuid {
			return reply{err: api.Errorf(api.CodeUnsupported, "the fake restores onto itself only")}
		}
		b := s.backups.items[req.Backup]
		if b == nil {
			return reply{err: notFound("backup", req.Backup)}
		}
		name := req.As
		if name == "" {
			name = b.Spec.Jail
		}
		// The jail goes into the project the body names, else the request's.
		if req.Project != "" {
			if s.projects.items[req.Project] == nil {
				return reply{err: notFound("project", req.Project)}
			}
			rc = &reqInfo{id: rc.id, kind: rc.kind, authed: rc.authed, project: req.Project}
		}
		if b.Spec.Kind == "volume" {
			return s.restoreVolumeBackup(rc.project, b, name, *req)
		}
		pf := api.RestorePreflight{}
		spec := clone(&b.Spec.Bundle.Spec)
		restoreVolumes := s.planRestoreVolumes(rc.project, b, name, *req, &spec, &pf)
		for i := range spec.Network {
			n := spec.Network[i].Network
			if m, ok := req.NetworkMap[n]; ok {
				n = m
			}
			spec.Network[i].Network = n
			if s.networks.items[n] == nil {
				pf.Missing = append(pf.Missing, "network "+n)
			}
			if !req.KeepIP {
				if spec.Network[i].IPv4 != "" && spec.Network[i].IPv4 != "none" {
					spec.Network[i].IPv4 = "auto"
				}
				if spec.Network[i].IPv6 != "" && spec.Network[i].IPv6 != "none" {
					spec.Network[i].IPv6 = "auto"
				}
			}
		}
		if s.images.items[imageName(spec.Image)] == nil {
			pf.Missing = append(pf.Missing, "image "+imageName(spec.Image))
		}
		if s.jails.items[s.jails.keyIn(rc.project, name)] != nil && !req.Replace {
			pf.Errors = append(pf.Errors, "jail "+name+" already exists")
		} else {
			pf.Changes = append(pf.Changes, "create jail "+name)
		}
		pf.OK = len(pf.Missing) == 0 && len(pf.Errors) == 0
		if req.DryRun {
			return reply{status: 200, meta: pf}
		}
		if !pf.OK {
			return reply{err: api.Errorf(api.CodeInvalid, "restore preflight failed").
				WithDetail("missing", strings.Join(pf.Missing, "; ")).WithDetail("errors", strings.Join(pf.Errors, "; "))}
		}
		jail := &api.Jail{Metadata: api.ObjectMeta{Name: name, Project: rc.project, Labels: nil}, Spec: spec}
		op := s.startOp(rc.project, "restores.create", "Restoring "+name, map[string][]string{"jails": {"/api/v1/jails/" + name}}, func() (any, *api.Error) {
			for _, vb := range restoreVolumes {
				s.restoreVolume(rc.project, vb, vb.Spec.Jail, "")
			}
			delete(s.jails.items, s.jails.keyIn(rc.project, name))
			if e := s.assignJail(jail, nil); e != nil {
				return nil, e
			}
			s.initJailStatus(jail)
			s.jails.insert(jail, false)
			return clone(jail), nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func imageName(ref string) string {
	if i := strings.IndexAny(ref, "@#"); i >= 0 {
		return ref[:i]
	}
	return ref
}

func genNumber(s string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(s, "g"))
	return n
}

// imageCreateHint is the server's hint for an image reference that names no image: the commands that make it.
func (s *Server) imageCreateHint(ref string) string {
	alias := ""
	if _, a, ok := strings.Cut(ref, "@"); ok {
		alias = a
	}
	return api.ImageCreateHint("it", imageName(ref), alias, api.BaseRelease(s.release))
}

// restoreVolumeBackup restores a volume backup as a new volume of the project, like the daemon: a name that is taken is
// refused, an encrypted volume needs its passphrase. s.mu is held.
func (s *Server) restoreVolumeBackup(project string, b *api.Backup, name string, req api.RestoreRequest) reply {
	if b.Spec.Volume == nil {
		return reply{err: api.Errorf(api.CodeInvalid, "backup %s holds no volume spec", b.Metadata.Name)}
	}
	pf := api.RestorePreflight{}
	switch {
	case s.volumes.items[project+"/"+name] != nil:
		pf.Errors = append(pf.Errors, "volume "+name+" already exists in project "+project+"; restore it under another name with as=NAME (a volume is never replaced)")
	case b.Spec.Volume.Encrypted && req.Passphrase == "":
		pf.Errors = append(pf.Errors, "the volume is encrypted: give its passphrase; it makes the volume again and is never stored")
	case !b.Spec.Volume.Encrypted && req.Passphrase != "":
		pf.Errors = append(pf.Errors, "a passphrase was given but the volume is not encrypted")
	default:
		pf.Changes = append(pf.Changes, "creates volume "+name+" in project "+project+" from backup "+b.Metadata.Name)
	}
	pf.OK = len(pf.Errors) == 0
	if req.DryRun {
		return reply{status: 200, meta: pf}
	}
	if !pf.OK {
		return reply{err: api.Errorf(api.CodeInvalid, "restore preflight failed").WithDetail("errors", strings.Join(pf.Errors, "; "))}
	}
	op := s.startOp(project, "restores.create", "Restoring "+name, map[string][]string{"volumes": {"/api/v1/volumes/" + name}}, func() (any, *api.Error) {
		v := s.restoreVolume(project, b, name, req.Passphrase)
		return clone(v), nil
	})
	return reply{op: &op}
}

// restoreVolume makes the volume of a volume backup. s.mu is held.
func (s *Server) restoreVolume(project string, b *api.Backup, name, passphrase string) *api.Volume {
	v := &api.Volume{Metadata: api.ObjectMeta{Name: name, Project: project}, Spec: *b.Spec.Volume}
	s.volumes.insert(v, false)
	if v.Spec.Encrypted {
		s.vol.init()
		key := project + "/" + name
		s.vol.pass[key], s.vol.locked[key] = passphrase, false
	}
	return v
}

// planRestoreVolumes decides how a jail restore gets the volumes the jail attaches that the project lacks: from their
// newest backup; with no_volumes every attachment is left out. It returns the backups to restore and notes the result in pf and spec.
// s.mu is held.
func (s *Server) planRestoreVolumes(project string, b *api.Backup, name string, req api.RestoreRequest, spec *api.JailSpec, pf *api.RestorePreflight) []*api.Backup {
	var restore []*api.Backup
	var keep []api.VolumeAttach
	if req.NoVolumes {
		if len(spec.Volumes) > 0 {
			pf.Changes = append(pf.Changes, "jail "+name+" is restored without its volumes (no_volumes): attach them with jailops volume attach")
		}
		spec.Volumes = nil
		return nil
	}
	for _, v := range spec.Volumes {
		if s.volumes.items[project+"/"+v.Name] != nil {
			keep = append(keep, v)
			continue
		}
		var best *api.Backup
		for _, k := range slices.Sorted(maps.Keys(s.backups.items)) {
			vb := s.backups.items[k]
			if vb.Spec.Kind == "volume" && vb.Spec.Jail == v.Name && vb.Metadata.Project == project && !vb.Status.Failed &&
				(best == nil || vb.Metadata.CreatedAt.After(best.Metadata.CreatedAt)) {
				best = vb
			}
		}
		switch {
		case best == nil:
			// like the daemon: the jail is restored, and does not start until the volume exists
			pf.Changes = append(pf.Changes, "volume "+v.Name+" is not in the project and no backup of it was found: the jail attaches it, and does not start until the volume exists")
		case best.Spec.Volume != nil && best.Spec.Volume.Encrypted:
			pf.Errors = append(pf.Errors, "volume "+v.Name+" is encrypted: restore its backup "+best.Metadata.Name+" first (it needs its passphrase), then restore the jail")
		default:
			restore = append(restore, best)
			pf.Changes = append(pf.Changes, "restores volume "+v.Name+" from backup "+best.Metadata.Name+" first")
		}
		keep = append(keep, v)
	}
	spec.Volumes = keep
	return restore
}
