package server

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// unsupportedRoutes are routes with a permission entry whose feature is not
// part of this version. They answer api.CodeUnsupported (501), never success.
var unsupportedRoutes = []struct{ method, pattern, what string }{
	{"PUT", "/api/v1/server", "changing the server configuration over the API"},
	{"GET", "/api/v1/server/config", "reading the server configuration over the API"},
	{"POST", "/api/v1/cluster/join", "cluster mode"},
	{"GET", "/api/v1/cluster", "cluster mode"},
	{"POST", "/api/v1/cluster/tokens", "cluster mode"},
	{"PUT", "/api/v1/cluster", "cluster mode"},
	{"DELETE", "/api/v1/cluster/members/{name}", "cluster mode"},
	{"GET", "/api/v1/cluster/members", "cluster mode"},
	{"GET", "/api/v1/jails/{name}/console", "listing console sessions (open one with POST /api/v1/jails/{name}/console)"},
	{"GET", "/api/v1/jails/{name}/files/{path...}", "file access"},
	{"PUT", "/api/v1/jails/{name}/files/{path...}", "file access"},
	{"POST", "/api/v1/jails/{name}/move", "cold moves"},
	{"POST", "/api/v1/jails/{name}/snapshots/{snapshot}", "snapshot rename"},
	{"GET", "/api/v1/jails/{name}/bundle", "bundle download"},
	{"GET", "/api/v1/jail-templates", "jail templates"},
	{"POST", "/api/v1/jail-templates", "jail templates"},
	{"GET", "/api/v1/jail-templates/{name}", "jail templates"},
	{"PUT", "/api/v1/jail-templates/{name}", "jail templates"},
	{"DELETE", "/api/v1/jail-templates/{name}", "jail templates"},
	{"POST", "/api/v1/backups", "starting a backup run"},
	{"POST", "/api/v1/backups/receive", "backup transport (it is the job of the backup node)"},
	{"GET", "/api/v1/backups/{id}/stream", "backup transport (it is the job of the backup node)"},
	{"GET", "/api/v1/backups/chains", "backup transport (it is the job of the backup node)"},
	{"POST", "/api/v1/backups/{id}/restore-preflight", "restore through this route (use POST /api/v1/restores)"},
	{"POST", "/api/v1/backups/{id}/restore", "restore through this route (use POST /api/v1/restores)"},
	{"GET", "/api/v1/groups", "host groups"},
	{"POST", "/api/v1/groups", "host groups"},
	{"GET", "/api/v1/groups/{name}", "host groups"},
	{"PUT", "/api/v1/groups/{name}", "host groups"},
	{"DELETE", "/api/v1/groups/{name}", "host groups"},
	{"GET", "/api/v1/rollouts", "rollouts"},
	{"POST", "/api/v1/rollouts", "rollouts"},
	{"GET", "/api/v1/rollouts/{name}", "rollouts"},
	{"PUT", "/api/v1/rollouts/{name}", "rollouts"},
	{"DELETE", "/api/v1/rollouts/{name}", "rollouts"},
}

// resource describes one plain CRUD collection.
type resource[T any] struct {
	base   string
	param  string
	list   func(ctx context.Context, labels map[string]string) ([]T, error)
	get    func(ctx context.Context, key string) (T, error)
	create func(ctx context.Context, v T) (T, error)
	put    func(ctx context.Context, key string, v T, expect int64) (T, error)
	patch  func(ctx context.Context, key string, p map[string]any, expect int64) (T, error)
	del    func(ctx context.Context, key string, expect int64) error
	gen    func(T) int64
	name   func(T) string
	// expanded answers ?expanded=true on an item.
	expanded func(ctx context.Context, key string) (any, int64, error)
}

func (res resource[T]) routes() []route {
	item := res.base + "/{" + res.param + "}"
	out := []route{
		{method: "GET", pattern: res.base, h: func(c *rc) error {
			l, err := c.labels()
			if err != nil {
				return err
			}
			v, err := res.list(c.r.Context(), l)
			if err != nil {
				return err
			}
			if v == nil {
				v = []T{}
			}
			c.sync(200, v, 0)
			return nil
		}},
		{method: "GET", pattern: item, h: func(c *rc) error {
			if res.expanded != nil && c.r.URL.Query().Get("expanded") == "true" {
				v, gen, err := res.expanded(c.r.Context(), c.pathArg(res.param))
				if err != nil {
					return err
				}
				c.sync(200, v, gen)
				return nil
			}
			v, err := res.get(c.r.Context(), c.pathArg(res.param))
			if err != nil {
				return err
			}
			c.sync(200, v, res.gen(v))
			return nil
		}},
	}
	if res.create != nil {
		out = append(out, route{method: "POST", pattern: res.base, h: func(c *rc) error {
			var in T
			if err := c.decode(&in); err != nil {
				return err
			}
			c.object = res.base + "/" + res.name(in)
			v, err := res.create(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.w.Header().Set("Location", res.base+"/"+res.name(v))
			c.sync(201, v, res.gen(v))
			return nil
		}})
	}
	if res.put != nil {
		out = append(out, route{method: "PUT", pattern: item, h: func(c *rc) error {
			var in T
			if err := c.decode(&in); err != nil {
				return err
			}
			exp, err := c.expect()
			if err != nil {
				return err
			}
			v, err := res.put(c.r.Context(), c.pathArg(res.param), in, exp)
			if err != nil {
				return err
			}
			c.sync(200, v, res.gen(v))
			return nil
		}})
	}
	if res.patch != nil {
		out = append(out, route{method: "PATCH", pattern: item, h: func(c *rc) error {
			var p map[string]any
			if err := c.decode(&p); err != nil {
				return err
			}
			exp, err := c.expect()
			if err != nil {
				return err
			}
			v, err := res.patch(c.r.Context(), c.pathArg(res.param), p, exp)
			if err != nil {
				return err
			}
			c.sync(200, v, res.gen(v))
			return nil
		}})
	}
	if res.del != nil {
		out = append(out, route{method: "DELETE", pattern: item, h: func(c *rc) error {
			exp, err := c.expect()
			if err != nil {
				return err
			}
			if err := res.del(c.r.Context(), c.pathArg(res.param), exp); err != nil {
				return err
			}
			c.sync(200, struct{}{}, 0)
			return nil
		}})
	}
	return out
}

func (s *Server) routeTable() []route {
	svc := s.svc
	var rs []route
	add := func(r ...route) { rs = append(rs, r...) }

	// Server.
	add(
		route{method: "GET", pattern: "/api/v1", h: func(c *rc) error {
			if c.actor.Perm == "" {
				// a caller that proved nothing learns what a client negotiates with, not the host's name, id,
				// software version or pool
				i := svc.Info("untrusted")
				c.sync(200, api.ServerInfo{APIVersion: i.APIVersion, APIExtensions: i.APIExtensions, Role: i.Role, Auth: i.Auth}, 0)
				return nil
			}
			c.sync(200, svc.Info("trusted"), 0)
			return nil
		}},
		// Readiness for load balancers and monitors: a fixed class only, never an error text.
		route{method: "GET", pattern: "/readyz", local: true, h: func(c *rc) error {
			reason := svc.Ready(c.r.Context())
			h := c.w.Header()
			h.Set("Content-Type", "text/plain; charset=utf-8")
			h.Set("Cache-Control", "no-store")
			if reason != "" {
				c.status = http.StatusServiceUnavailable
				c.w.WriteHeader(c.status)
				_, _ = io.WriteString(c.w, "not ready: "+reason+"\n")
				return nil
			}
			c.status = http.StatusOK
			_, _ = io.WriteString(c.w, "ok\n")
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/doctor", h: func(c *rc) error {
			c.sync(200, svc.Doctor(c.r.Context()), 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/doctor/fix", h: func(c *rc) error {
			var req api.DoctorFixRequest
			if err := c.decodeOptional(&req); err != nil {
				return err
			}
			res, err := svc.DoctorFix(c.r.Context(), req.DryRun)
			if err != nil {
				return err
			}
			c.sync(200, res, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/resources", h: func(c *rc) error {
			v, err := svc.Resources(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/audit", h: s.handleAudit},
		route{method: "GET", pattern: "/api/v1/events", h: s.handleEvents, long: true},
	)
	add(s.authRoutes()...)
	add(s.operationRoutes()...)

	// Images.
	add(resource[api.Image]{base: "/api/v1/images", param: "name",
		list:   svc.ListImages,
		get:    func(ctx context.Context, k string) (api.Image, error) { return svc.GetImage(ctx, k) },
		create: svc.CreateImage, put: svc.UpdateImage, patch: svc.PatchImage, del: svc.DeleteImage,
		gen: func(v api.Image) int64 { return v.Metadata.Generation }, name: func(v api.Image) string { return v.Metadata.Name },
	}.routes()...)
	add(
		route{method: "GET", pattern: "/api/v1/images/{name}/generations", h: func(c *rc) error {
			v, err := svc.ListGenerations(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/images/{name}/generations", h: func(c *rc) error {
			var b api.ImageBuild
			if err := c.decodeOptional(&b); err != nil {
				return err
			}
			op, err := svc.BuildGeneration(c.r.Context(), c.pathArg("name"), b)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/images/{name}/generations/{gen}", h: func(c *rc) error {
			n, err := strconv.Atoi(c.pathArg("gen"))
			if err != nil {
				return api.Errorf(api.CodeInvalid, "generation must be a number")
			}
			v, err := svc.GetGeneration(c.r.Context(), c.pathArg("name"), n)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/images/{name}/generations/{gen}", h: func(c *rc) error {
			n, err := strconv.Atoi(c.pathArg("gen"))
			if err != nil {
				return api.Errorf(api.CodeInvalid, "generation must be a number")
			}
			op, err := svc.DeleteGeneration(c.r.Context(), c.pathArg("name"), n)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/images/{name}/upgrade", h: func(c *rc) error {
			var u api.ImageUpgrade
			if err := c.decodeOptional(&u); err != nil {
				return err
			}
			op, err := svc.UpgradeImage(c.r.Context(), c.pathArg("name"), u)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "PUT", pattern: "/api/v1/images/{name}/aliases/{alias}", h: func(c *rc) error {
			var b api.ImageAliasSet
			if err := c.decodeOptional(&b); err != nil {
				return err
			}
			v, err := svc.SetImageAlias(c.r.Context(), c.pathArg("name"), c.pathArg("alias"), b.Generation)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/images/{name}/aliases/{alias}", h: func(c *rc) error {
			v, err := svc.DeleteImageAlias(c.r.Context(), c.pathArg("name"), c.pathArg("alias"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
	)

	add(s.jailRoutes()...)
	add(s.volumeRoutes()...)
	add(s.logRoutes()...)
	add(s.bootRoutes()...)
	add(s.firewallTestRoutes()...)

	// Networks and firewall.
	add(resource[api.Network]{base: "/api/v1/networks", param: "name",
		list:   svc.ListNetworks,
		get:    func(ctx context.Context, k string) (api.Network, error) { return svc.GetNetwork(ctx, k) },
		create: svc.CreateNetwork, put: svc.UpdateNetwork, patch: svc.PatchNetwork, del: svc.DeleteNetwork,
		gen: func(v api.Network) int64 { return v.Metadata.Generation }, name: func(v api.Network) string { return v.Metadata.Name },
	}.routes()...)
	add(route{method: "GET", pattern: "/api/v1/networks/{name}/leases", h: func(c *rc) error {
		v, err := svc.Leases(c.r.Context(), c.pathArg("name"))
		if err != nil {
			return err
		}
		c.sync(200, v, 0)
		return nil
	}})
	add(s.wireguardRoutes()...)
	add(resource[api.FirewallPolicy]{base: "/api/v1/firewall/policies", param: "name",
		list:   svc.ListPolicies,
		get:    func(ctx context.Context, k string) (api.FirewallPolicy, error) { return svc.GetPolicy(ctx, k) },
		create: svc.CreatePolicy, put: svc.UpdatePolicy, patch: svc.PatchPolicy, del: svc.DeletePolicy,
		gen: func(v api.FirewallPolicy) int64 { return v.Metadata.Generation }, name: func(v api.FirewallPolicy) string { return v.Metadata.Name },
	}.routes()...)
	add(resource[api.AddressSet]{base: "/api/v1/firewall/address-sets", param: "name",
		list:   svc.ListAddressSets,
		get:    func(ctx context.Context, k string) (api.AddressSet, error) { return svc.GetAddressSet(ctx, k) },
		create: svc.CreateAddressSet, put: svc.UpdateAddressSet, patch: svc.PatchAddressSet, del: svc.DeleteAddressSet,
		gen: func(v api.AddressSet) int64 { return v.Metadata.Generation }, name: func(v api.AddressSet) string { return v.Metadata.Name },
	}.routes()...)

	// Backup (host side).
	add(resource[api.BackupTarget]{base: "/api/v1/backup-targets", param: "name",
		list:   svc.ListTargets,
		get:    func(ctx context.Context, k string) (api.BackupTarget, error) { return svc.GetTarget(ctx, k) },
		create: svc.CreateTarget, put: svc.UpdateTarget, patch: svc.PatchTarget, del: svc.DeleteTarget,
		gen: func(v api.BackupTarget) int64 { return v.Metadata.Generation }, name: func(v api.BackupTarget) string { return v.Metadata.Name },
	}.routes()...)
	add(resource[api.BackupPolicy]{base: "/api/v1/backup-policies", param: "name",
		list:   svc.ListBackupPolicies,
		get:    func(ctx context.Context, k string) (api.BackupPolicy, error) { return svc.GetBackupPolicy(ctx, k) },
		create: svc.CreateBackupPolicy, put: svc.UpdateBackupPolicy, patch: svc.PatchBackupPolicy, del: svc.DeleteBackupPolicy,
		gen: func(v api.BackupPolicy) int64 { return v.Metadata.Generation }, name: func(v api.BackupPolicy) string { return v.Metadata.Name },
	}.routes()...)
	add(
		route{method: "GET", pattern: "/api/v1/backups", h: func(c *rc) error {
			l, err := c.labels()
			if err != nil {
				return err
			}
			v, err := svc.ListBackups(c.r.Context(), l)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/backups/{id}", h: func(c *rc) error {
			v, err := svc.GetBackup(c.r.Context(), c.pathArg("id"))
			if err != nil {
				return err
			}
			c.sync(200, v, v.Metadata.Generation)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/backups/{id}", h: func(c *rc) error {
			op, err := svc.DeleteBackup(c.r.Context(), c.pathArg("id"))
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/backup/key", h: func(c *rc) error {
			v, err := svc.BackupKeyStatus(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		// The recovery key is in this reply and nowhere else: a synchronous
		// answer, never an operation result, and nothing of it in the audit
		// detail or the log.
		route{method: "POST", pattern: "/api/v1/backup/key", h: func(c *rc) error {
			var in api.BackupKeyCreate
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			v, err := svc.CreateBackupKey(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.w.Header().Set("Cache-Control", "no-store")
			c.sync(201, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/backup/key/escrow", h: func(c *rc) error {
			var in api.BackupKeyEscrow
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			v, err := svc.EscrowBackupKey(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/backups/run", h: func(c *rc) error {
			var in api.BackupRunRequest
			if err := c.decode(&in); err != nil {
				return err
			}
			op, err := svc.RunBackups(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/backups/{id}/verify", h: func(c *rc) error {
			var in api.BackupVerifyRequest
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			op, err := svc.VerifyBackup(c.r.Context(), c.pathArg("id"), in)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/restores", h: func(c *rc) error {
			var req api.RestoreRequest
			if err := c.decode(&req); err != nil {
				return err
			}
			pf, op, err := svc.Restore(c.r.Context(), req)
			if err != nil {
				return err
			}
			if op != nil {
				c.async(*op)
				return nil
			}
			c.sync(200, pf, 0)
			return nil
		}},
	)

	// Configuration keys and profiles.
	add(resource[api.Profile]{base: "/api/v1/profiles", param: "name",
		list:   svc.ListProfiles,
		get:    func(ctx context.Context, k string) (api.Profile, error) { return svc.GetProfile(ctx, k) },
		create: svc.CreateProfile, put: svc.UpdateProfile, patch: svc.PatchProfile, del: svc.DeleteProfile,
		gen: func(v api.Profile) int64 { return v.Metadata.Generation }, name: func(v api.Profile) string { return v.Metadata.Name },
	}.routes()...)
	add(
		route{method: "GET", pattern: "/api/v1/config-keys", h: func(c *rc) error {
			c.sync(200, api.ConfigKeys(), 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/updates", h: func(c *rc) error {
			v, err := svc.ListUpdates(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/updates/check", h: func(c *rc) error {
			var in api.UpdateCheckRequest
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			op, err := svc.CheckUpdates(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/updates/apply", h: func(c *rc) error {
			var in api.UpdateApplyRequest
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			op, err := svc.ApplyUpdates(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/jails/{name}/updates", h: func(c *rc) error {
			v, err := svc.UpdateHistory(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}/provision", h: func(c *rc) error {
			var in api.ProvisionRequest
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			op, err := svc.ProvisionJail(c.r.Context(), c.pathArg("name"), in)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}/shell-setup", h: func(c *rc) error {
			var in api.ShellSetupRequest
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			op, err := svc.ShellSetupJail(c.r.Context(), c.pathArg("name"), in)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}/config", h: func(c *rc) error {
			var ch api.ConfigChange
			if err := c.decodeOptional(&ch); err != nil {
				return err
			}
			restart := c.r.URL.Query().Get("restart") == "true"
			op, err := svc.ConfigureJail(c.r.Context(), c.pathArg("name"), ch, restart)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
	)

	// The application catalog.
	add(
		route{method: "GET", pattern: "/api/v1/apps", h: func(c *rc) error {
			v, err := svc.ListApps(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/apps/{name}", h: func(c *rc) error {
			v, err := svc.GetApp(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/apps/{name}/install", h: func(c *rc) error {
			var in api.AppInstall
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			op, err := svc.InstallApp(c.r.Context(), c.pathArg("name"), in)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
	)

	// Host management.
	add(
		route{method: "GET", pattern: "/api/v1/host/identity", h: func(c *rc) error {
			v, err := svc.HostIdentity(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "PUT", pattern: "/api/v1/host/identity", h: func(c *rc) error {
			var in api.HostIdentityApply
			if err := c.decode(&in); err != nil {
				return err
			}
			if in.DryRun {
				c.detail = "dry_run"
			}
			v, err := svc.ApplyHostIdentity(c.r.Context(), in)
			if err != nil {
				return err
			}
			if v.Snapshot != "" {
				c.detail = "snapshot=" + v.Snapshot
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/host/snapshots", h: func(c *rc) error {
			v, err := svc.HostSnapshots(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/host/snapshots/{name}/restore", h: func(c *rc) error {
			var in api.HostRestore
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			if in.DryRun {
				c.detail = "dry_run"
			}
			v, err := svc.RestoreHostSnapshot(c.r.Context(), c.pathArg("name"), in)
			if err != nil {
				return err
			}
			if v.Snapshot != "" {
				c.detail = "snapshot=" + v.Snapshot
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/host/firewall", h: func(c *rc) error {
			v, err := svc.HostFirewall(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "PUT", pattern: "/api/v1/host/firewall", h: func(c *rc) error {
			var in api.HostFirewallApply
			if err := c.decode(&in); err != nil {
				return err
			}
			if in.DryRun {
				c.detail = "dry_run"
			}
			v, err := svc.ApplyHostFirewall(c.r.Context(), in)
			if err != nil {
				return err
			}
			if v.Pending != nil {
				c.detail = "snapshot=" + v.Snapshot + " pending=" + v.Pending.ID
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/host/pending", h: func(c *rc) error {
			v, err := svc.HostPending(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/host/pending/confirm", h: func(c *rc) error {
			var in api.HostPendingAction
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			v, err := svc.ConfirmHostPending(c.r.Context(), in)
			if err != nil {
				return err
			}
			if v.Last != nil {
				c.detail = "pending=" + v.Last.ID + " " + v.Last.Outcome
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/host/pending/revert", h: func(c *rc) error {
			var in api.HostPendingAction
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			v, err := svc.RevertHostPending(c.r.Context(), in)
			if err != nil {
				return err
			}
			if v.Last != nil {
				c.detail = "pending=" + v.Last.ID + " " + v.Last.Outcome
			}
			c.sync(200, v, 0)
			return nil
		}},
	)
	add(
		route{method: "GET", pattern: "/api/v1/host/certificate", h: func(c *rc) error {
			v, err := svc.HostCertificate(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "PUT", pattern: "/api/v1/host/certificate", h: func(c *rc) error {
			var in api.HostCertificateUpload
			if err := c.decode(&in); err != nil {
				return err
			}
			v, err := svc.UploadHostCertificate(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.detail = "uploaded fingerprint=" + v.Current.Fingerprint
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/host/certificate/acme", h: func(c *rc) error {
			var in api.ACMESpec
			if err := c.decode(&in); err != nil {
				return err
			}
			v, err := svc.UseACMECertificate(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.detail = "acme " + auditValue(strings.Join(in.Domains, ","))
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/host/certificate/self-signed", h: func(c *rc) error {
			v, err := svc.UseSelfSignedCertificate(c.r.Context())
			if err != nil {
				return err
			}
			c.detail = "self-signed fingerprint=" + v.Current.Fingerprint
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/setup", h: func(c *rc) error {
			v, err := svc.SetupStatus(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/setup", h: func(c *rc) error {
			var in api.SetupRequest
			if err := c.decode(&in); err != nil {
				return err
			}
			v, err := svc.Setup(c.r.Context(), in, c.remote())
			if err != nil {
				return err
			}
			c.object = "/api/v1/users/" + v.User.Metadata.Name
			c.sync(201, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/setup/token", h: func(c *rc) error {
			v, err := svc.IssueSetupToken(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
	)
	add(s.appAccessRoutes()...)
	add(s.renameRoutes()...)

	// Projects, storage, trust and sessions.
	add(resource[api.Project]{base: "/api/v1/projects", param: "name",
		list:   svc.ListProjects,
		get:    func(ctx context.Context, k string) (api.Project, error) { return svc.GetProject(ctx, k) },
		create: svc.CreateProject, put: svc.UpdateProject, patch: svc.PatchProject, del: svc.DeleteProject,
		gen: func(v api.Project) int64 { return v.Metadata.Generation }, name: func(v api.Project) string { return v.Metadata.Name },
	}.routes()...)
	add(resource[api.Storage]{base: "/api/v1/storage", param: "name",
		list:   svc.ListStorage,
		get:    func(ctx context.Context, k string) (api.Storage, error) { return svc.GetStorage(ctx, k) },
		create: svc.CreateStorage, put: svc.UpdateStorage, patch: svc.PatchStorage, del: svc.DeleteStorage,
		gen: func(v api.Storage) int64 { return v.Metadata.Generation }, name: func(v api.Storage) string { return v.Metadata.Name },
	}.routes()...)
	add(
		route{method: "POST", pattern: "/api/v1/trust/tokens", h: func(c *rc) error {
			var req api.TrustTokenRequest
			if err := c.decode(&req); err != nil {
				return err
			}
			c.object = "/api/v1/trust/tokens/" + req.Name
			out, err := svc.CreateTrustToken(c.r.Context(), req)
			if err != nil {
				return err
			}
			c.sync(201, out, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/trust/clients", h: func(c *rc) error {
			var req api.TrustClientRequest
			if err := c.decode(&req); err != nil {
				return err
			}
			cert, err := svc.RedeemTrustToken(c.r.Context(), req, c.remote())
			if err != nil {
				return err
			}
			c.object = "/api/v1/certificates/" + cert.Metadata.Name
			c.w.Header().Set("Location", "/api/v1/certificates/"+cert.Metadata.Name)
			c.sync(201, cert, cert.Metadata.Generation)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/sessions", h: func(c *rc) error {
			v, err := svc.ListSessions(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/sessions/{id}", h: func(c *rc) error {
			if err := svc.RevokeSession(c.r.Context(), c.pathArg("id")); err != nil {
				return err
			}
			c.sync(200, struct{}{}, 0)
			return nil
		}},
	)

	// Hub.
	add(resource[api.Remote]{base: "/api/v1/remotes", param: "name",
		list:   svc.ListRemotes,
		get:    func(ctx context.Context, k string) (api.Remote, error) { return svc.GetRemote(ctx, k) },
		create: svc.CreateRemote, put: svc.UpdateRemote, patch: svc.PatchRemote, del: svc.DeleteRemote,
		gen: func(v api.Remote) int64 { return v.Metadata.Generation }, name: func(v api.Remote) string { return v.Metadata.Name },
	}.routes()...)

	// Identity.
	add(resource[api.Certificate]{base: "/api/v1/certificates", param: "fingerprint",
		list: svc.ListCertificates, get: svc.GetCertificate,
		create: svc.CreateCertificate, put: svc.UpdateCertificate, patch: svc.PatchCertificate, del: svc.DeleteCertificate,
		gen: func(v api.Certificate) int64 { return v.Metadata.Generation }, name: func(v api.Certificate) string { return v.Metadata.Name },
	}.routes()...)
	add(resource[api.Token]{base: "/api/v1/tokens", param: "name",
		list: svc.ListTokens, get: svc.GetToken, create: svc.CreateToken,
		del: func(ctx context.Context, k string, _ int64) error { return svc.DeleteToken(ctx, k) },
		gen: func(v api.Token) int64 { return v.Metadata.Generation }, name: func(v api.Token) string { return v.Metadata.Name },
	}.routes()...)
	users := resource[api.User]{base: "/api/v1/users", param: "name",
		list: svc.ListUsers, get: svc.GetUser, put: svc.UpdateUser,
		patch: func(ctx context.Context, k string, p map[string]any, exp int64) (api.User, error) {
			cur, err := svc.GetUser(ctx, k)
			if err != nil {
				return cur, err
			}
			var out api.User
			if err := service.MergePatch(cur, p, &out); err != nil {
				return out, err
			}
			return svc.UpdateUser(ctx, k, out, exp)
		},
		del: func(ctx context.Context, k string, _ int64) error { return svc.DeleteUser(ctx, k) },
		gen: func(v api.User) int64 { return v.Metadata.Generation }, name: func(v api.User) string { return v.Metadata.Name },
	}.routes()
	add(users...)
	add(route{method: "POST", pattern: "/api/v1/users", h: func(c *rc) error {
		var in api.UserCreate
		if err := c.decode(&in); err != nil {
			return err
		}
		c.object = "/api/v1/users/" + in.Metadata.Name
		out, err := svc.CreateUser(c.r.Context(), in)
		if err != nil {
			return err
		}
		c.w.Header().Set("Location", "/api/v1/users/"+out.User.Metadata.Name)
		c.sync(201, out, 0)
		return nil
	}})

	add(route{method: "POST", pattern: "/api/v1/users/{name}/password", h: func(c *rc) error {
		var in api.PasswordSet
		if err := c.decodeOptional(&in); err != nil {
			return err
		}
		name := c.pathArg("name")
		c.object = "/api/v1/users/" + name
		out, err := svc.SetUserPassword(c.r.Context(), name, in.Password)
		if err != nil {
			return err
		}
		c.sync(200, out, 0)
		return nil
	}})

	for _, u := range unsupportedRoutes {
		what := u.what
		add(route{method: u.method, pattern: u.pattern, h: func(c *rc) error {
			return api.Errorf(api.CodeUnsupported, "%s is not part of this version", what)
		}})
	}
	return rs
}

// decodeOptional is decode for bodies that may be empty.
func (c *rc) decodeOptional(v any) error {
	if c.r.ContentLength != 0 {
		if err := c.jsonBody(); err != nil {
			return err
		}
	}
	return c.decodeBody(v, true)
}

var _ = http.StatusOK
