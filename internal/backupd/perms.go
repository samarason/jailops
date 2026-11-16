package backupd

import (
	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/sdk/api"
)

// Roles of the management API. A user holds exactly one.
const (
	RoleReadonly    = "readonly"     // look at everything except users, tokens and the audit log
	RoleBackupAdmin = "backup-admin" // operate: GC, verify, retention, protection, deletion requests, maintenance
	RoleAdmin       = "admin"        // everything, including hosts, users, tokens and the audit log
)

var roleToPerm = map[string]api.Permission{
	RoleReadonly:    api.PermReadonly,
	RoleBackupAdmin: api.PermBackupAdmin,
	RoleAdmin:       api.PermAdmin,
}

func pub(method, pattern string) auth.Entry {
	return auth.Entry{Method: method, Pattern: pattern, Public: true}
}

func ent(method, pattern string, p api.Permission) auth.Entry {
	return auth.Entry{Method: method, Pattern: pattern, Perm: p}
}

const (
	ro = api.PermReadonly
	ba = api.PermBackupAdmin
	ad = api.PermAdmin
)

// Perms is the permission table of the management API of the backup node. It
// is separate from the table of the host daemon: the backup node has its own
// roles and its own routes. Every route the server registers must have an
// entry; the server refuses to start otherwise. The routes of the host
// listener and of the admin socket are node.HostRoutes and node.AdminRoutes.
var Perms = []auth.Entry{
	pub("GET", "/api/v1"),
	pub("POST", "/api/v1/auth/login"),
	ent("POST", "/api/v1/auth/logout", ro),
	ent("GET", "/api/v1/auth/session", ro),
	ent("POST", "/api/v1/auth/password", ro),

	ent("GET", "/api/v1/repository", ro),
	ent("GET", "/api/v1/certificate", ro),

	ent("GET", "/api/v1/hosts", ro),
	ent("POST", "/api/v1/hosts", ad),
	ent("PUT", "/api/v1/hosts/{name}", ad),
	ent("DELETE", "/api/v1/hosts/{name}", ad),

	ent("GET", "/api/v1/groups", ro),
	ent("GET", "/api/v1/groups/{group}/snapshots", ro),
	ent("GET", "/api/v1/groups/{group}/snapshots/{snap}", ro),
	ent("PUT", "/api/v1/groups/{group}/snapshots/{snap}/protected", ba),
	ent("POST", "/api/v1/groups/{group}/snapshots/{snap}/deletion", ba),
	ent("DELETE", "/api/v1/groups/{group}/snapshots/{snap}/deletion", ba),
	ent("POST", "/api/v1/groups/{group}/snapshots/{snap}/deletion/execute", ba),

	ent("GET", "/api/v1/sessions", ro),
	ent("GET", "/api/v1/jobs", ro),
	ent("GET", "/api/v1/jobs/{id}", ro),
	ent("POST", "/api/v1/jobs/{id}/cancel", ba),
	ent("POST", "/api/v1/jobs/gc", ba),
	ent("POST", "/api/v1/jobs/verify", ba),
	ent("POST", "/api/v1/jobs/retention", ba),
	ent("POST", "/api/v1/jobs/reconcile", ba),

	ent("GET", "/api/v1/maintenance", ro),
	ent("PUT", "/api/v1/maintenance", ba),
	ent("GET", "/api/v1/quarantine", ro),
	ent("POST", "/api/v1/quarantine/purge", ba),
	ent("POST", "/api/v1/quarantine/{id}", ba),
	ent("GET", "/api/v1/escrow", ro),
	ent("DELETE", "/api/v1/escrow/{domain}", ba),
	ent("GET", "/api/v1/retention-policies", ro),
	ent("PUT", "/api/v1/retention-policies/{scope}", ba),
	ent("DELETE", "/api/v1/retention-policies/{scope}", ba),

	ent("GET", "/api/v1/audit", ad),
	ent("GET", "/api/v1/users", ad),
	ent("POST", "/api/v1/users", ad),
	ent("PUT", "/api/v1/users/{name}", ad),
	ent("DELETE", "/api/v1/users/{name}", ad),
	ent("GET", "/api/v1/tokens", ad),
	ent("POST", "/api/v1/tokens", ad),
	ent("DELETE", "/api/v1/tokens/{name}", ad),
}

// Registry is the registry over Perms.
func Registry() (*auth.Registry, error) { return auth.NewRegistry(Perms) }
