package node

import (
	"context"
	"slices"

	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/sdk/api"
)

// Route is one endpoint of the node, for the integrator's permission table.
type Route struct {
	Method  string
	Pattern string
	// Perm is the scope a caller needs. For host routes it is checked against
	// the host's enrolled scopes (restore includes read), for admin routes
	// against the permission of the local administrator or the UI user.
	Perm api.Permission
	// Local routes are administration: serve them on the local unix socket only.
	Local bool
	Doc   string
}

// Key is the "METHOD pattern" string handlers are registered under.
func (r Route) Key() string { return r.Method + " " + r.Pattern }

// Permission names used by the routes.
const (
	ScopePush    = api.PermBackupPush
	ScopePull    = api.PermBackupPull
	ScopeRestore = api.PermRestore
	ScopeAdmin   = api.PermBackupAdmin
	ScopeRead    = api.PermReadonly
)

// Base is the path prefix of the node API.
const Base = wire.Base

// HostRoutes are the routes a backup host (or recovery host) calls over the
// mutually authenticated network listener. None of them deletes or overwrites.
var HostRoutes = []Route{
	{"GET", Base, ScopePull, false, "repository description and limits"},
	{"POST", Base + "/sessions", ScopePush, false, "open the one session of a jail group (15 minute lease, renewed by activity)"},
	{"POST", Base + "/sessions/{sid}/missing", ScopePush, false, "which of up to 2000 chunk ids are missing; the present ones are pinned"},
	{"PUT", Base + "/sessions/{sid}/chunks/{id}", ScopePush, false, "upload a chunk blob, create-only; the SHA-256 trailer and the size are verified"},
	{"PUT", Base + "/sessions/{sid}/index", ScopePush, false, "upload the index of the snapshot"},
	{"PUT", Base + "/sessions/{sid}/manifest", ScopePush, false, "upload the encrypted manifest of the snapshot"},
	{"POST", Base + "/sessions/{sid}/commit", ScopePush, false, "commit: pin, check every chunk on the backend, write the receipt last; retries are idempotent"},
	{"POST", Base + "/sessions/{sid}/heartbeat", ScopePush, false, "renew the lease"},
	{"DELETE", Base + "/sessions/{sid}", ScopePush, false, "abort the session"},
	{"GET", Base + "/groups", ScopePull, false, "list the groups"},
	{"GET", Base + "/groups/{group}/snapshots", ScopePull, false, "list the committed snapshots of a group with their state"},
	{"GET", Base + "/groups/{group}/snapshots/{snap}", ScopePull, false, "one snapshot with its verify and protection state"},
	{"GET", Base + "/groups/{group}/snapshots/{snap}/index", ScopePull, false, "the index (Range supported)"},
	{"GET", Base + "/groups/{group}/snapshots/{snap}/receipt", ScopePull, false, "the commit receipt"},
	{"GET", Base + "/groups/{group}/snapshots/{snap}/manifest", ScopePull, false, "the encrypted manifest (Range supported)"},
	{"GET", Base + "/chunks/{id}", ScopePull, false, "a chunk blob (Range supported)"},
	{"POST", Base + "/restore-tests", ScopeRestore, false, "record the result of a restore test run on a host that holds the key"},
	{"GET", Base + "/escrow", ScopePull, false, "the key domains that have an escrow blob"},
	{"GET", Base + "/escrow/{domain}", ScopePull, false, "the escrow blob of a key domain (the master key wrapped to offline recovery recipients)"},
	{"PUT", Base + "/escrow/{domain}", ScopePush, false, "store the escrow blob of a key domain, create-only"},
}

// AdminRoutes are administration. They are served on the local unix socket
// only, never on the network listener.
var AdminRoutes = []Route{
	{"GET", Base + "/admin/status", ScopeRead, true, "repository status"},
	{"GET", Base + "/admin/sessions", ScopeRead, true, "open sessions"},
	{"GET", Base + "/admin/jobs", ScopeRead, true, "recent jobs"},
	{"GET", Base + "/admin/jobs/{id}", ScopeRead, true, "one job with its result"},
	{"POST", Base + "/admin/jobs/{id}/cancel", ScopeAdmin, true, "cancel a running job between batches"},
	{"POST", Base + "/admin/gc", ScopeAdmin, true, "garbage collection"},
	{"POST", Base + "/admin/verify", ScopeAdmin, true, "keyless verification (all, new, stale)"},
	{"POST", Base + "/admin/retention", ScopeAdmin, true, "apply retention (dry_run for the plan)"},
	{"POST", Base + "/admin/reconcile", ScopeAdmin, true, "rebuild the control plane's snapshot index from the repository"},
	{"GET", Base + "/admin/maintenance", ScopeRead, true, "maintenance mode"},
	{"PUT", Base + "/admin/maintenance", ScopeAdmin, true, "set the maintenance mode: online, read-only, offline"},
	{"PUT", Base + "/admin/groups/{group}/snapshots/{snap}/protected", ScopeAdmin, true, "protect or unprotect a snapshot"},
	{"POST", Base + "/admin/groups/{group}/snapshots/{snap}/deletion", ScopeAdmin, true, "request deletion (step one, with a delay)"},
	{"DELETE", Base + "/admin/groups/{group}/snapshots/{snap}/deletion", ScopeAdmin, true, "cancel a deletion request"},
	{"POST", Base + "/admin/groups/{group}/snapshots/{snap}/deletion/execute", ScopeAdmin, true, "execute a deletion request whose delay has passed"},
	{"GET", Base + "/admin/quarantine", ScopeRead, true, "quarantined chunks"},
	{"POST", Base + "/admin/quarantine/purge", ScopeAdmin, true, "remove healed quarantine entries"},
	{"POST", Base + "/admin/quarantine/{id}", ScopeAdmin, true, "move a chunk a host reported as undecryptable aside, although it passes the keyless check"},
	{"GET", Base + "/admin/escrow", ScopeRead, true, "key domains with an escrow blob"},
	{"DELETE", Base + "/admin/escrow/{domain}", ScopeAdmin, true, "delete a damaged escrow blob, so a host can store a new one"},
	{"GET", Base + "/admin/retention-policies", ScopeRead, true, "stored retention policies"},
	{"PUT", Base + "/admin/retention-policies/{scope}", ScopeAdmin, true, "store a retention policy (scope: default or a group id)"},
	{"DELETE", Base + "/admin/retention-policies/{scope}", ScopeAdmin, true, "remove a retention policy"},
}

// Routes returns every route of the node.
func Routes() []Route { return slices.Concat(HostRoutes, AdminRoutes) }

// Satisfies reports whether a holder of scope may use a route that needs need.
// The restore scope includes read access; admin includes everything.
func Satisfies(held, need api.Permission) bool {
	switch {
	case held == need, held == api.PermAdmin:
		return true
	case need == ScopeRead:
		return held == ScopePull || held == ScopeRestore || held == ScopeAdmin || held == api.PermOperator
	case need == ScopePull:
		return held == ScopeRestore
	case need == ScopeAdmin:
		return held == api.PermAdmin
	}
	return false
}

type ctxKey int

const (
	hostKey ctxKey = iota
	actorKey
)

// WithHost attaches the authenticated host to a request context. The transport
// layer (mutual TLS with pinned fingerprints) does this; the handler trusts it.
func WithHost(ctx context.Context, h Host) context.Context { return context.WithValue(ctx, hostKey, h) }

// HostFrom returns the host of a request context.
func HostFrom(ctx context.Context) (Host, bool) { h, ok := ctx.Value(hostKey).(Host); return h, ok }

// Actor is an administrator: a local unix socket peer or a management API user.
type Actor struct {
	Name   string
	Perm   api.Permission
	Remote string
}

// WithActor attaches the authenticated administrator to a request context.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey, a)
}

// ActorFrom returns the administrator of a request context.
func ActorFrom(ctx context.Context) (Actor, bool) { a, ok := ctx.Value(actorKey).(Actor); return a, ok }
