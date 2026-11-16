package api

import "time"

// KindAppAccess is the kind of the grant registry of one installed app (the
// jail's name is the object's name) in the state store and in fleet sync
// documents.
const KindAppAccess Kind = "AppAccess"

// AppAccessManagedBy is the managed_by marker of the firewall policies that
// app access writes (app-<jail>). Nobody else changes or deletes them.
const AppAccessManagedBy = "app-access"

// AppAccessTypePostgreSQL is the one type of access block this daemon knows.
const AppAccessTypePostgreSQL = "postgresql"

// AppAccessDef is the optional access block of a definition: what JailOps does
// inside the app's jail when a source is allowed, besides the firewall rule.
// An app without it gets the firewall rule only.
type AppAccessDef struct {
	// Type is "postgresql": a role and a database per grant, made with psql run
	// as postgres in the jail, and a line per source address in HBAFile.
	Type string `json:"type" yaml:"type"`
	// Port names the port of ports: a grant opens (the SQL port).
	Port string `json:"port" yaml:"port"`
	// Service is the rc.d service restarted when listen_addresses changes.
	Service string `json:"service" yaml:"service"`
	// HBAFile is the client authentication file; one of the config: paths.
	HBAFile string `json:"hba_file" yaml:"hba_file"`
}

// Source kinds of an access grant.
const (
	AccessSourceJail = "jail"        // @jail, a jail of the same project
	AccessSourceSet  = "address-set" // @set, an address set of the project
	AccessSourceCIDR = "cidr"        // an address or a prefix
	AccessSourceHost = "host"        // the host itself: the gateway addresses of the jail's networks
)

// AppAccessGrant is one source allowed to reach an installed app.
type AppAccessGrant struct {
	// Source is what was allowed, in its canonical form: "@web", "@office",
	// "192.0.2.0/24", "host".
	Source string `json:"source"`
	// SourceKind is jail, address-set, cidr or host.
	SourceKind string `json:"source_kind"`
	// Addresses are the prefixes the source stood for when the grant was last
	// applied (an address set stays a reference in the firewall).
	Addresses []string `json:"addresses,omitempty"`
	// Ports are "5432/tcp".
	Ports []string `json:"ports"`
	// Database and Role are set for an app with an access block. Only the
	// existence of the role is kept: its password is never stored.
	Database string `json:"database,omitempty"`
	Role     string `json:"role,omitempty"`
	// RoleCreated and DatabaseCreated say that JailOps made them; it never
	// changes or drops a role it did not make.
	RoleCreated     bool `json:"role_created,omitempty"`
	DatabaseCreated bool `json:"database_created,omitempty"`
	// Rules are the firewall rules of the grant as typed rules
	// ("allow in tcp from 192.0.2.7 to port 5432").
	Rules []string `json:"rules"`
	// PF are the lines of the jail's rendered anchor that the rules became;
	// empty while the jail has no anchor (it is stopped).
	PF []string `json:"pf,omitempty"`
	// HBA are the lines of the grant in the managed block of the app's
	// client authentication file.
	HBA       []string  `json:"hba,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	CreatedBy string    `json:"created_by,omitempty"`
	// Problems are differences between the grant and what the host has: a
	// rule missing from the policy, a line missing from the file, a source jail
	// that is gone.
	Problems []string `json:"problems,omitempty"`
}

// AppAccess is GET /api/v1/jails/<name>/access: who may connect to an
// installed app.
type AppAccess struct {
	Jail    string `json:"jail"`
	Project string `json:"project"`
	App     string `json:"app"`
	// Type is the definition's access type ("postgresql"), empty for an app
	// that gets firewall rules only.
	Type string `json:"type,omitempty"`
	// Policy is the managed firewall policy of the app (app-<jail>).
	Policy string `json:"policy"`
	// Closed says the jail is closed to every source that is not granted:
	// the policy exists and denies by default. An app installed before app
	// access existed is open until its first grant.
	Closed bool `json:"closed"`
	// Ports are the ports a grant opens by default ("5432/tcp").
	Ports  []string         `json:"ports"`
	Grants []AppAccessGrant `json:"grants"`
	// Warnings say what the reader should know (an open jail, a stopped one).
	Warnings []string `json:"warnings,omitempty"`
}

// AppAllow is the body of POST /api/v1/jails/<name>/access.
type AppAllow struct {
	// Source is @jail, @address-set, an address or a prefix, or host.
	Source string `json:"source"`
	// Ports are "N" or "N/proto"; default: the definition's ports (the access
	// block's port for an app that has one).
	Ports []string `json:"ports,omitempty"`
	// Database names the database and the role of a postgresql grant; default:
	// the source jail's name with "-" turned into "_". Required for other sources.
	Database string `json:"database,omitempty"`
	// Rotate gives the role of an existing grant a new password.
	Rotate bool `json:"rotate,omitempty"`
	// DryRun returns what would be done, without the password, and changes nothing.
	DryRun bool `json:"dry_run,omitempty"`
}

// AppAllowResult answers an allow.
type AppAllowResult struct {
	Jail  string         `json:"jail"`
	Grant AppAccessGrant `json:"grant"`
	// Changed is false when the grant existed as it is and nothing was done.
	Changed bool `json:"changed"`
	// ConnectionString is shown once, when a role was made or given a new
	// password: postgres://ROLE:PASSWORD@HOST:5432/DB?sslmode=disable. It is
	// not stored anywhere.
	ConnectionString string `json:"connection_string,omitempty"`
	// SQL are the statements run (or, in a dry run, that would run) with the
	// password left out.
	SQL []string `json:"sql,omitempty"`
	// Steps describe what was done, in order.
	Steps []string `json:"steps,omitempty"`
	// Notes are what the person has to know or do next.
	Notes  []string `json:"notes,omitempty"`
	DryRun bool     `json:"dry_run,omitempty"`
}

// AppDeny is the body of POST /api/v1/jails/<name>/access/deny.
type AppDeny struct {
	Source string `json:"source"`
	// DropRole drops the grant's role when JailOps made it and no other grant
	// uses it; what it owns is given to postgres, the database is kept.
	// Without it the role only loses its login.
	DropRole bool `json:"drop_role,omitempty"`
	DryRun   bool `json:"dry_run,omitempty"`
}

// AppDenyResult answers a deny.
type AppDenyResult struct {
	Jail string `json:"jail"`
	// Removed is the grant as it was.
	Removed AppAccessGrant `json:"removed"`
	// Changed is false when no such grant existed.
	Changed bool     `json:"changed"`
	SQL     []string `json:"sql,omitempty"`
	Steps   []string `json:"steps,omitempty"`
	Notes   []string `json:"notes,omitempty"`
	DryRun  bool     `json:"dry_run,omitempty"`
}
