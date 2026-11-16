// Package api defines the wire types of the JailOps management API.
//
// These types are the single source of truth for the REST API (/api/v1), the
// declarative YAML used by jailops-sync, the JSON written to the state
// dataset, and the Go SDK. The package depends on the standard library only.
//
// Every resource separates desired state (Spec) from observed state (Status).
// Spec is what a user, a Raft log or a fleet repository asks for. Status is
// what one host observed about the operating system, and it never enters a
// replicated log.
package api

import "time"

// Version is the API version served under /api/v1.
const Version = "1.0"

// APIVersion is the apiVersion string used in declarative documents.
const APIVersion = "jailops/v1"

// Kind names a resource type in declarative documents and in the state store.
type Kind string

const (
	KindJail            Kind = "Jail"
	KindImage           Kind = "Image"
	KindNetwork         Kind = "Network"
	KindFirewallPolicy  Kind = "FirewallPolicy"
	KindAddressSet      Kind = "AddressSet"
	KindBackupPolicy    Kind = "BackupPolicy"
	KindBackupTarget    Kind = "BackupTarget"
	KindHostGroup       Kind = "HostGroup"
	KindRollout         Kind = "Rollout"
	KindJailTemplate    Kind = "JailTemplate"
	KindRemote          Kind = "Remote"
	KindUser            Kind = "User"
	KindToken           Kind = "Token"
	KindCertificate     Kind = "Certificate"
	KindHost            Kind = "Host"
	KindImageGeneration Kind = "ImageGeneration"
	KindJailSnapshot    Kind = "JailSnapshot"
	KindBackup          Kind = "Backup"
	KindOperation       Kind = "Operation"
	KindProject         Kind = "Project"
	KindStorage         Kind = "Storage"
	KindVolume          Kind = "Volume"
	KindWireGuard       Kind = "WireGuard"
	KindHostIdentity    Kind = "HostIdentity" // the singleton host identity object
	KindLogForward      Kind = "LogForward"   // the singleton list of log sinks
	KindHostFirewall    Kind = "HostFirewall" // the singleton host firewall object
	// the certificate of the console and the API
	KindHostCertificate Kind = "HostCertificate"
)

// Scope says who is authoritative for an object.
//
// ScopeHost objects live on exactly one host and are authoritative in that
// host's state dataset. ScopeFleet objects are shared management metadata:
// authoritative in the local state files on a single host or hub, and
// authoritative in the Raft log when cluster mode is enabled (the local files
// are then a projection of the log).
type Scope string

const (
	ScopeHost  Scope = "host"
	ScopeFleet Scope = "fleet"
)

// ObjectMeta is the identity and bookkeeping shared by all resources.
type ObjectMeta struct {
	// Name is unique per kind within its scope (per host for ScopeHost).
	Name string `json:"name" yaml:"name"`
	// UUID is assigned once at creation, never reused, and stable across
	// restore, migration and rename. Cross-host references use UUIDs.
	UUID string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// Project is the namespace of a project-level object (jails, volumes,
	// firewall policies, address sets, snapshots, backup policies). A project-level
	// object always carries its project; host-level objects have none. There is no
	// default project.
	Project string `json:"project,omitempty" yaml:"project,omitempty"`
	// Host is the UUID of the host that owns a ScopeHost object.
	Host string `json:"host,omitempty" yaml:"host,omitempty"`
	// Scope is fixed per kind and reported for clients.
	Scope Scope `json:"scope,omitempty" yaml:"scope,omitempty"`
	// Generation increases on every change to Spec. It doubles as the ETag
	// source: an update with a stale generation is rejected.
	Generation int64 `json:"generation,omitempty" yaml:"generation,omitempty"`
	// Labels select objects (backup policies, rollouts, host groups).
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	// ManagedBy marks objects created by jailops-sync, for example
	// "sync:<fleet-id>". jailops-sync never changes or deletes objects it does
	// not own.
	ManagedBy string `json:"managed_by,omitempty" yaml:"managed_by,omitempty"`
	// CreatedAt and UpdatedAt are set by the server. The proposer of a
	// replicated command supplies them so that applying the command is
	// deterministic.
	CreatedAt time.Time `json:"created_at,omitzero" yaml:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero" yaml:"updated_at,omitempty"`
}

// Condition reports one observed fact about an object as a typed
// True/False/Unknown status with a reason and a message. Conditions live in
// Status only.
type Condition struct {
	Type    string    `json:"type"`
	Status  string    `json:"status"` // "True", "False" or "Unknown"
	Reason  string    `json:"reason,omitempty"`
	Message string    `json:"message,omitempty"`
	Since   time.Time `json:"since,omitzero"`
}

// Condition status values.
const (
	ConditionTrue    = "True"
	ConditionFalse   = "False"
	ConditionUnknown = "Unknown"
)

// Document is the declarative envelope used in YAML files and in the state
// dataset. Spec is decoded according to Kind.
type Document struct {
	APIVersion string     `json:"apiVersion" yaml:"apiVersion"`
	Kind       Kind       `json:"kind" yaml:"kind"`
	Metadata   ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       any        `json:"spec" yaml:"spec"`
}
