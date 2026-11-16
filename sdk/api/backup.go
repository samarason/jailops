package api

import "time"

// Role is the role a jailopsd process runs in.
type Role string

const (
	RoleHost   Role = "host"   // runs jails
	RoleBackup Role = "backup" // ZFS receiver, no jails
	// A hub is a mode, not a role: any host or backup node may also be a hub.
)

// BackupTarget is a backup node that stores encrypted backups. The node holds
// no key. A target may also be a local directory for tests and for backing up
// to an attached disk.
type BackupTarget struct {
	Metadata ObjectMeta       `json:"metadata"`
	Spec     BackupTargetSpec `json:"spec"`
}

// BackupTargetSpec describes a backup destination.
type BackupTargetSpec struct {
	// Comment is what the object is for: one line of free text.
	Comment string `json:"comment,omitempty"`
	// Kind is "node" (a jailopsd in backup role over HTTPS) or "directory".
	Kind    string `json:"kind"`
	Address string `json:"address,omitempty"`
	// Fingerprint pins the node's certificate.
	Fingerprint string `json:"fingerprint,omitempty"`
	Path        string `json:"path,omitempty"`
}

// BackupPolicy selects jails and says when and how to back them up.
type BackupPolicy struct {
	Metadata ObjectMeta       `json:"metadata"`
	Spec     BackupPolicySpec `json:"spec"`
}

// BackupPolicySpec is the desired backup behaviour. Backups are always
// encrypted on the host before they leave it.
type BackupPolicySpec struct {
	// Comment is what the object is for: one line of free text.
	Comment string `json:"comment,omitempty"`
	// Selector matches jails by label. An empty selector matches none; use
	// the label "all" explicitly to match every jail.
	Selector map[string]string `json:"selector,omitempty"`
	// Targets are BackupTarget names.
	Targets []string `json:"targets"`
	// Schedule is a five-field cron expression.
	Schedule  string          `json:"schedule"`
	Retention RetentionPolicy `json:"retention"`
	// IncludeState also backs up the host's state dataset.
	IncludeState bool `json:"include_state,omitempty"`
	// ExcludeVolumes leaves the volumes out. By default a policy also backs up the volumes the jails it selects
	// attach, and the volumes whose own labels match the selector, each volume once however many jails attach it.
	ExcludeVolumes bool `json:"exclude_volumes,omitempty"`
	// FullEvery forces a full read of the data (still deduplicated) when
	// the last full read is older than this many days. Zero uses the default.
	FullEvery int `json:"full_every,omitempty"`
	// VerifySchedule is a cron expression for restore tests, which run on a
	// host that holds the key.
	VerifySchedule string `json:"verify_schedule,omitempty"`
	// VerifyMode is "deep", "extract" or "full".
	VerifyMode string `json:"verify_mode,omitempty"`
}

// RetentionPolicy is grandfather-father-son retention, evaluated on the
// backup node, which is the only place backups are deleted.
type RetentionPolicy struct {
	Last    int `json:"last,omitempty"`
	Hourly  int `json:"hourly,omitempty"`
	Daily   int `json:"daily,omitempty"`
	Weekly  int `json:"weekly,omitempty"`
	Monthly int `json:"monthly,omitempty"`
	Yearly  int `json:"yearly,omitempty"`
}

// Backup is one committed backup snapshot in a repository.
type Backup struct {
	Metadata ObjectMeta   `json:"metadata"`
	Spec     BackupSpec   `json:"spec"`
	Status   BackupStatus `json:"status"`
}

// BackupSpec identifies what was backed up.
type BackupSpec struct {
	// Kind is "jail" (the default) or "volume". A volume is a backup of its own: Jail and JailUUID then name the
	// volume and its UUID, and Volume holds what restore needs to make it again.
	Kind     string `json:"kind,omitempty"`
	Jail     string `json:"jail"`
	JailUUID string `json:"jail_uuid"`
	// Volume is the spec of the volume of a volume backup (never the passphrase of an encrypted one).
	Volume   *VolumeSpec `json:"volume,omitempty"`
	HostUUID string      `json:"host_uuid"`
	Policy   string      `json:"policy,omitempty"`
	Target   string      `json:"target,omitempty"`
	// Snapshot is the repository snapshot id (YYYYMMDDHHMMSS-xxxxxxxx).
	Snapshot string `json:"snapshot"`
	// ZFSSnapshot is the name of the consistent snapshot the capture read.
	ZFSSnapshot string `json:"zfs_snapshot,omitempty"`
	// KeyDomain is the non-secret domain id of the master key that protects
	// the snapshot; restore needs the key or its escrow on the restoring host.
	KeyDomain string `json:"key_domain,omitempty"`
	// Full is true when the capture read all data instead of reusing the
	// previous catalog.
	Full bool `json:"full,omitempty"`
	// Bundle is the restore closure manifest (see RestoreBundle).
	Bundle RestoreBundle `json:"bundle"`
}

// BackupStatus is the state recorded on the backup node.
type BackupStatus struct {
	Bytes      int64     `json:"bytes,omitempty"`     // logical size
	NewBytes   int64     `json:"new_bytes,omitempty"` // bytes uploaded for this snapshot
	Chunks     int       `json:"chunks,omitempty"`
	Files      int64     `json:"files,omitempty"`
	Verified   bool      `json:"verified,omitempty"`
	VerifiedAt time.Time `json:"verified_at,omitzero"`
	// Failed is set when verification found a missing or corrupt chunk; a
	// failed snapshot is never a base for later runs.
	Failed    bool `json:"failed,omitempty"`
	Protected bool `json:"protected,omitempty"`
	// PendingDeletion is set when an admin requested deletion; the delay
	// before it takes effect protects against mistakes and compromise.
	PendingDeletion *time.Time `json:"pending_deletion,omitzero"`
}

// RepositoryStatus is reported by a backup node.
type RepositoryStatus struct {
	ID           string    `json:"id"`
	Mode         string    `json:"mode"`    // online, read-only, offline
	Backend      string    `json:"backend"` // directory, s3
	Snapshots    int       `json:"snapshots"`
	Chunks       int64     `json:"chunks"`
	Bytes        int64     `json:"bytes"`
	LastGC       time.Time `json:"last_gc,omitzero"`
	LastVerify   time.Time `json:"last_verify,omitzero"`
	Quarantined  int       `json:"quarantined"`
	OpenSessions int       `json:"open_sessions"`
}

// RestoreBundle is written to the jail dataset on every change and travels in
// every backup. It lists everything a jail needs on a new host.
type RestoreBundle struct {
	Spec JailSpec `json:"spec"`
	// ImageGeneration and ImageManifest identify the base the root needs.
	ImageGeneration string `json:"image_generation"`
	ImageManifest   string `json:"image_manifest"`
	// Networks, Policies and AddressSets are frozen copies of the objects the
	// jail referenced when the backup was taken.
	NetworkNames    []string             `json:"network_names,omitempty"`
	PolicyNames     []string             `json:"policy_names,omitempty"`
	AddressSetNames []string             `json:"address_set_names,omitempty"`
	Networks        []NetworkSpec        `json:"networks,omitempty"`
	Policies        []FirewallPolicySpec `json:"policies,omitempty"`
	AddressSets     []AddressSetSpec     `json:"address_sets,omitempty"`
	Volumes         []string             `json:"volumes,omitempty"`
	// VolumeIDs maps the name of each volume the jail attached to the volume's UUID. A restore brings back a volume
	// the project lacks only from a backup of that very volume, never from a newer one of another volume that had the
	// name.
	VolumeIDs map[string]string `json:"volume_ids,omitempty"`
	// SecretRefs name sealed secrets; the secrets are never in the bundle.
	SecretRefs []string `json:"secret_refs,omitempty"`
}

// RestoreRequest is the body of POST /api/v1/restores.
type RestoreRequest struct {
	Backup string `json:"backup"`
	// Host is the UUID of the host to restore on; empty means this host.
	Host string `json:"host,omitempty"`
	// As renames the restored jail; the restored jail gets a new UUID unless
	// Replace is set.
	As      string `json:"as,omitempty"`
	Replace bool   `json:"replace,omitempty"`
	// Project is the project to restore into; empty means the project of the
	// backup. The caller needs access to it, and it applies the project's
	// grants and quotas like a new jail does.
	Project string `json:"project,omitempty"`
	// NetworkMap maps network names in the bundle to local networks.
	NetworkMap map[string]string `json:"network_map,omitempty"`
	KeepIP     bool              `json:"keep_ip,omitempty"`
	// DryRun returns the preflight report and changes nothing.
	DryRun bool `json:"dry_run,omitempty"`
	// NoVolumes restores a jail with no volume attachments at all (attach them afterwards). By default the volumes
	// the project lacks are restored from their newest backup first and the others are attached as they are.
	NoVolumes bool `json:"no_volumes,omitempty"`
	// Passphrase is the passphrase of the restored volume when the backup holds an encrypted volume; it is used once
	// to make the volume and never stored.
	Passphrase string `json:"passphrase,omitempty"`
}

// RestorePreflight is the report produced before any restore changes state.
type RestorePreflight struct {
	OK      bool     `json:"ok"`
	Missing []string `json:"missing,omitempty"` // generations, networks, policies
	Changes []string `json:"changes,omitempty"` // what would be created or altered
	Errors  []string `json:"errors,omitempty"`  // address conflicts, version skew
}

// BackupKeyStatus is the reply of GET /api/v1/backup/key. Status is "none" (no
// key on this host), "present" (a key, not escrowed) or "escrowed".
type BackupKeyStatus struct {
	Status string `json:"status"`
	// Domain identifies the key domain; it is not secret.
	Domain string `json:"domain,omitempty"`
	// Path is the key file on the host.
	Path string `json:"path,omitempty"`
}

// BackupKeyCreate is the body of POST /api/v1/backup/key. Recipients are age
// public keys the key is escrowed to; empty uses the daemon's configuration.
type BackupKeyCreate struct {
	Recipients []string `json:"recipients,omitempty"`
}

// BackupKeyCreated is the reply of POST /api/v1/backup/key. RecoveryKey is
// shown once: the daemon keeps it nowhere and never logs it, and nothing can
// show it again. Escrowed is false, with EscrowError set, when the key was
// created but could not be uploaded; POST /api/v1/backup/key/escrow retries.
type BackupKeyCreated struct {
	Domain      string `json:"domain"`
	RecoveryKey string `json:"recovery_key"`
	Escrowed    bool   `json:"escrowed"`
	EscrowError string `json:"escrow_error,omitempty"`
}

// BackupKeyEscrow is the body of POST /api/v1/backup/key/escrow.
type BackupKeyEscrow struct {
	Recipients []string `json:"recipients,omitempty"`
}

// BackupRunRequest is the body of POST /api/v1/backups/run: run a backup policy
// now for every jail it selects.
type BackupRunRequest struct {
	Policy string `json:"policy"`
	// NoVolumes leaves the volumes out of this run.
	NoVolumes bool `json:"no_volumes,omitempty"`
}

// BackupVerifyRequest is the body of POST /api/v1/backups/{id}/verify. Depth is
// "deep" (read and check every chunk), "extract" (restore into a scratch
// directory) or "full" (restore and start the jail isolated); the default is
// "deep".
type BackupVerifyRequest struct {
	Depth string `json:"depth,omitempty"`
}

// BackupRun is the result of one backup or restore test. The result of a run
// operation is a list of them.
type BackupRun struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // backup or drill
	Policy    string    `json:"policy,omitempty"`
	Target    string    `json:"target,omitempty"`
	Project   string    `json:"project,omitempty"`
	Jail      string    `json:"jail"`
	JailUUID  string    `json:"jail_uuid,omitempty"`
	Scheduled bool      `json:"scheduled,omitempty"`
	Attempt   int       `json:"attempt,omitempty"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	Code      Code      `json:"code,omitempty"`
	Snapshot  string    `json:"snapshot,omitempty"`
	Full      bool      `json:"full,omitempty"`
	Bytes     int64     `json:"bytes,omitempty"`
	NewBytes  int64     `json:"new_bytes,omitempty"`
	Files     int64     `json:"files,omitempty"`
	Warnings  []string  `json:"warnings,omitempty"`
	Depth     string    `json:"depth,omitempty"`
	Problems  []string  `json:"problems,omitempty"`
}
