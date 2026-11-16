// Package hostbackup is the host side of JailOps backups (design section 9):
// the jail host's key, capture, schedule, restore and restore tests. It sits
// between the daemon and the repository engine (internal/repo/engine) and talks
// to a backup node through internal/node/client. The backup node itself never
// links this package: it holds no key and runs no restore.
//
// # What it does
//
//   - Key management (keymgr.go). CreateKey makes the key file (mode 0600,
//     optionally wrapped with Argon2id) at Config.KeyPath, which defaults to
//     /var/db/jailops/backup.key, and returns the recovery key, which the caller
//     shows once and nobody stores. EscrowKey wraps the key to the offline
//     recovery recipients (age public keys) and uploads the blob to the node.
//     Status is none, present or escrowed. ImportKey and RecoverKeyFromEscrow
//     install the key on a new host from the recovery key or from the escrow blob
//     and a recovery identity. A backup is refused with api.CodeKeyNotEscrowed
//     when the key is not escrowed (unless Config.AllowUnescrowed) and with
//     api.CodePlaintextDenied when the host holds no key: nothing leaves the host
//     unencrypted.
//   - Capture (capture.go). BackupJail takes ONE atomic zfs snapshot named
//     jailops-backup-<time>-<rand> over the data datasets of the jail's record,
//     reads each through <mountpoint>/.zfs/snapshot/<name>, hands each dataset to
//     engine.Backup as a stream with its GUID, createtxg and the properties
//     restore needs, includes the restore bundle (backup.BuildBundle), and
//     destroys the snapshot afterwards, also on failure, through a reverter. The
//     previous snapshot is the base: the engine fetches its manifest and catalog
//     and applies the forced-full-read rules of design 9.4 (no usable base, base
//     failed verification, last full read too old, change of the ctime setting).
//     Missing-chunk queries of the engine's parallel workers are batched
//     (batch.go). The jail is not stopped; Hooks may quiesce an application
//     around the snapshot only. The thin root is not captured; the container
//     dataset (spec.json, bundle.json) and the persistent datasets are, and so
//     is the root of a thick jail. A volume is no part of a jail's capture: it is
//     a record of its own (IsVolume, from Deps.Volumes) with one dataset, backed
//     up as its own unit, so a volume that many jails attach is copied once.
//   - Policies and schedule (scheduler.go). Service.Run evaluates api.BackupPolicy
//     objects (label selector, targets, cron schedule with deterministic jitter,
//     include_state, full_every, verify_schedule and verify_mode), runs due jobs
//     with bounded concurrency and one job per jail, retries with exponential
//     backoff, treats a node in maintenance as a deferral, and records every run
//     in the Catalog. A policy also backs up the volumes the jails it selects
//     attach and the volumes whose labels match its selector, each once, unless
//     the policy sets exclude_volumes (RunOptions.NoVolumes for one run). RunNow runs a policy at once. Retention is the backup
//     node's job and is not done here.
//   - Restore (restore.go). Preflight gathers the real host state (through Host)
//     and applies backup.Preflight; a missing image generation on the target
//     storage is refused. RestoreWith creates the jail's datasets below the
//     placement the daemon chooses, extracts them with engine.Restore, rebuilds
//     the thin root as a clone of the image generation, ensures networks,
//     policies and address sets, applies network_map and keep_ip, registers the
//     jail with a new UUID unless replace is set, and leaves it stopped unless
//     RestoreOptions.Start. A volume of the jail that the project lacks is
//     restored first from its newest backup (VolumeHost), or its attachment is
//     left out with no_volumes; an encrypted volume is restored on its own, with
//     its passphrase (RestoreVolumeBackup). A failure at any step is undone. Replace never
//     destroys: the old datasets are parked. RestoreFiles restores single files
//     or subtrees into a directory. Restore needs the key of the backup's key
//     domain on the host.
//   - Restore tests (drill.go). drillEnv implements backup.DrillEnv on engine.Verify
//     (deep and extract) and on the restore machinery (full, with the daemon's
//     DrillRunner). They run on the host, never on the node, on the schedule of
//     the policy, and the result is reported to the node, which marks a damaged
//     snapshot failed so that it is never a base again.
//
// # Wiring in the daemon
//
// The daemon (role host) must do exactly this:
//
//  1. Build a Config from its configuration: HostUUID, KeyPath, Passphrase or
//     PassphraseFile, RecoveryRecipients, Node (Address, Fingerprint pinned,
//     CertFile and KeyFile of the host's client certificate), Concurrency,
//     ScratchDir, and ScratchDataset for full restore tests.
//  2. Build Deps. ZFS is the internal/sys/zfs client. Jails turns the host's jail
//     registry into JailRecord values: name, uuid, project, labels, spec, the
//     container dataset and every dataset of the jail with its Kind and
//     mountpoint (taken from the record and the dataset properties, never built
//     here), the image generation of the root and the sealed secret references.
//     Objects resolves networks, policies and address sets. Policies reads
//     BackupPolicy and BackupTarget objects. Host implements State, Place,
//     EnsureObjects, Adopt, Running and Start with the lifecycle, the network and
//     firewall objects and the registry; Adopt writes spec.json and bundle.json
//     and registers the jail. Images is ImagegenImages over the image managers
//     (one per storage). Catalog is OpenFileCatalog in the state directory (or an
//     SQLite implementation). Optional: Hooks, State (include_state), Drill (full
//     restore tests), Observer (events, metrics).
//  3. Call New(cfg, deps) and pass the result as the daemon service's Backups
//     dependency: *Service satisfies service.Backups (List, Get, Delete,
//     Preflight, Restore) as it is. Delete answers api.CodeUnsupported: deletion
//     is the backup node's retention.
//  4. Start the scheduler with go svc.Run(ctx) on a daemon context and call
//     svc.Close() after cancelling it. Run removes stale backup snapshots first.
//  5. Expose the key operations to the CLI and API (CreateKey, Status, EscrowKey,
//     ImportKey, RecoverKeyFromEscrow), print the recovery key once, and call
//     Reindex(ctx, "") once at start when the catalog is empty (a new host with
//     a recovery key). Expose RunNow, RunDrill and RestoreFiles for the matching
//     commands. A restore's RestoreRequest.As and Replace are handled here; the
//     daemon's per-jail lock around the operation is still the daemon's.
//
// # Not verified on FreeBSD
//
// Everything that needs a real pool is marked UNVERIFIED where it is used: the
// .zfs/snapshot access (OSMounter), whether ctime and inode numbers are stable
// across snapshots (Config.NoTrustCtime), extraction into a container whose
// children are mounted, and zfs rename of a mounted tree when a jail is
// replaced. The tests run against the in-memory ZFS of internal/sys/zfs and a
// directory that stands in for the snapshot directory.
package hostbackup
