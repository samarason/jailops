# Backup and restore

## What it is

Backups are **encrypted on the host before they leave it**, into a repository on a **backup node that holds no key**. The
host cuts data into content-defined chunks, compresses them (zstd) and encrypts them (XChaCha20-Poly1305). A chunk's id is a
keyed HMAC, so the node cannot even confirm that it holds known data. Every snapshot is self-contained, a list of references
to chunks: there are no incremental chains to break, and only new chunks are uploaded. The node sees object counts and sizes,
the deduplication graph, snapshot times, and host and jail identity. It never sees file names, contents or keys.

This is **not ZFS send and not ZFS native encryption**. ZFS gives the backup a consistent view (an atomic recursive snapshot).
Replication between hosts you trust is a separate feature that has no API or CLI yet. Design section 9 has the details.

What is in a backup, and what is not: see the last section of [storage.md](storage.md).

Verified on FreeBSD 15.1 arm64 (design 18.3, 18.4, and the clean-install run on both architectures): back up, verify at three
depths, restore as a new jail, the restored jail starts and has its data.

## The pieces

| | Where | Program |
|---|---|---|
| The jail host | every host | `jailopsd`, with a `backup:` section in `jailopsd.yaml` |
| The backup node | a machine you trust to be available, not to be secret | `jailops-backupd`, package `jailops-backupd`, needs PostgreSQL and a directory or an S3 bucket |

## 1. Set up the node

    # /usr/local/etc/jailops/backupd.yaml: see packaging/backupd.yaml
    jailops-backupd -c /usr/local/etc/jailops/backupd.yaml init --admin alice
    sysrc jailops_backupd_enable=YES
    service jailops_backupd start

`init` creates the repository, probes the datastore, migrates the database, creates the node's certificate and optionally the
first administrator, and **prints the certificate's fingerprint, which hosts pin**. Keep it.

## 2. Enrol the host

The host authenticates to the node with a client certificate; the node knows the certificate by fingerprint:

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout /var/db/jailops/backup-client.key -out /var/db/jailops/backup-client.crt -subj /CN=host1 -days 3650
    chown jailops /var/db/jailops/backup-client.*; chmod 600 /var/db/jailops/backup-client.key
    jailops-backupd -c /usr/local/etc/jailops/backupd.yaml hosts enroll host1 \
        --fingerprint <sha256 hex of the client certificate> --scopes backup-push,backup-pull,restore

`hosts list` and `hosts revoke NAME` manage them. A host cannot delete or overwrite its backups: writes are create-only, and
deletion is a request with a delay (`delete request`, default 72 hours) that the node's administrator can cancel.

## 3. Point the host at it

In `jailopsd.yaml` (see [configuration.md](configuration.md)):

    backup:
      node:
        name: vault
        address: backup.example.net:39111
        fingerprint: <the node's fingerprint>
        cert_file: /var/db/jailops/backup-client.crt
        key_file: /var/db/jailops/backup-client.key
      recovery_recipients: []        # age public keys; see the next section

Restart `jailopsd`. Without a `backup:` section every backup call answers `unsupported`.

## 4. The key, and the one thing you must not lose

    jailops backup key create        # prints the recovery key ONCE
    jailops backup key status

The **recovery key** (`JOR1-...`) is shown once, kept nowhere by JailOps and cannot be shown again. It is the only way to restore on
another machine if this host is lost. Store it offline. The host key itself is a file (`backup.key`, default under
`/var/db/jailops`), optionally wrapped with a passphrase (`backup.passphrase_file`; without one the file mode protects it, which
unattended schedules need).

**Escrow** wraps the key to one or more age recipients and uploads it to the node, so a holder of a matching identity can
recover it even when the host and the printed recovery key are gone:

    jailops backup key escrow --recipient age1...

Raw backups are **refused** (`key_not_escrowed`) while the key is not escrowed, unless `backup.allow_unescrowed` is true, which you
should not use outside a test.

## 5. Targets, policies and runs

A policy selects jails **by label**, so label the jails first:

    jailops label web --project shop backup=yes
    jailops backup target create vault --url https://backup.example.net:39111 --fingerprint <the node's fingerprint>
    jailops backup policy create nightly --project shop --selector backup=yes --target vault \
        --schedule "0 2 * * *" --keep-daily 14 --keep-weekly 8 --keep-monthly 12 \
        --verify-schedule "0 4 * * 0" --verify-mode extract
    jailops backup run --project shop nightly      # now, instead of at 02:00
    jailops backup list --project shop

An empty selector matches no jail. `--include-state` also backs up the host's state dataset.

**Volumes.** A policy also backs up the volumes of the jails it selects, and the volumes whose own labels match the selector.
A volume is a backup of its own, taken from its own snapshot, so a volume that three jails attach is copied **once** per run,
and a jail's backup holds no volume files. `jailops backup list` shows jail and volume backups with a KIND column
(`--volume NAME` lists one volume's). To leave volumes out, set `--no-volumes` on the policy, or
`jailops backup run nightly --no-volumes` for one run. An encrypted volume is backed up while it is unlocked; a locked one
is reported (`locked`) and backed up by the next run after `jailops volume unlock`. The files go to the node encrypted with
the backup key, like everything else. The node applies retention,
garbage collection (with a grace period, minimum 12 hours) and quarantine of corrupt chunks on its own schedule
(`jailops-backupd gc`, `verify`, `retention`, `quarantine list`, `quarantine add`, `escrow list`, `escrow delete`).

## 6. Verify

    jailops backup verify --project shop <id>                  # deep: reads and checks every chunk
    jailops backup verify --project shop <id> --depth extract  # restores into a scratch directory
    jailops backup verify --project shop <id> --depth full     # restores and boots a hidden jail with no network, checks it from the inside

`extract` and `full` need the key on the host that runs the check and a scratch location (`backup.scratch_dir`,
`backup.scratch_dataset`). Run verification on a schedule; an untested backup is not a backup. The node verifies the structure of what it holds
without a key (`jailops-backupd verify`).

### Who trusts whom: hosts that share a node

A repository has **one master key**, so one key domain: the node binds itself to the domain of the first host that backs up
or escrows (or to `init --key-domain`) and refuses every host with another key. Hosts that share a node therefore share the
key file: **each of them can read every other's backups**, and each can damage them. Treat the hosts of one node as one trust
group; hosts that do not trust each other need their own node (or their own repository).

What a host of the group can do to the others, and what the node does about it:

- **Plant a wrong chunk.** A chunk's id is a keyed hash of its plaintext, and the node holds no key: it checks only the
  unkeyed trailer of a blob, and it stores every chunk create-only. A host that uploads a self-consistent blob under the id
  of a chunk another host will need first makes the node answer "present" to the honest host, which then never uploads its
  own copy. The node's verify does not see it; a host's verify (`jailops backup verify`, deep by default) and every
  restore do, because they decrypt and recompute the id. The remedy is on the node: `jailops-backupd quarantine add CHUNK`
  (the id from the host's error) moves the blob aside, and the next backup that holds the chunk uploads it again. Run deep
  verification from a host on a schedule; an untested backup is not a backup.
- **Store a wrong escrow blob.** The node accepts only an age file (it checks the header, it cannot open it), create-only, so
  the first host to escrow a domain decides what is stored, and `jailops backup key status` on the others says "escrowed".
  Open the escrow blob with the recovery identity once, offline, after it is made. A blob that does not open is deleted by
  an administrator of the node (`jailops-backupd escrow delete DOMAIN`, or `DELETE /api/v1/escrow/{domain}` as
  `backup-admin`), and a host stores a new one with `jailops backup key escrow`.

Both remedies are audited. Making the node itself refuse a wrong chunk would need a change of the repository format (a
proof per chunk that the node can check without the key, or one chunk namespace per host at the cost of deduplication
between hosts); it is not built ([design.md](design.md) section 16).

## 7. Restore

Restoring always starts with a **preflight** that lists what is missing (image generations, networks, policies), what would be
created and what conflicts. Nothing is touched until you confirm.

    jailops backup restore --project shop <id> --as web-restored --dry-run     # the preflight only
    jailops backup restore --project shop <id> --as web-restored -y

**Volumes in a restore.** A jail restore brings back the volumes the jail attaches that the project does not have, each from
its newest backup, before the jail; a volume the project already has is attached as it is and never touched. `--no-volumes`
restores the jail with no volume attachments at all (attach the volumes afterwards). A volume
backup is restored on its own, as a new volume of the project, and never replaces one:

    jailops backup restore --project shop <volume backup id> --as mail-restored

An encrypted volume needs its passphrase for this (typed twice, or `--passphrase-file`), so it is restored before the
jail, not with it. The preflight lists the volumes a restore would make.

A restore names the project it goes into (`--project`; there is no default) and is admitted like a new jail: the project's
grants and quotas apply, and the network and storage must be granted to it. The jail gets a new UUID and fresh addresses
(`--keep-ip` keeps the fixed addresses, `--map` moves its networks). `--replace` destroys an existing jail and needs its name
typed or `--confirm-data-loss`.

**On a new host** (the old one is gone): the design is that a restore there needs only the recovery key (design 9.3). Install
JailOps, set up `backup:` pointing at the same node and enrol the new host's certificate on the node. **Not done yet:** the
`jailops backup key` commands are `create`, `escrow` and `status`; there is no command that loads a recovery key or an
escrowed key into a new host, so this path is **UNVERIFIED and not usable from the CLI today**. Keep the old host's
`backup.key` file (it is the key) in your own backup, and test a restore on a second machine with it before you rely on this.
The jail itself comes back from the repository: the preflight lists an image generation that is missing on the new host, and it
is rebuilt from pkgbase.

**UNVERIFIED:** S3 as a datastore on a real service.
