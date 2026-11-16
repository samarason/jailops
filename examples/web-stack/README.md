# web-stack

nginx in front of an app in front of PostgreSQL, on one host, with **encrypted backups to a keyless backup node**.

    internet --80/443--> nginx (10.60.0.10) --8080--> app (10.60.0.20) --5432--> postgres (10.60.0.30)

- The jails sit on one network of one project (`shop`). Each has its own firewall policy, so nginx accepts web traffic
  from anywhere, the app accepts port 8080 only from nginx and PostgreSQL accepts port 5432 only from the app.
- PostgreSQL's data is a **volume** (`postgres-data` at `/var/db/postgres`, a quota of 50G, owned by uid 770): a dataset of the
  project with its own snapshots, untouched when the OS root is replaced by an image update and still there when the jail is deleted.
- `DB_PASSWORD` and `POSTGRES_PASSWORD` are `secret:db.password`, a value of `shared/secrets.sops.yaml` (SOPS + age). Sync
  decrypts it in memory when it applies, seals it to the host's own age key and sends it sealed; the repository holds only
  ciphertext and the API never returns it.
- `provision:` installs nginx and PostgreSQL inside the new jails the first time they start.

## The backup schedule

`projects/shop/backup-policies/nightly.yaml` selects every jail labelled `backup: nightly` (app and postgres), runs at 02:17,
keeps 14 daily, 8 weekly and 12 monthly backups on the node and restore-tests the newest one every Sunday at 04:30
(`verify_mode: extract`). `shared/backup-targets/vault.yaml` is the node.

Backups are **encrypted on the host before they leave it**, with a key the backup node never holds: the node stores
chunks it cannot read and sees only sizes, timestamps and jail identity. A stolen node leaks no data, and a compromised
host cannot delete its own backups (writes are create-only; deletion is a delayed request the node's administrator
can cancel). The pieces that are **not** YAML, because they are keys and enrolment, are done once:

    # 1. on the backup machine (package jailops-backupd, PostgreSQL, a directory or an S3 bucket)
    jailops-backupd -c /usr/local/etc/jailops/backupd.yaml init --admin alice     # prints the node's fingerprint
    # 2. on the host: a client certificate, enrolled on the node (see backup-restore.md section 2)
    # 3. on the host, jailopsd.yaml gets a `backup:` section naming the node (address, fingerprint, cert_file, key_file)
    # 4. on the host: create the key and escrow it. The recovery key is shown ONCE; store it offline.
    jailops backup key create
    jailops backup key escrow --recipient age1...

Put the node's fingerprint into `shared/backup-targets/vault.yaml`, then `jailops-sync sync --apply` creates the target and the
policy. Everything in [backup-restore.md](../../docs/backup-restore.md) applies: restore always starts with a preflight, and
restoring on a new host from the recovery key alone is **not usable from the CLI today** (UNVERIFIED, said there too).

## Run it

    jailops-sync -C examples/web-stack validate
    jailops-sync -C examples/web-stack plan          # compare with EXPECTED-PLAN.md
    jailops-sync -C examples/web-stack secrets check # the age token opens with $JAILOPS_SYNC_AGE_IDENTITY
    jailops-sync -C examples/web-stack sync --apply
    jailops backup run --project shop nightly        # now, instead of at 02:17

`hosts/app1/host.yaml` reaches the host over https with a pinned fingerprint and an API token of a **global admin**
(creating networks, images and projects needs one): `jailops token create sync --role admin --global --expires 2160h
--allow-from <your address>`, then `jailops-sync secrets set app1-token`. To take the token out of the picture use a client
certificate instead (`jailops-sync remote bootstrap`, see [multi-host-fleet](../multi-host-fleet)).

## Verified, and not

Backup, verify at three depths and restore as a new jail are verified on FreeBSD 15.1 arm64 (backup-restore.md).
**UNVERIFIED:** the provisioning of nginx and PostgreSQL inside the jails as written here, and this repository applied to a
real host (the tests apply it to in-memory hosts and check every object with the daemon's validators).
