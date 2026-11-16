# Upgrading

Two different things: upgrading **JailOps itself**, and upgrading the **jails** it runs.

## JailOps

    pkg upgrade jailops jailops-client            # and jailops-backupd on a node
    service jailopsd restart
    jailops doctor

Both binaries are new and each service runs the old one until it restarts. The two are one service: the helper is the
part that runs as root. `service jailopsd stop` stops the helper after the daemon and `service jailopsd start` starts it
first, so `restart` replaces both. (`service jailopsd restart` alone restarts only the helper: the daemon, which keeps
running, reconnects once it is back, and the requests it makes meanwhile fail.) `service jailopsd start` also warns while
the helper still runs a replaced binary.
Running jails are not stopped by restarting either service: they are kernel jails. Restarting `jailopsd` briefly stops the
reconcile loop and the API. For a switched-IPv6 network the proxy stops answering while `jailopsd` is down, and announces its addresses
again when it is back.

What protects your data across an upgrade:

- The daemon copies its SQLite database (users, token hashes, sessions, audit log) with `VACUUM INTO` once a day into
  `<data_dir>/backups/`, keeping the newest seven, and a ZFS snapshot of the state dataset is taken before destructive operations.
- Everything else is derived: the jail files and PF anchors are rendered again from the stored objects on the next pass.
- Back up `<data_dir>/secrets.key` (the age identity that opens sealed secrets), `backup.key` and your TLS material with your
  own tools; they are not in a JailOps backup.

**The helper's socket moved** to `/var/run/jailops-priv/priv.sock` (a directory of root, mode 0710, group `jailops`).
Upgrading from a release that used `/var/run/jailops/priv.sock`, stop both services before `pkg upgrade` and start them
after it, the helper first:

    service jailopsd stop && service jailops_priv stop
    pkg upgrade jailops jailops-client
    service jailopsd start

`priv.conf` and `jailopsd.yaml` that still name the old path keep working: both programs read it as the new one. A
daemon of the old release left running would look for the helper at the old path. At its first start the new helper
also gives the directory of every storage root to root with mode 0700 and sets `devices=off` on the root dataset
([security-model.md](security-model.md#two-programs-one-boundary)); `service jailops_priv checkconfig` shows a root it refuses.

Read [CHANGELOG.md](../CHANGELOG.md) before upgrading. A configuration key that was removed is an error, because the files
reject unknown keys: the daemon names the key and does not start until you remove it (for example `experimental:` from an
early build). **UNVERIFIED:** upgrades between released versions of JailOps; there has been no release yet, and nothing
migrates from the pre-release layouts.

After a FreeBSD minor release upgrade of the host (15.1 to 15.2 and so on), run `jailops doctor` and, if you can, the PF test
(`scripts/ci-freebsd-pf.sh`) before relying on the firewall: pf changes between releases, and a rule that loads without an
error but does nothing is exactly what the read-back and that test exist to catch.

## Jails

### An image is one release

An image is one FreeBSD release and is named after it: `freebsd-15-1` is 15.1-RELEASE, `freebsd-15-2` is 15.2-RELEASE.
Its **generations** (g1, g2, ...) are the patch levels of that release: each `jailops image upgrade` builds the next one
with the release's current patches and packages. A thin jail's root is a clone of one generation, an immutable pkgbase
userland; a jail made with `--image freebsd-15-1` follows the newest generation of the image. A new release (15.2, 16.0)
is **a new image**, never a new generation of an old one: there is no in-place release upgrade of a jail.

**g1 is JailOps's generation counter; p6 is the FreeBSD patch level of its packages.** The number of a generation counts
the builds of the image on this host (g1, g2, ...) and says nothing about FreeBSD. When a generation is built, JailOps
records the FreeBSD version its base packages come from (the version of the `FreeBSD-runtime` package, `15.1p6`, shown
as `15.1-RELEASE-p6`; a snapshot of a branch keeps the package version as it is, `15.snap20261031190411`). `jailops image
show` and `jailops image generation list` have a column `FREEBSD`, `jailops list` writes `freebsd-15-1 (g1, p6)`, and the
console shows it on the Images page and the jail's page. A generation built before 0.6.1 shows `-`: JailOps does not
guess it afterwards.

| You want | You run |
|---|---|
| the patches of the release your jails run | `jailops image upgrade freebsd-15-1` (or the nightly auto upgrade, below) |
| a new release | upgrade the host, then `jailops image create freebsd-15-2 --release 15.2-RELEASE` and `jailops image build freebsd-15-2`, and create new jails on it |

### Patch levels: image upgrade

Upgrading moves a jail to a newer generation of its image and keeps its data. One command does it for the whole image:

    jailops image upgrade freebsd-15-1 --dry-run         # the build plan, and which jails would move
    jailops image upgrade freebsd-15-1                   # build the next generation, then move every thin jail to it

`image upgrade` builds the next generation from the newest one (its packages upgraded; minutes), then moves every thin jail
that uses the image, in every project, one at a time, exactly as `jail upgrade` does (below), writing the same update history
and events as `update apply`. It **stops at the first jail that fails or needs a human**: the jails after it are listed as not
attempted, so a bad generation is not rolled across the host; fix the jail (its history says what happened) and run the
command again. When the package set did not change, nothing is kept and no jail is touched; the command says so. A stopped
jail is moved too: it is started for the health check and stopped again. Thick jails, Linux jails (always thick), jails with an
update strategy other than `rebase` and jails pinned to a generation (`freebsd-15-1#g3`) are skipped and listed. `--project P`
moves one project's jails, `--no-jails` builds the generation only, and `jailops image generation list freebsd-15-1` shows who is
where afterwards.

The same in two steps, one jail at a time:

    jailops image build freebsd-15-1                     # build the next generation (minutes)
    jailops jail upgrade web --dry-run --project shop    # what would change
    jailops jail upgrade web --project shop              # snapshot, new root, /etc merge, swap, health check
    jailops jail rollback web --project shop             # root only: back to the previous generation, data untouched

A generation is written `gN` wherever a command takes one (`image build --from g2`, `jail upgrade --generation g4`,
`image generation delete freebsd-15-1 g1`); a bare number is accepted too. As an advanced option an image can also carry
aliases, movable names for one generation (`jailops image alias add freebsd-15-1 tested g2`, used as `freebsd-15-1@tested`);
the plain name, which follows the newest generation, is what the console and these documents use.

### Nightly auto upgrade

Instead of running `image upgrade` by hand, let JailOps do it every night, per image:

    jailops image set freebsd-15-1 --auto-upgrade --upgrade-at 03:00     # --no-packages leaves the packages inside the jails alone
    jailops image set freebsd-15-1 --auto-upgrade=false
    jailops image show freebsd-15-1                           # the next run and the latest runs with their results

In the console it is the checkbox **Upgrade automatically every night** on the image's card of the Images page (with the
time and **Also upgrade the packages inside the jails**), and the same checkbox in **Create image**. It is off until you tick it: JailOps upgrades nothing on its own
unless you asked. The card shows the next run and the latest runs; a failed run is shown as a notice on the card until a later
run succeeds. Only a global administrator changes it; everyone else sees it.

What a run does, every night at the chosen time (the host's time zone; 03:00 unless you choose another):

1. It builds the image's next generation: the patch updates of the release (minutes). When nothing changed, the run is
   recorded as unchanged and nothing else happens.
2. It moves the thin jails of the image to the new generation one at a time, exactly as `image upgrade` does: snapshot,
   new root, `/etc` merge, health check, and the automatic rollback of a jail whose health check fails. **It stops at the
   first jail that fails**; the jails after it stay where they are until the next run or until you run `image upgrade`.
3. With packages on (the default), it upgrades the packages inside the jails of the image.

It leaves alone the jails whose update strategy is manual or in place (and thick jails, Linux jails and jails pinned to a
generation, as `image upgrade` does). A host that was off at the chosen time runs the upgrade when it is back, if that is
within four hours; later than that it waits for the next night. Each run is recorded with its time, its result (ok,
unchanged or failed, with what failed) and the number of jails moved, upgraded and failed.

**From a cron script to auto upgrade.** If you ran `jailops image upgrade` (and a package upgrade per jail) from cron, remove
that entry and turn auto upgrade on for the image at the same hour. What changes: the daemon runs it itself, so it needs no
token or client on the host; a host that was off catches up within four hours; the packages are upgraded in the same run;
and each run's result is kept with the image (`jailops image show`, the console) instead of in a mail from cron.

### A new release: a new image

A new FreeBSD release is a new image. Existing jails stay on the image of their release; nothing moves them to another
release. The order:

1. **Upgrade the host first.** A jail runs on the host's kernel, so the host must run a release at least as new as the
   image's; a jail is not moved to a generation of a newer release than the host's kernel ("upgrade the host first").
   After the host's upgrade run `jailops doctor`
   (see [JailOps](#jailops) above for the firewall check).
2. **Create and build the image of the new release:**

       jailops image create freebsd-15-2 --release 15.2-RELEASE
       jailops image build freebsd-15-2
       jailops image set freebsd-15-2 --auto-upgrade --upgrade-at 03:00

   The console proposes this itself: when the host runs a newer release than the newest FreeBSD image, the Images page and
   the Overview say so and offer **Create image** for it, filled in.
3. **Create new jails on the new image** (`--image freebsd-15-2`); `jailops app install` takes the newest release the host
   can run when no `--image` is given.

**Moving a jail's data to a jail of the new release is not automated.** No command moves a jail, its volumes or its data from
one release to another. Do it as you would on any new machine: create the new jail next to the old one, copy or export the
data from the old jail and import it in the new one with the application's own tools, check it, move the addresses or
ports over, and delete the old jail when you no longer need it. Take a backup of the old jail first
([backup-restore.md](backup-restore.md)). The old image keeps receiving its patch levels for as long as the release is
supported; delete it (`jailops image delete freebsd-15-1`) once no jail uses it.

### What an upgrade of a jail does

The upgrade takes one atomic snapshot of all the jail's datasets (the rollback point), clones the new generation, merges
`/etc` three ways (the account databases `passwd`, `master.passwd` and `group` are merged by JailOps itself by user and group
name), swaps the roots with `zfs rename`, starts the jail and runs its health check. On failure it swaps back and starts the old
root. An `/etc` conflict a human must resolve leaves the jail on the old generation (`merge_conflict`).

What a failed upgrade puts back depends on whether the jail had run on the new generation. Before the start nothing the
jail wrote exists, so `/etc` and `/var/db` go back to the moment before the merge. After the start `/etc` still goes back
(it was merged for the new generation and the old root needs its own), but `/var/db` keeps what the jail wrote while it ran:
the databases of the packages are not rolled back. Changes made to files in `/etc` by the jail in that window are lost.

Rollback has scopes, and the difference matters:

| Scope | Does | Data |
|---|---|---|
| `--root` (default) | the OS root back to the previous generation | untouched |
| `--data --snapshot S` | the data datasets back to a snapshot | **everything written since is discarded for good** |
| `--all` | both | as `--data` |

Before `--data` or `--all` the command shows how many bytes were written since the snapshot and asks you to type the jail name;
in a script pass `--confirm-data-loss` (`-y` does not apply to data loss).

Open: how `/var/db/pkg` behaves after a root swap (design section 16). A thick jail (a full copy) and a Linux jail are not
rebased; they are updated in place, and a debootstrap (Debian) generation cannot be upgraded: build a new one.

## Managed updates

Updates are **off for every jail** until you set its update mode:

    jailops set web updates.mode=notify updates.schedule="0 3 * * 0" updates.packages=true updates.os=true --project shop
    jailops update check --project shop         # every jail of the project: lists what could change, changes nothing
    jailops update apply --project shop web     # snapshot first, update, health check, record
    jailops update history web --project shop

Modes: `manual` (default), `notify` (check on the schedule and report), `managed` (check and apply on the schedule). `updates.packages`
updates packages inside the jail from the host, `updates.os` moves it to a newer image generation, `updates.reboot` (`manual` or `auto`)
says whether a restart an update needs is applied automatically. The daemon evaluates schedules every `updates.tick`.

- An apply takes a snapshot, updates, runs the jail's health check and records the result. A **failed OS update is swapped back**
  by the root-swap plan.
- A **failed package update is not rolled back by itself**: package files live in the jail's datasets, so a root rollback does not
  undo them. The way back is `jail rollback --all --snapshot <the recorded one>`, which discards what the jail wrote since. The record
  says so.
- Package checks and updates inside a jail run `pkg` (FreeBSD jails) or `apk` (Alpine). **Debian jails have no managed package
  updates or provisioning yet** (design section 16).
- UNVERIFIED: the package and generation updates have been tested with fakes, and the mechanism ran on a real jail only
  for the generation swap. `jailops-sync` rollouts stage upgrades across hosts (canary, batches, a health gate); see
  [fleet-sync.md](fleet-sync.md).
