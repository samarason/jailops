# Operations: runbooks and monitoring

What to do when something goes wrong, written from what the product does today. Every command here exists in
`jailops --help`, `jailops-priv` or `jailops-backupd`; what is not built is said plainly. Run the `jailops` commands as
root on the host (root on the unix socket is a global administrator) or with an identity that has the role named.

Two questions are kept apart in every runbook: **taking access away** (a credential stops working at once) and
**getting data back** (from snapshots, the database copies, the backup node). The first never needs the second.

## Lost administrator access

Root on the host is the recovery access, always; it is not an identity of the database and cannot be locked out by it.

    sudo jailops user list                                # who exists, who is disabled
    sudo jailops user set-password admin                  # a lost password; the user's sessions end
    sudo jailops user set-role admin --role admin --global
    sudo jailops user enable admin
    sudo jailops user create admin2 --admin --password-prompt   # a new global administrator

A lost second factor: sign in with a recovery code. Without one, root creates a new administrator as above and deletes
the old user (`jailops user delete NAME`); there is no command that removes another user's second factor.

`service jailopsd setuptoken` (as root) prints a one-time token for the console's first-run setup, and only while **no**
global administrator exists (a user, or a token or certificate that has not expired). Once one exists the setup routes
answer `not_found`: use `jailops user create` as root instead. No root on the host means no recovery from JailOps;
that is the boundary ([security-model.md](security-model.md#the-first-administrator-the-setup-token)).

## A stolen API token, client certificate or session

Take the credential away first; it stops working on its next request, and long requests (event streams, console and exec
sessions) end at their next keepalive.

    jailops token list && jailops token revoke NAME            # an API token
    jailops cert revoke NAME|FINGERPRINT                      # a client certificate (also: jailops cert revoke)
    jailops sessions list && jailops sessions revoke ID        # a console session
    jailops user disable NAME                                  # every session and login of a user, until enable

Then find out what it did. The audit log names the requestor (a user, a token's name or a certificate's fingerprint):

    jailops audit --user NAME --since 72h --limit 1000

Entries older than the newest 1000 can be pruned by retention (`audit.retention`, default 90 days); forward the audit log
off the host ([logging.md](logging.md)) so that it outlives the host. Make the replacement narrower than the one that
leaked: `jailops token create NAME --role ROLE --projects P --expires 720h --allow-from 192.0.2.0/24`.

A stolen client certificate of the **backup node** (`backup-client.key`): on the node, `jailops-backupd hosts revoke NAME`,
then enrol a new certificate ([backup-restore.md](backup-restore.md#2-enrol-the-host)).

## A daemon you suspect is compromised

**What still holds** while `jailopsd` (the user `jailops`) is in someone else's hands: the helper checks every request
against `priv.conf`, so no path outside the storage roots, no program outside the allow-list, no host directory the operator
did not name, no raw `pf.conf` text, no private WireGuard key and no deadline of a pending firewall change
([security-model.md](security-model.md#two-programs-one-boundary)). **What does not:** the attacker can do anything an API
administrator can do within those bounds, and holds everything the daemon holds.

1. Stop it and keep the evidence: `service jailopsd stop`, then copy `/var/db/jailops` and `/var/log/messages` (the
   helper's audit lines, `priv.request`, record every operation the daemon asked for). Running jails keep running.
2. Rotate what the daemon held. All of it is in `data_dir` (default `/var/db/jailops`) or was seen while it ran:

| Secret | Where | What to do |
|---|---|---|
| API tokens, passwords, sessions | the database, hashed | delete and reissue the tokens; `jailops user set-password` for every user; sessions end with it |
| Second factors | sealed with `seal.key` | each user removes the second factor and sets it up again in the console |
| The server certificate's key (self-signed) | `tls/server.{crt,key}` | remove both and restart: a new one is generated; every client pins the new fingerprint, and a hub's hosts trust its new client certificate |
| ACME account and certificate keys | `tls/acme` | remove `tls/acme/account.key` with the daemon stopped and request again (`jailops host certificate acme`); the certificate key is new at every order. JailOps cannot revoke the old certificate at the CA |
| Sealed secrets of jails (`sealed:age:`) | `secrets.key` opens them | treat every sealed value as read: change it where it is used. There is no command to replace `secrets.key` and seal again |
| Passphrases of encrypted volumes | never stored, but typed through the daemon | change those typed while it was compromised: `jailops volume passphrase NAME` |
| WireGuard keys | in the helper's `wireguard-dir`, never in the daemon | not exposed; a join token shown while compromised held a peer's key: remove that peer (`jailops wireguard peer remove SERVER PEER`) and enrol it again. `jailops wireguard rotate-keys NAME` gives a tunnel a new key pair |
| The backup key | `backup.key`, readable by the daemon | assume the backups can be read by whoever reaches the node. Rotation is a new repository; see below |
| The backup node client key | `backup-client.key` | revoke and enrol a new one on the node |
| Log forwarding tokens | `logging.secrets_dir` | the daemon reads them: issue new ones at the receivers |

3. Look for what it changed: `jailops audit --since 168h`, the helper's log lines, `jailops doctor` (drift of the host
   modules), `jailops host snapshots`. Reinstalling the package does not clean a compromised database; the jails' own
   data is outside the daemon's reach only as far as the helper's rules go.

## A lost backup key

The host key is `backup.key` (default under `/var/db/jailops`); the recovery key `JOR1-...` was printed once by
`jailops backup key create`; the escrow is the key wrapped to your age recipients and stored on the node
(`jailops backup key escrow`). `jailops backup key status` tells which of them this host has.

- **The key file is gone, the recovery key or an escrow identity is kept:** the backups are not lost, but **loading a
  recovery key or an escrowed key into a host is not built**: the library has it, no API route or command calls it
  ([backup-restore.md](backup-restore.md#7-restore)). Until it is, the only working path is a copy of `backup.key` (and
  its `backup.passphrase_file`, if the key is wrapped) kept with your own tools. Keep one.
- **The key file, the recovery key and every escrow identity are gone:** the backups cannot be read by anyone, JailOps
  included. Start again: a new key needs a new repository, because `jailops backup key create` refuses to replace a key
  and a node binds itself to one key domain.
- **Rotating the repository key** (after a compromise): not built in place. The way is a new repository (a node set up
  again, or another node) with a new key; the old repository stays readable with the old key until its backups expire or
  are deleted on the node.

## Restoring onto a new host

UNVERIFIED end to end: no restore onto a second machine has been run by the test suite. What the code does:

1. Install the packages and run `jailops-setup` ([install.md](install.md)), which also starts both services.
2. Put back what is not in a JailOps backup, from your own copies: `backup.key` (and its passphrase file),
   `secrets.key` (sealed secrets), the backup client certificate or a new one enrolled with `jailops-backupd hosts enroll`.
3. Point `backup:` of `jailopsd.yaml` at the same node and restart `jailopsd`. With an empty catalog and the key present,
   the daemon rebuilds its catalog from the repository at start.
4. Create the projects, networks and storages again (`jailops-sync` from your repository, if you keep one); a restore is
   admitted like a new jail and needs them granted.
5. Restore each jail; the preflight lists what is missing (an image generation is rebuilt from pkgbase):

       jailops backup list --project shop
       jailops backup restore --project shop BACKUP --as web --dry-run
       jailops backup restore --project shop BACKUP --as web -y

## A firewall change that locks you out

Only with the host firewall module ([appliance.md](appliance.md#commit-confirmed-built-firewall-now-network-later)).
Every change waits for a confirmation, and the **helper**, not the daemon, puts the old `pf.conf` back when the deadline
passes. A change that would shut out the address the request came from is refused before it is made.

- **Locked out, change unconfirmed:** wait for the deadline (default 120 seconds). The helper reverts and reloads pf
  without anything reaching the host. `jailops host pending` shows the outcome afterwards (`last`: `timed_out`).
- **Still connected and it looks wrong:** `jailops host revert` puts it back now; `jailops host confirm` keeps it.
- **The host reboots before the deadline:** the boot script `jailops_revert` puts the old files back before the network
  and pf start (`reverted_at_boot`).
- **The helper is down while a change waits:** its timer went with it. When it crashed, daemon(8) starts it again after
  5 seconds; after a `service jailops_priv stop`, `service jailopsd start` starts it again. Either start reads
  the pending record first and reverts at once when the deadline has passed. If it does not start, as root at the
  console: `jailops-priv revert-pending` (it puts the files back and does not reload) and then `service pf reload`.
- **The revert itself failed** (`last.outcome` is `revert_failed`, with the snapshot in `detail`): from the console as
  root, `jailops host snapshots` and `jailops host restore SNAPSHOT`.
- **A confirmed change locks you out later** (your address changed): nothing reverts it. From the console as root,
  `jailops host restore` (the latest snapshot) or edit `/etc/pf.conf` and `service pf reload`.

## Upgrading, and going back one version

    bectl create pre-jailops-upgrade                 # a boot environment of the root file system
    pkg upgrade jailops jailops-client
    service jailopsd restart
    jailops doctor

Both binaries are new, and each service runs the old one until it restarts. The two are one service, the helper being the
part that runs as root: `jailops_priv` starts first at boot and stops last at shutdown, `service jailopsd start` starts
the helper first when it is not running (the force_depend of rc.subr: "depends on jailops_priv, which will be forced to
start") and `service jailopsd stop` stops it after the daemon, so `service jailopsd restart` replaces both. Jails keep
running either way: they are kernel jails. `service jailopsd restart` alone restarts only the helper; the daemon
reconnects, and the requests it makes meanwhile fail. A `service jailopsd start` while the helper still runs the replaced
binary warns that it needs a restart.

The database (`/var/db/jailops/jailops.db`) has **forward-only** schema migrations (`internal/store/migrations`,
three so far): none has a way back. A daemon older than the database refuses to start with `version_skew` and leaves the
database as it is. Going back is therefore a matter of putting the old database back with the old binaries:

- **With the boot environment** (`bectl activate pre-jailops-upgrade`, then reboot): binaries, configuration and the
  database go back together, as long as `/var/db` is part of the root file system (the installer's default layout;
  check with `zfs list -o name,mountpoint`). The **state dataset** (`<pool>/jailops/state`, mounted at
  `/var/db/jailops/state`) and the jails are datasets of their own and are not rolled back: objects created after the
  upgrade stay. Its documents have no migrations today, so an older daemon reads them.
- **Without one:** stop `jailopsd` before the upgrade and copy `jailops.db` (the daemon checkpoints it when it stops).
  To go back, install the older package file (`pkg add -f FILE`; pkg keeps what it downloaded in `/var/cache/pkg`
  until `pkg clean`), put the copy back, start both services. The daily copies in `/var/db/jailops/backups/` are a last
  resort: what changed since the copy (users, tokens, audit entries) is lost.

UNVERIFIED: neither path, nor an upgrade between two released versions, has been run by the test suite ([upgrade.md](upgrade.md)).

## Recovery objectives (RPO and RTO)

How often snapshots are taken is **not** a recovery objective. A snapshot lives on the same pool as the jail: it protects
against a bad change, not against losing the pool or the host. Write down, per service:

- **RPO**, the data you accept to lose: at worst the interval of its backup policy (`--schedule`) plus the time a run
  takes, and more when runs fail. Measure it as the age of the newest backup of the jail (`metadata.created_at` in
  `jailops backup list --project P -o json`), not as the schedule.
- **RTO**, how long until it serves again: measure it with a drill, not an estimate. `jailops backup verify --project P
  BACKUP --depth full` restores the backup as a hidden jail, boots it without network and checks it from the inside;
  time it (`time jailops backup verify ...`) and compare with the target. A real restore onto a second machine
  (`jailops backup restore --as NAME`) measures the whole path, including what is not in the backup (step 2 above).
  Policies run the drill on a schedule with `--verify-schedule` and `--verify-mode full`.

A target the drill does not meet is a finding: shorten the schedule, keep the key copies where the restoring host gets
them, or change the target.

## Start at boot

A jail starts when the host boots only when it has **autostart**. A jail that was running before a reboot does not come back on its own: the daemon starts what the jails' specifications say, nothing it remembers. The daemon does this once per boot of the host (it keeps the boot time it ran for in `boot-id` in its state directory): a daemon that starts again on a host that stayed up, by `service jailopsd restart` or a package upgrade, starts no jail, so a jail you stopped for maintenance stays stopped.

    jailops create web --image freebsd-15-1 --network lan --storage default --start --autostart
    jailops config set web boot.autostart true        # for a jail that exists
    jailops list -c name,state,autostart              # which jails have it
    jailops boot                                      # in which order they start, and which do not

`jailops boot` shows what the daemon's boot pass would do after a boot of the host, from the jails as they are now: the jails in the order they start, with the reason (`autostart`, or `dependency of NAME`), and the jails with autostart that it does not start, with why. A jail starts after the jails in its `boot.depends`, which start too even without autostart of their own; among the jails that are ready, the lower `boot.priority` starts first, then the name. Almost nobody needs `boot.depends` and `boot.priority`: `jailops config set web boot.depends db` and `boot.priority 10` are there for the case where one jail must be up before another. A cycle, a dependency that does not exist, and a jail with an encrypted volume (it waits for its passphrase after every boot: `jailops volume unlock`) are listed as not started, and so is a jail that depends on one of them. The order is that of the whole host; you see the jails of every project you may use, or one project with `--project`. `jailopsd` starts the jails once, in its first pass after it starts (`reconcile.autostart` of `jailopsd.yaml`).

## Stop at shutdown

When the host shuts down, the jails are stopped, up to eight at a time and each after the jails that depend on it, before the daemon and the helper stop, so that a database
flushes and the poststop hooks run (the interfaces and the pf anchors of the jail are taken down). The rc script
`jailops_shutdown`, which comes with the package and runs whenever `jailopsd_enable` is `YES`, asks the daemon to do it with

    jailops stop-all                  # every running jail of every project, a jail before the jails it depends on
    jailops stop-all --grace 60s      # how long each jail gets to shut down
    jailops stop-all --dry-run        # the order, without stopping anything

The order is the reverse of `jailops boot`: a jail stops before the jails in its `boot.depends`, and among independent
jails the one with the higher `boot.priority` stops first. A jail that cannot be stopped is reported and the rest are stopped
anyway; init stops whatever is left. Restarting the daemon (`service jailopsd restart`) never stops a jail, and nothing
runs at boot.

| `rc.conf` | Default | Meaning |
|---|---|---|
| `jailops_shutdown_enable` | `jailopsd_enable` | `NO` leaves the jails to init at shutdown |
| `jailops_shutdown_timeout` | `80` | seconds for all the jails together; it must stay below `rcshutdown_timeout` (90 by default), so raise both for a host with slow databases |
| `jailops_shutdown_grace` | empty | seconds, or a duration such as `30s`, each jail gets to shut down |

### How long a jail gets

After its stop command (`/etc/rc.shutdown`) a jail has thirty seconds to end by itself; what is still running then is killed. A database that needs longer says so for itself, and a jail that must go down quickly asks for less:

    jailops config set db boot.stop_timeout 60        # seconds, 1 to 3600; 0 is the thirty seconds
    jailops create db ... --stop-timeout 60

The key is written into the jail's configuration at its next start. `jailops stop`, `restart`, `stop-all` and the stop at shutdown all wait as long as the jail asks (`--grace` shortens the wait for one run, and the jail is killed when it passes). Up to eight jails stop at once, each after the jails that depend on it, so `jailops_shutdown_timeout` has to cover the longest chain of jails that depend on each other (and, with more than eight jails, the time the queue takes), and `rcshutdown_timeout` has to stay above it: with a database that gets 60 seconds, raise `jailops_shutdown_timeout` to 120 and `rcshutdown_timeout` to 130.

**A stop is always bounded.** The stop commands of a jail get its stop timeout (`boot.stop_timeout`, 30 seconds unless set) and the jail the same time again to exit after SIGTERM, with five seconds on top (65 seconds by default); after that it is removed without them, which kills what is left, and a `jail-stop-forced` event and the console log of the jail name the processes that still ran. After the jail is gone a stop waits five seconds in all for its datasets to be released; what is still busy stays mounted until the next start or stop and is reported as a `jail-unmount-busy` event. `jailops op show ID` lists the steps of an operation with the time each took, and `jailops doctor --fix` takes the mounts that a stop which did not finish left below the root of a stopped jail off ([troubleshooting.md](troubleshooting.md)).

## Resource limits of a jail

A jail has five limits. They are keys of the jail (`jailops config set JAIL KEY VALUE`, also in a profile or a file) and
each one is enforced by the kernel, not by JailOps polling.

| Key | Enforced with | What happens at the limit |
|---|---|---|
| `limits.memory` | rctl `swapuse`, `deny` | the anonymous memory the jail may reserve in total: a `malloc` or `mmap` beyond it fails, and nothing is killed |
| `limits.pids` | rctl `maxproc`, `deny` | `fork` fails while the jail has that many processes |
| `limits.cpu` | rctl `pcpu`, `deny`, at cores times 100 | the jail is slowed down to that many cores, nothing is killed |
| `limits.disk`, `limits.disk_reservation` | ZFS `quota` and `reservation` of the jail's container dataset | writes fail below the container: the root, the persistent datasets and the snapshots of all of them count; a volume is a dataset of the project, outside the container: it is bounded by its own `--size` and by the project's storage quota, not by the jail's limit |
| `limits.states` | pf `keep state (max N)` on every pass rule of the jail's anchor | a rule creates no new state beyond N; the host's state table cannot be filled by one jail |

Memory is `swapuse` because it is the one resource that counts what a program reserves and refuses the allocation
beyond the limit. `vmemoryuse` counts every mapping, shared libraries and sparse arenas included: an idle PostgreSQL maps
1.8 GB for 0.3 GB of memory, and a limit of 1G on it stops the server from starting. `memoryuse` is the resident set,
summed over the processes, so the pages that processes share are counted for each of them, and the kernel does not
refuse an allocation for it (`deny` is not enforced; the action `sigkill` kills the process that is over). The limit is
therefore the memory the jail's programs reserve, not the size of a single process: a server with many processes, such
as PostgreSQL with twenty busy connections, reserves more than the value it needs when idle, and a limit set to the
catalog's hint of the application (1G for PostgreSQL) leaves room for a small server and no more. Raise
`limits.memory` for a busy one. `limits.disk` is a `quota`, so snapshots count against it; a `refquota` would leave them
out, and the jail could then fill the pool with what its snapshots keep.

`limits.cpu`, `limits.memory` and `limits.pids` need the kernel's resource accounting, which is a boot tunable:

    # /boot/loader.conf
    kern.racct.enable=1

Without it the kernel accepts no rctl rule. A jail with such a limit still starts, `jailops doctor` fails the check
`sysctl.kern.racct.enable`, and the jail shows the condition `Limits` (`NotEnforced`) and a warning. The rules are added
after the jail has started and removed when it stops and when it is deleted (the kernel keeps a rule by the jail's name, so
a rule left behind would apply to the next jail of that name); a start removes any rule of the name before it adds its own. The three keys take
effect at the next start of the jail; `limits.disk` and `limits.disk_reservation` apply at once, and ZFS refuses a quota
below what the jail already uses.

`limits.states` is per rule: a jail with five pass rules may hold five times the number. A jail that sets none gets
`jails.max_states` of `jailopsd.yaml`, 10000 by default, which is far below pf's default table of 100000 states and
above what a busy DNS or web server of one jail keeps open; `0` there sets no limit. A jail that needs more has its own
`limits.states`. Raise the host's table (`set limit states` in `pf.conf`) when the sum of the limits of the jails on it
should fit. pf also shortens the timeouts of a jail's states once a rule holds 60% of its limit (its adaptive defaults), and refuses new states at the limit.

## Events from the kernel

FreeBSD's devd(8) publishes what the kernel notices, and `jailopsd` reads it from devd's socket
(`/var/run/devd.seqpacket.pipe`, readable by everyone on a stock host). The few notifications an administrator acts on
become events in the same stream as the rest (`jailops events`, the console's Events page), so a problem shows
without anyone polling for it:

| Event (`action`) | When | Source | Who sees it |
|---|---|---|---|
| `host-zfs-error` | a pool or a device reports a checksum, I/O, data or device error, a failed probe or a failed pool load | the host | global identities |
| `host-zfs-pool` | a device of a pool changed state or was removed, a scrub finished or was aborted | the host | global identities |
| `host-link-down`, `host-link-up` | the link of the uplink of a network changed | the host | global identities |
| `jail-limit-hit` | a resource limit with the rctl action `devctl` that names a jail of JailOps was reached | the jail | those who may use its project |

The `detail` of an event is one line of text: `pool tank: checksum on /dev/da0`. The ends of a jail's epair change state
with every start and stop and give no events. The same event is shown once in 30 seconds and at most 30 events are
published in a minute, so a failing disk cannot flood the stream. A host without devd, or a socket the daemon cannot
read, never stops the daemon: it tries again slowly, and `jailops doctor` says so with the check `host.devd`.
`devd.enable: false` in `jailopsd.yaml` turns the reading off, `devd.pipe` names another socket.

## When the daemon crashes

A panic in one of the background loops of `jailopsd` (the reconcile loop, the housekeeping, the devd watcher, the host
directory watcher, the backup scheduler, the hub loops) does not end the daemon: the loop is logged with its stack in the
log of `jailopsd`, counted, and started again after a delay that doubles from one second to a minute. `jailops doctor`
warns (`daemon.loops`) while one was restarted in the last day: report the stack as an issue. A panic in a request is
answered with an error and logged, as before.

If the daemon itself exits (the kernel killed it for memory, a panic outside the loops), daemon(8) starts it again after
10 seconds (`-R 10` in `/usr/local/etc/rc.d/jailopsd` and `jailops_backupd`; the helper has `-R 5`). The jails keep
running meanwhile; the API and the console are back with the daemon. `service jailopsd stop` stops the supervisor first,
so a stop is not undone. A daemon that exits at once on every start is started again every 10 seconds, no faster; its
reason is in `/var/log/messages` (tag `jailopsd`).

## What to monitor

Only what the product exposes today. Use a dedicated read-only token for the checks that need one:

    jailops token create monitor --role readonly --global --expires 2160h

A non-administrator sees each doctor check's status but not the text of a failing one (it can hold paths of the host);
read the details as an administrator when an alert fires.

| What | How | Alert when |
|---|---|---|
| The daemon serves | `GET /readyz`, no credentials ([exposure.md](exposure.md#load-balancers-and-monitors)) | not 200 for two probes in a row; the body names the class |
| The daemon runs | `GET /healthz`, no credentials | no answer: restart `jailopsd` |
| The helper is down | `/readyz` answers `not ready: helper`; `service jailops_priv status` (or `service jailopsd status`, which names both); a crashed helper is started again by daemon(8) after 5 seconds | for more than a minute: nothing on the host can change |
| The host checks | `GET /api/v1/doctor` with the token (or `jailops doctor`, exit status 1 on a failed check) | `metadata.status` is `fail`; `warn` for a day |
| Reconcile failures | doctor check `reconcile` (`fail` with the error, `warn` for drift); `status.conditions` of each object | `fail` |
| Pool health | doctor checks `zfs.pool` and `zfs.pool.<storage>`; the events `host-zfs-error` and `host-zfs-pool` ([above](#events-from-the-kernel)) | not `ok`; any `host-zfs-error` |
| Pool capacity | `GET /api/v1/resources`: `size`, `allocated`, `free` of the pool (global identity; no doctor check) | `allocated / size` above 80% |
| The certificate | doctor check `tls.certificate` (warns 14 days before an expiry nothing renews, fails once expired); `tls.acme`; `GET /api/v1/host/certificate`: `current.days_left`, `acme.failures`, `acme.last_error` | `days_left` below 14, or ACME failures |
| The last successful backup | `GET /api/v1/backups?project=P` (readonly in the project): the newest `metadata.created_at` per `spec.jail` with `status.failed` false; `status.verified_at` for the last verification | older than the RPO |
| Failed scheduled backups | the daemon's log only: `backup: job failed` | any line |
| A firewall revert that failed | `GET /api/v1/host/pending`: `last.outcome` is `revert_failed` | at once |
| Who did what | the audit log forwarded to syslog ([logging.md](logging.md)), or `GET /api/v1/audit` (global admin) | `denied` results and `authentication failed` from unknown sources |
| Protocol violations at the helper | the helper's log: `priv.protocol.violation` (a peer sent frames out of order; the helper closed that connection) | any line: the daemon or something else on the socket misbehaves |

**Not exposed yet**, so it cannot be monitored from the API: there is **no metrics endpoint** (counters, latencies,
queue lengths); the history of backup and drill runs (the scheduler keeps it, no route returns it); reconcile pass
durations; the helper's own state beyond whether it answers. JailOps pushes no alerts itself: a monitor polls.
