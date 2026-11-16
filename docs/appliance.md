# Host management (appliance mode)

JailOps manages jails. By default it leaves the host alone: the administrator sets the host name, the network, the
host's own firewall, the time service and the system updates with the tools of FreeBSD, and JailOps never edits
`pf.conf`, `rc.conf`, `resolv.conf` or any other file of the host's own configuration.

Appliance mode is the **optional** exception. An administrator who wants to run a host from the console alone (set its
name, its addresses, its firewall, its updates) can hand JailOps one area of the host at a time. Each area is a
**module**, and each module is off until it is listed by name in two configuration files, or until one line of
`/etc/rc.conf` turns appliance mode on. Nothing changes for a host that does not opt in: the light, command-line use stays
the default.

The short way, for a host that is to be run from the console (the five commands are in [install.md](install.md)):

    sysrc jailopsd_enable=YES jailopsd_web=YES jailops_appliance=YES

The first start then needs no shell: the helper sets the host up, the daemon prints a one-time setup token and the
console's address on the system console, and the console's first-run wizard does the rest.

This page is the design of all modules and the description of the two that are built. What is built and what is not is
in the table below; everything that has not run on a FreeBSD host is marked UNVERIFIED.

## Status

| Part | State |
|---|---|
| Opt-in switches (`host.manage.modules` in `jailopsd.yaml`, `host-manage` in `priv.conf`) | Built, for `identity` and `firewall` |
| One switch in `rc.conf` (`jailops_appliance`, `jailops_appliance_modules`, `jailops_pool`) | Built: the rc scripts pass the modules to both programs, the first start sets the host up (`jailops-priv appliance-init`), doctor check `appliance`. Tested with the rc scripts run against a stand-in of `rc.subr` and their headers sorted like `rcorder`, and on FreeBSD 15.1 by the block `JAILOPS_E2E_APPLIANCE=1` of `scripts/ci-freebsd-e2e.sh` (the switch on a test configuration, `check-config`, doctor `appliance`). UNVERIFIED: a true first boot (root pool detection, `appliance-init` on a fresh install) |
| Setup token of the first administrator | Built: `POST /api/v1/setup`, `jailops-priv setup-token`, printed by the rc script of `jailopsd`. Verified on FreeBSD 15.1: the token on the start of `jailopsd` and in `/var/log/auth.log` (not in `/var/log/messages`), a wrong token refused, the right one creating the first administrator, a second attempt answering 404. UNVERIFIED: `/dev/console` on a real console |
| Module 1, identity: host name, resolvers, NTP | Built: API, helper operations, CLI, doctor checks, console page. Verified on FreeBSD 15.1 by the end-to-end block of `scripts/ci-freebsd-e2e.sh` (off unless `JAILOPS_E2E_HOST=1`): hostname, resolvers and NTP applied, the files and `sysrc` values checked, drift detected after a hand edit, and the restore putting the originals back byte for byte. A restore now puts back the module's three `rc.conf` variables and its block of `ntp.conf` only (no longer the whole files); the block checks that a line root adds to `rc.conf` after the snapshot survives the restore: UNVERIFIED until it runs again. Not verified: a host where DHCP or resolvconf rewrites `resolv.conf` |
| Snapshots before a change, restore | Built for modules 1 and 2 |
| Commit confirmed (automatic revert) | Built in the helper (the pending record, its timer, the re-arm at start, the boot script `jailops_revert`), used by module 2. Verified on FreeBSD 15.1: a change that is not confirmed reverts by itself after the window and a confirmed one stays. UNVERIFIED: the boot ordering has been checked as text only (a test sorts the rc.d headers), a real reboot with a pending change has not been run |
| Boot environment before a risky change | Design only (the firewall module does not create one) |
| Module 2, host firewall | Built: API, helper operations, CLI, doctor check, console section and pending banner. Verified on FreeBSD 15.1 by the end-to-end block of `scripts/ci-freebsd-e2e.sh` (off unless `JAILOPS_E2E_HOSTFW=1`): the rendered file loads with the real `pfctl`, an unconfirmed change reverts by itself, a confirmed one stays, drift is detected, and the restore returns the original `pf.conf` byte for byte. Not verified: a host whose pf was disabled before the first apply, and IPv6 sources from a real client |
| Module 3, network | Design only |
| Module 4, updates | Design only |
| Module 5, system | Design only |
| Module 6, storage overview | Design only |
| First-boot wizard | Built in the console (`/setup`), with the modules that exist: account, identity, certificate, firewall, storage and network defaults, the base image. The network and pool steps of the design wait for module 3 and the installer. Tested in the console's demo mode and its API against in-process daemons; UNVERIFIED in a browser against a FreeBSD host |
| The console's certificate: upload, ACME | Built ([exposure.md](exposure.md)); the ACME redirect is rendered by the firewall module. UNVERIFIED: issuance by a real CA |
| Installer image | Design only |

## Goals and non-goals

Goals:

- A host can be run from the console without a shell, one area at a time, when the administrator chooses so.
- Each module owns an exact, documented set of files and settings, and nothing else.
- Every change can be previewed (a dry run with a diff), is audited, is preceded by a copy of exactly the files it
  touches, and can be undone with one command.
- A change that can cut the administrator off (network, firewall) reverts itself unless it is confirmed, and the revert
  does not depend on the daemon or the console being reachable.
- A hand edit is never silently overwritten: it is reported as drift.
- The root helper stays narrow: a module adds a few typed operations that take validated fields, never a file body or a
  command line from the daemon.

Non-goals:

- A general host configuration tool. Modules cover what a host that runs jails needs; anything else stays with the
  administrator.
- Owning the host by default. Without the switches JailOps behaves exactly as before appliance mode existed.
- Managing other operating systems, or FreeBSD releases before 15.1.
- Replacing the administrator's shell. Everything a module does is plain FreeBSD configuration that can be read and
  changed by hand; the module then reports the change.
- Cluster-wide host management. A module manages the host its daemon runs on; a hub forwards requests like any other.

## The opt-in model

### Two switches, both needed

A module is managed only when **both** files list it:

```yaml
# /usr/local/etc/jailops/jailopsd.yaml
host:
  manage:
    modules: [identity]
```

```
# /usr/local/etc/jailops/priv.conf
host-manage = identity
```

Restart both services after a change (`service jailopsd restart`).

### One switch in rc.conf

Editing both files is what a person does who picks modules one by one. A host meant to be run from the console says so
once, in `/etc/rc.conf`:

```
jailops_appliance="YES"
jailops_appliance_modules="identity firewall"   # optional; default: all modules of this version
jailops_pool="zroot"                            # optional; the pool of the first start (default: the root file system's)
```

The rc script of `jailops_priv` passes the modules to the helper when it starts (`-appliance-modules identity,firewall`,
or `all`): the helper changes the modules of `host-manage` in `priv.conf` **and** these. `service jailops_priv checkconfig` (and
`service jailops_priv checkconfig`) prints both lists. The rc script of `jailopsd` passes the same list to the daemon,
which manages `host.manage.modules` of `jailopsd.yaml` and these. The helper's list is what authorises: a module the daemon
lists and the helper does not still answers `not_managed`. `jailops doctor` has a check `appliance`: ok when both list the
same modules (or none), a warning naming the module and the line to add when one side has a module the other lacks.
`appliance-modules` is not a key of `priv.conf`, and the helper reads it only from its own command line at start; a
change of `rc.conf` needs a restart of both services.

Why this is no weaker than the two files: `rc.conf` belongs to root, as `priv.conf` does, and the daemon never reads or
writes it; the rc script runs as root and hands the list to the helper on its command line. Whoever can write
`/etc/rc.conf` is root already and could edit `priv.conf`, or anything else. The daemon still cannot opt itself in.

**The first start.** With `jailops_appliance="YES"` and no `priv.conf` yet, the rc script of `jailops_priv` runs
`jailops-priv appliance-init` before the helper starts: the one-time setup of `jailops-priv init` (the user and group, the
datasets `POOL/jailops` and `POOL/jailops/state`, the two configuration files) on `jailops_pool`, or on the pool of the root
file system (`zfs list -H -o name /`); a name that starts with `-` is refused, by the rc script and by the helper. It refuses a pool that already holds a dataset with `jailops:managed=on` other than
`POOL/jailops` (another setup's), does nothing once `priv.conf` exists, and logs every command it runs and every file it
writes to syslog (tag `jailops-priv`). The rc script of `jailopsd` then asks the daemon for a setup token (below) after
every start, while no administrator exists.

The default of both is an empty list. Then:

- The daemon refuses every change of that module with the code `not_managed` (HTTP 403). The error's hint names the
  lines to add. `jailops explain not_managed` says the same.
- The helper refuses the module's changing operations with `forbidden`, whatever the daemon asks.
- Reading always works: `GET /api/v1/host/identity`, `jailops host show` and the console page show the host's current
  values read-only, and say that the module is not managed and how to enable it.

Why two switches: `priv.conf` is root's file and the operator's authority over the root helper (see
[security-model.md](security-model.md)). `jailopsd.yaml` is the daemon's file. If the daemon's switch alone were
enough, a compromised daemon could opt itself in by ignoring its own configuration. The helper's switch is the
boundary; the daemon's switch makes the choice visible where people configure the daemon and lets the API answer with
a clear error instead of a refusal from below. The status of the object reports both (`config_enabled`,
`helper_enabled`), and `managed` is true only when both are on.

### What a module owns, and how its files are marked

A module owns an exact list of files, blocks inside files, and `rc.conf` variables, written in this page and in the
helper's code. It never touches anything else. Two ways of marking:

- **A whole file** the module renders starts with the header line `# managed by jailops`, followed by one line of
  explanation. Module 1 owns `/etc/resolv.conf` this way, module 2 `/etc/pf.conf`.
- **A managed block** inside a file the administrator also edits sits between `# jailops begin` and `# jailops end`.
  Everything outside the markers is left byte for byte as it was. Module 1 owns such a block in `/etc/ntp.conf`. A file
  whose markers are broken (a begin without an end, two blocks, an end before the begin) is refused: the helper never
  guesses where a block ends.
- **`rc.conf` variables** are named one by one in an allow-list and set with `sysrc(8)`; other variables are never
  written.

### Drift: a hand edit is reported, never silently overwritten

The helper keeps a record of what a module last applied (for module 1, `<host-dir>/identity.json`). When the host's
current values differ from that record, the module reports **drift**: `jailops doctor` warns (check `host.identity`),
`jailops host show` lists the drifting parts, and the console shows a drift badge. Nothing is changed back on its own.
The administrator either applies again (the file is rewritten, after a snapshot) or keeps the hand edit, in which case
the next apply will show it in the diff.

A module may later offer an explicit `reconcile: true` setting that makes the daemon re-apply on drift, the way it
asserts the forwarding sysctls today. That is opt-in per module and documented with the module; module 1 does not offer it.

## Common mechanics of every module

Each module follows the same pattern, so that what is learned on one applies to all.

- **A declarative singleton object.** Each module is one object of a `Host*` kind under `/api/v1/host/...`
  (`HostIdentity` at `/api/v1/host/identity`). `GET` returns the values read from the host as `spec` and the management
  state as `status` (managed, drift, what was last applied). `PUT` with a spec asks for that state; a part left out of
  the spec is not changed (the firewall is the exception: its spec is one rendered file and is applied whole).
- **Dry run.** Every change accepts `dry_run`. The reply is the same as for a real change: a unified diff of the files
  the module renders, and the list of actions in order (commands that would run, services that would restart). Nothing
  is written. The console shows this as Preview before Apply.
- **Snapshot of exactly what the module owns.** Before a change, the helper keeps what will change in a new snapshot
  directory with a manifest (module, time, reason, each file's path, mode, owner, and whether it existed): a copy of a
  file the module owns whole (`resolv.conf`, `pf.conf`), a copy of `ntp.conf` of which only the jailops block is ever
  used, and, for `rc.conf`, only the values of the module's own variables (set or not set), never a copy of the file.
  The apply's reply names the snapshot. `jailops host restore [SNAPSHOT]` (default: the latest) puts a whole file back
  byte for byte (or removes it when it did not exist before), puts the jailops block of `ntp.conf` back in place of the
  current one, sets or removes (`sysrc -x`) the module's `rc.conf` variables, and re-runs what makes them take effect.
  Every other line of `rc.conf` and `ntp.conf` stays as it is now, and the diff names only the module's variables and
  block. A revert of commit confirmed and the revert at boot do the same. A snapshot of an earlier version, which holds
  a copy of `rc.conf`, gives only the module's variables from that copy. A restore first takes a snapshot of its own
  (reason `restore`), so a restore can be undone too. The last 20 snapshots are kept.
- **A boot environment first, for risky modules (design).** Modules that change what the host boots (updates) or that
  can make it unreachable after a reboot (network, firewall) create a boot environment with
  `bectl create jailops-<module>-<time>` before the change, and name it in the reply. Falling back to it is the last
  resort when everything else fails; the loader menu offers it. Not built: the firewall module relies on commit
  confirmed (an unconfirmed change never survives a reboot) and on its snapshots. UNVERIFIED: `bectl` on the root pool
  layouts `bsdinstall` creates on 15.1.
- **Audit.** Every `PUT` and `POST` under `/api/v1/host` is in the audit log like any other change (dry runs too, with
  `dry_run` in the detail), and the helper's own audit log records each of its operations.
- **Roles.** Changing the host needs the `admin` role and a global identity. `operator` is not enough: these are not
  jail operations, and a host change affects every project.
- **Idempotent.** Applying the same spec twice changes nothing the second time (`changed: false`, no snapshot, no
  restart).
- **The helper renders.** The daemon sends validated, structured fields. The helper validates them again and renders the
  files itself. No module accepts a file body or a command line from the daemon.
- **Atomic writes.** A file is written to a temporary file in the same directory, synced, and renamed over the old one;
  mode and owner are kept.
- **A failed change rolls back.** When a step fails after the snapshot was taken, the helper puts the snapshot back (best
  effort) and the error says whether that worked and which snapshot to restore by hand otherwise.

### Commit confirmed (built; firewall now, network later)

A change to the host's addresses, routes or firewall can cut off the administrator who made it, and with them the
console that would undo it. Such modules use **commit confirmed**: the change is applied, and it reverts itself after a
time unless it is confirmed. The mechanism is generic, in the helper; the firewall module is its first user.

1. The administrator applies with a confirmation window, for example
   `jailops host firewall set ... --confirm-within 120` (seconds, or `90s`, `5m`; default 120 seconds, 10 at least, at
   most 30 minutes; `confirm_within` in the API). The reply says the change is pending, with its id and deadline.
2. The helper takes the snapshot, then writes the **pending change record** `<host-dir>/pending.json` (a random id, the
   module, the snapshot to put back, the time it was made, the deadline, the window) and syncs it (the file and its
   directory) **before** it touches anything of the host. Then it applies the change. When a step of the apply fails,
   the snapshot goes back at once and the record ends as `reverted`.
3. The helper arms a **timer in its own process**. When the deadline passes without a confirmation, the helper puts
   the snapshot back and makes it take effect (`pfctl -f /etc/pf.conf`, and `pfctl -e` or `-d` to put pf's state
   back as the snapshot recorded it; `service netif restart` for the network module), removes the record and keeps how
   it ended in `<host-dir>/pending.last.json` (`timed_out`; `revert_failed` with the snapshot to restore by hand if
   putting it back failed). The helper's audit log has a line for each of these.
4. The administrator confirms with `jailops host confirm [--id ID]`, the Confirm button of the console's banner, or
   `POST /api/v1/host/pending/confirm`. The daemon passes it to the helper's `host.pending.confirm` operation, which
   stops the timer, removes the record and keeps the outcome `confirmed`. A confirmation that arrives through the new
   configuration proves the administrator can still reach the host; that is the point. `jailops host revert`, the
   Revert button or `POST /api/v1/host/pending/revert` put the snapshot back at once (`reverted`), and
   `jailops host pending` or `GET /api/v1/host/pending` show the module, the deadline, the seconds left and how the
   last change ended. An id, when given, must name the pending change.

Why the timer lives in the helper and not in the daemon: the daemon may be the thing that is unreachable, may be
restarted, or may be the compromised party. The helper is root, starts before the daemon and is the only process that
can revert the files anyway. A console that the change locked out cannot prevent the revert, because nothing has to
reach the host for it to happen. The daemon and the console only read the record: the console polls
`GET /api/v1/host/pending` and shows a banner with a countdown and Confirm and Revert on every page, also after a reload.

What survives what:

- **The daemon restarts**: nothing changes; the record and the timer are in the helper.
- **The helper restarts**: at start, before it accepts a request, the helper reads `pending.json`. If the deadline has
  passed it reverts at once; otherwise it re-arms the timer for the time left.
- **The host reboots before the deadline**: the rc.d script `jailops_revert` of the helper package
  (`REQUIRE: FILESYSTEMS zfs`, `BEFORE: netif pf jailops_priv`; it runs whenever `jailops_priv_enable` is set) runs
  `jailops-priv revert-pending`. An unconfirmed record is reverted before the network and pf come up: only the files
  go back (the snapshot), and the `netif` and `pf` scripts that follow load them, so the network starts with the old
  configuration. The record is removed, the outcome is kept as `reverted_at_boot` and logged. A reboot therefore never
  makes an unconfirmed change permanent. Scripts of `/usr/local/etc/rc.d` are ordered together with the base scripts
  after `FILESYSTEMS`, which is what makes `BEFORE: netif` possible. UNVERIFIED: a test checks the order the headers ask
  for against the headers of the 15.1 base scripts; a real reboot with a pending change has not been run.
- **Two pending changes**: refused. One change waits for its confirmation at a time, and while it waits every other
  change of the host (any module's apply, a restore) answers `busy` with the id of the pending change in
  `detail.pending`. A dry run still works.

Corrections to the earlier design: the record is removed rather than "moved aside" (how it ended is kept in
`pending.last.json`, which the API returns as `last`); the operation is `host.pending.confirm`, not `host.confirm`; and
the boot step puts back files only, because pf and the network are not up yet when it runs.

## The modules, in build order

### 1. Identity: host name, resolvers, NTP (built)

Scope: the host name (one label or a fully qualified name; the domain is part of it), the resolvers and search domains,
and the NTP servers and whether `ntpd` runs. Kind `HostIdentity`, extension `host_identity`.

**What it owns, exactly:**

| What | How |
|---|---|
| `/etc/resolv.conf` | the whole file, rendered by the helper: `# managed by jailops`, one comment line, a `search` line when there are search domains, then one `nameserver` line per server |
| `/etc/ntp.conf` | only the block between `# jailops begin` and `# jailops end`: one `server <name> iburst` line per server. Every other line stays, including the default `pool` lines. The block is appended at the end when the file has none, and removed when the server list is empty. A file with broken markers is refused |
| `/etc/rc.conf` variables | `hostname`, `ntpd_enable`, `ntpd_sync_on_start`, nothing else (an allow-list in the helper), set with `/usr/sbin/sysrc -f /etc/rc.conf name=value` |
| the running host name | `/bin/hostname <name>` |
| `ntpd` | `/usr/sbin/service ntpd restart` when NTP is enabled and the block or the switch changed; `/usr/sbin/service ntpd onestop` when it is disabled |

Reading uses `/bin/hostname`, a parse of `/etc/resolv.conf`, `/etc/ntp.conf` and `/etc/rc.conf`, and `/usr/bin/ntpq -pn`
for the time sync state (a line starting with `*` is the selected system peer: synchronised). Only the values the module
manages leave the helper, never the contents of the files.

In Go: `c.HostSystem().Identity().Get(ctx)`, `.Apply(ctx, spec, dryRun)`, `c.HostSystem().Snapshots(ctx)` and
`c.HostSystem().Restore(ctx, name, dryRun)` (`c.Host(name)` was taken: it scopes a hub's client to one of its hosts).

**Validated values** (by the client, the daemon and again by the helper):

- host name: RFC 1123 labels (letters, digits, hyphens, at most 63 characters each, not starting or ending with a
  hyphen), at most 253 characters, not an IP address;
- nameservers: 1 to 3 IPv4 or IPv6 literals, no zone, not the unspecified address, no duplicates;
- search domains: at most 6, valid domain names, at most 256 characters together, no duplicates;
- NTP servers: at most 4 host names or IP literals, no duplicates.

No value can carry a newline, a space, a quote or a `#`, so none can add a line to a file.

**API, CLI, console:**

```
GET  /api/v1/host/identity                       values and management state (readonly role, global identity)
PUT  /api/v1/host/identity                       {"spec": {...}, "dry_run": true}  (admin)
GET  /api/v1/host/snapshots                      the snapshots
POST /api/v1/host/snapshots/{name}/restore       {"dry_run": true}  (admin; name "latest" for the newest)
```

```
jailops host show
jailops host identity set --hostname web1.example.org --nameserver 192.0.2.53 --nameserver 2001:db8::53 \
    --search example.org --ntp-server ntp1.example.org --ntp enable --dry-run
jailops host snapshots
jailops host restore [SNAPSHOT] [--dry-run]
```

The replies are synchronous (no operation): the change takes a few seconds. The console's Host page has the identity
form, shows whether the module is managed (with the exact lines to enable it), shows the dry-run diff before Apply,
lists the snapshots with a Restore button, and shows a drift badge.

**Doctor:** `host.identity` is ok with the message "not managed" when the module is off (the doctor has no
informational level), warns on drift, and is ok when managed without drift. `host.ntp` warns when `ntpd_enable` is not
`YES` or `ntpq` shows no system peer, and is unknown with the reason when `ntpq` cannot be asked.

**Risks and limits:**

- On a host that gets its address by DHCP, `dhclient(8)` and `resolvconf(8)` rewrite `/etc/resolv.conf` on every lease.
  The module then reports drift. Stop that by setting `resolv_conf="/dev/null"` in `/etc/resolvconf.conf`
  (UNVERIFIED on 15.1), or do not manage the resolvers on such a host.
- `/etc/rc.conf.local` and files under `/etc/rc.conf.d` are not read. A `hostname` set there wins at boot over the one
  the module writes; the module does not detect it.
- The running host name and the one in `rc.conf` can differ; the status shows both (`spec.hostname` and
  `status.rc_hostname`) and drift covers both.
- The daemon's generated TLS certificate and anything else that was made with the old name keep it.
- A restore puts back what the module owns and nothing else: `resolv.conf` whole, the jailops block of `ntp.conf`, and
  `hostname`, `ntpd_enable` and `ntpd_sync_on_start` of `rc.conf` (set to the recorded value, or removed when they were
  not set). A change root made after the snapshot to any other line of `rc.conf` or `ntp.conf` stays. `sysrc` writes a
  value it puts back in its own quoting (`name="value"`).
- Verified on FreeBSD 15.1 by the end-to-end block: `sysrc -f` on the host's `rc.conf`, the `ntpq -pn` output, and the restore putting the
  originals back byte for byte (before a restore set only the module's variables; that, and `sysrc -x`, are UNVERIFIED
  until the block runs again). Not verified: a host where DHCP or resolvconf rewrites `resolv.conf`.

### 2. Host firewall (built)

Scope: the host's own packet filter: what may reach the host itself (ssh, the console, the API), not the jails. Kind
`HostFirewall`, extension `host_firewall`; every change goes through commit confirmed (extension `host_pending`).

Without the module JailOps never owns `pf.conf`: the administrator adds the anchor line and JailOps loads only its
anchors (`jailops/...`); that stays exactly so on a host that does not enable `firewall`. With the module enabled in
both files, and only then, **JailOps owns `/etc/pf.conf`** (whole-file, with the header) and the `rc.conf` variables
`pf_enable` (set to `YES`) and `pf_rules` (set to `/etc/pf.conf` only when it names another file).

**What the helper renders.** The daemon sends a validated spec, never a file; the helper validates it again and renders
the whole file itself, in pf's required order:

1. the address sets, as `table <jo_hf_NAME> const { ... }`;
2. options and normalisation: `set skip on lo0` (loopback), `set state-policy if-bound` (the jails' NAT needs it, see
   [install.md](install.md)), `scrub in all fragment reassemble`;
3. the anchor `anchor "jailops/*"`, **first** among the rules: it holds the filter rules of the jails and the NAT and port forwards of their networks (design 5.2);
4. the host policy: `block in all` (`block log in all` with `logging`), `pass out all keep state` (replies to what the
   host sends match its state), always neighbour discovery and router advertisements (`icmp6-type { neighbrsol,
   neighbradv, routersol, routeradv }`), path MTU discovery and ICMP errors (`toobig`, `unreach`, `timex`,
   `paramprob`, and IPv4 `unreach code needfrag`), then ssh on its ports from its sources, the console and API on the
   daemon's TLS port from its sources, the `allow` rows, and echo requests when `icmp` is on. Every pass names
   `to (self)`, the host's own addresses.

Correction to the earlier design, which placed the filter anchor after the host policy: it comes first. The jails'
anchors are final (`quick`) for the jails' own interfaces and do not depend on what follows, while a broad rule of the
host before them would decide for them; `jailops doctor`'s `pf.order` check asks for exactly this order.

**Templates and the spec** (`GET`/`PUT /api/v1/host/firewall`):

- `default`: block inbound to the host; pass ssh (port 22 unless `ssh.ports` says otherwise, at most 4 ports) and the
  console/API port (`listen.https.address`, 39110 by default; filled in by the daemon, no rule when the daemon has no TLS
  listener); the always-on rules above; ping when `icmp` is on.
- `open`: pass everything to the host (for a host behind another firewall). Sources for ssh or the console are refused
  with it, since they would have no effect.
- `custom-rules`: `default` plus `allow`, at most 64 rows of `proto` (`tcp` or `udp`), `ports` (`N` or `N-M`, at most 16),
  `from` (sources) and a `comment` (at most 80 characters, no line break, quote or backslash), rendered as a comment line.

Sources (`ssh.allow_from`, `console.allow_from`, `allow[].from`; empty means anywhere) are addresses, prefixes without
host bits or `@name` of a set in `sets` (at most 16 sets of 1 to 256 members). The design named one list,
`admin_sources`, and project address sets: the built spec has one list per door, and the sets are defined in the spec
itself, because the project address sets belong to projects, change without the host firewall knowing, and would make
the helper render from data it cannot check. `nat` is `none` (another value is `unsupported`; the jails' NAT is in their
networks' anchors). `logging` logs what the final block rule drops (to `pflog0`). The spec is applied whole: a part left
out takes its default, not the value applied before (one rendered file; this differs from the identity module).

**Before anything is written:**

- the rendered text is checked with `pfctl -n -f -` (on standard input; never a file the daemon names);
- the **lock-out guard**: the daemon passes the address the request came from, as its listener saw it. When that address
  could reach neither an ssh port nor the console port under the new rules, the apply is refused (`forbidden`, detail
  `guard: lockout`). When the address is unknown (the unix socket, a request through a hub), the apply needs `confirm_lockout`
  (`--confirm-lockout`), and the confirmation window still applies. A dry run reports both as warnings. The guard runs on every
  apply, not only the first.

Then the snapshot (`/etc/pf.conf`, its absence included, and the values of `pf_enable` and `pf_rules` when one changes;
reason `adopt` for
the first apply, which keeps the administrator's own file, `apply` after), the pending record, the file, `sysrc`,
`pfctl -f /etc/pf.conf`, `pfctl -e` when pf did not run, and a read-back that `pfctl -s rules` calls the anchor
`jailops/*`. On a confirmation the file stays; at the deadline, or with `jailops host revert`, the snapshot goes back:
`pf.conf` byte for byte (or the file is removed when there was none) and the two variables as they were (nothing else
of `rc.conf`), the file is loaded, and pf is turned off again if it was off.
Applying the same spec again changes nothing and arms nothing.

**Drift and the dry run.** `<host-dir>/firewall.json` records the spec and the SHA-256 of the file written. A hand edit
of `/etc/pf.conf` (or `pf_enable` that is not `YES`, or `pf_rules` naming another file) is drift: `jailops doctor` warns
(`host.firewall`), `jailops host firewall show` names it, the console shows a badge, and `jailops host firewall diff`
shows the difference. A dry run (`--dry-run`, Preview in the console) prints the unified diff of the file and the
`rc.conf` variables, the rules in plain words, the actions and the warnings (ssh open to the world, the open template,
a refusal the apply would meet).

**CLI and console.** `jailops host firewall show|set [flags]|apply -f FILE|diff [-f FILE]`, `jailops host pending`,
`jailops host confirm [--id ID]`, `jailops host revert [--id ID]`; `--dry-run` everywhere, `--confirm-within` and
`--confirm-lockout` on the changes. The console's Host page has a Firewall section (the rules, an editor for the template, the
ssh and console sources, the allow rows and the sets with inline validation, Preview with the diff, Apply with the
window explained, a warning chip while ssh is open to the world), and every page shows the pending banner.

**Doctor:** `host.firewall` is ok "not managed" when the module is off, warns when it is enabled on one side only,
while a change waits for its confirmation, and on drift.

**The helper's pfctl forms**, its own allow-list (not part of `run.exec`, which the daemon cannot use for any of them):
`pfctl -n -f -`, `pfctl -f /etc/pf.conf`, `pfctl -e`, `pfctl -d`, `pfctl -s info`, `pfctl -s rules`.

Risks and limits:

- A lock-out: mitigated by the guard and by commit confirmed, which reverts without anything reaching the host. A
  confirmed change that locks out a later session (an address that changes) is not reverted; the console of the host or
  `jailops host restore` from a local shell put a snapshot back.
- An existing hand-written `pf.conf` with rules the template lacks (NAT of the host's own, queues, other anchors): the
  first apply shows them in the diff, and the `adopt` snapshot keeps the file.
- The rules apply to the host only (`to (self)`); traffic to the jails is decided by their anchors and, on the uplink,
  by `block in all`: as on a host that follows the install guide, inbound traffic to jails needs a rule of its own,
  which this module does not render (`allow` rows open the host, not the jails).
- Verified on FreeBSD 15.1 by the end-to-end block: the rendered syntax (`(self)`, `set state-policy`,
  the `scrub` line, the ICMPv6 lists) with the real `pfctl`. UNVERIFIED: a host whose pf was disabled before
  the first apply (`pfctl -e` after the load, `pfctl -d` on the revert) and one where the pf module is not loaded at all
  (the apply fails and is undone; the module does not load `pf.ko`); IPv6 sources from a real client; the boot order of
  `jailops_revert`.

### 3. Network (design)

Scope, deliberately minimal: the host's interfaces and their IPv4 and IPv6 addresses (static or DHCP/SLAAC), the
default routes, and VLAN and LAGG interfaces. Owned: the `rc.conf` variables `ifconfig_<if>`, `ifconfig_<if>_ipv6`,
`ifconfig_<if>_alias<N>`, `defaultrouter`, `ipv6_defaultrouter`, `vlans_<if>`, `cloned_interfaces` entries the
module added (`vlan*`, `lagg*`), and `create_args_<if>`; only for interfaces the request names, never the `jo*`
interfaces JailOps creates for jails. Values are validated as interface names, prefixes and addresses; an `ifconfig_`
value is assembled by the helper from fields (address, prefix length, `up`, `DHCP`, `inet6 accept_rtadv`, `vlan`
tag and parent, `laggproto` and ports), never taken as a string.

Applying runs `service netif restart <if>` and `service routing restart` for the interfaces involved, always with
commit confirmed and a boot environment first. The console warns when the change touches the interface its own
connection uses.

Risks: the biggest of all modules. A lost default route or a wrong address cuts the host off; DHCP leases change the
address after the change; uplinks the jail networks use (`projects.uplink`, NDP proxy uplinks) must not be renamed under
them, so the module refuses to remove or rename an interface a JailOps network uses.

### 4. Updates (design)

Scope: updating the host's base system and its packages, with a way back.

JailOps targets 15.1 and later, where `bsdinstall` installs the base system as packages (pkgbase), `freebsd-update` is
planned for removal in 16, and JailOps itself builds images from pkgbase only. The module therefore updates the base
system with `pkg upgrade` of the base repository (`FreeBSD-*` packages) and the third-party packages with `pkg upgrade`.
A host installed from distribution sets is reported by the doctor and refused by the module (`unsupported`, with the
hint to convert the host to pkgbase); `freebsd-update` is not used.

Every update: check (`pkg upgrade -n`, shown as the dry run), `bectl create` of a boot environment, the upgrade, and a
reboot only when asked (`reboot: manual | auto` like jail updates). After the reboot the daemon checks that it came up
on the new release and that the helper and the daemon run; `jailops host rollback` activates the previous boot
environment (`bectl activate`) and reboots. Owned: nothing in `/etc`; the module acts through `pkg` and `bectl` only.

Risks: `/etc` merges after a base upgrade (pkgbase leaves `.pkgsave` files; the module reports them and does not merge
them by hand), a kernel that does not boot (the boot environment is the answer), and jails whose image generation is
older than the host (reported; images are upgraded separately, design section 4.3). An image is one release: the patch
levels of the host's release reach the jails through the image's nightly auto upgrade (or `jailops image upgrade`), and a
new release of the host is followed by a new image (`freebsd-15-2` after 15.2), on which new jails are created; the
console points this out when the host runs a newer release than its newest FreeBSD image ([upgrade.md](upgrade.md#a-new-release-a-new-image)).

### 5. System (design)

Scope:

- reboot and shutdown (`shutdown -r now`, `shutdown -p now`) with a confirmation and an audit entry;
- a **sysctl allow-list**: a fixed list of tunables (for example `kern.ipc.somaxconn`, `vfs.zfs.arc.max`,
  `net.inet6.icmp6.nd6_onlink_ns_rfc4861`) with a value pattern each, written to a managed block of `/etc/sysctl.conf`
  and set at run time; nothing outside the list;
- **ssh keys and users**: the `authorized_keys` of named users (a managed block per user) and creating or locking local
  users with `pw(8)`, never uid 0, never changing `root`'s shell or password, and never removing the last key of the
  user the request came from.

Risks: a reboot interrupts every jail (the console says how many run); a wrong `authorized_keys` locks out ssh (the
module refuses to leave the requesting administrator with no key, and keeps a snapshot).

### 6. Storage overview (design)

Scope: read-only first. Pools (`zpool list`, `zpool status`: health, errors, last scrub), disks (`camcontrol devlist`,
SMART health where `smartctl` is installed) and a scrub schedule (`periodic.conf` variables
`daily_scrub_zfs_enable`, `daily_scrub_zfs_pools`, `daily_scrub_zfs_default_threshold` in a managed block of
`/etc/periodic.conf`). Creating pools stays with the first-boot wizard and the administrator; destroying pools is not
offered.

Risks: low; the only write is the scrub schedule.

### The shell prompt of the host (not a module)

Jails get bash and a coloured prompt from JailOps ([shell.md](shell.md)); the host does not, and no module writes the
host's shell files. The reasons: the prompt is a matter of the administrator's own shell and cuts nobody off, so it gains
nothing from snapshots and commit confirmed; the host may not have bash at all, and installing a package on the host is
a software decision the helper does not take (its `pkg` rule works on jail roots only); and the start-up files of bash
(`/usr/local/etc/profile`, `/usr/local/etc/bash.bashrc`) are the administrator's. The green prompt is one paste,
described in [shell.md](shell.md#the-host), with the same override story as in a jail (your own `~/.bashrc` wins).

Should it be managed later, it belongs in module 5 (System) as one typed field, the prompt text checked like a jail's
(`api.CheckPrompt`), writing exactly one file (`/usr/local/etc/profile.d/jailops-prompt.sh`) and the marked block at the
top of the two start-up files, with a snapshot of the three before the change and the restore of the module. Design
only.

## The first-boot wizard (built)

With `jailops_appliance`, a fresh host starts without any user. Three parts make the first visit safe and need no shell:

- **The setup token.** After the start of `jailopsd`, the rc script runs `jailops-priv setup-token`, which asks the daemon
  over its socket, as root, for a one-time token (`POST /api/v1/setup/token`): 32 random bytes in base32, valid for 24
  hours, stored only as its SHA-256 in `<state_dir>/setup/token.json`, and replaced by every new one. The token and the
  console's addresses (`https://HOST:39110/`, the host name when it is qualified, then the host's addresses) are written
  to `/dev/console` (and to the terminal of `service jailopsd start`) and logged with the facility `authpriv` (on FreeBSD
  `/var/log/auth.log`, root only). The daemon's own log says only that a token was issued: `/var/log/messages` is readable
  by everyone. The motd is not touched. `service jailopsd setuptoken` as root prints a new one at any time; once an
  administrator exists it answers that the setup is complete (exit 3). It trusts nothing of the daemon's answer: it
  prints only a token of 52 base32 characters (another answer is an error), only addresses of the form
  `https://HOST:PORT/` in printable ASCII, and the hint with control, bidirectional and zero-width characters replaced,
  so a compromised daemon cannot send escape sequences to root's terminal or the system console.
- **The setup route.** `GET /api/v1/setup` (anyone) says that an administrator is missing and whether a token is valid;
  `POST /api/v1/setup` with the token, a name and a password creates the first **global administrator**, uses the token up,
  and answers with the address the request came from. The password follows the rules of every password (12 characters at
  least, 5 distinct, not a common one, not containing the name). Wrong, expired and missing tokens get one answer
  (`unauthorized`) and count toward a lockout per source like failed logins (5 tries, then a growing wait); once any global
  administrator exists (a user, or an API token or client certificate that has not expired) every setup route answers
  `not_found` and a token issued before is removed. The last global administrator cannot be deleted or demoted while
  no other exists; root on the socket recovers in every case.
- **The wizard** in the console (`/setup`), shown instead of the login while the setup route answers. Every step uses
  the existing API, and every step but the first can be skipped:
  1. **Account**: the token, the name, the password twice. Then the console signs in.
  2. **Identity**: host name, resolvers, NTP (module 1; when it is not managed the step says so).
  3. **Certificate**: keep the self-signed one, upload your own, or request one with ACME (with the CA's terms; see
     [exposure.md](exposure.md)): from the internet, ACME; inside a network, your own certificate.
  4. **Host firewall**: the default template, with ssh open only to the address the browser came from (the setup route's
     answer) and the console from anywhere, applied with commit confirmed (120 seconds): the step has the Confirm button,
     and a mistake reverts by itself.
  5. **Storage and network defaults**, only what does not exist yet: the pool as storage `default`, a managed network
     `lan` with an IPv4 /24 (10.77.0.0/24 by default) and NAT through the uplink you name, and a project `main` that may
     use them.
  6. **Base image**: the FreeBSD image of the host's release (`environment.kernel_version` of `GET /api/v1`
     without the patch level; another release of 15.1 or later can be chosen) and architecture, named after the release
     (`freebsd-15-1`; the name follows the release until it is edited), with the checkbox **Upgrade automatically every night**
     (off until ticked; then 03:00, packages too; one line in the step says what it does): `POST /api/v1/images` (with
     `spec.auto_upgrade` when ticked), then
     its first generation with `POST /api/v1/images/freebsd-15-1/generations`, followed in the step as an operation (progress, Cancel while it may be
     cancelled). The build downloads the base system packages and takes minutes; a failed build keeps the definition,
     says what to check (the network, `pkg.freebsd.org` from the host) and is built again with Try again. When a FreeBSD
     image exists the step says so. Skipping it is allowed: apps and jails then need an image, which the Images page
     (Create image) makes later.
  7. **Done**: **Install your first app** (the app catalog) when an image exists, else **Create the base image** (the
     Images page with its Create image dialog).

Corrections to the design below: the token is issued by the rc script of `jailopsd` (the daemon makes it; root asks for
it), not by an installer; the account comes first, because every later step is an API call that needs it; the pool is
chosen in `rc.conf` (`jailops_pool`) before the first start, since the helper's setup runs before the console exists;
there is no network step until module 3 exists; TOTP is enrolled after the first sign-in, as for every user.

The design, for the installer image that does not exist yet:

1. **Setup token.** The installer prints a one-time setup token on the system console (and writes it to a root-only
   file). The wizard asks for it; without it nothing can be done, so a host reachable on the network before setup
   cannot be taken over. The token expires after 24 hours and after first use; `service jailopsd setuptoken` prints a new
   one on the console.
2. **Host name** (module 1).
3. **Network**: confirm or change what DHCP gave, or set a static address (module 3, with commit confirmed).
4. **Pool**: choose the pool and the dataset for JailOps (`jailops-setup -pool`), or create a pool on empty disks
   (a mirror or a single disk; the wizard lists the disks and says what will be erased).
5. **Admin account**: the first global administrator with a password and, optionally, TOTP.
6. **First app**: optionally install one app from the catalog (or skip).

At the end the setup token is gone, the firewall module's default template is loaded (ssh and the console open), and
the console asks the administrator to sign in.

## The installer image (design)

A FreeBSD installation image with a `bsdinstall` script (`installerconfig`) and the JailOps packages on it.

It asks only: the target disk or disks (with a clear warning), the keyboard layout and time zone, and the root password
(or an ssh key). It installs:

- the FreeBSD base system as packages (pkgbase) on ZFS on root, with boot environments;
- `jailops`, `jailops-priv`, `jailopsd` and `jailops-apps`;
- an `rc.conf` with DHCP on the first interface that has a link, `sshd_enable`, `ntpd_enable`, `jailops_priv_enable`,
  `jailopsd_enable` and `jailopsd_web="YES"`;
- `rc.conf` with `jailops_appliance="YES"` (in place of editing `priv.conf` and `jailopsd.yaml`);
- the setup token, printed on the console at first boot with the address to open.

Nothing else: no extra packages, no users besides root. Everything the wizard does can be changed later from the console
or by hand.

## Security

### What the helper may touch

The helper's operations for appliance mode are typed, take structured fields, and work only when `priv.conf` lists the
module (`host-manage`). Changing operations also need the admin assertion. Built (modules 1 and 2, and commit
confirmed):

| Operation | Admin | Needs `host-manage` | What it may touch |
|---|---|---|---|
| `host.identity.read` | no | no | reads `/etc/resolv.conf`, `/etc/ntp.conf`, `/etc/rc.conf`, runs `/bin/hostname` and `/usr/bin/ntpq -pn`; writes nothing |
| `host.identity.apply` | yes | `identity` | writes `/etc/resolv.conf` (whole) and the jailops block of `/etc/ntp.conf`; `sysrc -f /etc/rc.conf` for `hostname`, `ntpd_enable`, `ntpd_sync_on_start` only; `/bin/hostname <name>`; `service ntpd restart` or `onestop`; the snapshot directory and `identity.json` under `host-dir`. With `dry_run` it writes nothing |
| `host.snapshot.list` | no | no | reads the snapshot manifests under `host-dir` |
| `host.snapshot.restore` | yes | the module of the snapshot | what that module's apply touches, from a snapshot under `host-dir`: a file it owns whole, its block of `ntp.conf`, and its own `rc.conf` variables through `sysrc -f /etc/rc.conf NAME=VALUE` or `sysrc -f /etc/rc.conf -x NAME` (a value of letters, digits and `._/:+-` only, else refused); nothing else of `rc.conf` or `ntp.conf`, whatever a manifest says (a manifest of an unknown module or naming another file is refused); then what makes them take effect (ntpd and the host name, or `pfctl -f`/`-e`/`-d`). Refused (`busy`) while a change waits for its confirmation |
| `host.firewall.read` | no | no | reads `/etc/pf.conf` (only whether it exists, carries the header and its digest leave the helper) and `/etc/rc.conf`, runs `pfctl -s info`; writes nothing |
| `host.firewall.apply` | yes | `firewall` | renders `/etc/pf.conf` (whole) from validated fields, with, while the console's certificate comes from ACME, two `match … rdr-to` rules of port 80 (http-01) or 443 (tls-alpn-01) to the loopback addresses and one `pass` rule, from the challenge and a port of 1024 to 65535 only; `pfctl -n -f -` of that text; `sysrc -f /etc/rc.conf` for `pf_enable` (`YES` only) and `pf_rules` (`/etc/pf.conf` only); `pfctl -f /etc/pf.conf`, `pfctl -e`, `pfctl -s rules`; the snapshot directory, `pending.json` and `firewall.json` under `host-dir`. Refused when the caller's address would be shut out, and while another change waits. With `dry_run` it writes nothing |
| `host.pending.read` | no | no | reads `pending.json` and `pending.last.json` |
| `host.pending.confirm` | yes | the module of the pending change | removes `pending.json`, writes `pending.last.json`, stops the timer |
| `host.pending.revert` | yes | no (undoing is always allowed) | puts the snapshot of the pending change back as `host.snapshot.restore` does, then removes the record |

The timer, the re-arm at start and `jailops-priv revert-pending` (the boot script) act without a request; they do only
what `host.pending.revert` does, and log it.

Planned, per module: network: the `rc.conf` variables listed
above for named interfaces; updates: `pkg` and `bectl` with fixed arguments; system: `shutdown` with two fixed forms, a
managed block of `/etc/sysctl.conf` with an allow-list, managed blocks of `authorized_keys`, `pw` with fixed forms;
storage: a managed block of `/etc/periodic.conf`. Each is added as its own operations with refusal tests, like module 1.

### Where snapshots live, and why

The helper keeps snapshots and its records in its **own** directory, `host-dir` in `priv.conf` (default
`/var/db/jailops-priv/host`, owned by root, mode 0700): `snapshots/<name>/` with the copies and a manifest,
`identity.json`, the last applied identity, `firewall.json`, the last applied firewall and the digest of the file, and
`pending.json` and `pending.last.json` of commit confirmed. A snapshot also carries the record that was current when it
was taken (and whether pf ran), so a restore puts the record back with the files. A pending record is read only when it
names a known module and a snapshot name of the helper's own form.

The helper never keeps a copy of `rc.conf`: a snapshot records the values of the module's own variables, so a restore
cannot undo what root changed in the rest of the file (services, interfaces) since.

They are not in the daemon's state directory, although that would be the obvious place. The helper never writes in a
directory the daemon can write (the daemon could swap a path component for a symlink between a check and the write).
More importantly, a restore copies files back into `/etc` as root. If the copies lived where the daemon can write, a
compromised daemon could plant an `rc.conf` of its own in a "snapshot" and ask for a restore: root code execution at
the next boot. In the helper's directory the copies are what the helper itself took from the host, and nothing else.

### Threat model

Assume the daemon is compromised. With appliance mode off, it gains nothing new: the changing operations are refused
by the helper. With a module on, it gains exactly that module's operations, with validated values:

- module 1: it can set a wrong host name, point the resolvers at a server it controls, change the NTP servers and
  stop ntpd. That is a real power (resolvers decide where names resolve, and time matters for certificates), and it is
  why the module is opt-in in `priv.conf`. It cannot write any other line into those files, any other `rc.conf`
  variable, or any file outside the list, not even by restoring an old snapshot (a restore sets only the module's
  variables and block); it cannot run a command of its choosing; it cannot restore content it wrote itself.
- firewall (built): it can open or close the host's firewall within the templates and the validated fields: open
  ssh, the console and up to 64 ports to chosen sources, or close them, and turn pf on. With the ACME redirect it can
  also send port 80 or 443 to a loopback port of its choosing (1024 or more), so a service that listens only on the
  loopback addresses of the host could be reached from outside on that port: on a host with the firewall module, do not
  rely on a loopback-only listener as a boundary. It cannot write a pf rule of its
  own (there is no raw text; every value is an address, a prefix, a port or a set name), cannot load another file, flush
  states or tables or disable pf except to put back the state a snapshot recorded. The lock-out guard takes the caller's
  address from the daemon, so a compromised daemon can defeat it; it is a guard against mistakes.
- network (planned): it can change addresses, within the validated fields. Commit confirmed does not protect against a
  compromised daemon (it can confirm, or revert); it protects the administrator against mistakes. It cannot extend a
  deadline: the deadline is written by the helper.

An API admin with a module enabled can change what that module owns; that is the purpose. As with the other `priv.conf`
allow-lists, enable only the modules you would let your API admins change.

### Why commit confirmed lives in the helper

The revert must happen when the daemon is down, unreachable, or cut off by the very change it applied, and after a
reboot. The helper is root, independent of the daemon, already holds the snapshot, and is started early by rc.d; the
daemon is none of these. Keeping the timer and the pending record in the helper's directory also means the daemon
cannot extend or fake a deadline: it can only confirm or let the change revert.
