# Security model

Read this before you give anyone an `admin` role or edit `priv.conf`. The full reasoning and the audit that produced it
are in [design.md](design.md) section 18.6; this page is what an operator needs.

## Two programs, one boundary

| | `jailopsd` | `jailops-priv` |
|---|---|---|
| Runs as | the unprivileged user `jailops` | root |
| Does | the API, authentication, the database, the reconcile loop, the web consoles | the privileged operations: `zfs`, `jail`, `pfctl`, `ifconfig`, `route`, `wg`, mounts, packet capture for the IPv6 proxy, file access inside jails, the keys of WireGuard tunnels |
| Trusts | its clients, as far as their role and project scope allow | **the daemon not at all** |
| Configured by | `jailopsd.yaml` | `priv.conf`, owned by root |

The helper offers a fixed list of typed operations over a unix socket. It has no shell and no free-form command. A
compromised daemon can ask for anything on that list, and the helper checks every request again against `priv.conf`:
the storage roots the paths must lie below, the allow-lists, and the limits. The helper accepts connections only from root and from the
users and groups named in `priv.conf` (checked with `LOCAL_PEERCRED`). The helper is a service boundary between two
processes of JailOps, not a place where people sign in, so it keeps Unix peer credentials. The helper's socket is
`/var/run/jailops-priv/priv.sock`, in a directory of root (mode 0710, group `jailops`): the daemon can reach it and
can put nothing in its place, so it cannot keep the helper from starting. The daemon's own socket is in
`/var/run/jailops` (mode 1771, group `jailops`). The pid files that daemon(8) writes as root are in `/var/run` itself,
where the daemon cannot leave a symlink for root to write through.

**What a compromised daemon cannot do:** name a path outside the storage roots, run a program that is not on the
allow-list, change, destroy, rename or take over a network interface JailOps did not create (see
[Interfaces](#interfaces)), sniff or inject on an interface the operator did not approve, mount a directory the operator did not name,
make the helper answer neighbor discovery for an address outside the bounds the helper checks itself (a global or unique-local prefix of /48 to /120 on a plain uplink, with no address of the host in it, overlapping no other network), make the helper trust a package repository,
key or keyring of its own choosing ([Whom the helper trusts](#whom-the-helper-trusts-when-it-runs-package-tools)), or turn
a ZFS user property into authority (the helper keeps what it granted in its own memory, never in something the daemon can write).

**What it can do, and you should assume it can:** act as any API user for anything inside those bounds. That includes
storing a network in proxy mode: the helper takes the prefix from the stored networks, which the daemon writes, so a compromised
daemon can make the host answer neighbor discovery for any prefix that passes the checks above on the uplink (a segment shared
with other hosts). The operator approves such a prefix by creating the network, not by a line in `priv.conf`. The helper takes
the "this request is for an admin" assertion from the request itself, because only the daemon knows who authenticated.
So **the allow-lists in `priv.conf`, not the assertion, are the boundary.** Separating that further would need a second
credential the daemon cannot hold, such as an administrator confirming at a terminal, which is not how the API works.

There is no Capsicum confinement of the helper or of its file agents yet. The file agents are chrooted child processes with
a lifetime limit and a global cap (16 at once; one more answers `busy`).

**Storage roots keep the jails' files out of reach.** A jail's tree holds setuid programs (`su`, `sudo`) and its users'
files; root in the jail may make more. On the host they are safe only because nobody but root can reach them, so the
helper keeps four rules, each with a test (`internal/priv/invariants_test.go`):

- The directory of every storage root belongs to root with mode 0700. The helper sets it at every start, reload and
  registration (a root registered before, made with mode 0755, is closed at the first start of this release) and
  refuses a mountpoint that is not a plain directory.
- No dataset is mounted on a storage root's own directory (create, set, clone, receive: `mountpoint` must lie below
  it), and the root itself is never unmounted, remounted or moved, nor its `canmount` changed, through the helper.
  Either would put a directory with another mode at that place.
- A root's mountpoint is not on, above or inside a system directory (`/etc`, `/boot`, `/root`, `/usr/local/etc`,
  `/var/db`, `/var/run` and the like) or a directory of the helper (`conf-dir`, `host-dir`, `wireguard-dir`, the
  storage file's directory); it may be elsewhere in `/usr` or `/var` (`/usr/jails`).
- `devices` is off on every root, so on every dataset below it; a request cannot turn it on, and a received stream
  cannot set it, nor `setuid`, `exec`, `mountpoint`, `sharenfs`, `sharesmb`, `jailed` or `keylocation` (they are
  inherited). FreeBSD makes device nodes in devfs only; this is a second guard.

A restore writes a jail through a file agent, which runs as root chrooted to the dataset being restored. Into a jail's
root it restores setuid and setgid files and device nodes as the backup recorded them,
because the jail needs them; that is safe only because of the 0700 directory above. Into anything else (the jail's
container) it makes no device node and drops setuid and setgid, and says so in the restore's skipped list.

**Host directories.** The helper's `fs.source_probe` looks at a directory below an `admin-host-mount` directory for a volume
that is one: it opens it from that directory one plain directory at a time (a symbolic link anywhere is refused), says whether
a mount point lies on the way (a change of device) and, when asked, makes and removes one file in it. It changes nothing
else. The mount a running jail gets again when its directory is back is `mount -t nullfs`, accepted for an administrator
from below an approved directory only, through no link, onto a jail's own tree.

**Files inside jails.** Root in a jail controls its tree, symlinks included. A file operation of the helper on a path
below a jail's root (or its `root.new`, `root.old`, a volume of the project, or an image generation) opens that tree as
its root and walks to it one plain directory at a time: a relative symlink is followed only while it stays inside the
tree, as the jail itself would see it, and an absolute symlink is refused (the helper does not resolve it as the jail
would). So no symlink a jail makes turns an operator's `app allow`, an app draft or any other file operation into a read
or a write of another jail's files, and the path arguments of allow-listed commands below a jail's tree must resolve
inside it as well.

**The root of a jail, its mounts and its links.** The `path` of a jail's `jail.conf` is exactly
`<storage mount>/projects/<project>/jails/<name>/root` of that jail and reaches it without a symbolic link, checked when the
file is written and again at every start: `jail(8)` follows a link in `path`, and a jail whose root is a link to `/` would
have the host's files. Nothing is mounted below a volume or on a mount point that another line uses, because a link
in the volume would carry the second mount over a directory of the host. After a `mount` the helper compares the host's
mounts with those before, and a mount that appeared anywhere but at its path is unmounted at once; `umount` takes only a path
that is a mount point now, and `chmod` is refused in the tree of a running jail. The helper reads a file of a jail's tree
without ever waiting on it (a FIFO a jail planted is refused), and a look at a host directory whose mount does not answer
gives up after ten seconds and holds one of four slots, never the whole budget of requests.

**Addresses, routes and forwards.** The helper puts an address on a jail's link, or a route through it, only inside the
subnet of a network JailOps has stored (the gateway's `fe80::1` aside); the route of the IPv6 proxy only for an address
inside the prefix of a network in proxy mode, never the prefix's anycast address, the host's IPv6 default router or an
address in the uplink's neighbor cache. A port forward leads to an address of a stored network and takes over a
privileged port, or one a host process listens on, only when the request carries the admin assertion.

**The log.** An exec session is recorded with its program and the number of its arguments, not the arguments; a command
line can carry a secret. An archive is copied into the helper's own directory, listed there and extracted from there.

## What you decide, in `priv.conf`

| Line | What it lets an admin do | Default |
|---|---|---|
| `storage-root` | where jails, images and their files may live | the root `init` made |
| `admin-host-mount` | mount host directories below this path into a jail (nullfs), and make volumes of them (`volume create --path`): the mount point has to lie below the path | nothing |
| `admin-raw-param`, `admin-allow-flag`, `admin-devfs-ruleset`, `admin-zfs-prop` | set these raw `jail.conf` parameters, `allow.*` flags, devfs rulesets or ZFS properties | nothing |
| `admin-routes`, `admin-raw-pf`, `admin-resume-send` | change routes (WireGuard routes of any kind included), load raw PF, resume a ZFS send | off |
| `wireguard-routes` | WireGuard tunnels may route these networks into themselves although a route there is wider than a /8 (/16 for IPv6) or covers the host's addresses, default gateway, resolvers, loopback, link-local or multicast ([wireguard.md](wireguard.md)) | nothing |
| `fetch-host` | download from these hosts, over https: files, package repositories of image builds and `debootstrap` mirrors (`http://<host>` also allows plain http for a package repository there) | the Alpine CDN, `pkg.freebsd.org`, `pkg.jailops.net`, `deb.debian.org`, `archive.ubuntu.com`, `ports.ubuntu.com` |
| `pkg-keys-dir` | the key directories a package repository of an image build may use besides `/usr/share/keys` (root, not writable by others, no links; outside the daemon's directories) | `/usr/local/etc/jailops/keys` |
| `keyring-dir` | the keyrings `debootstrap` may check a release with (the same rules) | `/usr/local/share/keyrings` |
| `wireguard-dir` | where the helper keeps the keys of WireGuard tunnels (root, 0700; outside the daemon's directories) | `/var/db/jailops-priv/wireguard` |

**An admin who may set these is root on the host.** Keep the lists short, and write nothing you would not give root.

## Host management (appliance mode)

By default JailOps never changes the host's own configuration. Appliance mode lets it manage parts of the host (so
far the host name, resolvers and NTP, and the host's own `/etc/pf.conf`) one module at a time, and only when **both** `jailopsd.yaml`
(`host.manage.modules`) and `priv.conf` (`host-manage`) list the module: the `priv.conf` line is the boundary, so a
compromised daemon cannot opt itself in. A module's helper operations take validated fields, never a file body, touch
an exact list of files and `rc.conf` variables, and need the admin assertion; snapshots are kept in a root-only
directory (`host-dir`) so a restore can only put back what the helper itself copied. A snapshot keeps only what the
module owns (a copy of a file it owns whole, its block of `ntp.conf`, the values of its `rc.conf` variables), and a
restore, a revert and the revert at boot put back only that: whatever root changed elsewhere in `rc.conf` or
`ntp.conf` since stays, and the diff shows no other line of those files. Enable a module only if you would
let your API admins change what it owns. The details, and the threat model, are in the security section of
[appliance.md](appliance.md#security).

**One switch in `rc.conf`.** `jailops_appliance="YES"` in `/etc/rc.conf` (with `jailops_appliance_modules`, default all
modules) turns the same modules on in both programs without editing the two files: the rc script of `jailops_priv`
passes them to the helper when it starts (`-appliance-modules`; the helper manages `host-manage` of `priv.conf` and these
together), and the rc script of `jailopsd` passes them to the daemon. This is no weaker than the two files: `rc.conf`
belongs to root like `priv.conf`, the helper reads the list once at its start from its own command line and never from
the daemon, and whoever can write `rc.conf` is root and could edit `priv.conf` as well. The daemon still cannot switch
itself on: what it lists and the helper does not answers `not_managed`, and `jailops doctor` (check `appliance`) warns
when the two lists differ. A first start in appliance mode also runs `jailops-priv appliance-init` (the setup `init`
does) when `priv.conf` does not exist yet, on `jailops_pool` or the pool of the root file system, and never on a pool
that holds another JailOps dataset; every command it runs goes to syslog.

## The first administrator: the setup token

A host without an administrator accepts one request that creates the first one, `POST /api/v1/setup`, with a one-time
setup token. Only root issues the token (`POST /api/v1/setup/token` over the socket, which `service jailopsd setuptoken`
and, in appliance mode, the rc script of `jailopsd` call); it is 32 random bytes (base32), valid for 24 hours, replaced
by the next one, stored only as its SHA-256 (`<state_dir>/setup/token.json`, 0600) and used up by the administrator it
creates. The rc script shows it on the system console and logs it with the facility `authpriv` (on FreeBSD
`/var/log/auth.log`, readable by root only), never in the daemon's own log (`/var/log/messages` is readable by
everyone). Wrong, expired and missing tokens get the same answer and count toward a lockout per source, like failed
logins. A host reachable from the network before its setup therefore cannot be taken over without what is printed on its
console. Once any global administrator exists (a user, or an API token or client certificate that has not expired),
every setup route answers `not_found`, a new token cannot be issued, and a token issued before is removed. The last
global administrator cannot be deleted or demoted (`conflict`) while no other one exists, because the setup would open
again and the next start of `jailopsd` would print a token on the console: make the next administrator first. Root on
the socket stays the recovery access in every case (`sudo jailops user create NAME --admin`, `set-password`,
`set-role`); it is not an identity of the database and does not count as one.

## Log forwarding

`jailopsd` can send the jails' logs and its audit log to syslog servers and webhooks ([logging.md](logging.md)). It reads
the files through the helper's two read-only log operations and needs nothing new from the helper. TLS receivers are
always verified (there is no switch to turn that off); a plain udp or tcp sink to a remote address is reported as a
warning. Only a global admin may read or change the sink list, which names receivers and files of the host; reading
many jails' logs at once needs the operator role, as one jail's does. Log lines are data: escaped, cut at 8 KiB, never
interpreted.

A sink list set through the API (a global admin's token, not root) is held to two limits, because the daemon would
otherwise act for the token with more reach than the token has:

- **Files**: its `ca_file` and `token_file` must be plain files directly in `logging.secrets_dir` (default
  `/usr/local/etc/jailops/sinks`, root-owned, 0750 `root:jailops`). Without this, a token could name any root-owned
  file the daemon's group may read and have its first line sent as a bearer token to a receiver of its choosing. Every
  CA and token file, of the API or of `jailopsd.yaml`, is opened from `/` one directory at a time without following a
  symbolic link, and its owner (root) and mode are checked on the open file; the token is read again at each delivery
  the same way.
- **Receivers**: not the loopback, link-local (`169.254.0.0/16`, `fe80::/10`, where cloud metadata services answer),
  unspecified, multicast or broadcast addresses, and not the daemon's own ports on an address of the host. The check
  runs on the address a name resolved to, when the socket connects, so a name that resolves differently later
  (rebinding) does not get past it; an address or `localhost` is refused when the list is stored. Private addresses of
  other machines stay allowed: that is where log servers live.

The forward test answers delivered or not, the time, and a short class of the failure (`connection refused`,
`timeout`, `HTTP 503`, ...), never what the receiver answered. Sinks in `jailopsd.yaml` are root's word and may name
any file and any address, the loopback included. The ACME directory URL of the console's certificate may name any
address; only a global admin sets it, and its last error is a short, escaped snippet.
The firewall module is the one exception to "JailOps never edits `pf.conf`": with `firewall` in both files the helper
writes the whole file, rendered by itself from validated fields (no rule text from the daemon), checked with `pfctl -n`
and loaded with `pfctl -f` through six fixed `pfctl` forms of its own, none of which `run.exec` accepts. Every change
waits for a confirmation and is reverted by the helper's own timer (and, after a reboot, by the boot script
`jailops_revert` before `netif` and `pf`) unless it is confirmed; the deadline is the helper's, the daemon can confirm or
revert but not move it. A change that would shut out the address the request came from is refused. Both are guards
against mistakes: a compromised daemon with the module enabled can open or close the host's firewall within the
validated fields, which is the power the `priv.conf` line grants.

## What listens, and how to expose it

By default only the unix socket listens. `listen.https.address` opens a TLS 1.3 listener, with a generated self-signed
certificate that clients pin, one you provide (`listen.https.cert`/`key`, reloaded without a restart, never generated over),
one an administrator uploads, or one the daemon obtains with ACME. The only plain-http TCP listener is the ACME challenge
listener (`listen.https.acme.challenge_address`, default `:39080`, open only while ACME with http-01 is the source): it
answers `/.well-known/acme-challenge/<token>` for the tokens of a running order and 404 for everything else. Clients are
pinned client certificates, API tokens, or console logins; the listener requests a client certificate and does not require
one. The web console is always built in and off by default (`web.enabled: true` or `jailopsd_web="YES"` turns it on;
`-tags noweb` builds `jailopsd` without it). Three recipes (local only, behind a proxy, direct with mTLS), ACME and its
limits, what changes behind a proxy, and the **Not yet** list (DNS-01 and wildcard certificates, a require-client-certificate
mode, the caller's address behind a proxy) are in [exposure.md](exposure.md).

Answers carry a `Permissions-Policy` that turns off camera, microphone, location and the other device features, and
`Strict-Transport-Security` (one year, no `includeSubDomains`, no `preload`) only while the served certificate is one a
browser trusts by itself (ACME, or an uploaded or configured certificate that verifies against the host's roots); never
with the self-signed certificate, which a browser that remembered the header would refuse without a way to click
through. Going back to the self-signed certificate after a trusted one leaves browsers that saw the header refusing it
for up to a year: keep a trusted certificate on that name, or use another name. The backup node never sends it.

The ACME account key and the certificate's key live in `<data_dir>/tls/acme` (0700, files 0600), the daemon's own
directory: they are the daemon's secrets like its seal key, and a compromised daemon holds them anyway. The redirect of
the CA's port (80 or 443) to the daemon's unprivileged port is pf's: rendered by the helper when the firewall module
manages `/etc/pf.conf` (two `match … rdr-to` rules to the loopback addresses and one `pass`, from two validated numbers), otherwise
two lines the administrator adds. Changing the certificate (upload, ACME, self-signed again) needs a global admin and
is audited.

## Devices

A FreeBSD jail that is given no device mounts `/dev` with the stock jail ruleset (4): the basic and login nodes and nothing
else. A jail that is given devices (`devfs.NAME.device`), and every Linux jail, mounts it with a private ruleset. The
ruleset is made of the stock sets that hide everything and unhide the basic and login nodes, then the paths of the
allow-listed devices (`bpf`, `dri`, `fuse`, `pf`, `tap`, `tun`) or, for a Linux jail, the nodes of a Linux userland.
Nothing else can be named: the device list is an allow-list, and the helper's `devfs` grammar refuses a bare `unhide`, a
path outside the list and a ruleset number below 100.

The kernel treats a ruleset number nobody loaded as an empty ruleset, and an empty ruleset hides nothing, so a jail
started on it would see every device of the host, raw disks included. The helper therefore loads the ruleset in the
prestart hook, before the jail is created, and **a jail whose ruleset is not in the kernel does not start**: the hook
fails, with the stock ruleset missing or a rule refused as the reason. A jail's `/dev` holds no disk node.

## Roles and scopes of API users

Every identity (a user of the web console, an API token, a client certificate) has a **role** and a **scope**.

- Roles: `readonly`, `operator` (jail lifecycle, snapshots, exec, backups of its jails) and `admin` (configuration). There
  are also narrow roles for restores and for backup transport.
- Scope: a non-empty list of projects, or `global`. **An empty list never means everything.** An identity with neither can
  call nothing except its own session routes. Only a global admin may grant `global`.
- A request for an object of a project the caller may not use answers `not_found`, never `forbidden`, so that existence
  does not leak. A role that is too low is checked first and answers `forbidden`.
- Dangerous parameters (raw jail parameters, host directories, device nodes, ZFS delegation, raw PF, provisioning commands)
  need `admin` or a global admin, are allow-listed by `priv.conf`, and are audited.
- Every route has a permission entry in the code, or the daemon refuses to start.
- A value a client sends that goes into the detail of an audit entry (a source, a sink name, a domain) is quoted with
  escapes and cut at 200 bytes, also when the request is refused: a line break or a `key=value` cannot forge an entry.
  See [The audit log](#the-audit-log) for what every entry gets.
- Jail logs (`GET /api/v1/jails/<n>/logs`, `jailops jail logs`) need `operator`, not `readonly`: what a service prints
  often holds tokens, passwords in error messages or other people's data, and an operator may already read all of it by
  running a shell in the jail. The read goes through two helper operations that accept only the log directory of a jail
  root (`/var/log` and one directory below, plain names, regular files, no symlink followed below the jail root; a
  listing reads at most 4097 entries of a directory and 64 subdirectories and says when it was cut), so the daemon cannot
  turn it into a read of anything else, and it is audited (one entry per identity, jail and file every five minutes,
  since a client following a file asks every second). A compressed rotated copy is listed, and the daemon refuses to
  read it; the helper itself does not tell compressed files apart and would return its bytes like any other log file.

### One identity system, over every transport

There is one set of identities (JailOps users with a password and sessions, API tokens, client certificates), one
permission table, one scope rule and one audit trail, whether the request arrives over TLS or over the local unix socket.
**Unix users and groups are not mapped to roles.** The kernel-reported peer uid of the socket decides exactly one thing:

- **uid 0 (root) is a global admin.** This is the host's break-glass and recovery access, not an ordinary user: whoever is
  root on the host can read every secret the daemon holds anyway. Root's requests are audited under its user name, with
  kind `unix`. `sudo jailops user create admin --admin` creates the first administrator; `sudo jailops user set-password`
  and `set-role` recover a lost password or a wrong role. There is no separate reset mechanism.
- **Every other local user is anonymous**, exactly like an unauthenticated remote client. It reaches `GET /api/v1`,
  `GET /healthz`, `GET /readyz`, the login (`POST /api/v1/auth/login`), trust-token redemption (`POST /api/v1/trust/clients`),
  `POST /api/v1/cluster/join` (answers 501), the first-run setup (`GET` and `POST /api/v1/setup`, which need the setup
  token and answer `not_found` once an administrator exists) and the static web console, and nothing else. It can authenticate over the socket
  with an API token, or with a session cookie from a password login, like any remote client. A test runs every route as an
  anonymous remote client and as an anonymous local one and requires the same answer.

The socket stays mode `0666`. Being able to connect confers nothing, because a non-root peer has precisely the rights of an
anonymous remote client, who can connect to the HTTPS listener (when it is on) just as freely. A tighter mode would only
keep people from signing in locally with a token or a password; it would add no protection. The same rate limits and audit
apply to what an anonymous local caller tries: each local user is its own source, `unix:<uid>`, so one of them cannot lock
the others out.

The backup node (`jailops-backupd`) is stricter: its admin socket is mode `0600` and the peer check admits only root (uid 0) as
administrator; every other local user is refused. The former `admin_group` key is removed and stops the node with a message.

## The audit log

Every state change, every refused one and every failed authentication is an entry. What a caller can put into it is
bounded, so that nobody can fill the disk or forge an entry by being refused:

- Every entry passes through one function when it is written: control characters (line breaks and escape sequences
  included), bidirectional controls, zero-width characters and bytes that are not UTF-8 become Go escapes (`\x1b`, `\n`,
  `\u202e`), and the object is cut at 256 bytes, the detail at 4096 (256 for an anonymous caller).
- Nothing of the body of a public route is written: a failed login records the route, the source and the result, not
  the user name that was typed. The path of a refused request is escaped and cut like any object.
- While a source is locked out, its first refusal is written as usual and the others are counted: one more entry when
  the minute ends says how many were refused.
- The log keeps its entries for `audit.retention` (default `90d`) and at most `audit.max_entries` (default 1000000);
  once a day the daemon deletes what is older or beyond. The newest 1000 entries are never deleted, and the database
  refuses to (a trigger), so even a mistaken configuration leaves the recent history. A compromised daemon owns the
  database file and could do more; the log protects against callers of the API, not against the daemon. Forward the
  audit log to a syslog server ([logging.md](logging.md)) to keep it beyond the host.

## Signing in, and what an unauthenticated caller costs

- A password is checked with argon2id, which takes 64 MiB of memory for each check. At most four checks run at once
  for the whole daemon; more wait their turn, and when 32 already wait a login is answered `rate_limited` (429) at once.
- Every login attempt is counted before its password is checked, per user and source and per source: attempts sent at
  once cannot pass the threshold together, and a source that is locked out costs no password check at all. An unknown
  user, a wrong password and a disabled user cost one check each, so the time does not tell them apart. Five failures
  for one user from one source lock that user at that source (30 seconds at first, twice as long after each further
  failure, up to 15 minutes). The source alone has a limit ten times looser: fifty failures from one address, over any
  users, lock the address in the same way. So a spray over many users from one address is stopped after fifty
  attempts, and people behind one address (a NAT, a proxy) are not locked out by a stranger's few wrong passwords.
- The checks of a secret by a user who is signed in (the current password before a change, a second-factor code) are
  counted the same way, before the secret is checked, and wait for a password check slot like a login.
- A source is an IPv4 address, an IPv6 **/64** (one host usually holds the whole prefix) or a local user (`unix:<uid>`).
- Guesses for one account from many sources are slowed down, not locked out (that would let anyone lock a real user
  out): after 10 failures for the account, each further attempt waits 1 s, then 2 s, 4 s and so on up to 30 s before its
  password is checked, and only one such attempt runs at a time; a right password or a quiet half hour forgets them.
- A bad token, an untrusted certificate or a forged hub claim counts toward the lockout of its source, and a wrong token
  from a locked source is answered with the lock. A **valid** token (256 bits, not guessable) or a hub claim that
  verifies is never refused because of what others at its address tried.
- Starting a second factor and making new recovery codes ask for the password again, as removing the second factor does.
  A recovery code has 128 random bits and a salt of its own, is shown once, is compared in constant time and works
  once; a copy of the database does not give the second factor away.
- An anonymous `GET /api/v1` learns the API version, the extensions and the role, not the host name, host id, pool or
  software version. A non-admin caller of `doctor` gets the status of each check without the text of a failing one,
  which can be a raw error with paths of the host.
- Request bodies are strict: an unknown member (a misspelled `dry_run` above all), a member in other cases, a member
  twice or data after the value are refused instead of being dropped.

## Sessions and long requests

- A user sees and ends their own sessions; other users' sessions are for a global admin only (a global reader does
  not see them).
- An event stream, a console's output and an exec session check their credential again at every keepalive (and an
  event stream before each event after any credential changed): a token or certificate deleted, a user disabled, a
  session ended or a role or scope changed ends them. An identity holds at most 16 event streams.
- A console session belongs to the identity that opened it, by the kind of its credential and its name, and to its
  project; its id is in no log line and no audit entry (they show a short hash).
- API answers are `Cache-Control: no-store`. A token in the query string authenticates nothing.

## What the clients show

- `jailops` cleans every string a server sends before a terminal sees it (names, labels, messages and hints, the audit
  log, doctor, events, certificate subjects): control characters, bidirectional controls and zero-width characters
  become U+FFFD. `-o json` and `-o yaml` print what the server sent, escaped by their encoders (JSON keeps a
  bidirectional control as the character itself). `remote add` prints the fingerprint first and quotes the
  certificate's subject and issuer, so they cannot paint over it.
- The server refuses control characters in labels, descriptions and comments in the first place (label keys of letters,
  digits, `-`, `_` and `.` up to 63 characters with an optional prefix and `/`, values up to 253 bytes of printable
  text, 64 labels an object; descriptions and comments up to 4096 bytes).
- `jailops exec` and `shell` put the terminal back on SIGINT, SIGTERM and SIGHUP; after a SIGKILL nothing can, and
  `reset` repairs the terminal.
- The web console embedded in `jailopsd` has no demo mode: `?demo` changes nothing (only a demo build, made for the tests
  and the screenshots, carries canned data). A token used to sign in is forgotten when the server answers 401.

## How clients are trusted

There is no trust on first use. An admin creates a single-use token bound to a name, with an expiry (one hour by
default); the token carries the server certificate's fingerprint, so the new client pins the server before it sends
anything. The client then sends its own certificate, and the server stores it with the role and scope the token asked for.
The fingerprint is that of the certificate served when the token is issued. With a certificate a public CA signed (ACME),
which is replaced at every renewal, a pin breaks: use an API token instead and let the client verify the certificate with
its trusted roots; the console's Host page and `GET /api/v1/host/certificate` (`remote_add`) give the command without a
fingerprint then.
A hub forwards requests to hosts over pinned mTLS with a signed claim of the caller's role and scope that a host only
accepts from a certificate of kind `hub` and limits by that certificate's own entry. Failed authentications are rate
limited per source and audited.

## Whom the helper trusts when it runs package tools

An image build runs `pkg` (and, for a Debian or Ubuntu image, `debootstrap`) as root on the host, and a package's install
scripts run with root's rights. So whom they trust is not the daemon's choice, and the daemon is not asked. The helper
refuses a repository configuration, a key or a keyring that root did not provide:

- **The hosts.** A package repository or a `debootstrap` mirror must be on a host listed in `fetch-host` of `priv.conf`,
  over https unless the host is written `http://<host>` there. A user name, a variable or a port trick in the host part
  is refused, so is any other scheme.
- **The keys.** A repository must be verified against a key directory below `/usr/share/keys` (the base system's) or below
  `pkg-keys-dir`. That directory, everything in it and every directory above it belong to root and cannot be written by
  anyone else, and none of it is a symbolic link; the helper checks this every time it is used, and it lies outside every
  directory the daemon can write. A key directory made in the daemon's work area is refused, however it is named.
- **The keyrings.** The keyring that checks a `debootstrap` release is a file directly in `keyring-dir`, with the same
  rules.

The repository configuration is not checked where the daemon wrote it. The daemon can change a file between a check and
the run, so the helper reads the whole directory itself (every entry, every file to its end, none longer than 16 KiB, no
more than 32 entries), accepts exactly the one block JailOps writes with every key once, copies the bytes it checked into
a directory of its own (root's, mode 0700) and runs `pkg` on that copy, which it removes afterwards.

To build an image from a repository of your own, list its host in `fetch-host` and put its key directory below
`pkg-keys-dir` yourself, as root. An app installation uses the host's own repository configuration (root's files), not
one the daemon writes.

## Package scripts run as root, so never in a root that runs

`pkg` runs the install scripts of a package in a chroot of the root it was given, as the user that started it, with the
shell and the libraries it finds there. Started by the helper (root of the host) against the root of a jail, that is
the jail's tree: a process of a running jail that replaced `/bin/sh` or a library, or put a symbolic link where `pkg`
writes, would have root of the host at the next package operation. So the helper refuses `pkg -r ROOT` for the root of
a running jail, however the path is spelled (a trailing slash, a symbolic link on the way, `..`); `-r` is for a root no
jail runs in: an image being built, and the jail of an app installation before it has first run.

- **`jailops app install`** makes the jail, mounts its datasets on the host and installs the packages with `pkg -r <jail
  root> install` through the helper while the jail has never run, and only then starts it. What is in the root is the
  base system of its image. An `operator` may install. A package from a repository the host trusts runs its scripts with
  root's rights inside that chroot, as it would for an image build; the app installation uses the host's own repository
  configuration (root's files), not one the daemon writes. For a package from the JailOps repository the host's
  configuration of that repository and its key are copied into the jail, so that its packages are updated from it later.
- **The bash of a new jail** is installed with `pkg -r` before its first start (nothing runs in the root yet, and the
  host's network fetches the package); a start never waits more than a minute for the shell setup.
- **Package updates, the retry of the shell setup and the app draft of a running jail** run `pkg -j <jail>`: `pkg` attaches
  to the jail before it does anything, so what it writes and the scripts it runs are the jail's own, with the jail's
  rights. The helper allows `-j` for a running jail JailOps manages, with none of the options that name a directory of
  the host. `pkg` then reads the repository configuration, the keys and the cache inside the jail, and fetches from the
  jail's network: a jail that must update its packages must be allowed to reach the package servers, and the
  repositories it updates from are the ones its own `/etc/pkg` and `/usr/local/etc/pkg/repos` name. That configuration is
  the jail's, as the packages it installs are. While a package operation works in a jail, the daemon refuses every exec,
  shell and console session into it (`busy`, "packages are being installed or updated").

## Drafting an app from a jail reads, never writes

`jailops app export` (`GET /api/v1/jails/<n>/app-draft`) needs `operator`, the role that may exec into the jail,
because it runs commands there: `sockstat`, `find` and `stat` through the in-jail exec, as root in the jail, so what
they print is the jail's word and is parsed as untrusted text (bounded counts, paths checked against the catalog's
rules). On the host it runs one exact form, `pkg -j <jail> query -e "%a = 0" "%n %v %R %w"`, which the helper's
allow-list accepts as it is and in no other shape, and it reads the jail's `/etc/rc.conf` through the helper's file
operations. It never reads a configuration file, leaves out an rc.conf knob whose name looks like a secret or whose
value holds a shell expansion, and is audited with counts only. A jail's owner can make the draft say anything; the
person who sends it to the catalog reviews it.

## Who may connect to an app

An installed app is closed: its managed firewall policy denies every inbound connection, the host's included, until
`jailops app allow` lets a source in (`operator` in the project). The managed policies are written by app access only; the firewall
routes refuse to change them, so a person cannot widen a grant behind the registry's back, and a jail's own policy
cannot reopen the closed default. A jail that is the source of a grant is not deleted until the grant is denied:
the rule names the jail, and a jail made later under the name would take its place.

For a database app, `psql` runs as `postgres` in the jail through the helper's in-jail exec with the statements on its
standard input: no statement is in an argument vector. The daemon generates the password (32 characters, about 190 bits),
computes its SCRAM-SHA-256 verifier and sends only the verifier, so the password reaches no statement, server log or
history; it is in the one answer to the allow and nowhere else (not the registry, the operation journal, the audit log
or the daemon log). Whoever reads that answer holds the role's password: treat the terminal or the console where it is
shown accordingly. Database names are checked against `^[a-z][a-z0-9_]{0,62}$` and PostgreSQL's reserved names before
any SQL is built, and JailOps never alters or drops a role or a database that its registry does not say it made.
`pg_hba.conf` is written through the helper's file operations below the jail root (they open the jail root as their
root, so no symlink of the jail leads out of it, and refuse a file that is not a regular file) and given back to
`postgres` in the jail; an allow that fails half way keeps the role it made in the registry, and the next allow sets a
new password and finishes; the lines it writes always require
`scram-sha-256`. What a jail's root does to its own PostgreSQL afterwards (another `trust` line above the block) is the
jail's own business, as before.

## Encrypted volumes

An encrypted volume ([storage.md](storage.md#encrypted-volumes)) protects data **at rest**: on the disks, in a raw copy,
on a host that is powered off or has the volume locked. It does not protect data from the running jail, from root on the
host while the volume is unlocked, or from anyone who can read the kernel's memory. ZFS keeps dataset names, sizes and
properties readable.

The passphrase passes through the daemon: it arrives in the body of a creation or an unlock (over TLS or the local
socket), goes to the helper on the request stream of the operation, and from the helper to `zfs` on standard input. It is
in no argument vector, answer, operation record, journal, audit entry or log line, and the tests search all of them for
it. **A compromised daemon sees every passphrase typed while it is compromised**, and can unload keys (stop and lock jails)
like an operator. What it cannot do through the helper: run `zfs load-key`, `unload-key` or `change-key` on any dataset
but an encrypted volume of a JailOps project (managed, of kind `volume`, below the project's `volumes` parent, its own encryption root
with `keyformat=passphrase`), give a key file or another key location, change the cipher or the key derivation of a new
volume (the helper sets `aes-256-gcm`, `keyformat=passphrase`, `keylocation=prompt` itself), or change a passphrase
without the current one (the helper checks it with `zfs load-key -n` first). Unlocking needs the operator role in the
jail's project, changing the passphrase the admin role; five wrong passphrases in a row lock a jail's unlocks out for
30 seconds. The helper counts wrong passphrases itself too, so a compromised daemon cannot guess without limit: after
five for a volume (twenty for all volumes together) every try waits, 30 seconds at first and twice as long after each
further wrong one, at most an hour; a right passphrase forgets the count, and so does a restart of the helper (which
needs root). There is no recovery key: a lost passphrase is lost data.

## Interfaces

The helper runs as root and changes network interfaces for the daemon: the epairs of jails, their addresses, routes, MTUs
and their move into and out of a jail's vnet. It must never be made to change one that is not JailOps's: the host's
uplink (`vmx0`, `em0`), `lo0`, a bridge an administrator made, a tunnel. **An interface is JailOps's when the kernel says
so: it is an epair (its driver's group) and its description carries JailOps's marker** (`jailops ...`). Its name says
nothing: a name that looks like JailOps's (`jo7`) is not enough.

- **Only root sets a description** of an interface in the host's network stack, and the only operations of the helper
  that write one are the creation of an interface and the description of an interface that already carries the marker.
  So the daemon cannot have the marker put on an interface that exists, and cannot take it off one (a description that
  is not JailOps's is refused, and clearing one writes the bare marker `jailops managed`).
- **Create.** The helper creates an epair under a generic name (`epair5a`), gives it the marker,
  and only then renames it to the name asked for. The rename is the kernel's atomic check that the name is free: if an
  interface has the name (made a moment ago, whatever it is), the rename fails, the new interface is destroyed and
  nothing else is touched. No interface ever has the name without the marker, and no interface is ever taken over by
  its name. Before that, the helper refuses a name that exists (`forbidden: interface "mybr" exists and is not
  JailOps's; the helper never takes over an interface by its name`; one that is JailOps's answers `already_exists`) and
  a name of the form a driver gives its interfaces, whether or not that driver is loaded: a driver name alone (an
  interface group, `epair`, `all`) or followed by a unit number, an epair end or a vlan tag (`vmx0`, `em1`, `lo0`,
  `bridge0`, `epair0a`, `tap0`, `wg0`, `pflog0`, `vlan0.10`; `invalid: interface name "vmx0" has the form of the
  interfaces of the driver "vmx"`). A device the kernel attaches later is therefore never confused with an interface of
  JailOps. The list is in `internal/ipam/drivers.go`.
- **Change, destroy, address, route, MTU, move.** The helper reads the interface from the kernel
  (`ifconfig NAME`) in the same operation, just before it acts, and refuses one that is not an epair
  (`forbidden: interface "vtnet0" is not managed by JailOps: JailOps changes only epairs it created`) or
  that does not carry the marker (`... it has no JailOps description (JailOps marks every interface it creates and
  never takes one over by its name)`, or `... its description "uplink" is not one JailOps writes`). Between the read and the action only root can rename an
  interface: the helper renames none but the one it has just created.
- **Command lines.** The command allow-list has no form that creates, renames or destroys a host interface any more
  (`ifconfig epair create`, `ifconfig epairN name X` are refused); its `ifconfig -j JAIL IF ...` and `route -j JAIL
  ...` forms act in the vnet of a managed jail and read the interface there first. Root in a vnet jail can set the
  descriptions in its own vnet, so the marker proves less inside a jail: it keeps the helper off the jail's loopback,
  and what the jail could forge is an interface of its own vnet. An interface that comes back from a jail's vnet through the
  helper (`net.move_from_jail`) is a virtual one the jail could reach anyway, and the helper refuses it when the host has
  an interface of that name: the kernel would bring it back and let two interfaces share the name (verified on FreeBSD
  15.2). When a jail is removed, the kernel returns its interfaces by itself, with whatever name the jail's root gave
  them, possibly a name the host has; a lookup by name (the helper's read and its action alike) finds the host's own,
  which was there first, so such a twin is not taken for JailOps's.
- **Reading stays open.** The interface list, the uplink's addresses and any one interface are read as before.
- **jail.conf.** `vnet.interface` must name an epair end of the form JailOps gives them (`jo` and the jail's hash), and
  each one that exists when the jail is created must be JailOps's in the kernel.
- **No description, no ownership.** An epair without a description is not JailOps's, whatever its name or its
  prefix; one with someone else's description, or of another kind, is not either.

What it does not cover: root on the host can put JailOps's description on anything, and an administrator who does so
hands that interface to JailOps.

- **Reject routes.** The helper adds a route that answers with an error (`route -reject` through the loopback address) only for the subnet of a network JailOps has stored, never for another prefix, so a compromised daemon cannot cut the host off from a part of the network.

## Projects are not a security boundary against the kernel

A project separates names, quotas, networks and firewall policy. Jails share the host kernel. A high-security tenant needs an isolation
boundary judged on its own terms, such as a host of its own: a separate pool splits storage and operations, not the kernel. A jail with `zfs_delegation` or a host-directory volume is not isolated from that storage: root in a jail with `zfs_delegation` manages the dataset `<container>/delegated` itself, with `allow.mount.zfs`, outside the helper's mountpoint rules; it needs a global administrator and `admin-zfs-delegation` in `priv.conf`.

## Network isolation

Every jail has a link of its own to the host: an epair whose host end is the jail's only neighbour. Jails share no network
segment, so they cannot see each other's traffic, and what a jail forges at layer 2 (ARP, neighbour advertisements, router
advertisements, DHCP) reaches the host's end of its own link and changes nothing outside it. The host routes each of a
jail's addresses to that link and answers for the other addresses of the subnet with an error. Every jail also gets a PF
anchor on its link: it binds the jail to its own addresses (anti-spoofing), closes it to other projects unless a rule you
wrote opens the way, and holds the policies of the jail. Between two jails the host forwards what the anchors of both
allow. The PF matrix of the end-to-end tests checks each of these with real traffic and forged frames
([networking.md](networking.md)). Jails share the host kernel; this is a separation of networks, not of kernels
([above](#projects-are-not-a-security-boundary-against-the-kernel)).

**Port forwards.** A forward (a `redirect` rule of a firewall policy, a `proxy.<name>` device of a jail or a profile) takes
traffic that would reach the host, so only a **global administrator** gives or changes one; an administrator of a project
may edit the other rules of a policy that already has a forward. A forward is refused on a port some service of the host
listens on (ssh, the console, the other JailOps listeners, the ACME challenge port while ACME is the source) and on a
listen address that is not an address of the host.

**Size of the firewall objects.** One project cannot fill the table space pf has for every project: a policy has at most 500
rules, an address set 5000 members, a project 200 policies and 200 address sets and 20000 set members together.
`jailops doctor` warns (`firewall.size`) at 80% of a limit.

## Name resolution of jails

A network without `dns` gives its jails the host's own nameservers from `/etc/resolv.conf`, read by the daemon (the file
is world readable): the jails reach them like any other address, through the network's NAT or routing and their own
firewall policy, and nothing on the host is opened for it. A host that resolves only through loopback (a local unbound)
gives its jails the network's gateway address instead. That answers only if the administrator lets the resolver listen on
the gateway and admits the network's subnet (and, with a `pf.conf` that blocks by default, passes port 53 in on the
gateway interface): JailOps never edits the resolver or `pf.conf` and opens no port. Until then the jails' queries go
unanswered; no host service is exposed by the default. A jail's own policy governs port 53 like any other traffic. A jail
that runs its own resolver removes the line `# written by JailOps` from its `resolv.conf`; JailOps then never writes the file again, and
it rewrites the file of a running jail only through the helper's file operations, which replace a regular file inside the
jail's root and refuse a symlink.

## Secrets

- A jail's `env` value `sealed:age:<ciphertext>` is sealed to the host's age key (`<data_dir>/secrets.key`, public half
  published as `secrets_recipient`). The API returns the ciphertext, never the plaintext; the daemon opens it only when it
  starts a process in the jail.
- The backup key is a file on the host; the recovery key is shown once and kept nowhere. The backup node never holds a key.
  See [backup-restore.md](backup-restore.md).
- A backup node holds one key domain, so all hosts using it share the backup key: each can read and damage the others'
  backups (the node cannot tell a wrong chunk from a right one without the key). Give hosts that do not trust each
  other their own node ([backup-restore.md](backup-restore.md#who-trusts-whom-hosts-that-share-a-node)).
- Do not put tokens on a command line (visible to other users); use `--token-file -` or `token_file`.
- WireGuard: private and preshared keys are made and kept by the helper in `wireguard-dir` (files 0600) and never reach
  a command line, the API, the audit log or a log. A join token holds a peer's private key and is shown once by
  `jailops wireguard peer add`; the server keeps only the peer's public key and the preshared key. `jailops wireguard
  join -` reads a token from standard input and `--token-file` from a file; a token given as an argument is accepted
  with a warning. Reading tunnels needs the operator role, changing them a global admin.
  See [wireguard.md](wireguard.md).
- The passphrase of encrypted volumes is typed (`jailops` asks without echo) or read from a file you name
  (`--passphrase-file`); it is never a command line argument and never stored by JailOps. See above.
- Interface descriptions are built from names only and checked by the helper (`jailops ...`, at most 64 characters of
  `A-Za-z0-9 ._:/=()-`): nothing a user types reaches `ifconfig` as free text. The description is also the mark of
  ownership ([Interfaces](#interfaces)).
