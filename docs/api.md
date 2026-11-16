# The API, for programs

JailOps is an API first: `jailops`, `jailops-sync` and the web console are clients of the same HTTP API, `/api/v1/...`, JSON, with
operations for long work (a jail create, an image build, an image upgrade that also moves the jails) and an event stream.

| What | Where |
|---|---|
| The Go SDK (`jailops.net/jailops/sdk`): typed clients for jails, networks, storage, projects, images, firewall, backups, tokens, the application catalog, its installation, app drafts from a running jail, and host management (`HostSystem()`) | `sdk/` and its `doc.go` |
| The Go SDK (`jailops.net/jailops/sdk`): typed clients for jails, networks, WireGuard tunnels, storage, projects, images, firewall, backups, tokens, the application catalog, its installation and app drafts from a running jail | `sdk/` and its `doc.go` |
| The Go SDK (`jailops.net/jailops/sdk`): typed clients for jails, networks, storage, projects, images, firewall, backups, tokens, the application catalog, its installation, app drafts from a running jail and who may connect to an installed app (`Apps().Access`, `Allow`, `Deny`) | `sdk/` and its `doc.go` |
| The wire types (`sdk/api`) and the protocol, route by route, with error codes | [../sdk/PROTOCOL.md](../sdk/PROTOCOL.md) |
| An in-memory server with the same routes, for tests | `sdk/fake` |
| Error codes and what to do | `jailops explain CODE` |

There is no OpenAPI document today.

**WireGuard** (extension `wireguard`, [wireguard.md](wireguard.md)): `GET|POST /api/v1/wireguard`,
`GET|PUT|PATCH|DELETE /api/v1/wireguard/{name}`, `POST /api/v1/wireguard/{name}/peers` (answers `WireGuardPeerCreated`
with the join `token` and the `config` file: secrets, returned once, never stored), `DELETE .../peers/{peer}`,
`POST /api/v1/wireguard/join` (`WireGuardJoin`: a client from a token), `POST .../up`, `.../down`, `.../rotate-keys`.
Reads need the operator role and never carry a private or preshared key; changes need a global admin. SDK:
`c.WireGuard()`. The extension `interface_descriptions` says the host describes its interfaces (`net.descriptions`).

**Firewall test** ([networking-ipv6.md](networking-ipv6.md#would-it-pass)): `POST /api/v1/firewall/test` (extension `firewall_test`, operator in the project) takes `FirewallTestRequest` (`from`, `to`, `proto`, `port`, `icmp_type`, `family`) and answers `FirewallTestResult`: `verdict` (`pass`, `block`, `unknown`), `cases` (one per address pair: the `hops` with the anchor, interface, direction, `verdict`, `decided_by`, `skipped` (the allow rules a deny rule won over, and the disabled rules the packet would have met) and `loaded_matches_rendered`) and `caveats`. It changes nothing.

**Boot plan** ([operations.md](operations.md#start-at-boot)): `GET /api/v1/boot` (extension `boot_plan`, readonly) answers `BootPlan`:
what the daemon starts after a boot of the host, in order (`order`: `position`, `project`, `jail`, `priority`, `depends`,
`reason` `autostart` or `dependency of NAME`, `running`), and the jails it does not start with the reason (`not_started`:
a cycle, a dependency that does not exist, an encrypted volume that waits for its passphrase, a jail that depends on one
of those). The order is that of the whole host; a caller sees the jails of the project it names, or with `all_projects=true`
of every project it may use, in the same order and numbered again. SDK: `c.BootPlan(ctx, allProjects)`.

**Logs** ([logging.md](logging.md)): `GET /api/v1/logs` (extension `logs_unified`, operator) merges the end of one file
(`file`, default `messages`) of the jails of `?project=` (or of every project the caller may use with `all_projects=true`)
by time: `jail` (repeatable), `label=k=v` (repeatable), `app`, `app_logs=true`, `tail`, `since`, `grep`, and `cursor`,
the `next` map of the previous reply as JSON, to follow. Reply `LogsRead`: `lines` (`time`, `project`, `jail`, `app`,
`file`, `line`), `sources` (with `error` for a file that could not be read), `next`, `truncated`; at most 50 files and
2000 lines. Log forwarding (extension `log_forward`, global admin): `GET|PUT|DELETE /api/v1/logs/forward` (kind
`LogForward`: `spec.sinks` and `status` with `origin` config or api, `generation` as ETag and each sink's state; `PUT`
takes `LogForwardSpec` and `If-Match`, `DELETE` returns to `jailopsd.yaml`) and `POST /api/v1/logs/forward/test`
(`{"sink": NAME}`, one tagged line). SDK: `c.Logs()` (`Read`, `Forward`, `SetForward`, `ResetForward`, `TestForward`).
**Volumes** (extension `volumes`, [storage.md](storage.md#volumes)): a volume is an object of a project, `kind: Volume`
(`spec`: `storage`, `size`, `uid`, `gid`, `mode`, `encrypted`, `path`, `watch`, `probe`, `on_loss`, `comment`; `status`: `dataset`,
`mountpoint`, `used`, `locked`, `state`, `detail`, `attached_to`, `warnings`). A volume with a `path` is a directory of the host
([storage.md](storage.md#host-directories-as-volumes)): only a global administrator makes or attaches one, it has no dataset,
snapshots, size, key or backup (those answer `invalid`), `status.state` is `ok` or `lost` with `status.detail`, and a start of a
jail that attaches a lost one answers `busy`. The events `volume-lost`, `volume-restored` and `volume-remounted` follow its watch. `GET|POST /api/v1/volumes`, `GET|PUT|PATCH|DELETE /api/v1/volumes/{name}` (a PUT changes the
labels, the comment and the size, and the watch of a host directory; the rest is fixed at creation; `POST` and `DELETE` answer operations; a volume that a jail
attaches is not deleted: `busy`). `POST /api/v1/volumes` takes `VolumeCreate` (`metadata`, `spec`, `passphrase` for an
encrypted volume). A jail attaches volumes in its spec, `volumes: [{volume, mount, read_only}]`, which a create, a PUT and a
config change all check (the volume exists in the project, the jail is stopped, an encrypted volume has one jail);
`GET|POST /api/v1/jails/{name}/volumes` (`VolumeAttachRequest`: `volume`, `mount`, `read_only`, `copy_existing`) and `DELETE
/api/v1/jails/{name}/volumes/{volume}` attach and detach as operations whose result is the `Jail`. Snapshots:
`GET|POST /api/v1/volumes/{name}/snapshots`, `DELETE .../snapshots/{snapshot}` and `POST .../rollback` (`VolumeRollback`:
`snapshot`, `confirm_data_loss`). Encrypted volumes: `POST /api/v1/volumes/{name}/unlock` (`VolumeUnlock`: `passphrase`,
`start`; operator), `POST .../lock` (operator) and `POST .../passphrase` (`VolumePassphraseChange`: `old_passphrase`,
`new_passphrase`; admin) answer operations whose result is the `Volume`. A jail that attaches a locked volume has
`status.power` `locked` and `status.locked` (the volume names); starting it answers `locked` (409), a wrong passphrase fails
the operation with `bad_passphrase` (403), five in a row make the volume answer `rate_limited` (429) for 30 seconds. A
passphrase is never in a reply. SDK: `c.Volumes()` (`Create`, `Get`, `List`, `Update`, `Delete`, `Unlock`, `Lock`,
`ChangePassphrase`, `Rollback`, `Snapshots`), `Jails().AttachVolume`, `DetachVolume`, `Volumes`.

**Backups of volumes** (extension `backup_run`): a volume is a backup of its own. A `Backup` has `spec.kind` (`volume`; absent for a
jail), `spec.jail` and `spec.jail_uuid` naming the volume and its UUID, and `spec.volume` (its `VolumeSpec`). A policy backs up the
volumes of the jails it selects and the volumes whose labels match, each once per run; `BackupPolicySpec.exclude_volumes` and
`BackupRunRequest.no_volumes` (`POST /api/v1/backups/run`) leave them out. `POST /api/v1/restores` with a volume backup restores a
new volume (the operation's result is the `Volume`; `as` names it, a volume is never replaced; `passphrase` makes an encrypted one
and is never stored or logged); with a jail backup it first restores the volumes the project lacks from their newest backup, or
restores the jail with no volume attachments with `no_volumes`.

**Renames** (extension `rename`, [design.md](design.md#88-renames)): `POST /api/v1/networks/{name}/rename`,
`/api/v1/firewall/address-sets/{name}/rename`, `/api/v1/firewall/policies/{name}/rename`, `/api/v1/profiles/{name}/rename`,
`/api/v1/jails/{name}/rename` (a stopped jail), `/api/v1/images/{name}/rename`, `/api/v1/projects/{name}/rename` (its
jails stopped), `/api/v1/volumes/{name}/rename` (the jails that attach it stopped), `/api/v1/storage/{name}/rename`,
`/api/v1/backup-targets/{name}/rename`, `/api/v1/backup-policies/{name}/rename`, `/api/v1/certificates/{name}/rename`,
`/api/v1/users/{name}/rename` and `/api/v1/wireguard/{name}/rename`, body `Rename` (`new_name`, `dry_run`), `If-Match` checked against the object's generation. A dry run
answers at once with `RenameResult`: `changes` (`kind` object, reference, dataset, anchor, interface, file or state;
`object`; `detail`), `counts`, `steps` and `warnings`; a rename answers an operation whose result is the same. All of it
changes or none of it. Global admin for networks, images, projects, storage, backup targets, certificates, users and WireGuard tunnels, the project's admin for the others. An update
(`PUT`, `PATCH`) never changes a name. SDK: `Resource.Rename` (`c.Networks().Rename`, `c.Firewall().Policies().Rename`,
...) and `c.Jails().Rename`; the fake serves them.

## Reaching it

- **Local**: the unix socket. Root (uid 0) is a global admin, the host's recovery access; every other local user is anonymous, like an unauthenticated remote client, and authenticates with a token or a login. The same identities, roles, scopes and audit as the network listener.
- **Network**: a TLS 1.3 listener you switch on, a certificate you choose, and pinned client certificates, tokens or logins. Every
  option, the recipes and what is not implemented are in [exposure.md](exposure.md).

    c, err := sdk.Connect(ctx, sdk.Remote("https://host.example.org:39110",
        sdk.WithPinnedFingerprint(fp),          // a self-signed certificate; leave it out for a CA-signed one
        sdk.WithClientCert(cert)))              // pinned mTLS; or sdk.WithToken(token)

Every request about something a project owns names the project (`?project=`, `sdk.WithProject`); there is no default project.

Request bodies are read strictly: a member the request type does not have (a misspelled `dry_run`, say), a member spelled
with other cases, a member twice and anything after the JSON value answer `invalid` (400) with a message that names the
member. The `status` of an object read and sent back is ignored; maps such as `labels` and merge patches (`PATCH`) take any
key. Answers are `Cache-Control: no-store`. An anonymous `GET /api/v1` tells the API version, the extensions and the role
only. The credential goes in the `Authorization` header; a token in the query string authenticates nothing.
The SDK refuses plain `http://` to anything but loopback.

An error the daemon did not expect answers `internal` (500) with the text `internal error` and the id of the request in the
hint; the cause, which can carry paths and command output of the host, is in the daemon's log under that id. A port forward
(a redirect rule of a firewall policy, a `proxy.*` key of a jail or profile) answers `forbidden` (403) to anyone but a global
administrator and `invalid` (400) on a host port or an address that is the host's own. The firewall objects of a project are
bounded: a policy has at most 500 rules, an address set 5000 members, a project 200 policies, 200 address sets and 20000 set
members together (`quota_exceeded` or `invalid`).

Declarative management of everything the API can create is `jailops-sync` ([fleet-sync.md](fleet-sync.md)).

## Liveness and readiness

`GET /healthz` (liveness: `ok`, always 200) and `GET /readyz` (readiness: `ok` with 200 once start-up finished and the
helper and the database answer, else 503 `not ready: CLASS` with CLASS `starting`, `stopping`, `helper`, `storage` or
`store`, cached for 2 seconds) are plain text and public, for load balancers and monitors
([exposure.md](exposure.md#load-balancers-and-monitors)). The state of the host itself is `GET /api/v1/doctor`, which
needs a global identity ([operations.md](operations.md#what-to-monitor)).

## Host management

The host itself (appliance mode, [appliance.md](appliance.md)) is a set of singleton objects under `/api/v1/host/...`, one
per module, off until the administrator enables the module in `jailopsd.yaml` and in `priv.conf`. Two modules are built:
`identity` (extension `host_identity`) and `firewall` (below). Module `identity`:

| Route | Role | What |
|---|---|---|
| `GET /api/v1/host/identity` | readonly, global | kind `HostIdentity`: the host name, `/etc/resolv.conf`, the NTP servers JailOps manages and `ntpd_enable` as the host has them (`spec`), and `status`: `managed`, `config_enabled`, `helper_enabled`, `drift`, `applied`, `ntp_sync`. Always readable |
| `PUT /api/v1/host/identity` | admin, global | body `{"spec": {...}, "dry_run": true}`; reply `HostChange`: `changed`, `diff` (unified), `actions`, `snapshot` |
| `GET /api/v1/host/snapshots` | readonly, global | the copies of host files kept before each change, newest first |
| `POST /api/v1/host/snapshots/{name}/restore` | admin, global | `{name}` or `latest`; body `{"dry_run": true}` optional; reply `HostChange` |

The spec:

    {"hostname": "web1.example.org",
     "resolvers": {"nameservers": ["192.0.2.53", "2001:db8::53"], "search": ["example.org"]},
     "ntp": {"servers": ["192.0.2.123", "ntp.example.org"], "enable": true}}

A part left out is not changed. `hostname` is one label or a fully qualified name (RFC 1123, at most 253 characters, not an
address); 1 to 3 `nameservers`, IPv4 or IPv6 literals without a zone; at most 6 `search` domains, 256 characters together;
at most 4 NTP `servers`, host names or literals; no duplicates anywhere. The daemon checks the spec and the privileged
helper checks it again. While the module is off a change answers `not_managed` (HTTP 403) with the lines to add in the
hint. The operator role is not enough: changing the host needs a global admin. Every `PUT` and `POST` is in the audit log,
dry runs too. In Go:

    id, err := c.HostSystem().Identity().Get(ctx)
    ch, err := c.HostSystem().Identity().Apply(ctx, api.HostIdentitySpec{Hostname: "web1.example.org"}, true) // dry run
    ch, err = c.HostSystem().Restore(ctx, api.HostSnapshotLatest, false)

(`c.Host(name)` is the older method that scopes a hub's client to one of its hosts.)

### The host firewall and commit confirmed

Module `firewall` (extension `host_firewall`) owns `/etc/pf.conf` as a whole file, rendered by the privileged helper from
a spec; every change of it goes through **commit confirmed** (extension `host_pending`): it reverts itself at a deadline
unless it is confirmed. The timer is the helper's own; the daemon only reads it.

| Route | Role | What |
|---|---|---|
| `GET /api/v1/host/firewall` | readonly, global | kind `HostFirewall`: `spec` is what was applied last, or the default before any apply (a hand-written `pf.conf` is not read back into fields); `status`: `managed`, `config_enabled`, `helper_enabled`, `file_exists`, `file_managed`, `drift` (`pf.conf`, `pf_enable`, `pf_rules`), `applied`, `pf_enabled`, `rules` (in plain words), `warnings` (ssh open to the world), `pending`, `console_port`. Always readable |
| `PUT /api/v1/host/firewall` | admin, global | body `{"spec": {...}, "dry_run": true, "confirm_within": 120, "confirm_lockout": false}`; reply `HostChange` with `diff`, `rules`, `actions`, `warnings` and, after a real change, `snapshot` and `pending` |
| `GET /api/v1/host/pending` | readonly, global | `HostPending`: `pending` (`id`, `module`, `snapshot`, `created`, `deadline`, `seconds_left`, `confirm_within`) and `last`, how the last one ended (`confirmed`, `reverted`, `timed_out`, `reverted_at_boot`, `revert_failed`) |
| `POST /api/v1/host/pending/confirm` | admin, global | body `{"id": "..."}` optional; keeps the change; reply `HostPending` |
| `POST /api/v1/host/pending/revert` | admin, global | the same; puts the snapshot back now |

The spec:

    {"template": "custom-rules",
     "ssh": {"ports": [22], "allow_from": ["@admins"]},
     "console": {"allow_from": ["@admins", "198.51.100.7"]},
     "sets": [{"name": "admins", "members": ["192.0.2.0/24", "2001:db8:a::/48"]}],
     "allow": [{"proto": "tcp", "ports": ["80", "443"], "comment": "web"},
               {"proto": "udp", "ports": ["51820"], "from": ["2001:db8:1::/56"]}],
     "icmp": true, "logging": false, "nat": "none"}

The spec is applied whole: a part left out takes its default (template `default`, ssh port 22, sources anywhere), not the
value applied before. `template` is `default` (block inbound except ssh, the console and what is always passed), `open`
(pass everything) or `custom-rules` (`default` plus the `allow` rows, at most 64; `allow` with another template is
`invalid`). Sources are addresses, prefixes without host bits or `@set` of a set defined in `sets` (at most 16 sets of 1 to
256 members, at most 32 sources per list); ports `N` or `N-M`, at most 16 per row; `proto` `tcp` or `udp`; a `comment` has
at most 80 characters and no line break, quote or backslash. `console.port` is the daemon's TLS port and is filled in by
the daemon. `nat` other than `none` is `unsupported`. `confirm_within` is 10 to 1800 seconds (default 120).

A real change is refused with `forbidden` (detail `guard: lockout`) when the address the request came from could reach
neither an ssh port nor the console under the new rules, and with `invalid` (detail `guard: unknown_peer`) when that address
is unknown (the unix socket, a request through a hub) unless `confirm_lockout` is set; a dry run reports both as `warnings`. While a
change waits for its confirmation every other change of the host (`PUT` of a module, a restore) answers `busy` with the id
of the pending change in `detail.pending`. In Go:

    fw, err := c.HostSystem().Firewall().Get(ctx)
    ch, err := c.HostSystem().Firewall().Apply(ctx, api.HostFirewallApply{Spec: spec, ConfirmWithin: 300})
    p, err := c.HostSystem().Confirm(ctx, ch.Pending.ID) // or Revert, or Pending

While the console's certificate comes from ACME, the spec has `acme` (`{"challenge": "http-01", "port": 39080}`), filled
in by the daemon like `console.port` (a value a client sends is replaced): the helper renders the `rdr` of port 80 (or
443 for `tls-alpn-01`) to that port on `127.0.0.1` and `::1`, and its `pass` rule ([exposure.md](exposure.md#acme-a-certificate-from-a-public-ca)).

### The console's certificate

Extension `host_certificate` ([exposure.md](exposure.md)):

| Route | Role | What |
|---|---|---|
| `GET /api/v1/host/certificate` | readonly, global | kind `HostCertificate`: `source` (`self-signed`, `configured`, `uploaded`, `acme`), `current` (`subject`, `issuer`, `names`, `not_before`, `not_after`, `days_left`, `fingerprint`, `self_signed`, `public_ca`), `acme` (`spec`, `state` idle, requesting, valid or error, `last_attempt`, `last_success`, `last_error`, `failures`, `next_attempt`, `renew_at`, `challenge_port`, `terms_url`), `redirect` (`managed`, `applied`, `lines`), `configured`, `stored`, `listener`, `port`, `remote_add`, `warnings` |
| `PUT /api/v1/host/certificate` | admin, global | body `{"certificate": "PEM chain, leaf first", "key": "PEM", "hostname": "console.example.com"}`; `invalid` with the reason when it cannot work; `conflict` when `jailopsd.yaml` names the files |
| `POST /api/v1/host/certificate/acme` | admin, global | body `ACMESpec` (`domains`, `email`, `directory_url`, `challenge`, `accept_tos`); answers at once, the request to the CA runs in the background (follow `acme.state`); a wildcard is `unsupported` |
| `POST /api/v1/host/certificate/self-signed` | admin, global | the generated certificate again |

In Go: `c.HostSystem().Certificate().Get(ctx)`, `.Upload(ctx, in)`, `.UseACME(ctx, spec)`, `.UseSelfSigned(ctx)`.

### First-run setup

Extension `setup` ([appliance.md](appliance.md#the-first-boot-wizard-built)). While no global administrator exists:

| Route | Role | What |
|---|---|---|
| `GET /api/v1/setup` | public | `SetupStatus`: `required`, `token_issued`, `expires_at` |
| `POST /api/v1/setup` | public | body `{"token": "...", "name": "admin", "password": "..."}`; 201 `SetupResult` (`user`, `client_address`); `unauthorized` for a wrong, expired or missing token (locked out per source after 5, `rate_limited`), `invalid` for the name or the password |
| `POST /api/v1/setup/token` | admin, global (root on the socket) | `SetupToken`: `token` (shown once), `expires_at`, `urls`, `hint` |

All three answer `not_found` once an administrator exists. In Go: `c.SetupStatus(ctx)`, `c.Setup(ctx, req)`, `c.SetupToken(ctx)`.
