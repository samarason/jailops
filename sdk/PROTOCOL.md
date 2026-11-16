# JailOps wire protocol (SDK contract)

The SDK client (`sdk`) and the in-memory server (`sdk/fake`) implement this document.
The daemon must match it. Types are in `sdk/api`. Everything is JSON under `/api/v1`.

## Envelope

Every reply is an `api.Response`:

| type | HTTP | body |
|---|---|---|
| `sync` | 200, 201 (create), 204 | `metadata` holds the result |
| `async` | 202 + `Location` | `operation` is `/api/v1/operations/<id>`, `metadata` is the `api.Operation` |
| `error` | per code (`api.Code.HTTPStatus`) | `error` is `api.Error` (code, message, hint, detail) |

A server may answer a mutating call synchronously or asynchronously; the client handles both. A
non-JSON error body (a proxy, a crash) is mapped from the status: 400 invalid, 401 unauthorized,
403 forbidden, 404 not_found, 405/501 unsupported, 409 already_exists, 412 conflict,
429/502/503/504 busy, other 4xx invalid, other 5xx internal.

## Conventions

- `GET /api/v1` returns `api.ServerInfo` (allowed unauthenticated; `auth` says how the caller was seen).
  `api_extensions` drives `Client.Has`. An `untrusted` caller gets `api_version`, `api_extensions`, `role` and
  `auth` only; the software version, host name, host UUID, environment and secrets recipient need an identity.
- Request bodies are strict: a member the request type does not have (a misspelled option), a member in other
  cases, a member twice and anything after the JSON value are `invalid` (400), and the message names the member.
  The `status` of an object sent back with it is ignored. Maps (`labels`, configuration keys) and merge patches
  take any key.
- Every API answer carries `Cache-Control: no-store` (and `Pragma: no-cache`).
- Lists: `GET /api/v1/<resource>` returns `metadata` as an array of full objects (never URLs). Optional
  `?label=k=v` (repeatable, AND) and `?recursion=n` (reserved).
- Items: `/api/v1/<resource>/<name>`. `GET` sends `ETag: "<generation>"`.
  `PUT` replaces the object and may carry `If-Match: "<generation>"`; a mismatch is `412 conflict`.
  The server owns `uuid`, `scope`, `host`, `created_at` and all `status`; clients cannot change them.
  `PATCH` applies a JSON merge patch (RFC 7386) with the same `If-Match` rule.
  Responses to `PUT`/`PATCH` carry the new `ETag`. `generation` increases when the stored object changes.
- Creates are `POST /api/v1/<resource>` with the full object. Names: lowercase letters, digits and hyphens, starting with a letter and not ending in a hyphen (`^[a-z]([a-z0-9-]*[a-z0-9])?$`), at most 63 characters unless a derived name sets a shorter limit (a project 13, a jail 29, an address set 29).
- Operation results: on success `operation.metadata` is the resulting object (for example the `Jail`);
  when it is empty the client fetches the object by name where it knows it.
- Multi-host (hub): add `?host=<uuid-or-name>` to any request, including `/api/v1/events`. The hub
  forwards the request unchanged to that host over mTLS. This form was chosen over a
  `/api/v1/hosts/{h}/...` prefix because it leaves every route and its permission entry untouched.
- Auth: `Authorization: Bearer <token>`, or mTLS, or the unix socket. Every request carries
  `X-Request-ID` (16 hex) and `User-Agent: jailops-sdk/<version> ...`.
- Only GET/HEAD/OPTIONS are retried by the client; the server must keep them side-effect free.

## Routes

| Method and path | Request | Reply |
|---|---|---|
| `GET /api/v1` | | `ServerInfo`; `environment.kernel_version` is the host's `kern.osrelease` (`15.1-RELEASE-p3`), empty when it cannot be read: the console proposes it, without the patch level, as the release of the base image |
| `GET /healthz` | | `ok`, plain text, always 200: liveness, the process answers. Public, not in the access log |
| `GET /readyz` | | plain text, `ok` (200) or `not ready: CLASS` (503), CLASS one of `starting`, `stopping`, `helper`, `storage`, `store`: start-up finished, the helper answers a read-only call (the JailOps dataset exists), the database answers a query. Cached for 2 s; `?host=` is not forwarded. Public, not in the access log |
| `/api/v1/jails` GET, POST | `Jail` (`spec.volumes`: `{volume, mount, read_only}`, volumes of the project that exist) | list; POST async, result `Jail` |
| `/api/v1/jails/<n>` GET, PUT, PATCH, DELETE | | `Jail`; DELETE async |
| `GET /api/v1/jails/<n>/state` | | `JailStatus` |
| `GET /api/v1/jails/<n>/usage` | | `JailUsage`, measured for this reply and never stored: `accounting` (processes, `cpu_seconds`, `memory_bytes` from racct through `rctl -u`) only while the jail runs, with `error` instead of numbers when racct is off; `disk` (`root_bytes` and `root_referenced_bytes` of the root dataset, `data_bytes` of the persistent datasets and volumes) always, with `error` when a dataset cannot be read. Readonly; the jail list does not carry it (`jail_usage`) |
| `PUT /api/v1/jails/<n>/state` | `JailAction` (start, stop, restart) | async, result `Jail` |
| `/api/v1/volumes` GET, POST | `Volume`; POST takes `VolumeCreate` (`passphrase` for an encrypted volume, never returned) | list; POST async, result `Volume` (extension `volumes`) |
| `/api/v1/volumes/<n>` GET, PUT, PATCH, DELETE | `Volume` | `Volume`; a PUT changes labels, comment and `size` only; DELETE async, `busy` while a jail attaches it |
| `POST /api/v1/volumes/<n>/unlock` | `VolumeUnlock` (`passphrase`, `start`) | async, result `Volume`: loads the key and, with `start` or when the boot wanted to, starts the jail that attaches it; `bad_passphrase` (403) fails the operation, five in a row answer `rate_limited` (429) for 30 seconds. Operator |
| `POST /api/v1/volumes/<n>/lock` | | async, result `Volume`: stops the jail that attaches it, unmounts the volume, unloads the key. Operator |
| `POST /api/v1/volumes/<n>/passphrase` | `VolumePassphraseChange` (`old_passphrase`, `new_passphrase`, 12 to 512 bytes) | async, result `Volume`; the volume must be unlocked (`locked` otherwise). Admin |
| `/api/v1/volumes/<n>/snapshots` GET, POST | `VolumeSnapshot` (name optional) | list; POST async, result `VolumeSnapshot` |
| `DELETE /api/v1/volumes/<n>/snapshots/<s>` | | async |
| `POST /api/v1/volumes/<n>/rollback` | `VolumeRollback` (`snapshot`, `confirm_data_loss` required) | async, result `Volume`; refused while a jail that attaches the volume runs |
| `GET /api/v1/jails/<n>/volumes` | | the jail's `VolumeAttach` list |
| `POST /api/v1/jails/<n>/volumes` | `VolumeAttachRequest` (`volume`, `mount`, `read_only`, `copy_existing`) | async, result `Jail`; the jail must be stopped (`busy`) |
| `DELETE /api/v1/jails/<n>/volumes/<volume>` | | async, result `Jail`; the volume and its files stay |
| `/api/v1/jails/<n>/snapshots` GET, POST | `JailSnapshot` (name optional) | list; POST async, result `JailSnapshot` |
| `/api/v1/jails/<n>/snapshots/<s>` GET, DELETE | | `JailSnapshot`; DELETE async |
| `POST /api/v1/jails/<n>/rollback` | `JailRollback` | async, result `Jail`; data/all without `confirm_data_loss` is `data_loss_unconfirmed` |
| `POST /api/v1/jails/<n>/upgrade` | `JailUpgrade` | async, result `Jail` |
| `POST /api/v1/<kind>/<n>/rename` for `networks`, `firewall/address-sets`, `firewall/policies`, `profiles`, `jails`, `images`, `projects` | `Rename` (`new_name`, `dry_run`); `If-Match` optional | `dry_run`: sync `RenameResult` (`changes`, `counts`, `steps`, `warnings`), nothing changes; otherwise async, result `RenameResult`. The object and every reference to it change in one operation or not at all; a jail must be stopped (`busy`), a project's jails too; a `managed_by` object is `forbidden`. Admin; networks, images and projects need a global admin (`rename`) |
| `GET /api/v1/jails/<n>?expanded=true` | | `JailExpanded`: the jail with its profiles merged in (`spec` is the effective spec) and `sources`, the origin of every key (`jail` or `profile:<name>`) |
| `POST /api/v1/jails/<n>/config?restart=true` | `ConfigChange` (`set`, `unset`) | async, result `{...Jail, restart_required: [keys], restarted}`; **never restarts the jail unless `restart=true`**, and then only when a changed key needs it |
| `POST /api/v1/jails/<n>/exec` | `ExecRequest` | upgrade to a framed stream, see Exec |
| `GET /api/v1/jails/<n>/logs` | | `[]JailLogFile`: the regular files below `/var/log` of the jail root, one directory deep (`name`, `size`, `modified_at`, `kind` active or rotated, `compressed`), sorted by name; running or stopped, `busy` ("jail not mounted", the hint names the dataset) while the root of a stopped jail is not mounted. Operator (`jail_logs`) |
| `GET /api/v1/jails/<n>/logs/<file>?tail=N&since=T&grep=S&offset=O` | | `JailLogRead`: the last `tail` lines (default 200, at most 5000) of the file (a name below `/var/log`, segments `[A-Za-z0-9._-]+` not starting with a dot, at most two), read from at most 1 MiB before its end; `since` (RFC 3339 or a duration such as `15m`) keeps the lines whose timestamp is not older, a line without one belonging to the preceding line; `grep` (plain substring, case-insensitive, at most 128 bytes) keeps the lines containing it; `offset` continues from `next_offset` of a previous reply. `lines` are `{n, text}` (`n` when the reply starts at the beginning of the file), `next_offset` the size when read, `rotated` when the file was shorter than `offset` (the reply then starts over), `truncated` when a limit left lines out. A compressed rotated copy is `invalid` ("not readable (compressed)"). Operator; audited (`jail_logs`) |
| `POST /api/v1/firewall/test` | `FirewallTestRequest`: `from`, `to` (`jail:NAME`, an address, `host`), `proto`, `port`, `icmp_type`, `family` | `FirewallTestResult`: `verdict` `pass`, `block` or `unknown`, `cases` (`family`, `from`, `to`, `proto`, `port`, `icmp_type`, `verdict`, `hops`: `side`, `jail`, `anchor`, `interface`, `direction`, `verdict`, `decided_by` (`stage`, `policy`, `rule`, `name`, `comment`, `pf`), `skipped` (`rule`, `why`), `why`, `loaded_matches_rendered`), `caveats`. Operator in the project; reads only |
| `GET /api/v1/boot` | | `BootPlan`: `order` (`position`, `project`, `jail`, `priority`, `depends?`, `reason` `autostart` or `dependency of NAME`, `running?`) is what the daemon starts after a boot of the host, in order (a jail after its `boot.depends`, which start even without autostart, then the lower `boot.priority`, then the key), `not_started` (`project`, `jail`, `reason`) the jails with autostart a boot does not start: a dependency cycle or a dependency that does not exist, an encrypted volume that waits for its passphrase, a jail that depends on such a jail. The order is the host's: the reply holds the jails of the request's project, or of every project the caller may use when `all_projects=true` is given, numbered again. Readonly (`boot_plan`) |
| `GET /api/v1/logs?jail=J&label=K=V&app=A&app_logs=true&file=F&tail=N&since=T&grep=S&cursor=C` | | `LogsRead`: the end of one file (`file`, default `messages`) of every jail of the request's project, or of every project the caller may use when `all_projects=true` (or no project) is given, narrowed by `jail` and `label` (repeatable) and `app` (the `jailops.app` label); `app_logs=true` adds the files the jails' apps declare below `/var/log`. Each file is read like `GET .../logs/<file>` (`tail`, `since`, `grep` per file) and the lines are merged by the timestamp they start with (RFC 3339, RFC 5424, `YYYY-MM-DD HH:MM:SS`, `Mon DD HH:MM:SS` in the current year or the one before, the bracketed web form); a line without one keeps its place after the line before it in its file, equal times keep the order of the files. `lines` are `{time?, project, jail, app?, file, line}`, `sources` `{key, project, jail, app?, file, next_offset, rotated?, truncated?, error?}` (a file that could not be read, such as a jail that is not mounted, carries the error and the rest are read), `next` maps `project/jail/file` to the offset to continue from: send it back as `cursor` (JSON, at most 32 KiB). At most 50 files and 2000 lines (the newest); `truncated` when something was left out. Operator; audited once per identity and selection every five minutes (`logs_unified`) |
| `GET /api/v1/logs/forward` | | `LogForward`: `spec.sinks` (`name`, `type` syslog or webhook, `to`, `facility`, `ca_file`, `token_file`, `queue`, `sources`) and `status`: `origin` (`config`: logging.forward of jailopsd.yaml; `api`: a stored list), `generation` (also the ETag; 0 for the file's list), `updated_at`, `sinks` (`name`, `type`, `to`, `sources`, `sent`, `queued`, `dropped`, `skipped_bytes`, `last_success`, `failing_since`, `last_error`, `warning`). Global admin (`log_forward`) |
| `PUT /api/v1/logs/forward` | `LogForwardSpec` | `LogForward`; stores the list, which replaces the file's. `If-Match` is the generation read (0 while the file's list is in force); a stale one is `conflict`. Invalid lists, and a `ca_file` or `token_file` that is not a regular root-owned file writable by nobody else (the token file not readable by others either) are `invalid`. Global admin; audited (`log_forward`) |
| `DELETE /api/v1/logs/forward` | | `LogForward`: the stored list is deleted and the file's is in force again. Global admin; audited (`log_forward`) |
| `POST /api/v1/logs/forward/test` | `LogForwardTest` (`sink`) | `LogForwardTestResult`: `sink`, `ok`, `line` (the tagged line sent), `error`, `millis`; a failed send is `ok: false`, not an error; an unknown sink is `not_found`. Global admin; audited (`log_forward`) |
| `GET /api/v1/jails/<n>/app-draft` | | `AppDraft`: a definition drafted from a running FreeBSD jail, for a person to complete (docs/apps.md, "Write your own app"): `definition` (valid as it is, with `TODO` in the values a jail cannot tell: summary, description, license, notes, a secret-looking rc.conf knob), `todo` (a top-level key of the definition and what is left to do there) and `findings` (what was found and what was left out, one line each). It reads and changes nothing: the packages installed on purpose (`pkg -r <root> query -e "%a = 0" "%n %v %R %w"` on the host, through the helper), `/etc/rc.conf` (services with `<name>_enable` set to yes and their knobs, base services left out), in the jail `sockstat -4 -6 -l -q`, the names of the files below `/usr/local/etc` and `/var/log` newer than pkg's database (`find`), and the owners of the volumes, of the log directories and of `/var/run/<service>` (`stat`), which become `setup` lines. It never reads a configuration file. `busy` while the jail is stopped or an app is being installed into it, `invalid` for a Linux jail. Operator; audited (`app_draft`) |
| `GET /api/v1/jails/<n>/access` | | `AppAccess` of an installed app (docs/apps.md, "Who may connect"): `jail`, `project`, `app`, `type` (`postgresql` for a definition with an access block), `policy` (the managed firewall policy `app-<jail>`), `closed` (the policy denies by default), `ports` (what a grant opens by default), `grants` (`source` in canonical form, `source_kind`, `source_project`, `addresses`, `ports`, `database`, `role`, `role_created`, `database_created`, `rules` as typed text, `pf` the lines of the rendered anchor, `hba` the `pg_hba.conf` lines, `created_at`, `updated_at`, `created_by`, `problems`: drift), `warnings`. Never a password. `invalid` for a jail without the label `jailops.app`. Readonly (`app_access`) |
| `POST /api/v1/jails/<n>/access` | `AppAllow` (`source`: `jail:NAME`, `set:NAME`, an address or prefix, or `host`; `ports` `N[/proto]`; `database`; `rotate`; `dry_run`) | `AppAllowResult` at once, not an operation: `grant`, `changed` (false when it existed as it is), `connection_string` (only when a role was made or rotated: shown once, stored nowhere), `sql` (the password left out), `steps`, `notes`. Writes the managed policy and, for a postgresql app, runs psql as postgres in the jail with the statements on stdin and the `pg_hba.conf` block. `busy` for a stopped jail of a postgresql app, `conflict` for a role or database JailOps did not make or another database for the same source, `not_found` for an unknown source or a project the caller may not use. Operator; audited with the source, ports and database name |
| `POST /api/v1/jails/<n>/access/deny` | `AppDeny` (`source`, `drop_role`, `dry_run`) | `AppDenyResult`: `removed`, `changed`, `sql`, `steps`, `notes`; the role JailOps made loses its login (or is dropped with `drop_role`, its objects reassigned to postgres, the database kept). Operator; audited |
| `GET /api/v1/jails/<n>/updates` | | `[]UpdateRecord`, newest first (`updates`) |
| `POST /api/v1/jails/<n>/provision` | `ProvisionRequest` (`again`) | async, result `ProvisionResult`; `already_exists` when it ran before and `again` is not set (`provisioning`) |
| `POST /api/v1/jails/<n>/shell-setup` | `ShellSetupRequest` (empty) | async, result `ShellSetupResult` (`jail`, `shell`, `prompt`, `ps1`, `steps`): the keys `shell` and `prompt` the jail leaves empty are set from `jails.*` of `jailopsd.yaml`, bash is installed with `pkg -r ROOT` when it is the shell and missing, the prompt file and the blocks are written (docs/shell.md). `busy` for a stopped jail, `invalid` for a Linux jail. Operator (`jail_shell_setup`) |
| `GET /api/v1/config-keys` | | `[]ConfigKey`: the key registry (name, type, values, description, example, `restart_required`, `profile`, `admin`, `path` into the spec); any authenticated identity |
| `GET /api/v1/apps` | | `[]AppSummary`: the application catalog (docs/apps.md), every definition sorted by name, invalid ones with `valid: false` and `error`; `source` is `catalog` (`apps.catalog_dir`) or `local` (`apps.local_dir`), and a local definition that hides a packaged one of the same name carries `overrides: catalog`; any authenticated identity (`apps`) |
| `GET /api/v1/apps/<n>` | | `AppDetail`: the `definition` with defaults filled in, `hash` (`sha256:<hex>` of the file), `file`, `icon` (a data URI), `source` and `overrides` as in the list (the local definition is the one answered when both directories have the name); `invalid` with the reason for an invalid definition, `not_found` for an unknown name (`apps`) |
| `POST /api/v1/apps/<n>/install` | `AppInstall` (`jail`, `network`, `storage`, `image`, `limits`, `dry_run`; optional `project`, which must be the request's) | async, result `AppInstallResult` (`jail`, `version`, `addresses`, `ports` with `endpoint`, `data`, `config`, `logs`, `notes`, `snapshot`, `steps`): one operation that creates a thin jail with the app's data paths as volumes and the labels `jailops.app`, `jailops.app.hash`, `jailops.app.version`, installs the packages from the host, writes rc.conf, runs the setup commands and the services, checks the health and snapshots the result as `app-installed`; operator in the project. A failure after the jail's first start leaves it stopped: the error carries `detail.step`, `detail.jail` and `detail.jail_kept`. `not_found` for an unknown app, `invalid` for an invalid definition or an image older than `release_min`, `already_exists` for a jail of that name (`app_install`) |
| `/api/v1/profiles` and `/<n>` | `Profile` | CRUD; project-level, or host-level with `?project=host` (admin writes) |
| `GET /api/v1/updates` | | `[]UpdateReport`: the latest check of every visible jail |
| `POST /api/v1/updates/check` | `UpdateCheckRequest` (`jails`, `all`) | async, result `[]UpdateReport`; changes nothing but the package catalog in the jail |
| `POST /api/v1/updates/apply` | `UpdateApplyRequest` (`jails`, `all`, `packages`, `os`) | async, result `[]UpdateRecord` |
| `/api/v1/images` and `/<n>` | `Image` | CRUD |
| `/api/v1/images/<n>/generations` GET, POST | `ImageBuild` | list of `ImageGeneration`; POST async, result `ImageGeneration` |
| `DELETE /api/v1/images/<n>/generations/<number>` | | async; `image_in_use` while referenced |
| `POST /api/v1/images/<n>/upgrade` | `ImageUpgrade` (`no_jails`, `project`, `dry_run`, `storage`) | async, result `ImageUpgradeResult`: the next generation built from the newest one (none, `unchanged`, when the package set did not change), then every thin jail of the image moved to it one at a time through the OS update of the update pipeline (history records, `update.applied`/`update.failed` events), stopping at the first jail that fails; `jails` lists each with `upgraded`, `skipped`, `failed`, `not_attempted` or `planned` (dry run). Global admin; `not_found` with a hint when the image has no generation yet (`image_upgrade`) |
| `/api/v1/networks` and `/<n>` | `Network` | CRUD; `GET /api/v1/networks/<n>/leases` returns `[]Lease` |
| `/api/v1/wireguard` and `/<n>` | `WireGuard` | CRUD of the host's WireGuard tunnels (`wireguard`). Reads need the operator role, writes a global admin. `spec` holds public parts only; `status` adds the interface's `public_key`, `up`, per peer `latest_handshake`, `rx_bytes`, `tx_bytes`, `endpoint`, `preshared_key` (whether one is set), the `firewall_rule` of a server and `warnings`. A client cannot be created by POST (`invalid`: use join) |
| `POST /api/v1/wireguard/<n>/peers` | `WireGuardPeerAdd` (`name`, `address`, `keepalive`) | 201 sync `WireGuardPeerCreated` (`peer`, `token`, `config`, `warning`). The `token` (`jwg1.<base64url(JSON)>`) and the `config` hold the peer's private key and the preshared key **once**: never stored, never an operation result, never in the audit detail; `already_exists`, `pool_exhausted`, `invalid` for a client |
| `DELETE /api/v1/wireguard/<n>/peers/<peer>` | | `WireGuard` |
| `POST /api/v1/wireguard/join` | `WireGuardJoin` (`token`, `name`, `interface`, `endpoint`, `address`, `allowed_ips`) | 201 `WireGuard`: a client made from the token; the keys go to the helper; `invalid` for a token that is not one (the reply never repeats it) |
| `POST /api/v1/wireguard/<n>/up`, `/down`, `/rotate-keys` | | `WireGuard`; rotate-keys answers `WireGuardKeys` (`public_key`, `warning`) |
| `/api/v1/firewall/policies`, `/api/v1/firewall/address-sets` and `/<n>` | | CRUD |
| `/api/v1/backup-targets`, `/api/v1/backup-policies` and `/<n>` | | CRUD |
| `/api/v1/backups`, `/<n>` | | GET list/item; DELETE async |
| `POST /api/v1/restores` | `RestoreRequest` | `dry_run`: sync `RestorePreflight`; otherwise async, result `Jail`; a failing preflight is `invalid`. `project` restores into that project (else the backup's); the caller needs access to it (`not_found` otherwise) and its grants and quotas apply |
| `GET /api/v1/backup/key` | | `BackupKeyStatus` (`none`, `present`, `escrowed`); global admin (`backup_key`) |
| `POST /api/v1/backup/key` | `BackupKeyCreate` | 201 sync `BackupKeyCreated`. The `recovery_key` is in this reply **once**: it is never an operation result, never in the audit detail and never logged; the reply is `Cache-Control: no-store`. A second key is `already_exists` |
| `POST /api/v1/backup/key/escrow` | `BackupKeyEscrow` | sync `BackupKeyStatus` |
| `GET /api/v1/host/identity` | | `HostIdentity`: `spec` is what the host has (running host name, `/etc/resolv.conf`, the servers of the jailops block of `/etc/ntp.conf`, `ntpd_enable`; `resolvers` and `ntp` always present), `status` the management state (`managed` = `config_enabled` and `helper_enabled`), `drift` (parts that differ from `applied`), `ntp_sync` when ntpq answered. Works whether the module is enabled or not. Global identity, readonly (`host_identity`) |
| `PUT /api/v1/host/identity` | `HostIdentityApply` | sync `HostChange`: a part left out of `spec` is unchanged. `dry_run` returns the unified `diff` and the `actions` and changes nothing; otherwise `snapshot` names the copy of the touched files taken first. `not_managed` (403) while jailopsd.yaml or priv.conf does not enable `identity`, the hint names the lines; `invalid` for a bad field; `conflict` for an `/etc/ntp.conf` with broken markers. Global admin; audited (detail `dry_run` or `snapshot=<name>`) |
| `GET /api/v1/host/snapshots` | | `[]HostSnapshot`, newest first (`reason` apply, adopt (the first apply of a module, which keeps the administrator's file) or restore; `module` identity or firewall); at most 20 are kept. Global identity, readonly |
| `POST /api/v1/host/snapshots/<name>/restore` | `HostRestore` (optional) | sync `HostChange`: the files of the snapshot back byte for byte (`<name>` or `latest`), the host name it recorded, ntpd restarted or stopped to match (a firewall snapshot: `/etc/pf.conf` loaded with `pfctl -f` and pf on or off as it was); `snapshot` names the copy of what it replaced. The module of the snapshot must be enabled; `busy` while a change waits for its confirmation. `dry_run` as above. `not_managed` as above. Global admin; audited |
| `GET /api/v1/host/firewall` | | `HostFirewall`: `spec` is what was applied last or the default (`template` default, ssh port 22, `icmp`), `status` the management state, `file_managed`, `drift` (`pf.conf`, `pf_enable`, `pf_rules`), `pf_enabled` (omitted when pfctl did not answer), `rules` in plain words, `warnings`, `pending`, `console_port`. Works whether the module is enabled or not. Global identity, readonly (`host_firewall`) |
| `PUT /api/v1/host/firewall` | `HostFirewallApply` | sync `HostChange`: the spec is applied whole (`/etc/pf.conf` rendered by the helper around the three anchor lines, checked with `pfctl -n`, loaded with `pfctl -f`, pf turned on when it was off, `pf_enable` and `pf_rules` set). `dry_run` returns `diff`, `rules`, `actions`, `warnings` and changes nothing. A real change returns `snapshot` and `pending`: it reverts at `pending.deadline` (`confirm_within` seconds, default 120, 10 to 1800) unless confirmed. `forbidden` with detail `guard=lockout` when the caller's address would reach neither ssh nor the console; `invalid` with detail `guard=unknown_peer` without `confirm_lockout` when the address is unknown (unix socket, hub); `busy` with `detail.pending` while another change waits; `not_managed`, `invalid` and `unsupported` (`nat`) as usual. Global admin; audited (detail `dry_run` or `snapshot=<name> pending=<id>`) |
| `GET /api/v1/host/certificate` | | `HostCertificate`: the served certificate (`current`), its `source`, `acme` state, `redirect`, `remote_add`. Global identity, readonly (`host_certificate`) |
| `PUT /api/v1/host/certificate` | `HostCertificateUpload` | sync `HostCertificate`: the chain and key are checked, written 0600 and served from the next handshake on. `invalid` with the reason; `conflict` when `jailopsd.yaml` names the files. Global admin; audited |
| `POST /api/v1/host/certificate/acme` | `ACMESpec` | sync `HostCertificate` with `acme.state` `requesting`; the order runs in the background. `invalid` (terms, names, email, directory), `unsupported` (a wildcard). Global admin; audited |
| `POST /api/v1/host/certificate/self-signed` | | sync `HostCertificate`. Global admin; audited |
| `GET /api/v1/setup` | | `SetupStatus` while no administrator exists, `not_found` after. Public (`setup`) |
| `POST /api/v1/setup` | `SetupRequest` | 201 `SetupResult`: the first global administrator, the token used up. `unauthorized` for any bad token, counted per source (`rate_limited`); `not_found` once an administrator exists. Public |
| `POST /api/v1/setup/token` | | `SetupToken`, the token shown once; replaces the one before. Admin, global (root on the socket); `not_found` once an administrator exists |
| `GET /api/v1/host/pending` | | `HostPending`: `pending` (the change that waits, with `seconds_left`) and `last` (`outcome` confirmed, reverted, timed_out, reverted_at_boot or revert_failed, with `detail`). Global identity, readonly (`host_pending`) |
| `POST /api/v1/host/pending/confirm` | `HostPendingAction` (optional) | sync `HostPending`: the change stays and its timer stops. `id`, when given, must name the pending change (`conflict` otherwise); `not_found` when nothing waits (the message says how the last one ended). Global admin; audited (detail `pending=<id> confirmed`) |
| `POST /api/v1/host/pending/revert` | `HostPendingAction` (optional) | sync `HostPending`: the snapshot of the pending change goes back now and is loaded. As above. Global admin; audited |
| `POST /api/v1/backups/run` | `BackupRunRequest` (`policy`) | async, result `[]BackupRun`; global admin (`backup_run`) |
| `POST /api/v1/backups/<id>/verify` | `BackupVerifyRequest` (`depth` deep, extract, full) | async, result `BackupRun` (`backup_verify`) |
| `GET /api/v1/operations`, `/<id>`, `DELETE /<id>` | | `[]Operation`, `Operation`; DELETE cancels |
| `GET /api/v1/operations/<id>/wait?timeout=<s>` | | sync `Operation`, returned when final or after the timeout (the client re-polls) |
| `GET /api/v1/events?type=a,b` | | `text/event-stream` |
| `/api/v1/remotes`, `/api/v1/certificates` and `/<n>` | | CRUD; `/api/v1/certificates/<fingerprint-or-name>`; revocation (`DELETE`) and edits (`PUT`, `PATCH`) take effect on the next request |
| `/api/v1/tokens` | `Token` | `POST` returns the `Token` with `secret` set, once; never again |
| `/api/v1/users` | `UserCreate` | `POST` returns `UserCreated`; `password` only when generated |
| `/api/v1/users/{name}/password` | `PasswordSet` | `POST` (global admin): replaces the password without the old one and ends the user's sessions; an empty `password` asks for a generated one, returned once in the same type |
| `/api/v1/projects` and `/<n>` | `Project` | CRUD; see Projects |
| `GET /api/v1/projects/<n>?host=all` | | hub only: `ProjectAggregate` |
| `/api/v1/storage` and `/<n>` | `Storage` | CRUD; see Storage |
| `POST /api/v1/trust/tokens` | `TrustTokenRequest` | `TrustToken`, once (201); global admin |
| `POST /api/v1/trust/clients` | `TrustClientRequest` | `Certificate` (201); unauthenticated, authorised by the token only |
| `GET /api/v1/sessions`, `DELETE /api/v1/sessions/<id>` | | `[]Session`; DELETE revokes |

| `GET /api/v1/audit` | | `[]AuditEntry`, newest first; admin (`audit_log`) |
| `GET /api/v1/doctor` | | `DoctorReport`: checks with `ok`, `info` (a fact that is not a fault; counts as ok), `warn`, `fail` or `unknown` (`doctor`) |
| `GET /api/v1/resources` | | host resources and usage (`resources`) |
| `POST /api/v1/jails/<n>` | copy request | async, result `Jail` (`jail_copy`) |

### Console

The browser console cannot open an HTTP upgrade, so it uses a session (extension `jail_console`), with the same
project rules, per-jail limits and audit entries as exec:

- `POST /api/v1/jails/<n>/console` starts a command with a terminal and returns a session `id`; a session belongs to the
  identity that opened it (at most 8 per identity, 64 in total).
- `GET /api/v1/jails/<n>/console/<id>/output` streams what the command prints as server-sent events and honours
  `Last-Event-ID` (the last 1 MiB is kept for a client that reconnects).
- `POST .../input` (at most 64 KiB per request) and `POST .../resize` feed it; `DELETE .../console/<id>` closes it.

The Go SDK wraps the session as `Jails().Console(ctx, name, ExecOptions)` (a `ConsoleSession` with `Output`, `Write`,
`Resize`, `Wait`, `Close` and `Run`), and `jailops jail console NAME` uses it with a raw local terminal and resize
forwarding. Input is UTF-8 text; use exec (`jailops shell`) for binary input. Verified against the fake and the
in-process daemon only; a run on a real FreeBSD host is UNVERIFIED.

### Routes that exist and answer `unsupported`

These routes have a permission entry but their feature is not in this version, so they answer `unsupported` (501),
never success: `PUT /api/v1/server` and `GET /api/v1/server/config`; `/api/v1/cluster` and its sub-routes (cluster mode);
`GET /api/v1/jails/<n>/console` (list), `.../files/<path>`, `POST .../move`, `.../volumes`, `.../bundle`;
`POST .../snapshots/<s>` (rename); `/api/v1/jail-templates`; `/api/v1/groups`; `/api/v1/rollouts` (rollouts are a
`jailops-sync` feature); `POST /api/v1/backups`, `POST /api/v1/backups/<id>/restore` and `.../restore-preflight` (use
`POST /api/v1/restores`); and the backup transport routes `POST /api/v1/backups/receive`, `GET /api/v1/backups/<id>/stream`,
`GET /api/v1/backups/chains`, which are the job of the backup node.

## Exec

`POST /api/v1/jails/<n>/exec` takes an `ExecRequest` JSON body (`argv`, or `shell` and `shell_path` for the
jail's shell, `tty`, `rows`, `cols`, `env` as `NAME=value`, `user`) and the headers `Connection: Upgrade`
and `Upgrade: jailops-exec/1`. Errors that are known before the stream starts (`not_found`, `busy` for a
jail that does not run or has too many sessions, `invalid`, `forbidden`) are an ordinary JSON error. On
success the reply is `101 Switching Protocols` and the connection carries frames, both ways:

    +------+----------------+---------+
    | type | length (u32 BE) | payload |
    +------+----------------+---------+

The payload is at most 65536 bytes (a longer frame ends the session). Types: 1 `stdin` (an empty
frame is end of input), 2 `stdout`, 3 `stderr` (absent in TTY mode, where stderr is merged into
stdout), 4 `resize` (rows and cols, two u16 BE), 5 `signal` (an i32 BE signal number), 6 `exit` (an i32
BE exit status, the last frame). A session that is idle too long or runs too long is ended with exit
status -1. Closing the connection kills the command. HTTP/1.1 only: the client does not offer h2 on this
request. The same authentication, project and audit rules as every route apply, and the audit entry
carries the argv of the command; through a hub the upgrade is forwarded like any request.

## Projects

A project is a namespace. Project-level objects are jails (and their snapshots and volumes), firewall
policies, address sets and backup policies. Host-level objects are networks, storage, images, projects,
users, certificates, tokens, remotes and the server configuration.

- `?project=<name>` selects the project on every project-level route. There is no default project: a fresh host has
  none, and a project-level request without `?project=` is `400 invalid` (`a project is required`, with the hint
  `name one with --project NAME`). The server sets `metadata.project` of every project-level object; a body that
  names another project is rejected as `invalid`. Host-level kinds (images, networks, storage, projects,
  certificates, users, tokens, trust, server info, doctor, audit, operations, events, backup targets and keys) and
  host profiles (`?project=host`) never need one.
- Names are unique per kind and project; UUIDs are global. A jail's OS-level name and its datasets are
  qualified by the project, so `web/nginx` and `db/nginx` never collide.
- Lists (`GET /api/v1/jails`, policies, address sets, backup policies) return the objects of one project.
  `GET /api/v1/events`, `/api/v1/operations`, `/api/v1/audit` and `/api/v1/backups` return everything the caller may
  see, narrowed by `?project=` when given. Events, operations and audit entries of host-level objects
  (`metadata.project` empty) are visible to global identities only.
- An object of a project the caller may not use is `not_found`, never `forbidden`, on every verb:
  `GET`, `POST` (create), `PUT`, `PATCH`, `DELETE`, state changes, snapshots, and `GET /api/v1/operations/<id>`.
  The same is true of a project that does not exist. A role that is too low is checked first and is
  `forbidden`.
- Project grants. `spec.networks` lists the networks a jail may attach to (`"*"` is every network). A network
  is granted whole and to at most one project: granting one that another project holds is `conflict`
  (`network N is already granted to project P`), and there are no sub-ranges. `spec.storage` lists the storage a
  jail may be placed on with a quota for the project's dataset (`"*"` is every storage); storage may be granted to
  many projects, each getting its own `projects/<project>/` subtree. A jail naming a network or storage that is
  not granted fails with `forbidden`. Nothing is filled in: a jail whose own spec and profiles name no network
  is `invalid` (`a jail needs a network: name one with --network NAME or use a profile that has one`), and the
  same for storage.
- Quotas (`spec.quotas`) are checked before anything is created and fail with `quota_exceeded`:
  `jails`, `cpu`, `memory`, `pids` and `addresses` are sums over the project's jails. A project with a
  `cpu`, `memory` or `pids` quota requires every jail to set the matching `resources` limit (`invalid`
  otherwise). The per-storage `quota` is applied as a ZFS quota on the project dataset.
- `spec.firewall_policies` lists the policies of the project that are rendered, in this order, before every jail's own
  policies (`spec.firewall.policies` of the jail, also a list) in the jail's anchor `jailops/<project>/<jail>`; only a
  global admin may edit or delete one of them or change the field. A jail's list may not name one of them, nor a
  managed policy, and names none twice. `spec.images`, when not empty, restricts the images a jail may use.
- `POST /api/v1/projects` with `spec.new_network: true` creates a dedicated network with a subnet from the
  server's pool of subnets, grants it to the project and stores the project with the flag cleared
  (`unsupported` when the server has no pool configured).
- A project is deleted only when it holds no jails, policies, address sets or backup policies
  (`busy` otherwise). Only global admins create, change or delete projects;
  a restricted identity lists and reads only its own projects.
- Fleet projects. `spec.hosts` lists the hosts a project spans (remote names or UUIDs on a hub). The hub
  applies the definition to each listed host through the SDK client (same UUID, `managed_by:
  hub:<hub uuid>`), after checking that the host has every named network and storage; a missing one is a
  condition `Host:<host>` with status `False` and reason `MissingNetwork` or `MissingStorage` on the
  hub's project status, and nothing is applied to that host. Hosts that cannot be reached
  (`reason: Offline`) are retried every 30 s and catch up when they return. A host project that exists but
  is not managed by this hub is `reason: Conflict` and is never changed. Each host stores and enforces its
  own copy; there is no consensus and no fleet-wide quota. The hub's certificate on each host must be of
  kind `hub` with the rights the definition needs (`global: true` to write projects).
- `GET /api/v1/projects/<n>?host=all` on a hub returns `ProjectAggregate`: the definition, one
  `ProjectHostStatus` per listed host (`online`, `applied`, `in_sync`, the host's `status`, or an `error`)
  and the sum of the usage of the hosts that answered. The hub reads each host with the caller's signed
  requestor claim, so every host applies its own scoping. A request with `host=all` to any other route is
  `invalid`.

## Storage

A storage names a ZFS dataset root (`spec.dataset`, for example `tank/jailops`) on an imported pool.
Datasets live below it: `<root>/projects/<project>/jails/<name>` and `<root>/images/<image>/g<N>`.
Creating a storage requires the dataset to exist; the server registers it with the root helper and adopts
it (only an empty dataset or one already owned by JailOps is accepted). `status` is read from ZFS: `pool`,
`health`, `size`, `used`, `available`. A storage cannot be deleted while a project grants it or a jail
uses it; deleting it never destroys data. The host creates a storage `default` (dataset `<pool>/jailops`)
at its first start. Image generations are built or received per pool: a jail's root is cloned from a
generation on its own pool, so the first jail of an image on a pool builds or receives that generation
there; `ImageGeneration.storages` lists the storage that hold a copy. Only global identities write
networks, storage and images; project users read the ones granted to their projects.

The extensions `projects`, `project_quotas`, `storage`, `trust_tokens`, `sessions` and `fleet_projects` name
this part of the contract. Only `<root>/projects/<project>/jails/<name>` exists on disk.

## Identity and authorization

Every identity (user, token, certificate) has a role and a scope: `projects` (a non-empty list) or
`global: true`. An empty list never means all projects; an identity with neither can do nothing except
call the `/api/v1/auth/*` self-service routes and the public routes. Creating an identity with neither is
`invalid`. Authorization has two checks, both in the service layer: the role from the permission table
(`forbidden`) and then the object's project (`not_found`). Host-level writes need a global admin
(`forbidden` otherwise). Unix socket: the peer uid 0 (root) is a global admin (kind `unix`, the host's recovery
access); every other local peer is anonymous, exactly like an unauthenticated remote client, and reaches only the public
routes (`GET /api/v1`, `GET /healthz`, `GET /readyz`, `POST /api/v1/auth/login`, `POST /api/v1/trust/clients`, `POST /api/v1/cluster/join`, the static
console) until it authenticates with a token or a session cookie. No Unix user or group maps to a role.

- `GET /api/v1/auth/session` returns `Identity` (`user`, `kind`, `permission`, `projects`, `global`).
- Trust workflow. `POST /api/v1/trust/tokens` (`TrustTokenRequest`) returns `TrustToken` once. The token
  is `joc_<base64url JSON>.<base64url HMAC-SHA256>`; the JSON holds `v` (1), `id`, `name`, `fp` (the
  server certificate fingerprint, hex SHA-256), `exp` (unix seconds) and `sec` (random). The client pins
  `fp`, generates a key pair and sends `POST /api/v1/trust/clients` with the token and its PEM certificate.
  The server verifies the HMAC, the expiry and its own fingerprint, consumes the token atomically (a second
  use, an expired token and a forged token are all `unauthorized`), and stores the certificate
  fingerprint as a certificate named after the token with the requested role, scope and optional expiry.
  Failed attempts are rate limited per source (`rate_limited`, 429) and audited.
- Hub forwarding. A hub authorises the caller, then forwards the request over pinned mTLS with the header
  `X-JailOps-Requestor: <base64url payload>.<base64url signature>`. The payload is JSON: `v` (1), `name`,
  `kind`, `role`, `projects`, `global`, `iat`, `exp` (at most 60 s after `iat`), `aud` (the host UUID, when
  the hub knows it), `method` and `path` of the request. The signature is ASN.1 ECDSA over
  SHA-256(`jailops-requestor-v1\n` + payload) with the hub certificate key. The host accepts the header
  only on a TLS connection whose client certificate is a pinned certificate of kind `hub`, verifies the
  signature with that certificate's public key, and limits the claim by the certificate entry: the role
  cannot exceed its permission and the claimed scope must lie inside its `projects` (or it needs `global`).
  The header is rejected (`forbidden`) on the unix socket, with a token, with a session and with a
  non-hub certificate. Without a claim a hub certificate acts with the rights of its own entry only.
- `GET /api/v1/sessions` lists the caller's sessions (a global admin sees all; a global identity with a lower role
  only its own); `DELETE /api/v1/sessions/<id>` revokes one (own sessions, or any for a global admin). Revocation ends
  the session on its next request, and its event streams, console outputs and exec sessions at the next keepalive.
- `POST /api/v1/auth/totp` starts an enrolment with `{"password": ...}` and confirms it with `{"code": ...}`;
  `POST /api/v1/auth/recovery-codes` takes `{"password": ...}`. A missing or wrong password is `unauthorized`.
- Failed authentication (bad token, unknown or revoked certificate on a non-public route, bad trust token)
  is rate limited per source and audited as `denied`.

## Events

`GET /api/v1/events` answers `200 text/event-stream`. Each event:

```
id: <monotonic integer>
event: <lifecycle|operation|logging>
data: <api.Event as one line of JSON>

```

`?type=` filters. The credential travels in the `Authorization` header (a token in the query string is not
accepted). One identity holds at most 16 streams (`rate_limited`, 429, beyond); a stream ends when its credential
is deleted, disabled or changed. A client that reconnects sends `Last-Event-ID`; the server replays retained events
with a larger id, then continues live. Without it the stream starts at "now". A `retry:` field sets
the reconnect delay. Lines beginning with `:` are comments (keep-alives). Lifecycle metadata is
`api.LifecycleEvent` with actions like `jail-created`, `jail-started`, `network-updated`, and `app.installed` or
`app.install.failed` (source `/api/v1/jails/<jail>`) at the end of an app installation.

## Auth failures and TLS

401 `unauthorized` for a missing or bad credential, 403 `forbidden` for a valid credential without the
permission. Hosts are pinned by the SHA-256 of the leaf certificate (hex, `sdk.Fingerprint`).

## Optional extensions used by the CLI

These routes are not part of the base contract. A client calls them only when `api_extensions`
lists the name, and otherwise reports `unsupported`.

| Extension | Method and path | Reply |
|---|---|---|
| `backup_key` | `GET`/`POST /api/v1/backup/key`, `POST /api/v1/backup/key/escrow` | see Routes; advertised when the daemon has a `backup:` configuration |
| `backup_run` | `POST /api/v1/backups/run` | async, result `[]BackupRun` |
| `backup_verify` | `POST /api/v1/backups/<n>/verify` | async, result `BackupRun` |
| `config_keys`, `jail_config`, `profiles`, `jail_devices` | config registry, config operation, profiles, devices (`nic` names, MTU and rate limits, `devfs`, `proxy`) | see Routes |
| `jail_exec` | `POST /api/v1/jails/<n>/exec` | see Exec |
| `updates` | `/api/v1/updates`, `/api/v1/jails/<n>/updates` | managed updates (design 8.4); off for every jail until `updates.mode` is set |
| `jail_shell` | the `shell` key | the shell `jailops shell` starts; no fallback when it is missing |
| `provisioning` | `POST /api/v1/jails/<n>/provision` | design 8.5 |
| `jail_console` | `POST /api/v1/jails/<n>/console` and the session routes | see Console |
| `sealed_secrets` | `secrets_recipient` in `ServerInfo` | the age public key of the host; a jail `env` value `sealed:age:<base64>` is opened by the daemon only when it starts a process in the jail (design 18.8) |
| `audit_log`, `doctor`, `resources` | `GET /api/v1/audit`, `/api/v1/doctor`, `/api/v1/resources` | see Routes |
| `jail_copy` | `POST /api/v1/jails/<n>` | copy |
| `rename` | `POST /api/v1/<kind>/<n>/rename` | renames with every reference; `jailops <kind> rename OLD NEW`, `jailops rename` for a jail; see Routes and docs/design.md 8.8 |
| `image_upgrade` | `POST /api/v1/images/<n>/upgrade` | build the next generation and move the jails that use the image; see Routes |
| `jail_usage` | `GET /api/v1/jails/<n>/usage` | what a jail uses now; `jailops jail info` reads it; see Routes |
| `jail_logs` | `GET /api/v1/jails/<n>/logs`, `GET .../logs/<file>` | the log files of a jail root and the end of one; `jailops jail logs` reads them; see Routes |
| `firewall_test` | `POST /api/v1/firewall/test` | whether a connection would pass the firewall and which rule decides; `jailops firewall test`; see Routes and docs/networking-ipv6.md |
| `boot_plan` | `GET /api/v1/boot` | what a boot of the host starts and in which order; `jailops boot` reads it; see Routes and docs/operations.md |
| `logs_unified` | `GET /api/v1/logs` | the logs of many jails merged by time; `jailops logs` reads them; see Routes and docs/logging.md |
| `log_forward` | `/api/v1/logs/forward`, `POST .../forward/test` | log forwarding to syslog and webhooks; `jailops logs forward`; see Routes and docs/logging.md |
| `apps` | `GET /api/v1/apps`, `/api/v1/apps/<n>` | the application catalog: local definition files the daemon reads and never fetches; see Routes and docs/apps.md |
| `app_install` | `POST /api/v1/apps/<n>/install` | installing an app of the catalog as a jail, one operation; events `app.installed` and `app.install.failed`; see Routes and docs/apps.md |
| `host_identity` | `GET`/`PUT /api/v1/host/identity`, `GET /api/v1/host/snapshots`, `POST .../snapshots/<n>/restore` | host management, module identity (docs/appliance.md); `jailops host show`, `host identity set`, `host snapshots`, `host restore`; advertised when the daemon runs with the helper; changes need the module enabled on both sides |
| `host_firewall` | `GET`/`PUT /api/v1/host/firewall` | host management, module firewall (docs/appliance.md): `/etc/pf.conf` rendered whole by the helper; `jailops host firewall show|set|apply|diff`; changes need the module enabled on both sides and go through commit confirmed |
| `setup` | `GET`/`POST /api/v1/setup`, `POST /api/v1/setup/token` | the first administrator with a one-time setup token (docs/appliance.md) |
| `host_certificate` | `GET`/`PUT /api/v1/host/certificate`, `POST .../acme`, `POST .../self-signed` | the console's certificate: upload and ACME (docs/exposure.md) |
| `jail_shell_setup` | `POST /api/v1/jails/<n>/shell-setup` | bash and the prompt of a FreeBSD jail, as a new jail gets them; `jailops jail shell-setup`; the `prompt` key (docs/shell.md) |
| `host_pending` | `GET /api/v1/host/pending`, `POST .../pending/confirm`, `POST .../pending/revert` | commit confirmed: the change that reverts unless confirmed; `jailops host pending|confirm|revert`; the timer is the helper's |
| `app_draft` | `GET /api/v1/jails/<n>/app-draft` | a definition drafted from a running jail; `jailops app export` reads it; see Routes and docs/apps.md |
| `app_access` | `GET`, `POST /api/v1/jails/<n>/access`, `POST .../access/deny` | who may connect to an installed app; `jailops app allow`, `deny` and `access`; see Routes and docs/apps.md |
| `volumes` | `/api/v1/volumes` and below, `/api/v1/jails/<n>/volumes` | volumes of a project, attached to jails by name; encrypted volumes; `jailops volume ...`; see Routes and docs/storage.md |
| `backup_pull`, `backup_push` | the backup transport permissions of the backup node | not routes of the host daemon (see above) |

Update and provisioning keys of the registry: `shell` (`bash`, `sh` or a path), `prompt` (`default`, `none` or a PS1 text
that passes `api.CheckPrompt`), `updates.mode` (manual, notify, managed),
`updates.schedule` (cron), `updates.packages`, `updates.os`, `updates.reboot` (manual, auto).
