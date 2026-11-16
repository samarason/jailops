# Configuration

Four files. Each rejects keys it does not know, so a typo is an error, not a silent default. The annotated samples under
`packaging/` list every key, and a test keeps `packaging/jailopsd.yaml` equal to what the daemon accepts.

| File | Read by | Owner and mode |
|---|---|---|
| `/usr/local/etc/jailops/jailopsd.yaml` | the daemon `jailopsd` | written by `jailops-setup`, mode 0640, group `jailops` |
| `/usr/local/etc/jailops/priv.conf` | the root helper `jailops-priv` | root, 0600 or 0644; **the helper refuses a file others can write** |
| `/usr/local/etc/jailops/backupd.yaml` | the backup node `jailops-backupd` | see [backup-restore.md](backup-restore.md) |
| `~/.config/jailops/config.yaml`, `/usr/local/etc/jailops/client.yaml` | the `jailops` client | the user; keep it private, it can hold tokens |

And a few variables of `/etc/rc.conf`, read by the rc scripts (below).

## jailopsd.yaml

Only `pool` has no default. Sample: `packaging/jailopsd.yaml`.

| Key | Default | Meaning |
|---|---|---|
| `role` | `host` | the only role of this daemon; the backup node is a separate program |
| `hub` | `false` | keep a registry of remote hosts and forward `?host=` requests to them over pinned mTLS |
| `pool` | none | the ZFS pool |
| `dataset` | `<pool>/jailops` | the storage root dataset |
| `mount_base` | `/usr/local/jailops` | where the root is mounted |
| `state_dir` | `<data_dir>/state` | the host's configuration objects. **Outside the storage root**, because the root is root-owned and the daemon cannot write there |
| `data_dir` | `/var/db/jailops` | SQLite database, seal key, `secrets.key` (the age identity for sealed secrets), TLS material, operation journal |
| `conf_dir` | `/usr/local/etc/jailops/jails` | rendered `jail.conf` files; must equal `conf-dir` of `priv.conf` |
| `work_dir` | `/var/tmp/jailops` | scratch |
| `listen.unix.path`, `.mode` | `/var/run/jailops/jailops.sock`, `0666` | the local socket. Only root (uid 0) is recognised there, as a global admin; every other local user is anonymous like an unauthenticated remote client, so the mode confers nothing. An empty path disables it. The former keys `admin_group`, `user_group` and `user_projects` are removed: a configuration that still sets one stops the daemon with a message |
| `listen.https.address` | empty | `":39110"` or `"127.0.0.1:39110"` enables the network listener: **TLS 1.3 only**, there is no plain-http TCP listener (mTLS pinning, API tokens, the web console). Checked at load |
| `listen.https.names` | none | extra DNS names and IPs of the generated certificate |
| `listen.https.cert`, `.key` | generated | your own certificate and key, absolute paths, **both or neither**; both must exist (the daemon never generates over a configured path); a renewed pair is picked up without a restart (checked at most every 15 s, a broken one is ignored and logged). Default `<data_dir>/tls/server.{crt,key}`, generated self-signed on first start |
| `listen.https.acme.enabled`, `.email`, `.domains`, `.directory_url`, `.challenge`, `.accept_tos` | off; `https://acme-v02.api.letsencrypt.org/directory`; `http-01` | a certificate from a public CA with ACME ([exposure.md](exposure.md#acme-a-certificate-from-a-public-ca)): DNS names (1 to 20, no addresses, no wildcards), an optional contact address, the CA's directory (https; the staging one is `https://acme-staging-v02.api.letsencrypt.org/directory`), `http-01` or `tls-alpn-01`, and `accept_tos: true`, which is required. Needs the TLS listener; excludes `cert`/`key`. Checked at load. A choice made in the console replaces it |
| `listen.https.acme.challenge_address` | `":39080"` | the plain-http listener of http-01 challenges (it answers nothing else); port 1024 or more, on all addresses or a loopback address, because the host redirects port 80 to it on `127.0.0.1` and `::1` |
| `web.enabled` | `false` | `true` serves the embedded web console on the listeners (the API is unchanged); it is always in the binary. The same switch without editing the file: `jailopsd_web="YES"` in `/etc/rc.conf`, or the `-web` flag, which also opens the TLS listener on 39110 when none is configured (`"NO"` and `-no-web` force it off). `go build -tags noweb` leaves the console out of the binary. See [exposure.md](exposure.md) |
| `priv.socket` | `/var/run/jailops-priv/priv.sock` | where the helper listens (the former `/var/run/jailops/priv.sock` means this path) |
| `log.level`, `log.format` | `info`, `text` | `debug`, `info`, `warn`, `error`; `text` (key=value lines for syslog) or `json` |
| `reconcile.interval`, `.autostart` | `60s`, `true` | the loop that makes the live host equal the desired state; start jails with `boot.autostart` on the first pass |
| `zfs.compat_file`, `.compat_dir` | empty | an OpenZFS compatibility file name (for example `openzfs-2.2-freebsd`) to compare pool features with an older replication target; empty skips the check |
| `limits.max_body_bytes`, `.request_timeout` | `4194304`, `60s` | request bounds |
| `limits.auth_failure_threshold` | `5` | failed authentications from one source before it is locked out |
| `limits.exec_sessions_per_jail`, `.exec_idle`, `.exec_max` | `8`, `30m`, `12h` | exec and console session bounds |
| `projects.network_pool`, `.network_bits`, `.uplink`, `.nat` | none | the IPv4 pool `project create NAME --new-network` carves a `/24` from; without it that option answers `unsupported` |
| `updates.tick`, `.project_files_dir` | `1m`, `<state_dir>/project-files` | how often update schedules run; where provisioning files live, one directory per project |
| `jails.shell`, `.prompt`, `.prompt_color` | `bash`, `default`, `39` | what a new FreeBSD jail gets when its request and profiles leave the `shell` and `prompt` keys empty ([shell.md](shell.md)): `bash` (installed at the first start) or `sh`; the bash prompt (`default`, `short`, `none` or a PS1 text that may hold `{jail}`, `{project}` and `{host}`, checked at load like the key); the 256-colour number of `user@jail` in the default and short prompts (1 to 255). Existing jails are not changed; `jailops jail shell-setup` applies them to one |
| `jails.max_states` | `10000` | the pf states each pass rule of a jail may create when the jail's `limits.states` is 0; `0` sets no limit ([operations.md](operations.md#resource-limits-of-a-jail)) |
| `host.manage.modules` | `[]` | host management ([appliance.md](appliance.md)): the modules JailOps may change on the host itself. Empty, JailOps never changes the host and the host routes only read. `identity` is the host name, `/etc/resolv.conf`, the jailops block of `/etc/ntp.conf` and `ntpd_enable`; `firewall` is the whole of `/etc/pf.conf` with `pf_enable` and `pf_rules`, every change of it reverting unless confirmed (the console rule opens the port of `listen.https.address`). The helper must allow the same module (`host-manage` in `priv.conf`): with only one of the two, changes answer `not_managed`. Unknown modules and duplicates are an error at load. `jailops_appliance="YES"` in `rc.conf` adds its modules to this list (and to the helper's) |
| `apps.catalog_dir` | `/usr/local/share/jailops/apps` | the application catalog ([apps.md](apps.md)): one YAML definition per file, installed by the `jailops-apps` package. Read on each request, never fetched; a missing directory is an empty catalog |
| `apps.local_dir` | `/usr/local/etc/jailops/apps` | the host's own app definitions ([apps.md](apps.md), "Write your own app"): `NAME.yaml` and its icon, read with the catalog on each request; a definition here wins over a packaged one of the same name and is listed with `source: local`. A missing directory is empty; it must be readable by the user `jailops` |
| `lifecycle.persistent` | the built-in list | the paths of a thin jail that survive a generation switch, each in its own dataset (`dataset`, `path`, `class` system or data, `merge`, `no_seed`). The default is `/etc`, `/usr/local`, `/var/db`, `/var/log`, `/var/mail`, `/var/spool`, `/home`, `/root`. **Setting it replaces the list** |
| `logging.forward` | `[]` | log forwarding ([logging.md](logging.md)): the sinks (`name`, `type` syslog or webhook, `to`, `facility`, `ca_file`, `token_file`, `queue`, `sources`) the daemon sends the jails' logs and, when asked, its audit log to. In force until an administrator stores a list with `jailops logs forward` or the console, which replaces it until `jailops logs forward reset`. Checked at load; `ca_file` and `token_file` must be owned by root (the token file 0640 `root:jailops` or 0600) and are opened without following a symbolic link. These sinks may name any file and any receiver, the loopback address included |
| `logging.secrets_dir` | `/usr/local/etc/jailops/sinks` | the only directory the `ca_file` and `token_file` of a sink set through the API (`jailops logs forward`, the console) may lie in, as plain files directly in it; owned by root, mode 0750, group `jailops`, no symbolic link in its path. Sinks set through the API also may not send to loopback, link-local, unspecified, multicast or broadcast addresses, or to the daemon's own ports on an address of the host ([logging.md](logging.md#configure)) |
| `devd.enable`, `devd.pipe` | on for FreeBSD, `/var/run/devd.seqpacket.pipe` | read the kernel's notifications from devd(8) and publish ZFS errors, link changes of the uplink, and limits a jail hit as events ([operations.md](operations.md#events-from-the-kernel)); `pipe` is a clean absolute path |
| `audit.retention`, `audit.max_entries` | `90d`, `1000000` | how long the audit log keeps an entry (at least `1d`; whole days as `90d` or hours as `2160h`) and how many it keeps (at least 1000). Once a day the daemon deletes what is older or beyond; the newest 1000 entries are never deleted ([security-model.md](security-model.md#the-audit-log)) |
| `backup.*` | absent | host-side backups; absent, every backup call answers `unsupported`. See [backup-restore.md](backup-restore.md) |

The proxy for switched IPv6 has no switch in this file: it runs for every network in `proxy` mode, and what it may do is
decided in `priv.conf` ([networking-ipv6.md](networking-ipv6.md)).

## priv.conf

One `key = value` per line; the keys are the helper's command-line flags without the dash, and lists may be repeated or
comma separated. Check it with `service jailops_priv checkconfig` (or `service jailops_priv checkconfig`); reread the storage
file with `service jailops_priv reload`. Sample: `packaging/priv.conf.sample`.

This file is the **operator's authority**: everything the root helper will do for the daemon is bounded by it. See
[security-model.md](security-model.md).

| Key | Meaning |
|---|---|
| `storage-root` | a ZFS dataset that exists, is on an imported pool and carries `jailops:managed=on`. Everything the helper does with ZFS, mounts and files stays below one. Repeatable; more are registered at run time (admin only) in `storage-file` (`/usr/local/etc/jailops/priv.d/storage.conf`) and reread on SIGHUP |
| `allow-pool-root` | `false`; a pool's top dataset as a root is refused unless you say so |
| `allow-start-without-pf` | `false`; a jail with a network link does not start while pf is disabled unless you say so |
| `conf-dir`, `state-dir`, `work-dir`, `mount-base`, `helper-path` | directories; `state-dir` has no default unless `mount-base` is set |
| `socket`, `group`, `mode`, `allow-user`, `allow-group` | who may talk to the helper: the unix socket, its group and mode (`0660`), and the users and groups it accepts by peer credentials |
| `wireguard-dir` | `/var/db/jailops-priv/wireguard`; the keys of WireGuard tunnels, one directory per tunnel (root, 0700, created when needed). It must lie outside `state-dir`, `conf-dir`, `work-dir` and `mount-base` ([wireguard.md](wireguard.md)) |
| `sysctl` | extra sysctls readable through the helper (the built-in list covers `kern.osrelease`, forwarding, `hw.ncpu` and a few more) |
| `admin-raw-param`, `admin-allow-flag`, `admin-devfs-ruleset`, `admin-host-mount`, `admin-zfs-prop`, `admin-routes`, `admin-raw-pf`, `admin-resume-send`, `admin-zfs-delegation` | what a global admin may unlock; empty or off by default. **An admin who may set these is root on the host**: keep the lists short |
| `wireguard-routes` | empty; networks a WireGuard tunnel may route into itself although a route there is wider than a /8 (/16 for IPv6) or covers the host's addresses, default gateway, resolvers, loopback, link-local or multicast (one per line or comma separated; [wireguard.md](wireguard.md)) |
| `fetch-host` | the hosts the download rule, the package repositories of image builds and the `debootstrap` mirrors may use, over https (default `dl-cdn.alpinelinux.org`, `pkg.freebsd.org`, `pkg.jailops.net`, `deb.debian.org`, `archive.ubuntu.com`, `ports.ubuntu.com`); an entry written `http://<host>` also allows plain http for a package repository on that host |
| `pkg-keys-dir` | `/usr/local/etc/jailops/keys`; the key directories a package repository of an image build may use besides `/usr/share/keys`. Root-owned, not writable by others, no symbolic links, outside the daemon's directories: the helper checks it every time ([security-model.md](security-model.md#whom-the-helper-trusts-when-it-runs-package-tools)) |
| `keyring-dir` | `/usr/local/share/keyrings`; the keyrings `debootstrap` may check a release with (the same rules) |
| `unbound-conf` | `/var/unbound/conf.d/jailops.conf`, the conf.d of the base system's local-unbound, used when `local_unbound` is enabled and that directory is root's; the one file the helper writes the names of the running jails into, `NAME.PROJECT.internal`. Empty turns it off, a path points it at another file ([dns.md](dns.md)) |
| `dns-suffix` | `internal`; the zone of the names of the jails, `NAME.PROJECT.<suffix>`: DNS labels, not `local`. A suffix you own (`corp.example`) is the clean choice ([dns.md](dns.md)) |
| `image-mirror` | directories `fs.read_file` may read besides the storage roots (a local mirror of image archives) |
| `host-manage` | empty; the host management modules the helper may change (`identity`, `firewall`; one per line or comma separated). Empty, the host operations only read. The operator's own switch: `host.manage.modules` of `jailopsd.yaml` cannot enable anything the helper does not ([appliance.md](appliance.md)). `jailops_appliance="YES"` in `rc.conf` adds its modules when the helper starts (`check-config` prints both lists); `appliance-modules` is not a key of this file |
| `host-dir` | `/var/db/jailops-priv/host`; where the helper keeps the snapshots of host files (the last 20), the record of what it applied, and the record of a change that waits for its confirmation (`pending.json`, read again when the helper starts and by the boot script `jailops_revert`). Created root-owned with mode 0700 and refused otherwise: the daemon can neither read nor change it |

## rc.conf

The rc scripts read these from `/etc/rc.conf` (set them with `sysrc`); a change needs a restart of the service.

| Variable | Default | Meaning |
|---|---|---|
| `jailopsd_enable` | `NO` | start JailOps at boot: the daemon and the helper it needs. `jailops_priv_enable` defaults to it and needs no line |
| `jailops_shutdown_enable`, `_timeout`, `_grace` | `jailopsd_enable`, `80`, empty | stop the jails cleanly when the host shuts down, within this many seconds for all of them, each with this grace ([operations.md](operations.md#stop-at-shutdown)) |
| `jailops_priv_config`, `jailopsd_config` | the files above | another configuration file |
| `jailopsd_runas` | `jailops` | the daemon's user |
| `jailopsd_web` | unset | `YES` serves the web console (and opens the TLS listener on 39110 when none is set), `NO` forces it off; unset, `web.enabled` decides |
| `jailops_appliance` | unset | `YES`: appliance mode ([appliance.md](appliance.md)). Both programs manage the modules of `jailops_appliance_modules` besides their own lists; the first start of `jailops_priv` without `priv.conf` sets the host up (`jailops-priv appliance-init`); every start of `jailopsd` without an administrator prints a setup token on the system console |
| `jailops_appliance_modules` | all modules | the modules of appliance mode, separated by spaces (`identity firewall`) |
| `jailops_pool` | the pool of `/` | the pool the first start of appliance mode sets up |

## backupd.yaml

The backup node. It needs PostgreSQL (its control plane), a datastore (a directory or an S3 bucket) and a certificate.
The sample `packaging/backupd.yaml` is annotated: `hostname`, `listen` (default `:39111`), `admin_socket` (mode 0600, root only; the former `admin_group` key is removed and stops the node at start), `tls`,
`database.dsn_file`, `datastore` (`directory` or `s3`), `web`, `grace`, `deletion_delay`, `retention`, `schedule`.
`jailops-backupd -c FILE init` creates the repository and the certificate and prints the fingerprint that hosts pin.

## The client file

`~/.config/jailops/config.yaml` (override with `--config` or `JAILOPS_CONFIG`) and the host-wide
`/usr/local/etc/jailops/client.yaml` hold named remotes (`url` or `socket`, `token` or `token_file`, `fingerprint`,
`cert`, `key`, `ca`, `host`, `project`), the current remote and, per remote, the **current project** that
`jailops project switch NAME` sets. That project is client-side state: the server has no default project. Precedence,
strongest first: the flags `--remote`, `--host` and `--project`; the environment (`JAILOPS_REMOTE`, `JAILOPS_URL`,
`JAILOPS_TOKEN`, `JAILOPS_FINGERPRINT`, `JAILOPS_CERT`, `JAILOPS_KEY`, `JAILOPS_CA`, `JAILOPS_HOST`, `JAILOPS_PROJECT`,
`JAILOPS_SOCKET`, `JAILOPS_CONFIG`); the user file; the host file; the default socket
`/var/run/jailops/jailops.sock`. Prefer `token_file` (or `--token-file -`) to a token on the command line: a command-line
value is visible to other users.
