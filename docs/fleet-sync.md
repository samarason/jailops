# Fleets from git: `jailops-sync`

`jailops-sync` makes hosts match a **git repository of YAML**. It is a client of the API like the CLI (it imports only `sdk` and
`sdk/api`), so it needs no access to a host beyond a token or a client certificate. A complete small repository is
`examples/minimal-fleet`; `jailops-sync validate -C examples/minimal-fleet` checks it offline. Task-shaped, runnable examples
(IPv6 switched and routed, a web stack with backups, a 16 TB pool, two hosts with secrets, provisioning a fresh VM) are in
[../examples/README.md](../examples/README.md); the test suite applies every one of them to in-memory hosts, so none of them rots.

The rule that makes it safe: **sync changes only what it owns.** Every object it creates carries `managed_by: sync:<fleet id>`
(the `id` in `fleet.yaml`). Objects it did not create are never changed or deleted, `prune-check` lists what the repository does not
declare and never deletes, and there is no scheduler: a jail is declared on a named host.

## The repository

    fleet.yaml                      id: <fleet id>, the ownership marker
    .sops.yaml                      who can decrypt the SOPS files (age public keys) and which fields each rule encrypts
    hosts/<host>/host.yaml          kind Host: url, fingerprint, token_secret; labels select groups
    hosts/<host>/remote.sops.yaml   a client certificate for pinned mTLS (url and fingerprint readable, key encrypted)
    hosts/<host>/storage/*.yaml     storage that exists on that host (host-specific)
    hosts/<host>/wireguard/*.yaml   kind WireGuard: a tunnel server of that host and the public parts of its peers
    groups/*.yaml                   kind HostGroup: a selector over host labels
    shared/images|networks|backup-targets/*.yaml     host-level objects applied to the hosts that need them
    profiles/*.yaml                 kind Profile: a fragment merged into the jails that list it (repository only)
    shared/secrets.sops.yaml        values for jail environment `secret:<dotted.path>`
    secrets/<name>.age, recipients.txt   one age secret per file; the recipients are the hosts' keys
    projects/<project>.yaml         kind Project: hosts, networks (one project each), storage with quotas, quotas, firewall, images
    projects/<project>/jails/*.yaml, profiles/*.yaml, firewall-policies/*.yaml   everything a project owns
    rollouts/*.yaml                 kind Rollout: staged upgrades

**There is no default project.** Every jail and every project-level object lives under `projects/<project>/`; a jail names its
network and storage (or a profile does). `validate` reports a jail without a project, a network named by two projects, and a
jail that has no network or storage after its profiles.

## What you can declare

Every declarative object a user can create with the CLI has a file kind. Nothing here needs a second tool.

| By CLI | In the repository | Notes |
|---|---|---|
| `jailops project create/set` | `projects/<name>.yaml` (Project) | networks granted, storage granted with quotas (`fast=500G` is `{storage: fast, quota: 500G}`), `quotas`, the mandatory policies (`firewall_policies`, a list), the `images` allow-list, and `hosts` (a project spans hosts and has the same UUID on each). Removing a grant revokes it |
| `jailops network grant/revoke` | the project's `networks:` list | a network belongs to **one** project: `validate` refuses a second grant |
| `jailops network create` | `shared/networks/*.yaml` (or `hosts/<h>/networks/`) | every field of the API: IPv4, IPv6 `routed`, `proxy` and `none`, uplink, `private`, DNS, MTU, exclusions. See below for the CLI flags |
| `jailops wireguard create --mode server`, `peer add` | `hosts/<host>/wireguard/*.yaml` (WireGuard) | servers only, public parts only; see "WireGuard" below |
| `jailops storage create` | `hosts/<host>/storage/*.yaml` (Storage) | a dataset on any pool, a big HDD pool included; `compression`. Datasets may not be equal or nested |
| `jailops image create`, `image build` | `shared/images/*.yaml` (Image) | `aliases` are in the spec. `build: true` builds the **first** generation when the host has none (a fresh host has none and a jail cannot be created from an image without one). Later generations are an operation, not a declaration: `jailops image build`, or a rollout |
| `jailops create` | `projects/<p>/jails/*.yaml` (Jail) | the whole spec: network and storage (explicit), `volumes`, `proxy`, `devfs`, `resources`, `boot`, `update` schedule, `firewall` (`policies`, a list, and `tags`), `env` with `secret:` references, `provision`, `labels`. `start: true` and `after:` hooks (start, restart, snapshot, exec) run once, after creation |
| `jailops firewall policy/address-set create` | `projects/<p>/firewall-policies/`, `address-sets/` | the project's mandatory policies are set in a second write once the policies exist |
| `jailops backup target create` | `shared/backup-targets/*.yaml` (BackupTarget) | `kind: node` needs `address` and a pinned `fingerprint` |
| `jailops backup policy create` | `projects/<p>/backup-policies/*.yaml` (BackupPolicy) | selector, targets, `schedule`, retention, `include_state`, `exclude_volumes`, `verify_schedule`, `verify_mode` |
| `jailops profile create` | `profiles/` or `projects/<p>/profiles/` (Profile) | see "Profiles" below |
| secrets in a jail's environment | `secret:<name>` and `secret:<dotted.path>` | age and SOPS, see "Secrets" |
| `jailops app install` | `projects/<p>/apps/*.yaml` (App) | installed once, never changed or deleted; see "Apps and who may reach them" |
| `jailops app allow`, `app deny` | `projects/<p>/app-access/*.yaml` (AppAccess) | the whole list of sources of one app; see "Apps and who may reach them" |

Because the specs are the wire types of the API (decoded strictly: a misspelled key is an error), a field the daemon gains is
declarable the day it exists. `validate` also checks, offline, what the daemon would refuse at apply time: the name rules of
jails, networks, policies, address sets and WireGuard tunnels, overlapping subnets and storage datasets, the IPv6 proxy and routed prefix limits,
the proxy gateway and uplink, reserved fields (`encrypted`, `packages`), that a jail's `volumes` name a volume (`kind: Volume`, `projects/<p>/volumes/`), and that a **profile cannot carry `host_mounts` or
`zfs_delegation`**. It refuses a `Volume` with `encrypted: true`: its passphrase is typed by a person, so create that volume
with `jailops volume create --encrypted` ([storage.md](storage.md#encrypted-volumes)); a jail of the repository can then
attach it, and `validate` warns that a volume a jail names is not declared.

**IPv6, CLI flags and YAML.** `--ipv6-mode routed` and `--ipv6-mode proxy` fill in what a file spells out:

| CLI | YAML (`spec.ipv6`) |
|---|---|
| `--ipv6 2001:db8:1:2:1::1/80` (routed) | `mode: routed`, `subnet: 2001:db8:1:2:1::/80`, `gateway: 2001:db8:1:2:1::1`, `range: <first>-<last>` |
| `--ipv6 2001:db8:1:2:100::/80 --ipv6-mode proxy` | `mode: proxy`, `subnet: 2001:db8:1:2:100::/80`, `gateway: fe80::1`, `range: <first>-<last>` and `uplink: vtnet0` on the network |
| `--ipv4 10.50.0.1/24` | `ipv4: {subnet: 10.50.0.0/24, gateway: 10.50.0.1, range: 10.50.0.2-10.50.0.254}` |

Complete files are in `examples/ipv6-switched-cloud` and `examples/ipv6-routed-hetzner`.

**WireGuard.** A tunnel belongs to one host (its endpoint and its keys are that host's), so it is declared under
`hosts/<host>/wireguard/` and never under `shared/`. A file carries the spec of a **server**: `mode: server`, `interface`,
`address`, `listen_port`, `endpoint`, `allowed_ips` (the pool), `dns`, `keepalive`, `networks`, `down`, and per peer `name`,
`public_key`, `allowed_ips` (its tunnel address) and `keepalive`. There is no field for a private key or a preshared key, and the
strict decoding refuses one:

    apiVersion: jailops/v1
    kind: WireGuard
    metadata:
      name: office
    spec:
      mode: server
      address: [10.99.0.1/24]
      endpoint: vpn.example.com:51820
      networks: [lan]
      peers:
        - {name: laptop, public_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=, allowed_ips: [10.99.0.2/32]}

- The server's own key pair is made on the host by the daemon when sync creates the object; it never leaves the host. Its
  public key is in the object's status (`jailops wireguard show office`), which sync never writes.
- A peer listed in a file is a peer whose key pair was made elsewhere (a phone or laptop that made its own keys): it gets **no
  preshared key**, unless the host already holds one for exactly that public key (the helper keeps preshared keys by public
  key, so a peer enrolled with `jailops wireguard peer add` and then written into the file keeps its preshared key).
- A peer enrolled on the host with `jailops wireguard peer add` (the way to get a join token and a preshared key) is not in the
  repository: the next `sync --apply` would remove it, and because removing a peer cuts it off, sync calls that a dangerous
  change and refuses it without `--force`. Copy the peer's `name`, `public_key` and `allowed_ips` from
  `jailops wireguard show office -o yaml` into the file to keep it.
- What the daemon fills in is not drift: `interface` (`wg-<name>`), `listen_port` (51820), `allowed_ips` (the subnets of
  `address`), `endpoint` (the host name and the port) and each peer's `created` time. A re-plan after an apply is empty.
- **Clients are not declarable.** A client's private key comes from a join token on its own host (`jailops wireguard join
  TOKEN`) and cannot be reproduced from a file; `validate` refuses `mode: client`, and `adopt` skips client tunnels.
- `validate` checks offline what the daemon would refuse: the interface name (at most 15 characters starting with `wg`; a name
  longer than 12 characters needs `interface`), the addresses, the peers' keys (base64 of 32 bytes), addresses that overlap
  another peer or hold the server's own address, the networks named, and two tunnels of one host sharing an interface, a
  listen port or overlapping addresses. Deleting a tunnel, changing its address or its listen port, and removing a peer need
  `--force`.

**Not declarable, and why.**

- `jailops project create --new-network`: a create-time convenience that is never stored; declare the network and grant it
  (`validate` refuses `new_network`).
- Credentials: users, API tokens, trusted certificates, trust tokens, sessions. Their secrets are shown once and cannot be
  reproduced from a file; sync's own access is the token or certificate you give it (`secrets set`, `remote bootstrap`).
- Backup keys and the backup node itself: `jailops backup key create/escrow` produce key material that must not be in git, and the
  node (`jailops-backupd`) is configured by its own `backupd.yaml`. Targets and policies are declarable; see `examples/web-stack`.
- `priv.conf` (`admin-host-mount`, ...) and `jailopsd.yaml`: they are the host operator's boundary, on purpose out of
  reach of the API. `examples/provisioning/bootstrap.sh` writes them when it installs a host.
- Runtime actions and data: snapshots (use the `snapshot` hook), backups and restores, exec, updates, generations after the first.
- Provisioning **files**: `provision.files` copies from `<state_dir>/project-files/<project>/` on the host. Sync does not upload
  them (see `examples/pkgops-packaged-service`); commands, packages and services are declarable.
- Profile objects of the daemon (below).

### Apps and who may reach them

An **App** document installs an app of the host's catalog as a jail of the project, through the same request as
`jailops app install` (docs/apps.md). The file name is the jail's name; the spec names the app and, optionally, what the
command's flags name:

    apiVersion: jailops/v1
    kind: App
    metadata: {name: db}                 # the jail
    hosts: [db1]                         # exactly one host, like a jail
    spec:
      app: postgresql                    # the definition in the host's catalog
      network: shop                      # default: the project's only network
      storage: default                   # default: the project's only storage
      image: freebsd-15-1                # default: the host's FreeBSD image of the newest release it can run
      limits: {memory: 2G, disk: 20G, cpu: 2}   # replace the definition's resource hints

`plan` shows `create` when the jail does not exist, and `sync --apply` installs it and waits for the installation. After
that sync **never reinstalls, changes or deletes** it: the jail is the app's data, an installation is not repeatable as an
update, and the API gives an installed jail no ownership marker, so `--prune` never applies to apps (remove one with
`jailops delete`, which shows what it destroys and asks for the name). A jail of that name that was not installed from the catalog, or runs another app, is a refusal (the
label `jailops.app` differs) and nothing is applied. An App and a Jail document of the same name are a `validate` error. The
`limits`, `network` and the rest are read only at the installation; a later change of the document is not drift.

An **AppAccess** document is the list of sources allowed to reach one installed app (metadata.name is the app's jail). An
installed app is closed to everything else; each entry is what `jailops app allow APP --from SOURCE` is given:

    apiVersion: jailops/v1
    kind: AppAccess
    metadata: {name: db}
    hosts: [db1]
    spec:
      grants:
        - {source: "jail:web", database: shop}           # a jail of the project; database and role shop
        - {source: "set:office"}                        # an address set of the project
        - {source: 192.0.2.0/24, ports: ["5432"]}    # an address or a prefix
        - {source: host}                             # the host itself

`ports` are `N` or `N/udp` (default: the ports of the definition), `database` names the database and role of a
PostgreSQL grant (default: the source jail's name). Sources compare in the form the host stores them (`192.0.2.7/32` is `192.0.2.7`), so `validate` refuses a source listed twice. `plan` compares the list with
`GET .../access`: a missing grant is `create`, changed ports or a grant the host reports drift for (a missing firewall rule
or `pg_hba.conf` line) is `update`, both applied with `jailops app allow`. A changed `database` of an existing grant is a plan
error: deny it first. A grant the host has and the document does not list is `delete`, applied only with `--prune`, as for
every owned object: the document owns the whole access list of its app. Without an AppAccess document sync never touches the
grants of an app. A deny never drops a role: it loses its login and keeps its database.

**The password.** A PostgreSQL grant makes a role with a generated password. The host returns the connection string
(`postgres://ROLE:PASSWORD@HOST:5432/DB?sslmode=disable`) once, in the answer of the allow, and keeps only the existence of
the role. `sync --apply` prints it **once, in its own output**, under the change that made it:

      ok       db1 AppAccess/shop/db from jail:web (create)
        connection string for jail:web on shop/db (shown once, stored nowhere; ...):
          postgres://shop:...@<address of db>:5432/shop?sslmode=disable

It is not in the plan, not in the JSONL apply log, not in the state directory and never written into the repository. Copy
it into the application's secret store at once; `watch --apply` prints it to wherever its output goes, so make the first
apply of a new grant by hand. Re-applying never makes a new password (sync never asks for a rotation);
`jailops app allow APP --from SOURCE --rotate` does, and prints the new string.

**Order.** Apps come after every stored kind of the host (images, networks, storage, projects, policies, jails), and
grants after the apps: a grant's app is installed and its source jails exist when it is allowed. `validate` warns about a
grant whose app or `@` source the repository does not declare for that host (it may exist there already).

### Profiles

A `Profile` document in the repository is a fragment that sync **merges into the jail before sending it**: devices merge by name,
the jail's own keys win, and `render` shows where each key came from. The daemon's own profile objects (`jailops profile create`)
are a different mechanism with the same purpose; sync does not create them, because a profile that lives only on a host would
make the host, not git, the source of truth for every jail that lists it. The effect is the same: a changed repository profile
shows in `plan` as a change of each jail that lists it. `adopt` tells you when a jail lists host profiles the repository does not know.

## Commands

| Command | Does |
|---|---|
| `validate` (alias `check`) | checks layout, names, references and values; offline |
| `render` | prints the resolved documents sync would send; offline, never decrypts |
| `plan` | reads the hosts and shows what would change; writes nothing; needs no decryption key (a secret's change is detected from a digest of its stored ciphertext) |
| `sync` | plans; with `--apply` makes the hosts match |
| `drift` | exits non-zero when live hosts differ from the repository, for CI and cron |
| `watch` | pulls the repository on an interval, plans, optionally applies |
| `rollout` | runs the staged upgrades declared as `Rollout` objects |
| `adopt` | writes live objects into the repository as YAML (`--claim` also takes ownership) |
| `prune-check` | lists live objects the repository does not declare; deletes nothing |
| `doctor` | checks the tool, the repository, the identity and every host |
| `secrets`, `remote`, `vault` | manage age secrets, the client-certificate identity of hosts, and the SOPS recipients |

Only the keys a document **declares** are compared: a key you did not write is not drift. A changed declared key is reported as
drift and reverted by `sync --apply`.

## Secrets

Two mechanisms, which can be mixed:

- `secrets/<name>.age`: one age-encrypted secret per file, for the API tokens of hosts and the hub (`token_secret`) and for jail
  environment values `secret:<name>`.
- SOPS: `shared/secrets.sops.yaml` and `hosts/<host>/remote.sops.yaml`, governed by `.sops.yaml`. A jail value
  `secret:app.db_password` is a value of the SOPS file.

Either way, sync decrypts a value **in memory only when it applies it**, and sends it **sealed** (`sealed:age:...`) to the age key
of the host (`secrets_recipient` in the host's server info, extension `sealed_secrets`), so the host that holds the key opens it,
and only when it starts a process in the jail. The API never returns the plaintext.

The key for SOPS files comes only from SOPS's own variables: `SOPS_AGE_KEY` (the key text), `SOPS_AGE_KEY_FILE` (an identity
file, which may hold an age plugin identity so that a hardware token or an agent supplies the key) or `SOPS_AGE_KEY_CMD` (a command
that prints it). The implicit `~/.config/sops/age/keys.txt` is not counted. `jailops-sync vault status|list-recipients|add-recipient|
remove-recipient` edits the recipients in `.sops.yaml` and re-wraps the files; removing a recipient is revocation only after the
re-wrap, and a removed key may already have read the current values, so rotate them.

## A first fleet

    jailops-sync -C ./fleet validate
    jailops-sync -C ./fleet plan
    jailops-sync -C ./fleet sync --apply
    jailops-sync -C ./fleet drift            # in CI: non-zero when something changed behind your back
    jailops-sync -C ./fleet adopt --claim    # take over what is already running, as YAML

Rollouts stage an upgrade (a project, a label selector, a canary, a batch size, a pause, a health gate) so one bad generation
does not reach every jail at once.

## Naming rules

File name equals `metadata.name`. Every kind uses the daemon's one rule (`^[a-z]([a-z0-9-]*[a-z0-9])?$`, hyphens only, at most 63 characters; an address
set 29, because its name becomes a PF table with the hyphens written as underscores); `validate` says so before the daemon would.

## Plain http

A host URL is `https://`, with a pinned `fingerprint` for a self-signed certificate (or none for a certificate a public CA
signed). `http://` is accepted for loopback only, as the SDK does. See [exposure.md](exposure.md) for how a host gets its listener
and certificate.

## Verified, and not

Run against a real FreeBSD host: adopt with claim, plan, apply (a dual-stack network, a project grant and a jail), a changed
declared key reported as drift and reverted, and a secret in a SOPS file sealed to the host's own age key, stored sealed, and
opened inside the jail. **UNVERIFIED:** age plugin identities, `remote bootstrap` against a real host, and rollouts on real jails
(the package and generation updates they drive were tested with fakes).

Tested with fakes only (in-memory hosts, `internal/fleet/e2e`): `build: true` for images, every object kind of the table above applying
and then planning to zero (a WireGuard server with a listed peer included), and the eight example repositories. **UNVERIFIED on a real host:** `build: true` (the first image build
and then planning to zero, and the nine example repositories. Apps and their grants (`examples/app-access-fleet`) are tested against the
in-memory host's catalog only: **UNVERIFIED on a real host:** an App installed and an AppAccess applied by sync (the same calls as the CLI). **UNVERIFIED on a real host:** `build: true` (the first image build
through sync), an IPv6 proxy or routed network created by sync (the same objects created by the CLI are verified), a host-directory volume applied by
sync with a global-admin token, and `jailops-sync` over the network with a CA-signed server certificate (a pinned self-signed one is
verified).
