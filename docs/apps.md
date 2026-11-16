# Applications: the catalog

An **app** is a definition of a jail that runs one or more packages from the FreeBSD repository or from the JailOps
package repository, with what an operator needs to run it: the services, the ports, where the data, the
configuration and the logs live, how to check that it runs. The catalog is the set of definitions a host has;
`jailops app list` shows it and `jailops app info NAME` describes one entry.

This page is the contract of the catalog and of the installation: `jailops app install NAME` creates a jail that runs
an app as one operation, `jailops app installed` lists the jails that came from the catalog, and `jailops app allow`
and `deny` say who may connect to an installed app ([Who may connect](#who-may-connect)).

## Trust model

The catalog is delivered as an ordinary signed package, `jailops-apps`, from `pkg.jailops.net`. It installs one
YAML file per app under `/usr/local/share/jailops/apps/` (`apps.catalog_dir` of `jailopsd.yaml`, see
[configuration.md](configuration.md)). The signature of the package is the root of trust: the daemon **reads local
files only and never fetches anything**, so a catalog cannot change without a package operation on the host.

The host's own definitions go into a second directory, `apps.local_dir` (default `/usr/local/etc/jailops/apps`),
which the daemon reads with the catalog on each request, so a definition dropped there (`NAME.yaml` and its icon) is
listed and installable at once, without a package. A local definition is listed with `source: local`; one whose name
is also in the packaged catalog **wins** and says so (`overrides: catalog`), and the packaged one is back as soon as
the local file is removed. A local definition is checked like a packaged one; an invalid one is listed as invalid with
the reason, and it still hides a packaged one of the same name. The directory must be readable by the user `jailops`
the daemon runs as (`0755` for the directory, `0644` for the files, owned by root); `jailops doctor` reports
`apps.local_dir` when the directory exists (how many definitions, how many invalid, or that it cannot be read, which
makes the whole listing fail). Nothing writes into it but you.

The catalog is not part of the JailOps source or its releases. Its definitions live in the packages repository
(`main/jailops-apps/apps/` of `jailops/jailops-packages`), and `jailops-apps` is a package with a version of its own:
a new or changed app is one pull request there and a new `jailops-apps` version, with no JailOps release. The
`jailops` package depends on `jailops-apps` by name, so any version satisfies it and `pkg upgrade` brings the newest
catalog. See [Adding or changing an app](#adding-or-changing-an-app).

**Older daemons, newer definitions.** A definition is checked against the format this daemon knows. One written for a
newer daemon (a key it does not know, a `version` other than 1, a category it does not know) is **listed as invalid with
the reason** and cannot be installed; the other definitions are unaffected. Since a catalog update can reach a host
before the JailOps update it needs, such an app stays invalid on that host until `jailops` is upgraded.

Every definition is validated when it is read (on each request; the directory is small). A definition that fails is
**listed as invalid with the reason** (`jailops app list` shows it, `GET /api/v1/apps` carries `valid: false` and
`error`) and `GET /api/v1/apps/NAME` answers `invalid`; it can never be installed. The other definitions are not
affected. A missing directory is an empty catalog, not an error. A file that is not a regular file (a symbolic link,
a directory) or larger than 256 KB is invalid. The list reads at most 512 definitions, in name order; the first one
beyond is listed once as invalid ("catalog has too many definitions"), the others are not read. The list does not read
icons; `GET /api/v1/apps/NAME` reads the one definition and its icon, so a bad icon shows there.

Each definition carries the hash of its file (`sha256:<hex>`); an installed jail will record it, so a later
`app info` can say whether the definition changed since the installation.

## The definition format, version 1

One YAML document per file, strict: an unknown key is an error, like every other configuration file of JailOps.
The file name is the app name with `.yaml` (`postgresql.yaml` holds `name: postgresql`; a mismatch is invalid, so two
files cannot claim one name). The catalog in the packages repository is the reference; a copy of it is the test data of
`internal/apps` (`internal/apps/testdata/catalog/`).

```yaml
version: 1                       # required, 1
name: postgresql                 # a jail name (lowercase letters, digits and hyphens, starting with a letter), equal to the file name
title: PostgreSQL                # one line, at most 80 characters
summary: Relational database server, PostgreSQL 18 from the FreeBSD packages.   # one line, at most 140
description: |                   # plain text paragraphs, no markup, at most 2000 characters
  ...
category: database               # database, web, tools, devops, storage, monitoring, communication, network, security, other
homepage: https://www.postgresql.org/    # an https URL
license: PostgreSQL              # free text, at most 64 characters
icon: postgresql.svg             # optional: a .png or .svg next to the definition, at most 64 KB
image: {os: freebsd, release_min: "15.1"}   # freebsd only; 15.1 or later
packages:                        # at least one; repo: ports (default) or jailops
  - {name: postgresql18-server, repo: ports, version: "18.6"}   # version: what the definition was written against
services:                        # rc.d services, in start order
  - name: postgresql             # the rc.d script name
    rc: {postgresql_initdb_flags: "--encoding=utf-8"}   # rc.conf knobs; <name>_enable is written by the installer
    start: true                  # default true; false: enabled, not started
ports:
  - {name: postgres, port: 5432, proto: tcp, description: The SQL port., expose: false}
data:                            # the state; each path becomes a persistent dataset of the jail
  - {path: /var/db/postgres, description: The cluster.}
config:                          # files a person edits; restart names the service to restart afterwards
  - {path: /var/db/postgres/data18/postgresql.conf, description: Server settings., restart: postgresql}
logs:                            # files or directories; reading them is a separate feature
  - {name: server, path: /var/log/messages, description: The port logs to syslog.}
setup:                           # run once in the jail after the packages, before the services: argv, no shell
  - [/usr/sbin/chown, "postgres:postgres", /var/db/postgres]
  - [/usr/sbin/service, postgresql, initdb]
sysvipc: true                    # optional, default false: System V IPC of the jail's own (see below)
health:                          # optional; exactly one of tcp, http, exec; wait_seconds at most 300 (default 60)
  exec: [/usr/local/bin/pg_isready, -U, postgres]
  wait_seconds: 60
resources: {memory: 1G, disk: 10G, cpu: "1"}   # hints for the jail's limits, not limits
notes: |                         # shown after the installation, at most 2000 characters
  ...
access:                          # optional (0.4.0): what jailops app allow does in the jail besides the firewall rule
  type: postgresql               # the one type there is: a role and a database per grant, made with psql
  port: postgres                 # a name of ports (tcp): the port a grant opens
  service: postgresql            # a name of services: restarted once when listen_addresses changes
  hba_file: /var/db/postgres/data18/pg_hba.conf   # one of the config paths: the managed block goes here
```

Rules the validator enforces, besides the sizes above:

- `data`, `config` and `logs` paths are absolute and clean (no `.`, `..`, empty segments, no characters outside
  `A-Za-z0-9/._+@:=,-`). `data` and `config` paths lie **below** `/var`, `/usr/local`, `/usr/local/etc` or `/home`
  (never one of those themselves); `logs` paths below `/var/log`, `/var/db` or `/usr/local`. A `data` or `config` path
  is never one of the persistent datasets of every jail (`/etc`, `/usr/local`, `/var/db`, `/var/log`, `/var/mail`,
  `/var/spool`, `/home`, `/root`); the installer also refuses, before the operation starts and with the same message,
  a path that equals one this host adds in `lifecycle.persistent`. Nothing lies under the base
  system (`/etc`, `/bin`, `/sbin`, `/lib`, `/usr/bin`, `/usr/lib`, `/usr/share`, ...) nor under the packages' own
  directories (`/usr/local/bin`, `/usr/local/lib`, `/usr/local/share`, `/usr/local/etc/rc.d`, ...) nor under `/var/run`,
  `/var/tmp` or `/tmp`.
- Two `data` paths never overlap: each is its own dataset.
- `rc` keys are rc.conf variable names (`^[a-z][a-z0-9_]{0,63}$`); values are one printable line. The installer writes
  `<name>_enable=YES` itself, with `-` and `.` of the service name turned into `_` as rc.conf spells it, and a
  definition that sets any service's `_enable` is invalid. Two services whose names are the same once converted
  (`foo-bar` and `foo_bar`) are invalid.
- `setup` and `health.exec` commands are argv with an absolute program path; there is no shell, no search path, no
  pipe. At most 32 setup commands.
- Names of ports and logs are short names (the name rule, at most 32 characters); a port is unique per `port/proto`.
- `health.http.path` is an absolute request path; `status` defaults to 200. A definition may leave `health` out; the
  catalog does so only for an app that starts none of its services (`isms`: nothing runs to check until the
  operator has configured it).
- `resources.memory` and `.disk` are sizes (`512M`, `10G`); `cpu` is a number.
- `access` is optional and strict like the rest: `type` must be `postgresql`, `port` a tcp port of `ports`, `service` one
  of `services`, `hba_file` one of the `config` paths; any other key is invalid. The key is new in 0.4.0, so a daemon
  before it lists a definition that has it as invalid (see the trust model). The reference copy of `postgresql` in
  `internal/apps/testdata/catalog/` has the block; the definition that hosts install lives in the packages repository
  and gets it there, by a pull request of its own, once 0.4.0 is the release that repository builds against. What the
  block makes JailOps do is in [Who may connect](#who-may-connect).
- `sysvipc` is a boolean (`true` or `false`, nothing else). A jail has no System V shared memory, semaphores or message
  queues unless its parameters allow them, and a server that needs them fails: PostgreSQL's `initdb` stops at
  `shmget(...)` "Failed system call". `sysvipc: true` sets the jail spec's `sysvipc`, which renders
  `sysvmsg = new; sysvsem = new; sysvshm = new;` into the jail's `jail.conf`: namespaces of the jail's own, separate
  from the host's and from every other jail's (never `inherit`, which would share the host's). The objects still count
  against the host's `kern.ipc` limits. The key is an ordinary key of the jail too (`jailops config set NAME
  sysvipc=true`, a restart applies it; a profile may carry it). The FreeBSD end-to-end test (below) installs PostgreSQL
  with it and runs a query.

Defaults are filled in when the definition is read, so the API always answers a complete object: `repo: ports`,
`proto: tcp`, `start: true`, `health.wait_seconds: 60`, `health.http.status: 200`.

## The API and the clients

| Route | Reply |
|---|---|
| `GET /api/v1/apps` | `[]AppSummary`: `name`, `title`, `summary`, `category`, `version` (of the first package, when the definition states one), `valid`, `error`, `source` (`catalog` or `local`), `overrides` (`catalog` for a local definition that hides a packaged one) |
| `GET /api/v1/apps/<name>` | `AppDetail`: `definition` (the `App`), `hash`, `file`, `icon` (a data URI, `image/png` or `image/svg+xml`, when the definition has one), `source`, `overrides`; the local definition when both directories have the name; `invalid` for an invalid definition, `not_found` for an unknown name |
| `GET /api/v1/jails/<name>/app-draft` | `AppDraft`: `jail`, `definition` (a draft made from the running jail, valid as it is, with `TODO` markers), `todo` (a top-level key and what is left to do there), `findings` (what was found and left out); see [Write your own app](#write-your-own-app). Operator in the project, audited, extension `app_draft` |

| `GET /api/v1/jails/<jail>/access` | `AppAccess` of an installed app: `jail`, `project`, `app`, `type` (the definition's access type), `policy` (`app-<jail>`), `closed`, `ports`, `grants`, `warnings`; see [Who may connect](#who-may-connect). Readonly in the project |
| `POST /api/v1/jails/<jail>/access` | body `AppAllow` (`source`, `ports`, `database`, `rotate`, `dry_run`); answers `AppAllowResult` at once (`grant`, `changed`, `connection_string` once, `sql` without the password, `steps`, `notes`). Operator in the project, audited, extension `app_access` |
| `POST /api/v1/jails/<jail>/access/deny` | body `AppDeny` (`source`, `drop_role`, `dry_run`); answers `AppDenyResult` (`removed`, `changed`, `sql`, `steps`, `notes`). Operator, audited |
| `POST /api/v1/apps/<name>/install` | body `AppInstall`: `jail` (default: the app name), `network`, `storage` (each defaults to the project's only grant of its kind), `image` (default: the FreeBSD image of the highest release the host can run, ties by name; none is `invalid`), `limits` (replaces the resource hints), `dry_run`; async, result `AppInstallResult`: `jail`, `version`, `addresses`, `ports` (with `endpoint`), `data`, `config`, `logs`, `notes`, `snapshot`, `steps` |

Extensions `apps` (the catalog), `app_install` (the installation) and `app_access` (who may connect; the SDK has
`Apps().Access`, `Apps().Allow` and `Apps().Deny`, and the fake answers them with grants it keeps in memory). The Go SDK has `Apps().List`, `Apps().Get`,
`Apps().Install` and `Apps().Installed` (the jails of the project that carry the label `jailops.app`); the in-memory
server of `sdk/fake` starts with six definitions (nginx, postgresql, valkey, isms, nsd, mail, shortened) and installs them as running jails. The CLI:
`jailops app list [PATTERN...] [--category C] [-c COLS] [--sort COL] [-o wide|json|yaml|name|csv]`,
`jailops app info NAME [-o json|yaml]`, `jailops app install NAME [--name JAIL] [--network N] [--storage S]
[--image I] [--memory M] [--disk D] [--cpu N] [--project P] [--dry-run] [--no-wait]` and
`jailops app installed [PATTERN...] [-o json|yaml|name|csv]` (columns `JAIL`, `APP`, `VERSION`, `STATE`,
`ADDRESSES`, `PORTS`; the list is the project's jail list narrowed on the client to the label, no route of its own).
`jailops app list --source local` (or `catalog`) narrows the list to one directory; the full table has a `SOURCE`
column (`catalog`, `local`, `local, overrides catalog`), the short one on a terminal marks a local definition with
`(local)`, and `app info` has a `Source:` line. `jailops app new NAME` and `jailops app export JAIL` write
definitions ([Write your own app](#write-your-own-app)); the SDK has `Jails().AppDraft`, and the fake server answers
it for a running jail (`SeedAppDraft` sets the answer, `SeedLocalApp` adds a local definition).
`jailops app validate PATH... [-o json|yaml]` checks definition files on the machine it runs on, without a server
([Adding or changing an app](#adding-or-changing-an-app)); it is the one command of the client that links the daemon's
catalog validator (`internal/apps`, which imports nothing that runs commands or touches state; a test keeps it so).

**`stop_timeout`** (seconds, optional) is the shutdown budget the app recommends: it becomes `boot.stop_timeout` of the jail. A database that needs a minute to flush and close says `stop_timeout: 60` (PostgreSQL does); an app that leaves it out gets the default, which is bounded too (see the stop in [operations.md](operations.md)).

**Permissions.** The catalog is readable by **any authenticated identity**, whatever its role and project scope
(route class `self`, like the configuration key registry): it is documentation of what the host can run, not an object
of a project. Installing is a project operation: `POST /api/v1/apps/<name>/install` is its own entry of the permission
table, **operator** in the project of the request (route class `project`: a scope-less identity is forbidden, a project
the identity may not use is `not_found`). The create of a jail stays `admin`; the install is `operator` because it creates
nothing the definition does not say. The jail it makes is an ordinary jail of the project afterwards, with the ordinary
roles (`delete` is admin, `start` and `stop` are operator).

## Console

The host console has an **Apps** page (`/apps`): the catalog as cards (a local definition carries a small **local** chip, here, on its page, where it also says when it overrides the catalog's definition, and in the Installed tab) with a search over name, title and summary and category filters; an invalid definition is shown with its reason and cannot be installed. `/apps/NAME` shows a definition in full (packages, services and their `rc.conf` knobs, ports and whether they are exposed, the data paths with the volume each becomes, the configuration files and the service each one restarts, the log files, the health check, the resource hints, the notes and the definition's hash). **Install** opens a dialog with the jail name (the app name by default), the image (each listed with its release, `freebsd-15-1 (15.1-RELEASE)`; the newest release the host can run is preset), the network and storage among the project's grants (preset when there is one of a kind) and the limits prefilled from the hints; *Preview steps* runs the dry run and lists the steps, and the installation then follows the operation: the step list is ticked off from the operation's progress (the server sets it after each step) and ends in a report with the jail, its addresses, the port endpoints, where the data, configuration and logs are, the notes and the `app-installed` snapshot with the rollback command, or with the error, its hint and a link to the jail when it was kept. The button is disabled, with the reason, for an identity below operator in the project and for a project without a network or storage grant. On a host without a FreeBSD image the dialog says so in place and offers **Create the base image** (the dialog of the Images page: the host's release and architecture, the name from the release such as `freebsd-15-1`, the nightly auto upgrade, the first generation built and followed as an operation); the install becomes possible once it exists. The **Installed** tab lists the project's jails that carry `jailops.app`, with their version, state, addresses and ports, and an *Open* link for the exposed `http` and `https` ports. The log files of a definition link to the **Logs** tab of the jail they were installed as, which reads the jail logs API (tail, since, text filter, follow).

The declared log files below `/var/log` also join the merged view of all jails (`jailops logs --app NAME --app-logs`,
the console's Logs page) and are forwarded by default with the jail's `messages` when log forwarding is configured
([logging.md](logging.md)); paths below `/var/db` or `/usr/local` are not readable through the helper and are left out.

The page of a jail that came from the catalog has an **Access** tab (when the server offers `app_access`). It says whether the app is closed by its managed policy `app-JAIL` or still open to its network, and lists every grant with its source, ports, database and role, who made it and when, and any drift the server found; each grant's firewall rules, anchor lines and `pg_hba.conf` lines are in an expandable block. **Allow...** opens a dialog to pick the source: a jail of the project from a searchable list, an address set, an address or prefix (checked as you type), or the host; it takes optional ports and, for an app with an access block, a database name (the source jail's name by default). *Preview* shows the rule, the `pg_hba.conf` lines and the SQL without the password. After allowing a postgresql source the connection string is shown once with a copy button and forgotten when the dialog closes. **Deny** asks for confirmation and can also drop the role JailOps made. Both buttons are disabled, with the reason, for an identity below operator in the project. The Installed tab of the Apps page links to each app's Access tab.

## How the installation works

`jailops app install NAME [--name JAIL] [--network N] [--storage S] [--project P]` is one operation with the usual
journal: `POST /api/v1/apps/NAME/install` answers `202` with the operation, and the client waits for it. The steps, in
this order, each a step of the operation's plan (`--dry-run` returns them and does nothing):

1. **Create a thin jail** from the image `--image` names (`freebsd-15-1`, its newest generation), or else from the
   FreeBSD image of the highest release the host's kernel can run (of two images of the same release, the first by
   name), so a host with `freebsd-15-1` and `freebsd-15-2` on 15.2 takes `freebsd-15-2`. Without any FreeBSD image the
   request is refused before the operation, and the hint names the two commands that make the base image
   (`jailops image create freebsd-15-1 --release 15.1-RELEASE`, then `jailops image build freebsd-15-1`, with the host's
   release; 15.1 when the server cannot read it); when every FreeBSD image is of a newer release than the host the hint
   lists the images: upgrade the host or name one with `--image`. The image must be a FreeBSD image whose release is at least
   `image.release_min`, compared major.minor. The jail is created in the project, on the network and storage named
   (the project's only grant of a kind is the default), with the `data` paths as **volumes** of the project: one each, named `<jail>-<what the path is called>`
   (`/var/db/postgres` of the jail `db` becomes the volume `db-var-db-postgres`), made by steps of their own before the
   jail (`create-volume-NAME` in the plan) and attached at the path. A volume has its own snapshots, is untouched by a
   generation switch and by the jail's snapshots and rollbacks, and stays when the jail is deleted (`jailops volume
   list`). The volumes start empty and root-owned; the definition's `setup` chowns them. The labels `jailops.app=<name>` and
   `jailops.app.hash=<hash>` are set at creation. The `resources` hints become the jail's limits unless `--memory`,
   `--disk` or `--cpu` replace them. The jail is not started yet: its datasets are **mounted** on the host.
2. **Install the packages from the host** into that root, while the jail has never run, with `pkg -r <root> install -y <names>` through the privileged helper, from
   the FreeBSD repository (`repo: ports`, the host's own repository configuration) or from `pkg.jailops.net`
   (`repo: jailops`: `pkg -r <root> install -y -r jailops <names>`, the repository named `jailops` in the host's
   `pkg` configuration, the one [install.md](install.md) sets up). `-r jailops` limits the whole installation to that
   repository, dependencies included: a JailOps package that needs packages from the FreeBSD repository installs only if
   the definition lists them as `repo: ports` packages too, which go in first (the `ports` group is installed before
   the `jailops` group). The installer assumes the repository exists on the host and does not check it beforehand; a
   host without it fails at this step with pkg's own message, and the jail is kept stopped. For packages of the JailOps
   repository the repository's configuration and key are then copied from the host into the jail (`seed-jailops-repo`), so
   that `jailops update` can update them from inside the jail later. The version that was installed is read with
   `pkg -r <root> query %v <first package>` and becomes the label `jailops.app.version`. The jail is then **started**, and
   `pkg -r` has not run the jail's library trigger, so the library cache of the running jail is refreshed with
   `/sbin/ldconfig -m /usr/local/lib` in the jail.

   **Ownership.** `pkg -r` extracts the files from the host. A package that creates a user in its install script and
   lists directories owned by that user (`/var/log/valkey`, `/var/run/valkey` belong to `valkey`) gets them
   **root-owned** in the jail, or owned by a number that is the host's idea of that user, depending on the package,
   because the user exists only in the jail's password file. Restoring the owners generically is not possible from what
   the packages leave behind: pkg's local database records the paths and checksums of files and the paths of
   directories, not their owners or modes, so `pkg query` cannot report them and `pkg check` has nothing to re-apply.
   A definition therefore gives the directories its services write to their user in `setup`, with `mkdir -p` first for
   a directory that may not exist and `chown` (the catalog: `valkey:valkey` on `/var/db/valkey`, `/var/log/valkey`
   and `/var/run/valkey`; `git:git` on `/usr/local/etc/forgejo`, `/var/db/forgejo` and `/var/log/forgejo`;
   `postgres:postgres` on `/var/db/postgres`; `prometheus:prometheus` on `/var/db/prometheus`; `isms:isms` on
   `/var/db/isms`, `/var/db/isms/private` and `/usr/local/etc/isms/server.env`; `nsd:nsd` on `/var/db/nsd` and
   `/var/run/nsd`). The `data` volumes start root-owned anyway (step 1). What a package's install message leaves to the
   person is the definition's to do as well: the `mail` definition writes `/usr/local/etc/mail/mailer.conf` itself, and
   runs `postfix set-permissions` to give Postfix's programs and queue the owners, groups and setgid bits its own
   file list names.
3. **Enable the services**: `<service>_enable="YES"` and the `rc` knobs are written into the jail's `/etc/rc.conf`
   (read and written through the helper's file operations, below the jail root; a line that already sets a variable is
   replaced, the others are kept). Every value is written double-quoted with `\`, `"`, `$` and the backquote escaped,
   so nothing is read as shell syntax; no `sysrc` and no shell is involved. The jail's own `rc.conf.local` (the network
   JailOps renders) is untouched.
4. **Run the `setup` commands** in the jail, in order, with the in-jail exec of the helper (`jexec`, argv only, no
   shell, 30 minutes each at most); the first failure ends the installation.
5. **Start the services** with `/usr/sbin/service <name> start` in the jail, in the order of the definition, those
   with `start: true`. The command runs through a fixed wrapper, `/bin/sh -c '<script>' jailops-start <name>`, whose
   script is a constant and takes the service name as its positional parameter, never as text:

   ```sh
   out=$(/usr/bin/mktemp -t jailops) || exit 1; /usr/sbin/service "$1" start </dev/null >"$out" 2>&1; rc=$?; [ $rc -eq 0 ] || /bin/cat "$out"; /bin/rm -f "$out"; exit $rc
   ```

   An rc script that starts its daemon through daemon(8) without `-f` (forgejo's) leaves a supervisor that keeps the
   descriptors it was given; given the pipes of the in-jail exec, it would keep them open and the step would wait for
   the end of an output that never comes. With the wrapper the rc script and everything it starts write to a temporary
   file in the jail; when the start fails, the file is printed and the error names `/usr/sbin/service <name> start` with
   that output. The service name is checked against `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` before the command is built.
   The provisioning `services.start` step of a FreeBSD jail uses the same wrapper. `setup` and `health.exec` commands
   stay plain argv: they are the definition's own commands, without a shell. The jail's own start (`jail -c` running
   `/etc/rc`) is detached the same way by `exec.consolelog` in its `jail.conf`: the output of `/etc/rc` goes to
   `/var/log/jailops/jail_<project>_<jail>_console.log` on the host (design section 6).
6. **Run the health check**: `tcp` connects from the host to the port on the jail's first address, `http` requests
   the path there (plain HTTP) and expects the status, `exec` runs the command in the jail; the check is retried once a
   second until it passes or `wait_seconds` have passed. Each attempt is given at most 5 seconds, and never more than
   the time left, so the step ends within `wait_seconds` and one attempt.
7. **Close the jail** (`close-firewall`): the firewall policy `app-<jail>` is created, managed by app access, with
   `default_in: deny`, `default_out: allow` and no rule. From the next reconcile pass (a few seconds) nothing reaches the jail, neither its
   network nor the host, until `jailops app allow` lets a source in ([Who may connect](#who-may-connect)). It comes after
   the health check, which connects from the host; the services have run only for the time of that check before. A
   policy of that name that app access does not manage refuses the installation before it starts (`conflict`).
8. **Take the snapshot `app-installed`** of all the jail's datasets: the point to roll back to before the first
   change (`jailops jail rollback JAIL --all --snapshot app-installed`).
9. **Start with the host** (`enable-autostart`): `boot.autostart` of the jail is turned on, the last step, so that an
   installation that was interrupted or failed, and is kept stopped for inspection, never starts again by itself. The
   jail then comes back at every boot, in the order `jailops boot` shows;
   `jailops config set JAIL boot.autostart false` turns it off for one jail.
10. **Say how to reach it**: the jail's addresses with the `ports` (`endpoint` is `<first address>:<port>`), the
   `data`, `config` and `logs` paths, and the `notes`. Ports marked `expose: true` are recorded as such and nothing
   more: forwarding them through the jail's PF anchor (`proxy` devices) is a later feature.

The events `app.installed` and `app.install.failed` (source `/api/v1/jails/<jail>`) end it, after the ordinary
`jail-created`, `jail-started` and `jail-snapshot-created` of the steps.

**While the installation runs**, the jail refuses every exec, shell and console session (`busy`, "the app is being
installed"). The packages go in from the host while the jail has never run, so what is in its root is the base system of
its image: their install scripts run as root chrooted into that root, and the app's services are not running until the
installation has finished (they are enabled and started afterwards). See [security-model.md](security-model.md).

**What a failure leaves behind.** A failure before the jail's first start (the creation itself, also after the jail was
made, and the start) undoes the creation: the jail and its datasets are deleted again, nothing is left. A failure after the start (a package that does
not install, a setup command or a service that fails, a health check that does not pass within `wait_seconds`) ends the
operation with the jail **stopped and kept** for inspection, with its labels (`jailops.app.version` once the packages
went in): look inside it with `jailops start JAIL` and `jailops shell JAIL`, and `jailops delete JAIL` (it asks you to
type the name, since it destroys the jail's data; `--confirm-data-loss` in a script) before trying again. The error of the operation names the step (`detail.step`), the jail (`detail.jail`) and whether it was kept
(`detail.jail_kept`), and its hint says what to do. A daemon restart in the middle of an installation does the same from
the journal: a jail whose start never completed is deleted (a start that was cut short is rolled back first), one that
was started is stopped and kept.

| Refused before the operation starts | Code |
|---|---|
| the app is not in the catalog | `not_found` |
| the definition is invalid (listed with the reason) | `invalid` |
| the jail name is not a name, or the body names another project | `invalid` |
| a jail of that name exists in the project | `already_exists` |
| no network or storage named and the project is granted none or several | `invalid` |
| the network or storage is not granted to the project | `forbidden` |
| the image does not exist, or the project does not allow it | `not_found` |
| no image named, and there is no FreeBSD image of a release the host can run | `invalid` |
| the image is not FreeBSD, or its release is below `release_min` | `invalid` |
| a project quota would be exceeded | `quota_exceeded` |
| the role is below operator, or the identity has no project scope | `forbidden` |
| a firewall policy `app-<jail>` exists that app access does not manage | `conflict` |

A definition has no parameters: what needs a value is a `config` file the person edits, as `notes` says. The one
generated secret is the password of a database role, made by `jailops app allow` and shown once
([Who may connect](#who-may-connect)).

## Who may connect

An installed app is **closed**: the installation's last firewall step gives the jail the policy `app-<jail>`, which
denies every inbound connection, from the jail's network, from other jails and from the host. Nothing but the jail
itself reaches it until a source is allowed. Three verbs, all in the project of the request:

```sh
jailops app allow APP --from SOURCE [--port N[/proto]]... [--db NAME] [--rotate] [--dry-run] [--project P]
jailops app deny  APP from SOURCE [--drop-role] [--dry-run] [--project P]
jailops app access [APP] [-o json|yaml]       # who may connect; without APP, every installed app of the project
```

`APP` is the jail the app was installed as (`--name` of the installation), not the catalog name. `SOURCE` is one of:

| Source | What it stands for | In the firewall rule | In `pg_hba.conf` |
|---|---|---|---|
| `jail:NAME` | a jail of the same project | `jail:NAME`, so the rule follows the jail at every render | one line per address (`/32`, `/128`), a copy made when the grant is made |
| `set:NAME` | an address set of the project (`jailops firewall address-set`) | `set:NAME`, so the rule follows the set | one line per member, a copy made when the grant is made |
| an address or a prefix | `192.0.2.7`, `192.0.2.0/24`, `2001:db8::/48` | the prefix | the prefix |
| `host` | the host itself: the gateway addresses of the jail's networks, which the host connects from (IPv4, and IPv6 of a routed network; a proxy-mode network has a link-local gateway and is left out) | those addresses | those addresses |

A jail and an address set may have the same name: `jail:` and `set:` say which is meant. A jail whose name is
longer than 29 characters cannot be named in a rule: put it in an address set. The shell completes `APP`, the word
`from` and `SOURCE` (`jail:`, `set:` and `host`, then the jails or the address sets of the project).

The sources are the same words as in a firewall rule (the table of endpoints in [networking-ipv6.md](networking-ipv6.md)),
and `jail:NAME` and `set:NAME` keep their names in the rule: the firewall follows them at every render. `pg_hba.conf` cannot follow
them, so its lines are a copy: when the addresses of a source no longer match them, `jailops app access` and
`jailops doctor` say so (`the addresses of jail:web are now ... but the pg_hba lines name ...`), and allowing again from the
same source writes the lines again.

**A grant lives with the app, in the app's project.** Another project is treated exactly like an external host: only
addresses and address sets cross it, never a jail reference. Do two things need to talk to each other as one system?
Then they belong in the same project. Across projects, write the addresses explicitly on both sides. A grant for a source in another project is an address or a prefix (or an address set that
holds them); the other project's operators allow the app's addresses out in a policy of their own:

```sh
# project shop: the app db lets the jail of project reports in, by its address
jailops app allow db --from 10.30.0.5 --db reports
# project reports: the jail (10.30.0.5) may connect out to the app's address, written on this side too
jailops firewall policy create to-shop-db --default-in deny --default-out allow
jailops firewall rule add to-shop-db out --action allow --proto tcp --to 10.20.0.10 --port 5432 --comment "the shop database"
```

**What one allow does.**

1. **The firewall rule**: one rule per protocol in the managed policy `app-<jail>`, `allow in <proto> from <source>
   to port <ports>`, named `access <source>`. The ports are the definition's (for an app with an access block, the
   block's port only) unless `--port` names others. The policy is an ordinary firewall policy that `jailops firewall
   policy show app-<jail>` displays, with `managed_by: app-access`; changing or deleting it through the firewall routes
   is `forbidden` ("managed by app access"). Its rules are rendered into the jail's anchor after the project's mandatory
   policy and before the jail's own policy, and a jail's own policy cannot turn the closed default back into allow. Like
   every policy change, it takes effect at the next reconcile pass, within seconds.
2. **In the jail, for an app with an access block** (`type: postgresql`):
   - `psql` runs as `postgres` in the jail (`/usr/local/bin/psql -X -q -A -t -v ON_ERROR_STOP=1 -d postgres`) with the
     statements on **standard input**, through the helper's in-jail exec: nothing of them is in an argument vector or
     a process list. It first asks whether the role and the database exist and what `listen_addresses` is.
   - The **role and the database** are named `--db` (default: the source jail's name with `-` turned into `_`;
     required for any other source) and must match `^[a-z][a-z0-9_]{0,62}$`, not `postgres`, `public`, `template0`,
     `template1` or `pg_*`, so no quoting is ever needed (identifiers are quoted anyway). `CREATE ROLE "db" LOGIN
     PASSWORD '<verifier>'` and `CREATE DATABASE "db" OWNER "db"`. The password is 32 characters of `[A-Za-z0-9]` from
     the system's random source; the daemon computes its SCRAM-SHA-256 verifier (4096 iterations, a random salt) and the
     server gets **the verifier, never the password**, so the password is in no statement, log or history of the
     server. A role or a database of that name that JailOps did not make is refused (`conflict`): JailOps never changes
     or drops a role it did not make.
   - `listen_addresses` is set once, with `ALTER SYSTEM`, to what it was plus the jail's addresses (`*` is left as it
     is), and the service named in the block is restarted through the same detached wrapper as a start; later grants
     find it set and only reload.
   - The **managed block** of the `hba_file` (between `# jailops access begin: ...` and `# jailops access end`, appended
     at the end of the file the first time) holds one line per grant and address, `host DB ROLE PREFIX
     scram-sha-256`, sorted; every other line of the file stays as it is, byte for byte. The file is written through
     the helper's file operations, which open the jail root as their root (a symlink of the jail cannot lead them into
     another jail; an absolute one is refused), then given back to `postgres:postgres` with mode `0600` in the
     jail, and the server reads it again (`SELECT pg_reload_conf()`). A block whose markers are broken is refused, never
     guessed at. A person's line above the block that matches the same client first (a `reject` for all) wins, as
     PostgreSQL reads the file top down.
   - The answer carries the **connection string once**: `postgres://ROLE:PASSWORD@HOST:5432/DB?sslmode=disable`, with
     `HOST` the app jail's first IPv4 address. It is printed by the CLI and shown once with a copy button in the console,
     and stored nowhere: not in the grant, the operation journal, the audit log (which records the source, the ports
     and the database name) or the daemon log. `jailops app access` never shows it. `--rotate` gives the role a new
     password (`ALTER ROLE ... PASSWORD`) and prints the new string; allowing again without it changes nothing and says
     that the role exists.
3. **For an app without an access block** (nginx, valkey, prometheus, forgejo, nsd, mail, isms) an allow is the
   firewall rule only. The app itself must listen on the jail's address and accept the client: the answer says so, and
   for valkey also that it binds `127.0.0.1` with `protected-mode yes` until `bind` and `protected-mode` in
   `/usr/local/etc/valkey.conf` are changed, and that `requirepass` should be set first.

**What one deny does.** The rule leaves the policy at once (the firewall first, so nothing new gets in), the grant's lines leave the managed block and the server reloads.
The role JailOps made for it loses its login and its password (`ALTER ROLE ... NOLOGIN PASSWORD NULL`) and its open
sessions are ended; its database and data stay, and a later allow with the same name gives it a login and a new password
again. `--drop-role` drops it instead: in its database `REASSIGN OWNED BY` the role `TO postgres` and `DROP OWNED`, then
`DROP ROLE`; the database is kept and belongs to postgres afterwards. A role another grant uses, or one JailOps did not
make, is left as it is. Denying a source that has no grant changes nothing (`changed: false`).

**The registry.** The grants of an app are an object of kind `AppAccess` in the state store, named after the jail: per
grant the source, what it resolved to, the ports, the database and the lines written, who made it and when; per app the
access block as it was at the first grant (so a deny works after the definition changed) and the roles JailOps made,
with whether their database was made too and whether they may log in. It never holds a password. Deleting the app's jail
deletes its policy and its registry; a jail that is the source of a grant is not deleted or renamed until the grant is denied (the refusal says
`jailops app deny APP --from jail:NAME`), because the rule names it.

**Transparency.** `jailops app access APP` lists each grant with its typed rules, the lines of the jail's rendered
anchor they became (the state labels left out), its `pg_hba.conf` lines, who made it, and the **problems**: a rule
missing from the policy, a line missing from the file (read through the helper while the jail runs), addresses of a source
that the file's lines no longer name. `jailops doctor` reports the same as `apps.access` (warn) for every app of the host. Allowing the same
source again writes what is missing back.

**Idempotent, audited, dry run.** Allow and deny of the apps of a host run one at a time and under the jail's lock; both
answer at once, not as an operation (an operation's result is kept, and the connection string must not be). Both are
audited with the source. `--dry-run` resolves the source and asks the server (read-only) what exists, then prints the
rule, the `pg_hba.conf` lines, the SQL with `<generated, shown once>` for the password, and the steps, and changes
nothing; the jail must run for an app with an access block (`busy` otherwise, also for a real allow or deny).

**Apps installed before 0.4.0** have no policy and are open to their network. `jailops app access` says so, and their
first allow closes them to every other source (the answer says that too).

**Fleet sync** declares apps and their grants too (kinds `App` and `AppAccess`, [fleet-sync.md](fleet-sync.md)).

**UNVERIFIED on a FreeBSD host** until the end-to-end test has run it: the `postgresql-access` block of
`scripts/ci-freebsd-e2e.sh` installs PostgreSQL, allows a second jail, connects from it with the printed string and runs
`select 1`, checks that a jail that was not allowed cannot, and checks the closure after a deny. Not covered by it: the
restart of a server whose `listen_addresses` was already set by hand, IPv6 sources and address sets.

## Logs, updates, upgrades

- **Logs.** A definition declares its log files and directories; reading them is a separate feature (the jail logs
  API) and the catalog only says where they are.
- **Updates.** The packages of an app follow the jail's ordinary update policy ([upgrade.md](upgrade.md)):
  `updates.packages` upgrades them with `pkg upgrade` inside the jail, `updates.os` moves the jail to a newer image
  generation with the data datasets untouched. There is no separate app update; the catalog's `version` is what the
  definition was written against, not a pin.
- **Rollback.** `jailops jail rollback JAIL --all --snapshot app-installed` is the way back to the fresh installation.

## Deliberately out of scope

- **Parameters** beyond generated secrets: a definition has no variables and no templates. What needs a choice (a
  domain, a port, a password policy) is a `config` file the person edits, and `notes` says so.
- **Dependencies between apps** (a forge that needs a database): each app is one jail. `jailops app allow DB --from
  @FORGE` makes the database's side (role, database, `pg_hba.conf`, firewall) and prints the connection string; writing
  it into the consumer's configuration is the person's step, as its `notes` say.
- **Multi-jail apps**: one definition, one jail.
- **Fetching catalogs**: the catalog comes with a package, signed, or from the operator's own files. The daemon makes
  no request for it.

## Write your own app

An app usually starts on a host: you make a jail, install the packages, enable the services, fix what does not work,
and end with a jail that runs the software well. A definition is that work written down, so that `jailops app install`
repeats it on any host. The loop:

1. **Start a definition**, either from scratch or from the jail that runs it:

   ```sh
   jailops app new memcached --package memcached --service memcached --port 11211/tcp --category database
   jailops app export cache --file cache.yaml     # from the running jail "cache" of the current project
   ```

   `jailops app new NAME [--package PKG[,PKG...]] [--service NAME] [--port N[/proto]] [--category C] [--dir DIR]`
   needs no server. It writes `DIR/NAME.yaml` (`DIR` is `.` by default) with every key of the format, a short comment
   on each (what it does, and the traps: `pkg -r` installs from the host and leaves the directories of a package's
   user to root, the installer runs `ldconfig` and starts services through a wrapper itself, `sysvipc` is for servers
   that need it) and the values the flags give; `--package`, `--service` and `--port` repeat or take commas. It also
   writes `NAME.svg`, a neutral placeholder icon (a rounded square with the first letter), unless an icon of that name
   is there. It refuses to write over an existing `NAME.yaml` without `--overwrite`.

   `jailops app export JAIL [--project P] [--file FILE]` asks the daemon for a draft of a running FreeBSD jail and writes
   it to `FILE` or the standard output (`--overwrite` writes over an existing file; `-o json` or `-o yaml` prints the
   draft as data instead, `-o` being the output format as everywhere else). The draft is read, nothing in the jail changes: the packages installed on purpose (their
   dependencies come with them; `pkg -r <root> query` on the host), the services enabled in the jail's `/etc/rc.conf`
   and their knobs, the ports something listens on now (`sockstat` in the jail; a port bound to localhost only says
   so), the jail's volumes as `data` paths, the names of the files below `/usr/local/etc` and `/var/log` that changed
   after the last package operation (`find -newer /var/db/pkg/local.sqlite`) as `config` and `logs`, and `setup` lines
   that give the volumes, the log directories and `/var/run/<service>` the owners they have in the jail (`stat`). What
   belongs to the base system (sshd, syslogd, cron, base log files) is left out. **It never holds a secret**:
   configuration files are listed by name and never read, a knob whose name looks like a secret (`pass`, `secret`,
   `token`, `key`, `cred`) is written as `TODO`, and a knob with a shell expansion is left out. The comment at the top
   of the file lists what was found and what was left out. The jail's state that is not on a volume (a database under
   the jail's own `/var/db`) is not found: give it a `data` path. Operator role; the request is audited; a stopped jail
   is refused (`busy`).

2. **Edit it.** Both commands mark with `TODO` what a person has to decide: the summary, the description, the license,
   the health check (a draft proposes a tcp check on the first port that is not on localhost), the notes, and the
   sections that are guesses. The file parses and validates as it is, so you can install it before it is finished.

3. **Check it**: `jailops app validate NAME.yaml` runs the daemon's parser and validator offline and reports, besides
   every problem, **each line that still holds a `TODO` marker** as `FILE: line N: replace TODO` (a marker in a
   comment counts too: delete the comment once it is done). Only `validate` looks for the markers; the daemon does not,
   which is what lets a draft install while you work on it.

4. **Try it on a host**: copy `NAME.yaml` and its icon into `/usr/local/etc/jailops/apps` (`apps.local_dir`) and run
   `jailops app list --source local`, then `jailops app install NAME`. A local definition of the same name as a
   packaged one replaces it on that host, which is how you test a change to a packaged app.

5. **Iterate**: `jailops delete --stop NAME` (type the name to confirm), edit the file in place, `jailops app install NAME` again. A failed installation
   keeps the jail stopped for inspection (`jailops start NAME`, `jailops shell NAME`); the error names the step.

6. **Validate again**, until `jailops app validate NAME.yaml` prints `valid: 1 definition(s), 1 icon(s)`.

7. **Send it**: add `NAME.yaml` and `NAME.svg` to `main/jailops-apps/apps/` of the packages repository in a pull
   request ([Adding or changing an app](#adding-or-changing-an-app); its `CONTRIBUTING.md` has the review checklist
   and `scripts/new-app.sh NAME` runs `jailops app new` in the right directory).

### A worked example: memcached

memcached (`databases/memcached`) is small: one package, one rc.d service, one TCP port, no state on disk. Start with

```sh
jailops app new memcached --package memcached --service memcached --port 11211/tcp --category database
```

and fill in the marked lines. memcached keeps nothing on disk, so `data`, `config` and `logs` become `[]` (it logs
nothing by default); its rc script runs it as `nobody`, which writes its pid file into `/var/run/memcached`, a
directory `pkg -r` leaves to root, so the setup creates it and gives it to `nobody`. The finished file (it is
`internal/apps/testdata/authoring/memcached.yaml`, with the icon `app new` wrote, and a test checks that it validates
with no marker left):

```yaml
version: 1
name: memcached
title: memcached
summary: Distributed in-memory object cache, memcached from the FreeBSD packages.
description: |
  memcached keeps objects in memory for other programs and forgets them when it
  restarts. It has no authentication: anything that reaches the port can read and
  write the cache, so it listens on the jail's network only.
category: database
homepage: https://memcached.org/
license: BSD-3-Clause
icon: memcached.svg
image:
  os: freebsd
  release_min: "15.1"
packages:
  - name: memcached
    repo: ports
    version: "1.6.39"
services:
  - name: memcached
    rc:
      memcached_flags: "-l 0.0.0.0 -m 64"
    start: true
ports:
  - name: memcached
    port: 11211
    proto: tcp
    description: The memcached protocol, without authentication.
    expose: false
# memcached keeps nothing on disk
data: []
config: []
logs: []
# The rc script runs memcached as nobody, which writes its pid file into
# /var/run/memcached; pkg -r leaves that directory to root, if it creates it at all.
setup:
  - [/bin/mkdir, -p, /var/run/memcached]
  - [/usr/sbin/chown, "nobody:nobody", /var/run/memcached]
sysvipc: false
health:
  tcp: 11211
  wait_seconds: 30
resources:
  memory: 128M
  disk: 1G
  cpu: "1"
notes: |
  memcached listens on port 11211 of the jail's address, 64 MB of cache.
  Change the size or the address with memcached_flags in the jail's
  /etc/rc.conf (jailops exec NAME -- sysrc memcached_flags="-l 0.0.0.0 -m 256"),
  then jailops exec NAME -- service memcached restart.
```

Then on a FreeBSD 15.1 host:

```sh
cp memcached.yaml memcached.svg /usr/local/etc/jailops/apps/
jailops app validate /usr/local/etc/jailops/apps/memcached.yaml   # valid: 1 definition(s), 1 icon(s)
jailops app list --source local
jailops app install memcached
```

**UNVERIFIED**: this example has not been installed on a FreeBSD host. What a first run there must confirm: that the
rc script reads `memcached_flags` and runs the server as `nobody` with its pid file in `/var/run/memcached`, that the
health check passes on 11211, and that the version is the one of the quarterly packages. `jailops app export` has not
run against a real jail either: the output of `sockstat`, `find` and `stat` in a jail and the repository `pkg query %R`
reports for a package `pkg -r` installed are parsed as their manual pages describe them.

## Adding or changing an app

The definitions and their icons are in `main/jailops-apps/apps/` of the packages repository
(`jailops/jailops-packages`); its `README.md` and `docs/ADD-A-PACKAGE.md` have the details. A new or changed app is one
pull request there:

1. Add or edit `NAME.yaml` (and its icon) in `main/jailops-apps/apps/`, following the format above.
2. Raise `version:` in `main/jailops-apps/pkgops.yaml` by hand (`0.4.0` to `0.5.0` for a new app, `0.4.1` for a fix). A
   published version is never rebuilt, so a change without a new version is refused by the repository's checks.
3. Check it locally with the client, which needs no server, no network and no root:

   ```sh
   jailops app validate main/jailops-apps/apps
   ```

   It runs the daemon's own parser and validator on every `*.yaml`, reads the icon each definition names, reports every
   line that still holds a `TODO` marker of `app new` or `app export` (`FILE: line N: replace TODO`), prints every
   problem as `FILE: reason` and exits 2 when there is one; otherwise it prints one line
   (`valid: 8 definition(s), 3 icon(s)`). `-o json` gives the counts and the problems. It also takes single files and
   several paths, and `jailops app validate /usr/local/share/jailops/apps` checks what a host has.
4. Open the pull request. Its CI builds `jailops` at the release the repository packages (the version of
   `main/jailops/pkgops.yaml`) and runs the same command on the directory before it builds the package, so a
   definition must be valid for the daemon that hosts actually run. Merging to `master` publishes the new
   `jailops-apps`; no JailOps release or tag is involved.

A definition that needs a newer daemon (a new key or category) is listed as invalid on older hosts (see the trust model),
so it waits for the JailOps release that understands it. When the format itself changes, refresh the reference copy in
`internal/apps/testdata/catalog/` in the same JailOps change.

## The catalog

The catalog holds eight definitions. The first five were written against the FreeBSD 15 quarterly packages of
October 2026: package names, rc.d names, rc.conf knobs, ports and paths were taken from the packages themselves. The
three later ones were not: their sources are named in the table and below, and what could not be checked is marked.

| App | Category | Packages (repository) | Ports | Health check | Source of the facts |
|---|---|---|---|---|---|
| `postgresql` | database | `postgresql18-server` (ports) | 5432/tcp | `pg_isready` | the package |
| `nginx` | web | `nginx` (ports) | 80/tcp, 443/tcp | HTTP `/` | the package; ran on a host |
| `valkey` | database | `valkey` (ports) | 6379/tcp | `valkey-cli ping` | the package |
| `forgejo` | devops | `forgejo16` (ports) | 3000/tcp | tcp 3000 | the package |
| `prometheus` | monitoring | `prometheus3` (ports) | 9090/tcp | HTTP `/-/healthy` | the package; ran on a host |
| `isms` | security | `isms` (jailops), `openssh-portable` (ports) | 8080/tcp (UNVERIFIED) | none: not started | the package recipe of the JailOps repository, its `server.env.sample` and install message |
| `nsd` | network | `nsd` (ports) | 53/udp, 53/tcp | tcp 53 | NSD's documented configuration; the FreeBSD package not inspected |
| `mail` | communication | `postfix`, `dovecot` (ports) | 25, 587, 143, 993 (tcp) | tcp 25 | Postfix's and Dovecot 2.3's documented configuration and the Postfix package's install message; the packages not inspected |

**isms** (featured: the platform's own information security management system) installs the package `isms` from the
JailOps package repository (and `openssh-portable` from the FreeBSD packages, because the thin image has no `ssh-keygen`, which the signing key needs): `pkg -r ROOT install -y -r jailops isms`, which assumes the host's pkg configuration has the
repository named `jailops` (the one [install.md](install.md) sets up for JailOps itself). The package has no
dependencies. The paths (`/usr/local/bin/isms`, data `/var/db/isms`, `/var/db/isms/private` for the signing key,
`/usr/local/etc/isms/server.env` mode 0600 owner `isms`, log `/var/log/isms.log`), the user `isms`, the rc.d service
`isms` (daemon(8), restarted 5 seconds after it exits) and the first-run steps come from the package recipe and its
install message. The definition enables the service but does not start it, and generates nothing: isms needs a
PostgreSQL database, and its master secret `ISMS_SECRET` is empty until the operator sets it (isms refuses to start
without it). The setup only gives the data directory, the key directory and `server.env` back to `isms` with the modes
the package intends. Its `notes` are the manual steps: a role and a database in a `postgresql` jail with a `pg_hba.conf`
rule for the isms jail's address, `DATABASE_URL`, `ISMS_BASE_URL`, `ISMS_SIGNING_EMAIL` and the secret in `server.env`,
the signing key, `isms server migrate` as `isms`, then `service isms start`. The database's side is one command,
`jailops app allow ISMS-DB --from jail:ISMS --db isms`, which makes the role, the database, the `pg_hba.conf` line and the
firewall rule and prints the connection string for `DATABASE_URL`; the rest stays the person's. The end-to-end test installs it, runs these steps
against a `postgresql` jail and sees port 8080 answer with a 2xx or 3xx status. **UNVERIFIED**: what exactly the program
answers there, and therefore the health path, which the definition leaves out (8080 is the default of `isms server
serve`; the FreeBSD service passes no `--addr`). Until `server.env` is complete, a restart of the jail starts the
service, which exits and is restarted by daemon(8) every 5 seconds with the reason in `/var/log/isms.log`.

**nsd** is the authoritative DNS server NSD (`dns/nsd`), chosen because one program is both a primary (it sends NOTIFY
and answers zone transfers) and a secondary (it requests them) with a short configuration. The setup writes a starter
`nsd.conf` and one zone, `example.com`, under `/var/db/nsd/zones` (the package's sample configuration is replaced, a zone file that exists stays), with the state files
on the volume, no database file and no remote control; it gives `/var/db/nsd` and `/var/run/nsd` to `nsd`, then runs
`nsd-checkconf` and `nsd-checkzone`, so a configuration the packaged release rejects ends the installation at that
step. The ports are 53/udp and 53/tcp; the definition format has had `proto: udp` since version 1, and ports are recorded
only (forwarding is a later feature), so nothing else changes for UDP. The `notes` give the lines for a primary
(`notify`, `provide-xfr`) and a secondary (`allow-notify`, `request-xfr`) and recommend a TSIG key. The end-to-end test
installs it, runs `nsd-checkconf` and asks the jail for the SOA of `example.com` over UDP and over TCP. **UNVERIFIED**:
that NSD logs to syslog facility daemon (`/var/log/daemon.log`) and a zone transfer between two jails.

**mail** is a starting point, said so in its summary: Postfix (SMTP 25, submission 587) and Dovecot 2.3 (IMAP 143; 993
disabled until a certificate is configured) for one domain, `example.com` until changed, with system users whose homes
lie on the volume `/home/mail` (mail goes to `~/Maildir`), the queue on the volume `/var/spool/postfix`, and no TLS,
spam filter, DKIM signing or webmail. `sendmail_enable="NONE"` keeps the base system's MTA off; the setup copies
`main.cf` and `master.cf` from their samples when missing, sets the domain and Dovecot authentication for submission
with `postconf -e`, `-M` and `-P`, runs `postfix set-permissions` and then `postfix check`, builds the aliases with
`postalias`, writes `/usr/local/etc/mail/mailer.conf` so that `/usr/sbin/sendmail` is Postfix's, writes `dovecot.conf`
when absent and checks it with `doveconf -n`. The `notes` add a user, set the domain, add TLS to both servers, and list
the DNS records (A/AAAA and PTR, MX, SPF, DMARC; DKIM needs a signing service this app does not include). The end-to-end test installs it
(the packaged Dovecot is 2.3, so the starter configuration uses its syntax; `doveconf -n` fails the installation if it
is not), starts both services and reads the Postfix `220` and Dovecot `* OK` greetings. **UNVERIFIED**: PAM
authentication of system users through `/etc/pam.d/other`, delivering a message to a local user and reading it over
IMAP, and TLS.

The reference copy of the catalog (`internal/apps/testdata/catalog/`) is validated by a test on every build, the
catalog itself by `jailops app validate` in the CI of the packages repository, and the installation is tested
end to end against in-memory fakes of ZFS, the jail runtime and `pkg`. What is checked against the privileged helper's
real rules: the argument vectors the builders of `internal/apps` make (`pkg -r ... install`, `pkg -r ... query`), the
rc.conf path and the in-jail commands, in `internal/priv`; the install tests assert that the service sends exactly those
vectors. What is not: the service's own call sites are not run through the helper, and the whole flow on FreeBSD is left
to the end-to-end test below.

**Testing limits.** The fake `pkg` accepts any argument vector with `-r`; the tests compare what it received with the
builders' output instead. The fake log reader keeps the helper's path rules (a jail's `/var/log`, names two segments deep at
most) but not its symlink and file-type checks, which `internal/priv` tests on a real file system. The ZFS fake does not
model a dataset mounted under an unmounted parent; the tests assert the volume datasets' own mountpoint and `canmount=on` instead.

**What ran on a FreeBSD 15.1 host:** `nginx` and `prometheus` installed and ran. That run found the three problems
this version addresses: PostgreSQL's `initdb` failed without System V shared memory (`sysvipc`), Valkey could not open
its log file in a root-owned `/var/log/valkey` (the `setup` lines above), and forgejo failed because the daemon(8)
supervisor of its rc script held the pipes of the in-jail `service forgejo start` and, at the next start, of `jail -c`
(the start wrapper and the console log).

Verified on a FreeBSD host with the end-to-end test: PostgreSQL with `sysvipc`, Valkey with its setup lines, forgejo with
the start wrapper and the console log, and `isms`, `nsd` and `mail` as far as stated above. The end-to-end test
(`scripts/ci-freebsd-e2e.sh`) installs nginx, fetches its default page from the host and stops it; with
`JAILOPS_E2E_APPS="postgresql valkey prometheus forgejo nsd mail isms postgresql-access"` (or any of them) it then installs each named
app in its own block and checks it: `select 1` through `psql` as `postgres`, `valkey-cli ping` answering `PONG`,
Prometheus' `/-/ready`, forgejo's port 3000 answering 200 or a redirect to its installer; for `nsd`, `drill` from the
host asks the jail for the SOA of `example.com` over UDP and over TCP and `nsd-checkconf` passes in the jail; for `mail`,
Postfix's `220` greeting on port 25 and Dovecot's `* OK` on port 143 (`nc` that sends `QUIT` or `LOGOUT` one second after connecting, because Postfix refuses commands that arrive before its greeting) and the
`sendmail` line of `mailer.conf`; for `isms`, the steps of its notes with a `postgresql` jail of its own (`isms-db`):
`jailops app allow isms-db --from jail:isms --db isms` for the role, the database, `listen_addresses`, the `pg_hba.conf` line
and the connection string, then `server.env`, the secret, the signing key, `isms server migrate`, `service isms start`,
and port 8080 answering a 2xx or 3xx status (curl retries while the program starts). Every app is closed after its
installation, so each check that connects from the host first runs `jailops app allow APP --from host`; the nginx block
also checks that the page does **not** answer before that. `postgresql-access` in the list is a block of its own: a
`postgresql` jail and two plain jails with the PostgreSQL client, `allow` from the first (the dry run first), `select 1`
with the printed connection string from it and a refusal from the second, `app access`, a second `allow` that changes
nothing, then `deny` and the first refused too.
None of these checks reaches the internet. `isms` needs the `jailops` repository in the host's pkg configuration; the
script refuses to start (exit 2) with the reason when it is missing. Then it lists the jail's log files and stops the
jail. CI does not set the variable.
