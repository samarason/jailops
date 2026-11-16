# JailOps web consoles

One repository, several small consoles. Each console is an app in its own directory, shares only
`shared/`, talks to one kind of server, and is embedded in one Go binary. `apps.json` is the registry;
the build tooling, the architecture tests and the Go embed tests are all driven by it.

| App | Binary | Embed package | Dist directory | API role | URL prefixes it may call (under `/api/v1`) |
|---|---|---|---|---|---|
| `host` | `jailopsd` | `internal/webui` | `internal/webui/dist` | host (also hub) | jails, projects, storage, trust, sessions, profiles, updates, images, apps, networks, firewall, backup-targets, backup-policies, backups, restores, remotes, operations, events, audit, users, certificates, resources, logs, plus the shared set |
| `backup` | `jailops-backupd` | `internal/backupui` | `internal/backupui/dist` | backup | repo, hosts, enrolment, snapshots, retention, gc, verify, quarantine, maintenance, deletions, operations, events, audit, plus the shared set |

The shared set (`shared/src/api/core.ts`) is the server info at `/api/v1`, `auth`, `doctor` and `tokens`.
The host console shows only the host side of backup (targets, policies, snapshots, last runs, restore);
the backup console has no jail, image, network or firewall code.

## Layout

```
web/apps.json       registry (single source of truth)
web/shared/         tokens and base CSS, theme, session, events, operations, API client base, generic
                    components (shell, modal, login, token manager), types.gen.ts. No feature views.
web/host/           the host and hub console
web/backup/         the backup-node console
web/templates/app/  scaffold template for a new console; web/templates/go/ for its embed package
web/tests/          architecture tests (boundaries, registry, index.html identity)
web/scripts/        app.mjs (build, dev, typecheck, e2e) and new-app.mjs
```

`types.gen.ts` is generated from `sdk/api` by `go run ./scripts/gen-ts` (check with `-check`).

## Commands (from `web/`)

| Command | Does |
|---|---|
| `npm ci` | install all workspaces |
| `npm run build -- --app host` / `npm run build:all` | build into the app's registered dist directory |
| `npm run dev -- --app backup` | dev server on the app's port; `/api/v1` is proxied to the env var named in the registry (`JAILOPS_API`, `JAILOPS_BACKUP_API`) |
| `npm run typecheck` | vue-tsc for every app (shared is compiled with each) |
| `npm test` / `npm run test:all` | vitest for every app, shared and the architecture tests |
| `npm run e2e -- --app host` / `npm run e2e:all` | Playwright against a demo build of the app (made into `<app>/.demo-dist` by the test's web server) |
| `npm run new-app -- <name> [--role host\|hub\|backup] [--title T] [--label L] [--binary B] [--prefixes a,b]` | scaffold a console |

In a demo build (`JAILOPS_DEMO_BUILD=1`, which the end-to-end tests make; `JAILOPS_DEMO_BUILD=1 npm run dev -- --app host`
for the dev server) append `?demo` to any URL to run
a console on canned data without a server (`?demo=login` starts signed out). The console a binary embeds is never a
demo build: it ignores `?demo`.

## Images and the base image (host console)

An image is one FreeBSD release (`freebsd-15-1`); its generations are the patch levels. `/images` shows each image as a
card (the nightly upgrade in `src/components/ImageAutoUpgrade.vue`) with its release, its number of generations and its nightly auto upgrade: **Upgrade automatically every night**, the
time (HH:MM in the host's time zone, 03:00 by default) and **Also upgrade the packages inside the jails** (on when the
upgrade is turned on), saved with `PATCH /images/{name}` and `{spec: {auto_upgrade}}`. The card shows the next run and the
latest runs from `status.auto_upgrade` (time, ok, unchanged or failed with the detail, jails moved, upgraded and failed); a
failed latest run is a danger notice on the card, not a toast. Only a global admin changes it; everyone else sees it
read-only. **Upgrade image and jails** (by hand, at once) stays as it was.

**Create image** (`src/components/ImageCreateDialog.vue`, the fields in `ImageFields.vue`, the checks in `lib/images.ts`)
posts the definition and then, unless the box is cleared, builds the first generation and follows that operation with its
progress (`composables/imageCreate.ts`; a failed build keeps the definition and Try again builds it again). The release
defaults to the host's (`environment.kernel_version` of `GET /api/v1` without the patch level) and nothing older than 15.1
is offered; the architecture is the host's. The name is proposed from the release (`freebsd-` major `-` minor, so
15.1-RELEASE gives `freebsd-15-1`) and follows the release select until it is edited. No alias is offered. The nightly auto
upgrade is a checkbox of the dialog, off until it is ticked. An empty page offers the dialog as its first
action, `/images?create=1` opens it, and the install dialog and the jail form offer it when there is no image; both list
the images with their release (`freebsd-15-1 (15.1-RELEASE)`) and preset the newest release the host can run. The first-run
wizard's Base image step uses the same fields and composable, with one line on what the auto upgrade does.

When the host runs a newer release than the newest FreeBSD image (the host on 15.2, only `freebsd-15-1`), the Images page
and the Overview show a quiet notice (`src/components/NewReleaseNotice.vue`) with a button that opens Create image filled in for the host's release: a new release
is a new image, and existing jails stay on theirs.

In the demo, an image whose name starts with `fail` fails to build, one that starts with `flaky` fails at its first try;
`?demo=noimage` is the demo without images and `?demo=newrelease` a host on 15.2 with only `freebsd-15-1`. The demo's
`freebsd-15-1` has the nightly upgrade on with an ok run and two unchanged ones; `?demo=nightlyfail` adds a failed night on
top. The demo accepts the PATCH and checks the time as the server does.

## Apps and logs (host console)

`/apps` is the app catalog and its Installed tab, `/apps/:name` one definition with the install dialog
(`src/views/AppsView.vue`, `AppDetailView.vue`, `src/components/AppInstallDialog.vue`). The install follows the
operation like every other dialog (`runOp`), with a poll that also reads the operation's progress: the server sets it
after each step, so `lib/apps.ts` maps it onto the step list of the dry run. The jail's Logs tab
(`src/components/JailLogsTab.vue`) reads `/jails/{name}/logs`; following polls once a second from `next_offset`.
`lib/logs.ts` holds the follow state and strips terminal control characters; log lines are only ever rendered as
text. The demo serves a catalog, installations and growing log files (`src/demo/apps.ts`); `?demo` jail names that
start with `fail` show a failed installation.

`/logs` (`src/views/LogsView.vue`) reads `GET /logs`: the ends of many jails' files merged by time, filtered from the
address (`?jail=web&since=1h`, `project=*` for every project) and followed every two seconds with the reply's `next` map as
the cursor (`lib/logs.ts`). Its Forwarding tab, for a global admin, edits the sink list of `/logs/forward`
(`lib/logforward.ts` checks the form); the demo serves both from `src/demo/logs.ts`.

## Search, labels and the shell (host console)

**Quick switcher** (`src/components/QuickSwitcher.vue`, the index in `composables/search.ts`, the ranking in
`lib/search.ts`): `Ctrl+K` (`Cmd+K`) anywhere except inside the terminal, `/` where no text is typed, or the Search
button at the top of the side bar (the top bar on a phone). It searches the jails of the current project (name, image,
addresses, labels as `key=value`, the app of an installed jail), the app catalog, images, networks, projects, storage
and the console's pages, with the label terms of the jail filter (`env=prod`, `team:`, `-tier=edge`). **Every project**
searches the jails of all the projects the identity may use (choosing one switches to its project, as the project
switcher does); the choice is remembered. Matches rank whole name, prefix, start of a part, anywhere, then letters in
order (in the name only); each group shows its best few and says how many more a refined search would show. An empty box
shows the recent items (jails opened from it or visited, kept in `localStorage`, never required) and the pages. The lists
are loaded when the box opens and again after a change event, a project switch or a minute; ranking runs in memory, so
thousands of jails stay fast. It is a dialog with a combobox and a grouped listbox: the focus stays in the box, the arrows
move the active option, Enter opens it, Escape closes and gives the focus back, the number of results is announced. A
jail row has its quick actions: **Shell** (`Shift+Enter`), **Logs** (`Alt+L`) and **Start** or **Stop** (`Alt+S`; stop
asks first, tier 2).

**Labels** (`src/components/LabelChips.vue`, `JailLabels.vue`, `JailFilter.vue`, `BulkLabelDialog.vue`, the rules and
the filter language in `lib/labels.ts`, [docs/labels.md](../docs/labels.md)): chips in the jail list (the first two by
the keys people look for, env, app, team, then `+N`) and under the jail's name; a chip filters the list. The list's
filter box reads `key=value`, `key:`, `-key=value` and words, suggests keys and values, and keeps the filter in
`?q=` (and the state in `?state=`): a chip, a state, a suggestion or Enter is a history step, typing is not. The last
filter is remembered per user and project. **Edit labels** on the jail page and **Labels** for the selected jails send
merge patches of `metadata.labels` (`null` removes a key); the label rules are those of `sdk/api/text.go`, tested on the
same cases (`sdk/api/testdata/labels.json`). Keys starting with `jailops.` are shown but not edited. Only an admin of the
project is offered the editors.

**Shell**: a running jail has a Shell button in its list row and its page header, and the switcher's Shift+Enter;
`/jails/NAME/shell` is the shareable address (it opens the Console tab and connects at once, the request is then taken
off the address so a reload does not open a second session). A stopped jail offers **Start and open shell**: start is
tier 1, the console connects as soon as the jail runs. The Console tab says which shell runs as whom and shows the same
shell's command line (`jailops shell NAME --project P`) with a copy button. The tab and the buttons are offered only when
the server has `jail_console` and the identity is an operator or admin of the project, as `jailops exec` needs; the server
checks it again. A jail page opens on the tab used last for that jail.

In the demo the project `web` has thirteen jails with labels (`env`, `team`, `app`, `role`; `api` carries ten), the
staging project two; the demo accepts the label patch and checks the rules as the server does.

## Firewall (host console)

`/firewall` has three tabs, Policies, Address sets (`?tab=sets`) and Test (`?tab=test`, `/firewall/test`; extension `firewall_test`, operator or admin), all of the current project. The Test tab (`src/components/FirewallTest.vue`, the pure logic in `lib/fwtest.ts`) asks `POST /firewall/test` for a From and a To (a jail, an address or `host`), a protocol and a port, and draws the answer as a flow of hops with what decided each; the form is kept in the query, and the demo (`src/demo/fwtest.ts`) walks its own policies the way the server walks the anchor. **Create policy** and
**Add set** open a dialog; a policy is edited rule by rule and saved with If-Match, and deleted with its name typed while
jails use it (the server refuses until they use another policy). An address set (`src/components/AddressSetCreateDialog.vue`,
the checks in `lib/firewall.ts`) has a name (`^[a-z][a-z0-9_]{0,23}$`), members (one address or CIDR per line; empty is
allowed) and includes (other sets, comma separated); the form refuses what the server refuses, an include that does not
exist or closes a cycle among them. The editor of a set says which policies and sets use it; **Delete set** lists them
and shows the server's refusal (`busy`, with the policies in `detail.policies`) while any is left. A project without sets
shows an empty state with **Add set**. The demo checks names, members, includes and cycles as the server does, refuses a
set in use and a policy in use or mandatory, and keeps what was created until the page is reloaded.

## Rename (host console)

**Rename network**, **Rename image**, **Rename project**, **Rename jail**, **Rename policy**, **Rename address set** and
**Rename profile** sit with the other actions of the object: a network's card, an image's card, the project's page, the
jail's page header, the policy and set editors of `/firewall`, a profile's row. They are offered only when the server
has the `rename` extension and to the role the server asks for (`composables/rename.ts`): a global admin for networks,
images, projects, the host profiles and a project's mandatory policy; an admin of the project for the rest. Storage,
users, certificates, WireGuard, remotes and backup targets and policies have no Rename. A jail is renamed while it is
stopped: on a running (or locked) jail the button stays and says next to it to stop (or unlock) the jail first, and
opens nothing.

The dialog (`src/components/RenameDialog.vue`, the helpers in `lib/rename.ts`) is tier 2: it names what changes before
anything does. The New name field follows the create rule of the kind (`shared/src/lib/names.ts`, `addressSet` for
sets); once the name passes, a dry run (`POST <object>/rename` with `dry_run`, debounced) lists the changes grouped by
what they touch (the object, what refers to it, datasets, firewall anchors, interface descriptions, files, records),
the counts in words and the server's warnings, in a region that is announced politely. A refusal (a taken name, a
running jail, a managed object, a stale generation) takes the plan's place in words. **Rename** runs the rename as an
operation with If-Match (the generation the page read) and follows it; on success the page moves to the new address
when it is the object's own page (`/jails/NEW`, `/projects/NEW`), and the project switcher follows a renamed current
project.

The demo (`src/demo/rename.ts`) answers every kind: the plan from the references it holds (project grants and image
lists, jail networks, policies, profiles, images and boot dependencies, `@set` in policy rules, set includes), the
rename applied to its data with the old name free again, and the server's refusals: the name rule, a name in use, a
running jail (busy, with the hint), a locked jail, the hub-managed project `shop`, and a stale If-Match (conflict). A
new name that starts with `fail` fails the operation and changes nothing.

## Rules, enforced by `web/tests/architecture.test.ts`

- An app imports `shared` and itself, never another app. Shared imports no app.
- An app's API module (`src/api/`) is the only place that talks to the network, and it may only call the
  first path segments listed under `prefixes` of its registry entry.
- Shared code has no feature views and no app-specific endpoints.
- Every `index.html` carries its own title, `jailops-app` and `jailops-role` meta and a visible header, so
  consoles cannot be confused. Titles, ports, dist directories and binaries are unique.
- An app's `vite.config.ts` is one `appConfig('<name>', import.meta.dirname)` call; the output directory
  comes from the registry only.
- Go side (`internal/<pkg>/embed_test.go`): the embedded index belongs to its app and to no other, and
  `dist/.gitkeep` exists so `go:embed` compiles before the first build.

## Add an app

1. `npm run new-app -- inventory --role host --prefixes inventory,items` creates `web/inventory`
   (router, layout on `shared`, demo mode, tests, e2e smoke), registers it in `apps.json` and `package.json`,
   and creates `internal/inventoryui` (embed handler and tests) if it does not exist.
2. `npm install`, then `npm run build -- --app inventory`, `npm run test:all`.
3. Serve `inventoryui.Handler()` from the binary and fix `binary`, `embedPackage` and `prefixes` in the registry.
4. Put every endpoint in `src/api/endpoints.ts`, canned data in `src/demo/`, copy in `src/i18n/en.ts`.

## Interface conventions (shared by every console)

- **Confirmations** (`shared/src/composables/confirm.ts`, `ConfirmDialog.vue`): tier 1 runs at once (start, snapshot,
  preview); tier 2 asks and names what is affected (stop or restart a running jail, image upgrade, uninstall an app);
  tier 3 needs the name typed (delete a jail, data rollback, delete a project, a volume, a network with jails, a
  firewall policy in use). The button label alone is never the warning.
- **Names**: `shared/src/lib/names.ts` holds the server's name rules and their hints; a form never writes its own regex.
- **Forms** (`composables/form.ts`): required fields carry `*`; a field shows its message once touched or after a
  submit; a primary button is never silently disabled: the reason sits next to it and a submit focuses the first
  field with a problem.
- **Tabs** (`composables/tabs.ts`, `TabBar.vue`): the tab is in `?tab=`, the default tab is left out of the address,
  arrow keys, Home and End move between tabs.
- **Tables** on a phone: class `rtable`, a `data-label` on every cell, the row buttons in `td.actions` (a
  `.row-actions` group elsewhere).
- **Time and units**: `stamp()` / `TimeStamp.vue` (ISO date and time in UTC, the relative time in the tooltip),
  `bytes()` (binary units, a decimal only when it is not zero), `plural()` for counts, `sentence()` for words that come
  from the server. API paths and error codes are never shown as such: `lib/describe.ts` turns them into links and words.
- **Verbs**: Create and Delete for objects (jail, network, project, policy, token, user), Add and Remove for members
  of a list (a peer, a rule, a sink, a nameserver), Revoke for access (a token, a session, a certificate), Install and
  Uninstall for apps. A button says the verb and the object ("Create network"), a dialog title says it with the name
  ("Delete jail web"). Spelling is British, as in the documentation (neighbour, enrol, utilisation).
