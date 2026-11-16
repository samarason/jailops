# Labels

A label is a `key=value` pair on a jail (and on images, networks, projects and other objects). JailOps itself gives no
meaning to most labels: they are how you group jails (`env=prod`, `team=web`, `app=nginx`) and how other parts select
them. What selects jails by label:

- backup policies (`jailops backup policy create nightly --selector backup=yes`, [backup-restore.md](backup-restore.md));
- log forwarding (`sources.labels` and `exclude_labels`, [logging.md](logging.md)) and the merged log view
  (`jailops logs -l env=prod`);
- bulk actions of the command line: `jailops start|stop|restart|delete -l env=prod`;
- rollouts of `jailops-sync` ([fleet-sync.md](fleet-sync.md)).

A changed label changes what these select: removing `backup=yes` from a jail takes it out of the nightly backup.

## The rules

The server checks every label when it changes (`invalid` otherwise); the console checks the same rules before it sends
anything, against the same test cases (`sdk/api/testdata/labels.json`).

| Part | Rule |
|---|---|
| key | letters, digits, `-`, `_` and `.`, beginning and ending with a letter or digit, at most 63 characters; an optional prefix of letters, digits, `-` and `.` (at most 253) and a `/` before it: `env`, `jailops.app`, `example.org/tier` |
| value | at most 253 bytes of printable UTF-8: no control characters, no characters that reverse or hide text; it may be empty |
| count | at most 64 labels on one object |

Keys that start with `jailops.` are set by JailOps: an app installation writes `jailops.app` (the app),
`jailops.app.version` and `jailops.app.hash`. The console shows them but does not offer to change them; the command
line can, which turns the jail into one the app pages no longer know.

Changing labels needs the **admin** permission in the jail's project (it is a `PATCH` of the jail); reading them is
part of reading the jail.

## Command line

    jailops label web env=prod team=web        # set or change
    jailops label web tier-                    # remove
    jailops label web                          # list
    jailops create web --image freebsd-15-1 --storage default --label env=prod --label team=web
    jailops list -l env=prod -l team=web       # every label must match
    jailops stop -l env=staging                # a bulk action over the jails the labels select

Over the API, a merge patch changes the labels and nothing else (the console does this): `PATCH /api/v1/jails/{name}` with `{"metadata": {"labels": {"tier":
"edge", "old": null}}}` sets `tier`, removes `old` and leaves every other label as it is. A list narrows by label with
`GET /api/v1/jails?label=env=prod` (repeatable, all must match).

## In the console

- The jail list shows the labels of each jail as chips (the first two, then `+N`); a click on a chip filters the list
  by it.
- The filter box of the list reads `env=prod` (the label has this value), `env:` (the jail has the label, any
  value), a leading `-` for the opposite (`-team=web`, `-backup:`, `-mail`) and plain words, which match the name,
  the image, the addresses and the labels' text. Every term must hold; `"..."` keeps a value with blanks together.
  While a key is typed the box suggests the keys the project's jails carry, after `key=` their values with the
  number of jails. The filter is in the address (`/jails?q=env%3Dprod%20-team%3Dweb&state=running`), so a link
  shows the same list and the back button undoes a chip; the last filter is remembered per user and project in the
  browser and comes back on a bare `/jails`.
- The jail page shows all labels under the name; **Edit labels** adds or changes one label at a time and removes one
  with its `x`, each a merge patch.
- With jails selected in the list, **Labels** sets one label on all of them or removes one from all of them.
- **Create jail** takes labels as `key=value` pairs separated by spaces.
- The quick switcher (`Ctrl+K`) understands the same `key=value`, `key:` and `-` terms.

The console's `key:` and `-key=value` terms filter in the browser; the command line's `-l` takes `key=value` only.
