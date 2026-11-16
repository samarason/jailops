# Logs: reading them all, and sending them elsewhere

JailOps reads the log files of jails through the privileged helper, without SSH and without a shell in the jail. Three
ways use the same reads:

| What | How |
|---|---|
| One jail | `jailops jail logs NAME [FILE]` (also `jailops logs NAME [FILE]`), the **Logs** tab of a jail in the console |
| Many jails merged by time | `jailops logs`, the **Logs** page of the console (`/logs`), `GET /api/v1/logs` |
| Forwarding to a syslog server or a webhook | `logging.forward` in `jailopsd.yaml`, `jailops logs forward ...`, the **Forwarding** tab of the Logs page |

Nothing here has run on a FreeBSD host yet; the open points are at the end and in [design.md](design.md) section 16.

## What is read

The files below `/var/log` of a jail's root, at most one directory deep, regular files only, no symbolic link followed
below the jail root; at most 1 MiB from the end of a file per read. That is all the helper's two read operations
(`fs.list_logs`, `fs.tail_file`) allow, and log forwarding needs nothing else from the helper.

- **The default file is `messages`**: what the jail's own `syslogd` writes. Another file with `--file` (the view) or
  `sources.files` (a sink).
- **Logs of installed apps**: a catalog app declares its log files ([apps.md](apps.md), `logs:`). Those below `/var/log`
  are added with `--app-logs` in the view and by default for a sink (`no_app_logs: true` leaves them out). A declared
  directory stands for the files being written in it. Declared paths below `/var/db` or `/usr/local` cannot be read
  through the helper and are left out.
- **A stopped jail** has its root mounted only while it runs: its files are not readable then. The view names it
  ("not mounted", with the dataset to mount); a sink reads it again from where it stopped once it is mounted.
- **Rotated copies** (`messages.0`) are readable one by one with `jail logs`; compressed ones (`messages.1.gz`) are not.
  The view and the forwarder read the file being written.
- **The audit log** of the daemon (who changed what, through which route) can be forwarded as the source `audit`.

## The merged view

    jailops logs                                 every jail of the project, the last 200 lines of messages of each
    jailops logs -f                              and what is written afterwards, until interrupted
    jailops logs --jail web --jail db --since 15m
    jailops logs -l tier=front --grep error      jails with that label, lines containing "error"
    jailops logs --app postgresql --app-logs     the jails installed from an app, with the app's own files
    jailops logs --all-projects -o json          every project you may use, one JSON object per line

Each line starts with `jail/file` (`project/jail/file` with `--all-projects`), coloured per jail on a terminal
(`NO_COLOR` turns it off). `--tail`, `--since` and `--grep` apply to every file before the merge. `-o json` prints
`{"time", "project", "jail", "app", "file", "line"}` per line; `time` is absent for a line without a timestamp.

**Ordering.** A line's timestamp is read from its start: RFC 3339 and the RFC 5424 form (`<PRI>1 2026-11-01T09:30:00Z`
or without the `<PRI>1`), `2026-11-01 09:30:00`, the classic syslog form (`Nov  1 09:30:00`) and the bracketed web
server form. The classic syslog form has no year: it is the current year, or the year before when the date would be
more than a day ahead (a line from 31 December read on 1 January). A line without a timestamp of its own (a stack trace,
a continued message) keeps its place after the line before it in its file, and lines before a file's first timestamp
stay before it; lines with the same time keep the order of their files. Forms with no zone are read in the host's zone.

**Limits.** At most 50 files per read (the first 50 by project, jail and file), at most 1 MiB from the end of each and
at most 2000 merged lines, the newest. Standard error says so when something was left out. `-f` asks every 2 seconds
and continues each file at its own offset (the `next` map of the reply, sent back as `cursor`); a rotated file starts
over. Reading is audited like `jail logs`: once per identity and selection every five minutes. It needs the operator
role in the project, or in every project read with `--all-projects`.

## Forwarding

`jailopsd` itself sends the lines, one loop per sink. There is no agent in the jails and nothing is installed in them.

### Configure

In `jailopsd.yaml` (restart `jailopsd` after a change):

    logging:
      forward:
        - name: central
          type: syslog
          to: tls://logs.example.com:6514
          facility: local3
          ca_file: /usr/local/etc/jailops/logs-ca.pem
        - name: alerts
          type: webhook
          to: https://hooks.example.com/jailops
          token_file: /usr/local/etc/jailops/sinks/hook.token
          sources: {no_jails: true, audit: true}

Or from the command line or the console, which store the list in the daemon's state (the state kind `LogForward`). **A
stored list replaces the file's** until `jailops logs forward reset` (or *Reset to the file* in the console) deletes it.
`jailops logs forward list` says which one is in force.

    jailops logs forward add central --url tls://logs.example.com:6514 --facility local3 [--ca FILE] [--jail NAME]... [-l K=V]...
    jailops logs forward add hooks --url https://hooks.example.com/jailops --token-file /usr/local/etc/jailops/sinks/hook.token --audit
    jailops logs forward set central --facility local5
    jailops logs forward test central            one tagged line, and whether it was delivered
    jailops logs forward status                  sent, queued, dropped, last delivery, failing since, last error
    jailops logs forward remove alerts           asks first; -y in a script
    jailops logs forward reset                   back to logging.forward of jailopsd.yaml; asks first, -y in a script

**A list set from the command line or the console is restricted**, because an administrator's token, not root, sets
it: its `ca_file` and `token_file` must be files directly in `logging.secrets_dir` (default
`/usr/local/etc/jailops/sinks`, a directory owned by root, mode 0750, group `jailops`, which the setup makes),
and its receivers may not be on this host's loopback addresses, link-local addresses (`169.254.0.0/16`, `fe80::/10`,
cloud metadata services among them), the unspecified, multicast or broadcast addresses, or the daemon's own ports
(the console's listener and the ACME challenge listener) on an address of the host. A host name is checked on the
address it resolves to, when the connection is made, so a name that later resolves elsewhere changes nothing; an
address or `localhost` is refused when the list is stored. A receiver on this host, and files anywhere else, go into
`logging.forward` of `jailopsd.yaml`, which only root writes. A list stored through the API replaces the file's whole list, so it cannot
carry such a sink along either: `jailops logs forward add` on top of a file list that has one is refused until that
sink is removed from the stored list (or `jailops logs forward reset` goes back to the file).

`--dry-run` shows what add, edit, remove and reset would send. A sink without a name is named after the receiver's
host (`logs` for `logs.example.com`).

| Key | Meaning |
|---|---|
| `name` | the name rule (hyphens only, at most 32 characters), unique; at most 16 sinks |
| `type` | `syslog` or `webhook` |
| `to` | `udp://HOST[:514]`, `tcp://HOST[:514]`, `tls://HOST[:6514]` for syslog; an `https://` URL for a webhook |
| `facility` | `local0` (default) to `local7`; syslog only |
| `ca_file` | PEM certificates to verify the receiver with (tls, webhook); default the host's roots. Set through the API: a file directly in `logging.secrets_dir` |
| `token_file` | webhook: a file whose first line is the bearer token. Set through the API: a file directly in `logging.secrets_dir` |
| `queue` | lines held while the receiver is away, 100 to 1,000,000 (default 10,000) |
| `sources.projects`, `jails`, `labels` | only these jails (all must match when several are given); all jails when none |
| `sources.exclude_jails`, `exclude_labels` | leave these out (a jail with any one of the labels) |
| `sources.files` | the files of every jail instead of `messages` (names below `/var/log`, at most 8) |
| `sources.no_app_logs` | leave out the files installed apps declare |
| `sources.audit`, `no_jails` | add the audit log; with `no_jails` send nothing else |

The CLI flags are the same: `--from-project`, `--jail`, `-l/--label`, `--exclude-jail`, `--exclude-label`, `--file`,
`--no-app-logs`, `--audit`, `--audit-only`, `--queue`, `--ca`, `--token-file`. Reading and changing the list, its
status and the test need a **global administrator**; every change and test is in the audit log. The test answers whether
the line was delivered and, when it was not, a short class of the failure (`connection refused`, `timeout`,
`dns lookup failed`, `tls handshake failed`, `certificate not trusted`, `HTTP 503`, `target refused: loopback`, ...),
never what the receiver answered; a webhook's answer body is not kept anywhere.

### What is sent

**Syslog** is RFC 5424. A line of `messages` of the jail `nginx` (installed from the app `nginx`) in the project `web`,
with `facility: local3`, on a host named `host1.example.com`:

    <158>1 2026-11-01T09:30:00.000000Z host1.example.com jailops - log [jailops project="web" jail="nginx" app="nginx" file="messages"] Nov  1 09:30:00 nginx sshd[42]: Accepted publickey for deploy

- PRI is facility × 8 + 6: every line is sent as *informational*; a log line carries no severity JailOps could trust.
- TIMESTAMP is the line's own when it has one (the forms of the view), otherwise when it was read. HOSTNAME is the host's
  name, APP-NAME `jailops`, PROCID `-`, MSGID `log` (or `audit` for the audit log).
- The structured data `[jailops project="" jail="" app="" file=""]` says where the line comes from (`app` is empty for a
  jail that was not installed from the catalog; the audit log has `jail=""` and `file="audit"`). `"`, `\` and `]` in
  a value are escaped with a backslash. The SD-ID is `jailops` without an enterprise number; a receiver that insists
  on RFC 5424's `name@number` form for private IDs may reject it.
- MSG is the line as it is in the file, as data: control characters become `\t`, `\n`, `\r`, `\xHH` or `\u00HH`,
  invalid UTF-8 becomes U+FFFD, and the result is cut at 8 KiB. A jail cannot forge a second message or a header.
- Over **udp** one message per datagram. Over **tcp** and **tls** octet-counted frames (RFC 6587 and RFC 5425): the
  length in decimal, a space, the message; the sample above travels as `193 <158>1 2026-...`. The connection is kept
  open, checked before each batch and dialled again after an error.

**Webhook**: `POST` of `application/x-ndjson`, one JSON object per line, up to 200 lines per request, with
`Authorization: Bearer <token>` when `token_file` is set:

    {"time":"2026-11-01T09:30:00Z","host":"host1.example.com","project":"web","jail":"nginx","app":"nginx","file":"messages","line":"Nov  1 09:30:00 nginx sshd[42]: Accepted publickey for deploy"}

`line` is escaped as above. A 2xx answer is a delivery; a redirect, another status or no answer within 10 seconds is a
failure.

### Receiving

- **A syslog server on the same host or a trusted network**: `udp://` or `tcp://`. With the FreeBSD `syslogd` of another
  machine, udp: allow the sender with `-a` in `syslogd_flags` (for example `syslogd_flags="-a 192.0.2.10/32:*"`) and
  route the facility in `/etc/syslog.conf`, for example `local3.*	/var/log/jails.log` (create the file, then
  `service syslogd restart`). FreeBSD's `syslogd` does not listen on tcp. UNVERIFIED: how FreeBSD 15.1's `syslogd`
  stores the structured data of a received RFC 5424 message (`-O rfc5424` keeps the RFC 5424 form in its files).
- **Over the internet**: a syslog server that accepts RFC 5425 (syslog over TLS, port 6514) with a certificate your
  host can verify; give `ca_file` when it is signed by your own CA. Search for `[jailops ` or the `jail=` parameter
  there.
- **Anything with an HTTPS endpoint**: a webhook. Check the bearer token on the receiver.
- To see what arrives during a test, a plain listener is enough: `nc -lk 127.0.0.1 1514` and a sink
  `tcp://127.0.0.1:1514` in `logging.forward` of `jailopsd.yaml` show the frames as they come (that is what
  `scripts/ci-freebsd-e2e.sh` does; the API refuses a loopback receiver).

### Delivery, honestly

- **At least once, while nothing overflows.** Each sink keeps, per file, the offset after the last line it delivered,
  saved in the daemon's database at most every two seconds and when the daemon stops. After a restart the sink reads
  again from there, so lines sent after the last save are sent twice. The audit log is followed the same way by entry id.
- **Delivered means**: udp, handed to the network (nothing confirms it; a datagram can be lost without anyone knowing);
  tcp and tls, written into the connection (a batch written just as the receiver goes away can be lost); webhook,
  answered with 2xx.
- **When the receiver is away** the sink keeps reading into its queue and retries with a backoff that doubles from
  one second up to five minutes, with jitter (a wait between half of that and all of it).
  When the queue is full the **oldest lines are dropped and counted**
  (`dropped`). After a failure the sink resumes from its queue, not from the files.
- **What is never sent**: a sink starts at the **end** of the files (what is written from now on); a jail that appears
  later is read from its beginning (at most its last 1 MiB). When more than 1 MiB is written to a file between two reads
  (two seconds; or while the daemon is stopped) the part before the last 1 MiB is skipped and counted
  (`skipped_bytes`). Rotation is noticed when the file is shorter than the saved offset; a rotated file that is longer
  again before the next read is read from the old offset, which loses or cuts lines (newsyslog rotates far less often
  than every two seconds). Lines are cut at 8 KiB. A line still being written (no newline yet) waits for its end.
- **Order** is the order of each file; lines of different files are not ordered against each other.
- **Status**: `jailops logs forward status`, the console and `jailops doctor` (`logs.forward`, a warning when a sink has
  failed for more than five minutes; info when a plain sink goes to a remote address).

### Limits

At most 16 sinks, 1000 files per sink (more are listed as a warning in the status), 8 files per jail in
`sources.files`, a queue of 100 to 1,000,000 lines (the memory is about the size of the lines held), 1 MiB read per
file and round, files read every two seconds and the jail list every 30 seconds, 10 seconds per delivery.

## Security

- **TLS is verified, always**: the receiver's certificate must chain to the host's roots or to `ca_file` and name the
  host of `to`. There is no option to switch verification off.
- **Plain udp and tcp** send logs, which may hold secrets, in the clear. A plain sink to an address that is not a
  loopback one carries a warning in its status; the daemon logs it when the sink starts and doctor reports it.
- **The token is never in the configuration, the API or the audit log**: `token_file` names a file the daemon reads at
  each delivery. It must be a regular file, owned by root, not writable by anyone else and not readable by others:
  `install -m 0640 -o root -g jailops token /usr/local/etc/jailops/sinks/hook.token`. `ca_file` must be owned by root
  and not writable by group or others. Both are opened from `/` one directory at a time without following a symbolic
  link anywhere in the path, and owner and mode are checked on the open file, so what is read is what was checked.
  Both are checked when the list is stored and again when the sink reads them (the token at each delivery, the CA file
  when a connection is set up).
- **What an administrator's token can point a sink at**: through the API, only files directly in
  `logging.secrets_dir` (so a token cannot make the daemon send the first line of another root-owned file the daemon
  may read to a receiver of its choosing), and only receivers off this host and off the link-local network (see
  Configure). `jailopsd.yaml` is root's and has neither limit.
- **Who may**: the sink list names receivers and files of the host, so reading it, changing it and testing it need a
  global administrator. Reading many jails' logs needs the operator role in each project read, as one jail's does.
- **Log lines are data**: escaped as described above, never interpreted, never run.

## Open points (UNVERIFIED)

The forwarder, the view and the senders are tested in process: the timestamp forms, the merge, cursors, offsets across
a restart and a rotation, the queue and backoff with an injected clock, and the senders against listeners over udp,
tcp, tls (with a test CA) and https. Verified on FreeBSD 15.1 by the block of `scripts/ci-freebsd-e2e.sh`: a tcp listener on
the host, a sink added with the CLI, `logger` in a running jail, and the line arriving with the jail in the structured data
(so a running jail's `messages` is read through the helper while its `syslogd` writes it). Not run on a FreeBSD host: the
forwarder following a rotation by newsyslog, a stopped jail coming back, a tls receiver, and FreeBSD's `syslogd` as a receiver.
