# Roadmap

What is planned, in the order it will be built. This is a plan, not a promise: an item moves when something we learn
says it should, and a release only claims what was tested ([CHANGELOG.md](../CHANGELOG.md) says what shipped).

## 0.7.0: more than one host, and knowing what happens

The goal of 0.7.0 is that a small fleet of hosts can be run with the same ease as one host, without a cluster to
operate and without pretending that jails can be live-migrated.

1. **Move a jail to another host.** `jailops jail move NAME --to HOST`: stop, send the ZFS snapshots (incrementally when
   an earlier copy is there), start on the other host, run the health check, and keep the old copy until the new one is
   confirmed. It is not live migration (a jail shares the kernel of its host, so there is none): the jail is down for
   the last increment. Encrypted volumes stay encrypted (raw sends). The console shows it as one operation with progress.
2. **Replication between hosts.** A schedule that keeps a second copy of chosen jails (or whole projects) on another host:
   `jailops replicate`, with the age of the last send, the size and errors shown in the console, and a one-command
   restore or promote of the copy by hand after a failure. This is the "enough availability" for most users: a copy that is
   minutes old and a person who decides.
3. **Notifications.** A webhook and mail sink for events that need a person: a failed nightly upgrade, a replication that
   lags, a certificate that expires, a pool that fills, a jail that does not come back after an update. The log
   forwarding sinks already exist; this adds the rules for what is sent and when.
4. **Graphs.** CPU, memory, network and disk of a jail over time in the console, from the accounting JailOps already
   reads (rctl, ZFS), kept in the operational database with a bounded retention.
5. **One console for every host.** From the console of one host (the hub) see the jails, projects, images and
   updates of all the hosts it knows, manage them from there and move a jail between them (item 1). The hub and its
   Hosts page exist; this makes them the place where a small fleet is run, with the same search and shell access as on a
   single host.
6. **Automatic failover, last and only with fencing.** Promoting a replica without a person needs a rule for who may
   promote, a way to be sure the old host is down (fencing), and a way back. It is built after 1 to 5, and no stateful
   jail is ever promoted automatically without all three ([design.md](design.md), section 8.6).

## Later, if asked for

- Sign-in with an identity provider (OpenID Connect). Local users with a second factor (TOTP) exist today.
- A permission for opening a shell in a jail that is separate from the one for starting and stopping it.
- Restart a service or a jail when one of its packages was upgraded (the update record already lists what changed).
- Moving the data of a jail to a jail of a new release.
- A ready-made installation image of FreeBSD with JailOps, if people ask for one.
