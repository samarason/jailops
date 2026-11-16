# Names for jails

The jails of a project reach each other by name. A jail called `postgres` in the project `verkis` is
`postgres.verkis.internal`, and a jail of that project can say just `postgres`. The host on the network of the project is
`host.verkis.internal`. A jail sees the names of its own project and of no other. The defaults are meant to be used: this is
how the jails of a host resolve names, and nothing needs setting.

## Nothing to configure

The names come from the host's resolver, the base system's `local-unbound`. `jailops-setup` enables it as part of the
normal setup (`sysrc local_unbound_enable=YES`, `local-unbound-setup`, `service local_unbound start`; Enter answers yes,
`-y` yes, `-n` only prints) and makes its `/var/unbound/conf.d` root's, which the helper insists on, because it writes a
file there as root. A resolver that already listens on port 53 of the host is left alone. After that:

- the helper writes `/var/unbound/conf.d/jailops.conf`, which `local-unbound-setup` includes, with the names of the running
  jails and what the resolver needs to answer them: the host's address on the network of each project with a running
  jail (`interface:`, with `ip-transparent: yes`; an address your own configuration already lists is not repeated) and the
  subnets it admits (`access-control:`);
- a jail asks the gateway of its network, and its `/etc/resolv.conf` has `search PROJECT.internal`. Everything that is not a
  jail's name goes on to wherever the host resolver sends it.

## See how it works

`jailops jail info postgres` shows how the jail resolves names:

```
DNS
  Nameserver:   172.17.28.1 (the gateway)
  Search:       verkis.internal
  Names:        postgres.verkis.internal, postgres, postgres.v4.verkis.internal, postgres.v6.verkis.internal
  Other names:  forwarded to 192.0.2.53
```

and `jailops doctor` says the same for the host in one line:

```
dns.unbound   PASS   14 names for 3 jails in 2 projects; suffix internal; unbound forwards everything else to 192.0.2.53
```

When the host resolver is not enabled, doctor warns with the way to enable it (`jailops-setup`) and `info` says that the
jail has no names. Nothing stops a jail from starting either way.

## IPv4 and IPv6

Every jail has three names, for the families it has an address of: `postgres.verkis.internal` answers with every address
(A and AAAA), `postgres.v4.verkis.internal` with the IPv4 ones only and `postgres.v6.verkis.internal` with the IPv6 ones
only. A jail without an IPv6 address has no `.v6` name. The short forms work through the search domain, `postgres`,
`postgres.v4` and `postgres.v6`; the host is `host` and `host.v4`. Use the `.v4` or `.v6` name where a program has to
connect over one family.

## Make it your own

Three things, and only these:

1. **Another suffix.** `dns-suffix = corp.example` in `priv.conf` (one or more DNS labels, `internal` by default; `local` is
   refused, it is multicast DNS) gives `postgres.verkis.corp.example` and the search line to match. A suffix you own is the
   clean choice: it can never collide with a public name, and you can answer it elsewhere too.
2. **A network with its own nameservers.** `dns:` in `jailops network edit` names the resolvers of the network's jails. They keep
   them and get no names: a network that points at its own resolver brings its own names.
3. **A jail with its own `resolv.conf`.** JailOps writes `/etc/resolv.conf` of a jail at creation and at each start (and when
   the network's `dns` changes), with the first line `# written by JailOps`. Edit the file and delete that line, or put a
   file of your own there before the first start, and JailOps never writes it again.

## What happens

The names follow what runs. The helper rewrites the file when a jail starts, stops, is created, deleted or renamed or a
network changes (within the minute at most) and asks the resolver to read it again (`local-unbound-control reload`). A
stopped jail has no name. A new network with its first running jail adds an `interface:` line, which a reload does not
bind: JailOps restarts local-unbound then (`service local_unbound restart`), a few hundred milliseconds in which the jails
get no answer. Nothing the file says can stop a jail from starting: a failure only shows in `jailops doctor`.

The resolver checks the file before it reads it (`local-unbound-checkconf` with the new file in place). When it
refuses the text, for instance because your own configuration names the same `interface:` address, the old file is put
back, nothing is reloaded, and `jailops doctor` says what the resolver said. The resolver listens on the host's address
of every network of a project, running jail or not, so a first jail finds it there, and it is started again only when
the networks change. After a project is renamed the names follow within a minute, and a running jail keeps its old
`search` line until its next start. `jailopsd`
starts after `local_unbound`, so the names exist after a reboot.

The file is made by the helper from the stored objects of the jails and networks, not by the daemon. It holds a view for
each project with a running jail, given to the subnets of the project's networks, so that a jail's queries see its own
project's names (and everything else the resolver knows) and no other project's.

## Resolving yourself instead of forwarding

Whether the resolver forwards the other names to someone or resolves them itself from the root servers is the host
resolver's own setting; JailOps does not touch it. `local-unbound-setup` made `/var/unbound/forward.conf` from the
nameservers the host used at that time: look at it, or ask `local-unbound-control list_forwards` (nothing listed means it
recurses). To resolve yourself, run `local-unbound-setup none` (it keeps the old file as a backup) and
`service local_unbound restart`.

## Switching it off, or another resolver

`unbound-conf =` (empty) in `priv.conf` turns it off. A path there points the helper at another file, for a plain `unbound`
with `unbound-control` (the package): include that file from `unbound.conf`, let the resolver listen on the gateway
addresses and read its control socket; `jailops doctor` checks the answer.

## Why `.internal`

`.internal` is reserved for private use and never becomes a name on the internet. `.local` is multicast DNS, which the
resolver of a jail would send to the network instead of asking the gateway.
