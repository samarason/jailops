# Networking

JailOps runs the network of your jails itself. A network is an address range with an uplink; every jail gets an address
from it and a private link to the host, and the host is the router. There is no bridge, no switch and nothing to
configure on the host besides forwarding.

    jailops network create office --ipv4 192.0.2.1/24 --uplink em0 --nat
    jailops project create shop
    jailops network grant office --project shop && jailops storage grant default --project shop
    jailops create site --project shop --image freebsd-15-1 --network office --storage default
    jailops start site --project shop
    jailops list --project shop

## What you get

- **Addresses are allocated for you.** The range of the network is the pool. A jail's address is written into its
  specification and stays with it; there is no DHCP, no router advertisement and no SLAAC. `jailops network leases
  office` lists who has what.
- **One link per jail.** Each interface of a jail is its own point-to-point link to the host. The host end carries the
  network's gateway address (`192.0.2.1`, the same on every link) and the link-local `fe80::1`; the jail holds its address
  as a `/32` and its IPv6 address as a `/128` and sends everything to the gateway.
- **The host is the router.** Traffic between two jails, from a jail to the internet and from the internet to a jail
  all passes through the host and its firewall. Nothing in the subnet that no jail has is reachable: the host answers
  such a packet with an error instead of sending it out of the uplink.
- **A network belongs to one project.** A project is granted whole networks; another project's jails are outside, and
  the firewall of a jail closes them out unless a rule opens the way.
- **`ifconfig` says what each interface is.** The host end of a jail's link says
  `jailops jail=shop/site net=office (host side)`; inside the jail the other end says `(jail side)`.

## Isolation between jails

Every jail has a link of its own, so jails never share a network segment:

- **They cannot see each other's traffic.** What a jail sends and receives travels on its own link to the host. A jail
  that captures packets sees its own traffic only.
- **They cannot poison each other.** ARP, neighbour advertisements, router advertisements and DHCP answers of a jail
  reach the host's end of its own link and nobody else. A forged one changes nothing outside that jail.
- **They cannot use each other's addresses.** The host routes an address to the one link of the jail that owns it, and the
  jail's firewall drops everything it sends from another source address and everything addressed to an address it does
  not own. An address a jail gives itself sends and receives nothing.
- **They talk only as far as the firewall allows.** The host forwards between two jails what both jails' policies allow.
  `jailops firewall test` says what happens to a connection before you try it ([firewall-testing](networking-ipv6.md#would-it-pass)).
- **There is no layer 2 between jails.** Multicast, mDNS, VRRP/CARP and other non-IP protocols do not pass from one jail to
  another. Services that need to find each other use addresses or DNS.

## The jail and the host

The host is an endpoint of a policy like any other: `allow out tcp to host port 443` lets a jail reach a service on the
host, `allow in tcp from host port 22` lets the host reach the jail. With a policy, everything else a jail sends to an
address of the host is dropped; what stays open is ICMP echo and DNS to the network's gateway address. A jail without
a policy is open to everything but the host: it gets ping and DNS from the host and nothing else, and `jailops jail info` says so.

**`any` is not the host.** As the destination of an allow rule, `any` (named or left out) is every address except the host's
own and those of the networks of other projects: `allow out tcp port 22` lets a jail ssh to the internet, not to the sshd of
the host or to the jails of another project. Name the host (`--to host`) or the other project's prefix to open them. A deny
rule to `any` still denies the host.

**Ping and DNS to the host stay open under every policy**, a deny-all one included, because a jail needs its gateway and its
resolver. To close them, add deny rules, which win over every allow rule: `jailops firewall rule add POLICY out --action deny
--proto udp --port 53 --to host` (and `--proto tcp`, and `--proto icmp` for ping).

**A jail with a link and no address** (`--network lan=none`) has an anchor that drops everything in both directions: there is
no source address it may use and nothing is addressed to it. A jail with a link and no rendered anchor does not start.

Raw PF fragments in a policy are for operators who set `admin-raw-pf` in `priv.conf`. The helper refuses a fragment
that does not name its interface with `on`, and one that names an interface that is not the jail's own link.

**Names.** With one line in `priv.conf` the jails of a project reach each other by name, `postgres.verkis.internal`, answered
by the unbound of the host and limited to the project of the jail that asks: [dns.md](dns.md).

## Several networks, several families

A jail can attach to several networks; each attachment is its own link with its own gateway. A network has IPv4, IPv6 or
both. IPv6 comes in two modes, `routed` (your provider routes a prefix to the host) and `proxy` (a prefix on the shared
segment of the uplink, for which the host answers neighbour discovery); see [networking-ipv6.md](networking-ipv6.md).

## Reaching the outside

`--nat` translates what leaves through the uplink to the uplink's address. A jail that must be reached from outside gets
a port forward in its firewall policy (`redirect`) or a routed IPv6 address. The host's own `pf.conf` is the door: it
must let the traffic in and contain the line `anchor "jailops/*"` ([install.md](install.md#3-the-firewall-one-line-in-pfconf)).

## Limits

A device can be limited in each direction with `nic.eth0.egress` (what the jail sends) and `nic.eth0.ingress` (what it
receives), for example `10M` for 10 Mbit/s. Limits survive a restart of the jail and apply to everything the jail sends or
receives, whoever started the connection. The dummynet pipes numbered 40000 to 59999 belong to JailOps: it numbers them once,
stores the numbers, and removes a pipe of that range that no jail's loaded anchor names; use other numbers for pipes of your own.

    jailops config set site nic.eth0.egress 20M --project shop
    jailops config set site nic.eth0.ingress 50M --project shop

## What the host needs

Forwarding on (`gateway_enable=YES`, `ipv6_gateway_enable=YES`), the `pf` and `if_epair` modules, and the one anchor line
in `pf.conf`. `jailops doctor` checks all three and says what to do.

## When pf is off or was flushed

A jail with a network link does not start while pf is disabled (`pfctl -s info` says `Status: Disabled`): its anchor would be
loaded and nothing would evaluate it. `jailops doctor` fails `pf.enabled` in that case. Set `allow-start-without-pf = true`
in `priv.conf` only on a host where that is what you want. `service pf start` and `service pf restart` empty every anchor;
the daemon looks every few seconds and loads the anchors of the running jails again at once.

## Forwarded ports

Only a global administrator makes a forward (a proxy device, a profile with one, or a redirect rule of a policy), because a
forward takes traffic that would reach the host: it is refused on a port that a service of the host listens on (ssh, the
console, the other JailOps listeners, the ACME challenge port while ACME is the source) and on a `listen` address that the
host does not have. An administrator of the project edits the other rules of a policy that already has a forward.

Two jails cannot forward the same host port (a proxy device, or a redirect rule of a policy the jail is rendered with): the
second is refused when it is made, and the message names the first jail. A mandatory policy of a project with a redirect can
be used by one jail of the project only.

## Networks

A network is an ordinary unicast range: IPv4 not in 0/8, loopback, link-local (169.254/16), multicast or 240/4; IPv6 a global
(2000::/3) or unique-local (fc00::/7) prefix.
