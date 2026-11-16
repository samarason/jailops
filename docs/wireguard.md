# WireGuard tunnels

JailOps manages WireGuard tunnels of the host: a **server** that peers join, and a **client** of a server. The goal is
one command per side and nothing to remember: the host makes the keys, assigns the addresses, applies the
configuration, and keeps the tunnel up across reboots. A server can name JailOps networks its peers may reach, so a
laptop or a branch host reaches the jails of a project through the tunnel.

What it is not: a full VPN suite. There is no full tunnel (a client never takes the host's default route), no DNS
handling on the host, no NAT for peers and no change to the host's own `pf.conf`.

## The one-command flow

On the server host:

    jailops wireguard create office --address 10.99.0.1/24 --network web --endpoint vpn.example.com:51820
    jailops wireguard peer add office laptop

`peer add` prints a **join token** once (`jwg1.` followed by base64url). On another JailOps host:

    jailops wireguard join office --token-file token.txt

The client is created, its keys go to the helper of that host, and the tunnel comes up. For a phone or a laptop
without JailOps, print a configuration file instead and import it into the WireGuard app:

    jailops wireguard peer add office phone --format conf > phone.conf

Then:

    jailops wireguard list
    jailops wireguard status office        # per peer: latest handshake, bytes received and sent, endpoint
    jailops wireguard peer list office
    jailops wireguard peer remove office laptop
    jailops wireguard down office          # the interface goes, the keys stay
    jailops wireguard up office
    jailops wireguard rotate-keys office
    jailops wireguard delete office        # interface, pf anchor and keys

Every command that changes something takes `--dry-run` (it sends nothing; for `join` the token is not printed). The web console has the same
under Networks, WireGuard.

## Concepts

| Field (`spec`) | Server | Client |
|---|---|---|
| `interface` | `wg-<name>` by default; at most 15 characters, starting with `wg` | same |
| `address` | the interface's address with its prefix, IPv4 and/or IPv6 (`10.99.0.1/24`, `fd99::1/64`) | the address the token assigned (`10.99.0.2/32`) |
| `listen_port` | UDP port, default 51820 | none (the kernel picks one) |
| `endpoint` | what peers dial, written into tokens; default the host's name and the port | the server's `host:port` |
| `allowed_ips` | the **pool** peer addresses come from; default the subnets of `address` | what is **routed into the tunnel** |
| `dns` | handed to peers in their tokens | kept for reference; the host's resolver is not changed |
| `keepalive` | per peer, optional | default 25 seconds |
| `peers` | name, public key, addresses, created | none |
| `networks` | JailOps networks the peers may reach | none |
| `down` | interface removed, keys kept | same |

`peer add` takes the next free address of each family of the pool (never the server's own, never one of another peer;
the first address and an IPv4 broadcast address are skipped), or `--address`. A peer's token routes the server's tunnel
subnets and the subnets of the networks it names.

## How it is kept running

The tunnel is applied when it is created or changed, and the daemon's reconcile loop keeps it applied: after a reboot
it creates the interface again (like the interfaces of jails), sets its description, addresses and configuration, and
changes nothing that already matches. Nothing is written to `rc.conf`. A configuration change is applied with
`wg syncconf`, so peers that did not change keep their sessions. The kernel module `if_wg` is loaded by the same loop
when a tunnel exists (add `if_wg_load="YES"` to `/boot/loader.conf` to have it at boot before the daemon starts).

## Security model

**Where keys live.** The privileged helper keeps one directory per tunnel below its own WireGuard directory,
`/var/db/jailops-priv/wireguard/<name>/` (root, mode 0700; `wireguard-dir` in `priv.conf`). It holds the interface's
private key (`private.key`, 0600, made with `wg genkey` on the host or taken from a join token), its public key, the
preshared key of each peer (`psk/<id>.psk`, 0600, keyed by the peer's public key) and the name of the interface the
helper created. The directory is outside the daemon's data directory on purpose: the daemon must not be able to
replace it, and the helper refuses to work in it unless it and its parent belong to root and nobody else may write
them. The helper writes nothing outside it.

**What never leaves the host's helper.** The daemon never reads that directory. A private key is never on a command
line: `wg pubkey` reads it on standard input, and the configuration is written to a 0600 file in the tunnel's
directory, read by `wg syncconf` and removed. `wg show <if> dump` prints the private key and the preshared keys; the
helper reads past them and answers with public parts only. The API, the audit log, the daemon's log, events and the
fake server used by tests never carry a private or preshared key.

**What the token is.** A join token holds the peer's private key, the preshared key, the server's public key, the
endpoint, the peer's addresses, the routes, DNS and the keepalive, as base64url of JSON. It is a secret: whoever holds
it can be that peer. It is printed once, by `peer add`, and is not stored anywhere on the server, which keeps only the
peer's public key and the preshared key. The `--format conf` file is the same secret in the format of the WireGuard
apps. Pass it on over a channel you trust; `join NAME --token-file -` reads it from standard input and `--token-file FILE` from a file, so it
stays out of shell history and the process list (a token is never an argument).
A lost token is replaced by removing the peer and adding it again.

**Who may do what.** Reading tunnels and their state (public keys, peers, handshakes) needs the operator role; creating,
changing, enrolling, joining, rotating and deleting need a global administrator. Every change is audited with the
object's name, never with a body. In the helper every WireGuard operation that changes something needs the admin
assertion; each field is validated again there (names, interface names starting with `wg`, at most two addresses,
ports, keys as base64 of 32 bytes, endpoints as `host:port`, no default route).

**Interfaces that are not JailOps's.** The helper records which interface it created for a tunnel and touches no
other: an interface of that name that it did not create (one made with the WireGuard tools by hand, for example) is
refused and left alone, and deleting the tunnel then removes only the keys.

## Firewall and routing

**The listen port.** JailOps never edits `pf.conf`. A server's peers reach its UDP port only if the host's own ruleset
lets them; add the one rule `jailops wireguard show` prints as `firewall_rule`, with your external interface:

    pass in on $ext_if proto udp to port 51820

`jailops doctor` warns (`wireguard.firewall`) while no loaded rule of the host mentions the port.

**Reaching JailOps networks.** For a server with `networks`, JailOps loads the pf anchor `jailops/wg.<name>`. It passes
traffic that comes in on the tunnel from the tunnel's subnets to the subnets of those networks and drops everything else
a peer sends (the host itself and its LAN included), so a peer reaches only what the server names. Each jail's own
firewall policy still applies to what is admitted: a jail that refuses traffic from outside its network refuses the
tunnel too. The anchor is evaluated through the `anchor "jailops/*"` line you already have.
Forwarding stays your switch, as for networks: `jailops doctor` warns (`wireguard.forwarding`) when a tunnel serves
networks and `net.inet.ip.forwarding` is off. Jails answer through their default route, the host, which knows the
tunnel's subnet.

**A client** routes its `allowed_ips` into the tunnel (`route add -net ... -interface wg-<name>`); a default route
(`0.0.0.0/0`, `::/0`) is refused.

**Which routes the helper adds.** The routes reach the host's own routing table, so the helper checks them itself,
whatever the daemon asks: every route lies inside the allowed IPs of a peer of its tunnel, and, unless `priv.conf`
says otherwise, is at least a /8 (IPv4) or a /16 (IPv6) and stays clear of loopback, link-local and multicast, of the
host's own addresses (the tunnel's excepted), of its default gateways and of the resolvers in `/etc/resolv.conf`. So a
tunnel cannot take over the host's traffic with two halves of the address space (`0.0.0.0/1`, `128.0.0.0/1`) or with
the /32 of its resolver. A network you do want to route that way goes in `priv.conf`, one line per network:
`wireguard-routes = 0.0.0.0/1` (a route inside a listed network skips the checks above, but not the one of the
allowed IPs); `admin-routes = true` lifts them for every route. What the helper cannot know (the address of a backup
node or an ACME CA the host talks to) is not checked: a route to one of them inside a peer's allowed IPs is the
power the tunnel's admin has.

## The wg program and the module

FreeBSD has the WireGuard driver, `if_wg`, in the base system. The `wg` program is looked for at `/usr/bin/wg` (if your
release has it in the base system) and then at `/usr/local/bin/wg` (the package `wireguard-tools`); it must belong to
root and be writable by nobody else. `jailops doctor` checks it (`wireguard.tools`) only on a host that has a tunnel:

    pkg install wireguard-tools

## Fleet sync

A server can be declared in a fleet repository; private keys and preshared keys are never in files. See
[fleet-sync.md](fleet-sync.md) for the rules (clients are made with `join`, peers listed in a file get no preshared
key unless the host already holds one for that public key).

## Limits

- One server address per family; peers get single addresses (/32, /128), not routed subnets behind them.
- No full tunnel on a client, no NAT for peers, no DNS change on the host, no automatic port forwarding of the
  listen port.
- A rotated key is not sent anywhere: after `rotate-keys` on a server every peer needs a new token; after it on a
  client, the server must enroll the client again.
- A peer added on a server that fleet sync manages is removed by the next forced sync apply unless the repository lists it.
- Routes of a client are added when its interface is created or its configuration changes; a route removed by hand
  comes back at the next change, not at the next pass.

## UNVERIFIED

Nothing of this has run on a FreeBSD host yet; `scripts/ci-freebsd-e2e.sh` has a block for it (it skips, saying what
is missing, on a machine without `if_wg` or `wg`). In particular:

- `ifconfig wg create` and the rename to a name holding `-` (`wg-office`), and destroying the renamed interface.
- The output of `wg show <if> dump` and `wg syncconf` of the wg program on FreeBSD 15.1, and whether 15.1 ships `wg`
  in the base system or only in `wireguard-tools`.
- A pf rule that names an interface with `-` (`pass in quick on wg-office ...`).
- A handshake between two interfaces of one host over the loopback address (the end-to-end block).
- Traffic from a peer into a jail through `jailops/wg.<name>` and the jail's own anchor.
- `kldload if_wg` through the helper.
