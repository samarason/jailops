# ipv6-switched-cloud

A cloud server whose provider gives you **a `/64` on a segment shared with other customers**. The provider's router
believes every address of the `/64` is on-link and asks neighbor discovery who has it, so JailOps answers for each jail
address itself (**proxy mode**, see [networking-ipv6.md](../../docs/networking-ipv6.md)). Two projects, each with its own
`/80` carved out of the `/64`:

| Project | Network | IPv6 `/80` | IPv4 | Jails |
|---|---|---|---|---|
| `shop` | `shop` | `2001:db8:1:2:100::/80` | `10.94.0.0/24` (NAT) | `web` (public), `app` |
| `intra` | `intra` | `2001:db8:1:2:101::/80` | `10.95.0.0/24` (NAT) | `wiki` |

Replace `2001:db8:1:2::/64` with your provider's prefix and `vtnet0` with the uplink. Keep the host's own address outside
the carved `/80`s.

## What the example shows

- **Proxy-mode networks** (`ipv6.mode: proxy`, gateway `fe80::1`, uplink `vtnet0`, a range inside the `/80`). A network
  belongs to one project; the two `/80`s cannot overlap (`validate` checks that offline).
- **The floor**: both projects name `firewall_policies: [floor]`, a policy with `default_in: deny`. A jail's own policies add rules but cannot
  weaken it. Projects cannot reach each other: there is no rule that says they can.
- **A firewall per jail**: `web` has `public-web` (HTTP and HTTPS from anywhere, SSH from `set:admins`), `app` has
  `app-private` (port 8080 only from `set:web-tier`).
- **A public web jail** with a fixed IPv6 address (`2001:db8:1:2:100::80`, your AAAA record) and, for IPv4, `proxy:` devices that
  forward the host's ports 80 and 443.
- Explicit network and storage on every jail; the image is built once by `build: true`.

## Before you apply

1. Let packets in: pf's default for the uplink is yours. Admit the jails' addresses and the ports you want, for example
   `pass in quick on vtnet0 inet6 proto tcp from any to 2001:db8:1:2:100::/80 port { 80 443 }`. The jail's anchor
   still decides afterwards (see install.md section 3).
2. Run `jailops doctor`: it fails `network.ndproxy` while a proxy network is not answering.

## Run it

    jailops-sync -C examples/ipv6-switched-cloud validate
    jailops-sync -C examples/ipv6-switched-cloud plan       # compare with EXPECTED-PLAN.md
    jailops-sync -C examples/ipv6-switched-cloud sync --apply
    jailops-sync -C examples/ipv6-switched-cloud drift      # later: non-zero when something changed behind the repository

`host.yaml` uses the local socket, so run `sync` on the host (or as root through `ssh`); root is a global admin on the
socket. For a remote controller use `url`, `fingerprint` and `token_secret` as in [multi-host-fleet](../multi-host-fleet).

## Verified, and not

The model (carving, proxy answers, per-jail anti-spoofing) is verified on FreeBSD 15.1 amd64 with a switched `/64`; see
networking-ipv6.md for exactly what ran. **UNVERIFIED:** this exact repository applied to a real host (the test suite applies it
to in-memory hosts and validates every object with the daemon's validators), a `vlan(4)` uplink, providers that filter by MAC
address.
