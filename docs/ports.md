# Ports

The JailOps family has a small range of its own, **39110 to 39112**, outside the ports everything else uses (in the way Proxmox
keeps 8006 and 8007). Nothing listens on the network until you ask for it: `jailopsd` talks on a Unix socket by default, and the
network listeners below are opt-in or loopback only. Opening a port to the outside is a decision of the host's firewall, and
JailOps never edits `pf.conf`.

| Process | Port or socket | What it is for | Default | Open it to |
|---|---|---|---|---|
| `jailopsd` | `/var/run/jailops/jailops.sock` | the local API: the `jailops` CLI, the SDK and `jailops-sync` on the host itself | on | nobody (local only) |
| `jailopsd` | **39110**/tcp (`listen.https.address`, for example `":39110"`) | JailOps: the remote API over TLS 1.3 (CLI remotes, `jailops-sync`, a hub) and, when enabled, the host console | off: no TCP listener until you set the address | your admin machines, the hub, CI |
| `jailopsd` | **39080**/tcp (`listen.https.acme.challenge_address`) | the ACME http-01 challenge listener: plain http, challenge tokens only, nothing else ([exposure.md](exposure.md#acme-a-certificate-from-a-public-ca)) | only while ACME with http-01 is the console's certificate | nobody directly: the host redirects **80**/tcp to it (with `tls-alpn-01`, **443**/tcp to 39110); the CA must reach port 80 (or 443) from anywhere |
| `jailops-priv` | `/var/run/jailops-priv/priv.sock` | the small root helper of `jailopsd` | on | nobody, never the network |
| `jailops-backupd` | **39111**/tcp (`listen`, default `:39111`) | JailOps Backup: backup hosts back up and restore here (mutual TLS, pinned fingerprints) the management API (users, tokens, sessions) and, when `web.enabled`, the backup console | on while the node runs; the console is off (`web.enabled: false`) | the backup hosts, and your admin machines |
| `jailops-backupd` | `/var/run/jailops-backupd/admin.sock` | the node's admin CLI (root only, mode 0600) | on | nobody |
| `jailopsd` (a WireGuard server you create) | **51820**/udp, or the tunnel's `listen_port` | the tunnel's peers ([wireguard.md](wireguard.md)) | only while such a tunnel exists | the peers; add `pass in on $ext_if proto udp to port 51820` |
| `pkgops serve` | **39112**/tcp on `127.0.0.1` (`--listen`) | PkgOps: a package repository, the upload API of the registry and, with `--ui`, its web UI | only while you run `serve` | the hosts that `pkg install` from it and the CI that uploads |

One port per service, and the web UI of each is in the binary and off until you turn it on.

## The same layout on every port

| Path | What |
|---|---|
| `/` | the web console, when it is enabled; with it off `/` answers 404 |
| `/api/v1/` | the API, always (for JailOps Backup the host API is under `/api/v1/repo/`) |

`web.enabled` switches the console only; it never moves a listener and never switches an API off. Nothing is answered with HTML under `/api/`. `pkgops serve` is the one exception to "console on `/`": the package repository's own files live at the root of its port, so its console is at `/ui/` and `/` redirects there when it is on.

## What to open

- **A host you manage from elsewhere:** 39110/tcp from your admin machines, and set `listen.https.address` in `jailopsd.yaml`.
  The host console (`web.enabled: true`, or `jailopsd_web="YES"` in rc.conf) uses the same port.
- **A backup node:** 39111/tcp from the backup hosts, and from your admin machines if you use the management API or the console.
  One port serves all of it, and the two ways of proving who you are are independent: the host API needs a valid
  certificate of an enrolled, non-revoked host (mutual TLS, pinned fingerprints) and says 401 to anything else, while the
  management API and the console take no identity from a certificate at all: a user, a token or a session signs in, with no
  certificate or with any certificate. A browser that has a client certificate installed (a smartcard, a corporate certificate)
  may be asked to pick one; any choice, or none, reaches the login page.
- **A package server:** 39112/tcp from the hosts that install from it, with TLS (`--tls-cert`, `--tls-key`, and `--client-ca` to
  require client certificates).

Open the port in your own firewall, for example in `pf.conf`:

    pass in quick on vtnet0 proto tcp from { 203.0.113.7, 198.51.100.0/24 } to (vtnet0) port 39110

## No proxy needed

Every network listener has TLS built in (`jailopsd` and `jailops-backupd` always speak TLS; `pkgops serve` with `--tls-cert`), so
a reverse proxy is not needed, in the way you do not put nginx in front of Proxmox. You can still put one in front, or a tunnel,
if you want one; [exposure.md](exposure.md) shows the shapes. Cloudflare in front of the web consoles is optional too.

## What is not in the range

The ports of your own services in your jails are yours: JailOps does not open them. `jailops-sync`, `jailops` and the `pkgops`
build commands are clients and listen on nothing.
