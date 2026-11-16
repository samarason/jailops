# Exposing the API (and the web console) safely

What is written here is what the code does; what is not implemented is in **Not yet** at the end. Nothing on this page
is needed to use JailOps on one host: the default is the local socket and nothing else.

## What listens

| Listener | Default | What it is |
|---|---|---|
| unix socket `listen.unix.path` | `/var/run/jailops/jailops.sock`, mode `0666` | the local API, one identity system with the TLS listener. The only thing the **peer's uid** decides is root (uid 0): a global admin, the host's recovery access. Every other local user is anonymous, exactly like an unauthenticated remote client (it reaches `GET /api/v1`, `GET /healthz`, `GET /readyz`, the login, trust-token redemption, `POST /api/v1/cluster/join` (501) and the static console, nothing else) and signs in with a token or a password login. No Unix user or group maps to a role. Mode `0666` is safe for that reason |
| TCP `listen.https.address` | **empty: no network listener** | the same API over **TLS 1.3 only**, plus the web console |
| TCP `listen.https.acme.challenge_address` | `:39080`, **only while ACME with http-01 is the source** | plain http that answers `/.well-known/acme-challenge/<token>` for the tokens of a running order, and 404 to everything else: no API, no console. The host redirects port 80 to it (below) |

Apart from the ACME challenge listener there is no plain-http TCP listener in `jailopsd`, and that one serves nothing but
challenge tokens. An API listener that is not TLS cannot be configured, so the daemon never serves the API without TLS on
a non-loopback (or any) address; a test connects with plain http and with TLS 1.2 and both fail. `listen.https.address` is
checked when the configuration is loaded (`":39110"` is every interface, `"127.0.0.1:39110"` and `"[::1]:39110"` are loopback only; a
wrong form is an error). The SDK, in turn, refuses plain `http://` to anything but loopback.

JailOps does not open ports for you: the host's `pf.conf` decides who can reach `listen.https.address`. Admit the addresses of your
administrators and nobody else. (With the host firewall module of [appliance.md](appliance.md) enabled, JailOps writes
`pf.conf` itself: `console.allow_from` of `jailops host firewall set --console-from` then decides who reaches the port.)

## The web console: built in, off until you turn it on

The console is the Vue application embedded in `jailopsd` (and the backup console in `jailops-backupd`). It is in every binary and
package, and it is **off by default**: the daemon and `jailops-sync` do not use it. Turn it on in one of three ways:

- **In the configuration**, `jailopsd.yaml`:

      web:
        enabled: true

  Without it (the default, or `enabled: false`) every path outside `/api/v1`, `/healthz` and `/readyz` answers 404 and the API is unchanged.
- **From rc.conf**: `sysrc jailopsd_web="YES"` (then `service jailopsd restart`) starts the daemon with `-web`, whatever
  `web.enabled` says, and opens the TLS listener on port 39110 when `listen.https.address` is empty, because asking for the
  console is asking to see it in a browser. `jailopsd_web="NO"` forces it off over the configuration. Unset, the configuration decides.
- **With a flag**: `jailopsd -web` (the same) and `jailopsd -no-web`.

For a daemon that has no console at all, `go build -tags noweb ./cmd/jailopsd` (`just build-noweb`) leaves the embedded application
out of the binary; `/` then answers 404 "this build has no web console". `just build` never does: it always builds everything in.

When the console is on it is served by the same listeners (the socket and the TLS listener, default port 39110), under `/`, and its
login routes (`/api/v1/auth/...`) exist whether or not the console is on: a user with a password can still log in through the API.
Create no users (`jailops user list`) if you want none. The backup node has the same switch: `web.enabled` (default `false`) in
`backupd.yaml` serves its console on the same port as the host API and the management API (39111); `web.listen` is gone. All
ports are listed in [ports.md](ports.md).

## The server certificate

| Option | Configuration | What happens |
|---|---|---|
| **Self-signed, pinned** (default) | nothing | on first start `jailopsd` generates an ECDSA P-256 certificate valid for **ten years**, with the host name and the entries of `listen.https.names` as names, into `<data_dir>/tls/server.{crt,key}` (key mode 0600). Clients **pin its SHA-256 fingerprint** (there is no trust on first use: a trust token carries it). It is not rotated by expiry |
| **Your certificate** | `listen.https.cert` and `listen.https.key`, absolute paths, both or neither | served as given (a file with the chain is fine). If a file is missing or only one of the two exists the daemon **refuses to start**: it never generates or overwrites a certificate you configured. The console cannot replace these files |
| **Uploaded** | the console's Host page (Certificates, Upload) or `jailops host certificate upload --cert FILE --key FILE` (`PUT /api/v1/host/certificate`, global admin) | a PEM chain (leaf first) and its PEM key, checked before anything is written: every certificate parses and is signed by the next, the key belongs to the leaf and is not encrypted, the leaf is valid now, for server authentication, and for the host name you give. Written by the daemon to `<data_dir>/tls/uploaded.{crt,key}` (0600, each to a temporary file that is synced and renamed) and served from the next handshake on; replacing those two files by hand is picked up like a renewal. Nothing renews it: the doctor warns 14 days before it expires |
| **ACME** | `listen.https.acme` in `jailopsd.yaml`, or the console (Request with ACME) / `jailops host certificate acme` (`POST /api/v1/host/certificate/acme`) | the daemon obtains a certificate for your DNS names from a CA (Let's Encrypt production by default) and renews it, below |

Going back: **Use self-signed again** in the console, or `jailops host certificate self-signed` (it asks you to type the
name of the certificate it replaces; `--confirm-replace` for a script), serves the generated certificate once more; browsers warn again and clients have to pin it. A choice made in the console or the API is kept in
`<data_dir>/tls/choice.json` and wins over `listen.https.acme` of the file (delete it and restart to let the file decide
again); `listen.https.cert`/`key` win over both. Whatever is served, the generated pair stays the daemon's own identity,
the client certificate a hub presents to its hosts.

`jailops host certificate show` prints what is served: subject, names, issuer, expiry, fingerprint, where it comes from,
the state of ACME, and the exact `jailops remote add` command for clients. The fingerprint is also in the start log line
(`jailopsd started ... fingerprint=`) and can be read from the file:

    openssl x509 -in /var/db/jailops/tls/server.crt -noout -fingerprint -sha256

**Reload.** The certificate files are looked at on a TLS handshake, at most every 15 seconds. When their modification time or size
changed, the pair is parsed and used for new connections, without a restart. A pair that does not parse (a half-written renewal) is logged
(`tls certificate changed on disk but does not load; still serving the previous one`) and the previous certificate stays. The key
file must be readable by the daemon's user (`jailops`): for example `chown root:jailops` and mode `0640`.

**Pinning and renewal do not mix.** A client pins the leaf certificate's fingerprint, so a certificate that renews every 60 to 90
days breaks every pin. With a certificate a public CA signed, **do not pin**: leave `fingerprint` out of `jailops remote add`
(the client trusts a certificate the system roots verify, and pins only when none does) and out of `host.yaml` of a fleet. The
console's Host page and `jailops host certificate show` show the right command (`remote_add` of `GET /api/v1/host/certificate`): without a fingerprint when the
served chain verifies against the host's trusted roots, with it otherwise. With the self-signed default, replacing the
certificate by hand (remove the two files, restart) changes the fingerprint and every client has to pin the new one. A trust
token carries the fingerprint of the certificate served when it is issued, so it pins a renewed ACME certificate too: with a
public certificate, give clients an API token instead.

## ACME: a certificate from a public CA

The daemon is its own ACME client (RFC 8555). It needs:

- **DNS names that point at this host** from the internet (`domains`, at most 20; no addresses, no wildcards).
- **The CA's terms of service**: `accept_tos: true` (the console has a checkbox with the terms' address, which the status
  shows as `terms_url` after the first request).
- **A way in for the CA's check**, the challenge. The daemon is not root and cannot listen on ports 80 or 443, so the host
  redirects them to its unprivileged ports:
  - `http-01` (the default): the CA fetches `http://NAME/.well-known/acme-challenge/TOKEN` on **port 80**, which is
    redirected to the challenge listener (`challenge_address`, default `:39080`).
  - `tls-alpn-01`: the CA opens TLS with the protocol `acme-tls/1` on **port 443**, which is redirected to the console's
    TLS listener; the daemon answers such a handshake with the challenge's certificate and refuses it when no challenge
    runs. Port 443 then leads to the console from any address (the CA's addresses are not known), so `console.allow_from`
    of the host firewall does not narrow it.

**The redirect.** With the host firewall module of [appliance.md](appliance.md) managing `/etc/pf.conf`, the daemon adds the
redirect to the firewall's spec while ACME is the source (`acme` of `GET /api/v1/host/firewall`, filled in by the daemon;
what a client sends is replaced), and the helper renders it, after the jails' anchor (a jail that forwards the
same port wins), with a pass rule for the redirected port:

    match in inet proto tcp from any to (self) port 80 rdr-to 127.0.0.1 port 39080
    match in inet6 proto tcp from any to (self) port 80 rdr-to ::1 port 39080
    pass in proto tcp from any to { 127.0.0.1, ::1 } port 39080

Apply the host firewall once after turning ACME on (the change waits for its confirmation like every firewall change);
the certificate's status says `redirect.applied` and `jailops doctor` warns until then. Without the module JailOps never
edits `pf.conf`: the status and the console print the two lines to add to it, after the line `anchor "jailops/*"`, here for http-01:

    pass in quick inet proto tcp from any to (self) port 80 rdr-to 127.0.0.1 port 39080
    pass in quick inet6 proto tcp from any to (self) port 80 rdr-to ::1 port 39080

The redirect targets the loopback addresses, so the challenge listener (and, with tls-alpn-01, the TLS listener) must
listen on all addresses or on a loopback address; the configuration is refused otherwise. UNVERIFIED: these rules have
not been loaded on a FreeBSD host; the IPv6 redirect to `::1` in particular (FreeBSD may drop a packet to a loopback
address that arrives on another interface).

**Requests and renewal.** Turning ACME on (in the file, at start, or in the console, at once) runs one order for all names:
the account (key P-256, created once), an authorization per name, the challenge, the CSR, the chain. The chain and its key
are written to `<data_dir>/tls/acme` (directory 0700, files 0600, each to a temporary file that is synced and renamed) and
served from the next handshake on, without a restart; until the first certificate arrives the self-signed one is served.
Once a day, with up to an hour of jitter, the daemon checks the certificate and renews it **30 days before it expires**. A
failed request is retried after 1 hour, then 2, 4, 8 and 16 hours, then once a day: never a burst of retries. The console's
Request button asks again at once, at most once a minute. The status (`GET /api/v1/host/certificate`, the console's
Certificates panel) shows the state (`requesting`, `valid`, `error`), the last error, the failures in a row, the next
attempt and the renewal date. `jailops doctor` has two checks: `tls.certificate` (what is served, its days left) and
`tls.acme` (warns about the last error, a missing redirect, and when the daemon cannot reach its own challenge listener:
it fetches a probe token from it, or completes an `acme-tls/1` handshake; this proves the listener answers, not that the CA
reaches it through your router and DNS).

**Limits.** Only `http-01` and `tls-alpn-01`: there is **no `dns-01`**, so **no wildcard certificates** (and no names the CA
cannot reach). The next step for those is a `dns-01` challenge through a DNS provider's API; until then obtain such a
certificate elsewhere and upload it, or point `listen.https.cert`/`key` at the files your tool keeps current. One
certificate per daemon; no external account binding; no revocation from JailOps.

**Tested how.** The tests run the whole flow against a CA written in the tests (`internal/daemon/dtest/acmeca.go`): the
directory and its terms, nonces, signed requests checked, the account, an order for two names, both challenges validated
against the daemon's real listeners, finalize with the CSR's names checked, the chain served on the TLS listener, a
restart that serves the cached certificate, a refused validation with its backoff. Not covered there: DNS, the CA's rate
limits, ports 80 and 443 behind pf. **UNVERIFIED: issuance by a real CA.** A person verifies it once against the staging
directory, on a host whose DNS name points at it and whose port 80 reaches it:

    # as root on the host
    jailops host certificate acme --domain console.example.com --accept-tos --staging
    jailops host certificate show                    # until the ACME state is valid
    openssl s_client -connect console.example.com:39110 -servername console.example.com </dev/null 2>/dev/null | openssl x509 -noout -issuer -dates
    jailops doctor                                   # tls.acme ok

The issuer is the CA's staging intermediate. Then switch to production (the same command without `--staging`) or back
with `jailops host certificate self-signed`. The same through the API, without the client (as root, on the socket):
`curl -s --unix-socket /var/run/jailops/jailops.sock -H 'Content-Type: application/json' -d '{"domains":["console.example.com"],"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","accept_tos":true}' http://jailops.local/api/v1/host/certificate/acme`.

## How a caller proves who it is

All of these work on the TLS listener at the same time; a credential that is present but bad is refused (and counts toward the lockout).

1. **A pinned client certificate** (mTLS). The listener *requests* a client certificate; it never requires one. A presented
   certificate must be within its validity and be a client certificate, and is then looked up **by fingerprint** in the trust store
   (`jailops cert create`, or the join flow below). It has a role and a scope (a project list or `global`; an empty list is never
   "everything") and an optional expiry. An unknown certificate with no other credential is answered `unauthorized`.
2. **An API token** in `Authorization: Bearer`: one role, a scope, `--expires` and `--allow-from` (source networks).
   `jailops token create ci --role operator --projects web --expires 720h --allow-from 203.0.113.0/24`. The secret is shown once.
3. **A user and password** (optionally TOTP) for the web console, which gets a session cookie (`Secure` when the connection is TLS,
   `SameSite=Strict`) and a CSRF token; mutations also check the `Origin` against the `Host` header.

The same three work over the unix socket (a client certificate needs TLS, so there it is a token or a session). Root on the host
needs none of them: uid 0 on the socket is a global admin. See [security-model.md](security-model.md).

Failed authentications from one source (a bad token, an untrusted certificate, a forged claim) are rate limited per source
(`limits.auth_failure_threshold`, default 5) and audited; while a source is locked out its valid tokens are refused as well.
Logins are counted the same way, per user and source and per source, before the password is checked. A source is an
IPv4 address or an IPv6 /64. Guesses for one account from many sources are slowed down (after 10 failures each attempt
waits 1 s, 2 s, 4 s ... up to 30 s), never locked, so nobody can lock a real user out. At most four password checks run at
once; the details are in [security-model.md](security-model.md#signing-in-and-what-an-unauthenticated-caller-costs). Creating networks, images, storage and projects needs a **global admin**
identity, so the identity of `jailops-sync` is one.

Join flow for a person or a machine, pinned in both directions:

    jailops cert enroll laptop --role admin --global --expires 15m --cert-expires 2160h   # on the host: prints a single-use token
    jailops remote add myhost host.example.org --token-file -                         # on the client: paste the token

The client side is the one-argument form of `remote add`: the server's address (port 39110 unless given), the trust token
on standard input. It pins the fingerprint the token carries, makes a key pair and is trusted with the token's role and
scope. The two-argument form, `remote add NAME URL`, is for an API token and refuses a trust token.
## Recipe 1: local only (the default)

Do nothing: leave `listen.https.address` empty. To administer from your laptop without opening a port, forward the socket over ssh:

    ssh -N -L /tmp/jailops.sock:/var/run/jailops/jailops.sock admin@host
    JAILOPS_TOKEN=jot_... JAILOPS_SOCKET=/tmp/jailops.sock jailops list --project web

The daemon sees the peer credentials of the process that connects to its socket, which for a forwarded connection is `sshd` running as
the user who logged in (reasoned from the code; UNVERIFIED on a real host). For an ordinary user that is an anonymous peer, so the
forwarded socket needs an API token like any remote client; logging in over ssh as root would make the forwarded socket root's,
a global admin, so do not forward as root for routine work. For a fleet, run `jailops-sync` on the host as root, or over the
network with a token or certificate. Leave `web.enabled` off (the default) if nobody uses the console.

## Recipe 2: behind a reverse proxy or Cloudflare

The listener speaks TLS only, so a proxy must connect to it with **https**. The daemon's certificate is self-signed by default, so tell the
proxy to trust exactly that certificate, and let the proxy hold the public certificate.

    # jailopsd.yaml
    listen:
      https:
        address: "127.0.0.1:39110"          # loopback: only the proxy on this host can reach it
        names: [jailops.internal]          # the name the proxy verifies
    web:
      enabled: false                       # API only, unless you want the console behind the proxy too

    # nginx, as one example of a proxy
    location / {
        proxy_pass https://127.0.0.1:39110;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /var/db/jailops/tls/server.crt;   # the daemon's own certificate, as the only trust anchor
        proxy_ssl_name jailops.internal;
        proxy_set_header Host $host;                # the console's CSRF check compares Origin with Host: keep the original
        proxy_http_version 1.1;
        proxy_buffering off;                        # the events stream is long-lived
        proxy_read_timeout 1h;
    }

What changes behind a proxy, all of it following from the code:

- **No client certificates.** TLS ends at the proxy, so pinned mTLS is not available through it: callers use API tokens (or the
  console login). Keep tokens short-lived and scoped, and put an access control **in the proxy** (Cloudflare Access, an IP allow
  list, basic auth): that is the outer door, and the token is the inner one.
- **The daemon sees the proxy's address**, not the caller's. The lockout counts failures per source, so one attacker behind the proxy can
  lock the proxy's address out for everyone (valid tokens included, for as long as the lock lasts), and a token's
  `--allow-from` can only name the proxy. `X-Forwarded-For` is not
  used. Do not rely on `--allow-from` here.
- **`exec`, `shell` and the console** use an HTTP `Upgrade` to a JailOps protocol (`jailops-exec/1`), not a WebSocket. A proxy that passes
  only WebSocket upgrades (a CDN, for instance) will not carry them; use ssh for shells and the proxy for the API. UNVERIFIED with any
  specific proxy or with Cloudflare; the facts above are from the code.
- **A tunnel** (a connector that dials out from the host) has the same shape: point it at `https://127.0.0.1:39110` and give it the
  daemon's certificate as its CA and the name above, rather than turning verification off. UNVERIFIED with `cloudflared`.
- With a certificate for the public name on the proxy and the daemon's self-signed one behind it, **clients pin nothing**: they verify the
  proxy's public certificate, and `host.yaml` has no `fingerprint`.

## Recipe 3: direct, with TLS and mTLS

The strongest setup JailOps has today: the listener on a public or private address, a certificate you control, and every administrator and
`jailops-sync` identified by a **pinned client certificate**, no tokens and no passwords.

1. Configure the listener and, if you have one, your certificate:

       listen:
         https:
           address: "203.0.113.10:39110"       # or ":39110"; bind the address you mean
           names: [host.example.org, 203.0.113.10]     # names of the generated certificate; unused with cert and key below
           # cert: /etc/ssl/jailops/fullchain.pem
           # key:  /etc/ssl/jailops/privkey.pem
       web:
         enabled: false

   `service jailopsd restart`, then `jailops doctor`.
2. Let only your administrators' addresses reach it, in `pf.conf` (JailOps never opens a port):

       pass in quick on vtnet0 proto tcp from { 203.0.113.7, 198.51.100.0/24 } to (vtnet0) port 39110

3. Give each person a pinned identity, valid for a limited time: the trust-token join flow above, with `--cert-expires`. For a fleet,
   make the client certificate of each host in the repository (`hosts/<host>/remote.sops.yaml`, encrypted; the plaintext key never
   touches the disk) and trust it on the host:

       jailops-sync remote bootstrap web1 --url https://web1.example.org:39110 --fingerprint <sha256 of the server certificate>
       # it prints the command to run on web1 as an administrator; run it there

   The connection refuses a server whose certificate does not match the fingerprint. With your own CA-signed certificate leave the
   fingerprint to the system roots instead (see "Pinning and renewal").
4. **Take the tokens and passwords away.** The listener requests a client certificate but does not require one, so a token that
   exists works from anywhere the firewall lets in: `jailops token list` and `jailops token revoke`, no `jailops user create`, and
   no `token_secret` in `host.yaml`. A client that presents no certificate and no token reaches only the public routes: `GET /api/v1` (the
   version, the extensions, and whether it is trusted), `GET /healthz`, `GET /readyz`, `POST /api/v1/auth/login` (which needs a valid user and
   password), `POST /api/v1/trust/clients` (which needs a valid single-use trust token), `POST /api/v1/cluster/join` (answers 501) and the
   static console files. A non-root local user of the unix socket is exactly such a client.
5. Revoke by deleting the identity: `jailops cert revoke NAME|FINGERPRINT`. There is no CRL; the trust store is the list.

**UNVERIFIED on a real network:** the whole recipe end to end on a public address, a CA-signed certificate with renewal on a real host,
`jailops-sync` over the network with a CA-signed certificate. What the repository's tests do prove, with in-process daemons: TLS 1.3 only
and no plain http, a served and a reloaded certificate, a broken renewal ignored, a configured certificate never generated over, pinned
client certificates and the join flow, the web console switched off.

## Load balancers and monitors

Two routes answer without credentials, plain text, and are left out of the access log:

| Route | Answers | Use it for |
|---|---|---|
| `GET /healthz` | `ok`, always 200 | **liveness**: the process runs and answers HTTP. It checks nothing else; restart the daemon when it stops answering |
| `GET /readyz` | `ok` (200), or `not ready: CLASS` (503) | **readiness**: send traffic only while it is 200 |

`/readyz` is 200 only when the daemon finished starting, the privileged helper answers a read-only call (whether the
JailOps dataset exists) and the database answers a query; each check has 2 seconds. CLASS is one of `starting`,
`stopping` (the daemon is shutting down), `helper`, `storage` (the helper answered, the dataset is missing) or `store`,
and nothing else: no error text, no path, no version. The answer is cached for 2 seconds, so a flood of probes reaches
the helper and the database at most once per period; a probe interval of 5 to 10 seconds is enough. Like every anonymous
route it has no request limit of its own; a bad credential sent with it counts toward the lockout of its source, and a
locked-out source gets 429. `?host=` is not forwarded to a hub's hosts: probe each host itself.

    curl -ks -o /dev/null -w '%{http_code}\n' https://host.example.org:39110/readyz     # 200 or 503
    curl -s --unix-socket /var/run/jailops/jailops.sock http://jailops.local/readyz     # any local user

Behind a proxy, probe the daemon (`https://127.0.0.1:39110/readyz`), not the proxy. Readiness is not health: a ready
daemon can still have a failing check (a pool that is degraded, a certificate about to expire). For those, see what to
monitor in [operations.md](operations.md#what-to-monitor).

## Not yet

- **ACME with `dns-01`, and wildcard certificates.** Only `http-01` and `tls-alpn-01` are built (above); upload a wildcard
  certificate obtained elsewhere, or point `listen.https.cert`/`key` at files another tool renews.
- **Requiring a client certificate** (an mTLS-only mode): the listener requests but never requires one, so tokens and logins that
  exist keep working. Client certificates are trusted one by one by fingerprint; there is no client CA, no CRL, no OCSP.
- **The caller's address behind a proxy** (`X-Forwarded-For`, the PROXY protocol): the lockout and `--allow-from` see the proxy.
- **A plain-http listener on loopback** for a proxy (the listener is TLS only, so the proxy needs `https://` upstream).
- **Separate listeners** for the API and the console, or a console switch per listener: `web.enabled` is for the daemon.
- **Trust tokens that follow a renewed certificate**: a token pins the certificate served when it is issued; with a public
  certificate use an API token.
- A hub that presents a CA-signed certificate as its client identity: a hub with `listen.https.cert`/`key` reuses that
  certificate for its client connections to hosts, which is meant for the self-signed one. Run a hub with the default
  certificate (an uploaded or ACME certificate is fine: the generated pair stays the hub's client identity).
