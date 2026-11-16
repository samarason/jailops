# Installing JailOps on a FreeBSD host

JailOps needs **FreeBSD 15.1 or later**, a ZFS pool, and a firewall that is `pf`. `scripts/ci-freebsd-e2e.sh` is the
whole sequence below on a clean machine, and it is what the CI job runs; if a step here and that script disagree, the
script is right.

## Quick install

As root, after trusting the package repository (section 2):

    pkg install jailops
    jailops-setup -n        # what it would do; changes nothing
    jailops-setup           # -pool NAME when the host has more than one pool

`jailops-setup` does sections 1 and 3 to 6 below, in that order, and only what is not done yet (run it again and
nothing changes): the kernel modules, the one-time setup of the pool, forwarding, the anchor line in
`/etc/pf.conf`, the service (`jailopsd` with the web console; it starts the helper), `jailops doctor` and the first
administrator; it ends with the console's address. Every action is printed on one line before it runs.

It never changes or moves a line of `pf.conf`: it inserts what is missing where pf wants it (`set state-policy
if-bound` and a `scrub` rule only when there are none, and says so), keeps the old file as
`/etc/pf.conf.jailops-setup-<date>`, checks the new text with `pfctl -nf` before writing anything and loads it with
`pfctl -f`, which keeps your ssh session. Without a `pf.conf` it writes a minimal one that blocks nothing. It never
runs `service pf restart`. Starting pf is said first and asked (a `pf.conf` with `block` rules can cut ssh if no rule
passes it); `-y` answers yes to everything. Then continue with section 7. `man jailops-setup` has the details; the
sections below explain each step and are the way to do it by hand.

## The appliance path

For a host you run from the web console: install FreeBSD (on ZFS, as the installer offers), then four commands as root,
and a browser.

    pkg install jailops
    sysrc jailopsd_enable=YES jailopsd_web=YES jailops_appliance=YES    # jailops_pool=zroot to name the pool
    service jailopsd start
    service jailopsd setuptoken                                 # or read the token and the address on the system console

Then open `https://HOST:39110/` in a browser and enter the token.

(Trust the package repository first, as section 2 says.) What happens: `jailops_appliance="YES"` hands host management
to JailOps ([appliance.md](appliance.md): the host name, resolvers and NTP, and the host's firewall) in both programs at
once, without editing `priv.conf` or `jailopsd.yaml`. The first start (of the helper, which `service jailopsd start` starts) finds no `priv.conf` and sets the
host up (`appliance-init`: the user, the datasets on `jailops_pool` or the pool of the root file system, the
configuration files; every command it runs is in syslog). The start of `jailopsd` prints a **one-time setup token** and
the console's addresses on the system console (and in `/var/log/auth.log`); `service jailopsd setuptoken` prints a new one,
valid for 24 hours. The console opens a wizard: the first administrator (with the token), the host name, the
certificate, the host firewall (ssh only from your address, reverted unless you confirm), storage and a network, and the
base image: the image of the host's own release and architecture, named after it (`freebsd-15-1` on 15.1-RELEASE),
created and built in the step, with an optional nightly auto upgrade (one checkbox, off until you tick it, 03:00 by default; see
[upgrade.md](upgrade.md#nightly-auto-upgrade)) (the build downloads the base system packages from `pkg.freebsd.org` and takes a few minutes; a failed
build says what to check and is tried again in place). The wizard ends with **Install your first app** (the app
catalog; `pkg install jailops-apps` installs it), or with **Create the base image** when that step was skipped: apps and
jails start from an image, and the Images page (Create image) makes it at any time. `jailops doctor` should then
report `appliance` ok.

The first service is then one dialog: on the Apps page choose an app and Install; it takes the project, network and
storage the wizard made and the FreeBSD image of the newest release the host can run (`freebsd-15-1`). Without an
image the dialog says so and offers to create the base image instead of failing.

The kernel modules, forwarding and the other host settings of sections 1 and 4 still apply; `jailops doctor` names what
is missing. The browser warns about the self-signed certificate until you replace it, one of two ways:

### Internet facing: ACME

When the host's DNS name points at it from the internet, let the daemon obtain a certificate from a public CA and renew
it: in the wizard's certificate step or the Host page (Certificates, Request with ACME), give the names, agree to the CA's
terms, and choose http-01 (port 80) or tls-alpn-01 (port 443). The daemon is not root, so the host redirects that port to
it: with the firewall module (on with `jailops_appliance`), apply the host firewall once more after turning ACME on and
JailOps adds the redirect; otherwise add the two `pass in quick … rdr-to` lines the page shows to `/etc/pf.conf`, after the line `anchor "jailops/*"`. Clients then trust the
certificate through their roots and pin nothing. Wildcard names are not possible (no dns-01). Details:
[exposure.md](exposure.md#acme-a-certificate-from-a-public-ca).

### Inside a network: your own certificate

On a private network, upload a certificate of your own CA in the wizard or on the Host page (Certificates, Upload): the
PEM chain, its key and the host name clients use. It is checked, written to `/var/db/jailops/tls`, and served from the
next connection on; nothing renews it, so upload the next one before it expires (`jailops doctor` warns 14 days before).
Or keep the self-signed certificate: clients pin its fingerprint (the page shows the `jailops remote add` command).
From the command line, `jailops host certificate show|acme|upload|self-signed` does the same as the Host page.

The rest of this page is the manual path, which the appliance path does for you.

## 1. What the host needs

- A ZFS pool you are willing to give a dataset to (below: `zroot`, the default pool of the FreeBSD installer). JailOps never runs `zpool upgrade`.
- Kernel modules `if_epair`, `pf` and `zfs`: the three `jailops doctor` checks (`zfs` is loaded already
  on a FreeBSD installed on ZFS). Load them now and at boot:

      kldload -n if_epair pf zfs
      sysrc -f /boot/loader.conf if_epair_load=YES pf_load=YES zfs_load=YES

  (Linux jails also need `linux64`, `linprocfs`, `linsysfs` and `fdescfs`; the daemon loads those itself while a Linux
  jail exists. `nullfs`, which host-directory volumes use, is loaded by `mount` when it is first needed.) `jailops doctor` reports
  a missing module with the command to load it.
- Network access to `pkg.freebsd.org` for building images from pkgbase. The helper's download rule allows only the
  hosts in `fetch-host` of `priv.conf` (default `dl-cdn.alpinelinux.org`, `pkg.freebsd.org`, `pkg.jailops.net`, `deb.debian.org`, `archive.ubuntu.com` and `ports.ubuntu.com`), over https.

## 2. Install the packages

There are three packages: `jailops-client` (`jailops`, `jailops-sync`), `jailops` (`jailopsd`, `jailops-priv`, the rc.d
scripts and sample configuration; depends on the client) and `jailops-backupd` (the backup node, only for a host that
runs one).

    pkg install jailops

Trust the repository first, once (the steps and the key fingerprint are in the README of
[jailops-packages](https://github.com/jailops/jailops-packages)): the public key at `https://pkg.jailops.net/jailops.pub`
and `/usr/local/etc/pkg/repos/jailops.conf` with `url: "https://pkg.jailops.net/${ABI}/latest"` and
`signature_type: "pubkey"`. The packages are built for the FreeBSD 15 ABI only, for amd64 and aarch64, and need FreeBSD
15.1 or later. The JailOps packages (`jailops`, `jailops-client`, `jailops-backupd`) appear in the repository after each
release; you can also build from source (`just build-freebsd`) or take the static binaries from the GitHub release archives.

The client package installs shell completion for `jailops` and `jailops-sync` where the shells look for it:
`/usr/local/share/bash-completion/completions/`, `/usr/local/share/zsh/site-functions/` and
`/usr/local/share/fish/vendor_completions.d/`. Bash finds it by itself with the `bash-completion` package (`pkg install
bash-completion` and its line in `.bashrc`); without the package, `source <(jailops completion bash)` in `.bashrc` does the
same, the script brings what it needs. Zsh needs `compinit`; fish finds it by itself. Tab completes commands and flags
offline, and asks the server for what a name or a value can be: jails, volumes, images, networks, storages, projects,
firewall policies, address sets, backups, users and sessions of the project you work in; the values of a flag or a
configuration key (`jailops config set web boot.autostart <Tab>`); the ends of `jailops firewall test` (`jail:web`, `host`,
the addresses of the jails); files where a flag names one (`-f`, `--passphrase-file`) and nothing where you type a new name
or free text (a second Tab says what is expected). Without a server the shell just gets no names. For a binary installed by
hand, `jailops completion bash|zsh|fish` prints the script (`jailops completion --help` says where to put it). The packages also install man pages: `man jailops`, `man jailops-jail-list` and so on for every command of
`jailops` and `jailops-sync` (client package), `man jailopsd` and `man jailops-priv` (host package), `man jailops-backupd`
(backup node package, which installs the completion of `jailops-backupd` too).

## 3. The firewall: one line in `pf.conf`

JailOps never owns `/etc/pf.conf` (unless you hand it over with the firewall module of [appliance.md](appliance.md)).
It loads one anchor per jail, per project and per network below `jailops/`, and you
add one line **once**: the anchors hold the filter rules of the jails and the NAT and port forwards of their networks
(`match … nat-to`, `rdr-to`), so the line belongs among your filter rules, before any `quick` rule that should not
decide first.

    # ... your own options and scrub, then ...
    anchor "jailops/*"
    # ... your filter rules

Two things to know about a host that already has a firewall:

- A `quick` pass rule that comes **before** `anchor "jailops/*"` passes its traffic for good, so JailOps's policies
  cannot filter it and the NAT of a network does not apply to it. `jailops doctor` warns (`pf.order`) and names such rules. Put the anchor line before broad `quick`
  passes.
- Reload with `pfctl -f /etc/pf.conf` and check it first with `pfctl -nf /etc/pf.conf`. Do **not** use
  `service pf restart` or `pfctl -F states` on a machine you are logged into over ssh: it flushes the states and cuts
  your session.

- **Normalise packets.** Put `scrub in all fragment reassemble` near the top of `pf.conf` (add `max-mss <n>` when the
  uplink is a tunnel or has a smaller MTU than the jails). The jails' anchors accept `match ... scrub` options (checked
  with `pfctl -a` on FreeBSD 15.1) but JailOps does not render any: the clamp depends on the uplink, which is yours.
  `jailops doctor` warns (`pf.scrub`) when the loaded ruleset has no scrub rule; the format it looks for is the one
  `pfctl -s rules` prints, `scrub in all fragment reassemble`.
- **`set state-policy if-bound`.** Put it at the top of `pf.conf`, with the other options. A jail's traffic crosses the
  host's firewall twice (in on the jail's link, out on another), and pf must judge it at both: with the default
  (floating) states a connection that the first hop admitted would pass the second without being looked at again, and
  the rules of the jail it is going to would never see it. JailOps's own rules say `if-bound` themselves; the line makes
  your rules behave the same. Load it with `pfctl -nf /etc/pf.conf && pfctl -f /etc/pf.conf`. `jailops-setup` adds it,
  and `jailops doctor` fails (`pf.state-policy`) when jails exist and the `pf.conf` the system loads (`pf_rules` of
  `rc.conf`, else `/etc/pf.conf`) lacks it. Because states are bound to interfaces, a host that blocks by default
  needs a rule that lets the jails' traffic out of the uplink (`pass out on vtnet0 keep state`) as it does for any
  other machine it forwards for.
- **DNS for the jails.** A network without `dns` hands its jails the host's own nameservers from `/etc/resolv.conf`.
  A host that resolves only through a local unbound (`nameserver 127.0.0.1`) hands them the network's gateway address
  instead, and unbound has to listen there: the lines are in
  [networking-ipv6.md](networking-ipv6.md#name-resolution-of-jails), and `jailops network create` prints them.
- **Traffic from the internet into a jail** is stopped by a host whose `pf.conf` blocks inbound traffic on the uplink by
  default. JailOps does not open the uplink for you: admit the addresses of the jails, and only the ports you want,
  with a rule of your own. The jail's anchor still applies afterwards (its policy decides what reaches the jail), so
  this rule is the host's door, not the jail's. For jails with addresses in `2001:db8:1:2:100::/80` behind `vtnet0`:

      pass in quick on vtnet0 inet6 proto tcp from any to 2001:db8:1:2:100::/80 port 8080

  (Verified on FreeBSD 15.1 amd64 with a jail listening on 8080 and `curl -6` from another host.) ICMPv6 errors, which
  path MTU discovery needs, are admitted by the jails' own anchors; the host's default `pass quick inet6 proto
  ipv6-icmp` line must stay.

Then `sysrc pf_enable=YES`, and start pf only if it is not running (`service pf onestart`).

## 4. Forwarding

JailOps turns forwarding on at run time when a network needs it, but it does not make it persistent: you do, and
`jailops doctor` checks that it is on and persistent:

    sysrc gateway_enable=YES ipv6_gateway_enable=YES
    sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1

A host with a switched IPv6 network (`--ipv6-mode proxy`, a `/64` on a segment shared with other customers) must also
answer the neighbor solicitations its routers send from off-link addresses, or the routers drop it for minutes at a
time (see [networking-ipv6.md](networking-ipv6.md)). `jailops doctor` checks it too, and JailOps never sets it:

    sysctl net.inet6.icmp6.nd6_onlink_ns_rfc4861=1

and in `/etc/sysctl.conf`, so it survives a reboot:

    net.inet6.icmp6.nd6_onlink_ns_rfc4861=1

Optional: `kern.racct.enable=1` in `/boot/loader.conf` (it takes a reboot) turns the kernel's resource accounting on,
which `jailops jail info` needs for a jail's usage and resource limits need for enforcement.

## 5. Set the host up

`jailops-setup` does this step (the Quick install at the top runs it; `jailops-setup -n` shows what it would do). The
helper program it uses is not run by hand: it is in `/usr/local/libexec`, not in `PATH`.

It is the one-time setup of what the unprivileged daemon cannot make for itself. It creates the user and group `jailops`,
the storage root dataset `<pool>/jailops` (mounted at `/usr/local/jailops`), the state dataset `<pool>/jailops/state`
(mounted at `/var/db/jailops/state`, owned by the daemon's user), the logs dataset `<pool>/jailops/logs` (at
`/var/log/jailops`), the directories, and the two configuration files `/usr/local/etc/jailops/priv.conf` and
`jailopsd.yaml`. It is idempotent: run it twice and nothing changes.

## 6. Start the services

Run these as root. FreeBSD has no `sudo` in the base system: log in as root, use `su -m root -c '...'` (or `su -`), or
install `doas` or `sudo` from packages; the examples below write the commands as root runs them.

    sysrc jailopsd_enable=YES jailopsd_web=YES
    service jailopsd checkconfig
    service jailopsd start
    jailops doctor

One service is enough: `service jailopsd start` starts the privileged helper first (rc.subr's force_depend), `stop` stops
both and `restart` replaces both. At boot the order is declared in the rc scripts, and a helper that crashes is started
again by daemon(8) after 5 seconds.

Then create the first administrator. On the host, **root is the global administrator of the unix socket** (the recovery access); every
other local user is anonymous until they sign in with a JailOps identity. There is no Unix group that grants a role.

    jailops user create admin --admin --password-prompt     # a global administrator; the password is asked, never an argument
    jailops user set-password admin                         # recovery: root replaces a lost password, no old one needed

Tokens for scripts come after the first project exists (section 7), because a token is scoped to projects:
`jailops token create ci --role operator --projects web --expires 720h`.

`jailopsd_web=YES` turns the web console on and opens the TLS listener on port 39110: open `https://HOST:39110/` and sign in as `admin` (the
server certificate is self-signed; open the port in your firewall for the machines that should reach it, see [ports.md](ports.md)). Leave
the line out for a host you only reach with the CLI.

Identities (users, API tokens, client certificates) have the same roles, scopes and audit over the socket and over the network.
A person who is not root uses a token (`JAILOPS_TOKEN`, or `jailops remote add`) or signs in to the web console. Run the commands
below as root or with such a token.

`jailops doctor` should show no `FAIL`. A `WARN` for `sysctl.persistent` means forwarding (or, with a switched IPv6
network, `net.inet6.icmp6.nd6_onlink_ns_rfc4861`) is on but will not survive a reboot until you set the `rc.conf` or
`sysctl.conf` lines of section 4. Section "doctor checks" of [troubleshooting.md](troubleshooting.md)
explains each check.

## 7. The first jail

There is no default project or network: you create them and name them. There is one storage from the start: `default`,
which the daemon creates on its first start for the dataset `<pool>/jailops` that section 5 made (`jailops storage list`
shows it). A project is granted the networks and storages its jails may use.

    jailops image create freebsd-15-1 --release 15.1-RELEASE    # the host's release; an image is one release
    jailops image build freebsd-15-1
    jailops image set freebsd-15-1 --auto-upgrade --upgrade-at 03:00      # optional: its patch levels every night
    jailops network create lan --ipv4 10.77.0.1/24 --uplink vtnet0 --nat    # vtnet0: the host's uplink, see below
    jailops project create web
    jailops network grant lan --project web && jailops storage grant default --project web
    jailops project switch web
    jailops create nginx --image freebsd-15-1 --network lan --storage default --start --autostart
    jailops exec nginx -- uname -a
    jailops token create ci --role operator --projects web --expires 720h    # a token for scripts, now that web exists

`--start` starts the jail now and `--autostart` starts it every time the host boots: a jail without it stays stopped after a reboot, also when it was running before. `jailops config set nginx boot.autostart true` turns it on for a jail that exists.

`--uplink` is the host's interface towards the outside: `vtnet0` on most virtual machines, `em0`, `igb0` or `ix0` on
real hardware (`ifconfig -l` lists them).

The project of a jail grants exactly one network and one storage here, so
`jailops create nginx --image freebsd-15-1 --start` would take `lan` and `default` by itself (and say so); naming
them keeps the command right when the project has more. A network is only an address range: it makes no interface of
its own, each jail gets a link of its own to the host ([networking.md](networking.md)).

`network create` checks the network against the host at once: an uplink that does not exist (or is a loopback, a bridge
or a bridge member) is refused with the interfaces that could be the uplink, a subnet that overlaps an address of the
host (`10.77.0.0/24` must not be the LAN `vtnet0` is on) is refused with the interface that has it, and when
forwarding is off (section 4) the command warns that the network stays not ready until `sysctl
net.inet.ip.forwarding=1`. New names have limits so that what is derived from them fits: a project at most 13
characters, a jail, a volume and an image 32, a snapshot 64 ([design.md](design.md#31-names-and-their-limits)).

The image is named after its release: `freebsd-15-1` is 15.1-RELEASE, and a jail made with `--image freebsd-15-1`
follows its newest generation (its newest patch level). The patch levels come with `jailops image upgrade freebsd-15-1`
or the nightly auto upgrade; a new release is a new image ([upgrade.md](upgrade.md#an-image-is-one-release)).

Without an image, `jailops app install` and `jailops create` are refused with a hint that names the two commands
above, with the host's release filled in.

`jailops shell nginx` (or the console's Console tab) opens bash in the jail with a light blue `root@nginx:/#` prompt:
a new FreeBSD jail gets bash from the host's package repository at its first start. `--shell sh` keeps FreeBSD's own
shell, `jailops config set nginx prompt ...` changes the prompt, your own `~/.bashrc` wins over it, and `jails:` in
`jailopsd.yaml` changes the defaults of the host ([shell.md](shell.md), also for the green prompt of the host).

An application from the catalog is one command more: `pkg install jailops-apps` puts the definitions under
`/usr/local/share/jailops/apps` (`jailops app list` shows them, `jailops app info nginx` describes one), and
`jailops app install nginx --network lan --storage default` creates a jail named `nginx`, installs the package into it
from the FreeBSD repository, enables and starts the service, checks that it answers, snapshots the fresh installation as
`app-installed` and prints where the site, the configuration and the logs are. `jailops app installed` lists the jails
that came from the catalog. What the installation does step by step, and what it leaves behind when a step fails, is in
[apps.md](apps.md).

Without `project switch` pass `--project web` (or set `JAILOPS_PROJECT=web`) on every jail command. `--start` starts the jail
once it is created (`jailops start nginx` does the same later). Several objects at once come from a file:
`jailops apply -f site.yaml` creates what is missing and updates what differs, document by document. IPv6, big pools and backups continue in
[networking-ipv6.md](networking-ipv6.md), [storage.md](storage.md) and [backup-restore.md](backup-restore.md).

## Start over

To wipe a host and install again (a test machine, a failed first try), as root. This destroys every jail, image,
volume and backup on the pool's `jailops` dataset; there is no undo. Replace `tank` with your pool.

```sh
service jailopsd stop; service jailops_backupd onestop 2>/dev/null
for j in $(jls -N name); do jail -r "$j"; done                  # every running jail
for i in $(ifconfig -l); do                                      # the epairs of JailOps, and the tunnels
	case $i in wg-*) ifconfig "$i" destroy ;; *) ifconfig "$i" 2>/dev/null | grep -q 'description: jailops' && ifconfig "$i" destroy ;; esac
done 2>/dev/null
zfs destroy -r tank/jailops                                      # images, jails, state, cache, logs
pkg delete -y jailops jailops-client
rm -rf /usr/local/etc/jailops /var/db/jailops /var/run/jailops /var/log/jailops /var/tmp/jailops
```

`jailops` remembers the current project in the client configuration (`~/.config/jailops/config.yaml`, root's own under
`/root`), not on the server: after starting over, `jailops doctor` warns that the project does not exist. Remove the
`project:` line of the remote there, or choose a new one with `jailops project switch NAME`.

Delete the anchor line of section 3 from `/etc/pf.conf` (with the `# jailops-setup:` comments and the
lines below them, if `jailops-setup` added them; its copy of the old file is `/etc/pf.conf.jailops-setup-<date>`) and
the `jailopsd_*` and `jailops_*` lines from `/etc/rc.conf` if the host keeps nothing of JailOps. The loop above destroyed the interfaces of your jails (they are in the kernel and
stay until they are destroyed or the host reboots; a running JailOps also removes the ones that belong to no jail). Then start at section 2 (or with `jailops-setup` after `pkg install jailops`). Packages of the base are fetched
again: the cache went with the dataset.

## Remote access

By default only the unix socket listens. To manage a host from another machine set `listen.https.address` in
`jailopsd.yaml` (for example `":39110"`), restart `jailopsd`, then on the host create a single-use trust token and use
it on the client (a token is valid for one hour by default):

    jailops cert enroll laptop --role operator --projects web          # on the host: prints a single-use token
    jailops remote add myhost host.example.org --token-file -         # on the client: paste the token, then Enter

`remote add` takes one argument here, the host's address (`host` or `host:port`, port 39110 by default): that is the
form that redeems a trust token. The client pins the server fingerprint from the token (there is no trust on first use),
makes a key pair and is trusted with the role and projects of the token. (`remote add NAME URL` with two arguments is for
an API token, `jot_...`.) The web consoles are served by the same listener.
