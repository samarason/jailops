# FreeBSD packages

The packages on `pkg.jailops.net` are built, signed and published by
[jailops-packages](https://github.com/jailops/jailops-packages) with [PkgOps](https://github.com/jailops/jailops-pkgops): no FreeBSD
machine is needed, Go cross-compiles on Linux. That repository holds the package definitions of the three packages below
(`main/jailops-client`, `main/jailops`, `main/jailops-backupd`) and the install instructions for a host.

The rest of this file describes the **old path**, kept for a transition: `scripts/pkg-build.sh` makes the packages from
binaries cross-built on any machine (`goreleaser` or `just build-freebsd`) and `scripts/pkg-repo.sh` turns a directory of
packages into a signed repository. Both run on FreeBSD, because they use `pkg(8)`. They can be removed once the first
JailOps packages have been published from jailops-packages.

Three packages come out of one build:

| package | holds |
|---|---|
| `jailops-client` | `jailops`, `jailops-sync` (any machine that talks to a daemon), their bash, zsh and fish completion and their man pages (`man1`, one page per command) under `share/`, generated from the binaries at build time (`scripts/gen-share.sh`; `just build` leaves them in `bin/share`) |
| `jailops` | `jailopsd`, `jailops-priv`, the rc.d scripts, sample configuration and the man pages `jailopsd(8)` and `jailops-priv(8)` (hand-written, `packaging/man/`); depends on `jailops-client` |
| `jailops-backupd` | the backup node, its rc.d script, sample configuration, completion scripts and `jailops-backupd(8)` |

JailOps targets FreeBSD 15.1 and later, so packages are built for the 15 ABI only (`FreeBSD:15:amd64`,
`FreeBSD:15:aarch64`); `jailops doctor` fails on an older release.

A fourth package, `jailops-apps`, installs the application catalog ([docs/apps.md](../../docs/apps.md)) under
`/usr/local/share/jailops/apps/`. It is not built from this repository: its definitions live in jailops-packages
(`main/jailops-apps/apps/`) and it has a version of its own, released without a JailOps release. It holds data only,
depends on nothing, and its signature is what makes the catalog trusted; the daemon never fetches one.

## The repository

    pkg.jailops.net/<ABI>/latest/All/*.pkg
    pkg.jailops.net/<ABI>/latest/{meta.conf,packagesite.pkg,data.pkg,...}   (written by pkg repo)

The repository is signed with an RSA key. The private key lives only in the `signing` environment of the
[jailops-packages](https://github.com/jailops/jailops-packages) repository (the `PKG_REPO_KEY` secret, made by its
`scripts/keygen.sh`), never in this repository or in any workflow here; the public key is published at
`https://pkg.jailops.net/jailops.pub` and its fingerprint is in that README.

A host uses it with `/usr/local/etc/pkg/repos/jailops.conf`:

    jailops: {
      url: "https://pkg.jailops.net/${ABI}/latest",
      signature_type: "pubkey",
      pubkey: "/usr/local/etc/pkg/keys/jailops.pub",
      enabled: yes
    }

Then `pkg update && pkg install jailops`, and `jailops-setup` once, as root: it sets the host up and turns the web console on (port 39110).
