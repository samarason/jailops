# Linux jails (Alpine and Debian)

JailOps runs Linux userlands as jails through the FreeBSD **Linuxulator**: Alpine from its minirootfs (musl) and Debian from
`debootstrap` (glibc). They are jails like any other (a ZFS dataset, a VNET interface, a PF anchor, snapshots, rollback,
backups) with a Linux userland instead of a FreeBSD one. What a Linux jail can run is bounded by what the Linuxulator
supports. Verified on **FreeBSD 15.1 arm64 and amd64** (below).

## What was verified (FreeBSD 15.1 arm64)

- **Alpine 3.22** (aarch64, musl): `apk update` and `apk add openssh nginx` work, nginx serves a page, sshd answers, a ZFS
  rollback repairs a broken root; the jail has IPv4 and IPv6 connectivity.
- **Debian 13 (trixie)**, glibc 2.41, built with `debootstrap` (80 packages, 140 MB): `apt-get update` and `install` work; the
  jail has IPv4 and IPv6 connectivity (`curl -4` and `curl -6` return 200).

**October 2026, with the /32 and /128 addressing of design 18.13, on arm64 (routed IPv6) and amd64 (proxy-mode IPv6):** an
Alpine 3.22 and a Debian 13 jail each got their `/32` with the on-link route to the gateway (`eth0`: `10.x.x.1 UH`, default
via it), `apk add curl` and `apt-get install curl iputils-ping netcat-openbsd` worked, `curl -4` and `curl -6` reached the
internet, the two jails reached each other (IPv4 ping, IPv6 over tcp) and the host reached them (and, on amd64, a host
on the internet reached both over IPv6 after the operator rule of [install.md](install.md)); 10 restarts of each jail on each
host were clean; and forged ARP frames and neighbour advertisements written from inside the Alpine jail (a FreeBSD
binary run in the jail, with `bpf` unhidden for the test) changed no cache. Two limits seen: `ping -6` does not work in a
Linux jail (the Linuxulator has no `ICMP6_FILTER`; use tcp), and the network needs `dns` servers or the jail has no
resolver (the network's `dns` list is written to `resolv.conf`; `network create` has no flag for it, use a file or
`network edit`); `jailops doctor` warns (`network.dns`) about a network in use without one.

Not verified: other glibc distributions, behaviour under load, **managed updates and package provisioning for Debian**
(they run `apk` only; an upgrade of a debootstrap generation is refused, build a new one).

## Host prerequisites

The daemon loads the Linux modules (`linux64`, `linprocfs`, `linsysfs`, `fdescfs`) while a Linux jail or a Linux image exists (and before it builds one, so the first build works from a clean host: verified on arm64 with the modules unloaded), and manages
`kern.elf64.fallback_brand=3` for as long as one does: unbranded ELF binaries (Alpine's `apk`, `nginx`, `sshd` are not
branded Linux) must run as Linux, and the kernel refuses them otherwise. Native FreeBSD binaries carry a FreeBSD brand and are
unaffected. `jailops doctor` checks it (`sysctl.kern.elf64.fallback_brand`); the daemon returns the value to -1 only if it was
the one that set it.

For Debian only:

    pkg install debootstrap
    # a Debian keyring, because the port ships only Ubuntu's
    # (for example debian-archive-keyring.gpg in /usr/local/share/keyrings)
    ln -s gpgv /usr/local/bin/gpgv2        # the port's debootstrap insists on a program named gpgv2 although it uses gpgv

## Build an image and start a jail

    jailops image create alpine-3 --os linux --release 3.22 --arch arm64 --source-type minirootfs --alias latest
    jailops image build alpine-3

    jailops image create debian --os linux --release trixie --arch arm64 --source-type debootstrap \
        --keys /usr/local/share/keyrings/debian-archive-keyring.gpg --alias stable
    jailops image build debian

    jailops create db --project web --image debian@stable --network lan --storage default
    jailops start db --project web
    jailops exec db --project web -- cat /etc/os-release

- **The release signature is always checked.** A keyring is mandatory for `debootstrap` (`--keys`) and the mirror must be https;
  the helper's `debootstrap` rule refuses anything else (debootstrap itself only warns about a missing signature and goes on).
  The Alpine rootfs is checked against its published (or pinned) sha256.
- The image's base is built with the helper (`debootstrap` runs with a fixed environment so that it finds its tools). Only the
  hosts in `fetch-host` of `priv.conf` can be downloaded from, and the keyring that checks the release is a file in `keyring-dir`
  (default `/usr/local/share/keyrings`) that root owns.
- Linux jails default to the **thick** layout (a full copy of the generation); copying it into the jail runs inside the helper
  (`zfs.replicate`), 140 MB in about 2 seconds.

## How they differ from FreeBSD jails

- **Mounts:** a private devfs ruleset, `fdescfs`, a `nullfs` mirror of the root on `compat/linux` (the Linuxulator resolves paths
  through `/compat/linux` first, and a file create below it fails otherwise), `tmpfs` on `compat/linux/dev/shm`, `linprocfs` and
  `linsysfs`. JailOps writes the jail's `fstab`. The jail's `/dev` is mounted with a private devfs ruleset that the helper loads into
  the kernel before the jail is created, from rules it validates itself; a jail whose ruleset cannot be loaded does not start
  (see [Devices](security-model.md#devices)).
- **Network:** a Linux userland has no tooling that works here, so the host configures the jail with the `-j` forms
  (`ifconfig -j`, `route -j`) after the epair moved. Linux sees the interface as `eth0`.
- **Updates** are in place (`apk` inside the jail), with a snapshot first. A root swap does not apply.
- **The shell** `jailops shell` starts is `/bin/sh` unless the jail's `shell` key says otherwise.

## Limits to keep in mind

A Linux jail is not a Linux kernel: system calls are translated, `/proc` and `/sys` are emulations, and software that needs
kernel features the Linuxulator lacks (containers inside, some `systemd` behaviour, `io_uring`, new syscalls) will not work.
Test your workload before you plan around it.
