# Provisioning: a host, and a jail

Two things are called provisioning. This page keeps them apart.

## 1. Provisioning a host: a fresh VM to a running fleet

[`examples/provisioning`](../examples/provisioning) is a cloud-init-style path in one repeatable script, `bootstrap.sh`: it checks
FreeBSD 15.1 and the pool, loads the kernel modules, installs the packages, adds the three `pf.conf` anchor lines, turns on
forwarding, runs the setup, writes what the host operator approves into `priv.conf` (`admin-host-mount`),
starts the services, requires a clean `jailops doctor`, clones a fleet repository and runs `jailops-sync validate`, `plan` and
`sync --apply`. It is the sequence of [install.md](install.md) as a script; the README of the example lists every variable.

Order of responsibility, and why it is split:

| Who | Decides | Where |
|---|---|---|
| the host operator (root) | what the unprivileged daemon may ask the helper for | `priv.conf`, `jailopsd.yaml`, `pf.conf`: written by `bootstrap.sh`, never by the API |
| a global admin | networks, storage, images, projects | the fleet repository, applied by `jailops-sync` |
| a project operator | jails inside a project's grants | the fleet repository or the CLI |

A fleet applied on the host itself reaches `jailopsd` through the local socket (root is a global admin there), so a bootstrap needs
no token. Anything remote uses a token or a pinned client certificate; see [exposure.md](exposure.md).

Keep it converged with `jailops-sync watch --once --apply` from cron, or only report with `jailops-sync drift`.

**UNVERIFIED:** the script on a fresh cloud VM, and `nuageinit` as the way to run it (the individual commands are those of install.md and
`scripts/ci-freebsd-e2e.sh`, which run on FreeBSD 15.1).

## 2. Provisioning a jail: the `provision:` step

`spec.provision` of a jail is a short, repeatable creation step, not configuration management: no agent in the jail, no convergence.

    provision:
      packages: [nginx]                       # pkg install -y   (apk add on Alpine)
      files:                                  # copied from <state_dir>/project-files/<project>/ on the host
        - {source: nginx/nginx.conf, destination: /usr/local/etc/nginx/nginx.conf, mode: "0644"}
      services: {enable: [nginx], start: [nginx]}     # sysrc nginx_enable=YES; service nginx start
      commands:                               # argv, never a shell
        - [nginx, -t]

- **The order is fixed: packages, files, services, commands.** Everything else (a private package repository, a database
  `initdb`) is a command, and a command that must come before `packages` cannot exist: install from a private repository with
  `commands` only (see the PkgOps example).
- It runs **once**, at the jail's first start (or `jailops provision JAIL`). Changing the declaration does nothing until
  `jailops provision JAIL --again`; the completion is recorded in the jail's status.
- File sources are **files of the project on the host**, never arbitrary host paths (symbolic links that leave the directory
  are refused). `jailops-sync` declares the jail, not those files: put them there yourself, for example from `bootstrap.sh`.
- `provision` commands and the whole step are marked admin-sensitive in the [security model](security-model.md).

Examples: `examples/web-stack` (nginx and PostgreSQL), `examples/pkgops-packaged-service` (a package from your own PkgOps repository).
**UNVERIFIED on FreeBSD:** every provisioning command as run through `jexec` (the design register says so), including `pkg install`
inside a minimal pkgbase jail.
