# provisioning

From a fresh FreeBSD 15.1+ VM with a ZFS pool to a running fleet, with one script. It is the cloud-init-style path:
install JailOps, set the host up, start the services, and let `jailops-sync` apply a fleet from git.

    provisioning/
      bootstrap.sh     the whole sequence of docs/install.md, repeatable
      user-data        a first-boot script for a cloud image that runs one: sets variables, fetches and runs bootstrap.sh
      fleet/           a small fleet the script applies (tested like every example): image, network, project, one nginx jail

## The one-liner

    JAILOPS_POOL=zroot \
    JAILOPS_PKG_DIR=/root/pkgs \
    JAILOPS_FLEET_REPO=https://git.example.org/ops/fleet.git \
    sh bootstrap.sh

What it does, in order (each step is idempotent):

1. refuses anything older than FreeBSD 15.1, and a pool that does not exist;
2. loads `if_epair`, `nullfs`, `pf` now and at boot;
3. installs the packages (`jailops-client`, `jailops`) from `JAILOPS_PKG_DIR` with `pkg add`, or `pkg install jailops` from a
   repository you configured. **`pkg.jailops.net` is not live yet**: build the packages with `just build-freebsd` and
   `scripts/pkg-build.sh` (see `packaging/pkg/README.md`);
4. adds the three `anchor "jailops/*"` lines to `pf.conf` when they are missing, checks the file with `pfctl -nf`, and enables
   pf **without restarting a running one** (a restart cuts an ssh session);
5. turns on IPv4 and IPv6 forwarding (JailOps never does);
6. `jailops-priv init -pool $JAILOPS_POOL -web`: the user and groups, the datasets, the directories, `priv.conf` and `jailopsd.yaml`, and the web console on port 39110 (`JAILOPS_WEB=no` leaves it off);
7. writes what the host operator approves into `priv.conf`: `JAILOPS_HOST_MOUNTS` (`admin-host-mount`);
8. starts `jailops_priv` and `jailopsd`, waits for the socket and fails if `jailops doctor` shows a `FAIL`, and creates the
   JailOps administrator `JAILOPS_ADMIN_USER` when given (password from `JAILOPS_ADMIN_PASSWORD_FILE`, else generated into `/root/jailops-admin-password`, mode 0600);
9. clones the fleet repository (`JAILOPS_FLEET_REPO`), installs the age key that opens its SOPS secrets
   (`JAILOPS_AGE_KEY_FILE`), and runs `jailops-sync validate`, `plan` and `sync --apply`.

Without `JAILOPS_FLEET_REPO` it stops after step 8: a working, empty JailOps host.

The fleet reaches the host through the **local socket** (`socket: /var/run/jailops/jailops.sock` in `fleet/hosts/self/host.yaml`),
where root is a global admin: no token and no certificate exist anywhere in the repository. A fleet that manages other
hosts uses `url`, `fingerprint` and a token or a client certificate ([multi-host-fleet](../multi-host-fleet)).

## First boot of a cloud image

`user-data` is a script a cloud image runs at first boot (FreeBSD's `nuageinit` runs user-data that starts with `#!`;
other providers have their own way). It sets the variables, downloads `bootstrap.sh` from your repository and runs it, logging to
`/var/log/jailops-bootstrap.log`. Deliver the age key **out of band** (a provider secret store, a mounted volume): never put it in
user-data, which most providers show to anyone who can read the instance's metadata.

## After the first run

    jailops-sync -C /var/db/jailops-fleet drift             # does the host still match git?
    jailops-sync -C /var/db/jailops-fleet watch --once --apply   # in cron: pull, plan, apply

Images: the fleet's image has `build: true`, so the first generation is built when the image is created, and a jail on it can start.
That first build downloads pkgbase packages and takes minutes.

## Verified, and not

Each command is one of `docs/install.md` or `scripts/ci-freebsd-e2e.sh`, which run on FreeBSD 15.1 (a clean install, both
architectures). **UNVERIFIED:** `bootstrap.sh` itself on a fresh VM (it is syntax-checked and its fleet is applied to in-memory hosts
by the test suite), `user-data` on any cloud provider including `nuageinit`, and the `provision:` step (`pkg install nginx` inside
the jail) on FreeBSD.
