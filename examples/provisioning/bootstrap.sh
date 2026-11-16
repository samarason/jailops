#!/bin/sh
# bootstrap.sh: turn a fresh FreeBSD 15.1+ VM with a ZFS pool into a JailOps host, then apply a fleet from git.
#
#   JAILOPS_POOL=zroot JAILOPS_FLEET_REPO=https://git.example.org/ops/fleet.git sh bootstrap.sh
#
# It is the sequence of docs/install.md as one repeatable script (running it twice changes nothing the second time).
# UNVERIFIED as a whole on a fresh cloud image: every step below is a command of docs/install.md or of
# scripts/ci-freebsd-e2e.sh, which do run on FreeBSD 15.1, but this script itself has only been syntax-checked.
#
# Settings (environment):
#   JAILOPS_POOL          ZFS pool that gets the JailOps dataset (default zroot)
#   JAILOPS_PKG_DIR       directory with the built packages (jailops-client, jailops); pkg.jailops.net is not live yet.
#                         Without it the script runs `pkg install jailops` from whatever repository you configured.
#   JAILOPS_WEB           yes (default): also turn the web console on (TLS, port 39110); no: leave it off
#   JAILOPS_FLEET_REPO    git URL of the fleet repository (empty: install only, apply nothing)
#   JAILOPS_FLEET_PATH    where the clone lives (default /var/db/jailops-fleet)
#   JAILOPS_FLEET_BRANCH  branch to follow (default: the remote's default branch)
#   JAILOPS_AGE_KEY_FILE  an age identity file that opens the fleet's SOPS secrets (copied to /root/.config/jailops-sync)
#   JAILOPS_HOST_MOUNTS   comma-separated directories a global admin may host-mount into jails (admin-host-mount)
#   JAILOPS_ADMIN_USER    name of a JailOps administrator to create (a JailOps user, not a Unix user); without
#                         JAILOPS_ADMIN_PASSWORD_FILE a password is generated and written to /root/jailops-admin-password (0600)
#   JAILOPS_ADMIN_PASSWORD_FILE  file whose first line is that administrator's password (read from stdin, never argv)
#   JAILOPS_FORCE_PF=1    load pf.conf even though pf is already running (see the warning below)

set -eu

pool=${JAILOPS_POOL:-zroot}
fleet_repo=${JAILOPS_FLEET_REPO:-}
fleet_path=${JAILOPS_FLEET_PATH:-/var/db/jailops-fleet}
priv_conf=/usr/local/etc/jailops/priv.conf
sync=/usr/local/bin/jailops-sync
jops=/usr/local/bin/jailops

step() { printf '\n== %s\n' "$*"; }
die() { echo "bootstrap: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
[ "$(uname -s)" = FreeBSD ] || die "this is a FreeBSD script"

step "FreeBSD 15.1 or later, and the pool"
ver=$(freebsd-version -u | sed 's/-.*//')
major=${ver%%.*}
minor=${ver#*.}
if [ "$major" -lt 15 ] || { [ "$major" -eq 15 ] && [ "$minor" -lt 1 ]; }; then
	die "FreeBSD $ver is too old: JailOps needs 15.1 or later"
fi
zpool list -H -o name "$pool" >/dev/null 2>&1 || die "no ZFS pool named $pool (set JAILOPS_POOL)"

step "kernel modules"
kldload -n if_epair nullfs pf
sysrc -f /boot/loader.conf if_epair_load=YES nullfs_load=YES pf_load=YES >/dev/null

step "packages"
if [ -n "${JAILOPS_PKG_DIR:-}" ]; then
	# shellcheck disable=SC2046
	pkg add $(ls "$JAILOPS_PKG_DIR"/jailops-client-*.pkg "$JAILOPS_PKG_DIR"/jailops-[0-9]*.pkg) || \
		pkg add -f $(ls "$JAILOPS_PKG_DIR"/jailops-client-*.pkg "$JAILOPS_PKG_DIR"/jailops-[0-9]*.pkg)
else
	pkg install -y jailops
fi
if [ -n "$fleet_repo" ]; then pkg install -y git; fi

step "pf: the three anchor lines (JailOps never owns pf.conf)"
touch /etc/pf.conf
if ! grep -q 'anchor "jailops/\*"' /etc/pf.conf; then
	# nat-anchor and rdr-anchor belong with the translation rules, anchor with the filter rules; with no other rules
	# in the file the order below is the right one. If you already have a pf.conf, put the lines where install.md says.
	cat >> /etc/pf.conf <<'PF'
nat-anchor "jailops/*"
rdr-anchor "jailops/*"
anchor "jailops/*"
PF
fi
pfctl -nf /etc/pf.conf || die "/etc/pf.conf does not parse"
sysrc pf_enable=YES >/dev/null
if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
	# Never `service pf restart` or flush states on a machine you are logged into over ssh: it cuts the session.
	[ "${JAILOPS_FORCE_PF:-}" = 1 ] && pfctl -f /etc/pf.conf
else
	service pf onestart >/dev/null 2>&1 || true
	pfctl -f /etc/pf.conf
fi

step "forwarding (JailOps asks you for this and never changes it)"
sysrc gateway_enable=YES ipv6_gateway_enable=YES >/dev/null
sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null

step "jailops-priv init: users, groups, datasets, directories, configuration"
web=${JAILOPS_WEB:-yes}
if [ "$web" = yes ]; then
	/usr/local/libexec/jailops-priv init -pool "$pool" -web
else
	/usr/local/libexec/jailops-priv init -pool "$pool"
fi

step "priv.conf: what the host operator approves"
add_priv() { # add_priv KEY VALUE: append "KEY = VALUE" unless that exact line exists
	grep -qxF "$1 = $2" "$priv_conf" || printf '%s = %s\n' "$1" "$2" >> "$priv_conf"
}
if [ -n "${JAILOPS_HOST_MOUNTS:-}" ]; then
	for d in $(echo "$JAILOPS_HOST_MOUNTS" | tr ',' ' '); do add_priv admin-host-mount "$d"; done
fi

step "services"
sysrc jailops_priv_enable=YES jailopsd_enable=YES >/dev/null
service jailops_priv checkconfig
service jailops_priv start || service jailops_priv restart
service jailopsd start || service jailopsd restart
n=0
until [ -S /var/run/jailops/jailops.sock ]; do
	n=$((n + 1))
	[ "$n" -gt 60 ] && die "jailopsd did not create its socket; see /var/log/messages"
	sleep 1
done
sleep 2
"$jops" doctor || true
if "$jops" doctor 2>&1 | grep -E ' FAIL '; then die "doctor reports a failing check (run: jailops doctor)"; fi

if [ -n "${JAILOPS_ADMIN_USER:-}" ]; then
	step "administrator"
	# root reaches the socket as the host's recovery access; everyone else signs in with a JailOps identity.
	if "$jops" user show "$JAILOPS_ADMIN_USER" >/dev/null 2>&1; then
		echo "user $JAILOPS_ADMIN_USER exists"
	elif [ -n "${JAILOPS_ADMIN_PASSWORD_FILE:-}" ]; then
		"$jops" user create "$JAILOPS_ADMIN_USER" --admin --password-file - < "$JAILOPS_ADMIN_PASSWORD_FILE"
	else
		# the generated password goes to a root-only file, not to the (world-readable) bootstrap log
		(umask 077; "$jops" user create "$JAILOPS_ADMIN_USER" --admin 2>/dev/null > /root/jailops-admin-password)
		echo "generated password for $JAILOPS_ADMIN_USER: /root/jailops-admin-password (delete it after the first sign-in)"
	fi
fi

[ -n "$fleet_repo" ] || { echo; echo "JailOps is running. No fleet repository was given: nothing applied."; exit 0; }

step "fleet from git"
if [ -d "$fleet_path/.git" ]; then
	git -C "$fleet_path" pull --ff-only
else
	git clone ${JAILOPS_FLEET_BRANCH:+--branch "$JAILOPS_FLEET_BRANCH"} "$fleet_repo" "$fleet_path"
fi
if [ -n "${JAILOPS_AGE_KEY_FILE:-}" ]; then
	install -d -m 0700 /root/.config/jailops-sync
	install -m 0600 "$JAILOPS_AGE_KEY_FILE" /root/.config/jailops-sync/age.key
	SOPS_AGE_KEY_FILE=/root/.config/jailops-sync/age.key
	JAILOPS_SYNC_AGE_IDENTITY=/root/.config/jailops-sync/age.key
	export SOPS_AGE_KEY_FILE JAILOPS_SYNC_AGE_IDENTITY
fi
# root reaches the local socket as a global admin: the fleet's host.yaml says `socket: /var/run/jailops/jailops.sock`.
"$sync" -C "$fleet_path" validate
"$sync" -C "$fleet_path" plan
"$sync" -C "$fleet_path" sync --apply

step "keep it converged (optional)"
echo "Add to root's crontab to follow the repository every five minutes:"
echo "  */5 * * * * $sync -C $fleet_path watch --once --apply >>/var/log/jailops-sync.log 2>&1"
echo "or only report drift:  $sync -C $fleet_path drift"
