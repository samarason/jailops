#!/bin/sh
# The whole product on a clean FreeBSD machine, as a user would meet it: packages, setup, services, an image, a jail,
# and a backup that is restored as a new jail. Runs as root on a disposable machine (the CI VM); it creates and
# destroys its own scratch pool and changes /etc/pf.conf and /etc/rc.conf.
#
#   sh scripts/ci-freebsd-e2e.sh
#
# JAILOPS_BIN_DIR   use these binaries instead of building them (jailops, jailopsd, ... as `just build-freebsd` names
#                   them, with or without the -freebsd-<arch> suffix)
# JAILOPS_E2E_PART   all (default), e2e (everything but the packet filter test), pf (only the packet filter test),
#                    scale (50 jails started and stopped together), soak (jails churn while traffic flows) or prepare (the
#                    machine set up with an image, a network and a project, left running: scripts/scale-study.sh starts there)
# JAILOPS_E2E_POOL_SIZE  size of the file-backed scratch pool (default 8G)
# The test host needs kern.racct.enable=1 in /boot/loader.conf (a boot tunable: reboot after adding it): the block on resource
# limits checks the rctl rules, which the kernel accepts only with it.
# JAILOPS_E2E_APPS   more apps of the catalog to install after nginx, space separated: postgresql, valkey,
#                   prometheus, forgejo, nsd, mail, isms (default none; CI does not set it). Each one is installed,
#                   checked in its own way, its logs listed, and stopped. An installed app is closed, so the host is
#                   allowed in first (jailops app allow NAME --from host) for the checks that connect from the host.
#                   isms needs the jailops package repository in the host's pkg configuration (docs/install.md) and
#                   installs a postgresql jail of its own, isms-db, which it is allowed to reach with app allow.
#                   postgresql-access is not an app but a block: a postgresql jail (pgacc) and two client jails
#                   (pgc1, pgc2) with the PostgreSQL client; pgc1 is allowed and runs select 1 with the connection
#                   string allow printed, pgc2 is refused, and after the deny pgc1 is refused too.
# JAILOPS_E2E_CATALOG  the catalog directory to install from (default: the reference copy internal/apps/testdata/catalog;
#                   for a change of the catalog itself, main/jailops-apps/apps of a packages repository checkout)
# JAILOPS_E2E_HOST  1 runs the host identity block (docs/appliance.md): it enables the module, changes the host name,
#                   /etc/resolv.conf (to documentation addresses that resolve nothing), the NTP block of /etc/ntp.conf
#                   and ntpd_enable of THIS machine, then restores them through 'jailops host restore' and checks that
#                   the files are back byte for byte (and puts them back from its own copies if anything fails on the
#                   way). Off by default; CI does not set it. A wrapper enables it with: JAILOPS_E2E_HOST=1 sh scripts/ci-freebsd-e2e.sh
# JAILOPS_E2E_HOSTFW  1 runs the host firewall block (docs/appliance.md): it enables the module and rewrites
#                   /etc/pf.conf of THIS machine, always with --confirm-within 20 and always keeping the ssh port open
#                   (the port sshd listens on, from sockstat -4l, to the address in SSH_CLIENT; to anywhere when
#                   SSH_CLIENT is not set). It first applies and does NOT confirm, and waits for the helper to put the
#                   original back; then applies and confirms; then restores the original through the snapshot and
#                   checks it byte for byte and that pf runs the original rules. On any failure the EXIT trap puts
#                   the original pf.conf and rc.conf back, reloads pf and restores the configuration. Off by default;
#                   CI does not set it: JAILOPS_E2E_HOSTFW=1 sh scripts/ci-freebsd-e2e.sh
# JAILOPS_E2E_APPLIANCE  1 runs the appliance block (docs/appliance.md, docs/exposure.md) on the test configuration this
#                   script made: it sets jailops_appliance in /etc/rc.conf with sysrc, restarts both services, checks
#                   check-config and doctor appliance, runs the setup token flow with curl (a wrong token refused, the
#                   right one creating the administrator e2e-admin, a second attempt not found), uploads a certificate
#                   made with openssl and checks that the TLS listener serves it (openssl s_client), checks that wrong
#                   ACME settings are refused (no CA is contacted), and puts rc.conf, the certificate and the user back.
#                   It changes no pf.conf. Off by default; CI does not set it: JAILOPS_E2E_APPLIANCE=1 sh scripts/ci-freebsd-e2e.sh
#
# Rules of this script (scripts/lint-e2e.sh checks the first one, `just check` and CI run it):
#   - No bare `sleep N`: wait for the condition (waitfor, expect_retry, check_retry, wait_counts). A pause that has to be
#     there says why with `# sleep-ok: reason` (the poll of a loop, a deadline that has to pass).
#   - No assertion on how long something took, except a very loose bound (minutes) that only tells a hang from a slow machine.
#   - Wait for readiness (a file, a listener, a running jail) before signalling or connecting to what was just started.
#   - No step depends on an external mirror without a retry (check_net); stop a jail and wait until it is gone before it
#     is deleted; a step does not rely on what an earlier step left behind unless it created it.
set -eu

cd "$(dirname "$0")/.."
root=$(pwd)
pool=jopsci
part=${JAILOPS_E2E_PART:-all}
case $part in all | e2e | pf | scale | soak | prepare) ;; *) echo "JAILOPS_E2E_PART must be all, e2e, pf, scale, soak or prepare" >&2; exit 2 ;; esac
e2e_apps=${JAILOPS_E2E_APPS:-}
for a in $e2e_apps; do
	case $a in postgresql | valkey | prometheus | forgejo | nsd | mail | isms | postgresql-access) ;; *) echo "JAILOPS_E2E_APPS: no check for $a (postgresql, valkey, prometheus, forgejo, nsd, mail, isms, postgresql-access)" >&2; exit 2 ;; esac
	# isms is installed with pkg -r ROOT install -r jailops: say so now, not after the setup of the whole machine
	if [ "$a" = isms ] && ! pkg -vv | grep -Eq '^[[:space:]]+jailops:[[:space:]]*\{'; then
		echo "JAILOPS_E2E_APPS: isms comes from the jailops package repository, which the pkg configuration of this host does not have (docs/install.md)" >&2
		exit 2
	fi
done
poolfile=/tmp/$pool.img
work=/tmp/jailops-e2e
mount=/jopsci
version=$(tr -d '[:space:]' < version.txt)
major=$(freebsd-version -u | cut -d. -f1)
case $(uname -p) in
amd64) goarch=amd64 ;;
aarch64 | arm64) goarch=arm64 ;;
*) echo "unsupported architecture $(uname -p)" >&2; exit 2 ;;
esac
release=$(freebsd-version -u | sed 's/-p[0-9]*$//')
# the end-to-end flow can build its image from another release than the host's (an older userland on a newer kernel is
# supported): JAILOPS_E2E_IMAGE_RELEASE=15.1-RELEASE tests the packages of 15.1 on a 15.2 host
host_release=$release # the hints of the server name the host's release, whatever image the flow builds
host_img=freebsd-$(echo "$release" | sed -E 's/^([0-9]+)\.([0-9]+)-.*/\1-\2/')
release=${JAILOPS_E2E_IMAGE_RELEASE:-$release}
img=freebsd-$(echo "$release" | sed -E 's/^([0-9]+)\.([0-9]+)-.*/\1-\2/') # the image of the host's release
J=/usr/local/bin/jailops

# set -e ends the script without a word: say which step it was
current=start
host_cleanup() { :; } # the host identity block replaces it while the machine's identity is changed
trap 'rc=$?; host_cleanup; [ $rc -eq 0 ] || echo "FAILED (exit $rc) in step: $current" >&2' EXIT
step() { current=$*; printf '\n== %s\n' "$*"; }
fail() {
	echo "FAILED: $*" >&2
	echo "--- last messages" >&2
	tail -n 40 /var/log/messages >&2 || true
	exit 1
}
check() { # check DESCRIPTION COMMAND...: the command must succeed
	desc=$1; shift
	"$@" >"$work/check.out" 2>&1 || { cat "$work/check.out" >&2; fail "$desc"; }
}
check_retry() { # check_retry DESCRIPTION COMMAND...: like check, tried for up to 15 s (what the daemon writes after a start lands a moment later)
	desc=$1; shift; n=0
	until "$@" >"$work/check.out" 2>&1; do
		n=$((n + 1)); [ $n -ge 15 ] && { cat "$work/check.out" >&2; fail "$desc"; }
		sleep 1 # sleep-ok: poll of a condition
	done
}
expect() { # expect DESCRIPTION PATTERN COMMAND...: the output must match
	desc=$1; pat=$2; shift 2
	out=$("$@" 2>&1) || { echo "$out" >&2; fail "$desc"; }
	printf '%s\n' "$out" | grep -E -q "$pat" || { echo "$out" >&2; fail "$desc (no match for $pat)"; }
	printf '%s\n' "$out"
}

expect_retry() { # expect_retry DESCRIPTION PATTERN COMMAND...: like expect, tried for up to 30 s (the firewall of a new jail settles a few seconds after it starts)
	desc=$1; pat=$2; shift 2
	n=0
	until out=$("$@" 2>&1) && printf '%s\n' "$out" | grep -E -q "$pat"; do
		n=$((n + 1))
		[ $n -ge 15 ] && { echo "$out" >&2; fail "$desc (no match for $pat after 30 s)"; }
		sleep 2 # sleep-ok: poll of a condition
	done
	printf '%s\n' "$out"
}
expect_refused_retry() { # expect_refused_retry DESCRIPTION COMMAND...: the command must fail, tried for up to 30 s (a firewall change settles a few seconds after it is made)
	desc=$1; shift
	n=0
	while out=$("$@" 2>&1); do
		n=$((n + 1))
		[ $n -ge 15 ] && { echo "$out" >&2; fail "$desc (still answered after 30 s)"; }
		sleep 2 # sleep-ok: poll of a condition
	done
}
expect_refused() { # expect_refused DESCRIPTION COMMAND...: the command must fail, at once
	desc=$1; shift
	if out=$("$@" 2>&1); then echo "$out" >&2; fail "$desc (it answered)"; fi
}
waitfor() { # waitfor DESCRIPTION SECONDS COMMAND...: the command must succeed within SECONDS (polled twice a second); what it printed last is shown when it never does
	desc=$1; secs=$2; shift 2
	end=$(( $(date +%s) + secs ))
	until "$@" >"$work/waitfor.out" 2>&1; do
		[ "$(date +%s)" -ge "$end" ] && { cat "$work/waitfor.out" >&2; fail "$desc (not after $secs s)"; }
		sleep 0.5 # sleep-ok: the poll of waitfor
	done
}
check_net() { # check_net DESCRIPTION COMMAND...: like check, for a command that reaches a package mirror: tried four times with a pause (a mirror that answers slowly or not at all once is not a failure of the product)
	desc=$1; shift; n=0
	until "$@" >"$work/check.out" 2>&1; do
		n=$((n + 1)); [ $n -ge 4 ] && { cat "$work/check.out" >&2; fail "$desc"; }
		sleep 10 # sleep-ok: the pause between the tries at a mirror
	done
}
wait_counts() { # wait_counts PROJECT V4PREFIX V6PREFIX WANT: until net_counts says WANT, for up to 90 s (the caller then checks it and says what is wrong)
	end=$(( $(date +%s) + 90 ))
	until [ "$(net_counts "$1" "$2" "$3")" = "$4" ] || [ "$(date +%s)" -ge "$end" ]; do sleep 0.5; done # sleep-ok: the poll of wait_counts
}
json_field() { # json_field NAME: the string value of a top-level field of the indented JSON on standard input
	sed -n "s/^  \"$1\": \"\([^\"]*\)\",*\$/\1/p" | head -1
}

rm -rf "$work"; mkdir -p "$work"

# CI logs show how fast this machine is (a VM without KVM acceleration is several times slower)
echo "machine: $(sysctl -n kern.vm_guest hw.ncpu hw.model | tr '\n' ' ')"
step "binaries"
bin=${JAILOPS_BIN_DIR:-}
if [ -z "$bin" ]; then
	command -v go >/dev/null || fail "go is needed to build (or set JAILOPS_BIN_DIR)"
	[ -s internal/webui/dist/index.html ] && [ -s internal/backupui/dist/index.html ] || fail "the web consoles are not built (just web-all): the binaries would have none embedded"
	bin=$work/bin; mkdir -p "$bin"
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$version" -o "$bin/" ./cmd/jailops ./cmd/jailopsd ./cmd/jailops-priv ./cmd/jailops-sync ./cmd/jailops-backupd
fi

step "packages"
sh scripts/pkg-build.sh "$version" "$goarch" "$bin" "$work/pkgs" "$major" >/dev/null
abi=$(pkg config ABI)
pkgdir=$work/pkgs/$abi/latest/All
ls "$pkgdir"
pkg add "$pkgdir/jailops-client-$version.pkg" "$pkgdir/jailops-$version.pkg" "$pkgdir/jailops-backupd-$version.pkg" >/dev/null 2>&1 || \
	pkg add -f "$pkgdir/jailops-client-$version.pkg" "$pkgdir/jailops-$version.pkg" "$pkgdir/jailops-backupd-$version.pkg" || fail "pkg add"
check "users exist" id jailops
check "backup user exists" id jailops-backup

step "state of an earlier run: jails, rctl rules and devfs rulesets"
# a run that failed leaves its jails running, the rctl rules of their limits (the kernel keeps a rule by the jail's name,
# so it would apply to the jail of the same name in this run) and the devfs rulesets of their devices: remove them
for j in $(jls -h name 2>/dev/null | grep '^demo_'); do jail -r "$j" >/dev/null 2>&1 || true; done
for r in $(rctl 2>/dev/null | cut -d: -f1,2 | sort -u | grep '^jail:demo_'); do rctl -r "$r" >/dev/null 2>&1 || true; done
for s in $(devfs rule showsets 2>/dev/null); do [ "$s" -ge 5000 ] 2>/dev/null && devfs rule -s "$s" delset >/dev/null 2>&1; done
[ -z "$(jls -h name 2>/dev/null | grep '^demo_')" ] || fail "jails of an earlier run are still running: $(jls -h name | grep '^demo_')"

step "scratch pool and kernel modules"
zpool destroy -f "$pool" 2>/dev/null || true
rm -f "$poolfile"
truncate -s "${JAILOPS_E2E_POOL_SIZE:-8G}" "$poolfile"
check "zpool create" zpool create -m none "$pool" "$poolfile"
for m in if_epair nullfs pf; do kldload -n $m 2>/dev/null || true; done

step "PF anchors (the one line of PF setup JailOps asks for)"
touch /etc/pf.conf
grep -q 'anchor "jailops/\*"' /etc/pf.conf || cat >> /etc/pf.conf <<'PF'
anchor "jailops/*"
PF
if ! grep -q '^set state-policy if-bound' /etc/pf.conf; then { echo 'set state-policy if-bound'; cat /etc/pf.conf; } > /etc/pf.conf.new && mv /etc/pf.conf.new /etc/pf.conf; fi
sysrc pf_enable=YES >/dev/null
# enabling pf flushes its states on a machine where it is already running, which cuts the ssh session of whoever runs
# this: start it only when it is not running, and otherwise just reload the rules
pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' || service pf onestart >/dev/null 2>&1 || true
# a pf that was already running keeps the ruleset it had: load the file we just changed, and refuse to go on if it
# does not parse (a broken pf.conf on a machine with a real firewall must be noticed here, not later)
pfctl -nf /etc/pf.conf || fail "/etc/pf.conf does not parse"
pfctl -f /etc/pf.conf || fail "could not load /etc/pf.conf"
pfctl -s info >/dev/null 2>&1 || fail "pf is not running"

step "forwarding (JailOps asks the administrator for this, it never changes forwarding itself)"
sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null
sysrc gateway_enable=YES ipv6_gateway_enable=YES >/dev/null

step "jailops-priv init"
check "init" /usr/local/libexec/jailops-priv init -pool "$pool" -mount "$mount"
check "init is repeatable" /usr/local/libexec/jailops-priv init -pool "$pool" -mount "$mount"

step "services"
sysrc jailops_priv_enable=YES jailopsd_enable=YES jailopsd_web=YES >/dev/null
check "jailops_priv checkconfig" service jailops_priv checkconfig
check "jailops_priv start" service jailops_priv start
check "jailopsd start" service jailopsd start
n=0
until [ -S /var/run/jailops/jailops.sock ]; do
	n=$((n + 1)); [ $n -gt 30 ] && fail "jailopsd did not create its socket"
	sleep 1 # sleep-ok: poll of a condition
done
waitfor "the daemon answers" 60 $J host show
step "pid files: root writes them in /var/run, never in /var/run/jailops (the daemon may write there)"
for f in /var/run/jailops-priv.pid /var/run/jailops-priv-daemon.pid /var/run/jailopsd.pid /var/run/jailopsd-daemon.pid; do
	[ -s "$f" ] || fail "$f is missing"
done
[ -z "$(find /var/run/jailops -type f)" ] || fail "regular files in /var/run/jailops: $(find /var/run/jailops -type f)"
step "the helper's socket is in a directory only root writes; the daemon's user can put nothing there"
expect "the helper's socket directory" '^root:jailops 710$' stat -f '%Su:%Sg %Lp' /var/run/jailops-priv
[ -S /var/run/jailops-priv/priv.sock ] || fail "no socket at /var/run/jailops-priv/priv.sock"
[ ! -e /var/run/jailops/priv.sock ] || fail "a priv.sock is left in the daemon's directory"
expect_refused "the daemon's user cannot create a file there" su -m jailops -c 'touch /var/run/jailops-priv/x'
step "storage root: root's directory, mode 0700, devices off"
expect "the storage root's directory" '^root 700$' stat -f '%Su %Lp' "$mount"
expect "devices is off on the storage root" '^off	local$' zfs get -H -o value,source devices "$pool/jailops"
expect_refused "the daemon's user cannot enter the storage root" su -m jailops -c "ls $mount"
check "jailops_priv status" service jailops_priv status
check "jailopsd status" service jailopsd status
# -web: the quick start's console is on the TLS port, and the API is the same port (the certificate is self-signed)
step "web console and API on port 39110"
n=0; until curl -ks -o /dev/null https://127.0.0.1:39110/api/v1; do n=$((n + 1)); [ $n -gt 20 ] && fail "port 39110 does not answer"; sleep 1; done
curl -ks https://127.0.0.1:39110/ | grep -qi '<html' || fail "the web console is not served on port 39110"
curl -ks https://127.0.0.1:39110/api/v1 | grep -q '"untrusted"' || fail "the API is not served on port 39110"
$J doctor || true
if $J doctor 2>&1 | grep -E ' FAIL '; then fail "doctor reports a failing check"; fi
# GET /readyz (docs/operations.md): no credentials, a fixed answer, cached for 2 s; the helper stopped makes it 503
step "readiness: GET /readyz without credentials, and with the helper stopped"
readyz() { curl -ks -o "$work/readyz.out" -w '%{http_code} ' https://127.0.0.1:39110/readyz; cat "$work/readyz.out"; }
expect_retry "readyz answers 200 without credentials" '^200 ok$' readyz
expect "an ordinary local user gets the same over the socket" '^ok$' su -m nobody -c 'curl -s --unix-socket /var/run/jailops/jailops.sock http://jailops.local/readyz'
check "jailops_priv stop" service jailops_priv stop
expect_retry "readyz says the helper is down, and nothing more" '^503 not ready: helper$' readyz
expect "healthz is liveness and stays ok" '^ok$' curl -ks https://127.0.0.1:39110/healthz
check "jailops_priv start" service jailops_priv start
expect_retry "readyz is 200 again once the helper is back" '^200 ok$' readyz

# The host identity module changes this machine itself: only with JAILOPS_E2E_HOST=1, and always put back.
if [ "${JAILOPS_E2E_HOST:-}" = 1 ]; then
	step "host identity (JAILOPS_E2E_HOST=1: this machine's name, resolvers and NTP, then restored)"
	horig=$work/host-orig
	rm -rf "$horig"; mkdir -p "$horig"
	for f in resolv.conf ntp.conf rc.conf; do [ -f /etc/$f ] && cp -p /etc/$f "$horig/$f"; done
	cp -p /usr/local/etc/jailops/priv.conf /usr/local/etc/jailops/jailopsd.yaml "$horig/"
	orig_hostname=$(hostname)
	host_cleanup() { # what a failure in this block leaves behind: the originals go back from the copies above
		[ -n "${host_dirty:-}" ] || return 0
		echo "putting the host identity back from $horig" >&2
		for f in resolv.conf ntp.conf rc.conf; do
			if [ -f "$horig/$f" ]; then cp -p "$horig/$f" /etc/$f; else rm -f /etc/$f; fi
		done
		hostname "$orig_hostname"
		cp -p "$horig/priv.conf" /usr/local/etc/jailops/priv.conf; cp -p "$horig/jailopsd.yaml" /usr/local/etc/jailops/jailopsd.yaml
		service ntpd onestatus >/dev/null 2>&1 && service ntpd onerestart >/dev/null 2>&1
		service jailops_priv restart >/dev/null 2>&1; service jailopsd restart >/dev/null 2>&1
		host_dirty=
	}
	host_same() { # host_same: resolv.conf and ntp.conf are the originals byte for byte, rc.conf has the original
		# lines besides the module's three variables and their original values (sysrc may quote a value it puts back
		# its own way), and the host name is the original
		for f in resolv.conf ntp.conf; do
			if [ -f "$horig/$f" ]; then cmp -s "$horig/$f" /etc/$f || fail "/etc/$f is not the original"
			else [ ! -e /etc/$f ] || fail "/etc/$f exists and did not before"; fi
		done
		rcvars='^(hostname|ntpd_enable|ntpd_sync_on_start)='
		grep -Ev "$rcvars" "$horig/rc.conf" > "$work/rc.orig.rest"; grep -Ev "$rcvars" /etc/rc.conf > "$work/rc.now.rest"
		cmp -s "$work/rc.orig.rest" "$work/rc.now.rest" || { diff "$work/rc.orig.rest" "$work/rc.now.rest" >&2; fail "rc.conf changed outside the module's variables"; }
		for v in hostname ntpd_enable ntpd_sync_on_start; do
			[ "$(sysrc -f "$horig/rc.conf" -qn $v 2>/dev/null)" = "$(sysrc -qn $v 2>/dev/null)" ] || fail "rc.conf $v is not the original"
		done
		[ "$(hostname)" = "$orig_hostname" ] || fail "the host name is $(hostname), not $orig_hostname"
	}
	host_dirty=1
	expect "not managed by default" 'Managed: +no' $J host show
	expect "changing is refused while the module is off" 'not_managed' sh -c "$J host identity set --hostname e2e.example.org 2>&1; true"
	host_same
	echo 'host-manage = identity' >> /usr/local/etc/jailops/priv.conf
	printf 'host:\n  manage:\n    modules: [identity]\n' >> /usr/local/etc/jailops/jailopsd.yaml
	check "jailops_priv checkconfig with host-manage" service jailops_priv checkconfig
	check "restart jailops_priv" service jailops_priv restart
	check "restart jailopsd" service jailopsd restart
	n=0; until $J host show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
	expect "managed now" 'Managed: +yes' $J host show
	set -- --hostname jailops-e2e.example.org --nameserver 192.0.2.53 --nameserver 2001:db8::53 --search example.org --ntp-server 192.0.2.123 --ntp enable
	expect "the dry run shows the diff" '^\+nameserver 2001:db8::53$' $J --dry-run host identity set "$@"
	host_same
	out=$(expect "apply" 'undo with: jailops host restore ' $J host identity set "$@")
	snap=$(printf '%s\n' "$out" | sed -n 's/.*undo with: jailops host restore //p')
	[ -n "$snap" ] || fail "no snapshot name in the output"
	expect "hostname(1)" '^jailops-e2e\.example\.org$' hostname
	expect "resolv.conf carries the header" '^# managed by jailops$' head -1 /etc/resolv.conf
	expect "resolv.conf has the nameservers" '^nameserver 2001:db8::53$' cat /etc/resolv.conf
	expect "resolv.conf has the search list" '^search example\.org$' cat /etc/resolv.conf
	expect "ntp.conf has the block" '^server 192\.0\.2\.123 iburst$' sed -n '/^# jailops begin$/,/^# jailops end$/p' /etc/ntp.conf
	sed '/^# jailops begin$/,/^# jailops end$/d' /etc/ntp.conf > "$work/ntp.rest"
	if [ -f "$horig/ntp.conf" ]; then cmp -s "$work/ntp.rest" "$horig/ntp.conf" || { diff "$horig/ntp.conf" "$work/ntp.rest" >&2; fail "ntp.conf changed outside the jailops block"; }; fi
	expect "rc.conf hostname" '^jailops-e2e\.example\.org$' sysrc -n hostname
	expect "rc.conf ntpd_enable" '^YES$' sysrc -n ntpd_enable
	expect "rc.conf ntpd_sync_on_start" '^YES$' sysrc -n ntpd_sync_on_start
	expect "the snapshot is listed" "^$snap +identity +apply" $J host snapshots
	expect "doctor: managed, no drift" 'host\.identity +PASS' sh -c "$J doctor 2>&1; true"
	echo 'nameserver 192.0.2.54' >> /etc/resolv.conf
	expect "a hand edit is drift" 'Drift: +resolvers' $J host show
	expect "and doctor says so" 'host\.identity +WARN' sh -c "$J doctor 2>&1; true"
	expect "the hand edit is not overwritten" '^nameserver 192\.0\.2\.54$' cat /etc/resolv.conf
	expect "the restore dry run" '^-nameserver 192\.0\.2\.54$' $J --dry-run host restore "$snap"
	# a line root adds to rc.conf after the snapshot is not the module's: the restore leaves it, and does not show it
	echo 'jailops_e2e_marker="kept"' >> /etc/rc.conf
	if $J --dry-run host restore "$snap" 2>&1 | grep -q jailops_e2e_marker; then fail "the restore diff shows a line of rc.conf the module does not own"; fi
	check "restore" $J -y host restore "$snap"
	expect "the restore kept root's own rc.conf line" '^kept$' sysrc -n jailops_e2e_marker
	sysrc -x jailops_e2e_marker >/dev/null
	host_same
	expect "the restore kept a snapshot of its own" ' +identity +restore ' $J host snapshots
	cp -p "$horig/priv.conf" /usr/local/etc/jailops/priv.conf; cp -p "$horig/jailopsd.yaml" /usr/local/etc/jailops/jailopsd.yaml
	check "restart jailops_priv" service jailops_priv restart
	check "restart jailopsd" service jailopsd restart
	n=0; until $J host show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
	host_dirty=
	host_same
fi

# The host firewall module rewrites this machine's /etc/pf.conf: only with JAILOPS_E2E_HOSTFW=1, always with a
# confirmation window, never closing the ssh port this script is reached through, and always put back.
if [ "${JAILOPS_E2E_HOSTFW:-}" = 1 ]; then
	step "host firewall (JAILOPS_E2E_HOSTFW=1: this machine's /etc/pf.conf, with commit confirmed, then restored)"
	forig=$work/hostfw-orig
	rm -rf "$forig"; mkdir -p "$forig"
	cp -p /etc/pf.conf "$forig/pf.conf"
	cp -p /etc/rc.conf "$forig/rc.conf"
	cp -p /usr/local/etc/jailops/priv.conf /usr/local/etc/jailops/jailopsd.yaml "$forig/"
	pfctl -s rules > "$forig/rules" 2>/dev/null || true
	# the ssh port sshd listens on, and the address this session comes from: exactly these stay open
	sshport=$(sockstat -4l | awk '$2 == "sshd" { n = split($6, a, ":"); print a[n]; exit }')
	[ -n "$sshport" ] || sshport=22
	src=${SSH_CLIENT:-}; src=${src%% *}
	if [ -n "$src" ]; then
		set -- --ssh-port "$sshport" --ssh-from "$src" --console-from "$src"
		echo "keeping ssh port $sshport open to $src (from SSH_CLIENT)"
	else
		set -- --ssh-port "$sshport"
		echo "SSH_CLIENT is not set (not over ssh, or sudo dropped it): ssh port $sshport stays open to anywhere"
	fi
	set -- "$@" --template custom-rules --confirm-within 20 --confirm-lockout
	hostfw_cleanup() { # what a failure in this block leaves behind: the original pf.conf, loaded, and the configuration
		[ -n "${hostfw_dirty:-}" ] || return 0
		echo "putting /etc/pf.conf back from $forig" >&2
		$J -y host revert >/dev/null 2>&1 || true
		cp -p "$forig/pf.conf" /etc/pf.conf; cp -p "$forig/rc.conf" /etc/rc.conf
		pfctl -f /etc/pf.conf || echo "WARNING: pfctl -f /etc/pf.conf failed; load it by hand" >&2
		cp -p "$forig/priv.conf" /usr/local/etc/jailops/priv.conf; cp -p "$forig/jailopsd.yaml" /usr/local/etc/jailops/jailopsd.yaml
		service jailops_priv restart >/dev/null 2>&1; service jailopsd restart >/dev/null 2>&1
		hostfw_dirty=
	}
	host_cleanup() { hostfw_cleanup; }
	pf_same() { # pf_same: /etc/pf.conf is the original, byte for byte, and pf runs its rules
		cmp -s "$forig/pf.conf" /etc/pf.conf || { diff "$forig/pf.conf" /etc/pf.conf >&2; fail "/etc/pf.conf is not the original"; }
		pfctl -s rules > "$work/rules.now" 2>/dev/null
		cmp -s "$forig/rules" "$work/rules.now" || { diff "$forig/rules" "$work/rules.now" >&2; fail "pf does not run the original rules"; }
	}
	hostfw_dirty=1
	expect "not managed by default" 'Managed: +no' $J host firewall show
	expect "changing is refused while the module is off" 'not_managed' sh -c "$J host firewall set --confirm-lockout 2>&1; true"
	pf_same
	echo 'host-manage = firewall' >> /usr/local/etc/jailops/priv.conf
	printf 'host:\n  manage:\n    modules: [firewall]\n' >> /usr/local/etc/jailops/jailopsd.yaml
	check "jailops_priv checkconfig with host-manage" service jailops_priv checkconfig
	check "restart jailops_priv" service jailops_priv restart
	check "restart jailopsd" service jailopsd restart
	n=0; until $J host firewall show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
	expect "managed now" 'Managed: +yes' $J host firewall show
	expect "the unix socket has no address: the lock-out check needs --confirm-lockout" 'confirm-lockout' sh -c "$J host firewall set --ssh-port $sshport --confirm-within 20 2>&1; true"
	expect "the dry run shows the diff" '^\+block in all$' $J --dry-run host firewall set "$@"
	pf_same

	# 1. the revert path: apply, do NOT confirm, and the helper's timer puts the original back
	expect "apply" 'REVERTS at' $J host firewall set "$@"
	expect "pf.conf is the managed file" '^# managed by jailops$' head -1 /etc/pf.conf
	expect "pf runs it, with the jails' anchor" 'anchor "jailops/\*"' pfctl -s rules
	# pfctl prints a port by its name in /etc/services when it has one
	sshsvc=$(awk -v p="$sshport/tcp" '$2 == p { print $1; exit }' /etc/services)
	expect "pf passes ssh on port $sshport" "port = ($sshport|${sshsvc:-$sshport})( |$)" pfctl -s rules
	expect "it waits for its confirmation" 'Reverts at:' $J host pending
	expect "doctor says so" 'host\.firewall +WARN' sh -c "$J doctor 2>&1; true"
	expect_retry "the change reverts by itself after 20 s" 'was timed out' $J host pending
	pf_same
	expect "nothing waits any more" 'nothing waits' $J host pending

	# 2. apply and confirm: the change stays past its deadline
	expect "apply again" 'REVERTS at' $J host firewall set "$@"
	expect "confirm" 'was confirmed' $J host confirm
	sleep 22 # sleep-ok: the deadline of the confirmed change has to pass, nothing may revert it
	expect "still the managed file" '^# managed by jailops$' head -1 /etc/pf.conf
	# the rows of custom-rules and the address sets: one command each, every change waits for its confirmation
	expect "an allow row" 'REVERTS at' $J host firewall allow add --proto tcp --port 9 --from 192.0.2.1 --comment e2e --confirm-within 20 --confirm-lockout
	expect "confirm the row" 'was confirmed' $J host confirm
	expect "the row is listed" '1 +tcp +9 +192\.0\.2\.1 +e2e' $J host firewall allow list
	expect "an address set" 'REVERTS at' $J host firewall address-set create e2e --member 192.0.2.7 --confirm-within 20 --confirm-lockout
	expect "confirm the set" 'was confirmed' $J host confirm
	expect "the set is listed" 'e2e +192\.0\.2\.7' $J host firewall address-set list
	expect "remove the set" 'REVERTS at' $J host firewall address-set delete e2e --confirm-within 20 --confirm-lockout
	expect "confirm that" 'was confirmed' $J host confirm
	expect "remove the row" 'REVERTS at' $J host firewall allow remove 1 --confirm-within 20 --confirm-lockout
	expect "confirm that too" 'was confirmed' $J host confirm
	expect "doctor: managed, no drift" 'host\.firewall +PASS' sh -c "$J doctor 2>&1; true"
	cp -p /etc/pf.conf "$work/pf.managed"
	echo '# a hand edit' >> /etc/pf.conf
	expect "a hand edit is drift" 'Drift: +pf\.conf' $J host firewall show
	expect "and doctor says so" 'host\.firewall +WARN' sh -c "$J doctor 2>&1; true"
	expect "the diff shows it" '^-# a hand edit$' $J host firewall diff
	cp -p "$work/pf.managed" /etc/pf.conf

	# 3. the snapshot taken before the first apply puts the original back, byte for byte, and loads it
	snap=$($J host snapshots | awk '$2 == "firewall" && $3 == "adopt" { print $1; exit }')
	[ -n "$snap" ] || fail "no snapshot of the original pf.conf"
	expect "the restore dry run" '^\+# managed by jailops$|^-# managed by jailops$' $J --dry-run host restore "$snap"
	echo 'jailops_e2e_marker="kept"' >> /etc/rc.conf
	check "restore" $J -y host restore "$snap"
	pf_same
	expect "the restore kept root's own rc.conf line" '^kept$' sysrc -n jailops_e2e_marker
	sysrc -x jailops_e2e_marker >/dev/null
	# rc.conf: the original lines, and pf_enable and pf_rules as they were (sysrc may quote a value it puts back)
	grep -Ev '^(pf_enable|pf_rules)=' "$forig/rc.conf" > "$work/rc.orig.rest"; grep -Ev '^(pf_enable|pf_rules)=' /etc/rc.conf > "$work/rc.now.rest"
	cmp -s "$work/rc.orig.rest" "$work/rc.now.rest" || fail "/etc/rc.conf changed outside pf_enable and pf_rules"
	for v in pf_enable pf_rules; do
		[ "$(sysrc -f "$forig/rc.conf" -qn $v 2>/dev/null)" = "$(sysrc -qn $v 2>/dev/null)" ] || fail "rc.conf $v is not the original"
	done
	cp -p "$forig/priv.conf" /usr/local/etc/jailops/priv.conf; cp -p "$forig/jailopsd.yaml" /usr/local/etc/jailops/jailopsd.yaml
	check "restart jailops_priv" service jailops_priv restart
	check "restart jailopsd" service jailopsd restart
	n=0; until $J host firewall show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
	hostfw_dirty=
	pf_same
fi

# Appliance mode from rc.conf, the setup token and the console's certificate: only with JAILOPS_E2E_APPLIANCE=1, on the
# test configuration above, and always put back.
if [ "${JAILOPS_E2E_APPLIANCE:-}" = 1 ]; then
	step "appliance mode (JAILOPS_E2E_APPLIANCE=1: the rc.conf switch, the setup token, a certificate upload, ACME refusals)"
	aorig=$work/appliance-orig
	rm -rf "$aorig"; mkdir -p "$aorig"
	cp -p /etc/rc.conf "$aorig/rc.conf"
	tlsdir=/var/db/jailops/tls
	api() { # api METHOD PATH [BODY]: a request as root on the daemon's socket; prints the status, a space and the body
		curl -s --unix-socket /var/run/jailops/jailops.sock -o "$work/api.out" -w '%{http_code}' -X "$1" -H 'Content-Type: application/json' \
			${3:+-d "$3"} "http://jailops.local$2"
		printf ' '; cat "$work/api.out"
	}
	anon() { # anon METHOD PATH [BODY]: the same, anonymous, on the TLS listener
		curl -ks -o "$work/anon.out" -w '%{http_code}' -X "$1" -H 'Content-Type: application/json' ${3:+-d "$3"} "https://127.0.0.1:39110$2"
		printf ' '; cat "$work/anon.out"
	}
	appliance_cleanup() { # rc.conf, the certificate and the user as they were
		[ -n "${appliance_dirty:-}" ] || return 0
		echo "putting rc.conf, the certificate and the users back" >&2
		cp -p "$aorig/rc.conf" /etc/rc.conf
		$J -y user delete e2e-admin >/dev/null 2>&1 || true
		rm -f "$tlsdir/choice.json" "$tlsdir/uploaded.crt" "$tlsdir/uploaded.key"
		service jailops_priv restart >/dev/null 2>&1; service jailopsd restart >/dev/null 2>&1
		appliance_dirty=
	}
	host_cleanup() { appliance_cleanup; }
	appliance_dirty=1
	expect "doctor: appliance off" 'appliance +PASS' sh -c "$J doctor 2>&1; true"
	sysrc jailops_appliance=YES jailops_appliance_modules="identity firewall" >/dev/null
	expect "check-config lists the modules" '^host manage: +identity, firewall' service jailops_priv checkconfig
	expect "check-config says they come from rc.conf" '^appliance: +on: rc.conf' service jailops_priv checkconfig
	check "restart jailops_priv" service jailops_priv restart
	started=$(service jailopsd restart 2>&1) || { echo "$started" >&2; fail "restart jailopsd"; }
	n=0; until $J host show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
	expect "doctor: the daemon and the helper agree" 'appliance +PASS +.*identity, firewall' sh -c "$J doctor 2>&1; true"
	expect "the identity module is managed" 'Managed: +yes' $J host show
	# the setup token: on the console and in auth.log at the start, and again from jailops-priv setup-token
	printf '%s\n' "$started" | grep -q 'Setup token:' || { echo "$started" >&2; fail "the start of jailopsd printed no setup token"; }
	expect_retry "auth.log has the token" 'Setup token:' tail -n 300 /var/log/auth.log
	if grep -q 'Setup token:' /var/log/messages; then fail "the setup token is in /var/log/messages"; fi
	tok=$(/usr/local/libexec/jailops-priv setup-token | awk '/Setup token:/ { print $3 }')
	[ -n "$tok" ] || fail "jailops-priv setup-token printed no token"
	pw='e2e passphrase for the appliance'
	expect "setup is required" '^200 .*"required":true' anon GET /api/v1/setup
	expect "a wrong token is refused" '^401 ' anon POST /api/v1/setup "{\"token\":\"AAAA$tok\",\"name\":\"e2e-admin\",\"password\":\"$pw\"}"
	expect "the right token creates the administrator" '^201 .*"name":"e2e-admin"' anon POST /api/v1/setup "{\"token\":\"$tok\",\"name\":\"e2e-admin\",\"password\":\"$pw\"}"
	expect "a second attempt is not found" '^404 ' anon POST /api/v1/setup "{\"token\":\"$tok\",\"name\":\"e2e-two\",\"password\":\"$pw\"}"
	expect "the setup status is not found" '^404 ' anon GET /api/v1/setup
	expect "setup-token says the setup is complete" 'setup is complete' sh -c '/usr/local/libexec/jailops-priv setup-token 2>&1; true'
	expect "the administrator signs in" '^200 ' anon POST /api/v1/auth/login "{\"username\":\"e2e-admin\",\"password\":\"$pw\"}"
	# a certificate of a test CA, uploaded through the API and served by the TLS listener
	cd "$work"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 120 -subj /CN=e2e-ca -keyout ca.key -out ca.crt \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 || fail "openssl: the test CA"
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=e2e.example.com -keyout srv.key -out srv.csr >/dev/null 2>&1 || fail "openssl: the request"
	printf 'subjectAltName=DNS:e2e.example.com\nextendedKeyUsage=serverAuth\n' > srv.ext
	openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 90 -extfile srv.ext -out srv.crt >/dev/null 2>&1 || fail "openssl: the certificate"
	cd "$root"
	jpem() { awk 'BEGIN { ORS = "" } { print $0 "\\n" }' "$1"; } # a PEM file as one JSON string
	upload() { printf '{"certificate":"%s%s","key":"%s","hostname":"%s"}' "$(jpem "$work/srv.crt")" "$(jpem "$work/ca.crt")" "$(jpem "$work/srv.key")" "$1"; }
	expect "a certificate for another name is refused" '^400 .*not valid for www\.example\.com' api PUT /api/v1/host/certificate "$(upload www.example.com)"
	cat "$work/srv.crt" "$work/ca.crt" > "$work/chain.pem"
	expect "the CLI refuses it too" 'not valid for www\.example\.com' sh -c "$J host certificate upload --cert $work/chain.pem --key $work/srv.key --hostname www.example.com 2>&1; true"
	expect "the upload (jailops host certificate upload)" '^host-certificate/uploaded for e2e\.example\.com' $J host certificate upload --cert "$work/chain.pem" --key "$work/srv.key"
	expect "show says where it comes from" 'Certificate of this host: uploaded' $J host certificate show
	expect "show names the remote add command" 'jailops remote add [^ ]+ https://[^ ]+:39110 ' $J host certificate show
	expect "the files are 0600" '^-rw------- ' ls -l "$tlsdir/uploaded.key"
	expect "the TLS listener serves it" 'CN *= *e2e\.example\.com' sh -c "openssl s_client -connect 127.0.0.1:39110 -servername e2e.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject"
	expect "it verifies against the test CA" 'Verify return code: 0' sh -c "openssl s_client -connect 127.0.0.1:39110 -servername e2e.example.com -CAfile $work/ca.crt -verify_hostname e2e.example.com </dev/null 2>&1"
	expect "doctor: tls.certificate" 'tls\.certificate +PASS +uploaded' sh -c "$J doctor 2>&1; true"
	# ACME settings that cannot work are refused before a CA is asked
	expect "ACME without the terms" '^400 .*accept_tos' api POST /api/v1/host/certificate/acme '{"domains":["e2e.example.com"]}'
	expect "ACME with a wildcard" '^501 .*dns-01' api POST /api/v1/host/certificate/acme '{"domains":["*.example.com"],"accept_tos":true}'
	expect "ACME with an address" '^400 .*is an address' api POST /api/v1/host/certificate/acme '{"domains":["192.0.2.10"],"accept_tos":true}'
	expect "ACME with a bad email" '^400 .*not an email' api POST /api/v1/host/certificate/acme '{"domains":["e2e.example.com"],"email":"root","accept_tos":true}'
	expect "ACME over plain http" '^400 .*https' api POST /api/v1/host/certificate/acme '{"domains":["e2e.example.com"],"directory_url":"http://ca.example.com/dir","accept_tos":true}'
	expect "still the uploaded certificate" '"source":"uploaded"' api GET /api/v1/host/certificate
	expect "replacing the uploaded certificate needs its name typed" 'confirmation required' sh -c "$J host certificate self-signed -y </dev/null 2>&1; true"
	expect "the self-signed certificate again" 'self-signed served' $J host certificate self-signed --confirm-replace
	expect "the API agrees" '"source":"self-signed"' api GET /api/v1/host/certificate
	expect "the TLS listener serves it" 'CN *= *' sh -c "openssl s_client -connect 127.0.0.1:39110 </dev/null 2>/dev/null | openssl x509 -noout -subject"
	appliance_cleanup
	n=0; until $J host show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
	expect "doctor: appliance off again" 'appliance +PASS +off' sh -c "$J doctor 2>&1; true"
	cmp -s "$aorig/rc.conf" /etc/rc.conf || fail "/etc/rc.conf is not the original"
fi

# net_counts PROJECT V4PREFIX V6PREFIX: running jails, host ends, and host routes through jail links
net_counts() {
	_jails=$(jls -N name 2>/dev/null | grep -c "^$1_" || true)
	_links=$(ifconfig -a | grep -c "description: jailops jail=$1/" || true)
	_r4=$(netstat -rn -f inet | awk -v p="^$2" '$1 ~ p && $NF ~ /^jo/ {n++} END {print n+0}')
	_r6=$(netstat -rn -f inet6 | awk -v p="^$3" '$1 ~ p && $NF ~ /^jo/ {n++} END {print n+0}')
	echo "jails=$_jails links=$_links routes4=$_r4 routes6=$_r6"
}
no_fail_in_doctor() {
	out=$($J doctor 2>&1) || true
	if printf '%s\n' "$out" | grep -E -q ' FAIL '; then printf '%s\n' "$out" | grep ' FAIL ' >&2; fail "$1: the doctor fails"; fi
}

run_scale() {
	step "scale: 50 jails on one routed network, started and stopped together, again and again"
	count=50
	check "network" $J network create scale --ipv4 10.88.0.1/24 --ipv6 fd50:88::/64 --uplink "$uplink" --nat
	check "project" $J project create scale
	check "grant" sh -c "$J network grant scale --project scale && $J storage grant default --project scale"
	names=""; i=0
	while [ $i -lt $count ]; do
		i=$((i + 1)); n=$(printf 's%02d' $i); names="$names $n"
		check "create $n" $J create "$n" --project scale --image "$img" --network scale --storage default
	done
	cycle=0
	while [ $cycle -lt 3 ]; do
		cycle=$((cycle + 1))
		echo "-- cycle $cycle: start all"
		t0=$(date +%s)
		case $cycle in
		2) # five starts at once, as five operators would
			set -- $names; k=0; pids=""
			while [ $# -gt 0 ]; do
				batch=""; j=0
				while [ $j -lt 10 ] && [ $# -gt 0 ]; do batch="$batch $1"; shift; j=$((j + 1)); done
				$J start $batch --project scale > "$work/scale.start.$k" 2>&1 & pids="$pids $!"; k=$((k + 1))
			done
			for p in $pids; do wait $p || fail "a parallel start failed"; done ;;
		*) check "start all" $J start --all --project scale ;;
		esac
		echo "OK: $count jails started in $(( $(date +%s) - t0 )) s"

		want="jails=$count links=$count routes4=$count routes6=$count"
		wait_counts scale '10\.88\.0\.' 'fd50:88:' "$want"
		got=$(net_counts scale '10\.88\.0\.' 'fd50:88:')
		[ "$got" = "$want" ] || fail "after the start of cycle $cycle: $got (want $want)"
		expect "the reject route of the subnet stays" '^10\.88\.0\.0/24 +[^ ]+ +URS +lo0' sh -c "netstat -rn -f inet | grep '^10.88.0.0/24'"
		gws=$(ifconfig -a | grep -c 'inet6 fe80::1%jo' || true)
		[ "$gws" = "$count" ] || fail "cycle $cycle: $gws host ends carry the link-local gateway (want $count)"
		bad=0; prev=""
		for n in $names; do
			a4=$($J config get "$n" nic.eth0.ipv4 --project scale | tail -1)
			a6=$($J config get "$n" nic.eth0.ipv6 --project scale | tail -1 | sed 's#/.*##')
			echo "$a4" | grep -q '^10\.88\.0\.' || fail "$n has no address on the network ($a4)"
			if [ -n "$prev" ]; then
				$J exec --project scale "$n" -- ping -c1 -t5 "$prev4" >/dev/null 2>&1 || { bad=$((bad + 1)); echo "$n cannot reach $prev ($prev4)" >&2; }
				$J exec --project scale "$n" -- ping -6 -c1 -t5 "$prev6" >/dev/null 2>&1 || { bad=$((bad + 1)); echo "$n cannot reach $prev over IPv6 ($prev6)" >&2; }
			fi
			$J exec --project scale "$n" -- ping -c1 -t5 10.88.0.1 >/dev/null 2>&1 || { bad=$((bad + 1)); echo "$n cannot reach its gateway" >&2; }
			prev=$n; prev4=$a4; prev6=$a6
		done
		[ $bad -eq 0 ] || fail "cycle $cycle: $bad failed pings between the running jails"
		echo "OK: every jail reaches its gateway and the jail before it, over IPv4 and IPv6"
		no_fail_in_doctor "cycle $cycle, running"
		echo "-- cycle $cycle: stop all"
		check "stop all" $J stop --all --project scale

		want="jails=0 links=0 routes4=0 routes6=0"
		wait_counts scale '10\.88\.0\.' 'fd50:88:' "$want"
		got=$(net_counts scale '10\.88\.0\.' 'fd50:88:')
		[ "$got" = "$want" ] || fail "after the stop of cycle $cycle: $got (want $want)"
		leftover=$(ifconfig -l | tr ' ' '\n' | grep -c '^jo' || true)
		[ "$leftover" = 0 ] || { ifconfig -l >&2; fail "cycle $cycle: $leftover interfaces of JailOps are left after every jail stopped"; }
		states=$(pfctl -ss 2>/dev/null | grep -c '10\.88\.0\.' || true)
		[ "$states" = 0 ] || { pfctl -ss | grep '10\.88\.0\.' >&2; fail "cycle $cycle: $states pf states of the stopped jails are left"; }
		expect "the reject route of the subnet stays" '^10\.88\.0\.0/24 +[^ ]+ +URS +lo0' sh -c "netstat -rn -f inet | grep '^10.88.0.0/24'"
		no_fail_in_doctor "cycle $cycle, stopped"
	done
	check "delete the jails" $J delete $names --project scale --confirm-data-loss
	expect "no anchor of the project is left" '^0$' sh -c "pfctl -sA 2>/dev/null | grep -c 'jailops/scale/' || true"
	check "delete the project" $J project delete scale -y
	check "delete the network" $J network delete scale -y
	expect_refused "the reject route of the deleted network is gone" sh -c "netstat -rn -f inet | grep -q '^10.88.0.0/24'"
	echo "OK: scale"
}

run_soak() {
	step "soak: jails start and stop while TCP streams and pings run between the others"
	secs=${JAILOPS_SOAK_SECONDS:-300}
	check "network" $J network create soak --ipv4 10.89.0.1/24 --ipv6 fd50:89::/64 --uplink "$uplink" --nat
	check "project" $J project create soak
	check "grant" sh -c "$J network grant soak --project soak && $J storage grant default --project soak"
	churn=""; i=0
	while [ $i -lt 20 ]; do i=$((i + 1)); churn="$churn $(printf 'c%02d' $i)"; done
	for n in st1 st2 $churn; do check "create $n" $J create "$n" --project soak --image "$img" --network soak --storage default; done
	# the host answers a jail with ping and DNS only; the stream to the host is a rule of its own
	check "a policy that lets the jail send to a port of the host" $J firewall policy create tohost --project soak --default-in allow --default-out allow
	check "its rule" $J firewall rule add tohost out --project soak --action allow --proto tcp --to host --port 9100 --comment "the metrics port of the host"
	check "st2 uses it" $J config set st2 firewall.policies tohost --project soak
	check "start the steady jails" $J start st1 st2 --project soak
	waitfor "st1 runs" 60 jexec soak_st1 true
	waitfor "st2 runs" 60 jexec soak_st2 true
	a1=$($J config get st1 nic.eth0.ipv4 --project soak | tail -1)
	a1v6=$($J config get st1 nic.eth0.ipv6 --project soak | tail -1 | sed 's#/.*##')
	bytes=$((secs * 4 * 100000)) # four chunks of 100000 bytes a second, one TCP connection each
	rm -f "$work"/soak.*
	$J exec --project soak st1 -- sh -c 'nc -l 9101 | wc -c > /tmp/rx4 & nc -6 -l 9102 | wc -c > /tmp/rx6 & wait' > "$work/soak.srv1" 2>&1 &
	srv1=$!
	nc -l 9100 | wc -c > "$work/soak.rxh" &
	srvh=$!
	# the clients start when the three listeners are there (a fixed pause is not enough on a slow machine)
	waitlisten() { # waitlisten WHAT 'COMMAND listing the sockets' PORT
		n=0
		while [ $n -lt 30 ]; do
			sh -c "$2" 2>/dev/null | grep -q ":$3 " && return 0
			sleep 1 # sleep-ok: poll of a condition
			n=$((n + 1))
		done
		fail "the listener $1 is not up after thirty seconds"
	}
	waitlisten "of st1 on 9101" "$J exec --project soak st1 -- sockstat -4l" 9101
	waitlisten "of st1 on 9102" "$J exec --project soak st1 -- sockstat -6l" 9102
	waitlisten "of the host on 9100" "sockstat -4l" 9100
	t0=$(date +%s)
	loop="i=0; while [ \$i -lt $((secs * 4)) ]; do dd if=/dev/zero bs=100000 count=1 2>/dev/null; sleep 0.25; i=\$((i + 1)); done"
	# each client leaves a file with what it did: the command in the jail says its own exit status and the clock, and so does
	# the exec that carries it (a stream that ends early is told apart from one that was cut off)
	client() { # client NAME COMMAND...: run COMMAND in st2, in the background
		cn=$1; shift
		( s0=$(date +%s); $J exec --project soak st2 -- sh -c "$*; echo \"command rc=\$? at \$(date +%s)\""; echo "exec rc=$? after $(( $(date +%s) - s0 )) s" ) > "$work/soak.$cn" 2>&1 &
	}
	client c4 "$loop | nc $a1 9101"
	c4=$!
	client c6 "$loop | nc -6 $a1v6 9102"
	c6=$!
	client ch "$loop | nc 10.89.0.1 9100"
	ch=$!
	client cp "ping -c $((secs * 4)) -i 0.25 -q 10.89.0.1 > /tmp/ping.out 2>&1; cat /tmp/ping.out"
	cp=$!
	# the churn: while the streams run, the other jails start, stop and restart, in batches and one by one
	rounds=0
	end=$((t0 + secs - 20))
	half1=$(echo $churn | cut -d' ' -f1-10); half2=$(echo $churn | cut -d' ' -f11-20)
	while [ "$(date +%s)" -lt $end ]; do
		rounds=$((rounds + 1))
		$J start $half1 --project soak >/dev/null 2>&1 || fail "churn round $rounds: start of the first half"
		$J start $half2 --project soak >/dev/null 2>&1 || fail "churn round $rounds: start of the second half"
		for n in c01 c07 c13 c20; do $J exec --project soak "$n" -- ping -c1 -t5 10.89.0.1 >/dev/null 2>&1 || echo "note: $n did not reach the gateway in round $rounds" >&2; done
		$J stop $half1 --project soak >/dev/null 2>&1 || fail "churn round $rounds: stop of the first half"
		$J restart $half2 --project soak >/dev/null 2>&1 || fail "churn round $rounds: restart of the second half"
		for n in $half2; do $J stop "$n" --project soak >/dev/null 2>&1 || fail "churn round $rounds: stop of $n"; done
	done
	echo "OK: $rounds rounds of churn (20 jails started and stopped, ten of them restarted, in each)"
	for p in $c4 $c6 $ch $cp; do rc=0; wait $p || rc=$?; echo "note: the client $p ended with status $rc at $(date +%s) (the churn ended at $(( t0 + secs - 20 )) or later)"; done
	for w in c4 c6 ch cp; do
		if ! grep -q 'command rc=0 ' "$work/soak.$w" || ! grep -q '^exec rc=0 ' "$work/soak.$w"; then
			echo "--- $work/soak.$w" >&2; cat "$work/soak.$w" >&2
			fail "the stream $w of the steady jails did not end well"
		fi
	done
	took=$(( $(date +%s) - t0 ))
	rc=0; wait $srv1 2>/dev/null || rc=$?; echo "note: the server in st1 ended with status $rc"
	rc=0; wait $srvh 2>/dev/null || rc=$?; echo "note: the server on the host ended with status $rc"
	rxh=$(tr -d ' ' < "$work/soak.rxh")
	rx4=$($J exec --project soak st1 -- cat /tmp/rx4 | tr -d ' ')
	rx6=$($J exec --project soak st1 -- cat /tmp/rx6 | tr -d ' ')
	[ "$rxh" = "$bytes" ] && [ "$rx4" = "$bytes" ] && [ "$rx6" = "$bytes" ] || fail "the streams lost data: host $rxh, jail v4 $rx4, jail v6 $rx6 bytes (want $bytes)"
	[ $took -le $((secs + 120)) ] || fail "the streams took $took s for a run of $secs s: they stalled"
	grep -E -q ' 0\.0% packet loss' "$work/soak.cp" || { cat "$work/soak.cp" >&2; fail "pings from a steady jail to the gateway were lost while jails came and went"; }
	echo "OK: three TCP streams delivered $bytes bytes each in $took s and no ping was lost while the other jails churned"
	check "stop what runs" $J stop --all --project soak
	wait_counts soak '10\.89\.0\.' 'fd50:89:' "jails=0 links=0 routes4=0 routes6=0"
	got=$(net_counts soak '10\.89\.0\.' 'fd50:89:')
	[ "$got" = "jails=0 links=0 routes4=0 routes6=0" ] || fail "after the churn: $got"
	leftover=$(ifconfig -l | tr ' ' '\n' | grep -c '^jo' || true)
	[ "$leftover" = 0 ] || fail "$leftover interfaces of JailOps are left after the churn"
	no_fail_in_doctor "after the churn"
	check "delete the jails" $J delete st1 st2 $churn --project soak --confirm-data-loss
	check "delete the project" $J project delete soak -y
	check "delete the network" $J network delete soak -y
	echo "OK: soak"
}

run_pf() {
	step "the packet filter, with real traffic (scripts/ci-freebsd-pf.sh)"
	# the full matrix takes minutes of waiting in its last phases; the quick form still covers every rule path
	# FORGE_BIN (set by the caller) runs phase 0e, the forged-frame probes; without it phase 0e is skipped
	PF_FAST=1 PF_IMAGE="$img" FORGE_BIN="${FORGE_BIN:-}" sh "$root/scripts/ci-freebsd-pf.sh" || fail "the packet filter test failed"
}

step "image, network, project"
uplink=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
[ -n "$uplink" ] || uplink=$(ifconfig -l | tr ' ' '\n' | grep -v -E '^(lo0|pflog0)$' | head -1)
jarch=$goarch
check "network create" $J network create lan --ipv4 10.77.0.1/24 --uplink "$uplink" --nat
check "project create" $J project create demo
check "project grant" sh -c "$J network grant lan --project demo && $J storage grant default --project demo"
# before any image exists the CLI names the two commands that make the base image, and a create with an image that does not
# exist names the one it was asked for (the catalog is configured later, so this does not go through an app install)
out=$($J image list 2>&1) || true
printf '%s\n' "$out" | grep -F -q "jailops image create $host_img --release $host_release, then jailops image build $host_img" ||
	{ echo "$out" >&2; fail "the empty image list names the commands that make the base image"; }
if out=$($J create hintcheck --project demo --image nosuch --network lan --storage default 2>&1); then
	echo "$out" >&2; fail "a jail create with an image that does not exist (it answered)"
fi
printf '%s\n' "$out" | grep -E -q "jailops image create nosuch --release [0-9]+\.[0-9]+-[A-Z0-9]+', then build it with 'jailops image build nosuch'" ||
	{ echo "$out" >&2; fail "a create with a missing image names the commands that make it"; }
check "image create" $J image create "$img" --release "$release" --arch "$jarch"
check "image build" $J image build "$img"
# a generation records the FreeBSD version of its packages (FreeBSD-runtime): a release with its patch level, or the
# package version of a branch's snapshot as it is
expect "the generation shows its FreeBSD version" '^ +g1 +([0-9]+\.[0-9]+-RELEASE(-p[0-9]+)?|[0-9]+\.snap[0-9]+) +[0-9]+ ' $J image show "$img"
expect "and so does the list of generations" "^$img#g1 +1 +- +([0-9]+\\.[0-9]+-RELEASE(-p[0-9]+)?|[0-9]+\\.snap[0-9]+) " $J image generation list "$img"
if [ "$part" = prepare ]; then echo "OK: the machine is prepared"; exit 0; fi
if [ "$part" = scale ]; then run_scale; echo "OK: the scale test passed"; exit 0; fi
if [ "$part" = soak ]; then run_soak; echo "OK: the soak test passed"; exit 0; fi
if [ "$part" = pf ]; then # its own VM in CI: the packet filter test builds its jails from the image above
	run_pf
	echo "OK: the packet filter test passed"
	exit 0
fi

step "a jail"
check "create" $J create web --project demo --image "$img" --network lan --storage default --autostart
check "start" $J start web --project demo
expect "the jail list has the AUTOSTART column" 'web +running +yes' $J list --project demo -c name,state,autostart
expect "the boot plan lists the autostart jail first" '^1[[:space:]]+web[[:space:]]+0[[:space:]]+autostart' $J boot
expect "the boot plan of one project" '^1[[:space:]]+web[[:space:]]+0[[:space:]]+autostart' $J boot --project demo

expect "the package cache has a dataset of its own" "^$mount/cache\$" zfs get -H -o value mountpoint "$pool/jailops/cache"
expect "the image build downloaded into the shared cache" '\.pkg' ls "$mount/cache/pkg"
# what the helper trusts when pkg runs as root is root's choice: a key directory the daemon could write, and a package
# repository on a host nobody listed in fetch-host, are refused by the helper (the images are made and deleted at once)
check "an image with a key directory of the daemon's own" $J image create e2e-evilkeys --release "$release" --arch "$jarch" --keys /var/tmp/jailops/e2e-keys
expect "the helper refuses a key directory the daemon chose" 'keys are chosen by root' sh -c "$J image build e2e-evilkeys 2>&1; true"
check "an image from a repository on a host nobody listed" $J image create e2e-evilrepo --release "$release" --arch "$jarch" --repo 'https://evil.example/${ABI}/latest'
expect "the helper refuses a repository host that is not in fetch-host" 'not in fetch-host' sh -c "$J image build e2e-evilrepo 2>&1; true"
check "delete the refused images" $J image delete e2e-evilkeys e2e-evilrepo -y
expect "the logs of the jails have a dataset of their own" '^/var/log/jailops$' zfs get -H -o value mountpoint "$pool/jailops/logs"
expect "the start of the jail wrote its console log there" 'jail_.*_console\.log' ls /var/log/jailops
expect "the jail runs FreeBSD" 'FreeBSD' $J exec --project demo web -- uname -s
if [ -n "${JAILOPS_E2E_IMAGE_RELEASE:-}" ]; then
  expect "the jail's userland is the image's release" "^$(echo "$JAILOPS_E2E_IMAGE_RELEASE" | sed 's/^\([0-9]*\)\.\([0-9]*\).*/\1/')[0-9]{5}\$" $J exec --project demo web -- uname -U
else
  expect "the jail's userland is the host's release" "^$(uname -U)\$" $J exec --project demo web -- uname -U
fi
expect "the jail has its address" '10\.77\.0\.' $J exec --project demo web -- ifconfig -a
expect "the jail reaches the host" '1 packets received' $J exec --project demo web -- ping -c1 -t3 10.77.0.1
check "a file in the jail" $J exec --project demo web -- sh -c 'echo ci-marker > /root/marker'
expect "the jail's root inherits devices=off" '^off$' zfs get -H -o value devices "$pool/jailops/projects/demo/jails/web/root"
expect "setuid stays on for a jail's root" '^on$' zfs get -H -o value setuid "$pool/jailops/projects/demo/jails/web/root"
expect "su in the jail keeps its setuid bit" '^-r-sr-xr-x' $J exec --project demo web -- ls -l /usr/bin/su
expect "exec reads flags after the jail name, up to --" 'FreeBSD' $J exec web --project demo -- uname -s
# a short command run with a terminal keeps all of its output (FreeBSD dropped it when the session leader exited)
lost=0; i=0
while [ $i -lt 40 ]; do
	i=$((i + 1))
	script -q /dev/null $J exec -t web --project demo -- echo "tty-hello-$i" 2>&1 | grep -q "tty-hello-$i" || lost=$((lost + 1))
done
[ $lost -eq 0 ] || fail "the output of a short command run with a terminal was lost in $lost of 40 runs"
echo "OK: 40 short commands run with a terminal printed all of their output"
expect "without --, a flag after the jail name is refused" 'would be the command' sh -c "JAILOPS_PROJECT=demo $J exec web --project demo uname 2>&1; true"
expect "labels" 'backup=yes' $J label --project demo web backup=yes

# Each of these was accepted and failed later: at the first jail start, inside an operation, or never visibly.
step "refused when given (sizes as bytes, the host's subnets, the uplink, names), and the forwarding warning"
hostsub=$(ifconfig "$uplink" inet | awk '/inet / {split($2, a, "."); print a[1] "." a[2] "." a[3] ".1/24"; exit}')
[ -n "$hostsub" ] || fail "the uplink $uplink has no IPv4 address"
expect "a subnet of the uplink's own LAN is refused, naming the interface" "overlaps .* on the host interface $uplink" sh -c "$J network create hostlan --ipv4 $hostsub 2>&1; true"
out=$(expect "an uplink that does not exist is refused" 'uplink em9 cannot be used: em9 does not exist' sh -c "$J network create typo --ipv4 10.78.0.1/24 --uplink em9 --nat 2>&1; true")
printf '%s\n' "$out" | grep -q "candidates on this host: .*$uplink" || { echo "$out" >&2; fail "the refusal of a missing uplink names the candidates"; }
expect "the loopback is no uplink" 'lo0 is a lo interface' sh -c "$J network create typo --ipv4 10.78.0.1/24 --uplink lo0 --nat 2>&1; true"
check "an attachment MTU other than the network's is accepted: every jail has a link of its own" $J config set web --project demo nic.eth0.mtu=1400
check "and taken off again" $J config unset web --project demo nic.eth0.mtu
expect "a snapshot name of 70 characters is refused" 'at most 64' sh -c "$J jail snapshot create web $(printf '%070d' 0 | tr 0 s) --project demo 2>&1; true"
expect "a project name of 14 characters is refused" 'at most 13' sh -c "$J project create abcdefghijklmn 2>&1; true"
check "a project quota given as 4GiB" $J storage grant default --project demo --quota 4GiB
expect "ZFS has the quota in bytes" '^4294967296$' zfs get -Hp -o value quota "$pool/jailops/projects/demo"
check "a volume with --size 2GiB is created" $J volume create sizedata --project demo --storage default --size 2GiB
check "a jail with --disk 4GiB is created" $J create sizes --project demo --image "$img" --network lan --storage default --disk 4GiB
check "attach sizedata to sizes" $J volume attach sizes sizedata /data --project demo
expect "its container has the quota in bytes" '^4294967296$' zfs get -Hp -o value quota "$pool/jailops/projects/demo/jails/sizes"
expect "its root clone has none" '^(0|none|-)$' zfs get -Hp -o value quota "$pool/jailops/projects/demo/jails/sizes/root"
expect "its volume has the quota in bytes" '^2147483648$' zfs get -Hp -o value quota "$pool/jailops/projects/demo/volumes/sizedata"
check "the jail with sizes starts" $J start sizes --project demo
check "stop it" $J stop sizes --project demo
check "delete it" $J delete --confirm-data-loss sizes --project demo
check "the project quota is taken away again" $J storage grant default --project demo --quota ""

step "resource limits (docs/operations.md): rctl rules, the quota of the container and the pf state limit"
# kern.racct.enable=1 is a loader tunable: the test host must have it in /boot/loader.conf (doctor fails without it)
racct=$(sysctl -n kern.racct.enable)
[ "$racct" = 1 ] || echo "SKIPPED: kern.racct.enable is $racct on this host: the rctl checks of the block below do not run (add it to /boot/loader.conf and reboot)"
check "a jail with limits is created and started" $J create lim --project demo --image "$img" --network lan --storage default --memory 1G --pids 60 --cpu 1 --disk 512M --start
expect "the container has the quota in bytes" '^536870912$' zfs get -Hp -o value quota "$pool/jailops/projects/demo/jails/lim"
expect "the root clone has none" '^(0|none|-)$' zfs get -Hp -o value quota "$pool/jailops/projects/demo/jails/lim/root"
[ "$racct" != 1 ] || expect_retry "the memory rule is on the running jail" 'jail:demo_lim:swapuse:deny=1073741824' sh -c 'rctl 2>&1'
[ "$racct" != 1 ] || expect "the process rule is on the running jail" 'jail:demo_lim:maxproc:deny=60' sh -c 'rctl 2>&1'
[ "$racct" != 1 ] || expect "the CPU rule is on the running jail" 'jail:demo_lim:pcpu:deny=100' sh -c 'rctl 2>&1'
[ "$racct" != 1 ] || expect "an allocation beyond the memory limit fails" 'out of (memory|space)' sh -c "$J exec --project demo lim -- /usr/bin/awk 'BEGIN{s=\"x\"; for(i=0;i<29;i++) s=s s; print length(s)}' 2>&1 | head -c 300; true"
[ "$racct" != 1 ] || expect "fork fails beyond the process limit" 'Cannot fork|Resource temporarily unavailable' sh -c "$J exec --project demo lim -- /bin/sh -c 'i=0; while [ \$i -lt 150 ]; do sleep 6 & i=\$((i+1)); done; wait' 2>&1 | head -c 600; true"
expect "a write beyond the quota fails outside the root clone too" 'quota exceeded' sh -c "$J exec --project demo lim -- /bin/dd if=/dev/random of=/var/db/fill bs=1m count=700 2>&1 | head -c 600; true"
check "remove the file" $J exec --project demo lim -- /bin/rm -f /var/db/fill
expect_retry "the default state limit is on the pass rules of the jail's anchor" 'keep state \([^)]*max 10000[,)]' pfctl -a jailops/demo/lim -sr
check "a changed quota applies at once" $J config set lim --project demo limits.disk=1G
expect "the container has the new quota" '^1073741824$' zfs get -Hp -o value quota "$pool/jailops/projects/demo/jails/lim"
check "a state limit of the jail" $J config set lim --project demo limits.states=777
expect_retry "the anchor has the jail's state limit" 'keep state \([^)]*max 777[,)]' pfctl -a jailops/demo/lim -sr
check "stop the jail with limits" $J stop lim --project demo
[ "$racct" != 1 ] || expect "no rctl rule is left for it" '^0$' sh -c 'rctl 2>&1 | grep -c demo_lim; true'
check "delete it" $J delete --confirm-data-loss lim --project demo
expect "ZFS has no quota" '^(0|none|-)$' zfs get -Hp -o value quota "$pool/jailops/projects/demo"
sysctl net.inet.ip.forwarding=0 >/dev/null
expect "network create warns when forwarding is off" 'sysctl net.inet.ip.forwarding=1' sh -c "$J network create fwd --ipv4 10.79.0.1/24 --uplink $uplink --nat 2>&1"
sysctl net.inet.ip.forwarding=1 >/dev/null
check "delete that network" $J network delete fwd -y

step "stop timeout (docs/operations.md): a service that needs fifteen seconds after SIGTERM is killed by a stop timeout of five, and lives with the default of thirty"
# the service ends its work on SIGTERM (fifteen seconds), writes a marker into a volume of the host and exits
slowsh="trap 'sleep 15; echo done > /srv/out/marker; exit 0' TERM; touch /srv/out/ready; while :; do sleep 1; done"
for v in sto10 sto30; do check "volume $v" $J volume create $v --project demo; done
check "a jail with a stop timeout of five seconds" $J create slow10 --project demo --image "$img" --network lan --storage default --stop-timeout 5
check "attach sto10 to slow10" $J volume attach slow10 sto10 /srv/out --project demo
check "start slow10" $J start slow10 --project demo
check "a jail with the default stop timeout (thirty seconds)" $J create slow30 --project demo --image "$img" --network lan --storage default
check "attach sto30 to slow30" $J volume attach slow30 sto30 /srv/out --project demo
check "start slow30" $J start slow30 --project demo
expect "the setting is in the jail" 'stop_timeout.*5' sh -c "$J config show slow10 --project demo 2>&1"
expect "jail.conf of the jail with five seconds has it" 'stop\.timeout = 5;' cat /usr/local/etc/jailops/jails/demo_slow10/jail.conf
expect "jail.conf of the other one has the default" 'stop\.timeout = 30;' cat /usr/local/etc/jailops/jails/demo_slow30/jail.conf
for j in slow10 slow30; do check "the service of $j runs" $J exec --project demo $j -- daemon -f /bin/sh -c "$slowsh"; done
# the signal must not arrive before the shell has set its trap
for n in 10 30; do
	expect_retry "the service of slow$n has set its trap" '^ready$' sh -c "[ -e $(zfs get -H -o value mountpoint "$pool/jailops/projects/demo/volumes/sto$n")/ready ] && echo ready || echo no"
done
check "stop the jail with five seconds" $J stop slow10 --project demo
expect "its service was killed before it finished" '^none$' sh -c "[ -e $(zfs get -H -o value mountpoint "$pool/jailops/projects/demo/volumes/sto10")/marker ] && echo marker || echo none"
check "stop the jail with the default" $J stop slow30 --project demo
expect "its service finished" '^done$' cat "$(zfs get -H -o value mountpoint "$pool/jailops/projects/demo/volumes/sto30")/marker"
for j in slow10 slow30; do check "delete $j" $J delete --confirm-data-loss $j --project demo; done
for v in sto10 sto30; do check "delete volume $v" $J volume delete $v --project demo --confirm-data-loss; done

step "a jail that cannot reach the package servers starts at once; the host fetches bash for it, a start never waits long for a mirror"
check "a policy that denies everything outbound" $J firewall policy create closed --project demo --default-in deny --default-out deny
check "a jail under it" $J create closedj --project demo --image "$img" --network lan --storage default
check "it uses the policy" $J config set closedj firewall.policies closed --project demo
startbound() { # a start takes a minute at most, whatever the mirror does (the host gives bash 20 s, the jail's own network is never waited for)
	t0=$(date +%s)
	check "$1" $J start closedj --project demo
	[ $(( $(date +%s) - t0 )) -le 60 ] || fail "the start of a jail without network took $(( $(date +%s) - t0 )) s"
}
startbound "start it"
check "a shell is there whatever the mirror did" $J exec --project demo closedj -- /bin/sh -c true
expect "its shell is bash" '^/usr/local/bin/bash$' $J config get closedj shell --project demo
# what the host could not fetch in time it fetches at the next start (the cache keeps what it has)
for n in 1 2 3 4 5; do
	$J exec --project demo closedj -- test -x /usr/local/bin/bash >/dev/null 2>&1 && break
	check "stop it ($n)" $J stop closedj --project demo
	startbound "start it again ($n): the host fetches what it still lacks"
done
check "bash is in the jail" $J exec --project demo closedj -- test -x /usr/local/bin/bash
check "delete it" $J delete --confirm-data-loss --stop closedj --project demo
check "delete the policy" $J firewall policy delete closed --project demo -y

step "packages of a running jail change inside it (pkg -j); what a process of the jail plants cannot make the host write"
check "a jail that runs" $J create pkgj --project demo --image "$img" --network lan --storage default --start
expect "the check of its packages runs pkg inside the jail" 'pkgj' $J update check pkgj --project demo
check "the jail plants a link where pkg keeps its cache" $J exec --project demo pkgj -- sh -c 'rm -rf /var/cache/pkg; ln -s /jopsci-escape /var/cache/pkg; mkdir -p /usr/local/etc/pkg/repos; ln -s /jopsci-escape /usr/local/etc/pkg/repos/escape.conf'
$J update apply pkgj --project demo --packages -y >/dev/null 2>&1 || true
[ ! -e /jopsci-escape ] || fail "pkg wrote through a link of a running jail onto the host"
check "delete it" $J delete --confirm-data-loss --stop pkgj --project demo

step "the jail's shell and prompt (docs/shell.md): bash and the default prompt, an override, non-interactive commands"
webroot=$mount/projects/demo/jails/web/root
# the short name of the host as the daemon writes it into the prompt: the first label, lower case, letters, digits, hyphens
shorthost=$(hostname | cut -d. -f1 | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9-' | sed 's/^-*//; s/-*$//')
# DefaultPS1: user@jail in the colour, the grey tag [project/host] from the variables the prompt file derives it from, :dir and # or $, a space
ps1='\[\e[38;5;39m\]\u@\h\[\e[0m\]${_jailops_where:+ \[\e[38;5;245m\][${_jailops_where}]\[\e[0m\]}:\w\$ '
expect "a new jail's shell is bash" '^/usr/local/bin/bash$' $J config get --project demo web shell
expect "a new jail's prompt is the default" '^default$' $J config get --project demo web prompt
check "bash was installed into the jail's /usr/local at its first start" test -x "$webroot/usr/local/bin/bash"
expect "bash is a package of the jail" '^bash-' pkg -j demo_web info bash
check_retry "the prompt file is JailOps'" grep -F -x "	PS1='$ps1'" "$webroot/usr/local/etc/profile.d/jailops-prompt.sh"
check_retry "the variables script is JailOps'" grep -F "sysctl -n security.jail.env" "$webroot/usr/local/etc/profile.d/jailops-env.sh"
check "the variables script holds no name of the project" sh -c '! grep -q demo "$1"' sh "$webroot/usr/local/etc/profile.d/jailops-env.sh"
# where the jail is comes from the parameters env.jailops_* of its jail.conf: the jail reads them as a sysctl
expect "the jail knows its project" '^jailops_project=demo$' $J exec --project demo web -- sysctl -n security.jail.env
expect "the jail knows its name" '^jailops_jail=web$' $J exec --project demo web -- sysctl -n security.jail.env
expect "the jail knows its host" "^jailops_host=$shorthost\$" $J exec --project demo web -- sysctl -n security.jail.env
for f in profile bash.bashrc; do
	expect_retry "/usr/local/etc/$f sources them" '^# BEGIN jailops shell' head -1 "$webroot/usr/local/etc/$f"
done
# bash reads /usr/local/etc/bash.bashrc in an interactive shell and /usr/local/etc/profile in a login shell (the
# package is built with SYSBASHRC); both lead to the prompt file. An interactive bash needs a terminal (without one
# bash -i stops itself): script(1) inside the jail gives it one, and the exec itself stays a plain pipe.
same() { # same DESCRIPTION WANT COMMAND...: standard output must be exactly WANT
	desc=$1; want=$2; shift 2
	out=$("$@" 2>/dev/null) || { echo "$out" >&2; fail "$desc"; }
	# a command in a pseudo-terminal sometimes prints nothing (its shell ended before the output was written): ask again
	n=0; while [ -z "$out" ] && [ -n "$want" ] && [ $n -lt 3 ]; do n=$((n + 1)); sleep 1; out=$("$@" 2>/dev/null) || true; done
	[ "$out" = "$want" ] || { printf 'got:  %s\nwant: %s\n' "$out" "$want" >&2; fail "$desc"; }
}
in_pty() { # in_pty JAIL COMMAND...: what COMMAND printed in a pseudo-terminal in the jail, without carriage returns,
	# the echo of the ^D script sends at the end of its input, and empty lines
	j=$1; shift
	$J exec -T --project demo "$j" -- script -q /dev/null "$@" </dev/null 2>/dev/null | tr -d '\r\010' | sed 's/\^D//g' | grep -v '^$' || true
}
last_line() { "$@" | tail -n 1; } # a login reads ~/.profile, whose resizewin prints before the command
same "an interactive bash has the prompt" "PS1=[$ps1]" in_pty web /usr/local/bin/bash -ic 'echo "PS1=[$PS1]"'
same "an interactive login bash has the prompt" "PS1=[$ps1]" last_line in_pty web /usr/local/bin/bash -lic 'echo "PS1=[$PS1]"'
same "an interactive bash has the variables" "JAILOPS=[demo web $shorthost]" in_pty web /usr/local/bin/bash -ic 'echo "JAILOPS=[$JAILOPS_PROJECT $JAILOPS_JAIL $JAILOPS_HOST]"'
same "an interactive login bash has the variables" "JAILOPS=[demo web $shorthost]" last_line in_pty web /usr/local/bin/bash -lic 'echo "JAILOPS=[$JAILOPS_PROJECT $JAILOPS_JAIL $JAILOPS_HOST]"'
same "a bash script is not affected" "PS1=[unset]" $J exec --project demo web -- /usr/local/bin/bash -c 'echo "PS1=[${PS1-unset}]"'
same "a login bash running a command is not affected" "PS1=[unset]" $J exec --project demo web -- /usr/local/bin/bash -lc 'echo "PS1=[${PS1-unset}]"'
same "a login sh keeps FreeBSD's own prompt" 'PS1=[\u@\h:\w \$ ]' last_line in_pty web env HOME=/root sh -lic 'echo "PS1=[$PS1]"'
# the prompt as a terminal shows it: jailops shell (bash, the jail's shell) in a pseudo-terminal, typed into once bash
# is up (bash drops what was typed before it set the terminal up)
(sleep 3; printf 'echo "E2E PATH=$PATH HOME=$HOME"\n'; sleep 2; printf 'exit\n'; sleep 1) | TERM=xterm timeout -s KILL 60 script -q "$work/shell.out" $J shell --project demo web >/dev/null 2>&1 || true
grep -a -q "$(printf '\033')\[38;5;39mroot@web" "$work/shell.out" || { od -c "$work/shell.out" | head -20 >&2; fail "jailops shell shows the blue prompt"; }
grep -a -q "$(printf '\033')\[38;5;245m\[demo/$shorthost\]$(printf '\033')\[0m:/#" "$work/shell.out" || { od -c "$work/shell.out" | head -20 >&2; fail "jailops shell shows the project and the host in grey"; }
grep -a -q "E2E PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin HOME=/root" "$work/shell.out" || { cat -v "$work/shell.out" >&2; fail "a shell session has the PATH of a login and root's HOME"; }
# a user's own ~/.bashrc wins
check "a user's own prompt" $J exec --project demo web -- sh -c "echo \"PS1='mine> '\" > /root/.bashrc"
same "~/.bashrc wins over the prompt file" "PS1=[mine> ]" in_pty web /usr/local/bin/bash -ic 'echo "PS1=[$PS1]"'
check "drop the user's own prompt" $J exec --project demo web -- rm /root/.bashrc
# the key: a new prompt at once, none removes the files, an injection is refused
check "a red prompt" $J config set --project demo web prompt '\[\e[38;5;196m\]\u@\h:\w\$\[\e[0m\] '
check "the red prompt is written at once" grep -F -q '38;5;196m' "$webroot/usr/local/etc/profile.d/jailops-prompt.sh"
expect_refused "a prompt that would run a command is refused" $J config set --project demo web prompt '\044(touch /tmp/pwned)'
check "prompt short" $J config set --project demo web prompt short
check "short has no tag" grep -F -x "	PS1='\[\e[38;5;39m\]\u@\h\[\e[0m\]:\w\\$ '" "$webroot/usr/local/etc/profile.d/jailops-prompt.sh"
check "prompt none" $J config set --project demo web prompt none
if [ -e "$webroot/usr/local/etc/profile.d/jailops-prompt.sh" ]; then fail "prompt none left the prompt file"; fi
check "prompt none keeps the variables" test -e "$webroot/usr/local/etc/profile.d/jailops-env.sh"
check "the default prompt again" $J config set --project demo web prompt default
check "shell-setup on a jail that has everything changes nothing" $J jail shell-setup --project demo web
expect "the shell setup left no condition" '^$' sh -c "$J jail show --project demo web -o json | grep ShellSetup || true"

step "interface descriptions (ifconfig shows what JailOps made)"
expect "the host end of the jail's epair" 'description: jailops jail=demo/web net=lan \(host side\)' ifconfig -a
expect "the jail end, inside the jail" 'description: jailops jail=demo/web net=lan \(jail side\)' $J exec --project demo web -- ifconfig -a
expect "doctor finds every description" 'net.descriptions +PASS' $J doctor

step "kernel notifications: the daemon reads devd's socket, and a limit that a jail hit is an event (docs/operations.md)"
expect_retry "doctor says the daemon reads devd" 'host\.devd +PASS' sh -c "$J doctor 2>&1; true"
if [ "$(sysctl -n kern.racct.enable 2>/dev/null)" = 1 ]; then
	# a rule with the action devctl only notifies: the jail web has more than one process, so its next fork matches
	devd_rule=jail:demo_web:maxproc:devctl=1
	check "a notify-only rctl rule on the jail web" rctl -a $devd_rule
	$J exec --project demo web -- sh -c 'sleep 1 & sleep 1 & wait' >/dev/null 2>&1 || true
	expect_retry "the limit the jail hit is an event" 'jail-limit-hit' sh -c "timeout 4 $J events --project demo --since-id 0 --type lifecycle 2>&1; true"
	check "the notify-only rule is removed again" rctl -r $devd_rule
else
	echo "kern.racct.enable is 0: the event of a limit that a jail hit is not checked" >&2
fi
step "routed networks: the host is the router, every jail has a link of its own, and the helper's ownership of interfaces (docs/security-model.md, Interfaces)"
out=$($J network create office --ipv4 10.66.0.1/24 --uplink "$uplink" --nat 2>&1) || { echo "$out" >&2; fail "network create office"; }
printf '%s\n' "$out" | grep -q warning && { echo "$out" >&2; fail "network office is created without a note"; }
expect "the network is listed" '^office +10\.66\.0\.0/24' $J network list
expect_retry "the host rejects the addresses of the subnet that no jail has" '^10\.66\.0\.0/24 +[^ ]+ +URS +lo0' sh -c "netstat -rn -f inet | grep '^10.66.0.0/24'"
if ifconfig -a | grep -q 'description: jailops net='; then fail "a network made an interface of its own"; fi
check "project edge" $J project create edge
check "grant office to edge" sh -c "$J network grant office --project edge && $J storage grant default --project edge"
check "a jail on office" $J create edgeweb --project edge --image "$img" --network office --storage default
check "it starts" $J start edgeweb --project edge
waitfor "the host end of edgeweb exists" 60 sh -c "ifconfig -a | grep -q 'description: jailops jail=edge/edgeweb net=office'"
edgeweb_if=$(ifconfig -a | awk '/^[a-z0-9]+:/ {n=$1; sub(":","",n)} /description: jailops jail=edge\/edgeweb net=office \(host side\)/ {print n; exit}')
[ -n "$edgeweb_if" ] || fail "the host end of edgeweb was not found"
expect "its host end carries the gateway as a /32" 'inet 10\.66\.0\.1 netmask 0xffffffff' ifconfig "$edgeweb_if"
if ifconfig "$edgeweb_if" | grep -q 'inet6 fe80::1%'; then fail "the host end of a jail on an IPv4-only network carries the link-local gateway"; fi
edgeweb4=$($J config get edgeweb nic.eth0.ipv4 --project edge | tail -1)
expect "the host reaches the jail through its own link" "interface: $edgeweb_if" route -n get "$edgeweb4"
expect "the jail has its address on office as a /32" 'inet 10\.66\.0\.[0-9]+ netmask 0xffffffff' $J exec --project edge edgeweb -- ifconfig -a
expect "the jail reaches its gateway" '1 packets received' $J exec --project edge edgeweb -- ping -c1 -t3 10.66.0.1
gw4=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
expect "the jail reaches the host's default gateway through the NAT of the uplink" '1 packets received' $J exec --project edge edgeweb -- ping -c1 -t5 "$gw4"
expect "an address of the subnet that no jail has is refused at once" 'Destination Host Unreachable' sh -c "$J exec --project edge edgeweb -- ping -c1 -t2 10.66.0.77 2>&1; true"
expect "a jail without a policy says it is open" "Firewall: +open: no firewall policy" $J jail info edgeweb --project edge
check "a policy without --default-in and --default-out" $J firewall policy create nodefaults --project edge
expect "it denies inbound and allows outbound, written into the policy" 'nodefaults +deny +allow' $J firewall policy list --project edge
check "delete it" $J firewall policy delete nodefaults --project edge -y
# a rule names a jail: jail:edgeweb in an address set of the project, the set in a policy, the policy on another jail
check "an address set with a jail as a member" $J firewall address-set create git-allow --project edge --address jail:edgeweb
check "an address with a comment" $J firewall address-set create office-ip --project edge --address 192.0.2.7 --comment "the office"
check "a policy that names the set" $J firewall policy create git --project edge --default-in deny --default-out allow --comment "the git server of the team"
check "a rule that names the set" $J firewall rule add git in --project edge --action allow --proto tcp --from set:git-allow --port 22 --comment "ssh from the team"
check "a rule that names the jail" $J firewall rule add git in --project edge --action allow --proto tcp --from jail:edgeweb --port 5432 --comment "the web jail asks for rows"
expect "the rules are listed with their numbers" '1 +- +allow +in +tcp' $J firewall rule list git --project edge
check "the second rule is switched off" $J firewall rule disable git 2 --project edge
expect "policy show marks it" 'disabled' $J firewall policy show git --project edge -o yaml
check "and on again" $J firewall rule enable git 2 --project edge
check "the first rule moves behind the second" $J firewall rule move git 1 --after 2 --project edge
check "a second jail" $J create edgedb --project edge --image "$img" --network office --storage default
check "its policy" $J config set edgedb firewall.policies git --project edge
check "it starts" $J start edgedb --project edge
waitfor "the anchor of edgedb is loaded" 60 sh -c "pfctl -a jailops/edge/edgedb -sr | grep -q ."
expect "the anchor of the second jail holds the address of the first one in the table of the set" '10\.66\.0\.' pfctl -a jailops/edge/edgedb -t s_git_allow -T show
expect "the rule comments are in the loaded anchor's source: show says why a rule is there" 'ssh from the team' $J firewall policy show git --project edge
expect "and in the table of the jail itself" '10\.66\.0\.' pfctl -a jailops/edge/edgedb -t j_edgeweb -T show
check "delete the second jail" $J delete --stop --confirm-data-loss edgedb --project edge
check "delete the policy that names them" $J firewall policy delete git --project edge -y
check "delete the set with the jail in it" $J firewall address-set delete git-allow --project edge -y
check "delete the set with a comment" $J firewall address-set delete office-ip --project edge -y
# a bridge made by hand is someone else's and never part of a network
b=$(ifconfig bridge create) && ifconfig "$b" name mybr >/dev/null || fail "a bridge made by hand"
# an epair made by hand under a jo name, no description
ep=$(ifconfig epair create) && ifconfig "${ep%a}b" name jo79b >/dev/null && ifconfig "$ep" name jo79a >/dev/null || fail "a jo-named epair made by hand"
# the helper itself, over its socket: every request a compromised daemon could make on the uplink, lo0, mybr and jo79a is
# refused; an epair keeps the marker in a jail's vnet
if [ -n "${IFPROBE_BIN:-}" ]; then
	check "the helper's ownership probe" "$IFPROBE_BIN" -uplink "$uplink" -foreign mybr -bare jo79a -jail edge_edgeweb
	cat "$work/check.out"
else
	echo "IFPROBE_BIN is not set: the helper's ownership probe is skipped"
fi
expect "mybr is untouched" 'groups: bridge' ifconfig mybr
if ifconfig mybr | grep -q description; then fail "mybr was given a description"; fi
check "remove the bridge made by hand" ifconfig mybr destroy
check "remove the epair made by hand" ifconfig jo79a destroy
# a stale epair of JailOps (an epair with a jail's name and JailOps's description, of no jail) is found and removed
ep=$(ifconfig epair create) && ifconfig "${ep%a}b" name jo0123456789zzb >/dev/null && ifconfig "$ep" name jo0123456789zza >/dev/null || fail "a stale epair"
ifconfig jo0123456789zza description 'jailops jail=gone/old net=office (host side)'
ifconfig jo0123456789zzb description 'jailops jail=gone/old net=office (jail side)'
# The reconciler may remove it before the doctor looks, or while it destroys the pair the doctor sees one side only:
# either side in the warning, or the pair already gone, is the finding.
n=0
while ifconfig jo0123456789zza >/dev/null 2>&1; do
	$J doctor 2>&1 | grep -Eq 'network.epairs +WARN.*jo0123456789zz[ab]' && break
	n=$((n + 1)); [ $n -gt 30 ] && fail "doctor does not list the stale epair"; sleep 1
done
n=0 # the reconcile loop removes it on one of its next passes
while ifconfig jo0123456789zza >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 60 ] && fail "the stale epair is still there after 120 s"; sleep 2; done
expect "doctor: no stale epairs" 'network.epairs +PASS' $J doctor
expect "doctor: every description" 'net.descriptions +PASS' $J doctor
# network delete removes the reject route
check "delete the jail" $J delete --stop --confirm-data-loss edgeweb --project edge
check "delete project edge" $J project delete edge -y
check "delete network office" $J network delete office -y
expect_retry "the reject route of office is gone" 'gone' sh -c "netstat -rn -f inet | grep -q '^10.66.0.0/24' && echo there || echo gone"

step "name resolution of jails (docs/networking-ipv6.md): the host's nameservers, a live change, a resolver on the gateway"
# the network lan was made without dns: its jails get the host's own nameservers
hostns=$(awk '$1 == "nameserver" && $2 !~ /^(127\.|::1$)/ && $2 !~ /%/ {print $2; exit}' /etc/resolv.conf)
[ -n "$hostns" ] || fail "the step needs a nameserver in the host's /etc/resolv.conf that is not loopback"
expect "a network without dns hands the jail the host's nameserver" "^nameserver $hostns\$" cat "$webroot/etc/resolv.conf"
expect "network show says where they come from" "DNS: +$hostns .*the host's nameservers" $J network show lan
expect_retry "the jail resolves a name" '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' $J exec --project demo web -- drill -Q pkg.freebsd.org
# a change of the network's dns reaches the running jail at once, without a restart
jid=$(jls -j demo_web jid)
$J network show lan -o yaml >"$work/lan.yaml"
sed "/^spec:/a\\
\ \ dns: [\"$hostns\", \"192.0.2.53\"]
" "$work/lan.yaml" >"$work/lan-dns.yaml"
expect "network edit names the running jails it rewrote" 'resolv.conf rewritten in the running jails demo/web' $J network edit lan -f "$work/lan-dns.yaml"
expect "the running jail has the new resolv.conf" '^nameserver 192\.0\.2\.53$' cat "$webroot/etc/resolv.conf"
[ "$(jls -j demo_web jid)" = "$jid" ] || fail "the jail was restarted for a change of its nameservers"
# a jail whose resolv.conf lost the JailOps line is left alone, at a change and at a start
cp "$webroot/etc/resolv.conf" "$work/resolv.jail"
printf 'nameserver 127.0.0.1\n' >"$webroot/etc/resolv.conf"
expect "a jail's own resolv.conf is not rewritten" 'not rewritten in demo/web: its resolv.conf is its own' $J network edit lan -f "$work/lan.yaml"
check "restart" $J restart web --project demo
expect "nor at a start" '^nameserver 127\.0\.0\.1$' cat "$webroot/etc/resolv.conf"
check "the jail gives its resolv.conf back" rm "$webroot/etc/resolv.conf"
# a host that resolves only through a local resolver: the jails ask the gateway, which answers once a resolver listens there
cp -p /etc/resolv.conf "$work/resolv.host"
dns_cleanup() {
	cp -p "$work/resolv.host" /etc/resolv.conf
	[ -f "$work/unbound.pid" ] && kill "$(cat "$work/unbound.pid")" 2>/dev/null
	rm -f "$work/unbound.pid"
}
printf 'nameserver 127.0.0.1\n' >/etc/resolv.conf
expect "the jails of a host behind a local resolver ask the gateway" 'DNS: +10\.77\.0\.1 \(the gateway' $J network show lan
expect "and network show says what the administrator does" 'access-control: 10\.77\.0\.0/24 allow' $J network show lan
check "restart" $J restart web --project demo
expect "the jail's resolv.conf names the gateway" '^nameserver 10\.77\.0\.1$' cat "$webroot/etc/resolv.conf"
expect "doctor: nothing answers on the gateway yet" 'network\.dns +WARN .*the jails ask the gateway 10\.77\.0\.1' $J doctor
cat >"$work/unbound.conf" <<UNBOUND
server:
	username: ""
	chroot: ""
	directory: "$work"
	pidfile: "$work/unbound.pid"
	interface: 10.77.0.1
	access-control: 10.77.0.0/24 allow
	module-config: "iterator"
forward-zone:
	name: "."
	forward-addr: $hostns
UNBOUND
check "a resolver on the gateway (the administrator's part)" local-unbound -c "$work/unbound.conf"
expect_retry "doctor: the gateway answers" 'network\.dns +PASS +lan: the gateway 10\.77\.0\.1 answers DNS' $J doctor
expect_retry "the jail resolves through the gateway" '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' $J exec --project demo web -- drill -Q pkg.freebsd.org
dns_cleanup
check "restart" $J restart web --project demo
expect "the host's nameserver again" "^nameserver $hostns\$" cat "$webroot/etc/resolv.conf"
# pf.state-policy: jails need `set state-policy if-bound` in the pf.conf the system loads (a failed check without it)
cp -p /etc/pf.conf "$work/pf.host"
chmod 600 /etc/pf.conf # root's alone, as on a real host: the daemon (user jailops) cannot open it, the helper reads it
{ grep -v '^set state-policy' "$work/pf.host"; echo 'block drop in log on lo9 all'; } >/etc/pf.conf
check "a default block" sh -c 'pfctl -nf /etc/pf.conf && pfctl -f /etc/pf.conf'
expect "doctor: the state policy is missing" 'pf\.state-policy +FAIL .*set state-policy if-bound' sh -c "$J doctor 2>&1; true"
{ echo 'set state-policy if-bound'; grep -v '^set state-policy' "$work/pf.host"; echo 'block drop in log on lo9 all'; } >/etc/pf.conf
check "the state policy" sh -c 'pfctl -nf /etc/pf.conf && pfctl -f /etc/pf.conf'
expect "doctor: the state policy is there" 'pf\.state-policy +PASS' $J doctor
cp -p "$work/pf.host" /etc/pf.conf
check "the host's pf.conf again" pfctl -f /etc/pf.conf

step "logs of all jails, and forwarding them to a syslog listener (tcp on the host)"
marker="ci-forward-$$"
# a plain tcp listener on the loopback stands for the syslog server; it ends by itself after five minutes
timeout 300 nc -lk 127.0.0.1 15514 > "$work/syslog.out" 2>/dev/null &
ncpid=$!
# A receiver on this host is root's to configure (jailopsd.yaml): the API refuses loopback and link-local receivers.
cp -p /usr/local/etc/jailops/jailopsd.yaml "$work/jailopsd.yaml.logfwd"
cat >> /usr/local/etc/jailops/jailopsd.yaml <<YAML
logging:
  forward:
    - name: ci-tcp
      type: syslog
      to: tcp://127.0.0.1:15514
      facility: local3
      sources: {projects: [demo]}
YAML
check "restart jailopsd with a sink in jailopsd.yaml" service jailopsd restart
n=0; until $J logs forward list >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
expect "the sink is listed" '^ci-tcp +syslog +tcp://127\.0\.0\.1:15514 +local3' $J logs forward list
# the sink starts at the end of the files: log the line again until one arrives
expect_retry "a line logged in the jail arrives with the jail in the structured data" \
	"\\[jailops project=\"demo\" jail=\"web\" app=\"\" file=\"messages\"\\] .*$marker" \
	sh -c "$J exec --project demo web -- logger -t citest $marker >/dev/null 2>&1; grep -a -o '<15[0-9]>1 [^<]*$marker' '$work/syslog.out'"
expect "the unified view shows it as web/messages" "^web/messages +.*$marker" $J logs --project demo --grep "$marker"
expect "-o json carries the jail" "\"jail\":\"web\".*$marker" $J logs --project demo --jail web --grep "$marker" -o json
expect "the sink delivers" '^ci-tcp +ok ' $J logs forward status
expect "a list through the API may not keep the loopback sink of the file" 'target refused' sh -c "$J logs forward set ci-tcp --facility local4 2>&1; true"
check "an empty list through the API replaces the file's" $J logs forward remove -y ci-tcp
expect "the API refuses a loopback receiver" 'target refused' sh -c "$J logs forward add ci-lo --url tcp://127.0.0.1:15515  2>&1; true"
expect "the API refuses a link-local receiver" 'target refused' sh -c "$J logs forward add ci-md --url https://169.254.169.254/x  2>&1; true"
expect "the API refuses a token file outside logging.secrets_dir" 'not a file directly in' \
	sh -c "$J logs forward add ci-wh --url https://hooks.example.com/ci --token-file /usr/local/etc/jailops/priv.conf  2>&1; true"
expect "init made the secrets directory" '^root:jailops 750$' stat -f '%Su:%Sg %Lp' /usr/local/etc/jailops/sinks
printf 'ci-token\n' > "$work/ci.token"
check "a token file in the secrets directory" install -m 0640 -o root -g jailops "$work/ci.token" /usr/local/etc/jailops/sinks/ci.token
check "the API accepts a token file there" $J logs forward add ci-wh --url https://hooks.example.com/ci --token-file /usr/local/etc/jailops/sinks/ci.token  --audit-only
expect "the forward test answers a class, not the receiver's words" '(dns lookup failed|connection refused|timeout|unreachable|HTTP [0-9]+|tls handshake failed|certificate not trusted|send failed)' sh -c "$J logs forward test ci-wh 2>&1; true"
expect "removing a sink asks first" 'confirmation required' sh -c "$J logs forward remove ci-wh </dev/null 2>&1; true"
check "remove the sink" $J logs forward remove -y ci-wh
check "back to the list of jailopsd.yaml" $J logs forward reset -y
rm -f /usr/local/etc/jailops/sinks/ci.token
cp -p "$work/jailopsd.yaml.logfwd" /usr/local/etc/jailops/jailopsd.yaml
check "restart jailopsd without the sink" service jailopsd restart
n=0; until $J logs forward list >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
kill "$ncpid" 2>/dev/null || true

step "WireGuard (a server, a peer enrolled on it, and a client made from the token on the same host)"
# FreeBSD has the if_wg driver; the wg program comes with the base system or with the package wireguard-tools. A CI
# image without either skips this block and says what is missing.
wg_missing=""
kldload -n if_wg 2>/dev/null || wg_missing="the kernel module if_wg"
wgbin=""
for p in /usr/bin/wg /usr/local/bin/wg; do [ -x "$p" ] && { wgbin=$p; break; }; done
[ -n "$wgbin" ] || wg_missing="${wg_missing:+$wg_missing and }the wg program (pkg install wireguard-tools)"
if [ -n "$wg_missing" ]; then
	echo "SKIP: WireGuard: $wg_missing is missing on this machine"
else
	check "a server" $J wireguard create office --address 10.98.0.1/24 --listen-port 51820 --network lan --endpoint 127.0.0.1:51820
	expect "the server's interface says what it is" 'description: jailops wireguard=office' ifconfig wg-office
	expect "the server listens on its port" 'listening port: 51820' "$wgbin" show wg-office
	expect "its key is root's alone" '^600$' stat -f %Lp /var/db/jailops-priv/wireguard/office/private.key
	token=$($J wireguard peer add office laptop) || fail "peer add"
	case $token in jwg1.*) ;; *) fail "peer add printed no token" ;; esac
	expect "the peer is configured" 'laptop' $J wireguard peer list office
	# the same host: the client gets its own addresses and routes (they must not overlap the server's), and dials
	# the server on the loopback address
	# the token holds a private key: from standard input, never as an argument
	check "a client from the token" sh -c 'printf "%s\n" "$1" | '"$J"' wireguard join home --token-file - --endpoint 127.0.0.1:51820 --address 10.97.0.2/32 --allowed-ips 10.97.1.0/24' sh "$token"
	expect "the client's interface says what it is" 'description: jailops wireguard=home' ifconfig wg-home
	# a handshake starts with the first packet into the tunnel (or at the first keepalive, 25 s later): route the allowed
	# network into the client's interface (the route goes with the interface) and send a packet each try; no answer is needed
	route -n add -net 10.97.1.0/24 -interface wg-home >/dev/null 2>&1 || true
	n=0; wg_hs=full
	until $wgbin show wg-home latest-handshakes | grep -Eq '[[:space:]][1-9][0-9]+$'; do
		n=$((n + 1))
		# On some CI machines the reply of the server never reaches the client socket on the loopback address (the server
		# counts bytes received from and sent to the client, the client received none), though the server did what a
		# server does: it received a valid initiation from the peer's key and answered it. After 20 s that counts, with a note.
		if [ $n -gt 20 ] && [ "$($wgbin show wg-office transfer | awk '$3 > 0 {s += $3} END {print s + 0}')" -gt 0 ]; then
			wg_hs=answered
			echo "NOTE: the server of the tunnel received the client's initiation and answered it; the answer did not reach the client on this machine's loopback, so no handshake completed"
			$wgbin show wg-office >&2; $wgbin show wg-home >&2
			break
		fi
		if [ $n -gt 90 ]; then # a slow CI machine: ninety tries, and what both ends know when it still fails
			for w in wg-office wg-home; do $wgbin show $w >&2; done
			netstat -rn -f inet | grep -E '10\.9[78]\.' >&2 || true
			sockstat -4 -l | grep 51820 >&2 || true
			fail "a handshake between the two (none after 90 s)"
		fi
		ping -c 1 -t 1 10.97.1.1 >/dev/null 2>&1 || true
		sleep 1 # sleep-ok: poll of a condition
	done
	echo "OK: the tunnel between the two answers"
	if [ $wg_hs = full ]; then
		expect "the server reports it" 'laptop .* ago' $J wireguard status office
	else # the client never got the answer: the server lists the peer, with what it received from it and no handshake
		expect "the server lists the peer and what it received" 'laptop .* never +[0-9.]+ [KMG]?i?B / ' $J wireguard status office
	fi
	if $J doctor 2>&1 | grep -E ' FAIL '; then fail "doctor reports a failing check with tunnels"; fi
	check "delete the client" $J wireguard delete -y home
	check "delete the server" $J wireguard delete -y office
	if ifconfig wg-home >/dev/null 2>&1 || ifconfig wg-office >/dev/null 2>&1; then fail "a tunnel interface is still there"; fi
	[ ! -e /var/db/jailops-priv/wireguard/office ] || fail "the keys of a deleted tunnel are still there"
fi

step "ZFS delegation (a dataset of its own for a jail: jailed, attached by jail(8), managed from inside)"
# The operator allows it in priv.conf (admin-zfs-delegation); the daemon runs as a global administrator here.
deleg_orig="$work/priv.conf.deleg"
cp -p /usr/local/etc/jailops/priv.conf "$deleg_orig"
echo 'admin-zfs-delegation = true' >> /usr/local/etc/jailops/priv.conf
check "jailops_priv checkconfig with admin-zfs-delegation" service jailops_priv checkconfig
check "restart jailops_priv" service jailops_priv restart
check "restart jailopsd" service jailopsd restart
n=0; until $J host show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
dc="$pool/jailops/projects/demo/jails/deleg"
check "a jail with zfs delegation" $J create deleg --project demo --image "$img" --network lan --storage default --zfs-delegation --disk 20GiB --start
dds=$(zfs list -H -o name -r "$pool/jailops/projects/demo/jails/deleg" | grep '/delegated$' | head -n 1)
[ -n "$dds" ] || fail "the jail has no delegated dataset"
expect "the delegated dataset is jailed" '^on$' zfs get -H -o value jailed "$dds"
expect "the host does not mount it" '^no$' zfs get -H -o value mounted "$dds"
# zfs.dataset is resolved by jail(8) itself (a pseudo-parameter, not a kernel parameter): jls does not know it; the
# attachment is shown by what the jail's own zfs sees below
check "the jail's devfs holds /dev/zfs" $J exec --project demo deleg -- test -c /dev/zfs
expect "the jail's devfs holds no disk node" '^0$' sh -c "$J exec --project demo deleg -- ls /dev | grep -c -E '^(vtbd|ada|da|nvd|nda)[0-9]' || true"
if $J exec --project demo deleg -- test -x /sbin/zfs; then
	expect_retry "the jail's zfs sees the dataset" "$dds" $J exec --project demo deleg -- /sbin/zfs list -H -o name
	check "the jail creates a dataset below it" $J exec --project demo deleg -- /sbin/zfs create "$dds/inner"
	check "the jail snapshots it" $J exec --project demo deleg -- /sbin/zfs snapshot "$dds/inner@from-the-jail"
	expect "the host sees what the jail made" "$dds/inner@from-the-jail" zfs list -H -t all -o name -r "$dds"
else
	echo "note: the image has no /sbin/zfs; the checks that run zfs inside the jail are skipped" >&2
fi
if $J doctor 2>&1 | grep -E ' FAIL .*jail\.delegation'; then fail "doctor fails jail.delegation"; fi
check "a snapshot of the jail" $J jail snapshot create deleg delegsnap --project demo
expect "the snapshot took the delegated dataset along" "^$dds@delegsnap\$" zfs list -H -t snapshot -o name "$dds@delegsnap"
check "stop the jail" $J stop deleg --project demo
expect "the dataset stays jailed after the stop" '^on$' zfs get -H -o value jailed "$dds"
check "delete the jail" $J delete --confirm-data-loss deleg --project demo
if zfs list -H -o name "$dds" >/dev/null 2>&1; then fail "the delegated dataset is still there after the jail was deleted"; fi
cp -p "$deleg_orig" /usr/local/etc/jailops/priv.conf
check "restart jailops_priv" service jailops_priv restart
check "restart jailopsd" service jailopsd restart
n=0; until $J host show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done

step "volumes (owner and mode, nullfs into two jails, delete keeps the volume, snapshots)"
check "a volume owned by 5000:5000 with mode 0770" $J volume create maildir --project demo --storage default --uid 5000 --gid 5000 --mode 0770
vol=$pool/jailops/projects/demo/volumes/maildir
vmp=$(zfs get -H -o value mountpoint "$vol")
expect "its root has the owner and the mode" '^5000:5000 770$' sh -c "stat -f '%u:%g %Lp' $vmp"
expect "devices are off on its dataset" '^off$' zfs get -H -o value devices "$vol"
check "a jail attaches it at creation" $J create mail --project demo --image "$img" --network lan --storage default
check "attach maildir to mail" $J volume attach mail maildir /var/mail/vhosts --project demo
check "a second jail attaches it later" $J create desktop --project demo --image "$img" --network lan --storage default
check "attach to the second jail" $J volume attach desktop maildir /home/ann/Mail --project demo
expect "the volume says it is writable in two jails" 'writable in more than one jail' $J volume show maildir --project demo
check "start mail" $J start mail --project demo
expect_refused "a running jail does not detach a volume" $J volume detach mail maildir --project demo
expect "the jail sees the owner and the mode" '^5000:5000 770$' $J exec --project demo mail -- stat -f '%u:%g %Lp' /var/mail/vhosts
check "write a file in the volume" $J exec --project demo mail -- sh -c 'echo mail-1 > /var/mail/vhosts/m1'
check "start desktop" $J start desktop --project demo
expect "the second jail reads the same file" '^mail-1$' $J exec --project demo desktop -- cat /home/ann/Mail/m1
expect "the volume mount is a nullfs mount" 'volumes/maildir on .*nullfs' mount -t nullfs
expect "a volume that is attached is not deleted" 'busy|attached' sh -c "$J volume delete maildir --project demo --confirm-data-loss 2>&1; true"
check "stop both" $J stop mail desktop --project demo
if mount -t nullfs | grep -q "volumes/maildir"; then fail "a nullfs mount of the volume is left after the jails stopped"; fi
check "a snapshot of the volume" $J volume snapshot create maildir before --project demo
check "a jail snapshot leaves the volume alone" $J jail snapshot create mail js1 --project demo
if zfs list -H -t snapshot -o name "$vol@js1" >/dev/null 2>&1; then fail "a jail snapshot reached a volume"; fi
check "delete the jail" $J delete --confirm-data-loss mail --project demo
zfs list "$vol" >/dev/null 2>&1 || fail "deleting a jail destroyed the volume"
expect "the file is still there" '^mail-1$' cat "$vmp/m1"
check "detach from the second jail" $J volume detach desktop maildir --project demo
check "rename the volume" $J volume rename maildir mailbox --project demo -y
zfs list "${vol%maildir}mailbox" >/dev/null 2>&1 || fail "the dataset of the renamed volume is not there"
expect "the file moved with it" '^mail-1$' cat "${vmp%maildir}mailbox/m1"
check "rename it back" $J volume rename mailbox maildir --project demo -y
check "delete that jail" $J delete --confirm-data-loss desktop --project demo
check "the volume is deleted when nothing attaches it" $J volume delete maildir --project demo --confirm-data-loss
if zfs list "$vol" >/dev/null 2>&1; then fail "the volume is still there"; fi

step "a project with volumes is not deleted; a restart of the daemon starts no jail an operator stopped"
check "a project that holds a volume" sh -c "$J project create vkeep && $J storage grant default --project vkeep"
check "its volume" $J volume create precious --project vkeep
expect_refused "a project with a volume is not deleted" $J project delete vkeep -y
zfs list "$pool/jailops/projects/vkeep/volumes/precious" >/dev/null 2>&1 || fail "the refused delete destroyed the volume"
check "the volume goes first" $J volume delete precious --project vkeep --confirm-data-loss
check "then the project" $J project delete vkeep -y
check "a jail that starts at boot" $J create asj --project demo --image "$img" --network lan --storage default --start --autostart
check "an operator stops it for maintenance" $J stop asj --project demo
check "the daemon restarts" service jailopsd restart
waitfor "the daemon answers" 60 $J host show
sleep 6 # sleep-ok: the first reconcile pass of the new daemon runs within seconds; nothing is announced when it finds no jail to start
if jls -h name | grep -qx demo_asj; then fail "a restart of the daemon started a jail with boot.autostart that was stopped on purpose"; fi
check "delete it" $J delete --confirm-data-loss asj --project demo

step "an encrypted volume (passphrase from a file, lock, a refused start, a wrong and the right passphrase)"
# The volume is a ZFS encryption root; its passphrase goes from the file to the daemon and the helper and reaches zfs on
# standard input. A pool without the encryption feature skips this block and says so.
enc_state=$(zpool get -H -o value feature@encryption "$pool" 2>/dev/null || true)
case $enc_state in
enabled | active)
	(umask 077; printf '%s\n' 'ci-passphrase-0123' >"$work/vault.pass"; printf '%s\n' 'ci-wrong-passphrase' >"$work/wrong.pass"
		printf '%s\n' 'ci-new-passphrase-4567' >"$work/new.pass")
	check "an encrypted volume" $J volume create secrets --project demo --storage default --encrypted --passphrase-file "$work/vault.pass"
	check "a jail is made for it" $J create vault --project demo --image "$img" --network lan --storage default --autostart
	check "the jail attaches it" $J volume attach vault secrets /var/db/secrets --project demo
	check "the jail starts" $J start vault --project demo
	expect "the boot plan says the encrypted jail waits for its passphrase" 'vault[[:space:]]+waits for the passphrase' $J boot
	vds=$pool/jailops/projects/demo/volumes/secrets
	zfs list -H -o name "$vds" >/dev/null 2>&1 || fail "no dataset for the encrypted volume"
	keystatus() { zfs get -H -o value keystatus "$vds"; }
	expect "the key is loaded after the creation" '^available$' keystatus
	expect "aes-256-gcm under a passphrase typed at a prompt" '^aes-256-gcm,passphrase,prompt$' sh -c "zfs get -H -o value encryption,keyformat,keylocation $vds | paste -s -d , -"
	expect "the volume is its own encryption root" "^$vds\$" zfs get -H -o value encryptionroot "$vds"
	check "a file on the encrypted volume" $J exec --project demo vault -- sh -c 'echo ci-secret > /var/db/secrets/s'
	check "lock (stops the jail)" $J volume lock secrets --project demo
	expect "the key is unloaded" '^unavailable$' keystatus
	expect "the jail is locked" 'vault +locked' $J jail list --project demo
	expect "a start is refused with locked" '(^|[^_])locked' sh -c "$J start vault --project demo 2>&1; true"
	expect_refused "the start failed" $J start vault --project demo
	expect "a wrong passphrase is refused" 'bad_passphrase' sh -c "$J volume unlock secrets --project demo --passphrase-file $work/wrong.pass 2>&1; true"
	expect "still locked" '^unavailable$' keystatus
	check "unlock with the right passphrase" $J volume unlock secrets --project demo --passphrase-file "$work/vault.pass"
	expect "the key is loaded" '^available$' keystatus
	check "start" $J start vault --project demo
	expect "the file is read back" '^ci-secret$' $J exec --project demo vault -- cat /var/db/secrets/s
	check "change the passphrase" $J volume passphrase secrets --project demo --passphrase-file "$work/vault.pass" --new-passphrase-file "$work/new.pass"
	check "lock again" $J volume lock secrets --project demo
	expect_refused "the old passphrase opens it no more" $J volume unlock secrets --project demo --passphrase-file "$work/vault.pass"
	check "the new one does" $J volume unlock secrets --project demo --passphrase-file "$work/new.pass"
	expect "doctor checks the pool feature" 'volumes.encryption +PASS' $J doctor
	if grep -rq 'ci-passphrase-0123\|ci-new-passphrase-4567' /var/log/messages /var/db/jailops 2>/dev/null; then fail "a passphrase reached a log or the daemon's files"; fi
	expect "a delete shows the sizes and the snapshots read from ZFS" 'vault \([a-z]+\): root [0-9.]+ [KMGT]?i?B, data [0-9.]+ [KMGT]?i?B, [0-9]+ snapshots?; its volumes stay: secrets' $J --dry-run delete vault --project demo
	expect "-y does not answer the data-loss question" 'confirmation required' sh -c "$J delete -y vault --project demo </dev/null 2>&1; true"
	check "delete the jail" $J delete --confirm-data-loss vault --project demo
	zfs list "$vds" >/dev/null 2>&1 || fail "deleting the jail destroyed the encrypted volume"
	check "delete the volume" $J volume delete secrets --project demo --confirm-data-loss
	if zfs list "$vds" >/dev/null 2>&1; then fail "the encrypted volume is still there"; fi
	rm -f "$work/vault.pass" "$work/wrong.pass" "$work/new.pass"
	;;
*) echo "SKIP: encrypted volume: feature@encryption of pool $pool is ${enc_state:-unknown}, not enabled or active" ;;
esac

step "host directories as volumes (a mount below admin-host-mount: made, attached, watched, lost, given back)"
# The storage box is a UFS file system on md(4) behind gnop(8), mounted at /mnt/e2ebox/share, below the approved directory
# /mnt/e2ebox. A box that fails is what a failing gnop provider makes: the first write that cannot reach the device has
# UFS unmount the file system by force, and the nullfs mounts on it go with it, leaving the empty directory the mount
# was on. That is how a lost share looks to a jail (a ZFS dataset is a poor model: it is busy while nullfs sits on it).
hd_orig="$work/priv.conf.hostdir"
cp -p /usr/local/etc/jailops/priv.conf "$hd_orig"
kldload -n geom_nop || fail "geom_nop is not available"
mkdir -p /mnt/e2ebox/share
hd_img=$work/e2ebox.img
truncate -s 64m "$hd_img"
hd_md=$(mdconfig -a -t vnode -f "$hd_img")
check "gnop over the md device" gnop create "/dev/$hd_md"
newfs -U "/dev/$hd_md.nop" >/dev/null 2>&1 || fail "newfs of the stand-in for the storage box"
box_up() { fsck_ffs -y "/dev/$hd_md.nop" >/dev/null 2>&1 || true; mount "/dev/$hd_md.nop" /mnt/e2ebox/share; }
# a repaired file system of a failed device keeps nothing it had not written before (fsck is free to drop it), so what a
# box that is back "has" is written again: the check is that the jails see the box that is there now
box_back() { box_up && mkdir -p /mnt/e2ebox/share/backups && echo from-box > /mnt/e2ebox/share/backups/f1; }
box_up || fail "mounting the stand-in for the storage box"
mkdir -p /mnt/e2ebox/share/backups
echo 'admin-host-mount = /mnt/e2ebox' >> /usr/local/etc/jailops/priv.conf
check "jailops_priv checkconfig with admin-host-mount" service jailops_priv checkconfig
check "restart jailops_priv" service jailops_priv restart
check "restart jailopsd" service jailopsd restart
n=0; until $J host show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
mkdir -p /mnt/e2ebox/local
expect_refused "the approved directory itself is not a mount point below it" $J volume create bad --project demo --path /mnt/e2ebox
expect_refused "a directory of the host's own disk is not a volume" $J volume create bad --project demo --path /mnt/e2ebox/local
expect_refused "a directory outside the approved one is not a volume" $J volume create bad --project demo --path /etc
expect_refused "a size does not belong to a host directory" $J volume create bad --project demo --path /mnt/e2ebox/share/backups --size 1G
expect_refused "on-loss needs a watch" $J volume create bad --project demo --path /mnt/e2ebox/share/backups --on-loss stop
check "a volume of the directory, watched, stopping its jails when the mount is lost" $J volume create box --project demo --path /mnt/e2ebox/share/backups --watch --probe write --on-loss stop
check "a second volume of it that leaves the jails running" $J volume create box2 --project demo --path /mnt/e2ebox/share/backups --watch --probe write
expect "the volume is on its mount" 'State: +ok' $J volume show box --project demo
if zfs list -H -o name -r "$pool/jailops/projects/demo/volumes" 2>/dev/null | grep -Eq '/(box|box2)$'; then fail "a host directory got a dataset"; fi
expect_refused "a host directory has no snapshots" $J volume snapshot create box before --project demo
check "a jail attaches it" $J create hd1 --project demo --image "$img" --network lan --storage default
check "the attachment" $J volume attach hd1 box /srv/backups --project demo
check "a second jail attaches the other volume" $J create hd2 --project demo --image "$img" --network lan --storage default
check "its attachment" $J volume attach hd2 box2 /srv/b2 --project demo
check "start both" $J start hd1 hd2 --project demo
expect "the mount is a nullfs mount of the directory" '/mnt/e2ebox/share/backups on .*nullfs' mount -t nullfs
check "hd1 writes into the directory" $J exec --project demo hd1 -- sh -c 'echo from-hd1 > /srv/backups/f1'
expect "the file is on the box" '^from-hd1$' cat /mnt/e2ebox/share/backups/f1
expect "hd2 sees the same file" '^from-hd1$' $J exec --project demo hd2 -- cat /srv/b2/f1
sync; sync # what was written has reached the device before it fails
# the box fails: every read and write to the device fails from now on; a write makes UFS unmount it by force
check "the box fails" gnop configure -r 100 -w 100 "$hd_md.nop"
$J exec --project demo hd1 -- sh -c 'echo more > /srv/backups/f2; sync' >/dev/null 2>&1 || true
n=0; while mount | grep -q "/dev/$hd_md.nop on /mnt/e2ebox/share"; do n=$((n + 1)); [ $n -gt 15 ] && fail "the failed box is still mounted"; sleep 2; done
# the daemon looks every 15 s
expect_retry "the volume is lost" 'State: +lost' $J volume show box --project demo
expect_retry "the other volume is lost too" 'State: +lost' $J volume show box2 --project demo
expect_retry "doctor fails volume.hostdirs" 'volume\.hostdirs +FAIL' sh -c "$J doctor 2>&1; true"
expect_refused_retry "on-loss stop stopped hd1" sh -c "jls -h name | grep -qx demo_hd1"
check "hd2 keeps running (on-loss none)" sh -c "jls -h name | grep -qx demo_hd2"
expect_refused "a jail does not start on the empty directory the mount left behind" $J start hd1 --project demo
if [ -n "$(ls -A /mnt/e2ebox/share 2>/dev/null)" ]; then fail "the directory of the lost mount is not empty"; fi
check "hd2 can still be stopped (its nullfs mounts went with the box)" $J stop hd2 --project demo
if mount -t nullfs | grep -q "/mnt/e2ebox/share/backups"; then fail "a nullfs mount of the host directory is left after the jails stopped"; fi
expect_refused "hd2 does not start while the box is lost" $J start hd2 --project demo
check "the box is repaired" gnop configure -r 0 -w 0 "$hd_md.nop"
box_back || fail "the box is not mounted again"
expect_retry "the volume is on its mount again" 'State: +ok' $J volume show box --project demo
if $J doctor 2>&1 | grep -E 'volume\.hostdirs +FAIL'; then fail "doctor still fails volume.hostdirs with the mount back"; fi
check "hd1 starts again" $J start hd1 hd2 --project demo
expect "hd1 sees the box that is back" '^from-box$' $J exec --project demo hd1 -- cat /srv/backups/f1
expect "hd2 sees it too" '^from-box$' $J exec --project demo hd2 -- cat /srv/b2/f1
# the box fails again while hd2 runs on it with on-loss none, and returns: the daemon gives hd2 its mount again
check "the box fails again" gnop configure -r 100 -w 100 "$hd_md.nop"
$J exec --project demo hd2 -- sh -c 'echo again > /srv/b2/f3; sync' >/dev/null 2>&1 || true
n=0; while mount | grep -q "/dev/$hd_md.nop on /mnt/e2ebox/share"; do n=$((n + 1)); [ $n -gt 15 ] && fail "the failed box is still mounted"; sleep 2; done
expect_retry "the volume is lost again" 'State: +lost' $J volume show box2 --project demo
check "hd2 is still running with on-loss none" sh -c "jls -h name | grep -qx demo_hd2"
check "the box is repaired again" gnop configure -r 0 -w 0 "$hd_md.nop"
box_back || fail "the box is not mounted again"
expect_retry "the volume is on its mount again" 'State: +ok' $J volume show box2 --project demo
expect_retry "the running jail has its mount again and sees the file" '^from-box$' $J exec --project demo hd2 -- cat /srv/b2/f1
check "stop both" $J stop hd1 hd2 --project demo
if mount -t nullfs | grep -q "/mnt/e2ebox/share/backups"; then fail "a nullfs mount of the host directory is left after the jails stopped"; fi
check "detach" $J volume detach hd1 box --project demo
check "detach the other" $J volume detach hd2 box2 --project demo
check "delete the volume" $J volume delete box --project demo --confirm-data-loss
check "delete the other" $J volume delete box2 --project demo --confirm-data-loss
expect "deleting a volume of a directory leaves the files" '^from-box$' cat /mnt/e2ebox/share/backups/f1
check "delete the jails" $J delete hd1 hd2 --project demo --confirm-data-loss
umount -f /mnt/e2ebox/share || true
gnop destroy -f "$hd_md.nop" || true
mdconfig -d -u "$hd_md" -o force || true
rm -f "$hd_img"
cp -p "$hd_orig" /usr/local/etc/jailops/priv.conf
check "restart jailops_priv" service jailops_priv restart
check "restart jailopsd" service jailopsd restart
n=0; until $J host show >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done

step "OS upgrade of a thin jail (new generation, /etc merge, health check, root rollback)"
expect "a second jail takes the project's only network and storage, and says so" 'network lan: the only network of project demo' $J create up --project demo --image "$img" --start
check "a second generation of the image" $J image build "$img" --from-generation g1
check "a file that must survive" $J exec --project demo up -- sh -c 'echo ci-keep > /root/keep'
expect "dry run" 'g1 to g2' $J jail upgrade up --project demo --dry-run
check "upgrade to the newer generation" $J jail upgrade up --project demo --generation g2
expect "the jail is on the second generation" 'up +running.*#g2' $J jail list --project demo
expect "the jail still runs" 'FreeBSD' $J exec --project demo up -- uname -s
expect "its data survived the swap" 'ci-keep' $J exec --project demo up -- cat /root/keep
expect "bash survived the swap (/usr/local is persistent)" '^bash$' $J exec --project demo up -- /usr/local/bin/bash -c 'echo bash'
expect "so did the prompt" '38;5;39m' in_pty up /usr/local/bin/bash -ic 'echo "$PS1"'
check "root rollback" $J jail rollback up --project demo
expect "back on the first generation" 'up +running.*#g1' $J jail list --project demo
check "stop the second jail" $J stop up --project demo

step "devices: a jail given a device mounts a private devfs ruleset that is loaded, and sees no disk"
upnode=$mount/projects/demo/jails/up/root/dev
# ruleset 5032 is DevfsRulesetBase (5000) plus the bit of tun (32); a number nobody loaded would show the jail the host's whole /dev
check "give the second jail a device" $J config set --project demo up devfs.tun.device tun
check "start the jail that has a device" $J start up --project demo
check_retry "its private devfs ruleset is in the kernel" sh -c "devfs rule showsets | tr -s ' ' '\n' | grep -qx 5032"
check "the ruleset holds the device it was given" sh -c "devfs rule -s 5032 show | grep -q 'tun'"
check_retry "the jail's /dev has no disk node" sh -c "[ \"\$(ls $upnode | grep -c -E '^(vtbd|ada|da|nvd|nda)[0-9]')\" = 0 ]"
check "the jail's /dev is the jail's, not the host's" sh -c "[ \"\$(ls $upnode | wc -l)\" -lt 30 ] && [ -c $upnode/null ]"
check "stop the jail again" $J stop up --project demo
check "take the device away again" $J config unset --project demo up devfs.tun.device

step "automatic upgrade of an image (the nightly run, started by the clock of the daemon)"
expect "the nightly upgrade is off until it is asked for" 'Nightly: +off' $J image show "$img"
expect_refused "a time of day that does not exist is refused" $J image set "$img" --auto-upgrade --upgrade-at 25:00
# the jail `up` is on the first generation while the newest is the second (the rollback above), and it gets a package
# that is behind: the nightly run must move it and upgrade the package, though the repository has nothing new for the image
check "start the second jail" $J start up --project demo
check_net "refresh the package catalogue of the second jail" pkg -j demo_up update -q
check_net "install a package into the second jail" pkg -j demo_up install -y nano
check "make that package look old" pkg -j demo_up shell "UPDATE packages SET version = '0.1' WHERE name = 'nano';"
expect "the package is behind" '^0\.1$' pkg -j demo_up query %v nano
check "turn it on for two minutes from now" $J image set "$img" --auto-upgrade --upgrade-at "$(date -v+2M +%H:%M)"
expect "the image names it and its next run" 'Nightly: +every night at [0-9:]+: generation and jails and their packages; next ' $J image show "$img"
n=0
until $J image show "$img" | grep -q 'Automatic upgrades'; do
	n=$((n + 1)); [ $n -gt 150 ] && fail "the automatic upgrade did not run within five minutes"; sleep 2
done
expect "the run moved the two jails that were behind and upgraded the package" ' ok +2 moved, 1 packages upgraded' $J image show "$img"
expect "the second jail is on the newest generation" 'up +running.*#g2' $J jail list --project demo
if [ "$(pkg -j demo_up query %v nano)" = 0.1 ]; then fail "the package of the second jail was not upgraded"; fi
expect "the second jail still runs" 'FreeBSD' $J exec --project demo up -- uname -s
check "stop the second jail again" $J stop up --project demo
if $J image show "$img" | grep -E '^ +[0-9-]+ [0-9:]+ +failed'; then fail "the automatic upgrade failed"; fi
check "turn it off" $J image set "$img" --auto-upgrade=false
expect "off again" 'Nightly: +off' $J image show "$img"

step "an app from the catalog (nginx: thin jail, pkg -r from the host, rc.conf, service, health check, snapshot)"
# the catalog is a directory of local files: the reference copy (or JAILOPS_E2E_CATALOG), copied where the daemon may read it
appdir=$work/apps
catalog=${JAILOPS_E2E_CATALOG:-internal/apps/testdata/catalog}
[ -d "$catalog" ] || fail "JAILOPS_E2E_CATALOG: $catalog is not a directory"
rm -rf "$appdir"; cp -R "$catalog" "$appdir"; chmod -R a+rX "$appdir"
cat >> /usr/local/etc/jailops/jailopsd.yaml <<YAML
apps:
  catalog_dir: $appdir
YAML
check "restart jailopsd with the catalog" service jailopsd restart
n=0; until $J app list >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
expect "the catalog lists nginx as valid" '^nginx .*valid' $J app list -o wide
expect "a dry run lists the steps" 'install-packages-ports: pkg -r .* install -y nginx' $J app install nginx --project demo --network lan --storage default --dry-run
expect "an app's jail gets bash and the prompt like any new jail" 'set-up-shell: install bash' $J app install nginx --project demo --network lan --storage default --dry-run
check "install nginx" $J app install nginx --project demo --network lan --storage default
expect "the app's jail has bash as its shell" '^/usr/local/bin/bash$' $J config get --project demo nginx shell
check "bash is in the app's jail" test -x "$mount/projects/demo/jails/nginx/root/usr/local/bin/bash"
check "the prompt is in the app's jail" grep -F -q "PS1='" "$mount/projects/demo/jails/nginx/root/usr/local/etc/profile.d/jailops-prompt.sh"
expect "the jail runs and carries the labels" 'jailops.app=nginx' $J label --project demo nginx
expect "the app is listed as installed" 'nginx +nginx +[^ ]+ +running' $J app installed --project demo
addr=$($J app installed --project demo | awk '$1 == "nginx" {print $5}' | head -1 | cut -d, -f1)
[ -n "$addr" ] || fail "no address for the nginx jail"
# an installed app is closed, to the host too, until a source is allowed
expect_refused_retry "a fresh app is closed to the host" curl -sS --max-time 3 "http://$addr/"
expect "the closed app has no grant" 'No grants' $J app access nginx --project demo
check "allow the host to reach nginx" $J app allow nginx --from host --project demo
expect_retry "nginx answers from the host" 'Welcome to nginx' curl -sS --max-time 5 "http://$addr/"
expect "the grant is listed" '^host \(host\)' $J app access nginx --project demo
expect "the service is enabled in the jail's rc.conf" 'nginx_enable="YES"' $J exec --project demo nginx -- cat /etc/rc.conf
expect "the snapshot of the fresh installation exists" 'app-installed' $J jail snapshot list nginx --project demo
# the authoring path: a draft of the running jail has its package, its service and its port, and still carries TODO markers
$J app export nginx --project demo --file "$work/nginx-draft.yaml" >"$work/export.out" 2>&1 || { cat "$work/export.out" >&2; fail "export a draft of the nginx jail"; }
expect "-o json prints the draft as data" '"definition"' $J app export nginx --project demo -o json
grep -q 'name: nginx' "$work/nginx-draft.yaml" || { cat "$work/nginx-draft.yaml" >&2; fail "the draft names the nginx package"; }
grep -q 'port: 80' "$work/nginx-draft.yaml" || { cat "$work/nginx-draft.yaml" >&2; fail "the draft has port 80"; }
grep -q 'TODO' "$work/nginx-draft.yaml" || fail "the draft has TODO markers"
if $J app validate "$work/nginx-draft.yaml" >"$work/validate.out" 2>&1; then fail "validate accepts a draft with TODO markers"; fi
grep -q 'replace TODO' "$work/validate.out" || { cat "$work/validate.out" >&2; fail "validate names the TODO lines"; }
if ! $J stop nginx --project demo >"$work/stop.out" 2>&1; then # show what holds the root when the unmount stays busy
	cat "$work/stop.out" >&2
	echo "--- holders of the jail root:" >&2; fstat -f /jopsci/projects/demo/jails/nginx/root >&2 2>&1 || true
	echo "--- processes:" >&2; ps -axo pid,jid,etimes,command | grep -E 'nginx|syslogd|cron|jexec' | grep -v grep >&2 || true
	fail "stop the app jail"
fi

# one block per app of JAILOPS_E2E_APPS: install, the app's own check, the logs, stop
app_check() { # app_check NAME ADDRESS
	case $1 in
	postgresql)
		expect "postgresql answers a query" '^1$' $J exec --project demo postgresql -- su -l postgres -c "psql -tA -c 'select 1'"
		# it was installed under the limits its definition hints at (1G, one core) and runs under them
		[ "$racct" != 1 ] || {
			expect "the hinted memory limit is on the running jail" 'jail:demo_postgresql:swapuse:deny=1073741824' sh -c 'rctl 2>&1'
			expect "the hinted CPU limit is on the running jail" 'jail:demo_postgresql:pcpu:deny=100' sh -c 'rctl 2>&1'
			expect "an allocation far beyond the limit fails in the jail" 'out of (memory|space)' sh -c "$J exec --project demo postgresql -- /usr/bin/awk 'BEGIN{s=\"x\"; for(i=0;i<29;i++) s=s s; print length(s)}' 2>&1 | head -c 300; true"
			expect "postgresql answers after it" '^1$' $J exec --project demo postgresql -- su -l postgres -c "psql -tA -c 'select 1'"
		} ;;
	valkey) expect "valkey answers" '^PONG$' $J exec --project demo valkey -- /usr/local/bin/valkey-cli ping ;;
	prometheus) expect_retry "prometheus is ready" 'Ready' curl -sS --max-time 5 "http://$2:9090/-/ready" ;;
	forgejo) expect_retry "forgejo answers (the web installer or a redirect to it)" '^(200|302|303)$' curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://$2:3000/" ;;
	nsd) # the starter zone, from the host, over UDP and TCP
		expect_retry "nsd answers for example.com over UDP" 'IN[[:space:]]+SOA[[:space:]]+ns1\.example\.com\.' drill @"$2" example.com SOA
		expect "nsd answers for example.com over TCP" 'IN[[:space:]]+SOA[[:space:]]+ns1\.example\.com\.' drill -t @"$2" example.com SOA
		check "the configuration passes nsd-checkconf" $J exec --project demo nsd -- /usr/local/sbin/nsd-checkconf /usr/local/etc/nsd/nsd.conf ;;
	mail) # the greetings: the command is sent after a second, Postfix refuses commands that arrive before its greeting
		expect_retry "postfix greets on port 25" '^220 ' sh -c "(sleep 1; printf 'QUIT\r\n') | nc -w 5 $2 25"
		expect "dovecot greets on port 143" '^\* OK' sh -c "(sleep 1; printf 'a1 LOGOUT\r\n') | nc -w 5 $2 143"
		expect "mailer.conf hands /usr/sbin/sendmail to postfix" '^sendmail[[:space:]]+/usr/local/sbin/sendmail$' $J exec --project demo mail -- cat /usr/local/etc/mail/mailer.conf ;;
	isms) isms_check "$2" ;;
	esac
}
isms_check() { # isms_check ADDRESS: the steps of the definition's notes with a postgresql jail of its own, then HTTP
	check "install postgresql for isms" $J app install postgresql isms-db --project demo --network lan --storage default
	db=$($J app installed --project demo | awk '$1 == "isms-db" {print $5}' | head -1 | cut -d, -f1)
	[ -n "$db" ] || fail "no address for the isms-db jail"
	# the role, the database, the pg_hba.conf line, listen_addresses and the firewall rule, in one allow; the
	# connection string is in its answer only (never printed here: it holds the password)
	$J app allow isms-db --from jail:isms --db isms --project demo -o json >"$work/isms-allow.json" 2>&1 || { sed 's/postgres:\/\/[^@]*@/postgres:\/\/***@/' "$work/isms-allow.json" >&2; fail "allow isms to reach isms-db"; }
	url=$(json_field connection_string <"$work/isms-allow.json")
	rm -f "$work/isms-allow.json"
	case $url in "postgres://isms:"*"@$db:5432/isms?sslmode=disable") ;; *) fail "app allow printed no connection string for isms" ;; esac
	env=/usr/local/etc/isms/server.env
	check "server.env: database, base URL, signing address" $J exec --project demo isms -- sh -c "sed -i '' \
		-e 's|^DATABASE_URL=.*|DATABASE_URL=\"$url\"|' \
		-e 's|^ISMS_BASE_URL=.*|ISMS_BASE_URL=http://$1:8080|' -e 's|^ISMS_SIGNING_EMAIL=.*|ISMS_SIGNING_EMAIL=e2e@example.com|' $env"
	check "server.env: the master secret" $J exec --project demo isms -- sh -c "sed -i '' \"s|^ISMS_SECRET=.*|ISMS_SECRET=\$(openssl rand -hex 32)|\" $env"
	check "server.env: owner and mode" $J exec --project demo isms -- sh -c "chown isms:isms $env && chmod 600 $env"
	check "the signing key" $J exec --project demo isms -- su -m isms -c '/usr/local/bin/ssh-keygen -q -t ed25519 -N "" -C e2e@example.com -f /var/db/isms/private/isms_key'
	check "the schema" $J exec --project demo isms -- env ISMS_SERVER_ENV=$env su -m isms -c '/usr/local/bin/isms server migrate'
	check "start isms" $J exec --project demo isms -- service isms start
	# UNVERIFIED: port 8080 and what / answers; curl retries while the program starts
	expect "isms answers on port 8080" '^[23][0-9][0-9]$' curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --retry 30 --retry-connrefused --retry-delay 1 "http://$1:8080/"
	check "stop isms-db" $J stop isms-db --project demo
}
pg_access_check() { # postgresql-access: who may connect to a database, from the jails' side
	check "install postgresql as pgacc" $J app install postgresql pgacc --project demo --network lan --storage default
	for c in pgc1 pgc2; do
		check "create the client jail $c" $J create "$c" --project demo --image "$img" --network lan --storage default --start
		# the PostgreSQL client into the running thin jail, inside it, as package updates do
		check_net "psql in $c" pkg -j "demo_$c" install -y postgresql18-client
		check "the library cache of $c" $J exec --project demo "$c" -- /sbin/ldconfig -m /usr/local/lib
	done
	expect "a dry run shows the rule, the pg_hba line and the SQL without a password" 'CREATE ROLE "pgc1" LOGIN PASSWORD .<generated' \
		$J app allow pgacc --from jail:pgc1 --project demo --dry-run
	$J app allow pgacc --from jail:pgc1 --project demo -o json >"$work/pg-allow.json" 2>&1 || { sed 's/postgres:\/\/[^@]*@/postgres:\/\/***@/' "$work/pg-allow.json" >&2; fail "allow pgc1 to reach pgacc"; }
	url=$(json_field connection_string <"$work/pg-allow.json")
	rm -f "$work/pg-allow.json"
	case $url in postgres://pgc1:*@*:5432/pgc1?sslmode=disable) ;; *) fail "app allow printed no connection string for pgc1" ;; esac
	# a connection that the firewall drops must not wait for the default timeout
	url="$url&connect_timeout=3"
	expect_retry "pgc1 runs a query with the connection string" '^1$' $J exec --project demo pgc1 -- /usr/local/bin/psql "$url" -tAc 'select 1'
	expect_refused "pgc2 (not allowed) cannot connect" $J exec --project demo pgc2 -- /usr/local/bin/psql "$url" -tAc 'select 1'
	expect "app access lists the grant with its pg_hba line" 'host pgc1 pgc1 [0-9.]+/32 scram-sha-256' $J app access pgacc --project demo
	expect "allowing again changes nothing and prints no password" 'may already reach' $J app allow pgacc --from jail:pgc1 --project demo
	expect "the source of a grant is not deleted: the rule names it" 'jailops app deny pgacc --from jail:pgc1' \
		sh -c "$J delete --stop --confirm-data-loss pgc1 --project demo 2>&1; true"
	check "deny pgc1" $J app deny pgacc --from jail:pgc1 --project demo
	expect_refused_retry "pgc1 cannot connect after the deny" $J exec --project demo pgc1 -- /usr/local/bin/psql "$url" -tAc 'select 1'
	expect "the grant is gone" 'No grants' $J app access pgacc --project demo
	url=
	for j in pgc1 pgc2 pgacc; do check "stop $j" $J stop "$j" --project demo; done
}
for a in $e2e_apps; do
	if [ "$a" = postgresql-access ]; then
		step "who may connect to a database (app allow and deny)"
		pg_access_check
		continue
	fi
	step "the app $a from the catalog"
	check "install $a" $J app install "$a" --project demo --network lan --storage default
	expect "$a is listed as installed" "^$a +$a +[^ ]+ +running" $J app installed --project demo
	addr=$($J app installed --project demo | awk -v a="$a" '$1 == a {print $5}' | head -1 | cut -d, -f1)
	[ -n "$addr" ] || fail "no address for the $a jail"
	# the checks that connect from the host need it allowed (postgresql and valkey are checked inside the jail)
	case $a in prometheus | forgejo | nsd | mail | isms) check "allow the host to reach $a" $J app allow "$a" --from host --project demo ;; esac
	app_check "$a" "$addr"
	expect "the log files of $a are listed" 'messages' $J jail logs "$a" --project demo
	check "stop $a" $J stop "$a" --project demo
done

step "backup node (PostgreSQL, the node, this host enrolled)"
if ! su -m postgres -c "psql -c 'select 1'" >/dev/null 2>&1; then # the CI VM has it running already
	pkg install -y postgresql17-server >/dev/null 2>&1 || pkg install -y postgresql16-server >/dev/null || fail "postgresql"
	sysrc postgresql_enable=YES >/dev/null
	service postgresql oneinitdb >/dev/null 2>&1 || true
	service postgresql onestart >/dev/null 2>&1 || { tail -n 20 /var/db/postgres/data*/postgresql.log /var/db/postgres/*.log 2>/dev/null >&2; fail "postgresql does not start"; }
	n=0; until su -m postgres -c "psql -c 'select 1'" >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "postgresql does not answer"; sleep 1; done
fi
su -m postgres -c "dropdb --if-exists jopsnode; createdb jopsnode" || fail "createdb"
data=/var/db/jailops-backup
cat > /usr/local/etc/jailops/backupd.yaml <<YAML
hostname: ci-vault
listen: "127.0.0.1:39111"
admin_socket: /var/run/jailops-backupd/admin.sock
tls:
  cert_file: $data/backupd.crt
  key_file: $data/backupd.key
database:
  dsn: postgres://postgres@127.0.0.1:5432/jopsnode?sslmode=disable
datastore:
  kind: directory
  directory: $data/repository
web:
  enabled: false
YAML
chown root:jailops-backup /usr/local/etc/jailops/backupd.yaml; chmod 640 /usr/local/etc/jailops/backupd.yaml
install -d -m 0750 -o jailops-backup -g jailops-backup /var/run/jailops-backupd
init_out=$(su -m jailops-backup -c "/usr/local/sbin/jailops-backupd -c /usr/local/etc/jailops/backupd.yaml init" 2>&1) || { echo "$init_out" >&2; fail "backupd init"; }
echo "$init_out" | tail -3
nodefp=$(echo "$init_out" | sed -n 's/.*hosts pin this): *//p' | tr -d '[:space:]')
[ ${#nodefp} -eq 64 ] || fail "no node fingerprint in the init output"
# this host's client certificate, enrolled on the node
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /var/db/jailops/backup-client.key \
	-out /var/db/jailops/backup-client.crt -subj /CN=ci-host -days 30 >/dev/null 2>&1
chown jailops /var/db/jailops/backup-client.key /var/db/jailops/backup-client.crt; chmod 600 /var/db/jailops/backup-client.key
hostfp=$(openssl x509 -in /var/db/jailops/backup-client.crt -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
su -m jailops-backup -c "/usr/local/sbin/jailops-backupd -c /usr/local/etc/jailops/backupd.yaml hosts enroll ci-host --fingerprint $hostfp --scopes backup-push,backup-pull,restore" >/dev/null || fail "enroll"
sysrc jailops_backupd_enable=YES >/dev/null
check "backupd start" service jailops_backupd start
waitfor "the backup node writes its pid file" 60 test -s /var/run/jailops-backupd.pid
[ -s /var/run/jailops-backupd.pid ] || fail "the backup node's pid file is not in /var/run"
[ -z "$(find /var/run/jailops-backupd -type f)" ] || fail "regular files in /var/run/jailops-backupd"

step "the host backs up to the node"
cat >> /usr/local/etc/jailops/jailopsd.yaml <<YAML
backup:
  node:
    name: ci-vault
    address: 127.0.0.1:39111
    fingerprint: $nodefp
    cert_file: /var/db/jailops/backup-client.crt
    key_file: /var/db/jailops/backup-client.key
  allow_unescrowed: true
YAML
check "restart jailopsd" service jailopsd restart
n=0; until $J backup key status >/dev/null 2>&1; do n=$((n + 1)); [ $n -gt 30 ] && fail "the daemon does not answer after the restart"; sleep 1; done
expect "key created" 'JOR1-' $J backup key create
check "target" $J backup target create vault --url https://127.0.0.1:39111 --fingerprint "$nodefp"
check "policy" $J backup policy create nightly --project demo --schedule "0 3 * * *" --selector backup=yes --target vault --keep-last 3
expect "the backup runs" ' ok ' $J backup run --project demo nightly
id=$($J backup list --project demo --jail web -o name | head -1)
[ -n "$id" ] || fail "no backup is listed"
expect "deep verification" ' ok ' $J backup verify --project demo "$id"
expect "extract verification" ' ok ' $J backup verify --project demo "$id" --depth extract
expect "full verification (boots the backup as a jail of its own)" ' ok ' $J backup verify --project demo "$id" --depth full
if $J list --project demo -o name | grep -q '^jodrill-'; then fail "the restore test left its jail behind"; fi

step "restore as a new jail"
check "stop the original" $J stop web --project demo
expect "restore" 'restored' $J backup restore --project demo "$id" --as web-restored -y
check "start the restored jail" $J start web-restored --project demo

expect_retry "the file came back" 'ci-marker' $J exec --project demo web-restored -- cat /root/marker
expect_retry "its own address" '10\.77\.0\.' $J exec --project demo web-restored -- ifconfig -a

step "volumes in backups (one copy for several jails, --no-volumes, a lost volume comes back with the jail)"
check "a volume" $J volume create shared --project demo --storage default --uid 5001 --gid 5001 --mode 0770
check "the first jail attaches it" $J create vb1 --project demo --image "$img" --network lan --storage default
check "attach shared to vb1" $J volume attach vb1 shared /srv/shared --project demo
check "the second jail attaches it" $J create vb2 --project demo --image "$img" --network lan --storage default
check "attach shared to vb2" $J volume attach vb2 shared /srv/shared --project demo
check "label the first jail" $J label vb1 --project demo backup=vol
check "label the second jail" $J label vb2 --project demo backup=vol
# neither jail is ever started: their datasets are unmounted, and the volume is written from the host
shmp=$(zfs get -H -o value mountpoint "$pool/jailops/projects/demo/volumes/shared")
check "write a file in the volume from the host" sh -c "echo vol-1 > $shmp/f1"
check "a policy for the two jails" $J backup policy create vols --project demo --schedule "0 4 * * *" --selector backup=vol --target vault --keep-last 3
expect "the policy backs up both jails and the volume" ' ok ' $J backup run --project demo vols
vcount=$($J backup list --project demo --volume shared -o name | wc -l | tr -d ' ')
[ "$vcount" = 1 ] || fail "the volume has $vcount backups after one run with two jails attaching it, want exactly one"
expect "the list tells jail and volume backups apart" 'volume' $J backup list --project demo --volume shared
expect "a run without volumes" ' ok ' $J backup run --project demo vols --no-volumes
vcount=$($J backup list --project demo --volume shared -o name | wc -l | tr -d ' ')
[ "$vcount" = 1 ] || fail "a run with --no-volumes backed the volume up ($vcount backups)"
check "a policy that excludes volumes" $J backup policy create novols --project demo --schedule "0 5 * * *" --selector backup=vol --target vault --keep-last 3 --no-volumes
expect "its run is ok" ' ok ' $J backup run --project demo novols
vcount=$($J backup list --project demo --volume shared -o name | wc -l | tr -d ' ')
[ "$vcount" = 1 ] || fail "a policy with --no-volumes backed the volume up ($vcount backups)"
vbid=$($J backup list --project demo --jail vb1 -o name | head -1)
volid=$($J backup list --project demo --volume shared -o name | head -1)
[ -n "$vbid" ] && [ -n "$volid" ] || fail "the jail backup or the volume backup is not listed"
expect "the volume backup restores as a new volume" 'restored' $J backup restore --project demo "$volid" --as shared2 -y
v2mp=$(zfs get -H -o value mountpoint "$pool/jailops/projects/demo/volumes/shared2")
expect "its file came back" '^vol-1$' cat "$v2mp/f1"
expect "its root has the owner and the mode" '^5001:5001 770$' sh -c "stat -f '%u:%g %Lp' $v2mp"
expect_refused "a volume is never replaced" $J backup restore --project demo "$volid" --as shared2 -y
check "delete the first jail" $J delete --confirm-data-loss vb1 --project demo
check "detach from the second jail" $J volume detach vb2 shared --project demo
check "delete the second jail" $J delete --confirm-data-loss vb2 --project demo
check "lose the volume" $J volume delete shared --project demo --confirm-data-loss
expect "the preflight of the jail restore lists the volume" 'restores volume shared' $J backup restore --project demo "$vbid" --dry-run
expect "the jail restore brings the volume back first" 'restored' $J backup restore --project demo "$vbid" -y
smp=$(zfs get -H -o value mountpoint "$pool/jailops/projects/demo/volumes/shared")
expect "the volume has its file again" '^vol-1$' cat "$smp/f1"
expect "and its owner and mode" '^5001:5001 770$' sh -c "stat -f '%u:%g %Lp' $smp"
check "start the restored jail" $J start vb1 --project demo
expect "the jail sees the file" '^vol-1$' $J exec --project demo vb1 -- cat /srv/shared/f1
check "stop it" $J stop vb1 --project demo
expect "a restore without volumes" 'restored' $J backup restore --project demo "$vbid" --as vb3 --no-volumes -y
if $J jail show --project demo vb3 | grep -q 'shared'; then fail "a jail restored with --no-volumes attaches the volume"; fi
for j in vb1 vb3; do check "delete $j" $J delete --confirm-data-loss $j --project demo; done
for v in shared shared2; do check "delete volume $v" $J volume delete $v --project demo --confirm-data-loss; done

step "renames: a network with a running jail, a stopped jail, an image, a project (each renamed back)"
# a network: the running jail keeps its interfaces and its traffic; only names and descriptions change
expect "the plan lists the running jail's interfaces" 'interface .*jail=demo/web-restored net=office' $J network rename lan office --dry-run
check "rename the network while a jail on it runs" $J network rename lan office -y
expect "the running jail's host end carries the new name" 'description: jailops jail=demo/web-restored net=office \(host side\)' ifconfig -a
expect "the running jail's end, inside it" 'description: jailops jail=demo/web-restored net=office \(jail side\)' $J exec --project demo web-restored -- ifconfig -a
expect "the anchor of the network is loaded under the new name" 'match out on .* inet from 10\.77\.0\.0/24 .*nat-to' pfctl -a jailops/net.office -sr
expect_refused "the anchor of the old name is empty" sh -c "pfctl -a jailops/net.lan -sn 2>/dev/null | grep -q nat"
expect "the project's grant follows" 'office' $J project show demo
expect "the running jail still reaches the host" '1 packets received' $J exec --project demo web-restored -- ping -c1 -t3 10.77.0.1
gw=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
if [ -n "$gw" ]; then
	expect "and the host's gateway, through the NAT of the renamed network" '1 packets received' $J exec --project demo web-restored -- ping -c1 -t3 "$gw"
fi
# (doctor's exit status says more than descriptions: a failing check of the machine is not this block's business)
expect "doctor finds every description" 'net.descriptions +PASS' sh -c "$J doctor 2>&1; true"
check "rename it back" $J network rename office lan -y
expect "the old name is back" 'description: jailops jail=demo/web-restored net=lan \(host side\)' ifconfig -a
# a jail: refused while it runs, renamed when it is stopped, its datasets, mountpoints and kernel name follow
expect_refused "a running jail is not renamed" $J rename web-restored web-renamed --project demo -y
check "rename the stopped jail" $J rename web web-renamed --project demo -y
expect_refused "its old datasets are gone" zfs list "$pool/jailops/projects/demo/jails/web"
expect "its mountpoints moved" "^$mount/projects/demo/jails/web-renamed/root\$" zfs get -H -o value mountpoint "$pool/jailops/projects/demo/jails/web-renamed/root"
check "start it under the new name" $J start web-renamed --project demo
expect "the kernel knows it by the new name" '^demo_web-renamed$' jls -j demo_web-renamed name
expect "its file is there" 'ci-marker' $J exec --project demo web-renamed -- cat /root/marker
expect "its anchor" 'jailops/demo/web-renamed' pfctl -sA
check "stop it" $J stop web-renamed --project demo
check "and rename it back" $J rename web-renamed web --project demo -y
# an image: the generations move, the clones of running jails follow, the nightly runs move with it
check "rename the image while a jail on it runs" $J image rename "$img" e2e-img -y
expect "the jails follow" 'web-restored +running +e2e-img' $J jail list --project demo
expect "a thin root is a clone of the renamed generation" "^$pool/jailops/images/e2e-img/g[0-9]+@ro\$" zfs get -H -o value origin "$pool/jailops/projects/demo/jails/web-restored/root"
expect "the generations are mounted under the new name" "^$mount/images/e2e-img/g1\$" zfs get -H -o value mountpoint "$pool/jailops/images/e2e-img/g1"
expect "the nightly runs moved with it" 'Automatic upgrades' $J image show e2e-img
expect "the jail still runs" 'FreeBSD' $J exec --project demo web-restored -- uname -s
check "rename the image back" $J image rename e2e-img "$img" -y
# a project: every jail stopped, then the datasets, anchors and objects move
for j in $($J jail list --project demo -o name); do $J stop "$j" --project demo >/dev/null 2>&1 || true; done
check "rename the project" $J project rename demo e2e-proj -y
expect_refused "nothing is left under the old name" zfs list "$pool/jailops/projects/demo"
expect "the mountpoints moved" "^$mount/projects/e2e-proj/jails/web/root\$" zfs get -H -o value mountpoint "$pool/jailops/projects/e2e-proj/jails/web/root"
check "a jail starts in the renamed project" $J start web --project e2e-proj
expect "under its new kernel name" '^e2e-proj_web$' jls -j e2e-proj_web name
expect "with its anchor" 'jailops/e2e-proj/web' pfctl -sA
expect "and its file" 'ci-marker' $J exec --project e2e-proj web -- cat /root/marker
check "stop it" $J stop web --project e2e-proj
check "rename the project back" $J project rename e2e-proj demo -y
check "start the restored jail again" $J start web-restored --project demo

[ "$part" = e2e ] || run_pf

if [ "$part" != pf ]; then
	step "stop at shutdown: the rc script stops every running jail, a jail before the jails it depends on"
	check "the shutdown script is installed" test -x /usr/local/etc/rc.d/jailops_shutdown
	expect "stop-all lists the running jails of every project" 'would stop jail demo/' $J stop-all --dry-run
	check "the rc script stops the jails (what a host shutdown runs)" service jailops_shutdown onestop
	expect "no jail runs any more" '^0$' sh -c "jls -n jid 2>/dev/null | wc -l | tr -d ' '"
fi

if [ "$part" != pf ]; then
	step "a stop that did not finish: the mounts it left below the root are taken off by the next stop, by a start and by doctor --fix; a started jail has exactly one devfs and a working /dev"
	sr="$mount/projects/demo/jails/stale1/root"
	devfs_layers() { mount -p | awk -v p="$sr/dev" '$2 == p && $3 == "devfs"' | wc -l | tr -d ' '; }
	stale_mounts() { zfs mount -a >/dev/null 2>&1; mkdir -p "$sr/dev" "$sr/mnt"; mount -t devfs devfs "$sr/dev"; mount -t devfs devfs "$sr/dev"; mount -t nullfs /tmp "$sr/mnt"; }
	check "a jail for it" $J create stale1 --project demo --image "$img" --network lan --storage default --start
	expect "a started jail has /dev" 'null' $J exec --project demo stale1 -- ls /dev/null /dev/zero /dev/random
	expect "and exactly one devfs under its root" '^1$' devfs_layers
	check "stop it" $J stop stale1 --project demo
	stale_mounts
	expect "two stacked devfs are there" '^2$' devfs_layers
	expect "doctor names them" 'mounts\.leftovers +WARN' sh -c "$J doctor 2>&1; true" # the exit status is the verdict of every check: a CI host may fail others
	check "doctor --fix --dry-run lists what it would do" sh -c "$J doctor --fix --dry-run 2>&1; true"
	expect "and does nothing" '^2$' devfs_layers
	check "doctor --fix takes them off" sh -c "$J doctor --fix 2>&1; true"
	expect "no devfs is left" '^0$' devfs_layers
	stale_mounts
	check "the next stop takes them off" $J stop stale1 --project demo
	expect "no devfs is left after the stop" '^0$' devfs_layers
	stale_mounts
	check "a start takes them off" $J start stale1 --project demo
	expect "and the jail has exactly one devfs" '^1$' devfs_layers
	expect "and a working /dev" 'null' $J exec --project demo stale1 -- ls /dev/null /dev/zero
	check "a shutdown script that never returns" $J exec --project demo stale1 -- sh -c 'printf "#!/bin/sh\n# PROVIDE: zzhang\n# REQUIRE: LOGIN\n# KEYWORD: shutdown\n. /etc/rc.subr\nname=zzhang\nrcvar=zzhang_enable\nstart_cmd=:\nstop_cmd=zzhang_stop\nzzhang_stop() { echo zzhang hangs; sleep 300; }\nload_rc_config \$name\nrun_rc_command \$1\n" > /etc/rc.d/zzhang; chmod +x /etc/rc.d/zzhang; echo zzhang_enable=YES >> /etc/rc.conf'
	t0=$(date +%s)
	check "its stop finishes within its budget" $J stop stale1 --project demo
	[ $(( $(date +%s) - t0 )) -le 240 ] || fail "the stop of a jail whose shutdown never returns took $(( $(date +%s) - t0 )) s"
	expect "the jail is gone" '^0$' sh -c "jls -n name 2>/dev/null | grep -c 'name=demo_stale1\$' || true"
	expect "its console log says the shutdown was cut off" 'did not shut down' cat /var/log/jailops/jail_demo_stale1_console.log
	expect "no mount is left below its root" '^0$' devfs_layers
	check "delete it" $J delete --confirm-data-loss stale1 --project demo
fi

step "cleanup"
$J stop web-restored --project demo >/dev/null 2>&1 || true
echo "OK: the whole flow passed"
