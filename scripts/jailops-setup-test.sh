#!/bin/sh
# Tests of packaging/jailops-setup on any POSIX system: sysrc, sysctl, zpool, kldstat, kldload, pfctl, service,
# jailops, id and hostname are fakes in PATH that keep their state in files, jailops-priv is a fake through
# JAILOPS_SETUP_PRIV and every file path is below JAILOPS_SETUP_ROOT. The fake pfctl refuses a file whose rules are
# not in the order pf wants (options, scrub, queueing, translation, filtering), so the placement is checked by a
# second implementation. Run: just test-setup (or sh scripts/jailops-setup-test.sh). SH=dash picks the shell.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
setup=$here/packaging/jailops-setup
sh=${SH:-sh}
base=$(mktemp -d "${TMPDIR:-/tmp}/jailops-setup-test.XXXXXX")
[ -n "${KEEP:-}" ] || trap 'rm -rf "$base"' EXIT
failed=0 n=0

# ── the fakes ────────────────────────────────────────────────────────────────────────────────────────────────────
fakes=$base/bin
mkdir -p "$fakes"
fake() { printf '#!/bin/sh\necho "%s $*" >> "$FAKE/log"\n%s\n' "$1" "$2" > "$fakes/$1"; chmod 755 "$fakes/$1"; }
fake id 'echo "${FAKE_UID:-0}"'
fake hostname 'echo host.example'
fake zpool 'printf "%s\n" $FAKE_POOLS'
fake kldstat 'grep -qx "$3" "$FAKE/kld" 2>/dev/null'
fake kldload 'shift; for m; do echo "$m" >> "$FAKE/kld"; done'
fake sysctl '
if [ "$1" = -n ]; then v=$(grep "^$2=" "$FAKE/sysctl" 2>/dev/null) || exit 1; echo "${v#*=}"; exit 0; fi
for a; do grep -v "^${a%%=*}=" "$FAKE/sysctl" > "$FAKE/sysctl.t" 2>/dev/null; echo "$a" >> "$FAKE/sysctl.t"; mv "$FAKE/sysctl.t" "$FAKE/sysctl"; done'
fake sysrc '
f=$FAKE/rc.conf; n=0
while :; do case ${1:-} in -f) f=$2; shift 2 ;; -n) n=1; shift ;; *) break ;; esac; done
for a; do
	case $a in
	*=*) k=${a%%=*}; grep -v "^$k=" "$f" > "$f.t" 2>/dev/null; echo "$k=\"${a#*=}\"" >> "$f.t"; mv "$f.t" "$f"; echo "$k: -> ${a#*=}" ;;
	*) l=$(grep "^$a=" "$f" 2>/dev/null) || { echo "sysrc: unknown variable $a" >&2; exit 1; }
	   v=${l#*=}; v=${v#\"}; v=${v%\"}; if [ $n = 1 ]; then echo "$v"; else echo "$a: $v"; fi ;;
	esac
done'
fake service '
case $2 in
status) [ -e "$FAKE/run.$1" ] ;;
start|restart) touch "$FAKE/run.$1"; [ "$1" = jailopsd ] && mkdir -p "$JAILOPS_SETUP_ROOT/var/run/jailops" && touch "$JAILOPS_SETUP_ROOT/var/run/jailops/jailops.sock"; true ;;
*) exit 1 ;;
esac'
fake jailops '
case "$*" in
doctor) echo "ok pf.anchors" ;;
"user list -o name") cat "$FAKE/users" 2>/dev/null ;;
"user create"*) echo "$3" >> "$FAKE/users" ;;
*) exit 1 ;;
esac'
fake jailops-priv '[ "$1" = init ] || exit 1; case "$*" in *-dry-run*) echo "creating user jailops" ;; *) touch "$FAKE/inited"; echo "creating user jailops"; echo; echo "Done. Enable..." ;; esac'
# pfctl: -nf FILE checks the order of the top-level rules; -f FILE loads; -e enables; -s info|nat|rules.
fake pfctl '
order() {
	awk '\''
	/^[ \t]*(#|$)/ { next }
	{ k = $1; c = 0
	  if (k == "set") c = 1; else if (k == "scrub") c = 2; else if (k == "nat" || k == "rdr" || k ~ /-anchor$/) c = 4
	  else if (k == "pass" || k == "block" || k == "anchor") c = 5
	  if (depth == 0 && c) { if (c < last) { print "Rules must be in order: options, normalization, queueing, translation, filtering (line " NR ")"; bad = 1; exit 1 } last = c }
	  depth += gsub(/\{/, "{") - gsub(/\}/, "}") }
	END { exit bad }'\'' "$1"
}
case "$1" in
-nf) [ -z "${FAKE_PFCTL_FAIL:-}" ] || { echo "$2:3: syntax error"; exit 1; }; order "$2" ;;
-f) [ -z "${FAKE_PFCTL_LOADFAIL:-}" ] || { echo "load refused"; exit 1; }; order "$2" && cp "$2" "$FAKE/loaded" ;;
-e) touch "$FAKE/enabled" ;;
-s) case $2 in
	info) if [ -e "$FAKE/enabled" ]; then echo "Status: Enabled for 0 days"; else echo "Status: Disabled"; fi ;;
	nat) grep -E "^(nat|rdr)-anchor" "$FAKE/loaded" 2>/dev/null | sed "s/\$/ all/"; true ;;
	rules) grep -E "^[ \t]*(anchor|pass|block|scrub)" "$FAKE/loaded" 2>/dev/null | sed "s/\$/ all/"; true ;;
	esac ;;
*) exit 1 ;;
esac'

# ── the harness ──────────────────────────────────────────────────────────────────────────────────────────────────
# new_host: a fresh fake host; FAKE (state) and ROOT (files) are exported for the fakes and the script
new_host() {
	n=$((n + 1))
	FAKE=$base/h$n/state; ROOT=$base/h$n/root
	mkdir -p "$FAKE" "$ROOT/etc" "$ROOT/boot"
	: > "$FAKE/log"
	FAKE_POOLS=tank
	export FAKE ROOT FAKE_POOLS
}
# setup ARGS...: run the script on the current fake host; output in $out, status in $rc
setup() {
	rc=0
	out=$(PATH="$fakes:$PATH" JAILOPS_SETUP_ROOT=$ROOT JAILOPS_SETUP_PRIV=$fakes/jailops-priv JAILOPS_SETUP_WAIT=1 \
		$sh "$setup" "$@" 2>&1 < "${STDIN:-/dev/null}") || rc=$?
}
check() { # check NAME COMMAND...: a test assertion
	name=$1; shift
	if "$@"; then :; else
		echo "FAIL [$case] $name"
		failed=$((failed + 1))
	fi
}
has() { printf '%s\n' "$out" | grep -qF -- "$1"; }
logged() { grep -qF -- "$1" "$FAKE/log"; }
line_of() { grep -nxF -- "$2" "$1" | head -1 | cut -d: -f1; }
before() { # before FILE A B: line A comes before line B in FILE
	a=$(line_of "$1" "$2"); b=$(line_of "$1" "$3")
	[ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}
log_before() { a=$(grep -nF -- "$1" "$FAKE/log" | head -1 | cut -d: -f1); b=$(grep -nF -- "$2" "$FAKE/log" | head -1 | cut -d: -f1); [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; }
snapshot() { (cd "$base/h$n" && find . -type f ! -name log | sort | while read -r f; do echo "== $f"; cat "$f"; done) }
mutations() { grep -vE '^(id |hostname|zpool list|sysrc (-f [^ ]+ )?-n |sysctl -n |kldstat |pfctl -s |pfctl -nf |service [a-z_]+ status|jailops user list|jailops-priv init .*-dry-run)' "$FAKE/log" || true; }
# the lines of FILE without the ones jailops-setup adds: must be the original file, line for line
original_lines() { grep -vxE '# jailops-setup: .*|set state-policy if-bound|scrub in all fragment reassemble|anchor "jailops/\*"' "$1"; }
backups() { ls "$ROOT/etc" | grep -c 'pf.conf.jailops-setup-' || true; }

# ── cases ────────────────────────────────────────────────────────────────────────────────────────────────────────
case="no pf.conf"
new_host
setup -y
check "exit 0" [ "$rc" = 0 ]
check "pf.conf created" [ -f "$ROOT/etc/pf.conf" ]
check "minimal file passes all" grep -qx 'pass all' "$ROOT/etc/pf.conf"
check "anchor before pass all" before "$ROOT/etc/pf.conf" 'anchor "jailops/*"' 'pass all'
check "no translation anchors" eval '! grep -qE "^(nat|rdr)-anchor" "$ROOT/etc/pf.conf"'
check "checked before loading" log_before "pfctl -nf" "pfctl -f"
check "loaded" logged "pfctl -f $ROOT/etc/pf.conf"
check "pf enabled" logged "pfctl -e"
check "pf at boot" grep -qx 'pf_enable="YES"' "$FAKE/rc.conf"
check "no backup of a file that did not exist" [ "$(backups)" = 0 ]
check "said no block rule" has "it has no block rule"
check "init with the pool" logged "jailops-priv init -pool tank"
check "forwarding persistent" grep -qx 'gateway_enable="YES"' "$FAKE/rc.conf"
check "ipv6 forwarding persistent" grep -qx 'ipv6_gateway_enable="YES"' "$FAKE/rc.conf"
check "forwarding now" grep -qx 'net.inet.ip.forwarding=1' "$FAKE/sysctl"
check "modules loaded" logged "kldload -n if_epair pf zfs"
check "modules at boot" grep -qx 'pf_load="YES"' "$ROOT/boot/loader.conf"
check "services enabled" grep -qx 'jailopsd_enable="YES"' "$FAKE/rc.conf"
check "web on" grep -qx 'jailopsd_web="YES"' "$FAKE/rc.conf"
check "pf loaded before the daemon starts" log_before "pfctl -f" "service jailopsd start"
check "doctor" logged "jailops doctor"
check "no admin without a terminal" eval '! logged "jailops user create"'
check "console URL" has "https://host.example:39110/"
check "never restarts pf" eval '! grep -q "service pf" "$FAKE/log"'

case="second run changes nothing"
cp "$ROOT/etc/pf.conf" "$base/pf.first"
: > "$FAKE/log"
setup -y
check "exit 0" [ "$rc" = 0 ]
check "pf.conf unchanged" cmp -s "$ROOT/etc/pf.conf" "$base/pf.first"
check "no mutation" [ -z "$(mutations | grep -v '^jailops-priv init\|^jailops doctor')" ]
check "init again (idempotent)" logged "jailops-priv init -pool tank"
check "says ok for pf" has "ok: pf runs with the JailOps anchor"

case="pf.conf without anchors, pf running"
new_host
cat > "$ROOT/etc/pf.conf" <<'EOF'
# my firewall
ext_if = "vtnet0"
set skip on lo0
nat on $ext_if from 10.0.0.0/8 to any -> ($ext_if)
block in all
pass out all keep state
pass in on $ext_if proto tcp to port { 22, 443 }
EOF
chmod 600 "$ROOT/etc/pf.conf"
cp "$ROOT/etc/pf.conf" "$base/orig"
cp "$ROOT/etc/pf.conf" "$FAKE/loaded"; touch "$FAKE/enabled"
echo 'pf_enable="YES"' > "$FAKE/rc.conf"
setup -y
f=$ROOT/etc/pf.conf
check "exit 0" [ "$rc" = 0 ]
check "existing lines unchanged, in order" eval 'original_lines "$f" | cmp -s - "$base/orig"'
check "state-policy after the options" before "$f" 'set skip on lo0' 'set state-policy if-bound'
check "scrub before nat" before "$f" 'scrub in all fragment reassemble' 'nat on $ext_if from 10.0.0.0/8 to any -> ($ext_if)'
check "anchor before the first block" before "$f" 'anchor "jailops/*"' 'block in all'
check "anchor after translation" before "$f" 'nat on $ext_if from 10.0.0.0/8 to any -> ($ext_if)' 'anchor "jailops/*"'
check "one backup, equal to the original" eval '[ "$(backups)" = 1 ] && cmp -s "$base/orig" "$ROOT"/etc/pf.conf.jailops-setup-*'
check "mode kept" [ "$(ls -l "$f" | cut -c1-10)" = "-rw-------" ]
check "loaded" cmp -s "$f" "$FAKE/loaded"
check "not enabled again" eval '! logged "pfctl -e"'
check "says states are kept" has "keeps the states"
check "says what it adds" has "set state-policy if-bound is added"
check "says scrub is added" has "scrub in all fragment reassemble is added"
cp "$f" "$base/pf.first"
: > "$FAKE/log"
setup -y
check "idempotent: unchanged" cmp -s "$f" "$base/pf.first"
check "idempotent: no second backup" [ "$(backups)" = 1 ]
check "idempotent: no load" eval '! logged "pfctl -f"'

case="pf.conf with the anchor already"
new_host
cat > "$ROOT/etc/pf.conf" <<'EOF'
set state-policy if-bound
scrub in all
anchor "jailops/*"
pass all
EOF
cp "$ROOT/etc/pf.conf" "$base/orig"
setup -y
check "exit 0" [ "$rc" = 0 ]
check "unchanged" cmp -s "$ROOT/etc/pf.conf" "$base/orig"
check "no backup" [ "$(backups)" = 0 ]
check "says it has the line" has "has the anchor line"
check "loaded, because pf did not have them" logged "pfctl -f"
check "checked first" log_before "pfctl -nf" "pfctl -f"

case="block rule where the anchors go, pf stopped, the answer is no"
new_host
cat > "$ROOT/etc/pf.conf" <<'EOF'
set skip on lo0
anchor "mine" {
	block in all
	pass in proto tcp to port 22
}
block in all
pass in proto tcp to port \
	22
EOF
cp "$ROOT/etc/pf.conf" "$base/orig"
echo n > "$base/no"
STDIN=$base/no setup
check "exit 1 (pf not done)" [ "$rc" = 1 ]
check "warns about ssh" has "this session and every later ssh login are cut"
check "file unchanged after no" cmp -s "$ROOT/etc/pf.conf" "$base/orig"
check "nothing loaded or enabled" eval '! logged "pfctl -f" && ! logged "pfctl -e"'
check "the rest still done" logged "service jailopsd start"
printf 'y\n' > "$base/yes"
STDIN=$base/yes setup
f=$ROOT/etc/pf.conf
check "exit 0 after yes" [ "$rc" = 0 ]
check "anchor before the first top-level rule" before "$f" 'anchor "jailops/*"' 'anchor "mine" {'
check "existing lines unchanged" eval 'original_lines "$f" | cmp -s - "$base/orig"'
check "enabled after the warning" logged "pfctl -e"

case="validation fails"
new_host
printf 'set skip on lo0\npass all\n' > "$ROOT/etc/pf.conf"
cp "$ROOT/etc/pf.conf" "$base/orig"
printf 'old rules\n' > "$FAKE/loaded"; touch "$FAKE/enabled"
FAKE_PFCTL_FAIL=1 setup -y
check "exit 1" [ "$rc" = 1 ]
check "pf.conf untouched" cmp -s "$ROOT/etc/pf.conf" "$base/orig"
check "no backup, nothing to restore" [ "$(backups)" = 0 ]
check "no temporary file left" eval '[ -z "$(ls "$ROOT/etc" | grep -v "^pf.conf$")" ]'
check "nothing loaded" eval '! logged "pfctl -f"'
check "live ruleset untouched" grep -qx 'old rules' "$FAKE/loaded"
check "pfctl output shown" has "syntax error"
check "says nothing changed" has "nothing was written, nothing loaded"
check "services still started" logged "service jailopsd start"

case="load fails after the check"
new_host
printf 'set skip on lo0\npass all\n' > "$ROOT/etc/pf.conf"
cp "$ROOT/etc/pf.conf" "$base/orig"
printf 'old rules\n' > "$FAKE/loaded"; touch "$FAKE/enabled"
FAKE_PFCTL_LOADFAIL=1 setup -y
check "exit 1" [ "$rc" = 1 ]
check "pf.conf restored" cmp -s "$ROOT/etc/pf.conf" "$base/orig"
check "live ruleset untouched" grep -qx 'old rules' "$FAKE/loaded"

case="dry run"
new_host
printf 'set skip on lo0\nblock in all\npass out all\n' > "$ROOT/etc/pf.conf"
before_state=$(snapshot)
setup -n
check "exit 0" [ "$rc" = 0 ]
check "nothing changed" [ "$(snapshot)" = "$before_state" ]
check "only reads ran" [ -z "$(mutations)" ]
check "prints the actions" has "> pfctl -f $ROOT/etc/pf.conf"
check "prints the diff" has '+anchor "jailops/*"'
check "prints init" has "> $fakes/jailops-priv init -pool tank"
check "prints the services" has "> service jailopsd start"
check "says dry run" has "Dry run: nothing was changed."
check "no temporary file left" eval '[ -z "$(ls "$ROOT/etc" | grep -v "^pf.conf$")" ]'

case="pools and root"
new_host
FAKE_POOLS="tank zroot"
setup -y
check "two pools: exit 2" [ "$rc" = 2 ]
check "lists them" has "jailops-setup -pool zroot"
check "nothing ran" [ -z "$(mutations)" ]
setup -y -pool zroot
check "-pool chooses" logged "jailops-priv init -pool zroot"
new_host
setup -pool nope
check "unknown pool: exit 2" [ "$rc" = 2 ]
FAKE_UID=1001 setup -y
check "not root: exit 1" [ "$rc" = 1 ]
check "says root" has "must run as root"
setup -pool '-x'
check "pool as an option refused" [ "$rc" = 2 ]

case="includes"
new_host
printf 'include "/etc/pf.mine"\npass all\n' > "$ROOT/etc/pf.conf"
cp "$ROOT/etc/pf.conf" "$base/orig"
setup -y
check "not edited" cmp -s "$ROOT/etc/pf.conf" "$base/orig"
check "says why" has "includes other files"

case="appliance mode"
new_host
echo 'jailops_appliance="YES"' > "$FAKE/rc.conf"
setup -y
check "refused" [ "$rc" = 1 ]
check "nothing ran" [ -z "$(mutations)" ]

if [ "$failed" -gt 0 ]; then
	echo "jailops-setup: $failed check(s) failed"
	exit 1
fi
echo "jailops-setup: all checks passed ($n hosts)"
