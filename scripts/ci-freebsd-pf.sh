#!/bin/sh
# The packet filter of JailOps, tested with real traffic on a real FreeBSD host. Needs a running jailopsd with an image
# of the host's release (freebsd-15-1 on 15.1, or PF_IMAGE) and the storage "default" (scripts/ci-freebsd-e2e.sh leaves
# exactly that), PF running with the
# anchor lines of the setup guide, and root.
#
#   sh scripts/ci-freebsd-pf.sh              the whole matrix
#   PF_FAST=1 sh scripts/ci-freebsd-pf.sh    skip the phases that wait for minutes
#   PF_KEEP=1 ...                            leave the projects and jails in place to look at them
#   FORGE_BIN=/path/to/forge-freebsd-<arch>  run phase 0e, the forged-frame probes (scripts/forge); skipped without it
#
# Every line is a probe with an expected outcome: "allow" (the connection or packet arrives) or "deny" (it does not).
# A probe that gives the wrong answer is a FAIL; the script goes on and exits non-zero at the end if any failed.
# It creates and removes its own projects (pfa, pfb), networks, jails, policies and address sets, and for the port
# forward of phase 11 an epair pair (pfupa, pfupb) and a plain VNET jail (pfrdr) that stands for a machine on the uplink.
set -u

J=${JAILOPS:-/usr/local/bin/jailops}
img=${PF_IMAGE:-freebsd-$(freebsd-version -u | sed -E 's/^([0-9]+)\.([0-9]+)-.*/\1-\2/')}
fails=0
UC=0
passes=0
work=$(mktemp -d /tmp/jailops-pf.XXXXXX)
trap 'cleanup; exit 1' INT TERM

t0=$(date +%s)
say()  { printf '\n== %s  [+%ss]\n' "$*" "$(($(date +%s) - t0))"; }
pass() { passes=$((passes + 1)); printf 'PASS  %s\n' "$*"; }
bad()  { fails=$((fails + 1)); printf 'FAIL  %s\n' "$*"; }
die()  { printf 'ABORT %s\n' "$*" >&2; cleanup; exit 2; }
waitfor_() { # waitfor_ DESCRIPTION SECONDS COMMAND...: the command must succeed within SECONDS (polled twice a second); a miss is a FAIL line, not an abort
	wf_desc=$1; wf_secs=$2; shift 2
	wf_end=$(( $(date +%s) + wf_secs ))
	until "$@" >/dev/null 2>&1; do
		if [ "$(date +%s)" -ge "$wf_end" ]; then bad "$wf_desc (not after $wf_secs s)"; return 1; fi
		sleep 0.5 # sleep-ok: the poll of waitfor_
	done
}

# --- running things in a jail (as root on the host) --------------------------------------------------------------
# jx PROJECT NAME CMD... : run CMD in the jail
jx() { p=$1; n=$2; shift 2; jexec "${p}_${n}" "$@"; }

# --- probes: each returns 0 when the traffic arrived -------------------------------------------------------------
# icmp_from SRC DST: SRC is "host" or "project:name"
run_from() { # run_from SRC CMD...
	src=$1; shift
	case $src in
	host) "$@" ;;
	*) jx "${src%%:*}" "${src##*:}" "$@" ;;
	esac
}
fam() { case $1 in *:*) echo 6 ;; *) echo 4 ;; esac; }
icmp()  { run_from "$1" ping -"$(fam "$2")" -c1 -t2 "$2" >/dev/null 2>&1; }
tcp()   { run_from "$1" nc -z -w2 "$2" "$3" >/dev/null 2>&1; }
# expect VERDICT DESCRIPTION CMD...
expect() {
	want=$1; desc=$2; shift 2
	if "$@"; then got=allow; else got=deny; fi
	# An allowed probe that fails once is a lost packet or a slow start more often than a rule: look again, twice, and say
	# so (the note keeps it visible). A denied probe is never repeated: one answer through a rule that must deny is a leak.
	if [ "$want" = allow ] && [ "$got" = deny ]; then
		for try in 2 3 4 5 6 7 8 9 10 11; do
			sleep 1 # sleep-ok: pause between the looks at an allowed probe
			if "$@"; then got=allow; printf 'NOTE  %s: allowed on attempt %s\n' "$desc" "$try"; break; fi
		done
	fi
	if [ "$got" = "$want" ]; then pass "$desc ($want)"; else bad "$desc: expected $want, got $got"; fi
}

# --- addresses ---------------------------------------------------------------------------------------------------
addr4() { $J config get "$2" nic.eth0.ipv4 --project "$1" </dev/null 2>/dev/null | tail -1; }
addr6() { $J config get "$2" nic.eth0.ipv6 --project "$1" </dev/null 2>/dev/null | tail -1; }

# --- setup and cleanup -------------------------------------------------------------------------------------------
cleanup() {
	say "cleanup"
	[ -n "${PF_KEEP:-}" ] || remove_all
	rm -rf "$work"
	printf '\n%d passed, %d failed\n' "$passes" "$fails"
}
retry() { # retry TRIES COMMAND...: stop at the first success (a stopping jail needs a moment before its dataset can go)
	n=$1; shift
	while [ "$n" -gt 0 ]; do
		"$@" >/dev/null 2>&1 && return 0
		[ $? -eq 4 ] && return 0 # exit code 4 is "not found": there is nothing to remove, waiting would only burn time
		n=$((n - 1)); sleep 3
	done
	return 1
}
remove_all() {
	jail -r pfrdr >/dev/null 2>&1
	ifconfig lo0 inet6 fd91:1::fff0 -alias >/dev/null 2>&1; ifconfig lo0 inet6 fd93:1::fff0 -alias >/dev/null 2>&1
	ifconfig pfupa destroy >/dev/null 2>&1
	for f in "${TMPDIR:-/tmp}"/jailops-pf.*/h4.pid "${TMPDIR:-/tmp}"/jailops-pf.*/h6.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
	pkill -x nc 2>/dev/null
	for pn in pfa:a pfa:b pfa:c pfa:d pfa:r pfa:n pfa:m pfb:o; do
		$J stop "${pn#*:}" --project "${pn%%:*}" </dev/null >/dev/null 2>&1
	done
	for pn in pfa:a pfa:b pfa:c pfa:d pfa:r pfa:n pfa:m pfb:o; do
		retry 6 $J delete --confirm-data-loss "${pn#*:}" --project "${pn%%:*}" </dev/null
	done
	for p in pfa pfb; do
		$J project set $p --firewall-policy "" </dev/null >/dev/null 2>&1
		for x in $($J firewall policy list --project $p --no-headers -o name </dev/null 2>/dev/null); do
			retry 3 $J firewall policy delete -y "$x" --project $p </dev/null
		done
		for x in $($J firewall address-set list --project $p --no-headers -o name </dev/null 2>/dev/null); do
			retry 3 $J firewall address-set delete -y "$x" --project $p </dev/null
		done
		retry 3 $J project delete -y $p </dev/null
	done
	for n in pfa-net pfa-net2 pfa-up pfb-net; do retry 3 $J network delete -y $n </dev/null; done
}

policy() { # policy PROJECT NAME YAML-BODY: create or replace
	p=$1; n=$2; body=$3
	printf '%s\n' "$body" > "$work/$n.yaml"
	if $J firewall policy show "$n" --project "$p" </dev/null >/dev/null 2>&1; then
		cat > "$work/edit.sh" <<EOF
#!/bin/sh
cat "$work/$n.yaml" > "\$1"
EOF
		chmod +x "$work/edit.sh"
		EDITOR="$work/edit.sh" $J firewall policy edit "$n" --project "$p" </dev/null >/dev/null 2>&1 || die "policy edit $n"
	else
		$J firewall policy create "$n" -f "$work/$n.yaml" --project "$p" </dev/null >/dev/null 2>&1 || die "policy create $n"
	fi
}
# The reconciler loads anchors on its own schedule. settle waits until the anchors have changed after the action that
# came before it and have then stopped changing, and says how long that took (the time is a measurement of the product,
# not a pause that has to be long enough).
snapshot() { for a in jailops/pfa/a jailops/pfa/b jailops/pfa/c jailops/pfb/o jailops/pfa/d jailops/pfa/r jailops/net.pfa-net; do pfctl -a "$a" -sr 2>/dev/null; done | cksum; }
PRE=$(snapshot)
settle() {
	t=0; cur=$(snapshot)
	while [ "$cur" = "$PRE" ] && [ $t -lt "${SETTLE_WAIT:-60}" ]; do sleep 1; t=$((t + 1)); cur=$(snapshot); done
	same=0
	while [ $same -lt 3 ] && [ $t -lt 90 ]; do
		sleep 1; t=$((t + 1)); n=$(snapshot) # sleep-ok: poll of a condition
		if [ "$n" = "$cur" ]; then same=$((same + 1)); else same=0; cur=$n; fi
	done
	[ "$cur" = "$PRE" ] && printf 'note: the anchors did not change after the action (%ss)\n' "$t" || printf 'note: anchors converged after %ss\n' "$t"
	PRE=$cur
}


say "the rendered anchors in the repository parse with the real pfctl"
if [ -d internal/render/testdata ]; then
	for f in internal/render/testdata/pf_*.golden; do
		if out=$(pfctl -n -a jailops/x/y -f "$f" 2>&1 | grep -v 'already defined'); [ -z "$out" ]; then pass "$f"; else bad "$f: $out"; fi
	done
fi

say "setup"
[ "$(id -u)" -eq 0 ] || die "run as root"
remove_all # leftovers of an earlier run
sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null
$J network create pfa-net --ipv4 10.91.0.1/24 --ipv6 fd91:1::/64 </dev/null >/dev/null || die "network pfa-net"
$J network create pfb-net --ipv4 10.92.0.1/24 --ipv6 fd92:1::/64 </dev/null >/dev/null || die "network pfb-net"
$J network create pfa-net2 --ipv4 10.93.0.1/24 --ipv6 fd93:1::/64 </dev/null >/dev/null || die "network pfa-net2"
# the host's IPv6 addresses on the networks (a /128 on lo0 each), made after the networks (a network is refused when the
# host holds an address inside its subnet) and before any jail starts, so that they are in the table <host> of every
# anchor from the first load
ifconfig lo0 inet6 fd91:1::fff0/128 alias; ifconfig lo0 inet6 fd93:1::fff0/128 alias
$J project create pfa </dev/null >/dev/null || die "project pfa"
$J project create pfb </dev/null >/dev/null || die "project pfb"
{ $J network grant pfa-net --project pfa && $J network grant pfa-net2 --project pfa && $J storage grant default --project pfa; } </dev/null >/dev/null || die "grant pfa"
{ $J network grant pfb-net --project pfb && $J storage grant default --project pfb; } </dev/null >/dev/null || die "grant pfb"
for n in a b; do $J create $n --project pfa --image "$img" --network pfa-net --storage default </dev/null >/dev/null || die "create $n"; done
$J create c --project pfa --image "$img" --network pfa-net --storage default --tag web </dev/null >/dev/null || die "create c"
$J create d --project pfa --image "$img" --network pfa-net2 --storage default </dev/null >/dev/null || die "create d"
$J create o --project pfb --image "$img" --network pfb-net --storage default </dev/null >/dev/null || die "create o"
for pn in pfa:a pfa:b pfa:c pfa:d pfb:o; do $J start "${pn#*:}" --project "${pn%%:*}" </dev/null >/dev/null || die "start $pn"; done
for pn in pfa:a pfa:b pfa:c pfa:d pfb:o; do
	pp_=${pn%%:*}; pn_=${pn#*:}
	waitfor_ "$pn runs" 90 jexec "${pp_}_${pn_}" true
	waitfor_ "the anchor of $pn is loaded" 90 sh -c "pfctl -a jailops/$pp_/$pn_ -sr 2>/dev/null | grep -q ."
done

A4=$(addr4 pfa a); A6=$(addr6 pfa a); B4=$(addr4 pfa b); B6=$(addr6 pfa b)
C4=$(addr4 pfa c); C6=$(addr6 pfa c); D4=$(addr4 pfa d); D6=$(addr6 pfa d); O4=$(addr4 pfb o); O6=$(addr6 pfb o)
# the host on the network of project pfa: its IPv4 gateway, and an IPv6 address of its own (a /128 on lo0: a jail reaches it
# through its gateway fe80::1, and the host uses it as its source towards the network's addresses)
H4=10.91.0.1; H6=fd91:1::fff0; HD4=10.93.0.1; HD6=fd93:1::fff0
for v in "$A4" "$A6" "$B4" "$B6" "$C4" "$C6" "$D4" "$D6" "$O4" "$O6"; do [ -n "$v" ] || die "a jail has no address (v4/v6 missing)"; done
printf 'a=%s %s  b=%s %s  c=%s %s  o=%s %s\n' "$A4" "$A6" "$B4" "$B6" "$C4" "$C6" "$O4" "$O6"

# servers in jail a: tcp 8080, 9090, 2222 and a udp logger on 5353, on both families
for fam in 4 6; do
	if [ $fam = 4 ]; then ad=$A4; else ad=$A6; fi
	for port in 8080 9090 2222; do
		jx pfa a daemon -f nc -"$fam" -k -l "$ad" "$port" || die "nc server $port"
	done
done
udp_server() { # udp_server: (re)start loggers writing into the jail's /var/tmp/udp.log, mirrored to the host
	for ad in "$A4" "$A6"; do
		jx pfa a daemon -f sh -c "while :; do nc -u -l -w3 $ad 5353 >> /var/tmp/udp.log 2>/dev/null; done"
	done
}
udp_server
# udp probes read the jail's file
udp() {
	UC=$((UC + 1)); tok="t$$-$UC"
	run_from "$1" sh -c "echo $tok | nc -u -w1 $2 $3" >/dev/null 2>&1
	sleep 1 # sleep-ok: a udp probe that a rule drops leaves nothing to wait for: the look comes after the packet had its time
	jx pfa a grep -q "$tok" /var/tmp/udp.log 2>/dev/null
}

# the matrix of one source against jail a, both families. The icmp and tcp probes of the two families are independent of each
# other, so they run at the same time and their answers are printed afterwards in the usual order. The udp probes stay one at
# a time: the logger of a jail ("nc -u -l") talks to one sender at a time, so two probes at once would disturb each other.
# sim SRC DST PROTO [PORT]: `jailops firewall test` for the connection a probe makes. SRC is host, a jail of project pfa
# (pfa:b) or the jail o of project pfb (an address of another project, which the test treats as an external host); DST is
# an address of jail a. The exit status is the command's: 0 pass, 1 block, 8 it cannot say.
sim() {
	src=$1; dst=$2; proto=$3; port=${4:-}
	f=$(fam "$dst")
	[ "$proto" = icmp ] && [ "$f" = 6 ] && proto=icmp6 # a ping of an IPv6 address is icmp6
	case $src in
	host) from=host ;;
	pfa:*) from="jail:${src#*:}" ;;
	*) if [ "$f" = 6 ]; then from=$O6; else from=$O4; fi ;;
	esac
	set -- --project pfa --from "$from" --to "$dst" --proto "$proto" --family "$f"
	[ -n "$port" ] && set -- "$@" --port "$port"
	$J firewall test "$@" </dev/null >/dev/null 2>&1
}
# simexpect WANT DESCRIPTION SRC DST PROTO [PORT]: the test must say what the real probe did (allow = pass, deny = block).
# It is asked about the same connections the probes make, in every phase, so a rule the test misreads shows up where the
# traffic proves it.
simexpect() {
	want=$1; desc=$2; shift 2
	sim "$@"; rc=$?
	case $rc in
	0) got=allow ;;
	1) got=deny ;;
	*) printf 'NOTE  firewall test: %s: it cannot say (exit %s)\n' "$desc" "$rc"; return 0 ;;
	esac
	if [ "$got" = "$want" ]; then
		pass "firewall test: $desc ($want)"
	else
		bad "firewall test: $desc: expected $want, got $got"
		simshow "$@" | sed 's/^/      /' # what it said, for whoever reads the log
	fi
}
simshow() { # simshow SRC DST PROTO [PORT]: the same test, printed
	src=$1; dst=$2; proto=$3; port=${4:-}
	f=$(fam "$dst")
	[ "$proto" = icmp ] && [ "$f" = 6 ] && proto=icmp6 # a ping of an IPv6 address is icmp6
	case $src in
	host) from=host ;;
	pfa:*) from="jail:${src#*:}" ;;
	*) if [ "$f" = 6 ]; then from=$O6; else from=$O4; fi ;;
	esac
	set -- --project pfa --from "$from" --to "$dst" --proto "$proto" --family "$f"
	[ -n "$port" ] && set -- "$@" --port "$port"
	$J firewall test "$@" </dev/null 2>&1
}

matrix() { # matrix SRC ICMP T8080 T9090 T2222 UDP5353   (each allow|deny)
	src=$1
	for ver in 4 6; do
		if [ $ver = 4 ]; then t=$A4; else t=$A6; fi
		expect "$2" "$src -> a v$ver icmp" icmp "$src" "$t" > "$work/pm.$ver.1" 2>&1 &
		expect "$3" "$src -> a v$ver tcp 8080" tcp "$src" "$t" 8080 > "$work/pm.$ver.2" 2>&1 &
		expect "$4" "$src -> a v$ver tcp 9090" tcp "$src" "$t" 9090 > "$work/pm.$ver.3" 2>&1 &
		expect "$5" "$src -> a v$ver tcp 2222" tcp "$src" "$t" 2222 > "$work/pm.$ver.4" 2>&1 &
	done
	wait
	for ver in 4 6; do
		if [ $ver = 4 ]; then t=$A4; else t=$A6; fi
		for i in 1 2 3 4; do # the counters of a background probe were counted in its own shell: count what it printed
			f="$work/pm.$ver.$i"
			cat "$f"
			passes=$((passes + $(grep -c '^PASS' "$f" || true)))
			fails=$((fails + $(grep -c '^FAIL' "$f" || true)))
		done
		expect "$6" "$src -> a v$ver udp 5353" udp "$src" "$t" 5353
	done
	# the firewall test must agree with what the probes just showed
	for ver in 4 6; do
		if [ $ver = 4 ]; then t=$A4; else t=$A6; fi
		simexpect "$2" "$src -> a v$ver icmp" "$src" "$t" icmp
		simexpect "$3" "$src -> a v$ver tcp 8080" "$src" "$t" tcp 8080
		simexpect "$4" "$src -> a v$ver tcp 9090" "$src" "$t" tcp 9090
		simexpect "$5" "$src -> a v$ver tcp 2222" "$src" "$t" tcp 2222
		simexpect "$6" "$src -> a v$ver udp 5353" "$src" "$t" udp 5353
	done
}

say "phase 0: no policy anywhere. Open inside a project, closed between projects"
PRE=$(snapshot)
matrix host allow allow allow allow allow
matrix pfa:b allow allow allow allow allow
matrix pfa:c allow allow allow allow allow
matrix pfb:o deny deny deny deny deny
for ver in 4 6; do
	if [ $ver = 4 ]; then b=$B4; o=$O4; else b=$B6; o=$O6; fi
	expect allow "a -> b v$ver icmp" icmp pfa:a "$b"
	expect deny "a -> o (another project) v$ver icmp" icmp pfa:a "$o"
	expect deny "a -> o (another project) v$ver tcp 22" tcp pfa:a "$o" 22
done

say "phase 0b: a jail cannot send with another jail's address (nothing else is filtering yet)"
PRE=$(snapshot)
# the host is closed to a jail except for ping and the network's resolver: a rule opens the port of the listener below
policy pfa hostudp 'default_in: allow
default_out: allow
rules:
  - {name: to-host-udp, action: allow, direction: out, proto: udp, to: [host], ports: ["5454"]}'
$J config set a firewall.policies hostudp --project pfa </dev/null >/dev/null || die "attach hostudp"
settle 10
# UDP listeners that log what arrives: on the host, in jail c (same network) and in jail d (another network of the same
# project, reached through the host)
for fam in 4 6; do
	if [ $fam = 4 ]; then h=$H4; c=$C4; d=$D4; else h=$H6; c=$C6; d=$D6; fi
	: > "$work/h$fam.log"
	daemon -f -p "$work/h$fam.pid" sh -c "while :; do nc -u -l -w2 $h 5454 >> $work/h$fam.log 2>/dev/null; done"
	jx pfa c daemon -f sh -c "while :; do nc -u -l -w2 $c 5454 >> /var/tmp/u.log 2>/dev/null; done"
	jx pfa d daemon -f sh -c "while :; do nc -u -l -w2 $d 5454 >> /var/tmp/u.log 2>/dev/null; done"
done
waitfor_ "the UDP listeners are up" 30 sh -c "sockstat -46 -l | grep -q ':5454 ' && jexec pfa_c sockstat -46 -l | grep -q ':5454 ' && jexec pfa_d sockstat -46 -l | grep -q ':5454 '"
BIF=$(jx pfa a ifconfig -l | tr ' ' '\n' | grep -v lo0 | head -1)
send_from_a() { # send_from_a SOURCE DEST TOKEN
	jx pfa a sh -c "echo $3 | nc -u -w1 -s $1 $2 5454" >/dev/null 2>&1
}
arrived() { # arrived WHERE TOKEN: where is host, c or d
	sleep 1 # sleep-ok: a packet that must NOT arrive is looked for after it had its time
	case $1 in
	host*) grep -q "$2" "$work/h${1#host}.log" ;;
	c) jx pfa c grep -q "$2" /var/tmp/u.log ;;
	d) jx pfa d grep -q "$2" /var/tmp/u.log ;;
	esac
}
for ver in 4 6; do
	if [ $ver = 4 ]; then a=$A4; b=$B4; fl="inet $B4/32 alias"; fr="inet $B4 -alias"; else a=$A6; b=$B6; fl="inet6 $B6 prefixlen 128 alias"; fr="inet6 $B6 -alias"; fi
	jx pfa a ifconfig "$BIF" $fl >/dev/null 2>&1
	for target in host c d; do
		case $target in
		host) if [ $ver = 4 ]; then dst=$H4; else dst=$H6; fi; w="host$ver" ;;
		c) if [ $ver = 4 ]; then dst=$C4; else dst=$C6; fi; w=c ;;
		d) if [ $ver = 4 ]; then dst=$D4; else dst=$D6; fi; w=d ;;
		esac
		UC=$((UC + 1)); t1="own-$ver-$target-$UC"
		send_from_a "$a" "$dst" "$t1"
		expect allow "a sends from its own address to $target v$ver (control)" arrived "$w" "$t1"
		UC=$((UC + 1)); t2="spoof-$ver-$target-$UC"
		send_from_a "$b" "$dst" "$t2"
		expect deny "a sends from b's address to $target v$ver (spoofed)" arrived "$w" "$t2"
	done
	jx pfa a ifconfig "$BIF" $fr >/dev/null 2>&1
done
expect deny "a reaches a port of the host that no rule names (the host is closed to jails)" sh -c "jexec pfa_a nc -z -w2 $H4 22"
expect allow "a pings the host (ping stays open)" icmp pfa:a "$H4"
$J config unset a firewall.policies --project pfa </dev/null >/dev/null || die "detach hostudp"
settle 10

say "phase 0c: the anchors carry the ICMPv6 that must never be blocked (path MTU discovery) and the neighbour discovery rules"
PRE=$(snapshot)
# (Not automated: the packet-too-big itself. The host's pf refragments what it forwards instead of answering with the error, so
# an ordinary echo does not produce one; it was checked with a forged error, see docs/networking-ipv6.md.)
anchor_has() { pfctl -a jailops/pfa/a -sr 2>/dev/null | grep -q "$1"; }
expect allow "a's anchor passes packet-too-big in both directions" anchor_has "icmp6-type toobig"
expect allow "a's anchor blocks router advertisements from the jail" anchor_has "block drop in quick on .* icmp6-type routeradv"
expect deny "a's anchor does not allow all of fe80::/10 as source" anchor_has "fe80::/10"
expect deny "a's anchor lets :: send anything but a neighbour solicitation to a solicited-node group" anchor_has "from :: to ff02::/16"
jx pfa a ping -6 -c1 -t2 "$B6" >/dev/null 2>&1

say "phase 0d: a jail can use only the addresses and the MAC address it was given"
PRE=$(snapshot)
IFA=$(jx pfa a ifconfig -l | tr ' ' '\n' | grep '^jo' | head -1)
IFB=$(jx pfa b ifconfig -l | tr ' ' '\n' | grep '^jo' | head -1)
MACA=$(jx pfa a ifconfig "$IFA" | awk '/ether/ {print $2}'); MACB=$(jx pfa b ifconfig "$IFB" | awk '/ether/ {print $2}')
EXTRA4=10.91.0.99; EXTRA6=fd91:1::99
# the jails hold /32 and /128 addresses: nothing is on-link, every flow passes the host (and its PF)
expect allow "a holds its IPv4 address as /32" sh -c "jexec pfa_a ifconfig $IFA | grep -q 'inet $A4 netmask 0xffffffff'"
expect allow "a holds its IPv6 address as /128" sh -c "jexec pfa_a ifconfig $IFA | grep -q 'inet6 $A6 prefixlen 128'"
HEA=${IFA%b}a # the host end of a's epair: a's link to the host, and the only one
expect allow "the host routes a's IPv4 address through a's own link" sh -c "route -n get $A4 | grep -q 'interface: $HEA'"
expect allow "the host routes a's IPv6 address through a's own link" sh -c "route -n get -inet6 $A6 | grep -q 'interface: $HEA'"
expect allow "the host end of a's link carries the gateway as a /32" sh -c "ifconfig $HEA | grep -q 'inet $H4 netmask 0xffffffff'"
expect allow "no network has an interface of its own: no bridge of JailOps exists" sh -c "! ifconfig -g bridge | grep -q ."
jx pfa a ifconfig "$IFA" inet "$EXTRA4/32" alias >/dev/null 2>&1
jx pfa a ifconfig "$IFA" inet6 "$EXTRA6" prefixlen 128 alias >/dev/null 2>&1
waitfor_ "the extra IPv6 address is no longer tentative" 30 sh -c "! jexec pfa_a ifconfig $IFA | grep '$EXTRA6' | grep -q tentative"
expect deny "host -> an IPv4 address a gave itself" icmp host "$EXTRA4"
expect deny "b -> an IPv4 address a gave itself" icmp pfa:b "$EXTRA4"
expect deny "host -> an IPv6 address a gave itself" icmp host "$EXTRA6"
expect deny "b -> an IPv6 address a gave itself" icmp pfa:b "$EXTRA6"
expect deny "a sends from its extra IPv4 address" sh -c "jexec pfa_a ping -S $EXTRA4 -c1 -t2 $H4"
expect deny "a sends from its extra IPv6 address" sh -c "jexec pfa_a ping -6 -S $EXTRA6 -c1 -t2 $H6"
jx pfa a ifconfig "$IFA" inet "$EXTRA4" -alias >/dev/null 2>&1
jx pfa a ifconfig "$IFA" inet6 "$EXTRA6" -alias >/dev/null 2>&1
# a takes b's MAC address on its own interface: b is not affected (it is on another link), and a works again with its own
jx pfa a ifconfig "$IFA" ether "$MACB" >/dev/null 2>&1
jx pfa a ping -c1 -t2 "$H4" >/dev/null 2>&1
expect allow "host -> b over IPv4 after a took b's MAC address" icmp host "$B4"
expect allow "host -> b over IPv6 after a took b's MAC address" icmp host "$B6"
expect allow "b -> host after a took b's MAC address" icmp pfa:b "$H4"
jx pfa a ifconfig "$IFA" ether "$MACA" >/dev/null 2>&1

n=0; until jx pfa a ping -c1 -t2 "$H4" >/dev/null 2>&1; do n=$((n + 1)); [ $n -ge 15 ] && break; sleep 2; done # sleep-ok: poll of a condition
expect allow "a -> host with its own MAC address again" icmp pfa:a "$H4"
# no router advertisement is ever passed, and an advertisement of the jail never goes to a multicast group
anchor_has2() { pfctl -a jailops/pfa/a -sr 2>/dev/null | grep -q "$1"; }
expect allow "a's anchor drops router advertisements of the jail" anchor_has2 "block drop in quick on .* inet6 proto ipv6-icmp all icmp6-type routeradv"
expect allow "a's anchor drops redirects of the jail" anchor_has2 "block drop in quick on .* inet6 proto ipv6-icmp all icmp6-type redir"
expect allow "a's anchor drops neighbour advertisements of the jail to multicast groups" anchor_has2 "block drop in quick on .* inet6 proto ipv6-icmp from any to ff02::/16 icmp6-type neighbradv"
expect deny "a's anchor lets the jail advertise from addresses that are not its own" anchor_has2 "pass in quick .*from any to any icmp6-type neighbradv"

if [ -n "${FORGE_BIN:-}" ] && [ -x "$FORGE_BIN" ]; then
say "phase 0e: forged frames from inside a jail (scripts/forge) change nothing real"
PRE=$(snapshot)
GW=${IFA%b}a # the host end of a's own link
EVID="${EVID_DIR:-/var/tmp/jailops-forge}/forgery-$(hostname -s 2>/dev/null || hostname)-$(date +%Y%m%d).txt"
mkdir -p "$(dirname "$EVID")" 2>/dev/null
: > "$EVID"
log() { printf '%s\n' "$*" | tee -a "$EVID"; }
unhide_bpf() { # unhide_bpf PROJECT NAME
	r=$(jls -j "${1}_${2}" devfs_ruleset 2>/dev/null) || return 1
	root=$(jls -j "${1}_${2}" path 2>/dev/null) || return 1
	devfs -m "$root/dev" rule -s "$r" add path 'bpf*' unhide >/dev/null 2>&1
	devfs -m "$root/dev" rule -s "$r" applyset >/dev/null 2>&1
	cp "$FORGE_BIN" "$root/tmp/forge" && chmod +x "$root/tmp/forge"
}
unhide_bpf pfa a || die "forge: could not reach into pfa_a"
GWMAC=$(ifconfig "$GW" | awk '/ether/ {print $2}')
GWB=${IFB%b}a # the host end of b's own link
# what the host knows about b on b's own link; an entry for the same address that a forged frame made on the link of
# another jail is on that link only, and the host never sends to b through it (route_b_via_own)
arpcache_b() { arp -an | awk -v a="($B4)" -v i="$GWB" '$2==a && $6==i {print $4}'; }
route_b_via_own() { [ "$(route -n get "$B4" 2>/dev/null | awk '/interface:/ {print $2}')" = "$GWB" ]; }
ndcache_b() { ndp -an | awk -v a="$B6" '$1==a {print $2}'; }
jexec_b_gw_mac() { jexec pfa_b ndp -an 2>/dev/null | awk '/fe80::1%/ {print $2; exit}'; }
anchorA_neighbradv_pkts() { pfctl -a "jailops/pfa/a" -sr -v 2>/dev/null | grep -A1 "icmp6-type neighbradv$" | awk '/Packets:/ {s+=$5} END {print s+0}'; }
same() { [ "$1" = "$2" ]; } # same OLD NEW
unchanged_arp_b()    { same "$1" "$(arpcache_b)"; }
unchanged_nd_b()     { same "$1" "$(ndcache_b)"; }
unchanged_bgw_cache() { same "$1" "$(jexec_b_gw_mac)"; }
unchanged_a_v6()     { same "$1" "$(jexec pfa_a ifconfig "$IFA" | awk '/inet6/ {print $2}' | sort | tr '\n' ' ')"; }
unchanged_a_v4()     { same "$1" "$(jexec pfa_a ifconfig "$IFA" | awk '/inet /{print $2}')"; }
b_reaches_host_v6()  { jexec pfa_b ping -6 -c1 -t2 "$H6" >/dev/null 2>&1; }
neighbradv_blocked() { n=$(anchorA_neighbradv_pkts); [ "${n:-0}" -gt 0 ]; }

log "== phase 0e forgery evidence: $(date -u '+%Y-%m-%dT%H:%M:%SZ') host $(hostname) =="
log "jails: a=$A4/$A6 mac=$MACA  b=$B4/$B6  host end of a=$GW/$GWMAC"

# -- a continuous ping of b from the host runs for the whole phase: the victim must keep flowing throughout.
: > "$work/bg.log"
( n=0; lost=0; while [ $n -lt 60 ]; do if ping -c1 -t1 "$B4" >/dev/null 2>&1; then :; else lost=$((lost + 1)); fi; n=$((n + 1)); sleep 0.5; done; echo "$lost" > "$work/bg.log" ) &
BGPID=$!

echo "-- forged ARP reply: a claims the gateway, to b" | tee -a "$EVID"
before_bgw=$(jexec_b_gw_mac)
before=$(arpcache_b)
jx pfa a /tmp/forge arp -if "$IFA" -eth-dst "$MACB" -eth-src "$MACA" -op reply -sha "$MACA" -spa "$H4" -tha "$MACB" -tpa "$A4" 2>&1 | tee -a "$EVID"
sleep 1 # sleep-ok: what a forged frame must not change is looked at after the frame had its time
expect allow "ARP reply forgery (a->b, claims the gateway): b's cache for the gateway is unaffected" unchanged_bgw_cache "$before_bgw"

echo "-- forged ARP reply: a claims b, to the host" | tee -a "$EVID"
jx pfa a /tmp/forge arp -if "$IFA" -eth-dst "$GWMAC" -eth-src "$MACA" -op reply -sha "$MACA" -spa "$B4" -tha "$GWMAC" -tpa "$H4" 2>&1 | tee -a "$EVID"
sleep 1 # sleep-ok: what a forged frame must not change is looked at after the frame had its time
expect allow "ARP reply forgery (a->host, claims b): the host's cache for b on b's own link is unchanged" unchanged_arp_b "$before"
expect allow "and the host still sends to b through b's own link" route_b_via_own

echo "-- forged ARP request broadcast: a claims b's address" | tee -a "$EVID"
jx pfa a /tmp/forge arp -if "$IFA" -eth-dst ff:ff:ff:ff:ff:ff -eth-src "$MACA" -op request -sha "$MACA" -spa "$B4" -tpa "$H4" 2>&1 | tee -a "$EVID"
sleep 1 # sleep-ok: what a forged frame must not change is looked at after the frame had its time
expect allow "ARP request forgery (a broadcasts as b): the host's cache for b on b's own link is still unchanged" unchanged_arp_b "$before"
expect allow "and the host still sends to b through b's own link" route_b_via_own

echo "-- forged unicast NA: a claims the gateway's address, to b" | tee -a "$EVID"
beforeb=$(jexec_b_gw_mac)
jx pfa a /tmp/forge nd -type na -src "$A6" -dst "$B6" -target fe80::1 -if "$IFA" -lladdr "$MACA" 2>&1 | tee -a "$EVID"
sleep 1 # sleep-ok: what a forged frame must not change is looked at after the frame had its time
expect allow "unicast NA forgery (a->b, claims the gateway): b's cache for the gateway is unchanged" unchanged_bgw_cache "$beforeb"

echo "-- forged multicast NA: a claims b's address, to ff02::1" | tee -a "$EVID"
beforeh=$(ndcache_b)
jx pfa a /tmp/forge nd -type na -src "$A6" -dst ff02::1 -target "$B6" -if "$IFA" -lladdr "$MACA" 2>&1 | tee -a "$EVID"
sleep 1 # sleep-ok: what a forged frame must not change is looked at after the frame had its time
expect allow "multicast NA forgery (a claims b, to all nodes): the host's cache for b is unchanged" unchanged_nd_b "$beforeh"
expect allow "the anchor's neighbradv-block counter on a saw the attempt" neighbradv_blocked

echo "-- forged NS (unicast, not DAD): a solicits for b's address; b must not be disturbed" | tee -a "$EVID"
jx pfa a /tmp/forge nd -type ns -src "$A6" -dst "$B6" -target "$B6" -if "$IFA" -lladdr "$MACA" 2>&1 | tee -a "$EVID"
sleep 1 # sleep-ok: what a forged frame must not change is looked at after the frame had its time
expect allow "NS forgery: b -> host v6 still works" b_reaches_host_v6

echo "-- forged RA with an autonomous prefix, spoofing the gateway's link-local source" | tee -a "$EVID"
before_addrs=$(jexec pfa_a ifconfig "$IFA" | awk '/inet6/ {print $2}' | sort | tr '\n' ' ')
ra_out=$(jx pfa a /tmp/forge nd -type ra -src fe80::1 -dst ff02::1 -if "$IFA" 2>&1)
echo "$ra_out" | tee -a "$EVID"
if echo "$ra_out" | grep -q "can't assign requested address"; then
	log "note: the RA was never sent: a raw socket inside the jail cannot bind to fe80::1 (not its own address)."
	log "      PRIV_NETINET_BINDANY is unavailable inside a jail (EADDRNOTAVAIL), independently of pf."
else
	log "the RA was sent (bind succeeded); the anchor's drop is the only defence for it"
fi
sleep 2 # sleep-ok: what a forged frame must not change is looked at after the frame had its time
expect allow "RA forgery: a's address set is unchanged (no SLAAC), sent or not" unchanged_a_v6 "$before_addrs"

echo "-- forged packet-too-big (sanity: the tool and the anchor do not crash on it; same bind restriction may apply)" | tee -a "$EVID"
jx pfa a /tmp/forge nd -type ptb -src "$H6" -dst "$A6" -target "$B6" -if "$IFA" 2>&1 | tee -a "$EVID"

echo "-- DHCP discover (real dhclient, no forged frame needed): a's address must not change" | tee -a "$EVID"
before4=$(jexec pfa_a ifconfig "$IFA" | awk '/inet /{print $2}')
jx pfa a timeout 5 dhclient -n "$IFA" 2>&1 | tee -a "$EVID"
expect allow "DHCP discover: a's address is unchanged" unchanged_a_v4 "$before4"

echo "-- a jail cannot sniff another's traffic: a captures on its own link while the host and b talk" | tee -a "$EVID"
: > "$work/sniff.txt"
jx pfa a timeout -s INT 6 tcpdump -ni "$IFA" -c 3 "host $B4 or host $B6" > "$work/sniff.txt" 2>&1 &
SNIFF=$!
sleep 1 # sleep-ok: the sniffer is up before the traffic starts
n=0; while [ $n -lt 4 ]; do ping -c1 -t1 "$B4" >/dev/null 2>&1; ping -6 -c1 -t1 "$B6" >/dev/null 2>&1; jexec pfa_b ping -c1 -t1 "$H4" >/dev/null 2>&1; n=$((n + 1)); done
wait "$SNIFF" 2>/dev/null
cat "$work/sniff.txt" >> "$EVID"
expect allow "a captured none of the traffic between the host and b" grep -q '^0 packets captured' "$work/sniff.txt"

echo "-- no way around the host: a gives itself a direct route to b on its own link; nothing answers for b there" | tee -a "$EVID"
jx pfa a route add -host "$B4" -interface "$IFA" >/dev/null 2>&1
jx pfa a route add -inet6 -host "$B6" -interface "$IFA" >/dev/null 2>&1
expect deny "a -> b over IPv4 through a direct route on its own link (nothing answers ARP for b)" icmp pfa:a "$B4"
expect deny "a -> b over IPv6 through a direct route on its own link (nothing answers neighbour discovery for b)" icmp pfa:a "$B6"
jx pfa a route delete -host "$B4" >/dev/null 2>&1
jx pfa a route delete -inet6 -host "$B6" >/dev/null 2>&1
expect allow "a -> b through the host again once the routes are gone (the default policy is open)" icmp pfa:a "$B4"

echo "-- spoofed-source IPv4 in the same /24 (also covered in phase 0b/0d; repeated here with evidence)" | tee -a "$EVID"
expect deny "a sends from b's address to the host (spoofed source)" sh -c "jexec pfa_a ping -S $B4 -c1 -t2 $H4"

wait "$BGPID" 2>/dev/null
lost=$(cat "$work/bg.log" 2>/dev/null)
log "background ping of b from the host during the attack: lost=${lost:-unknown} of 60"
expect allow "the victim (b) kept answering the host through the whole attack (at most 2 of 60 lost)" sh -c "[ '${lost:-99}' -le 2 ]"

if [ -z "${PF_FAST:-}" ]; then
	echo "-- uplink capture: none of the forged frames or packets leave the host (jails are not bridged to the uplink)"
	UPLINK=$(ifconfig -l | tr ' ' '\n' | grep -vE '^(lo0|pflog0|jo|epair)' | head -1)
	if [ -n "$UPLINK" ]; then
		: > "$work/uplink.pcap.txt"
		timeout 4 tcpdump -ni "$UPLINK" -c 5 "host $B4 or host $B6" > "$work/uplink.pcap.txt" 2>&1 &
		TD=$!
		sleep 1 # sleep-ok: the sniffer is up before the frame is sent
		jx pfa a /tmp/forge arp -if "$IFA" -eth-dst ff:ff:ff:ff:ff:ff -eth-src "$MACA" -op request -sha "$MACA" -spa "$B4" -tpa "$H4" >/dev/null 2>&1
		wait "$TD" 2>/dev/null
		cat "$work/uplink.pcap.txt" >> "$EVID"
		expect allow "no forged packet reached the uplink ($UPLINK)" sh -c "! grep -qE 'ARP|$B4|$B6' '$work/uplink.pcap.txt'"
	fi
fi
log "evidence saved to $EVID"
jx pfa a ifconfig "$IFA" down 2>/dev/null; jx pfa a ifconfig "$IFA" up 2>/dev/null
else
	say "phase 0e: skipped (set FORGE_BIN=/path/to/forge-freebsd-<arch> to run the forged-frame probes)"
fi

say "phase 1: the project's mandatory policy denies everything in (egress allowed)"
PRE=$(snapshot)
policy pfa base 'default_in: deny
default_out: allow'
$J project set pfa --firewall-policy base </dev/null >/dev/null || die "project firewall"
settle 10
matrix host deny deny deny deny deny
matrix pfa:b deny deny deny deny deny
matrix pfa:c deny deny deny deny deny
matrix pfb:o deny deny deny deny deny
expect allow "a -> host address v4 icmp (egress allowed)" icmp pfa:a "$H4"
expect allow "a -> host address v6 icmp (egress allowed)" icmp pfa:a "$H6"
expect deny "a -> b v4 icmp (b denies in too)" icmp pfa:a "$B4"
expect deny "a -> b v6 icmp (b denies in too)" icmp pfa:a "$B6"

say "phase 2: a's own policy opens exactly what it names"
PRE=$(snapshot)
policy pfa friends-dummy 'default_in: deny
default_out: allow' # a policy to be replaced below, so that "edit" is exercised
$J firewall address-set create friends --address "$B4" --address "$B6" --project pfa </dev/null >/dev/null || die "address set"
$J firewall address-set create office --address "$H4" --address "$H6" --project pfa </dev/null >/dev/null || die "address set office"
$J firewall address-set create common --address "$O4" --address "$O6" --project pfa </dev/null >/dev/null || die "address set common"
policy pfa web "default_in: deny
default_out: allow
rules:
  - {name: from-friends, action: allow, direction: in, proto: tcp, from: ['set:friends'], ports: ['8080']}
  - {name: from-web-tag, action: allow, direction: in, proto: tcp, from: ['tag:web'], ports: ['9090']}
  - {name: host-ping4, action: allow, direction: in, proto: icmp, from: ['$H4']}
  - {name: host-ping6, action: allow, direction: in, proto: icmp6, from: ['$H6']}
  - {name: other-project-udp, action: allow, direction: in, proto: udp, from: ['set:common'], ports: ['5353']}"
policy pfb toa "default_in: allow
default_out: allow
rules:
  - {name: to-a-udp, action: allow, direction: out, proto: udp, to: ['$A4', '$A6'], ports: ['5353']}"
$J config set a firewall.policies web --project pfa </dev/null >/dev/null || die "attach web"
$J config set o firewall.policies toa --project pfb </dev/null >/dev/null || die "attach toa"
settle 10
matrix host allow deny deny deny deny
matrix pfa:b deny allow deny deny deny
matrix pfa:c deny deny allow deny deny
matrix pfb:o deny deny deny deny allow

say "phase 3: a policy cannot weaken the project's default (the floor)"
PRE=$(snapshot)
policy pfa open 'default_in: allow
default_out: allow'
$J config set b firewall.policies open --project pfa </dev/null >/dev/null || die "attach open"
# this action is meant to change nothing (the project floor wins): anchors converge in about 4s elsewhere, so 15s is plenty
SETTLE_WAIT=15 settle 10
# b has its own policy 'open' (default allow) but the project says default deny in: still denied
for ver in 4 6; do
	if [ $ver = 4 ]; then b=$B4; else b=$B6; fi
	expect deny "host -> b v$ver icmp (own default allow, project default deny)" icmp host "$b"
	expect deny "c -> b v$ver icmp" icmp pfa:c "$b"
done

say "phase 4: egress filtering. c may only open tcp 9090 to a"
PRE=$(snapshot)
policy pfa lock "default_in: deny
default_out: deny
rules:
  - {name: to-a-9090, action: allow, direction: out, proto: tcp, to: ['$A4', '$A6'], ports: ['9090']}"
$J config set c firewall.policies lock --project pfa </dev/null >/dev/null || die "attach lock"
settle 10
for ver in 4 6; do
	if [ $ver = 4 ]; then a=$A4; b=$B4; h=$H4; else a=$A6; b=$B6; h=$H6; fi
	expect allow "c -> a v$ver tcp 9090 (allowed by c's egress and a's ingress)" tcp pfa:c "$a" 9090
	expect deny "c -> a v$ver tcp 8080 (c's egress denies)" tcp pfa:c "$a" 8080
	expect deny "c -> b v$ver icmp (c's egress denies)" icmp pfa:c "$b"
	expect allow "c -> host v$ver icmp (ping to the host stays open)" icmp pfa:c "$h"
done

say "phase 5: a jail with two policies gets the rules of both"
PRE=$(snapshot)
policy pfa extra5 "default_in: deny
default_out: allow
rules:
  - {name: tcp-2222-from-friends, action: allow, direction: in, proto: tcp, from: ['set:friends'], ports: ['2222']}"
$J config set a firewall.policies web,extra5 --project pfa </dev/null >/dev/null || die "attach web and extra5"
settle 10
# web opens tcp 8080 for b, extra5 opens tcp 2222 for b: both are in a's anchor
matrix pfa:b deny allow deny allow deny
PRE=$(snapshot)
$J config set a firewall.policies web --project pfa </dev/null >/dev/null || die "attach web again"
settle 10
matrix pfa:b deny allow deny deny deny

say "phase 5b: a deny rule wins over an allow rule of another policy of the same jail, in either order; a disabled rule decides nothing"
PRE=$(snapshot)
policy pfa quiet5 "default_in: deny
default_out: allow
rules:
  - {name: no-8080-from-friends, action: deny, direction: in, proto: tcp, from: ['set:friends'], ports: ['8080']}"
# web (listed first) allows tcp 8080 for b; quiet5 (listed after it) denies it: the deny wins
$J config set a firewall.policies web,quiet5 --project pfa </dev/null >/dev/null || die "attach web and quiet5"
settle 10
matrix pfa:b deny deny deny deny deny
matrix pfa:c deny deny allow deny deny # what the deny does not match is decided as before: c's tcp 9090 from the tag
# the other order of the two policies gives the same answers
PRE=$(snapshot)
$J config set a firewall.policies quiet5,web --project pfa </dev/null >/dev/null || die "attach quiet5 and web"
settle 10
matrix pfa:b deny deny deny deny deny
matrix pfa:c deny deny allow deny deny
# switch the deny rule off: web's allow decides again
PRE=$(snapshot)
policy pfa quiet5 "default_in: deny
default_out: allow
rules:
  - {name: no-8080-from-friends, action: deny, direction: in, proto: tcp, from: ['set:friends'], ports: ['8080'], disabled: true}"
settle 10
matrix pfa:b deny allow deny deny deny
# a disabled allow rule lets nothing through: tcp 2222 from friends stays closed
PRE=$(snapshot)
policy pfa quiet5 "default_in: deny
default_out: allow
rules:
  - {name: tcp-2222-from-friends, action: allow, direction: in, proto: tcp, from: ['set:friends'], ports: ['2222'], disabled: true}"
settle 10
matrix pfa:b deny allow deny deny deny
PRE=$(snapshot)
$J config set a firewall.policies web --project pfa </dev/null >/dev/null || die "attach web again"
settle 10
matrix pfa:b deny allow deny deny deny

say "phase 6: pf anchors are real and well formed"
PRE=$(snapshot)
if pfctl -a jailops/pfa/a -sr 2>&1 | grep -q 'foreign'; then pass "a's anchor has the isolation rules"; else bad "a's anchor lacks the isolation rules"; fi
pfctl -a jailops/pfa/a -sr >/dev/null 2>&1 && pass "a's anchor loads and lists" || bad "a's anchor does not list"
for anchor in jailops/pfa/a jailops/pfa/b jailops/pfa/c jailops/pfb/o; do
	n=$(pfctl -a "$anchor" -sr 2>/dev/null | wc -l)
	[ "$n" -gt 3 ] && pass "$anchor has rules ($n)" || bad "$anchor is empty"
done

say "phase 7: a rule change does not interrupt what stays allowed"
PRE=$(snapshot)
ping -c 40 -i 0.25 -W 1000 "$A4" > "$work/ping.out" 2>&1 &
pp=$!
for i in 1 2 3 4; do
	policy pfa web "default_in: deny
default_out: allow
rules:
  - {name: from-friends, action: allow, direction: in, proto: tcp, from: ['set:friends'], ports: ['8080']}
  - {name: from-web-tag, action: allow, direction: in, proto: tcp, from: ['tag:web'], ports: ['9090']}
  - {name: host-ping4, action: allow, direction: in, proto: icmp, from: ['$H4']}
  - {name: host-ping6, action: allow, direction: in, proto: icmp6, from: ['$H6']}
  - {name: other-project-udp, action: allow, direction: in, proto: udp, from: ['set:common'], ports: ['5353']}
  - {name: extra-$i, action: allow, direction: in, proto: tcp, from: ['set:friends'], ports: ['70$i$i']}"
	sleep 2 # sleep-ok: paces the rule changes while a ping runs
done
wait $pp
loss=$(grep -o '[0-9.]*% packet loss' "$work/ping.out" | head -1)
case $loss in
	"0.0% packet loss") pass "no packet lost while the policy was replaced four times" ;;
	*) bad "packets were lost while the policy was replaced: $loss" ;;
esac
# a flow that is still running when its rule is removed must end: traffic that keeps a state alive would otherwise
# go on for ever
ping -c 90 -i 0.5 "$A4" 2>&1 | while read l; do echo "$(date +%s) $l"; done > "$work/live.out" &
lp=$!
waitfor_ "the ping runs" 30 sh -c "grep -q 'bytes from' $work/live.out"
PRE=$(snapshot)
policy pfa web "default_in: deny
default_out: allow
rules:
  - {name: from-friends, action: allow, direction: in, proto: tcp, from: ['set:friends'], ports: ['8080']}"
settle 10
T=$(date +%s)
sleep 8 # sleep-ok: a ping that must stop is watched for a while
late=$(awk -v t="$T" '$1 > t + 3 && /bytes from/' "$work/live.out" | wc -l | tr -d ' ')
[ "$late" = 0 ] && pass "a running ping stopped when its rule was removed" || bad "a running ping went on after its rule was removed ($late replies)"
kill $lp 2>/dev/null; wait $lp 2>/dev/null
expect deny "host -> a icmp after the rule was removed" icmp host "$A4"
expect allow "b -> a tcp 8080 still allowed" tcp pfa:b "$A4" 8080
expect deny "c -> a tcp 9090 after the rule was removed" tcp pfa:c "$A4" 9090

say "phase 8: a restarted jail is never open"
PRE=$(snapshot)
$J restart a --project pfa </dev/null >/dev/null 2>&1 || bad "restart a"
t=0
until jx pfa a true >/dev/null 2>&1; do t=$((t + 1)); [ $t -gt 60 ] && break; sleep 1; done
A4=$(addr4 pfa a); A6=$(addr6 pfa a)
for ad in "$A4" "$A6"; do
	for port in 2222 8080; do jx pfa a daemon -f nc -k -l "$ad" "$port"; done
done
opened=0; reached=0; t=0
while [ $t -lt 20 ]; do
	tcp pfa:b "$A4" 2222 && opened=1
	tcp pfa:b "$A4" 8080 && reached=1
	t=$((t + 1)); sleep 0.5
done
[ $opened -eq 0 ] && pass "the denied port stayed closed after a restart" || bad "the denied port answered after a restart"
[ $reached -eq 1 ] && pass "the allowed port works after a restart" || bad "the allowed port does not answer after a restart"

if [ -z "${PF_FAST:-}" ]; then
	say "phase 9: the reconciler restores a flushed anchor"
	pfctl -a jailops/pfa/a -F rules >/dev/null 2>&1
	t=0; back=0
	while [ $t -lt 90 ]; do
		if pfctl -a jailops/pfa/a -sr 2>/dev/null | grep -q foreign; then back=1; break; fi
		t=$((t + 3)); sleep 3
	done
	[ $back -eq 1 ] && pass "the anchor was restored after $t s" || bad "the flushed anchor was not restored within 90 s"
	expect deny "b -> a tcp 2222 after the restore" tcp pfa:b "$A4" 2222

	say "phase 10: IPv6 neighbour discovery survives its timers"
	sleep 120 # sleep-ok: IPv6 neighbour discovery has timers that need real time
	expect allow "b -> a v6 tcp 8080 after two minutes" tcp pfa:b "$A6" 8080
	expect deny "host -> a v6 icmp after two minutes (no rule)" icmp host "$A6"
	expect deny "b -> a v6 tcp 2222 after two minutes" tcp pfa:b "$A6" 2222
fi
say "phase 11: a port forward (a redirect rule of a policy) brings a connection that arrives on the uplink into the jail"
# A redirect is rendered as "match in on <uplink> ... to (<uplink>) port H rdr-to <jail> port J" and applies only to packets that
# arrive on the uplink. The host cannot test it against itself: what it sends to its own address never arrives on an
# interface. So the uplink of this network is one end of an epair (pfupa, 198.51.100.1/24) whose other end (pfupb,
# 198.51.100.2/24) is moved into a plain VNET jail (pfrdr, not a JailOps jail) that stands for a client on the
# uplink's network: its packets to 198.51.100.1 arrive on the uplink exactly as a remote client's would. What this does
# not cover is a physical uplink with a real remote machine (the NIC, the provider's network); the rule and the anchor
# path (anchor "jailops/*", the project anchor, the jail anchor) are the same.
PRE=$(snapshot)
ep=$(ifconfig epair create 2>/dev/null) || die "epair create"
ifconfig "$ep" name pfupa >/dev/null || die "rename $ep"
ifconfig "${ep%a}b" name pfupb >/dev/null || die "rename ${ep%a}b"
ifconfig pfupa inet 198.51.100.1/24 up || die "address on pfupa"
jail -c name=pfrdr persist vnet vnet.interface=pfupb path=/ host.hostname=pfrdr >/dev/null || die "vnet jail pfrdr"
jexec pfrdr ifconfig pfupb inet 198.51.100.2/24 up || die "address in pfrdr"
jexec pfrdr ifconfig lo0 up >/dev/null 2>&1
$J network create pfa-up --ipv4 10.94.0.1/24 --uplink pfupa --nat </dev/null >/dev/null || die "network pfa-up"
{ $J network grant pfa-net --project pfa && $J network grant pfa-net2 --project pfa && $J network grant pfa-up --project pfa && $J storage grant default --project pfa; } </dev/null >/dev/null || die "grant pfa-up"
$J create r --project pfa --image "$img" --network pfa-up --storage default </dev/null >/dev/null || die "create r"
policy pfa fwd "default_in: deny
default_out: allow
rules:
  - {name: forward-18080, action: allow, direction: in, proto: tcp, redirect: {host_port: 18080, jail_port: 8080}}"
$J config set r firewall.policies fwd --project pfa </dev/null >/dev/null || die "attach fwd"
$J start r --project pfa </dev/null >/dev/null || die "start r"
t=0; until jx pfa r true >/dev/null 2>&1; do t=$((t + 1)); [ $t -gt 60 ] && break; sleep 1; done
R4=$(addr4 pfa r)
[ -n "$R4" ] || die "r has no address"
jx pfa r daemon -f nc -k -l "$R4" 8080 || die "nc server in r"
settle 10
fwd_has() { pfctl -a jailops/pfa/r -sr 2>/dev/null | grep -q "$1"; }
expect allow "r's anchor carries the redirect on the uplink" fwd_has "match in on pfupa inet proto tcp .* port = 18080 rdr-to $R4 port 8080"
expect allow "and a labelled pass rule for what comes out of the translation (the state of the forward belongs to it)" fwd_has "pass in quick on pfupa inet proto tcp from any to $R4 port = [a-z0-9-]* .*label"
expect allow "a client on the uplink reaches r through the forwarded port 18080" sh -c "jexec pfrdr nc -z -w2 198.51.100.1 18080"
expect deny "a client on the uplink does not reach a port that is not forwarded (18081)" sh -c "jexec pfrdr nc -z -w2 198.51.100.1 18081"
# NAT of the network (match out ... nat-to): a connection from r to a machine on the uplink's network arrives from the
# uplink address, never from the jail's own address. The client jail pfrdr listens and says who connected.
jexec pfrdr daemon -f nc -k -l 198.51.100.2 9000 || die "nc server in pfrdr"
jx pfa r daemon -f sh -c 'sleep 20 | nc -w25 198.51.100.2 9000 >/dev/null 2>&1' || die "client connection in r"
waitfor_ "the client connection of r is up" 30 sh -c "jexec pfrdr sockstat -4 -c -P tcp 2>/dev/null | grep -q '198.51.100.2:9000 '"
nat_from_uplink() { jexec pfrdr sockstat -4 -c -P tcp 2>/dev/null | grep -Eq '198\.51\.100\.2:9000 +198\.51\.100\.1:'; }
nat_from_jail() { jexec pfrdr sockstat -4 -c -P tcp 2>/dev/null | grep -Eq '198\.51\.100\.2:9000 +10\.94\.0\.'; }
expect allow "a connection of r to the uplink's network is translated to the uplink address" nat_from_uplink
expect deny "it does not arrive from the jail's own address" nat_from_jail
# the states of a removed forward are ended: a client keeps a connection open through the forward, the policy then
# loses the rule, and the state (which pf keeps after a rule is gone) must not survive the next load of the anchor
jexec pfrdr daemon -f sh -c 'sleep 120 | nc 198.51.100.1 18080 >/dev/null 2>&1' || die "long connection through the forward"
waitfor_ "the connection through the forward has a state" 30 sh -c "pfctl -ss 2>/dev/null | grep -q '198.51.100.1:18080'"
expect allow "the open connection through the forward has a state" sh -c "[ \"\$(pfctl -ss 2>/dev/null | grep -c '198\.51\.100\.1:18080')\" -ge 1 ]"
policy pfa fwd "default_in: deny
default_out: allow
rules: []"
settle
expect allow "removing the forward ends the state of the connection that came through it" sh -c "[ \"\$(pfctl -ss 2>/dev/null | grep -c '198\.51\.100\.1:18080')\" -eq 0 ]"
expect deny "the removed forward no longer admits a new connection" sh -c "jexec pfrdr nc -z -w2 198.51.100.1 18080"
jail -r pfrdr >/dev/null 2>&1
ifconfig pfupa destroy >/dev/null 2>&1

say "phase 12: bandwidth limits of a device (dummynet pipes) slow what the jail sends and what it receives, each by itself, and stall nothing"
# The host listens on its address on the network of jail d (HD4); d sends 1.5 MB to it. Without a limit that takes a
# moment; with a limit of 2 Mbit/s (250 kB/s) it takes six seconds. A limit is a dummynet pipe of JailOps's range (40000 to
# 59999) per direction: the anchor of d sends what the jail sends (egress) and what the jail receives (ingress) into
# its pipes, on the jail's own link. Both directions are measured with real transfers of one connection each, counting the
# bytes that arrived, so that a transfer that did not finish is told from a slow one. nc -N ends the connection with the data.
PRE=$(snapshot)
SZ=1536000
XN=0
# (jx sets the shell variables p and n: the helpers below keep their own names)
xfer_up() { # xfer_up JAIL HOSTADDR: the jail connects to the host and sends 1.5 MB; prints "SECONDS BYTES"
	XN=$((XN + 1)); xp=$((9300 + XN)); rm -f "$work/recv.$xp"
	daemon -f sh -c "nc -l $2 $xp > $work/recv.$xp"
	waitfor_ "the listener of the transfer is up" 15 sh -c "sockstat -4 -6 -l | grep -q ':$xp '"
	xs=$(date +%s)
	jx pfa "$1" sh -c "dd if=/dev/zero bs=100k count=15 2>/dev/null | nc -N -w20 $2 $xp" >/dev/null 2>&1
	xe=$(date +%s)
	waitfor_ "the data has been written" 10 sh -c "[ \"\$(stat -f %z $work/recv.$xp 2>/dev/null || echo 0)\" -ge $SZ ]" || true
	echo "$((xe - xs)) $(stat -f %z "$work/recv.$xp" 2>/dev/null || echo 0)"
}
xfer_served() { # xfer_served JAIL JAILADDR: the host connects to the jail, which sends 1.5 MB (a server in the jail answering)
	XN=$((XN + 1)); xp=$((9300 + XN)); rm -f "$work/recv.$xp"
	jx pfa "$1" daemon -f sh -c "dd if=/dev/zero bs=100k count=15 2>/dev/null | nc -N -l $2 $xp"
	waitfor_ "the server of the transfer is up" 15 sh -c "jexec pfa_$1 sockstat -4 -6 -l | grep -q ':$xp '"
	xs=$(date +%s)
	nc -d -w20 "$2" "$xp" > "$work/recv.$xp" 2>/dev/null
	xe=$(date +%s)
	waitfor_ "the data has been written" 10 sh -c "[ \"\$(stat -f %z $work/recv.$xp 2>/dev/null || echo 0)\" -ge $SZ ]" || true
	echo "$((xe - xs)) $(stat -f %z "$work/recv.$xp" 2>/dev/null || echo 0)"
}
xfer_down() { # xfer_down JAIL JAILADDR: the host connects to the jail and sends 1.5 MB into it
	XN=$((XN + 1)); xp=$((9300 + XN)); xj=$1
	jexec "pfa_$xj" sh -c "rm -f /var/tmp/recv.$xp"
	jexec "pfa_$xj" daemon -f sh -c "nc -l $2 $xp > /var/tmp/recv.$xp"
	waitfor_ "the listener of the transfer is up" 15 sh -c "jexec pfa_$xj sockstat -4 -6 -l | grep -q ':$xp '"
	xs=$(date +%s)
	dd if=/dev/zero bs=100k count=15 2>/dev/null | nc -N -w20 "$2" "$xp" >/dev/null 2>&1
	xe=$(date +%s)
	waitfor_ "the data has been written" 10 sh -c "[ \"\$(jexec pfa_$xj stat -f %z /var/tmp/recv.$xp 2>/dev/null || echo 0)\" -ge $SZ ]" || true
	echo "$((xe - xs)) $(jexec "pfa_$xj" stat -f %z "/var/tmp/recv.$xp" 2>/dev/null || echo 0)"
}
pipes() { dnctl pipe list 2>/dev/null | grep -Ec '^0*[45][0-9]{4}:'; }
within() { # within LOW HIGH "SECONDS BYTES": a complete transfer that took LOW to HIGH-1 seconds
	wl=$1; wh=$2; wr=$3
	set -- $wr
	[ "${2:-0}" -eq "$SZ" ] && [ "${1:-999}" -ge "$wl" ] && [ "${1:-999}" -lt "$wh" ]
}
check_xfer() { # check_xfer LOW HIGH DESC FUNC ARGS...: one more try when the data did not all arrive (a lost SYN, not a limit)
	lo=$1; hi=$2; desc=$3; shift 3
	XN=$((XN + 10)) # the transfer runs in a subshell: every try gets ports of its own
	r=$("$@")
	case $r in *" $SZ") ;; *) printf 'NOTE  %s: the transfer was incomplete (%s), trying once more\n' "$desc" "$r"; sleep 2; XN=$((XN + 10)); r=$("$@") ;; esac
	expect allow "$desc ($r: seconds, bytes)" within "$lo" "$hi" "$r"
}
D4J=$(addr4 pfa d)
# the project's mandatory policy closes d to everything that comes in: a policy of its own opens the ports of the transfers
policy pfa xfer "default_in: deny
default_out: allow
rules:
  - {name: transfer-ports, action: allow, direction: in, proto: tcp, ports: ['9300-9999']}
  - {name: to-host-transfer-ports, action: allow, direction: out, proto: tcp, to: [host], ports: ['9300-9999']}"
$J config set d firewall.policies xfer --project pfa </dev/null >/dev/null || die "attach xfer to d"
$J config set a firewall.policies web,xfer --project pfa </dev/null >/dev/null || die "attach xfer to a"
settle
check_xfer 0 3 "an unlimited jail sends 1.5 MB to the host in less than 3 s" xfer_up d $HD4
check_xfer 0 3 "the host sends 1.5 MB into the jail in less than 3 s" xfer_down d $D4J
$J config set d nic.eth0.egress 2M --project pfa </dev/null >/dev/null || die "set the egress limit of d"
settle
t=0; until [ "$(pipes)" -eq 1 ] || [ $t -ge 30 ]; do sleep 1; t=$((t + 1)); done
expect allow "an egress limit made one pipe of JailOps's range" sh -c "[ \"\$(dnctl pipe list 2>/dev/null | grep -Ec '^0*[45][0-9]{4}:')\" -eq 1 ]"
# the two match rules carry the pipe of the one limited direction (the second number of a pair is the reverse direction of
# the state), so a connection is shaped whichever side opens it; pfctl prints a pair with a zero second number as one number
ONLY='dnpipe( [0-9]+$|\([0-9]+, ?0\))'
ZERO='dnpipe\(0, ?[0-9]+\)'
expect allow "the anchor of d shapes what the jail sends, in both directions of a state, and nothing else" sh -c "pfctl -a jailops/pfa/d -sr 2>/dev/null | grep -Eq 'match in on .* $ONLY' && pfctl -a jailops/pfa/d -sr 2>/dev/null | grep -Eq 'match out on .* $ZERO'"
EPIPE=$(pfctl -a jailops/pfa/d -sr 2>/dev/null | sed -n 's/.*match in on .* dnpipe \([0-9]*\).*/\1/p' | head -1)
check_xfer 4 20 "egress 2 Mbit/s, a connection the jail starts: 1.5 MB take 4 to 19 s" xfer_up d $HD4
check_xfer 4 20 "egress 2 Mbit/s, a connection the host starts, the jail answering: 4 to 19 s" xfer_served d $D4J
check_xfer 0 3 "egress 2 Mbit/s does not slow what is sent into the jail: under 3 s" xfer_down d $D4J
check_xfer 0 3 "a jail without a limit is not slowed down: under 3 s" xfer_up a $H4
# a limit of another jail does not renumber the pipe of this one: the numbers are given once
$J config set a nic.eth0.egress 50M --project pfa </dev/null >/dev/null || die "set the egress limit of a"
settle
EPIPE2=$(pfctl -a jailops/pfa/d -sr 2>/dev/null | sed -n 's/.*match in on .* dnpipe \([0-9]*\).*/\1/p' | head -1)
expect allow "the pipe of d keeps its number when another jail gets a limit" [ "$EPIPE2" = "$EPIPE" ]
$J config unset a nic.eth0.egress --project pfa </dev/null >/dev/null || die "unset the egress limit of a"
settle
$J config unset d nic.eth0.egress --project pfa </dev/null >/dev/null || die "unset the egress limit of d"
$J config set d nic.eth0.ingress 2M --project pfa </dev/null >/dev/null || die "set the ingress limit of d"
settle
t=0; until [ "$(pipes)" -eq 1 ] || [ $t -ge 30 ]; do sleep 1; t=$((t + 1)); done
expect allow "an ingress limit made one pipe" sh -c "[ \"\$(dnctl pipe list 2>/dev/null | grep -Ec '^0*[45][0-9]{4}:')\" -eq 1 ]"
expect allow "the anchor of d shapes what the jail receives, in both directions of a state, and nothing else" sh -c "pfctl -a jailops/pfa/d -sr 2>/dev/null | grep -Eq 'match out on .* $ONLY' && pfctl -a jailops/pfa/d -sr 2>/dev/null | grep -Eq 'match in on .* $ZERO'"
check_xfer 4 20 "ingress 2 Mbit/s, the host sends 1.5 MB into the jail: 4 to 19 s" xfer_down d $D4J
check_xfer 0 3 "ingress 2 Mbit/s does not slow what the jail sends: under 3 s" xfer_up d $HD4
check_xfer 0 3 "ingress 2 Mbit/s does not slow what the jail answers: under 3 s" xfer_served d $D4J
$J config set d nic.eth0.egress 2M --project pfa </dev/null >/dev/null || die "set both limits on d"
settle
t=0; until [ "$(pipes)" -eq 2 ] || [ $t -ge 30 ]; do sleep 1; t=$((t + 1)); done
expect allow "both limits make two pipes" sh -c "[ \"\$(dnctl pipe list 2>/dev/null | grep -Ec '^0*[45][0-9]{4}:')\" -eq 2 ]"
check_xfer 4 20 "both limits: what the jail sends takes 4 to 19 s" xfer_up d $HD4
check_xfer 4 20 "both limits: what the jail receives takes 4 to 19 s" xfer_down d $D4J
# the limits survive a restart of the jail
$J restart d --project pfa </dev/null >/dev/null 2>&1 || bad "restart d"
t=0; until jx pfa d true >/dev/null 2>&1; do t=$((t + 1)); [ $t -gt 60 ] && break; sleep 1; done
D4J=$(addr4 pfa d)
settle
check_xfer 4 20 "after a restart the limit on what the jail receives still holds: 4 to 19 s" xfer_down d $D4J
$J config unset d nic.eth0.egress --project pfa </dev/null >/dev/null || die "unset the egress limit of d"
$J config unset d nic.eth0.ingress --project pfa </dev/null >/dev/null || die "unset the ingress limit of d"
settle
t=0; until [ "$(pipes)" -eq 0 ] || [ $t -ge 30 ]; do sleep 1; t=$((t + 1)); done
expect allow "removing the limits removes the pipes" sh -c "[ \"\$(dnctl pipe list 2>/dev/null | grep -Ec '^0*[45][0-9]{4}:')\" -eq 0 ]"
expect allow "and the anchor no longer names one" sh -c "! pfctl -a jailops/pfa/d -sr 2>/dev/null | grep -q dnpipe"
check_xfer 0 3 "and the jail is fast again: under 3 s" xfer_up d $HD4
check_xfer 0 3 "and fast in the other direction: under 3 s" xfer_down d $D4J
pkill -f "nc -l " >/dev/null 2>&1
$J config unset d firewall.policies --project pfa </dev/null >/dev/null 2>&1
$J config set a firewall.policies web --project pfa </dev/null >/dev/null 2>&1

say "a jail with a link and no address has an anchor that closes both directions (docs/networking.md)"
$J create n --project pfa --image "$img" --network pfa-net=none --storage default </dev/null >/dev/null || die "create n (no address)"
$J start n --project pfa </dev/null >/dev/null || die "start n"
waitfor_ "n runs" 90 jexec pfa_n true
waitfor_ "the anchor of n is loaded" 90 sh -c "pfctl -a jailops/pfa/n -sr 2>/dev/null | grep -q ."
expect allow "the anchor of n drops what comes in on its link" sh -c "pfctl -a jailops/pfa/n -sr 2>/dev/null | grep -Eq '^block drop in quick on [^ ]+ all'"
expect allow "the anchor of n drops what goes out on its link" sh -c "pfctl -a jailops/pfa/n -sr 2>/dev/null | grep -Eq '^block drop out quick on [^ ]+ all'"
NHOST=$(pfctl -a jailops/pfa/n -sr 2>/dev/null | sed -n 's/^block drop in quick on \([^ ]*\) all.*/\1/p' | head -n 1)
NIF=$(jx pfa n ifconfig -l | tr ' ' '\n' | grep -v '^lo' | head -n 1)
NGW=$(ifconfig "$NHOST" 2>/dev/null | awk '/ether/ {print $2}')
if [ -n "$NHOST" ] && [ -n "$NIF" ] && [ -n "$NGW" ]; then
	# the jail takes the address of another jail, a static ARP entry for the gateway (the MAC of the host's end) and a route
	jx pfa n ifconfig "$NIF" inet "$A4/32" alias >/dev/null 2>&1
	jx pfa n route add -host "$H4" -interface "$NIF" >/dev/null 2>&1
	jx pfa n arp -s "$H4" "$NGW" >/dev/null 2>&1
	expect deny "n cannot ping the host in the name of jail a" jx pfa n ping -S "$A4" -c1 -t2 "$H4"
else
	bad "n: could not read its interfaces (host end '$NHOST', jail end '$NIF', MAC '$NGW')"
fi
$J stop n --project pfa </dev/null >/dev/null 2>&1

say "any as the destination of an allow rule is not the host (docs/networking.md)"
daemon -f nc -l "$H4" 2299 # a service of the host on the gateway address of the network
jx pfa b daemon -f nc -k -l "$B4" 7777 # a service of another jail of the project, which its policy opens (the project's default is deny in)
$J firewall rule add open in --project pfa --action allow --proto tcp --port 7777 --comment "the service of the any test" </dev/null >/dev/null || die "rule 7777 in b's policy"
{ $J firewall policy create anyout --project pfa --default-in deny --default-out deny \
	&& $J firewall rule add anyout out --project pfa --action allow --proto tcp --port 2299 --comment "any port 2299" \
	&& $J firewall rule add anyout out --project pfa --action allow --proto tcp --port 7777 --comment "any port 7777"; } </dev/null >/dev/null || die "policy anyout"
$J create m --project pfa --image "$img" --network pfa-net --storage default --firewall-policy anyout </dev/null >/dev/null || die "create m"
$J start m --project pfa </dev/null >/dev/null || die "start m"
waitfor_ "m runs" 90 jexec pfa_m true
waitfor_ "the anchor of m is loaded" 90 sh -c "pfctl -a jailops/pfa/m -sr 2>/dev/null | grep -q ."
settle
expect allow "m reaches the port 7777 of jail b: any is every address of the project but the host" tcp pfa:m "$B4" 7777
expect deny "m does not reach the port 2299 of the host: any is not the host" tcp pfa:m "$H4" 2299
$J firewall rule add anyout out --project pfa --action allow --proto tcp --port 2299 --to host --comment "the host, named" </dev/null >/dev/null || die "rule to host"
settle
expect allow "once the rule names the host, m reaches its port 2299" tcp pfa:m "$H4" 2299
pkill -f "nc -l $H4 2299" >/dev/null 2>&1
jx pfa b pkill -f "nc -k -l $B4 7777" >/dev/null 2>&1
$J stop m --project pfa </dev/null >/dev/null 2>&1

cleanup
[ "$fails" -eq 0 ]
