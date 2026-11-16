#!/bin/sh
# soak-watch.sh: create, start, stop and delete a scratch jail over and over on a real FreeBSD host and watch what the
# programs of JailOps keep: resident memory, open descriptors and threads of jailopsd and jailops-priv, zombies,
# mounts below the storage mount point, epair interfaces, jails in jls and the data of the helper's socket.
# Flat columns are the goal; a column that grows with the loop number is a leak.
#
#   sh scripts/soak-watch.sh -p PROJECT -i IMAGE -N NETWORK [-n LOOPS] [-m MOUNTBASE] [-s SECONDS]
#
# PROJECT must exist and be granted NETWORK and a storage; IMAGE is an image with a generation. The jail is called
# soak-watch and is deleted at the end of every loop (and on exit). -m is the mount point of the storage root
# (default /usr/local/jailops). -n loops (default 200), -s seconds to rest between loops (default 0).
# Run it as root on the host; it takes about 5 s per loop with the default image. Nothing else is touched.
set -u

project="" image="" network="" loops=200 mount=/usr/local/jailops rest=0
while getopts p:i:N:n:m:s: o; do
	case $o in
	p) project=$OPTARG ;; i) image=$OPTARG ;; N) network=$OPTARG ;; n) loops=$OPTARG ;; m) mount=$OPTARG ;; s) rest=$OPTARG ;;
	*) echo "usage: sh $0 -p PROJECT -i IMAGE -N NETWORK [-n LOOPS] [-m MOUNTBASE] [-s SECONDS]" >&2; exit 2 ;;
	esac
done
[ -n "$project" ] && [ -n "$image" ] && [ -n "$network" ] || { echo "-p, -i and -N are required" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }

J="jailops --project $project"
name=soak-watch
cleanup() { $J delete --confirm-data-loss --force "$name" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

pid_of() { pgrep -x "$1" | head -n 1; }
rss() { ps -o rss= -p "$1" 2>/dev/null | tr -d ' '; }
fds() { fstat -p "$1" 2>/dev/null | tail -n +2 | wc -l | tr -d ' '; }
thr() { ps -H -o tid= -p "$1" 2>/dev/null | wc -l | tr -d ' '; }

printf '%-5s %-8s %9s %6s %5s %9s %6s %5s %6s %6s %6s\n' loop secs d_rss_kb d_fds d_thr p_rss_kb p_fds p_thr zombie mounts epairs
first=""
n=1
while [ "$n" -le "$loops" ]; do
	t0=$(date +%s)
	$J create "$name" --image "$image" --network "$network" >/dev/null 2>&1 || { echo "create failed" >&2; exit 1; }
	$J start "$name" >/dev/null 2>&1 || { echo "start failed" >&2; exit 1; }
	$J exec "$name" -- /bin/sh -c 'echo soak' >/dev/null 2>&1
	$J stop "$name" >/dev/null 2>&1 || { echo "stop failed" >&2; exit 1; }
	$J delete --confirm-data-loss "$name" >/dev/null 2>&1 || { echo "delete failed" >&2; exit 1; }
	d=$(pid_of jailopsd)
	p=$(pgrep -f 'jailops-priv -log' | tail -n 1)
	z=$(ps -axo stat= | grep -c '^Z')
	m=$(mount -p | awk -v b="$mount" 'index($2, b) == 1' | wc -l | tr -d ' ')
	e=$(ifconfig -g epair 2>/dev/null | wc -l | tr -d ' ')
	row="$n $(( $(date +%s) - t0 )) $(rss "$d") $(fds "$d") $(thr "$d") $(rss "$p") $(fds "$p") $(thr "$p") $z $m $e"
	[ -n "$first" ] || first=$row
	# shellcheck disable=SC2086
	printf '%-5s %-8s %9s %6s %5s %9s %6s %5s %6s %6s %6s\n' $row
	last=$row
	[ "$rest" -gt 0 ] && sleep "$rest"
	n=$((n + 1))
done
echo
echo "first: $first"
echo "last:  ${last:-}"
