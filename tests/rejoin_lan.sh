#!/bin/sh
# The same reap as rejoin.sh, staged on a segment instead of through the DHT.
#
# A segment path ends when one end leaves the segment the other is on, which is
# what roaming is, so a client coming back over the segment is in exactly the
# position a punched one is: the worker it left may be gone, and the host may
# be answering it from a new one. It has no ICE agent to be told on, so the
# host says it over the segment.
#
# Two same-host processes over real link-local multicast (IP_MULTICAST_LOOP is
# set), which needs one up, multicast-capable, non-loopback interface; where
# there is none the case SKIPs (exit 77).
#
# Usage: rejoin_lan.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"

. "$(dirname "$0")/redact.sh"
redact_output

"$E2E" mcast-probe
if [ $? -eq 77 ]; then
	echo "skipped: no usable multicast interface on this host"
	exit 77
fi

tmp=$(mktemp -d)
hpid=""
clientpid=""
keep() {
	if [ "${COMRADE_E2E_KEEP:-0}" = 1 ]; then
		echo "logs kept in $tmp"
	else
		rm -rf "$tmp"
	fi
}
trap 'kill "$hpid" "$clientpid" 2>/dev/null; keep' EXIT INT TERM

# Serves twice: the session the reap ends, and the one the client comes back
# with. No DHT at either end, so the segment is the only way back.
COMRADE_DEBUG="$tmp/host.dbg" "$E2E" host --mcast --no-dht --stun none \
	--serve 2 --reap-ms 15000 --timeout 120 \
	>"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

tok=""
i=0
while [ "$i" -lt 60 ]; do
	c=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | tail -1)
	if [ -n "$c" ] && "$E2E" token "$c" 2>/dev/null |
	    grep -q 'ep6_settled=1 ep4_settled=1'; then
		tok="$c"
		break
	fi
	kill -0 "$hpid" 2>/dev/null || { echo "host exited early"; exit 1; }
	sleep 1
	i=$((i + 1))
done
[ -n "$tok" ] || { echo "no settled token after ${i}s"; exit 1; }

COMRADE_DEBUG="$tmp/client.dbg" "$E2E" client "$tok" --mcast --no-dht \
	--stun none --hold-ms 120000 --timeout 150 > "$tmp/client.out" 2>&1 &
clientpid=$!
i=0
while [ "$i" -lt 120 ]; do
	n=$(grep -c "conn_run: sock_pair" "$tmp/client.dbg" 2>/dev/null)
	[ "${n:-0}" -ge 2 ] && break
	kill -0 "$clientpid" 2>/dev/null || break
	sleep 1
	i=$((i + 1))
done
kill -TERM "$clientpid" 2>/dev/null	# wind up the hold and report
wait "$clientpid" 2>/dev/null

rc=0
grep -q "reap worker" "$tmp/host.dbg" || {
	echo "the host never reaped the worker"
	rc=1
}
grep -q "served by a new worker" "$tmp/client.dbg" || {
	echo "the client was never told over the segment that its worker was gone"
	rc=1
}
n=$(grep -c "conn_run: sock_pair" "$tmp/client.dbg")
[ "$n" -ge 2 ] || {
	echo "client never brought a fresh session up ($n bring-ups)"
	rc=1
}
[ "$rc" = 0 ] && echo "rejoin over the segment: worker reaped, client told, came back"
exit $rc
