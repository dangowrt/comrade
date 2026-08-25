#!/bin/sh
# One address family moving is not the other one moving.
#
# A residential ISP renumbers its v6 prefix on its own schedule, and DHCPv4 and
# DHCPv6/RA do not land in the same instant even when a laptop joins a single
# network. netmon reports which family moved (NETMON_CH_*) so the reachability
# model can discard that family's facts and leave the other's standing; before
# it did, every v6 event threw away v4 state that had just been gathered.
#
# Nothing about a real renumbering can be staged in CI without CAP_NET_ADMIN, so
# the harness host is told which family to report as moved (--roam-fam, session_cfg
# test_roam_mask) and the per-change log line is counted. A v6-only move must
# report v6 every time and v4 never, and the host must still be serving
# afterwards -- a family reset that took the other family with it would not show
# up as a count on its own.
#
# No DHT, so this is offline and deterministic: it needs one up,
# multicast-capable, non-loopback interface, and SKIPs (77) where there is none.
#
# Usage: roam_fam.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"

"$E2E" mcast-probe
if [ $? -eq 77 ]; then
	echo "skipped: no usable multicast interface on this host"
	exit 77
fi

# grep -c says nothing at all when the log does not exist yet, which is not 0.
count() {
	n=$(grep -c "$2" "$1" 2>/dev/null)
	echo "${n:-0}"
}

tmp=$(mktemp -d)
cleanup() { kill "$hpid" $cpids 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
cpids=""

ROAMS=3
COMRADE_DEBUG="$tmp/host.log" "$E2E" host --mcast --no-dht --stun none \
	--serve 1 --timeout 60 --roam-ms 2000 --roams "$ROAMS" --roam-fam 6 \
	>"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

tok=""
i=0
while [ "$i" -lt 60 ]; do
	cand=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | tail -1)
	if [ -n "$cand" ] && "$E2E" token "$cand" 2>/dev/null |
	   grep -q 'ep6_settled=1 ep4_settled=1'; then
		tok="$cand"; break
	fi
	if ! kill -0 "$hpid" 2>/dev/null; then
		echo "host exited before minting a token"; cat "$tmp/host.err"; exit 1
	fi
	sleep 0.5; i=$((i + 1))
done
if [ -z "$tok" ]; then echo "no settled token after ~30s"; cat "$tmp/host.err"; exit 1; fi

# Wait out the moves the host was told to report.
i=0
while [ "$i" -lt 60 ]; do
	[ "$(count "$tmp/host.log" 'net: change .*v6=1')" -ge "$ROAMS" ] && break
	sleep 0.5; i=$((i + 1))
done

v6=$(count "$tmp/host.log" 'net: change .*v6=1')
v4=$(count "$tmp/host.log" 'net: change v4=1')
if [ "$v6" -lt "$ROAMS" ]; then
	echo "FAIL: asked for $ROAMS v6 moves, saw $v6 (roam seam not firing?)"
	cat "$tmp/host.err"; exit 1
fi
if [ "$v4" -ne 0 ]; then
	echo "FAIL: a v6-only move was reported as a v4 move $v4 time(s)"
	cat "$tmp/host.err"; exit 1
fi

# v4 was left alone in the model; prove the session it belongs to is too, by
# admitting a client over signalling that has survived all of it.
"$E2E" client "$tok" --mcast --no-dht --stun none --timeout 40 \
	>"$tmp/c.out" 2>"$tmp/c.err" &
cpids="$cpids $!"
wait $cpids
if ! grep -q 'E2E PASS client' "$tmp/c.out"; then
	echo "FAIL: no client could be admitted after $v6 v6-only moves"
	cat "$tmp/c.err"; cat "$tmp/host.err"; exit 1
fi

echo "PASS: $v6 v6-only moves, v4 reported moved $v4 times, client still admitted"
exit 0
