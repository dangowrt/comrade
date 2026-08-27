#!/bin/sh
# The host turnstile rebuilds its signalling on a move, under load.
#
# session.c destroys sig and arms a fresh one whenever the network moves, on the
# thread that also owns the shared lanlink socket and drains every live worker.
# Nothing about a real move can be staged in CI without CAP_NET_ADMIN, so the
# harness host is told to report one on a period (--roam-ms, session_cfg
# test_roam_ms) instead: the netmon poll is the only trigger for the rebuild, so
# manufacturing its answer exercises the whole handler.
#
# Two things must hold across every rebuild, and both are asserted strictly:
#   1. A client already being served keeps being served. Client A holds its
#      session open across several rebuilds and still gets a byte-exact echo,
#      which is what "the lanlink socket deliberately outlives the rebuild"
#      means in practice -- its worker is draining the same socket the rebuild
#      runs beside.
#   2. The signalling that comes back still admits a NEW client. Client B joins
#      only after the host has rebuilt at least three times, so it can only be
#      admitted over multicast groups the fresh sig joined and an offer the
#      fresh sig published.
# The rebuild count is asserted too, so the case cannot pass vacuously if the
# roam ever stops firing.
#
# No DHT, so this is offline and deterministic: it needs one up,
# multicast-capable, non-loopback interface, and SKIPs (77) where there is none.
#
# Usage: roam.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"

"$E2E" mcast-probe
if [ $? -eq 77 ]; then
	echo "skipped: no usable multicast interface on this host"
	exit 77
fi

# grep -c says nothing at all when the log does not exist yet, which is not 0.
rebuilds() {
	n=$(grep -c 'sig: rebuilt on the new network' "$1" 2>/dev/null)
	echo "${n:-0}"
}

tmp=$(mktemp -d)
cleanup() { kill "$hpid" $cpids 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
cpids=""

# The roam period is several times a LAN connect attempt. Shorter than one and
# no client would ever finish joining -- a fresh sig has to open its multicast
# sockets, join the groups and publish an offer before anybody can be admitted
# over it, and a period that does not cover that is a pathological input rather
# than a defect worth asserting against. The case asserts a rebuild COUNT and
# not a rate, so the period can be generous without weakening anything.
COMRADE_DEBUG="$tmp/host.log" "$E2E" host --mcast --no-dht --stun none \
	--serve 2 --timeout 70 --roam-ms 5000 \
	>"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

# The host re-emits its token on every state change, so take the newest line and
# wait for both families to settle; with the DHT declined that is quick.
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

# A, held open across the rebuilds B has to be admitted after. How long that
# takes is what the loop below waits for, so the hold is only an upper bound.
"$E2E" client "$tok" --mcast --no-dht --stun none --hold-ms 90000 \
	--timeout 120 >"$tmp/a.out" 2>"$tmp/a.err" &
apid=$!
cpids="$cpids $apid"

# Wait for the rebuilds B has to be admitted after.
i=0
while [ "$i" -lt 60 ]; do
	[ "$(rebuilds "$tmp/host.log")" -ge 3 ] && break
	sleep 0.5; i=$((i + 1))
done
if [ "$i" -ge 60 ]; then
	echo "FAIL: the host did not rebuild its signalling (roam seam not firing?)"
	cat "$tmp/host.err"; exit 1
fi

# B, joining a host whose signalling has been thrown away and rebuilt since the
# token was minted.
"$E2E" client "$tok" --mcast --no-dht --stun none --hold-ms 500 \
	--timeout 60 >"$tmp/b.out" 2>"$tmp/b.err" &
bpid=$!
cpids="$cpids $bpid"

rc=0
# B has either been admitted or has failed to be; either way A has nothing
# left to hold the host busy for.
wait "$bpid" || rc=1
kill -TERM "$apid" 2>/dev/null	# wind up the hold and report
wait "$apid" || rc=1
wait "$hpid" 2>/dev/null || rc=1

grep -q "E2E PASS client" "$tmp/a.out" 2>/dev/null || {
	echo "held client dropped across a rebuild:"
	cat "$tmp/a.out" "$tmp/a.err"; rc=1; }
grep -q "E2E PASS client" "$tmp/b.out" 2>/dev/null || {
	echo "rebuilt signalling admitted no new client:"
	cat "$tmp/b.out" "$tmp/b.err"; rc=1; }
if grep -q 'sig: rebuild failed' "$tmp/host.log" 2>/dev/null; then
	echo "the host gave the session up on a rebuild:"
	grep 'sig: rebuild' "$tmp/host.log"; rc=1
fi

n=$(rebuilds "$tmp/host.log")
if [ "$rc" -eq 0 ]; then
	echo "roam e2e: host rebuilt its signalling $n times, kept one client" \
	     "served throughout and admitted another afterwards"
else
	echo "roam e2e FAILED after $n rebuilds"
fi
exit "$rc"
