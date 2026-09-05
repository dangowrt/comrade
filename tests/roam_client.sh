#!/bin/sh
# A client rebuilds its signalling while it is still looking, and still joins.
#
# This is the second of the three sig_rebuild sites in session.c: the client's
# netmon handler, which runs only before the link is up. A client that moves
# while searching must come back on the new network -- a fresh DHT socket, the
# rendezvous re-seeded from the node it kept warm, a fresh ICE identity -- and
# then join over what it rebuilt, rather than keep querying from an interface
# that has gone. The move is manufactured with --roam-ms (session_cfg
# test_roam_ms), since the netmon poll is that site's only trigger.
#
# The moves are made in the client's first half second, while ICE is still
# gathering and it cannot yet have read an offer, let alone claimed one, and
# they are counted out with --roams so that they stop. Both halves matter. A
# claim round trip over the live DHT is not bounded, so a client still being
# moved while it tries to complete one would race its own connect attempt for
# as long as the case let it, which asserts nothing about the rebuild; and a
# move landing between a claim and its pickup leaves the host punching an ICE
# identity the client has just discarded, which the turnstile recovers from by
# a route this case is not here to measure. Reaching the site is asserted from
# the client's own debug log, and the site is reachable only while st != ST_RUN,
# so the count is proof the handler ran rather than that the flag was read.
#
# DHT only, deliberately: it is the transport a roam exists for, and the one the
# rebuild re-seeds. It meets over the private swarm this script starts;
# COMRADE_E2E_NET=1 points it at the real mainline DHT instead.
#
# Usage: roam_client.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"
SEED="${2:?path to comrade-dhtseed}"

. "$(dirname "$0")/redact.sh"
redact_output

. "$(dirname "$0")/swarm.sh"

# A private DHT of our own, unless asked to use the real one.
if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit $?
fi

# grep -c says nothing at all when the log does not exist yet, which is not 0.
rebuilds() {
	n=$(grep -c 'sig: rebuilt on the new network' "$1" 2>/dev/null)
	echo "${n:-0}"
}

tmp=$(mktemp -d)
cleanup() { kill "$hpid" $cpid 2>/dev/null; swarm_stop; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
cpid=""
ROAMS=3

"$E2E" host --serve 1 --timeout 150 >"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

# Wait for a rendezvous node in the token: the client re-seeds it on every
# rebuild, which is what makes each one cheap to recover from.
tok=""
i=0
while [ "$i" -lt 120 ]; do
	cand=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | tail -1)
	if [ -n "$cand" ] && "$E2E" token "$cand" 2>/dev/null |
	   grep -q 'state[46]=RENDEZVOUS'; then
		tok="$cand"; break
	fi
	if ! kill -0 "$hpid" 2>/dev/null; then
		echo "host exited before minting a token"; cat "$tmp/host.err"; exit 1
	fi
	sleep 1; i=$((i + 1))
done
if [ -z "$tok" ]; then echo "no rendezvous token after 120s"; cat "$tmp/host.err"; exit 1; fi

COMRADE_DEBUG="$tmp/client.log" "$E2E" client "$tok" --roam-ms 150 \
	--roams "$ROAMS" --hold-ms 500 --timeout 90 \
	>"$tmp/c.out" 2>"$tmp/c.err" &
cpid=$!

rc=0
wait "$cpid" || rc=1
kill "$hpid" 2>/dev/null
wait "$hpid" 2>/dev/null

n=$(rebuilds "$tmp/client.log")
if [ "$n" -lt "$ROAMS" ]; then
	echo "FAIL: the client rebuilt $n times, not $ROAMS (roam seam not firing?)"
	cat "$tmp/c.err"; exit 1
fi
grep -q "E2E PASS client" "$tmp/c.out" 2>/dev/null || {
	echo "client never joined after rebuilding its signalling:"
	cat "$tmp/c.out" "$tmp/c.err"; tail -8 "$tmp/client.log" 2>/dev/null; rc=1; }
if grep -q 'sig: rebuild failed' "$tmp/client.log" 2>/dev/null; then
	echo "the client gave the session up on a rebuild:"
	grep 'sig: rebuild' "$tmp/client.log"; rc=1
fi

if [ "$rc" -eq 0 ]; then
	echo "roam client e2e: joined over signalling rebuilt $n times while looking"
else
	echo "roam client e2e FAILED after $n rebuilds"
fi
exit "$rc"
