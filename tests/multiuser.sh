#!/bin/sh
# Multi-user end-to-end driver: one host serves N clients concurrently through
# the turnstile, each client running the echo oracle over
# the real path. This exercises the concurrent worker layer that the unit tests
# (mailbox_test) cannot reach: several real ICE punches and KCP streams against
# one host at once.
#
# The peers meet through a private DHT this script starts (tests/swarm.sh), so
# what it measures is comrade and not how busy the public one was. Set
# COMRADE_E2E_NET=1 to point it at the real mainline DHT instead, which is a
# question worth asking deliberately and not on every build.
#
# Usage: multiuser.sh <path-to-comrade-e2e> <path-to-comrade-dhtseed> [N]
set -u

E2E="${1:?path to comrade-e2e}"
SEED="${2:?path to comrade-dhtseed}"
N="${3:-2}"

. "$(dirname "$0")/swarm.sh"

if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit 1
fi

tmp=$(mktemp -d)
cleanup() { kill "$hpid" $cpids 2>/dev/null; swarm_stop; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
cpids=""

# Host serves exactly N clients through the turnstile, then exits.
"$E2E" host --serve "$N" >"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

# Wait for a token whose rendezvous node is in it, so the clients skip cold
# convergence rather than starting from the bootstrap (~15 s either way).
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

# Launch N clients at once against the one token: they race the turnstile.
j=0
while [ "$j" -lt "$N" ]; do
	"$E2E" client "$tok" >"$tmp/c$j.out" 2>"$tmp/c$j.err" &
	cpids="$cpids $!"
	j=$((j + 1))
done

rc=0
for p in $cpids; do
	wait "$p" || rc=1
done
j=0
while [ "$j" -lt "$N" ]; do
	if ! grep -q "E2E PASS client" "$tmp/c$j.out"; then
		echo "client $j did not pass:"; cat "$tmp/c$j.out" "$tmp/c$j.err"; rc=1
	fi
	j=$((j + 1))
done
wait "$hpid" 2>/dev/null || true

if [ "$rc" -eq 0 ]; then
	echo "multiuser e2e: $N clients attached one host through the turnstile"
else
	echo "multiuser e2e FAILED"
fi
exit "$rc"
