#!/bin/sh
# Mixed link-local + DHT/ICE peers in one session.
#
# One product-shaped host (DHT and multicast both on) serves two clients that
# join at once: client A on the shared segment (multicast -> lanlink worker) and
# client B forced onto DHT/ICE (--no-multicast -> ICE turnstile worker). The two
# transports must coexist live -- the session must not degenerate to all-ICE.
# Per-connection transport_send is what lets a lanlink worker and an ICE worker
# run side by side.
#
# Needs the live mainline DHT (for the RENDEZVOUS token and client B) and a
# multicast interface, so it is SKIPPED (77) unless COMRADE_E2E_NET=1.
#
# Usage: lan_mixed.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"

if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	echo "skipped: set COMRADE_E2E_NET=1 to run (needs live mainline DHT)"
	exit 77
fi
"$E2E" mcast-probe
if [ $? -eq 77 ]; then
	echo "skipped: no usable multicast interface on this host"
	exit 77
fi

tmp=$(mktemp -d)
cleanup() { kill "$hpid" $ca $cb 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
ca=""; cb=""

# Product-shaped host: DHT + multicast, serves two clients then exits. STUN is
# left on (the managed pool) so the ICE turnstile serving the DHT client has a
# reflexive path, matching multiuser.sh; the LAN client is pinned below and does
# not depend on it.
"$E2E" host --mcast --serve 2 --timeout 120 \
	>"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

tok=""
i=0
while [ "$i" -lt 120 ]; do
	tok=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | head -1)
	[ -n "$tok" ] && break
	if ! kill -0 "$hpid" 2>/dev/null; then
		echo "host exited before minting a token"; cat "$tmp/host.err"; exit 1
	fi
	sleep 1; i=$((i + 1))
done
if [ -z "$tok" ]; then echo "no token after 120s"; cat "$tmp/host.err"; exit 1; fi

# Client A over the LAN only (multicast/lanlink, DHT dropped) and client B forced
# onto DHT/ICE (the e2e client is DHT-only unless --mcast is given). A is pinned
# to the LAN so the mix is deterministic: a dual-transport client would race the
# DHT turnstile against its own lanlink admission (the client withdraws its DHT
# answer once it learns a lanlink peer, but a slow multicast offer can still let
# the host punch it first -- a transient extra worker in production, and the
# reason A is LAN-pinned here rather than left to race).
"$E2E" client "$tok" --mcast --no-dht --stun none --hold-ms 2000 --timeout 90 \
	>"$tmp/ca.out" 2>"$tmp/ca.err" &
ca=$!
"$E2E" client "$tok" --hold-ms 2000 --timeout 90 \
	>"$tmp/cb.out" 2>"$tmp/cb.err" &
cb=$!

rc=0
wait "$ca" || rc=1
wait "$cb" || rc=1
grep -q "E2E PASS client" "$tmp/ca.out" || { echo "LAN client failed:"; cat "$tmp/ca.out" "$tmp/ca.err"; rc=1; }
grep -q "E2E PASS client" "$tmp/cb.out" || { echo "DHT client failed:"; cat "$tmp/cb.out" "$tmp/cb.err"; rc=1; }
wait "$hpid" 2>/dev/null || true

if [ "$rc" -eq 0 ]; then
	echo "lan mixed e2e: a lanlink worker and an ICE worker served two clients at once"
else
	echo "lan mixed e2e FAILED"
fi
exit "$rc"
