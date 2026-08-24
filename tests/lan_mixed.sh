#!/bin/sh
# Mixed link-local + DHT/ICE peers in one session.
#
# One product-shaped host (DHT and multicast both on) serves, in a single run,
# client A on the shared segment (multicast -> lanlink worker) and client B on
# DHT/ICE (-> ICE turnstile). Per-connection transport_send is what lets a
# lanlink worker and an ICE turnstile run side by side, so the session does not
# degenerate to all-ICE.
#
# Dependability (per the reviewer's guidance -- a flaky test must never mask a
# regression). Two things are asserted STRICTLY, and both are reliable:
#   1. The LAN client connects over lanlink (deterministic). It is --no-dht, so
#      lanlink is its ONLY path: it cannot pass if the lanlink worker path is
#      dead (the B1/B5 degeneration), so this alone rejects an all-ICE regression.
#      It HOLDS its session open so its lanlink worker is provably live while (2)
#      happens.
#   2. The host ENGAGES the ICE turnstile for the DHT claimant -- it picks up B's
#      sealed answer and starts a punch ("claim received -> punch" in the host
#      debug log) -- concurrently with A's live lanlink worker. This is the
#      coexistence proof and it does NOT depend on B's hole-punch completing,
#      which is the flaky part over localhost (DHT rendezvous + ICE punch; the
#      same flake multiuser.sh shows).
# B actually completing its punch is reported but BEST-EFFORT: the DHT turnstile
# itself is regression-guarded by multiuser.sh, so leaving B's completion soft
# here masks nothing.
#
# Needs the live mainline DHT and a multicast interface; SKIPPED (77) unless
# COMRADE_E2E_NET=1.
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
cleanup() { kill "$hpid" "$apid" "$bpid" 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
apid=""; bpid=""

# Product-shaped host: DHT + multicast, with the debug log on so the ICE pickup
# is observable. Runs until killed.
COMRADE_DEBUG="$tmp/host.log" "$E2E" host --mcast --timeout 150 \
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

# Client A over the LAN only (multicast/lanlink, DHT dropped), holding so its
# lanlink worker stays live while the host engages the ICE turnstile for B.
"$E2E" client "$tok" --mcast --no-dht --stun none --hold-ms 40000 --timeout 50 \
	>"$tmp/a.out" 2>"$tmp/a.err" &
apid=$!
sleep 2

# Client B forced onto DHT/ICE (DHT-only unless --mcast). Best-effort completion;
# what must happen is that the host picks up its claim (asserted via the log).
"$E2E" client "$tok" --hold-ms 500 --timeout 40 \
	>"$tmp/b.out" 2>"$tmp/b.err" &
bpid=$!
wait "$bpid" 2>/dev/null || true
wait "$apid" 2>/dev/null || true

rc=0
grep -q "E2E PASS client" "$tmp/a.out" 2>/dev/null || {
	echo "LAN client did not connect over lanlink (STRICT failure):"
	cat "$tmp/a.out" "$tmp/a.err"; rc=1; }
if ! grep -q "claim received -> punch" "$tmp/host.log" 2>/dev/null; then
	echo "host never engaged the ICE turnstile for the DHT claimant (STRICT):"
	tail -8 "$tmp/host.log" 2>/dev/null; tail -4 "$tmp/b.err" 2>/dev/null
	rc=1
fi

if [ "$rc" -eq 0 ]; then
	if grep -q "E2E PASS client" "$tmp/b.out" 2>/dev/null; then
		echo "lan mixed e2e: a lanlink worker and an ICE worker served two clients at once"
	else
		echo "lan mixed e2e: lanlink worker live while the host punched the DHT" \
		     "claimant over ICE (B's localhost punch did not complete this run)"
	fi
	exit 0
fi
echo "lan mixed e2e FAILED"
exit 1
