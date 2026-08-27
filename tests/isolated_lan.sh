#!/bin/sh
# Isolated-LAN token mint and connect.
#
# A host with no DHT (an isolated LAN) must mint and print a token whose two
# families settle to NONE -- carrying no address of the host's own, and with the
# retired NODHT bit clear -- and a client told to decline the DHT itself must
# still find the host over multicast and connect on the rendezvous secret alone.
# This runs two same-host processes over real link-local multicast
# (IP_MULTICAST_LOOP is set), which needs one up, multicast-capable, non-loopback
# interface; where there is none the whole case SKIPs (exit 77).
#
# What this harness does NOT prove, and why: the plan's strict "zero DHT egress"
# assertion needs a network namespace with no route (root/CAP_NET_ADMIN), which
# is not available here. Both ends here decline the DHT on the command line, the
# operator's only opt-out; the no-egress guarantee is proven in the netns L2 run,
# whose command is documented in the plan.
#
# Usage: isolated_lan.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"

. "$(dirname "$0")/redact.sh"
redact_output

# Skip cleanly where no multicast interface exists (e.g. a bare CI container).
"$E2E" mcast-probe
if [ $? -eq 77 ]; then
	echo "skipped: no usable multicast interface on this host"
	exit 77
fi

tmp=$(mktemp -d)
cleanup() { kill "$hpid" $cpid 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
cpid=""

# Isolated host: multicast only, no DHT. Serves one client through the turnstile
# then exits (--serve 1: an isolated host's ICE listener never gets a DHT claim,
# so it would otherwise run to the deadline).
"$E2E" host --mcast --no-dht --stun none --serve 1 --timeout 30 \
	>"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

# The host re-emits its token on every state change, so take the newest line and
# wait for both families to settle. With the DHT declined that takes only as long
# as ICE gathering. A truncated last line simply fails to decode and we retry.
tok=""
i=0
while [ "$i" -lt 40 ]; do
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
if [ -z "$tok" ]; then echo "no settled token after ~20s"; cat "$tmp/host.err"; exit 1; fi

# Assert the mint: both families settled to NONE, no address of the host's own
# in either slot, and no token state telling the client to drop a transport
# (NODHT is retired).
"$E2E" token "$tok" >"$tmp/flags.out" 2>&1
cat "$tmp/flags.out"
if ! grep -q 'nodht=0' "$tmp/flags.out"; then
	echo "FAIL: token carries the retired NODHT bit"; exit 1
fi
if ! grep -q 'state6=NONE state4=NONE' "$tmp/flags.out"; then
	echo "FAIL: a family did not settle to NONE"; exit 1
fi
if ! grep -q 'ep6=\[::\]:0' "$tmp/flags.out"; then
	echo "FAIL: the v6 slot carries a host address"; exit 1
fi
if ! grep -q 'ep4=0.0.0.0:0' "$tmp/flags.out"; then
	echo "FAIL: the v4 slot carries a host address"; exit 1
fi

# The client declines the DHT the way its operator would on an isolated LAN;
# --mcast enables the LAN.
"$E2E" client "$tok" --mcast --no-dht --stun none --timeout 30 \
	>"$tmp/client.out" 2>"$tmp/client.err" &
cpid=$!
wait "$cpid"; crc=$?

wait "$hpid" 2>/dev/null; hrc=$?

if [ "$crc" -ne 0 ] || ! grep -q "E2E PASS client" "$tmp/client.out"; then
	echo "client did not connect:"; cat "$tmp/client.out" "$tmp/client.err"; exit 1
fi
if [ "$hrc" -ne 0 ]; then
	echo "host did not exit cleanly:"; cat "$tmp/host.err"; exit 1
fi
echo "isolated-LAN e2e: both families settled to NONE and an RFC1918 client connected"
exit 0
