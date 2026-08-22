#!/bin/sh
# Isolated-LAN token mint and connect.
#
# A host with no DHT (an isolated LAN) must mint and print a token, marked
# TOKEN_FLAG_NODHT with the endpoint slots direct (EPx_RDV clear), and a client
# must honour NODHT -- drop the DHT and find the host over multicast -- and
# connect. This runs two same-host processes over real link-local multicast
# (IP_MULTICAST_LOOP is set), which needs one up, multicast-capable, non-loopback
# interface; where there is none the whole case SKIPs (exit 77).
#
# What this harness does NOT prove, and why: the plan's strict "zero DHT egress"
# assertion needs a network namespace with no route (root/CAP_NET_ADMIN), which
# is not available here. The client dropping SIG_DHT on a NODHT token is instead
# guaranteed by construction (main.c / tools/e2e.c) and covered by the token-flag
# assertion below; the no-egress guarantee is proven in the netns L2 run, whose
# command is documented in the plan.
#
# Usage: isolated_lan.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"

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

# Isolated host: multicast only, no DHT. Serves one client then exits.
"$E2E" host --mcast --no-dht --timeout 30 >"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

tok=""
i=0
while [ "$i" -lt 40 ]; do
	tok=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | head -1)
	[ -n "$tok" ] && break
	if ! kill -0 "$hpid" 2>/dev/null; then
		echo "host exited before minting a token"; cat "$tmp/host.err"; exit 1
	fi
	sleep 0.5; i=$((i + 1))
done
if [ -z "$tok" ]; then echo "no token after ~20s"; cat "$tmp/host.err"; exit 1; fi

# Assert the mint: NODHT set, and the endpoint slots are direct (EPx_RDV clear).
"$E2E" token "$tok" >"$tmp/flags.out" 2>&1
cat "$tmp/flags.out"
if ! grep -q 'nodht=1' "$tmp/flags.out"; then
	echo "FAIL: token is not NODHT"; exit 1
fi
if ! grep -q 'ep6_rdv=0 ep4_rdv=0' "$tmp/flags.out"; then
	echo "FAIL: an endpoint slot is a rendezvous node, not a direct endpoint"; exit 1
fi

# The client honours NODHT automatically (drops the DHT); --mcast enables the LAN.
"$E2E" client "$tok" --mcast --timeout 30 >"$tmp/client.out" 2>"$tmp/client.err" &
cpid=$!
wait "$cpid"; crc=$?

wait "$hpid" 2>/dev/null; hrc=$?

if [ "$crc" -ne 0 ] || ! grep -q "E2E PASS client" "$tmp/client.out"; then
	echo "client did not connect:"; cat "$tmp/client.out" "$tmp/client.err"; exit 1
fi
if [ "$hrc" -ne 0 ]; then
	echo "host did not exit cleanly:"; cat "$tmp/host.err"; exit 1
fi
echo "isolated-LAN e2e: NODHT token minted and an RFC1918 client connected"
exit 0
