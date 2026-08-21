#!/bin/sh
# Concurrent isolated-LAN admission.
#
# One no-DHT host mints a token whose families both settle to NONE, carrying no
# address of its own, and serves N clients that join at once over real link-local
# multicast (IP_MULTICAST_LOOP is set, so same-host multi-process works). Each
# client gets its own worker over the shared lanlink socket, demultiplexed by
# source; there is no DHT and no ICE punch (the host suppresses the ICE turnstile
# for a same-segment claimant it can serve directly -- sig mcast_claims -- so a
# connection here is proof the direct lanlink path carried it). This is the
# offline, deterministic counterpart to multiuser.sh (which needs the live DHT).
#
# Needs one up, multicast-capable, non-loopback interface; SKIPs (77) otherwise.
#
# Usage: lan_concurrent.sh <path-to-comrade-e2e> [N]
set -u

E2E="${1:?path to comrade-e2e}"
N="${2:-2}"

"$E2E" mcast-probe
if [ $? -eq 77 ]; then
	echo "skipped: no usable multicast interface on this host"
	exit 77
fi

tmp=$(mktemp -d)
cleanup() { kill "$hpid" $cpids 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
cpids=""

# Isolated multi-user host: multicast only, no DHT, serves exactly N clients
# through the LAN turnstile, then exits. A short hold keeps the workers live at
# once so their concurrency is real, not sequential.
"$E2E" host --mcast --no-dht --stun none --serve "$N" --timeout 60 \
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

# Assert the isolated mint, then launch N clients at once against the one token.
"$E2E" token "$tok"
"$E2E" token "$tok" | grep -q 'state6=NONE state4=NONE' ||
	{ echo "FAIL: a family did not settle to NONE"; exit 1; }

j=0
while [ "$j" -lt "$N" ]; do
	"$E2E" client "$tok" --mcast --no-dht --stun none --hold-ms 1500 \
		--timeout 40 >"$tmp/c$j.out" 2>"$tmp/c$j.err" &
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
wait "$hpid" 2>/dev/null || rc=1

if [ "$rc" -eq 0 ]; then
	echo "lan concurrent e2e: $N clients admitted over multicast/lanlink at once"
else
	echo "lan concurrent e2e FAILED"
fi
exit "$rc"
