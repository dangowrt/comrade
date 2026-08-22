#!/bin/sh
# A path dying moves the session to another one, rather than ending it.
#
# PROTOCOL.md section 11: "Roaming is a path switch, not a rejoin. When the path
# carrying the session dies, the session moves to the best warm path (section 9)
# with the connection, the worker, the tmux attach and the KCP stream all
# intact." Nothing about a real path being taken away can be staged in CI
# without CAP_NET_ADMIN, so the client is told to stop sending on whichever path
# is carrying the session at that moment (--blackhole-ms, session_cfg
# test_blackhole_ms) instead: the probes that keep a path warm are ours, so the
# path falls silent at both ends exactly as a severed one would.
#
# What is asserted:
#   1. The client leaves the blackholed path for another one it already held
#      warm, so the switch is a reordering rather than a rediscovery -- and the
#      path it left was scoring probe loss by then, so the move was caused by
#      the path dying and is not the ordinary drift a multi-homed pair does.
#   2. The session survives it. The heartbeat rides the SSH channel end to end
#      and knows nothing about paths, so a link it never reports lost (or
#      reports lost and then back) is proof the KCP stream, the SSH session and
#      the worker all came through the switch intact.
#   3. Neither end fell back to a rejoin.
#
# The switch needs somewhere to go, which needs this machine to have more than
# one address the peer can be reached at. Where it has only one, there is
# nothing to assert and the case SKIPs (77) rather than passing vacuously.
#
# No DHT, so this is offline and deterministic: it needs one up,
# multicast-capable, non-loopback interface, and SKIPs (77) where there is none.
#
# Usage: path_switch.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"

"$E2E" mcast-probe
if [ $? -eq 77 ]; then
	echo "skipped: no usable multicast interface on this host"
	exit 77
fi

tmp=$(mktemp -d)
cleanup() { kill "$hpid" "$cpid" 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
hpid=""
cpid=""

COMRADE_DEBUG="$tmp/host.log" "$E2E" host --mcast --no-dht --stun none \
	--serve 1 --timeout 70 >"$tmp/host.out" 2>"$tmp/host.err" &
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

# Blackhole well after the paths have qualified (the unqualified probe period is
# 200ms), and hold long enough afterwards for the switch, several heartbeat
# rounds and the loss verdict that would follow a failed one.
COMRADE_DEBUG="$tmp/client.log" "$E2E" client "$tok" --mcast --no-dht \
	--stun none --blackhole-ms 3000 --hold-ms 20000 --timeout 60 \
	>"$tmp/c.out" 2>"$tmp/c.err" &
cpid=$!

rc=0
wait "$cpid" || rc=1
wait "$hpid" 2>/dev/null || rc=1

bh=$(sed -n 's/.*path blackholed: //p' "$tmp/client.log" 2>/dev/null | head -1)
if [ -z "$bh" ]; then
	echo "FAIL: the client never blackholed a path (hook not firing?)"
	cat "$tmp/c.err"; tail -20 "$tmp/client.log" 2>/dev/null; exit 1
fi
# Only paths already qualified when the path died count: one adopted afterwards
# is a rediscovery, which is what this case exists to show is not needed.
warm=$(sed -n '/path blackholed:/q; s/.*path qualified: \([^ ]*\) .*/\1/p' \
	"$tmp/client.log" 2>/dev/null | sort -u | wc -l)
if [ "$warm" -lt 2 ]; then
	echo "skipped: this host offers only $warm path to the peer, so a" \
	     "switch has nowhere to go"
	exit 77
fi

# The switch has to be caused by the path dying, not by the ordinary drift a
# multi-homed pair does anyway: it must come after the blackhole, name the
# blackholed endpoint as the one it left, and that endpoint must have been
# scoring probe loss by then -- at either end. The selection combines both
# ends' published views, and the peer's verdict can land first: its probes
# still arrive on the muted path, carrying its own rising loss for it, while
# this end's first suppressed probe may still be inside the loss deadline.
# Either side's loss proves the death; only 0/0 is drift. awk rather than
# grep, so a v6 endpoint's brackets stay literal. Prints
# "<endpoint moved to> <own loss ppt> <peer loss ppt>".
sw=$(awk -v bh="$bh" '
	/path blackholed:/ { seen = 1; next }
	seen && /path: carrying / {
		i = index($0, "(was " bh " ")
		if (!i)
			next
		for (f = 1; f <= NF; f++)
			if ($f == "carrying") { to = $(f + 1); break }
		rest = substr($0, i)
		sub(/.*loss=/, "", rest)
		split(rest, L, /[\/)]/)
		print to, L[1], L[2]
		exit
	}
' "$tmp/client.log" 2>/dev/null)
to=${sw%% *}
rest=${sw#* }
own=${rest%% *}
peer=${rest##* }
if [ -z "$sw" ]; then
	echo "FAIL: the client stayed on the path it can no longer send on"
	grep -E 'path (blackholed|: carrying)' "$tmp/client.log"; rc=1
elif [ "$own" -eq 0 ] && [ "$peer" -eq 0 ]; then
	echo "FAIL: the client left $bh with neither end scoring a loss on" \
	     "it, so it drifted rather than switched"
	grep -E 'path (blackholed|: carrying)' "$tmp/client.log"; rc=1
fi
# The heartbeat may or may not notice a switch, depending on where in its
# 700ms round the path died -- a blip inside the rejoin grace is the outage the
# switch is repairing. What must not stand is a link that went down and never
# came back, so the last transition, if there is one, has to be the recovery.
# Only the client's, since the host legitimately ends on a loss: the client
# leaves for real when its hold expires.
case "$(grep -E 'link (lost|back)' "$tmp/client.log" 2>/dev/null | tail -1)" in
*'link lost'*)
	echo "FAIL: the client's link went down over the switch and stayed down"
	grep -E 'link (lost|back)' "$tmp/client.log"; rc=1 ;;
esac
for f in "$tmp/client.log" "$tmp/host.log"; do
	if grep -q 'session: rejoin (roam)' "$f" 2>/dev/null; then
		echo "FAIL: a path switch was taken for a rejoin ($f)"; rc=1
	fi
done
grep -q "E2E PASS client" "$tmp/c.out" 2>/dev/null || {
	echo "client did not complete its echo:"
	cat "$tmp/c.out" "$tmp/c.err"; rc=1; }

if [ "$rc" -eq 0 ]; then
	echo "path switch e2e: $warm paths warm, $bh taken away at" \
	     "${own}/${peer}ppt loss, session moved to $to and stayed up"
else
	echo "path switch e2e FAILED (blackholed $bh of $warm warm paths)"
fi
exit "$rc"
