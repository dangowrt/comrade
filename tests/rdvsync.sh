#!/bin/sh
# Rendezvous consensus: whatever token a client arrived on, it ends up holding
# the node the host is actually serving its mailbox from.
#
# A token is meant to be shareable before either family has a qualified
# rendezvous node -- that is what the client's DHT warm-up is for -- so the
# token somebody has already copied can name no node at all, or one the host
# has since replaced. Either way the client has to be told where the host
# rendezvous now, over the control channel, or the next move on either end
# costs it a full convergent search it should not have needed.
#
# Two things pinned here:
#
#   1. a client that joined on a token naming no rendezvous ends up holding
#      the host's node, and the same one the host puts in the token it would
#      hand out today
#   2. each served connection announces for itself. On a host that is never
#      the thread driving the signalling: every client is served by a worker,
#      so an announcement written only by the signalling thread reaches
#      nobody at all.
#
# Over a private DHT this script starts (tests/swarm.sh); COMRADE_E2E_NET=1
# uses the real one.
E2E="${1:?path to comrade-e2e}"
SEED="${2:?path to comrade-dhtseed}"

. "$(dirname "$0")/swarm.sh"

if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit 1
fi

tmp="$(mktemp -d)"
hostpid=""
c1=""
c2=""
trap 'kill "$hostpid" "$c1" "$c2" 2>/dev/null; swarm_stop; rm -rf "$tmp"' EXIT

COMRADE_DEBUG="$tmp/host.dbg" "$E2E" host --serve 2 --timeout 300 \
	> "$tmp/host.out" 2> "$tmp/host.err" &
hostpid=$!

# The token as first minted. head -1 rather than tail -1: this is the one an
# operator can already have pasted somewhere, before the host had anywhere to
# tell them to meet.
early=""
i=0
while [ "$i" -lt 60 ]; do
	early=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | head -1)
	[ -n "$early" ] && break
	kill -0 "$hostpid" 2>/dev/null || {
		echo "host exited before minting a token"
		cat "$tmp/host.err"
		exit 1
	}
	sleep 1
	i=$((i + 1))
done
[ -n "$early" ] || { echo "no token after ${i}s"; exit 1; }
if "$E2E" token "$early" 2>/dev/null | grep -qE "ep4_rdv=1|ep6_rdv=1"; then
	echo "skipped: the first token already named a rendezvous"
	exit 77
fi

# Now let the host find and qualify one, so what it would hand out today names
# a node the early token does not.
rdv=""
i=0
while [ "$i" -lt 150 ]; do
	c=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | tail -1)
	if [ -n "$c" ] && "$E2E" token "$c" 2>/dev/null | grep -q "ep4_rdv=1"; then
		rdv=$("$E2E" token "$c" 2>/dev/null | sed -n 's/^ep4=//p')
		break
	fi
	kill -0 "$hostpid" 2>/dev/null || {
		echo "host exited before qualifying a rendezvous"
		cat "$tmp/host.err"
		exit 1
	}
	sleep 1
	i=$((i + 1))
done
[ -n "$rdv" ] || { echo "host qualified no v4 rendezvous after ${i}s"; exit 1; }

# Both clients join on the early token, so both have to be told.
COMRADE_DEBUG="$tmp/c1.dbg" "$E2E" client "$early" --hold-ms 20000 \
	--timeout 150 > "$tmp/c1.out" 2>&1 &
c1=$!
COMRADE_DEBUG="$tmp/c2.dbg" "$E2E" client "$early" --hold-ms 20000 \
	--timeout 150 > "$tmp/c2.out" 2>&1 &
c2=$!
wait "$c1"
wait "$c2"

rc=0
for n in 1 2; do
	grep -q "E2E PASS client" "$tmp/c$n.out" || {
		echo "client $n never finished its session:"
		tail -5 "$tmp/c$n.out"
		rc=1
	}
	grep -q "rdv: adopted the peer's v4 node $rdv" "$tmp/c$n.dbg" || {
		echo "client $n was never told the host rendezvous at $rdv"
		grep "rdv:" "$tmp/c$n.dbg" | tail -3
		rc=1
	}
done
[ "$rc" = 0 ] && echo "rendezvous consensus: both clients hold the host's node"
exit $rc
