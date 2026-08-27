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

. "$(dirname "$0")/redact.sh"
redact_output

. "$(dirname "$0")/swarm.sh"

if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit $?
fi

tmp="$(mktemp -d)"
hostpid=""
c1=""
c2=""
trap 'kill "$hostpid" "$c1" "$c2" 2>/dev/null; swarm_stop; rm -rf "$tmp"' EXIT

COMRADE_DEBUG="$tmp/host.dbg" "$E2E" host --serve 2 --timeout 150 \
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
# a node the early token does not. Whichever family gets there first: the two
# converge on their own schedules and which one it is says nothing about the
# property under test.
rdv=""
fam=""
i=0
while [ "$i" -lt 100 ]; do
	c=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | tail -1)
	if [ -n "$c" ]; then
		d=$("$E2E" token "$c" 2>/dev/null)
		case "$d" in
		*ep4_rdv=1*)	fam=4; rdv=$(echo "$d" | sed -n 's/^ep4=//p') ;;
		*ep6_rdv=1*)	fam=6; rdv=$(echo "$d" | sed -n 's/^ep6=//p') ;;
		esac
		[ -n "$rdv" ] && break
	fi
	kill -0 "$hostpid" 2>/dev/null || {
		echo "host exited before qualifying a rendezvous"
		cat "$tmp/host.err"
		exit 1
	}
	sleep 1
	i=$((i + 1))
done
[ -n "$rdv" ] || { echo "host qualified no rendezvous at all after ${i}s"; exit 1; }

# Both clients join on the early token, so both have to be told.
COMRADE_DEBUG="$tmp/c1.dbg" "$E2E" client "$early" --hold-ms 90000 \
	--timeout 150 > "$tmp/c1.out" 2>&1 &
c1=$!
COMRADE_DEBUG="$tmp/c2.dbg" "$E2E" client "$early" --hold-ms 90000 \
	--timeout 150 > "$tmp/c2.out" 2>&1 &
c2=$!
# Held until both have been told, not for a span assumed to be long enough:
# being told is the whole assertion below, so it is also the thing to wait for.
i=0
while [ "$i" -lt 90 ]; do
	grep -qF "rdv: adopted the peer's" "$tmp/c1.dbg" 2>/dev/null &&
		grep -qF "rdv: adopted the peer's" "$tmp/c2.dbg" 2>/dev/null &&
		break
	kill -0 "$c1" 2>/dev/null || break
	kill -0 "$c2" 2>/dev/null || break
	sleep 1
	i=$((i + 1))
done
kill -TERM "$c1" "$c2" 2>/dev/null	# wind up the holds and report
wait "$c1"
wait "$c2"

rc=0
for n in 1 2; do
	grep -q "E2E PASS client" "$tmp/c$n.out" || {
		echo "client $n never finished its session:"
		tail -5 "$tmp/c$n.out"
		rc=1
	}
	# -F: a v6 endpoint is written [addr]:port, which as a pattern is a
	# bracket expression matching one character.
	grep -qF "rdv: adopted the peer's v$fam node $rdv" "$tmp/c$n.dbg" || {
		echo "client $n was never told the host rendezvous at $rdv"
		grep "rdv:" "$tmp/c$n.dbg" | tail -3
		rc=1
	}
done

# Each client says what it can reach as it joins, which is what lets a host
# that has lost a family pick one to rendezvous on its behalf. Reports are
# counted rather than peers: the dashboard id belongs to a row and is handed to
# the next client when a row is freed, so two clients served one after the
# other are both peer 0.
told=$(grep -c "reach: peer [0-9][0-9]* v4 " "$tmp/host.dbg")
if [ "$told" -lt 2 ]; then
	echo "the host was told what a peer can reach $told times, wanted 2"
	grep "reach:" "$tmp/host.dbg" | tail -4
	rc=1
fi
[ "$rc" = 0 ] && echo "rendezvous consensus: both clients hold the host's node"
exit $rc
