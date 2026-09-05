#!/bin/sh
# The HOST roams mid-session: its signalling is rebuilt, its offer rotates,
# and its old transport goes silent (--roam-hard) exactly as a move onto
# another network. The healthy client must resume in place -- re-claim under
# its session identity against the rotated offer and be grafted into the
# worker the host still runs. Over a private DHT this script starts
# (tests/swarm.sh); COMRADE_E2E_NET=1 uses the real one.
E2E="${1:?path to comrade-e2e}"
SEED="${2:?path to comrade-dhtseed}"

. "$(dirname "$0")/redact.sh"
redact_output

. "$(dirname "$0")/swarm.sh"

# A private DHT of our own, unless asked to use the real one.
if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit $?
fi

tmp="$(mktemp -d)"
hostpid=""
clientpid=""
trap 'kill "$hostpid" "$clientpid" 2>/dev/null; swarm_stop; rm -rf "$tmp"' EXIT

COMRADE_DEBUG="$tmp/host.dbg" "$E2E" host --serve 1 --timeout 150 \
	--roam-ms 5000 --roams 1 --roam-hard --roam-on-serve \
	> "$tmp/host.out" 2> "$tmp/host.err" &
hostpid=$!

tok=""
i=0
while [ "$i" -lt 120 ]; do
	c=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | tail -1)
	if [ -n "$c" ] && "$E2E" token "$c" 2>/dev/null |
	    grep -qE "ep4_rdv=1|ep6_rdv=1"; then
		tok="$c"
		break
	fi
	kill -0 "$hostpid" 2>/dev/null || {
		echo "host exited before locating a rendezvous"
		cat "$tmp/host.err"
		exit 1
	}
	sleep 1
	i=$((i + 1))
done
[ -n "$tok" ] || { echo "no rendezvous token after ${i}s"; exit 1; }

# Held open until the thing it is here to see has happened, not for a span
# chosen to be longer than it: the roam is staged 30s in, and what follows is
# the client resuming onto the host's new network. The hold is only an upper
# bound for a run where that never comes.
COMRADE_DEBUG="$tmp/client.dbg" "$E2E" client "$tok" \
	--hold-ms 120000 --timeout 160 > "$tmp/client.out" 2>&1 &
clientpid=$!
i=0
while [ "$i" -lt 120 ]; do
	grep -q "resume: link back" "$tmp/client.dbg" 2>/dev/null &&
		grep -q "punch connected -> resume worker" "$tmp/host.dbg" 2>/dev/null &&
		break
	kill -0 "$clientpid" 2>/dev/null || break
	sleep 1
	i=$((i + 1))
done
kill -TERM "$clientpid" 2>/dev/null	# wind up the hold and report
wait "$clientpid" 2>/dev/null

rc=0
grep -q "E2E PASS client" "$tmp/client.out" || {
	echo "client never finished its session:"
	tail -5 "$tmp/client.out"
	rc=1
}
grep -q "sig: rebuilt on the new network" "$tmp/host.dbg" || {
	echo "the staged host roam never fired"
	rc=1
}
grep -q "resume: link back" "$tmp/client.dbg" || {
	echo "the client never resumed onto the host's new network"
	rc=1
}
n=$(grep -c "spawn worker" "$tmp/host.dbg")
[ "$n" = 1 ] || { echo "host spawned $n workers, wanted exactly 1"; rc=1; }
grep -q "punch connected -> resume worker" "$tmp/host.dbg" || {
	echo "the host never grafted the resume punch"
	rc=1
}
[ "$rc" = 0 ] && echo "host roam: resumed in place, one worker, session intact"
exit $rc
