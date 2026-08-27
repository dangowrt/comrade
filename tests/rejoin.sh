#!/bin/sh
# The host reaps a worker while its client is still there -- what happens to a
# client that went quiet long enough, and what a roam that outlasts the host's
# patience leaves behind. The turnstile keeps serving, so a fresh worker with a
# fresh sshd answers the claim that comes back, and the client must notice it
# has nothing left to resume into and rejoin as a new one.
#
# What makes that worth staging is that the path never breaks. Every session
# shares one conversation id and one sealing key, so the new worker's frames
# arrive, open and are taken by the transport while reaching nothing above it,
# and a client that judges by the path alone waits for ever on a session that
# has ended.
#
# Sibling of resume.sh, which stages the outage a worker does survive. Peers
# meet through a private DHT this script starts (tests/swarm.sh);
# COMRADE_E2E_NET=1 uses the real one.
E2E="${1:?path to comrade-e2e}"
SEED="${2:?path to comrade-dhtseed}"

. "$(dirname "$0")/swarm.sh"

if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit $?
fi

tmp="$(mktemp -d)"
hostpid=""
keep() {
	if [ "${COMRADE_E2E_KEEP:-0}" = 1 ]; then
		echo "logs kept in $tmp"
	else
		rm -rf "$tmp"
	fi
}
clientpid=""
trap 'kill "$hostpid" "$clientpid" 2>/dev/null; swarm_stop; keep' EXIT

# Serves twice: the session the reap ends, and the one the client comes back
# with. The reap lands well inside the client's hold.
COMRADE_DEBUG="$tmp/host.dbg" "$E2E" host --serve 2 --reap-ms 15000 \
	--timeout 300 > "$tmp/host.out" 2> "$tmp/host.err" &
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

# Held open long enough for the reap, the grace that answers it and the punch
# that follows, and stopped as soon as the fresh session is up rather than
# sitting out the rest of a hold that has nothing left to prove.
COMRADE_DEBUG="$tmp/client.dbg" "$E2E" client "$tok" \
	--hold-ms 200000 --timeout 300 > "$tmp/client.out" 2>&1 &
clientpid=$!
i=0
while [ "$i" -lt 200 ]; do
	[ "$(grep -c "conn_run: sock_pair" "$tmp/client.dbg" 2>/dev/null)" -ge 2 ] &&
		break
	kill -0 "$clientpid" 2>/dev/null || break
	sleep 1
	i=$((i + 1))
done
kill "$clientpid" 2>/dev/null
wait "$clientpid" 2>/dev/null

rc=0
grep -q "reap worker" "$tmp/host.dbg" || {
	echo "the host never reaped the worker"
	rc=1
}
grep -q "session: rejoin" "$tmp/client.dbg" || {
	echo "the client kept waiting on a session that had ended"
	rc=1
}
n=$(grep -c "conn_run: sock_pair" "$tmp/client.dbg")
[ "$n" -ge 2 ] || {
	echo "client never brought a fresh session up ($n bring-ups)"
	rc=1
}
n=$(grep -c "spawn worker" "$tmp/host.dbg")
[ "$n" -ge 2 ] || { echo "host spawned $n workers, wanted 2"; rc=1; }
[ "$rc" = 0 ] && echo "rejoin: worker reaped, client came back fresh"
exit $rc
