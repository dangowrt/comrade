#!/bin/sh
# The host restarts under the same invitation (PROTOCOL.md section 4, rule L3):
# a client in a session with it finds a new host instance in the host slot,
# announces itself to that instance as a claimant it has never heard of, and is
# served again under the same pinned key. The first host is killed outright,
# so no tombstone is placed and nothing but the host slot changing says that
# anything happened. Over a private DHT this script starts (tests/swarm.sh);
# COMRADE_E2E_NET=1 uses the real one.
E2E="${1:?path to comrade-e2e}"
SEED="${2:?path to comrade-dhtseed}"

. "$(dirname "$0")/e2elib.sh"
. "$(dirname "$0")/redact.sh"
redact_output

. "$(dirname "$0")/swarm.sh"

if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit $?
fi

tmp="$(mktemp -d)"
h1=""
h2=""
cpid=""
keep() {
	if [ "${COMRADE_E2E_KEEP:-0}" = 1 ]; then
		echo "logs kept in $tmp"
	else
		rm -rf "$tmp"
	fi
}
trap 'kill "$h1" "$h2" "$cpid" 2>/dev/null; swarm_stop; keep' EXIT

COMRADE_DEBUG="$tmp/h1.dbg" "$E2E" host --serve 1 --hostkey "$tmp/hostkey" \
	--timeout 150 > "$tmp/h1.out" 2> "$tmp/h1.err" &
h1=$!

tok=""
i=0
while [ "$i" -lt "$(e2e_loops 120)" ]; do
	c=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/h1.out" 2>/dev/null | tail -1)
	if [ -n "$c" ] && "$E2E" token "$c" 2>/dev/null |
	    grep -qE "ep4_rdv=1|ep6_rdv=1"; then
		tok="$c"
		break
	fi
	kill -0 "$h1" 2>/dev/null || {
		echo "host exited before locating a rendezvous"
		cat "$tmp/h1.err"
		exit 1
	}
	sleep 1
	i=$((i + 1))
done
[ -n "$tok" ] || { echo "no rendezvous token after ${i}s"; exit 1; }

COMRADE_DEBUG="$tmp/client.dbg" "$E2E" client "$tok" --hold-ms 150000 \
	--timeout 200 > "$tmp/client.out" 2>&1 &
cpid=$!
# Killed only once the client's SSH session is up: a host that dies while
# the client is still punching or handshaking leaves nothing behind to be
# lost.
i=0
while [ "$i" -lt "$(e2e_loops 90)" ]; do
	grep -q "sshc: channel open ok" "$tmp/client.dbg" 2>/dev/null && break
	kill -0 "$cpid" 2>/dev/null || break
	sleep 1
	i=$((i + 1))
done
grep -q "sshc: channel open ok" "$tmp/client.dbg" 2>/dev/null || {
	echo "the client never got into a session with the first host"
	grep 'host: ' "$tmp/h1.dbg" | tail -8
	tail -8 "$tmp/client.dbg"
	exit 1
}

# Killed, not stopped: nothing is said in the rendezvous about the end.
kill -KILL "$h1" 2>/dev/null
wait "$h1" 2>/dev/null
h1=""

COMRADE_DEBUG="$tmp/h2.dbg" "$E2E" host --serve 3 --token "$tok" \
	--hostkey "$tmp/hostkey" --timeout 150 > "$tmp/h2.out" 2> "$tmp/h2.err" &
h2=$!

# Held until the client has been served again, by the second host.
i=0
while [ "$i" -lt "$(e2e_loops 120)" ]; do
	grep -q "punch connected -> spawn worker" "$tmp/h2.dbg" 2>/dev/null &&
		[ "$(grep -c "conn_run: sock_pair" "$tmp/client.dbg" 2>/dev/null)" -ge 2 ] &&
		break
	kill -0 "$cpid" 2>/dev/null || break
	kill -0 "$h2" 2>/dev/null || break
	sleep 1
	i=$((i + 1))
done
kill -TERM "$cpid" 2>/dev/null	# wind up the hold and report
wait "$cpid" 2>/dev/null

rc=0
grep -q "E2E PASS client" "$tmp/client.out" || {
	echo "the client never finished a session:"
	tail -3 "$tmp/client.out"
	echo "what it was doing:"; tail -8 "$tmp/client.dbg"
	rc=1
}
n=$(grep "sig: host instance" "$tmp/client.dbg" | sort -u | wc -l)
[ "$n" -ge 2 ] || {
	echo "the client saw $n host instance(s), wanted 2"
	grep "sig: host instance" "$tmp/client.dbg" | tail -3
	rc=1
}
grep -q "punch connected -> spawn worker" "$tmp/h2.dbg" || {
	echo "the restarted host never served the client"
	grep 'host: ' "$tmp/h2.dbg" | tail -8
	rc=1
}
n=$(grep -c "conn_run: sock_pair" "$tmp/client.dbg")
[ "$n" -ge 2 ] || { echo "client brought up $n session(s), wanted 2"; rc=1; }
[ "$rc" = 0 ] && echo "host restart: the client announced itself to the new instance and was served"
exit $rc
