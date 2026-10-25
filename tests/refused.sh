#!/bin/sh
# A claimant the grant has no room for is told so in its own slot (PROTOCOL.md
# section 4, rule L2): a host admitting one client refuses the second
# explicitly, and the second ends on that verdict rather than waiting on a
# silence. Over a private DHT this script starts (tests/swarm.sh);
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
hostpid=""
c1=""
keep() {
	if [ "${COMRADE_E2E_KEEP:-0}" = 1 ]; then
		echo "logs kept in $tmp"
	else
		rm -rf "$tmp"
	fi
}
trap 'kill "$hostpid" "$c1" 2>/dev/null; swarm_stop; keep' EXIT

COMRADE_DEBUG="$tmp/host.dbg" "$E2E" host --serve 1 --admit 1 --timeout 150 \
	> "$tmp/host.out" 2> "$tmp/host.err" &
hostpid=$!

tok=""
i=0
while [ "$i" -lt "$(e2e_loops 120)" ]; do
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

# The first claimant has to be in a session before the second asks, or which
# of the two is refused is a race the test would be asserting the outcome of.
# The host's own punch is one-sided and says nothing about what the claimant
# read, and an open channel is still too early: ending the hold below while
# the echo is outstanding leaves nothing to wind up.
COMRADE_DEBUG="$tmp/c1.dbg" "$E2E" client "$tok" --hold-ms 90000 \
	--timeout 120 > "$tmp/c1.out" 2>&1 &
c1=$!
i=0
while [ "$i" -lt "$(e2e_loops 90)" ]; do
	grep -q "sshc: echo round trip done" "$tmp/c1.dbg" 2>/dev/null && break
	kill -0 "$c1" 2>/dev/null || break
	sleep 1
	i=$((i + 1))
done
grep -q "sshc: echo round trip done" "$tmp/c1.dbg" 2>/dev/null || {
	echo "the first claimant never carried a session"
	grep 'host: ' "$tmp/host.dbg" | tail -8
	tail -8 "$tmp/c1.dbg"
	exit 1
}

# The second runs to its own verdict: refused, exit 3.
COMRADE_DEBUG="$tmp/c2.dbg" "$E2E" client "$tok" --hold-ms 90000 \
	--timeout 60 > "$tmp/c2.out" 2>&1
rc2=$?
kill -TERM "$c1" 2>/dev/null	# wind up the hold and report
wait "$c1"

rc=0
[ "$rc2" = 3 ] || {
	echo "second client exited $rc2, wanted 3 (refused):"
	tail -3 "$tmp/c2.out"
	echo "what it was doing:"; tail -8 "$tmp/c2.dbg"
	rc=1
}
grep -q "E2E REFUSED client" "$tmp/c2.out" || {
	echo "the second client was not told it was refused"
	rc=1
}
grep -q "admission budget spent" "$tmp/host.dbg" || {
	echo "the host never refused anybody"
	grep 'host: ' "$tmp/host.dbg" | tail -8
	rc=1
}
grep -q "sig: the host refused us" "$tmp/c2.dbg" || {
	echo "the second client never read a refusal from its slot"
	rc=1
}
grep -q "E2E PASS client" "$tmp/c1.out" || {
	echo "the admitted client never finished its session:"
	tail -3 "$tmp/c1.out"
	tail -8 "$tmp/c1.dbg"
	rc=1
}
[ "$rc" = 0 ] && echo "refused: the grant's second claimant was told so in its slot"
exit $rc
