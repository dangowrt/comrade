#!/bin/sh
# A wedged ICE punch must not head-of-line-block the next joiner.
#
# The host is told to wedge its FIRST ICE pickup (--stuck 1): that punch never
# connects, modelling a client whose hole-punch hangs. A head-start client is
# answered first and becomes the wedged one (the host holds it in its in-flight
# punch set and never serves it). Several more clients then join DURING the
# hang. Every claimant is answered with an agent of its own, so those later
# joiners are admitted and connect while it hangs; a host whose one agent was
# tied up in the wedge could admit nobody, so a single later joiner connecting
# here is the proof.
#
# Determinism: the wedge is host-controlled (not a real, timing-dependent libjuice
# hang), so the "a joiner is admitted during the hang" property is exact. The only
# non-determinism is the live-DHT/ICE signalling of the joiners themselves (as in
# multiuser.sh), so the case uses several later joiners to give a non-flaky one a
# chance. The assertion waits only on the later joiners (not the wedged one,
# which by design never completes): a DHT flake can make it fail, never falsely
# pass, so it cannot mask a regression.
#
# Usage: turnstile_stuck.sh <path-to-comrade-e2e>
set -u

E2E="${1:?path to comrade-e2e}"
SEED="${2:?path to comrade-dhtseed}"

. "$(dirname "$0")/e2elib.sh"
. "$(dirname "$0")/redact.sh"
redact_output

. "$(dirname "$0")/swarm.sh"

# A private DHT of our own, unless asked to use the real one.
if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit $?
fi

tmp=$(mktemp -d)
keep() {
	if [ "${COMRADE_E2E_KEEP:-0}" = 1 ]; then
		echo "logs kept in $tmp"
	else
		rm -rf "$tmp"
	fi
}
cleanup() { kill "$hpid" "$wedge" $cpids 2>/dev/null; swarm_stop; keep; }
trap cleanup EXIT INT TERM
wedge=""; cpids=""

# Host: pure DHT turnstile, wedge the first pickup, serve the later joiners, then
# exit once it has served enough of them.
COMRADE_DEBUG="$tmp/host.dbg" "$E2E" host --stuck 1 --serve 3 --timeout 120 \
	>"$tmp/host.out" 2>"$tmp/host.err" &
hpid=$!

tok=""
i=0
while [ "$i" -lt "$(e2e_loops 90)" ]; do
	cand=$(sed -n 's/^COMRADE TOKEN: //p' "$tmp/host.out" 2>/dev/null | tail -1)
	if [ -n "$cand" ] && "$E2E" token "$cand" 2>/dev/null |
	   grep -q 'state[46]=RENDEZVOUS'; then
		tok="$cand"; break
	fi
	if ! kill -0 "$hpid" 2>/dev/null; then
		echo "host exited before minting a token"; cat "$tmp/host.err"; exit 1
	fi
	sleep 1; i=$((i + 1))
done
if [ -z "$tok" ]; then echo "no rendezvous token after ${i}s"; cat "$tmp/host.err"; exit 1; fi

# The head-start joiner claims first and becomes the wedged one. It never gets
# served (by design), so we do not wait on it -- it is killed at cleanup.
"$E2E" client "$tok" --hold-ms 500 --timeout 90 >"$tmp/wedge.out" 2>"$tmp/wedge.err" &
wedge=$!
sleep 4

# Later joiners, launched during the wedge. At least one must be admitted and
# connect -- impossible unless the host released on pickup.
j=0
while [ "$j" -lt 3 ]; do
	COMRADE_DEBUG="$tmp/c$j.dbg" "$E2E" client "$tok" --hold-ms 500 \
		--timeout 60 >"$tmp/c$j.out" 2>"$tmp/c$j.err" &
	cpids="$cpids $!"
	j=$((j + 1))
done

for p in $cpids; do wait "$p" 2>/dev/null || true; done

passed=0
j=0
while [ "$j" -lt 3 ]; do
	if grep -q "E2E PASS client" "$tmp/c$j.out" 2>/dev/null; then
		passed=$((passed + 1))
	fi
	j=$((j + 1))
done

if [ "$passed" -ge 1 ]; then
	echo "turnstile stuck e2e: $passed later joiner(s) admitted while the first punch hung"
	exit 0
fi
echo "turnstile stuck e2e FAILED: no later joiner was admitted during the wedged punch"
echo "--- host.err ---"; tail -6 "$tmp/host.err"
j=0
while [ "$j" -lt 3 ]; do echo "--- c$j ---"; tail -2 "$tmp/c$j.err" 2>/dev/null; j=$((j + 1)); done
exit 1
