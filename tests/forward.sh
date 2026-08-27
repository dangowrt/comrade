#!/bin/sh
# Port forwarding end to end: a -L listener on the client must carry a real
# TCP connection to a target reachable from the host.
#
# Two arrangements, because they take different paths through the host and
# only one of them was ever covered by anything:
#
#   1. an ordinary host serving a shell, client asks for one and forwards
#      alongside it -- the pump runs with a child
#   2. a --forward-only host, client asks for no shell (-N) -- the pump runs
#      with no child at all
#
#   3. an ordinary host serving a shell, client asks for none (-N) -- the
#      host must serve the forwarding and the control channel anyway, which
#      it could not while it waited for a shell request before serving
#      anything
#
# Usage: forward.sh <path-to-comrade> <path-to-comrade-dhtseed>
set -u

CR="${1:?path to comrade}"
SEED="${2:?path to comrade-dhtseed}"

. "$(dirname "$0")/redact.sh"
redact_output

command -v nc >/dev/null 2>&1 || {
	echo "skipped: needs nc for the forward target"
	exit 77
}

. "$(dirname "$0")/swarm.sh"

if [ "${COMRADE_E2E_NET:-0}" != 1 ]; then
	swarm_start "$SEED" || exit $?
fi

tmp=$(mktemp -d)
hpid=""
cpid=""
tpid=""
cleanup() {
	kill "$hpid" "$cpid" "$tpid" 2>/dev/null
	"$CR" stop --id fwdtest >/dev/null 2>&1
	swarm_stop
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# A free port for the target and one for each listener.
TPORT=15931
LPORT=15932

# The target the forward must reach: one line, then close.
( while :; do echo HELLO-FORWARD | nc -l 127.0.0.1 "$TPORT" >/dev/null 2>&1; done ) &
tpid=$!
sleep 1

# probe <port> -- prints what came back through the forward
probe() {
	i=0
	while [ "$i" -lt 20 ]; do
		got=$(nc -w 2 127.0.0.1 "$1" 2>/dev/null | head -1)
		[ "$got" = "HELLO-FORWARD" ] && { echo ok; return 0; }
		sleep 1
		i=$((i + 1))
	done
	echo "no"
	return 1
}

wait_token() {
	i=0
	while [ "$i" -lt 60 ]; do
		tok=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | tail -1)
		[ -n "$tok" ] && return 0
		sleep 1
		i=$((i + 1))
	done
	return 1
}

rc=0

# ---- 1: an ordinary host, client forwards alongside its shell --------------
"$CR" --headless --id fwdtest --expire 200 --no-multicast \
	>"$tmp/h1.json" 2>"$tmp/h1.err" &
hpid=$!
wait_token "$tmp/h1.json" || { echo "host published no token"; exit 1; }

"$CR" "$tok" --no-multicast -L "$LPORT:127.0.0.1:$TPORT" -v \
	>"$tmp/c1.out" 2>&1 &
cpid=$!
if [ "$(probe "$LPORT")" = ok ]; then
	echo "forward with a shell: ok"
else
	echo "forward with a shell: FAILED"
	rc=1
fi
kill "$cpid" "$hpid" 2>/dev/null
"$CR" stop --id fwdtest >/dev/null 2>&1
wait "$cpid" 2>/dev/null
sleep 2

# ---- 2: a forward-only host, client asks for no shell ----------------------
LPORT=$((LPORT + 1))
"$CR" --headless --forward-only --id fwdtest --expire 200 --no-multicast \
	>"$tmp/h2.json" 2>"$tmp/h2.err" &
hpid=$!
wait_token "$tmp/h2.json" || { echo "forward-only host published no token"; exit 1; }

"$CR" "$tok" --no-multicast -N -L "$LPORT:127.0.0.1:$TPORT" -v \
	>"$tmp/c2.out" 2>&1 &
cpid=$!
if [ "$(probe "$LPORT")" = ok ]; then
	echo "forward with no shell, forward-only host: ok"
else
	echo "forward with no shell, forward-only host: FAILED"
	rc=1
fi

kill "$cpid" "$hpid" 2>/dev/null
"$CR" stop --id fwdtest >/dev/null 2>&1
wait "$cpid" 2>/dev/null
sleep 2

# ---- 3: the other spelling of the same thing, on both sides ---------------
# -N and --forward-only are one request: serve no shell. Each side used to
# accept only its own spelling and send you to the other one.
LPORT=$((LPORT + 1))
"$CR" --headless -N --id fwdtest --expire 200 --no-multicast \
	>"$tmp/h3.json" 2>"$tmp/h3.err" &
hpid=$!
wait_token "$tmp/h3.json" || { echo "host -N published no token"; exit 1; }

"$CR" "$tok" --no-multicast --forward-only -L "$LPORT:127.0.0.1:$TPORT" -v \
	>"$tmp/c3.out" 2>&1 &
cpid=$!
if [ "$(probe "$LPORT")" = ok ]; then
	echo "host -N, client --forward-only: ok"
else
	echo "host -N, client --forward-only: FAILED"
	rc=1
fi

kill "$cpid" "$hpid" 2>/dev/null
"$CR" stop --id fwdtest >/dev/null 2>&1
wait "$cpid" 2>/dev/null
sleep 2

# ---- 4: an ordinary shell-serving host, and a client that wants no shell ---
# The host must not make serving anything wait on a shell request: a client is
# entitled to ask for none, and its control channel and forwards are due to it
# either way.
LPORT=$((LPORT + 1))
"$CR" --headless --id fwdtest --expire 200 --no-multicast \
	>"$tmp/h4.json" 2>"$tmp/h4.err" &
hpid=$!
wait_token "$tmp/h4.json" || { echo "host published no token"; exit 1; }

"$CR" "$tok" --no-multicast -N -L "$LPORT:127.0.0.1:$TPORT" -v \
	>"$tmp/c4.out" 2>&1 &
cpid=$!
if [ "$(probe "$LPORT")" = ok ]; then
	echo "shell-serving host, client with no shell: ok"
else
	echo "shell-serving host, client with no shell: FAILED"
	rc=1
fi

[ "$rc" = 0 ] && echo "forward e2e PASSED" || echo "forward e2e FAILED"
exit "$rc"
