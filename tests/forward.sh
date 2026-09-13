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

. "$(dirname "$0")/e2elib.sh"
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
# Each phase starts its own host, so every one of them is ended where it was
# started rather than left to the exit trap, which only ever knew the last.
# The first signal asks for a wind-down and the second is the one comrade takes
# at its word; SIGKILL is the last resort, so an instrumented build that stalls
# on its way out cannot outlive the run.
end_host() {
	hp=$1
	[ -n "$hp" ] || return 0
	for sig in TERM TERM KILL; do
		kill -"$sig" "$hp" 2>/dev/null || return 0
		i=0
		while kill -0 "$hp" 2>/dev/null && [ "$i" -lt "$(e2e_loops 20)" ]; do
			sleep 0.1
			i=$((i + 1))
		done
		kill -0 "$hp" 2>/dev/null || break
	done
	wait "$hp" 2>/dev/null
}

# The target the forward must reach: one line, then close.
# mkdir is the lock: it is atomic everywhere and flock is not on macOS.
BANNER="HELLO-FORWARD-$$"
PORTLOCK=""
TPORT=""

# A lock with no pid yet is held, not stale: that is the mkdir/write window.
port_lock() {
	lk="${TMPDIR:-/tmp}/comrade-fwdtarget-$TPORT"
	if ! mkdir "$lk" 2>/dev/null; then
		lh=$(cat "$lk/pid" 2>/dev/null)
		[ -n "$lh" ] || return 1
		kill -0 "$lh" 2>/dev/null && return 1
		# Pid gone: the orphan makes no more nc, one in flight lands.
		rm -f "$lk/pid"
		sleep 0.3
		ln=""
		for lf in "$lk"/nc.*; do
			ln="$ln $(cat "$lf" 2>/dev/null)"
		done
		rm -rf "$lk"
		for lp in $ln; do
			target_pid "$lp" && kill "$lp" 2>/dev/null
		done
		mkdir "$lk" 2>/dev/null || return 1
	fi
	echo "$$" >"$lk/pid"
	PORTLOCK="$lk"
	return 0
}

port_unlock() {
	[ -z "$PORTLOCK" ] || rm -rf "$PORTLOCK"
	PORTLOCK=""
}

# A pid the system has reused is not ours; macOS spells comm as a path.
target_pid() {
	case "$(ps -o comm= -p "$1" 2>/dev/null)" in
	nc|nc.*|ncat|*/nc|*/nc.*|*/ncat) return 0 ;;
	esac
	return 1
}

# nc is a grandchild this shell cannot signal, so kill the pid the loop records.
target_stop() {
	[ -n "$tpid" ] || return 0
	: >"$tmp/target.off"
	i=0
	while [ -e "$PORTLOCK/nc.$$" ] && [ "$i" -lt "$(e2e_loops 50)" ]; do
		np=$(cat "$PORTLOCK/nc.$$" 2>/dev/null)
		[ -n "$np" ] && target_pid "$np" && kill "$np" 2>/dev/null
		sleep 0.1
		i=$((i + 1))
	done
	kill "$tpid" 2>/dev/null
	wait "$tpid" 2>/dev/null
	tpid=""
}

# Named for this run: an orphan must not delete the next claimant's record.
target_start() {
	rm -f "$tmp/target.off" "$tmp/target.bad" "$PORTLOCK/nc.$$"
	( while [ ! -e "$tmp/target.off" ] &&
		[ "$(cat "$PORTLOCK/pid" 2>/dev/null)" = "$$" ]; do
		echo "$BANNER" | nc -l 127.0.0.1 "$TPORT" >/dev/null 2>&1 &
		np=$!
		echo "$np" >"$PORTLOCK/nc.$$"
		wait "$np" || { echo x >>"$tmp/target.bad"; sleep 0.2; }
	done
	rm -f "$PORTLOCK/nc.$$" ) &
	tpid=$!
	i=0
	while [ "$i" -lt "$(e2e_loops 25)" ]; do
		[ -e "$tmp/target.bad" ] && break
		got=$(nc -w 2 127.0.0.1 "$TPORT" 2>/dev/null | head -1)
		[ "$got" = "$BANNER" ] && return 0
		[ -n "$got" ] && break
		sleep 0.2
		i=$((i + 1))
	done
	target_stop
	return 1
}

port_claim() {
	port_lock || return 1
	target_start && return 0
	port_unlock
	return 1
}

# A state directory of its own, so the stop below reaches only this run.
COMRADE_STATE_DIR="$tmp/state"
export COMRADE_STATE_DIR

cleanup() {
	kill "$cpid" 2>/dev/null
	end_host "$hpid"
	"$CR" stop --id fwdtest >/dev/null 2>&1
	target_stop
	port_unlock
	swarm_stop
	if [ "${COMRADE_E2E_KEEP:-0}" = 1 ]; then
		echo "logs kept in $tmp"
	else
		rm -rf "$tmp"
	fi
}
trap cleanup EXIT INT TERM

mkdir -p "$COMRADE_STATE_DIR" || exit 1
chmod 700 "$COMRADE_STATE_DIR" || exit 1

TPORT=$((15000 + $$ % 15000))
n=0
while [ "$n" -lt 50 ] && ! port_claim; do
	TPORT=$((TPORT + 1))
	n=$((n + 1))
done
[ -n "$tpid" ] || { echo "no port to serve the forward target on"; exit 1; }

# The line comes after SSH auth, so these polls cover the whole connect too.
FWD_POLLS=20
[ "${COMRADE_E2E_NET:-0}" = 1 ] && FWD_POLLS=60

# forwarded <client-output> -- prints ok when the forward carried the banner
forwarded() {
	i=0
	while [ "$i" -lt "$(e2e_loops "$FWD_POLLS")" ]; do
		lport=$(sed -n 's/.*-L listening on port \([0-9][0-9]*\).*/\1/p' \
			"$1" 2>/dev/null | tail -1)
		if [ -n "$lport" ]; then
			got=$(nc -w 2 127.0.0.1 "$lport" 2>/dev/null | head -1)
			[ "$got" = "$BANNER" ] && { echo ok; return 0; }
		fi
		sleep 1
		i=$((i + 1))
	done
	echo "no"
	return 1
}

wait_token() {
	i=0
	while [ "$i" -lt "$(e2e_loops 60)" ]; do
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

"$CR" "$tok" --no-multicast -L "0:127.0.0.1:$TPORT" -v \
	>"$tmp/c1.out" 2>&1 &
cpid=$!
if [ "$(forwarded "$tmp/c1.out")" = ok ]; then
	echo "forward with a shell: ok"
else
	echo "forward with a shell: FAILED"
	rc=1
fi
kill "$cpid" 2>/dev/null
end_host "$hpid"
"$CR" stop --id fwdtest >/dev/null 2>&1
wait "$cpid" 2>/dev/null
sleep 2

# ---- 2: a forward-only host, client asks for no shell ----------------------
"$CR" --headless --forward-only --id fwdtest --expire 200 --no-multicast \
	>"$tmp/h2.json" 2>"$tmp/h2.err" &
hpid=$!
wait_token "$tmp/h2.json" || { echo "forward-only host published no token"; exit 1; }

"$CR" "$tok" --no-multicast -N -L "0:127.0.0.1:$TPORT" -v \
	>"$tmp/c2.out" 2>&1 &
cpid=$!
if [ "$(forwarded "$tmp/c2.out")" = ok ]; then
	echo "forward with no shell, forward-only host: ok"
else
	echo "forward with no shell, forward-only host: FAILED"
	rc=1
fi

kill "$cpid" 2>/dev/null
end_host "$hpid"
"$CR" stop --id fwdtest >/dev/null 2>&1
wait "$cpid" 2>/dev/null
sleep 2

# ---- 3: the other spelling of the same thing, on both sides ---------------
# -N and --forward-only are one request: serve no shell. Each side used to
# accept only its own spelling and send you to the other one.
"$CR" --headless -N --id fwdtest --expire 200 --no-multicast \
	>"$tmp/h3.json" 2>"$tmp/h3.err" &
hpid=$!
wait_token "$tmp/h3.json" || { echo "host -N published no token"; exit 1; }

"$CR" "$tok" --no-multicast --forward-only -L "0:127.0.0.1:$TPORT" -v \
	>"$tmp/c3.out" 2>&1 &
cpid=$!
if [ "$(forwarded "$tmp/c3.out")" = ok ]; then
	echo "host -N, client --forward-only: ok"
else
	echo "host -N, client --forward-only: FAILED"
	rc=1
fi

kill "$cpid" 2>/dev/null
end_host "$hpid"
"$CR" stop --id fwdtest >/dev/null 2>&1
wait "$cpid" 2>/dev/null
sleep 2

# ---- 4: an ordinary shell-serving host, and a client that wants no shell ---
# The host must not make serving anything wait on a shell request: a client is
# entitled to ask for none, and its control channel and forwards are due to it
# either way.
"$CR" --headless --id fwdtest --expire 200 --no-multicast \
	>"$tmp/h4.json" 2>"$tmp/h4.err" &
hpid=$!
wait_token "$tmp/h4.json" || { echo "host published no token"; exit 1; }

"$CR" "$tok" --no-multicast -N -L "0:127.0.0.1:$TPORT" -v \
	>"$tmp/c4.out" 2>&1 &
cpid=$!
if [ "$(forwarded "$tmp/c4.out")" = ok ]; then
	echo "shell-serving host, client with no shell: ok"
else
	echo "shell-serving host, client with no shell: FAILED"
	rc=1
fi

[ "$rc" = 0 ] && echo "forward e2e PASSED" || echo "forward e2e FAILED"
exit "$rc"
