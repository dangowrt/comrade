#!/bin/sh
# What `comrade stop` reports about the session it was asked to end.
#
# Three answers, and the difference between them is the whole point: nothing
# running is quiet and successful (stop is idempotent, and a supervisor that
# calls it twice must not see an error the second time); a live session is
# ended, and reported as ended only once the service is actually gone; a
# session whose service cannot answer is reported as still running rather than
# claimed as stopped, so a supervisor that waits for the process to go is not
# left waiting for ever.
#
# Runs against a state directory of its own, so nothing here can touch, list or
# end a session the machine is really hosting.
#
# Usage: stop.sh <path-to-comrade>
set -u

CR="${1:?path to comrade}"

. "$(dirname "$0")/redact.sh"
redact_output

tmp=$(mktemp -d)
hpid=""

cleanup() {
	[ -n "$hpid" ] && {
		kill -CONT "$hpid" 2>/dev/null
		kill -KILL "$hpid" 2>/dev/null
		wait "$hpid" 2>/dev/null
	}
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

COMRADE_STATE_DIR="$tmp/state"
XDG_DATA_HOME="$tmp/data"
export COMRADE_STATE_DIR XDG_DATA_HOME
mkdir -p "$COMRADE_STATE_DIR" "$XDG_DATA_HOME" || exit 1
# comrade refuses a state directory anyone else can read.
chmod 700 "$COMRADE_STATE_DIR" || exit 1

rc=0
fail() { echo "FAILED: $*"; rc=1; }

# A phase that cannot run at all is a skip -- unless something has already
# failed, and then the failure is the answer.
skip() {
	echo "skipped: $*"
	[ "$rc" = 0 ] && exit 77
	exit "$rc"
}

# The pidfile is written once startup has succeeded, so it is what says the
# service is up -- and it is the file stop resolves the session through.
wait_pid() {
	i=0
	while [ "$i" -lt 100 ]; do
		[ -s "$COMRADE_STATE_DIR/$1.pid" ] && return 0
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

# start <id> -- a headless host with no DHT, so the run stays on this machine
# and needs no swarm; forwarding-only, so it needs no tmux either.
start() {
	_id=$1
	"$CR" --headless --forward-only --id "$_id" --no-dht \
		>"$tmp/$_id.json" 2>"$tmp/$_id.err" &
	hpid=$!
	wait_pid "$_id"
}

# ---- 1: nothing was ever published ----------------------------------------
if ! out=$("$CR" stop --id ghost 2>&1); then
	fail "stopping a session that never ran is an error: $out"
elif [ -n "$out" ]; then
	fail "stopping a session that never ran said: $out"
else
	echo "no such session: quiet and successful"
fi

# ---- 2: a live session ----------------------------------------------------
start live || skip "the host never started (see $tmp)"
if ! out=$("$CR" stop --id live 2>&1); then
	fail "stopping a live session reported failure: $out"
elif kill -0 "$hpid" 2>/dev/null; then
	fail "stop returned success with the service still running"
else
	echo "a live session: ended, and reported as ended"
fi
wait "$hpid" 2>/dev/null
hpid=""
# And it is gone from the machine interface as well.
"$CR" show --json | grep -q '"sessions":\[\]' ||
	fail "show --json still lists a session after stop"

# ---- 3: a session whose service cannot answer -----------------------------
# SIGSTOP is a service that is there and does not answer: the signals stop
# sends are never handled, so the process outlives the call. That is the
# wedged host, without needing one to actually wedge.
start wedged || skip "the second host never started (see $tmp)"
kill -STOP "$hpid" 2>/dev/null || skip "this system cannot SIGSTOP a process"
out=$("$CR" stop --id wedged 2>&1)
sc=$?
kill -CONT "$hpid" 2>/dev/null
if [ "$sc" -eq 0 ]; then
	fail "stop claimed success against a service it did not end"
elif ! echo "$out" | grep -q "still running"; then
	fail "stop failed without saying why: $out"
else
	echo "a service that cannot answer: reported, not claimed as stopped"
fi
kill -KILL "$hpid" 2>/dev/null
wait "$hpid" 2>/dev/null
hpid=""

[ "$rc" = 0 ] && echo "stop lifecycle PASSED" || echo "stop lifecycle FAILED"
exit "$rc"
