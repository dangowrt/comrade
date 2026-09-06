#!/bin/sh
# One swarm for the whole run, as a ctest fixture.
#
# Every DHT test used to build its own eight nodes and throw them away, which
# is a few seconds each and answers the same question every time. The nodes
# here outlive any one test; a test finds them through COMRADE_SWARM_FILE and
# leaves them alone (tests/swarm.sh). Nothing depends on this working: with no
# file to read, each test builds its own swarm exactly as before.
#
# Two runs against one build directory used to dismantle each other's swarm:
# the list and the pids go to fixed paths here, so a second `up` overwrote the
# first run's pid file -- orphaning its nodes -- and the first `down` then
# killed whatever pids the file named by then, which were the second run's.
# A test that passed alone failed in company for that reason and no other.
#
# So the swarm is shared and its users are recorded rather than counted. `up`
# joins a swarm that is running and in use and only builds one when there is
# none; `down` withdraws its user and tears down when no live user is left. A
# user is the ctest that asked, named by its pid, and is live while that
# process is: a run that was killed leaves no user behind that counts, so
# the nodes it started come down with the next `down` and a later `up`
# rebuilds them from the binary it was given. mkdir is the lock, because it
# is atomic everywhere and flock is not on macOS.
#
# Usage: swarmfix.sh <path-to-comrade-dhtseed> up|down
set -u

SEED="${1:?path to comrade-dhtseed}"
MODE="${2:?up or down}"
FILE="${COMRADE_SWARM_FILE:?COMRADE_SWARM_FILE must name where to write the list}"
PIDF="$FILE.pids"
DIRF="$FILE.dir"
USERS="$FILE.users"
LOCK="$FILE.lock"
SEEDNAME=$(basename "$SEED")

# Held across the bookkeeping and, on the run that builds the swarm, across
# starting it. The holder's pid is in the lock, and a lock is stale only when
# that holder is gone: a wait on a live one is bounded by its work, not a clock.
swarm_lock() {
	_i=0
	while ! mkdir "$LOCK" 2>/dev/null; do
		_h=$(cat "$LOCK/pid" 2>/dev/null)
		if [ -n "$_h" ] && ! kill -0 "$_h" 2>/dev/null; then
			rm -rf "$LOCK"
			continue
		fi
		_i=$((_i + 1))
		[ "$_i" -gt 3000 ] && return 1
		sleep 0.1
	done
	echo "$$" > "$LOCK/pid"
	return 0
}

swarm_unlock() { rm -rf "$LOCK"; }

# A pid that is still one of our nodes, not a number the system has reused.
seed_pid() {
	case "$(ps -o comm= -p "$1" 2>/dev/null)" in
	*"$SEEDNAME"*) return 0 ;;
	esac
	return 1
}

# Whether the nodes the pid file names are still there.
swarm_live() {
	[ -s "$PIDF" ] || return 1
	for _p in $(cat "$PIDF"); do
		seed_pid "$_p" && return 0
	done
	return 1
}

# Whether any user recorded is still a running process; the dead are dropped.
users_live() {
	_live=1
	for _u in "$USERS"/*; do
		[ -e "$_u" ] || continue
		if kill -0 "$(basename "$_u")" 2>/dev/null; then
			_live=0
		else
			rm -f "$_u"
		fi
	done
	return $_live
}

swarm_teardown() {
	for _p in $(cat "$PIDF" 2>/dev/null); do
		seed_pid "$_p" && kill "$_p" 2>/dev/null
	done
	[ -s "$DIRF" ] && rm -rf "$(cat "$DIRF")"
	rm -rf "$FILE" "$PIDF" "$DIRF" "$USERS"
}

if [ "${COMRADE_E2E_NET:-0}" = 1 ]; then
	echo "COMRADE_E2E_NET=1: the real DHT, no swarm to build or take down"
	exit 0
fi

case "$MODE" in
up)
	# Detached, so they outlive the process that starts them. setsid is
	# util-linux's and macOS has none, where nohup does the same for this
	# purpose; a machine with neither still gets nodes, just ones a stray
	# hangup could take with it.
	if command -v setsid >/dev/null 2>&1; then
		SWARM_SPAWN=setsid
	elif command -v nohup >/dev/null 2>&1; then
		SWARM_SPAWN=nohup
	else
		SWARM_SPAWN=
	fi
	export SWARM_SPAWN
	swarm_lock || { echo "swarm up: could not take the lock" >&2; exit 1; }
	mkdir -p "$USERS"
	if swarm_live && users_live; then
		touch "$USERS/$PPID"
		swarm_unlock
		echo "swarm up: joined the swarm already running"
		exit 0
	fi
	# Nothing alive, or nobody left using what is: a dead run's, or an
	# older binary's, and either is rebuilt.
	swarm_teardown
	. "$(dirname "$0")/swarm.sh"
	swarm_start "$SEED"
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		swarm_unlock
		exit "$_rc"
	fi
	printf '%s' "$COMRADE_DHT_BOOTSTRAP" > "$FILE"
	printf '%s' "$SWARM_PIDS" > "$PIDF"
	printf '%s' "$SWARM_DIR" > "$DIRF"
	mkdir -p "$USERS"
	touch "$USERS/$PPID"
	swarm_unlock
	# The count, not the list: this line lands in a workflow log, and the
	# addresses in it are the runner's own.
	echo "swarm up: $(printf '%s\n' "$COMRADE_DHT_BOOTSTRAP" |
			  awk -F, '{print NF}') node(s)"
	;;
down)
	swarm_lock || { echo "swarm down: could not take the lock" >&2; exit 0; }
	rm -f "$USERS/$PPID"
	if users_live; then
		swarm_unlock
		echo "swarm down: still in use"
		exit 0
	fi
	swarm_teardown
	swarm_unlock
	echo "swarm down"
	;;
*)
	echo "usage: $0 <comrade-dhtseed> up|down" >&2
	exit 2
	;;
esac
exit 0
