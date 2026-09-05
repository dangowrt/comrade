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
# So the swarm is shared and counted rather than owned. `up` joins a swarm that
# is already running and only builds one when there is none; `down` decrements
# and only tears down when the last user has gone. mkdir is the lock, because
# it is atomic everywhere and flock is not on macOS. A count left behind by a
# run that was killed is not trusted on its own: the recorded pids have to
# still be alive, or the swarm is rebuilt.
#
# Usage: swarmfix.sh <path-to-comrade-dhtseed> up|down
set -u

SEED="${1:?path to comrade-dhtseed}"
MODE="${2:?up or down}"
FILE="${COMRADE_SWARM_FILE:?COMRADE_SWARM_FILE must name where to write the list}"
PIDF="$FILE.pids"
DIRF="$FILE.dir"
NF="$FILE.n"
LOCK="$FILE.lock"

# Held only across the bookkeeping, never across starting the nodes.
swarm_lock() {
	_i=0
	while ! mkdir "$LOCK" 2>/dev/null; do
		# A lock older than a minute belonged to a run that died in it.
		if [ -d "$LOCK" ] && [ -z "$(find "$LOCK" -maxdepth 0 -mmin -1 2>/dev/null)" ]; then
			rmdir "$LOCK" 2>/dev/null
			continue
		fi
		_i=$((_i + 1))
		[ "$_i" -gt 600 ] && return 1
		sleep 0.1
	done
	return 0
}

swarm_unlock() { rmdir "$LOCK" 2>/dev/null || true; }

# Whether the nodes the pid file names are still there. A count without live
# nodes is a leftover, not a swarm.
swarm_live() {
	[ -s "$PIDF" ] || return 1
	for _p in $(cat "$PIDF"); do
		kill -0 "$_p" 2>/dev/null && return 0
	done
	return 1
}

case "$MODE" in
up)
	if [ "${COMRADE_E2E_NET:-0}" = 1 ]; then
		echo "COMRADE_E2E_NET=1: the real DHT, no swarm to build"
		exit 0
	fi
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
	if swarm_live; then
		_n=$(cat "$NF" 2>/dev/null || echo 0)
		case "$_n" in ''|*[!0-9]*) _n=0 ;; esac
		echo $((_n + 1)) > "$NF"
		swarm_unlock
		echo "swarm up: joined the swarm already running"
		exit 0
	fi
	# Nothing alive: any count and any directory left here are a dead run's.
	[ -s "$DIRF" ] && rm -rf "$(cat "$DIRF")"
	rm -f "$FILE" "$PIDF" "$DIRF" "$NF"
	. "$(dirname "$0")/swarm.sh"
	if ! swarm_start "$SEED"; then
		_rc=$?
		swarm_unlock
		exit "$_rc"
	fi
	printf '%s' "$COMRADE_DHT_BOOTSTRAP" > "$FILE"
	printf '%s' "$SWARM_PIDS" > "$PIDF"
	printf '%s' "$SWARM_DIR" > "$DIRF"
	echo 1 > "$NF"
	swarm_unlock
	# The count, not the list: this line lands in a workflow log, and the
	# addresses in it are the runner's own.
	echo "swarm up: $(printf '%s\n' "$COMRADE_DHT_BOOTSTRAP" |
			  awk -F, '{print NF}') node(s)"
	;;
down)
	swarm_lock || { echo "swarm down: could not take the lock" >&2; exit 0; }
	_n=$(cat "$NF" 2>/dev/null || echo 0)
	case "$_n" in ''|*[!0-9]*) _n=0 ;; esac
	_n=$((_n - 1))
	if [ "$_n" -gt 0 ]; then
		echo "$_n" > "$NF"
		swarm_unlock
		echo "swarm down: $_n run(s) still using it"
		exit 0
	fi
	# shellcheck disable=SC2046
	[ -s "$PIDF" ] && kill $(cat "$PIDF") 2>/dev/null
	[ -s "$DIRF" ] && rm -rf "$(cat "$DIRF")"
	rm -f "$FILE" "$PIDF" "$DIRF" "$NF"
	swarm_unlock
	echo "swarm down"
	;;
*)
	echo "usage: $0 <comrade-dhtseed> up|down" >&2
	exit 2
	;;
esac
exit 0
