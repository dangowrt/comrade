#!/bin/sh
# One swarm for the whole run, as a ctest fixture.
#
# Every DHT test used to build its own eight nodes and throw them away, which
# is a few seconds each and answers the same question every time. The nodes
# here outlive any one test; a test finds them through COMRADE_SWARM_FILE and
# leaves them alone (tests/swarm.sh). Nothing depends on this working: with no
# file to read, each test builds its own swarm exactly as before.
#
# Usage: swarmfix.sh <path-to-comrade-dhtseed> up|down
set -u

SEED="${1:?path to comrade-dhtseed}"
MODE="${2:?up or down}"
FILE="${COMRADE_SWARM_FILE:?COMRADE_SWARM_FILE must name where to write the list}"
PIDF="$FILE.pids"
DIRF="$FILE.dir"

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
	. "$(dirname "$0")/swarm.sh"
	swarm_start "$SEED" || exit $?
	printf '%s' "$COMRADE_DHT_BOOTSTRAP" > "$FILE"
	printf '%s' "$SWARM_PIDS" > "$PIDF"
	printf '%s' "$SWARM_DIR" > "$DIRF"
	# The count, not the list: this line lands in a workflow log, and the
	# addresses in it are the runner's own.
	echo "swarm up: $(printf '%s\n' "$COMRADE_DHT_BOOTSTRAP" |
			  awk -F, '{print NF}') node(s)"
	;;
down)
	# shellcheck disable=SC2046
	[ -s "$PIDF" ] && kill $(cat "$PIDF") 2>/dev/null
	[ -s "$DIRF" ] && rm -rf "$(cat "$DIRF")"
	rm -f "$FILE" "$PIDF" "$DIRF"
	echo "swarm down"
	;;
*)
	echo "usage: $0 <comrade-dhtseed> up|down" >&2
	exit 2
	;;
esac
exit 0
