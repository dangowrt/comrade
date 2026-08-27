# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org>
#
# A private DHT for the network tests to meet through. Sourced, not run.
#
# Driving these tests through the public mainline DHT made their result a
# reading of the internet: the same tree passed and failed within the hour,
# and failed on a different test each time, so a red run said nothing about
# the code. A swarm of loopback nodes that belongs to the run behaves the same
# way and answers about comrade instead.
#
# Whether the real DHT converges is a separate question, and one for a
# deliberate run against it rather than for every build.
#
# swarm_start <path-to-comrade-dhtseed> [count]  -- exports COMRADE_DHT_BOOTSTRAP
# swarm_stop                                     -- kills the nodes
#
# swarm_start returns 77 (ctest SKIP) where this machine has no address a swarm
# can be built on, and 1 where one could not be built for any other reason;
# callers pass the status straight out, since a test that cannot have a DHT has
# nothing to say either way.
#
# The nodes are addressed at one of this machine's own interface addresses,
# never 127.0.0.1: jech/dht drops any datagram whose source is a martian and
# counts loopback among them, so a loopback swarm never forms -- each member
# ignores every other and comrade ignores all of them. Each node reports the
# address it can be reached at, and this agrees with them.
#
# The run also gets a data dir of its own: COMRADE_DHT_BOOTSTRAP replaces the
# built-in routers, but the on-disk node cache is loaded whatever the bootstrap
# says, so a run without it pings every real mainline node this machine has
# cached, and a v4-only swarm leaves the v6 rendezvous to land on one of them.
# It also keeps what a run learns out of the cache the user's sessions read.
#
# jech/dht keeps its state in globals, so each node is its own process. Each is
# told where the previous ones are, which is enough for them to find each other.
#
# Eight of them by default, because that is how many a mutable item is spread
# across: a swarm smaller than k leaves the value on too few nodes, and the
# tests went back to failing now and then for want of a node to read it from
# rather than for anything comrade did.

SWARM_PIDS=""
SWARM_DIR=""

# A swarm the run already has: COMRADE_SWARM_FILE names a file the fixture
# wrote with the bootstrap list, and the nodes behind it outlive any one test.
# Building eight more per test costs a few seconds each and answers the same.
_swarm_shared() {
	[ -n "${COMRADE_SWARM_FILE:-}" ] && [ -s "${COMRADE_SWARM_FILE:-}" ]
}

# Everything the run starts reads its node cache from here, so nothing the
# machine already knows about the real DHT joins the swarm. Exported, so the
# comrade processes a test starts inherit it as well as the nodes.
_swarm_data() {
	XDG_DATA_HOME="$SWARM_DIR/data"
	mkdir -p "$XDG_DATA_HOME" || return 1
	export XDG_DATA_HOME
}

swarm_start() {
	_seed="${1:?path to comrade-dhtseed}"
	_n="${2:-8}"
	if _swarm_shared; then
		COMRADE_DHT_BOOTSTRAP=$(cat "$COMRADE_SWARM_FILE")
		export COMRADE_DHT_BOOTSTRAP
		SWARM_PIDS=""
		SWARM_DIR=$(mktemp -d)
		_swarm_data || return 1
		return 0
	fi
	_peers=""
	_boot=""
	SWARM_DIR=$(mktemp -d)
	_swarm_data || return 1
	_i=0
	while [ "$_i" -lt "$_n" ]; do
		# shellcheck disable=SC2086
		${SWARM_SPAWN:-} "$_seed" $_peers >"$SWARM_DIR/$_i.out" 2>/dev/null &
		SWARM_PIDS="$SWARM_PIDS $!"
		_w=0
		_port=""
		while [ "$_w" -lt 50 ]; do
			_port=$(sed -n 's/^port //p' "$SWARM_DIR/$_i.out" 2>/dev/null)
			[ -n "$_port" ] && [ "$_port" != 0 ] && break
			sleep 0.1
			_w=$((_w + 1))
		done
		if [ -z "$_port" ] || [ "$_port" = 0 ]; then
			echo "swarm: node $_i never reported a port" >&2
			swarm_stop
			return 1
		fi
		# After the port and not beside it: the node prints the address
		# first, so a read that has the port has the address too.
		_addr=$(sed -n 's/^addr //p' "$SWARM_DIR/$_i.out" 2>/dev/null)
		if [ -z "$_addr" ] || [ "$_addr" = "-" ]; then
			echo "skipped: no non-loopback address to build a swarm on" >&2
			swarm_stop
			return 77
		fi
		_peers="$_peers $_addr:$_port"
		_boot="${_boot:+$_boot,}$_addr:$_port"
		_i=$((_i + 1))
	done
	COMRADE_DHT_BOOTSTRAP="$_boot"
	export COMRADE_DHT_BOOTSTRAP
	# Let them find each other before anything asks them to store a value.
	sleep 2
	return 0
}

swarm_stop() {
	# A shared swarm is the fixture's to stop, not the test's.
	[ -n "$SWARM_PIDS" ] && kill $SWARM_PIDS 2>/dev/null
	[ -n "$SWARM_DIR" ] && rm -rf "$SWARM_DIR"
	SWARM_PIDS=""
	SWARM_DIR=""
}
