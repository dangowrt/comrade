/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CONN_H
#define COMRADE_CONN_H

/*
 * Structured connection status -- plain data the controller (session.c) fills
 * in and the view renders. No display text or terminal I/O here;
 * that keeps the model/controller side free of view concerns (see the MVC
 * split).
 */

/*
 * Appended to, never reordered: the scale below crosses the service/foreground
 * event stream, and a zeroed one has to keep meaning "connecting".
 */
enum conn_state {
	CONN_CONNECTING,
	CONN_GATHERING,
	CONN_PUNCHING,
	CONN_LIVE,
	CONN_LOST,
	/*
	 * Answering, but not lately. Between live and lost there is a stretch
	 * where the last thing heard is old enough to notice and not old
	 * enough to give up on, and calling that live is how a link that has
	 * quietly stopped looks fine right up until it is declared gone.
	 */
	CONN_LAGGED,
	/*
	 * Nothing has been heard on this network yet. Not a claim that the
	 * peer is unreachable -- a claim that we have no evidence either way,
	 * which is what a move leaves us with: every path was proven somewhere
	 * else, and only traffic arriving here can prove one again.
	 */
	CONN_UNKNOWN
};

struct conn_status {
	int state;			/* enum conn_state */
	char peer[80];			/* the in-use path's remote addr, "" if none */
	char rdv[80];			/* IPv4 rendezvous node, "" if none */
	char rdv6[80];			/* IPv6 rendezvous node, "" if none */
	int rtt_ms;			/* smoothed RTT, 0 if unknown */
	int rtt_known;			/* and it was measured: 0ms means under
					 * a millisecond, not unknown */
	int since_s;			/* seconds in the current state (loss age) */
	/* How long since the session itself last answered -- the heartbeat
	 * pong, which is end to end through SSH -- or -1 before the first one.
	 * A path can be carrying frames while the session behind it is gone,
	 * so this is the question "is there still a session here", which the
	 * path's own liveness cannot answer. */
	int silent_s;
	/* The peer said outright that the session this connection carried is
	 * over: it is serving us from a worker we were never part of. Waiting
	 * on silence is what this end does when nobody says anything. */
	int gone;
	int read_only;			/* this side is a view-only guest */
	/* Distinct paths a probe has ever qualified to this peer, the one in use
	 * included: what it is known reachable on, counted as the host dashboard
	 * counts it. */
	int nproven;
};

#endif
