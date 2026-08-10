/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SESSION_H
#define COMRADE_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "token.h"

/*
 * One comrade session: rendezvous over sig (DHT and/or multicast), punch a path
 * (ICE for routable, direct UDP for link-local), bring up KCP, and run SSH on
 * top -- a host serving a command, or a client attaching to it. This is the
 * connect+SSH core the e2e test harness and the product CLI both build on.
 */

/*
 * MVC seam. session_run is the controller: it drives the model (sig/nat/...)
 * and publishes semantic progress here, knowing nothing about how -- or
 * whether -- it is drawn. A view (src/ui.c) subscribes; the e2e harness passes
 * none. Every field is optional; a NULL callback is simply skipped.
 */
enum {					/* net path kinds for obs.net */
	SESSION_NET_DIRECT,		/* locally gathered host candidate */
	SESSION_NET_STUN,		/* server-reflexive, learnt via STUN */
	SESSION_NET_LINK		/* link-local multicast segment */
};
enum {					/* peer lifecycle for obs.peer */
	SESSION_PEER_SEEN,		/* mailbox read: peer endpoints known */
	SESSION_PEER_PUNCHING,		/* negotiating a path */
	SESSION_PEER_LIVE		/* a path carries the session */
};

struct session_obs {
	void *arg;
	/* A local network path became available (family: 4 or 6). */
	void (*net)(void *arg, int kind, int family, const char *addr);
	/* A per-family rendezvous node: located (host) or seeded (client). */
	void (*rendezvous)(void *arg, int family, const char *addr, int ready);
	/* The invite token is minted and ready to share (host). */
	void (*token)(void *arg, const char *token_str);
	/* The peer advanced to `state` (SESSION_PEER_*); addr may be "". */
	void (*peer)(void *arg, int state, const char *addr);
	/* The client had to fall back from a seeded node to a full DHT warm. */
	void (*escalate)(void *arg, const char *why);
	/* A path is up and the session is about to seize the terminal. */
	void (*established)(void *arg);
	/* Periodic heartbeat, ~10/s: advance spinners, repaint. */
	void (*tick)(void *arg);
};

struct session_cfg {
	int is_host;
	struct token tok;		/* rdv/auth/hostpub, and (client) the
					 * rendezvous node(s) to seed */

	unsigned sig_flags;		/* SIG_DHT | SIG_MCAST */
	int family;			/* 0 = every family */
	const char *stun_host;		/* NULL with stun_auto=0 => no STUN */
	uint16_t stun_port;
	int stun_auto;			/* rotate community STUN servers */
	int log_level;			/* libjuice log level, <0 = quiet */
	int connect_timeout_s;		/* give up establishing after this */

	/* Host only. */
	void *hostkey;			/* ssh_key (private) */
	const char *ssh_command;	/* command to serve; NULL => tmux default */
	int use_pty;			/* allocate a pty (interactive/tmux) */
	/*
	 * Called once the rendezvous is ready to advertise: with the located
	 * DHT node (embed it in the token), or NULL/0 when there is none to
	 * embed (multicast-only) so the token can be published immediately.
	 */
	void (*on_rendezvous)(void *arg, const struct sockaddr *sa, socklen_t len);
	void *arg;

	/* Progress observer (the view); NULL for a headless run. */
	const struct session_obs *obs;

	/* Client only. */
	int interactive;		/* bridge the local terminal */
	/* Client non-interactive test mode (e2e): send a buffer, collect echo. */
	const uint8_t *test_send;
	size_t test_send_len;
	uint8_t *test_recv;
	size_t test_recv_cap;
	size_t *test_recv_len;
};

/* Run the session to completion; returns 0 on success, non-zero on failure. */
int session_run(const struct session_cfg *cfg);

#endif
