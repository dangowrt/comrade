/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SSHC_H
#define COMRADE_SSHC_H

#include <stddef.h>
#include <stdint.h>

#include "conn.h"
#include "fwdspec.h"
#include "token.h"
#include "wsock.h"

/*
 * comrade SSH client. Connects over an already-connected byte stream, pins the
 * server's ephemeral host key against the fingerprint carried in the token
 * (no trust-on-first-use), and authenticates with the token's auth secret.
 *
 * Two I/O modes: an interactive terminal bridge (the product), and a
 * request/response test mode (send a buffer, collect the echoed reply) used
 * to validate the whole stack without a controlling tty.
 */

struct sshc_opts {
	uint8_t host_fp[32];		/* pinned SHA-256 host-key fingerprint */
	uint8_t auth[TOKEN_AUTH_LEN];	/* session password material */

	int interactive;		/* bridge local stdin/stdout raw */
	int forward_only;		/* -N: request no shell, forward only */
	int connect_timeout_s;		/* SSH_OPTIONS_TIMEOUT; 0 = libssh default */

	/*
	 * View-only grade (the token carried TOKEN_FLAG_RO). Keystrokes never
	 * reach the host's tmux, so the usual detach/exit keys do nothing; the
	 * interactive client watches for the tmux prefix followed by a
	 * detach/exit key and leaves locally instead. Ignored for a read-write
	 * client, whose keys must pass through to the real tmux untouched.
	 */
	int read_only;

	/*
	 * Optional control-plane fd. When > 0, the client opens one extra SSH
	 * channel (subsystem "comrade-ctl") alongside the shell channel and
	 * bridges it to this fd, carrying the session's control protocol inside
	 * the authenticated SSH session. 0/-1 leaves the single-channel path.
	 */
	sock_t ctl_fd;

	/*
	 * TCP port forwarding, OpenSSH semantics: fwd_l are -L specs (listen
	 * locally, connect from the host), fwd_r are -R specs (host listens,
	 * connect back here). Served alongside the shell on the same
	 * authenticated session; a host may refuse (--no-forwarding), which
	 * fails the individual forward, never the session.
	 */
	const struct fwdspec *fwd_l;
	int nfwd_l;
	const struct fwdspec *fwd_r;
	int nfwd_r;

	/*
	 * Optional transport back-pressure for the forwards (sshfwd_set_tx_room):
	 * bulk is fed only while tx_room(tx_room_arg) is nonzero, keeping the
	 * terminal and control plane responsive under a saturating transfer.
	 * NULL means unthrottled.
	 */
	int (*tx_room)(void *arg);
	void *tx_room_arg;

	/*
	 * Optional local status. When set, interactive mode reserves the bottom
	 * terminal row (runs the remote tmux one row shorter) and has the view
	 * paint this connection status there each tick -- staying live even when
	 * the link is down. The controller supplies data only; fill *out.
	 */
	void (*status)(void *arg, struct conn_status *out);
	void *status_arg;

	/* test mode (used when interactive == 0): */
	const uint8_t *send;
	size_t send_len;
	uint8_t *recv;
	size_t recv_cap;
	size_t *recv_len;
	/* Set by the harness to wind the hold up now. A test holds a session
	 * open to watch something happen to it, and how long that takes is the
	 * question, not something to be guessed at in advance: it waits for the
	 * evidence and then says so here. */
	volatile int *stop;
	int hold_ms;			/* after the echo, keep the session open this
					 * long (test: stay connected while another
					 * client joins) */
};

/*
 * The interactive session gave up on a path lost past the grace window and
 * wants the caller to rejoin (re-punch and re-attach) as a fresh client, rather
 * than end -- the shared session lives on the host, so a reconnect is just a new
 * attach. Distinct from 0 (clean end) and -1 (failure).
 */
#define SSHC_RECONNECT 2

/* How long the link may stay down before the interactive client gives up on
 * it and asks to rejoin as a fresh session. The last resort, not the first:
 * the connection resumes itself in place (resume_tick re-claims under the
 * session identity within seconds, and the host grafts the punch into the
 * worker it already runs), so this only fires when that keeps failing --
 * the worker reaped, the host gone, the network refusing every punch. */
/* Counted on the heartbeat pong, at tens of pongs to the second of it, so
 * nothing short of a session's absence reaches it -- and long enough that a
 * resume which is merely slow finishes first and never trips it. */
#define SSHC_REJOIN_GRACE_S 75

/*
 * Run one SSH session on fd; blocks until it ends. Returns 0 on a clean end,
 * SSHC_RECONNECT if the caller should rejoin after a lost path, or -1 on any
 * failure including a host-key fingerprint mismatch (which is treated as a hard
 * error: a mismatch means a MITM, never a prompt).
 */
int sshc_connect_fd(sock_t fd, const struct sshc_opts *o);

#endif
