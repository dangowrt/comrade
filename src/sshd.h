/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SSHD_H
#define COMRADE_SSHD_H

#include <stdint.h>

#include "token.h"
#include "wsock.h"

/*
 * comrade SSH server. Runs a single session over an already-connected byte
 * stream (a socketpair end that the caller bridges to the punched KCP path,
 * or a bare fd for local tests). The host identity is an ephemeral ed25519
 * key whose SHA-256 fingerprint the client pins from the token, so there is
 * no trust-on-first-use and no MITM window. The only credential is the
 * token's 16-byte auth secret, offered as an SSH password.
 */

struct sshd_opts {
	void *hostkey;			/* ssh_key (private), from sshd_hostkey_new */
	uint8_t auth[TOKEN_AUTH_LEN];	/* session password material */
	/*
	 * A second accepted secret that marks the client read-only. It is the
	 * one-way derivation of auth (keys_derive_ro_auth): a guest holding it
	 * authenticates but is served command_ro instead of command, and cannot
	 * recover the read-write secret. have_ro gates whether it is honoured.
	 */
	uint8_t auth_ro[TOKEN_AUTH_LEN];
	int have_ro;
	const char *command;		/* /bin/sh -c argument; NULL => default */
	const char *command_ro;		/* served to a read-only client; NULL => command */
	int use_pty;			/* allocate a pty (interactive shell/tmux) */
	/*
	 * Optional end-of-session fd. The command we run is `tmux attach`, which
	 * does not reliably exit when the shared session it serves is destroyed
	 * (it may print "[exited]" and linger), so watching the child pid is not
	 * enough. When >0, this fd is polled while serving; it becoming readable
	 * (typically EOF from a liveness monitor that exits with the session)
	 * means the session is over, so we close the channel toward the client
	 * at once rather than leave it hanging. 0 disables it (child-exit only).
	 * A socket, not any fd: it joins the WSAPoll set on Windows, where the
	 * monitor is a thread watching a process HANDLE rather than a pipe.
	 */
	sock_t end_fd;
	/*
	 * Optional control-plane fd. When > 0, the server accepts one extra SSH
	 * channel whose subsystem is "comrade-ctl" and bridges it to this fd, so
	 * the session layer can run an authenticated control protocol (liveness,
	 * rendezvous exchange) inside the SSH session rather than over the raw
	 * transport. The shell channel is unaffected. Dispatch is by subsystem
	 * name, leaving room for future services (comrade-transfer, ...). 0/-1
	 * disables it, in which case behaviour is exactly the single-channel one.
	 */
	sock_t ctl_fd;
	/*
	 * Decline all TCP port forwarding (client -L/-R): direct-tcpip channel
	 * opens and tcpip-forward global requests are refused. The zero value
	 * allows forwarding, matching the all-tokens-are-equal trust model;
	 * a host operator opts out with --no-forwarding.
	 */
	int no_fwd;
	/*
	 * Optional transport back-pressure for the forwards (sshfwd_set_tx_room):
	 * bulk is fed only while tx_room(tx_room_arg) is nonzero, keeping the
	 * terminal and control plane responsive under a saturating transfer.
	 * NULL means unthrottled.
	 */
	int (*tx_room)(void *arg);
	void *tx_room_arg;
	/*
	 * Optional out-parameter for the read-only grade. Only the auth exchange
	 * knows which secret a client presented, so when non-NULL this is set to
	 * 1/0 once the client has authenticated, letting the controller mark that
	 * worker read-only in the view. Read from another thread, so volatile.
	 */
	volatile int *ro_out;
};

/*
 * Generate an ephemeral ed25519 host key and fill fp with its SHA-256
 * fingerprint: the 32 bytes to place in token.hostpub for the client to pin.
 * Returns an opaque ssh_key (free with sshd_hostkey_free) or NULL.
 */
void *sshd_hostkey_new(uint8_t fp[32]);
void sshd_hostkey_free(void *hostkey);

/*
 * Serve exactly one SSH session on fd; blocks until the session ends.
 * Returns 0 on a clean session, -1 on error. Does not take ownership of
 * o->hostkey (imports a copy).
 */
int sshd_serve_fd(sock_t fd, const struct sshd_opts *o);

#endif
