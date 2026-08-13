/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SSHD_H
#define COMRADE_SSHD_H

#include <stdint.h>

#include "token.h"

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
	const char *command;		/* /bin/sh -c argument; NULL => default */
	int use_pty;			/* allocate a pty (interactive shell/tmux) */
	/*
	 * Optional liveness probe for the served session. The command we run is
	 * `tmux attach`, which -- surprisingly -- does not exit when the shared
	 * session it is attached to is destroyed (it prints "[exited]" and
	 * lingers), so watching the child pid is not enough to notice the end of
	 * the session. When set, this is polled while serving; returning zero
	 * means the session is over, and we close the channel toward the client
	 * so it does not hang. NULL disables the probe (child-exit only).
	 */
	int (*alive)(void *arg);
	void *alive_arg;
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
int sshd_serve_fd(int fd, const struct sshd_opts *o);

#endif
