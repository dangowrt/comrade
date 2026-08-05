/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SSHC_H
#define COMRADE_SSHC_H

#include <stddef.h>
#include <stdint.h>

#include "token.h"

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

	/* test mode (used when interactive == 0): */
	const uint8_t *send;
	size_t send_len;
	uint8_t *recv;
	size_t recv_cap;
	size_t *recv_len;
};

/*
 * Run one SSH session on fd; blocks until it ends. Returns 0 on success,
 * -1 on any failure including a host-key fingerprint mismatch (which is
 * treated as a hard error: a mismatch means a MITM, never a prompt).
 */
int sshc_connect_fd(int fd, const struct sshc_opts *o);

#endif
