/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_HOSTREAP_H
#define COMRADE_HOSTREAP_H

#include <stdint.h>

/*
 * When a host worker gives up on the client it serves. Nothing else frees the
 * worker, its tmux client and its dashboard row: without a clean disconnect
 * the SSH bridge never ends on its own, KCP buffering a dead path forever.
 *
 * A vanished client cannot say so, so only a clock can answer -- but the span
 * is the claimant's, not one chosen here. A client that has lost its link
 * claims again after RESUME_AFTER_MS and every RESUME_ATTEMPT_MS after that,
 * so a worker reaped before the second attempt ends the session of a client
 * still coming back, over one lost claim.
 */
#define RESUME_AFTER_MS 3000
#define RESUME_ATTEMPT_MS 10000

/* Both attempts, plus half a cadence for the second to be picked up. */
#define HOST_REAP_MS (RESUME_AFTER_MS + RESUME_ATTEMPT_MS + \
		      RESUME_ATTEMPT_MS / 2)
#if HOST_REAP_MS <= RESUME_AFTER_MS + RESUME_ATTEMPT_MS
#error "a worker must outlive the claimant's second attempt"
#endif

/*
 * Before the first pong there is no link to lose and no claim to wait for, so
 * a peer that never finishes the handshake is bounded by this instead:
 * generous against a slow link's key exchange, short against a session that is
 * never coming. Not the operator's connect timeout, which would hold the
 * claimant's identity for as long as the operator is patient.
 */
#define HOST_HANDSHAKE_MS 30000

/* What the worker knows about its client, as the reap reads it. */
struct host_reap {
	uint64_t conn_start_ms;
	uint64_t lost_since_ms;		/* 0 while the link is live */
	uint64_t resume_last_ms;	/* last claim picked up, 0 if none */
	int resume_pending;		/* a punch for a claim is in flight */
	int pong_seen;			/* the control channel ever answered */
};

enum host_reap_verdict {
	HOST_REAP_KEEP = 0,
	HOST_REAP_SILENT,	/* stopped answering and stayed away */
	HOST_REAP_NO_HANDSHAKE	/* connected, never finished handshaking */
};

int host_reap_due(const struct host_reap *r, uint64_t now);

#endif /* COMRADE_HOSTREAP_H */
