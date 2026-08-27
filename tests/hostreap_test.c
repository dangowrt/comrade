/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "hostreap.h"

/* Serving a client that has answered. */
static void serving(struct host_reap *r)
{
	memset(r, 0, sizeof(*r));
	r->pong_seen = 1;
}

/* Nothing has ever answered here. */
static void connecting(struct host_reap *r)
{
	memset(r, 0, sizeof(*r));
}

static void a_live_client_is_never_reaped(void)
{
	struct host_reap r;

	serving(&r);
	assert(host_reap_due(&r, 1) == HOST_REAP_KEEP);
	assert(host_reap_due(&r, 60 * 60 * 1000) == HOST_REAP_KEEP);
}

/* The first attempt goes missing, so the worker has to outlive it. */
static void the_second_claim_still_finds_a_worker(void)
{
	struct host_reap r;
	uint64_t second = RESUME_AFTER_MS + RESUME_ATTEMPT_MS;

	serving(&r);
	r.lost_since_ms = 1;
	assert(host_reap_due(&r, 1 + RESUME_AFTER_MS) == HOST_REAP_KEEP);
	assert(host_reap_due(&r, 1 + second) == HOST_REAP_KEEP);
	/* And once heard, the punch it starts holds the reap off. */
	r.resume_pending = 1;
	assert(host_reap_due(&r, 1 + second + HOST_REAP_MS * 4) ==
	       HOST_REAP_KEEP);
}

static void silence_past_every_attempt_reaps(void)
{
	struct host_reap r;

	serving(&r);
	r.lost_since_ms = 1;
	assert(host_reap_due(&r, 1 + HOST_REAP_MS) == HOST_REAP_KEEP);
	assert(host_reap_due(&r, 2 + HOST_REAP_MS) == HOST_REAP_SILENT);
}

/*
 * A claim picked up is the freshest thing heard, so the span runs from it --
 * and a client that claimed once and never arrived is let go like any other.
 */
static void a_claim_restarts_the_span(void)
{
	struct host_reap r;
	uint64_t claim = 1 + HOST_REAP_MS;

	serving(&r);
	r.lost_since_ms = 1;
	r.resume_last_ms = claim;
	assert(host_reap_due(&r, claim + HOST_REAP_MS) == HOST_REAP_KEEP);
	assert(host_reap_due(&r, claim + HOST_REAP_MS + 1) ==
	       HOST_REAP_SILENT);
}

/* The handshake budget decides until something answers, and not after. */
static void a_peer_that_never_handshakes_is_let_go(void)
{
	struct host_reap r;

	connecting(&r);
	assert(host_reap_due(&r, HOST_HANDSHAKE_MS) == HOST_REAP_KEEP);
	assert(host_reap_due(&r, HOST_HANDSHAKE_MS + 1) ==
	       HOST_REAP_NO_HANDSHAKE);

	serving(&r);
	assert(host_reap_due(&r, HOST_HANDSHAKE_MS * 10) == HOST_REAP_KEEP);
}

int main(void)
{
	a_live_client_is_never_reaped();
	the_second_claim_still_finds_a_worker();
	silence_past_every_attempt_reaps();
	a_claim_restarts_the_span();
	a_peer_that_never_handshakes_is_let_go();
	printf("hostreap_test: ok\n");
	return 0;
}
