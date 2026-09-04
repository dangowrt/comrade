/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "claimlog.h"

/*
 * A worker one second old, and the claim that made it coming round again: the
 * password says it is the same attempt, and a resumption would have minted a
 * new one.
 */
static void the_attempt_behind_a_worker_is_known(void)
{
	assert(claim_made("92d421", "92d421"));
	assert(!claim_made("92d421", "5b0e77"));
	assert(!claim_made("", "92d421"));
	assert(!claim_made("92d421", ""));
	/* Two blanks are not a match, they are two things unknown. */
	assert(!claim_made("", ""));
}

/*
 * A claimant coming back keeps its ufrag, so the host recognises it; one
 * joining for the first time is unknown, and has no session of its own to be
 * told is over.
 */
static void a_claimant_served_before_is_known(void)
{
	struct claim_served l;
	char u[16];
	int i;

	memset(&l, 0, sizeof(l));
	assert(!claim_served_has(&l, "1f78cab7"));
	claim_served_note(&l, "1f78cab7");
	assert(claim_served_has(&l, "1f78cab7"));
	assert(!claim_served_has(&l, "dad971d7"));

	/* Noting one twice must not cost the ring an entry. */
	for (i = 0; i < CLAIM_SERVED_MAX * 2; i++)
		claim_served_note(&l, "1f78cab7");
	assert(claim_served_has(&l, "1f78cab7"));

	/* Past the ring the oldest is forgotten, and a claimant forgotten is
	 * simply treated as new. */
	memset(&l, 0, sizeof(l));
	for (i = 0; i < CLAIM_SERVED_MAX; i++) {
		snprintf(u, sizeof(u), "ufrag%d", i);
		claim_served_note(&l, u);
	}
	assert(claim_served_has(&l, "ufrag0"));
	claim_served_note(&l, "one-too-many");
	assert(!claim_served_has(&l, "ufrag0"));
	assert(claim_served_has(&l, "ufrag1"));
	assert(claim_served_has(&l, "one-too-many"));

	/* Nothing is not a claimant. */
	claim_served_note(&l, "");
	assert(!claim_served_has(&l, ""));
}

int main(void)
{
	the_attempt_behind_a_worker_is_known();
	a_claimant_served_before_is_known();
	printf("claimlog_test: ok\n");
	return 0;
}
