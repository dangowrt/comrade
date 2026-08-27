/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>

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

int main(void)
{
	the_attempt_behind_a_worker_is_known();
	printf("claimlog_test: ok\n");
	return 0;
}
