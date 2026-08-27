/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>

#include "sig.h"

/* A node still asking is given the long benefit of the doubt: reads cross two
 * DHTs and a slow round is not a dead rendezvous. */
static void a_slow_round_is_not_a_dead_one(void)
{
	assert(sig_quiet_due(1, 0) == 0);
	assert(sig_quiet_due(1, 30000) == 0);
	assert(sig_quiet_due(1, 60000) == 0);
	assert(sig_quiet_due(1, 60001) != 0);
}

/* A node with no table is not asking at all, so waiting the long span out only
 * delays the rebuild -- but a moment between refreshes still has to pass. */
static void an_unasking_node_is_answered_sooner(void)
{
	assert(sig_quiet_due(0, 1000) == 0);
	assert(sig_quiet_due(0, 8000) == 0);
	assert(sig_quiet_due(0, 8001) != 0);
	assert(sig_quiet_due(0, 20000) != 0);
	/* And sooner is the point: the same age says nothing on a live node. */
	assert(sig_quiet_due(1, 20000) == 0);
}

int main(void)
{
	a_slow_round_is_not_a_dead_one();
	an_unasking_node_is_answered_sooner();
	printf("sigquiet_test: ok\n");
	return 0;
}
