/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "sig.h"

/* What each route needs. A convergent one walks the DHT and is worth nothing
 * without a table; a direct one addresses the nodes already held, so a node
 * whose table never filled still has a mailbox to work. */
static void a_direct_route_needs_only_a_node(void)
{
	assert(sig_routes_open(0, 0) == 0);
	assert(sig_routes_open(0, 1) == SIG_ROUTE_DIRECT);
	assert(sig_routes_open(1, 0) == (SIG_ROUTE_DIRECT | SIG_ROUTE_WIDE));
	assert(sig_routes_open(1, 1) == (SIG_ROUTE_DIRECT | SIG_ROUTE_WIDE));

	/* The convergent route never opens alone, which is what lets a caller
	 * act on an empty mask rather than testing each bit. */
	assert(!(sig_routes_open(0, 1) & SIG_ROUTE_WIDE));
	assert(sig_routes_open(1, 0) & SIG_ROUTE_DIRECT);
}

/* A node still asking is given the long benefit of the doubt: reads cross two
 * DHTs and a slow round is not a dead rendezvous. */
static void a_slow_round_is_not_a_dead_one(void)
{
	assert(sig_quiet_due(1, 1, 0) == 0);
	assert(sig_quiet_due(1, 1, 30000) == 0);
	assert(sig_quiet_due(1, 1, 60000) == 0);
	assert(sig_quiet_due(1, 1, 60001) != 0);
}

/* A signaller with no route open is asking nothing, so waiting the long span
 * out only delays the rebuild; a moment between refreshes still has to pass. */
static void an_unasking_node_is_answered_sooner(void)
{
	assert(sig_quiet_due(0, 1, 1000) == 0);
	assert(sig_quiet_due(0, 1, 8000) == 0);
	assert(sig_quiet_due(0, 1, 8001) != 0);
	assert(sig_quiet_due(0, 1, 20000) != 0);
	/* And sooner is the point: the same age says nothing on a live node. */
	assert(sig_quiet_due(1, 1, 20000) == 0);
}

/* A signaller never answered is judged on a span of its own: the other two are
 * ages of a read, and a mailbox that never started has none to age. */
static void a_mailbox_that_never_answered(void)
{
	assert(sig_quiet_due(1, 0, 1000) == 0);
	assert(sig_quiet_due(1, 0, 45000) == 0);
	assert(sig_quiet_due(1, 0, 45001) != 0);

	/* Whether it is asking makes no difference: nothing has come back
	 * either way, and the wait is the longer of the two. */
	assert(sig_quiet_due(0, 0, 8001) == 0);
	assert(sig_quiet_due(0, 0, 45001) != 0);
}

/*
 * A tombstone is a claim anyone holding the invitation can make, so it is
 * believed only after standing a while with nothing contradicting it.
 */
static void a_tombstone_has_to_stand(void)
{
	assert(sig_tomb_settled(0, 0, 100000) == 0);	/* none seen */
	assert(sig_tomb_settled(10000, 0, 10000) == 0);
	assert(sig_tomb_settled(10000, 0, 13999) == 0);
	assert(sig_tomb_settled(10000, 0, 14000) != 0);
}

/* And an offer beside it is a host still serving, however long it has stood:
 * a forged tombstone costs a joiner a pause, never the session. */
static void an_offer_since_answers_it(void)
{
	assert(sig_tomb_settled(10000, 12000, 60000) == 0);
	/* The same read carrying both is the same answer: not ended. */
	assert(sig_tomb_settled(10000, 10000, 60000) == 0);
	/* An offer from BEFORE it says nothing; that host has gone quiet. */
	assert(sig_tomb_settled(10000, 9999, 14000) != 0);
}

int main(void)
{
	a_direct_route_needs_only_a_node();
	a_slow_round_is_not_a_dead_one();
	an_unasking_node_is_answered_sooner();
	a_mailbox_that_never_answered();
	a_tombstone_has_to_stand();
	an_offer_since_answers_it();
	printf("sigquiet_test: ok\n");
	return 0;
}
