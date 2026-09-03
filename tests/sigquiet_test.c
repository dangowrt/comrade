/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdint.h>
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

/*
 * A HOST'S SECOND OFFER WAITS FOR THE CANDIDATES TO STOP ARRIVING.
 *
 * Gathering produces candidates over seconds and posts an offer for each, and
 * storing every one of them is a round trip and a sequence bump for a
 * description superseded a moment later. The first is never waited on: nothing
 * can find the host until an offer is stored.
 */
static void a_settled_offer_is_stored_once(void)
{
	uint64_t t = 1000000;

	/* Nothing of ours out there yet: at once, whoever we are. */
	assert(sig_offer_settle_until(1, 0, 1, t) == 0);
	assert(sig_offer_settle_until(0, 0, 1, t) == 0);

	/* A client is claiming a mutex and never waits. */
	assert(sig_offer_settle_until(0, 1, 1, t) == 0);

	/*
	 * A CHANGE THAT IS NOT GATHERING GOES AT ONCE. A rotation, a
	 * resumption under a fresh password, a rebuilt agent -- somebody is
	 * already waiting on each of those, and the wait exists to save
	 * needless stores, not to hold up the session.
	 */
	assert(sig_offer_settle_until(1, 1, 0, t) == 0);

	/* Only more candidates wait, and each new one puts the wait back to
	 * the beginning rather than shortening it. */
	assert(sig_offer_settle_until(1, 1, 1, t) > t);
	assert(sig_offer_settle_until(1, 1, 1, t + 3000) >
	       sig_offer_settle_until(1, 1, 1, t));
}


int main(void)
{
	a_settled_offer_is_stored_once();
	a_slow_round_is_not_a_dead_one();
	an_unasking_node_is_answered_sooner();
	a_tombstone_has_to_stand();
	an_offer_since_answers_it();
	printf("sigquiet_test: ok\n");
	return 0;
}
