/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The two rules that decide when the DHT routers are asked again.
 *
 * They exist because a bootstrap round is a handful of UDP packets to hosts
 * that answer when they feel like it, so whether the table ever fills is not
 * something one round can settle. The failure both rules prevent is silent: an
 * empty routing table looks exactly like a quiet network, and a node that has
 * given up looks exactly like one that is waiting.
 *
 * Neither can be exercised against a live DHT, because doing so would mean
 * arranging for the internet to fail in a particular way at a particular
 * moment, so both are pure and both are tested here -- the same reason
 * sig_tomb_settled is exported.
 */

#include <assert.h>

#include "dhtnode.h"

int main(void)
{
	uint64_t d;
	int i;

	/*
	 * A family is asked about on its own. The bug this defends against is
	 * a sum: a full IPv4 table and an empty IPv6 one adds up to plenty,
	 * and the family that has nothing is the one whose routers are thin.
	 */
	assert(dhtnode_bootstrap_wanted(1, 99, 1, 0) == 1);
	assert(dhtnode_bootstrap_wanted(1, 0, 1, 99) == 1);
	assert(dhtnode_bootstrap_wanted(1, 99, 1, 99) == 0);

	/* A family with no socket is not a family with no nodes: a v4-only
	 * node must not ask for ever on behalf of an address family it does
	 * not speak. */
	assert(dhtnode_bootstrap_wanted(1, 99, 0, 0) == 0);
	assert(dhtnode_bootstrap_wanted(0, 0, 1, 99) == 0);
	assert(dhtnode_bootstrap_wanted(0, 0, 0, 0) == 0);

	/* The threshold itself, from both sides. */
	assert(dhtnode_bootstrap_wanted(1, DHTNODE_BOOTSTRAP_MIN_GOOD - 1,
					0, 0) == 1);
	assert(dhtnode_bootstrap_wanted(1, DHTNODE_BOOTSTRAP_MIN_GOOD,
					0, 0) == 0);

	/* The first round is due one interval after the one that went out,
	 * not immediately and not never. */
	assert(dhtnode_bootstrap_backoff(0) == DHTNODE_BOOTSTRAP_FIRST_MS);

	/* It doubles, so a set that answers nothing is asked less and less
	 * rather than at the opening cadence for ever. */
	assert(dhtnode_bootstrap_backoff(DHTNODE_BOOTSTRAP_FIRST_MS) ==
	       2 * DHTNODE_BOOTSTRAP_FIRST_MS);

	/* And it stops doubling. A node with no path to the DHT at all runs
	 * for years, so the sequence has to reach a ceiling and stay there
	 * rather than overflow or drift out to never. */
	d = 0;
	for (i = 0; i < 64; i++)
		d = dhtnode_bootstrap_backoff(d);
	assert(d == DHTNODE_BOOTSTRAP_MAX_MS);
	assert(dhtnode_bootstrap_backoff(d) == DHTNODE_BOOTSTRAP_MAX_MS);

	/* The ceiling is reached from below rather than jumped past, so no
	 * interval in the sequence is longer than the ceiling. */
	d = 0;
	for (i = 0; i < 64; i++) {
		d = dhtnode_bootstrap_backoff(d);
		assert(d >= DHTNODE_BOOTSTRAP_FIRST_MS);
		assert(d <= DHTNODE_BOOTSTRAP_MAX_MS);
	}
	return 0;
}
