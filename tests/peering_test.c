/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "peering.h"

/* What a producer thread posts, the loop takes, and nothing is left behind. */
static void what_is_posted_is_taken_once(void)
{
	struct nsfact out[NSFACTS_OUT];
	struct peering_facts f;
	uint8_t a[4] = { 198, 51, 100, 9 };

	peering_facts_init(&f);
	assert(!peering_facts_take(&f, out, NSFACTS_OUT));

	peering_facts_post(&f, NSF_ROUNDTRIP, 4, 3);
	peering_facts_post_addr(&f, 4, 3, a, "198.51.100.9");
	assert(peering_facts_take(&f, out, NSFACTS_OUT) == 2);
	assert(!peering_facts_take(&f, out, NSFACTS_OUT));
	peering_facts_destroy(&f);
}

/*
 * A fact is fed under the epoch the MODEL is on, not the one it was posted
 * with: a playbook holding a model per peer stamps what it learns with its own
 * generation and hands it to each of them under theirs.
 */
static void a_fact_is_fed_under_the_model_s_own_epoch(void)
{
	const struct netstate_row *rows;
	struct nsfact out[NSFACTS_OUT];
	struct peering_facts f;
	struct netstate ns;
	uint8_t a[4] = { 198, 51, 100, 9 };

	peering_facts_init(&f);
	netstate_init(&ns, 1, 1000);
	/* Posted under a generation of the machine's own, which is not the
	 * epoch this model counts in. */
	peering_facts_post_addr(&f, 4, 77, a, "198.51.100.9");
	assert(peering_facts_take(&f, out, NSFACTS_OUT) == 1);

	assert(!peering_facts_feed(&ns, &out[0], 77, 1000));
	assert(!netstate_rows(&ns, 4, &rows));	/* not this model's epoch */

	assert(!peering_facts_feed(&ns, &out[0], netstate_epoch(&ns, 4), 1000));
	assert(netstate_rows(&ns, 4, &rows) == 1);
	assert(!strcmp(rows[0].text, "198.51.100.9"));
	assert(rows[0].scope == NET_SCOPE_GLOBAL);
	peering_facts_destroy(&f);
}

/* An address is classified by scope as it is fed, since that is what the model
 * ranks it on. */
static void an_address_is_classified_as_it_is_fed(void)
{
	const struct netstate_row *rows;
	struct peering_facts f;
	struct nsfact q;
	struct netstate ns;
	uint8_t a[4] = { 100, 64, 0, 1 };

	peering_facts_init(&f);
	netstate_init(&ns, 1, 1000);
	memset(&q, 0, sizeof(q));
	q.kind = NSF_ADDR;
	q.family = 4;
	memcpy(q.addr, a, 4);
	snprintf(q.text, sizeof(q.text), "100.64.0.1");

	assert(!peering_facts_feed(&ns, &q, netstate_epoch(&ns, 4), 1000));
	assert(netstate_rows(&ns, 4, &rows) == 1);
	assert(rows[0].scope == NET_SCOPE_CGNAT);
	peering_facts_destroy(&f);
}

/*
 * Only the end of a round says so, because that is the caller's cue to reap
 * the thread that posted it.
 */
static void only_a_round_s_end_says_so(void)
{
	struct peering_facts f;
	struct nsfact q;
	struct netstate ns;

	peering_facts_init(&f);
	netstate_init(&ns, 1, 1000);
	memset(&q, 0, sizeof(q));
	q.family = 4;
	q.epoch = netstate_epoch(&ns, 4);

	q.kind = NSF_ROUNDTRIP;
	assert(!peering_facts_feed(&ns, &q, q.epoch, 1000));
	q.kind = NSF_PROBE_DONE;
	assert(peering_facts_feed(&ns, &q, q.epoch, 1000));
	peering_facts_destroy(&f);
}

/*
 * Every distinct egress address is kept, because a carrier that maps per
 * destination shows a different one to each server it is asked through.
 */
static void every_distinct_egress_address_is_kept(void)
{
	uint8_t out[PEERING_POOL4_MAX][4];
	struct peering_pool p;
	uint8_t a[4] = { 198, 51, 100, 1 };
	uint8_t b[4] = { 198, 51, 100, 2 };
	uint8_t zero[4] = { 0, 0, 0, 0 };
	int i;

	peering_pool_init(&p);
	assert(!peering_pool_count(&p));

	assert(peering_pool_note(&p, a) == 1);
	assert(!peering_pool_note(&p, a));	/* the same one, once */
	assert(peering_pool_note(&p, b) == 2);
	assert(peering_pool_count(&p) == 2);

	/* A placeholder is nowhere a carrier maps this machine to. */
	assert(!peering_pool_note(&p, zero));
	assert(peering_pool_count(&p) == 2);

	assert(peering_pool_copy(&p, out) == 2);
	assert(!memcmp(out[0], a, 4));
	assert(!memcmp(out[1], b, 4));

	/* The cap bounds what one network can make this machine remember. */
	for (i = 0; i < 32; i++) {
		uint8_t x[4] = { 198, 51, 101, 0 };

		x[3] = (uint8_t)(i + 1);
		peering_pool_note(&p, x);
	}
	assert(peering_pool_count(&p) == PEERING_POOL4_MAX);
	peering_pool_destroy(&p);
}

/*
 * The mapping verdict is about one socket, so it is forgotten at the top of a
 * round; the pool is about the carrier, so it is not.
 */
static void a_round_forgets_the_samples_and_keeps_the_pool(void)
{
	struct peering_pool p;
	uint8_t a[4] = { 198, 51, 100, 1 };
	uint8_t b[4] = { 198, 51, 100, 2 };

	peering_pool_init(&p);
	assert(peering_pool_mapping(&p) == STUN_MAPPING_UNKNOWN);

	peering_pool_note(&p, a);
	peering_pool_sample(&p, a, 4000);
	peering_pool_sample(&p, a, 4000);
	assert(peering_pool_mapping(&p) == STUN_MAPPING_INDEPENDENT);
	assert(peering_pool_port_stable(&p));

	peering_pool_round(&p);
	assert(peering_pool_mapping(&p) == STUN_MAPPING_UNKNOWN);
	assert(peering_pool_count(&p) == 1);	/* the carrier's, not the socket's */

	peering_pool_note(&p, b);
	peering_pool_sample(&p, a, 4000);
	peering_pool_sample(&p, b, 4001);
	assert(peering_pool_mapping(&p) == STUN_MAPPING_DEPENDENT);
	assert(!peering_pool_port_stable(&p));	/* and the fan cannot survive it */
	peering_pool_destroy(&p);
}

/* A move: every address seen before it belongs to the network we have left. */
static void a_move_empties_the_pool(void)
{
	struct peering_pool p;
	uint8_t a[4] = { 198, 51, 100, 1 };

	peering_pool_init(&p);
	peering_pool_note(&p, a);
	peering_pool_sample(&p, a, 4000);
	peering_pool_sample(&p, a, 4000);
	peering_pool_reset(&p);
	assert(!peering_pool_count(&p));
	assert(peering_pool_mapping(&p) == STUN_MAPPING_UNKNOWN);
	/* And it is the same address again on the next network, as news. */
	assert(peering_pool_note(&p, a) == 1);
	peering_pool_destroy(&p);
}

int main(void)
{
	what_is_posted_is_taken_once();
	every_distinct_egress_address_is_kept();
	a_round_forgets_the_samples_and_keeps_the_pool();
	a_move_empties_the_pool();
	a_fact_is_fed_under_the_model_s_own_epoch();
	an_address_is_classified_as_it_is_fed();
	only_a_round_s_end_says_so();
	printf("peering_test: ok\n");

	return 0;
}
