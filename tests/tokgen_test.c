/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Exercises the per-family advert decision tree exhaustively. The named cases
 * document the intent; the loop then checks all 32 fact combinations against an
 * independent restatement of the tree, so a bug in either the decision or this
 * restatement is caught.
 */

#include <assert.h>

#include "tokgen.h"

static enum tok_advert decide(int addr, int route, int ack, int concluded,
			      int proven)
{
	struct tokgen_facts f;

	f.has_usable_addr = addr;
	f.has_default_route = route;
	f.dht_acked = ack;
	f.dht_attempt_concluded = concluded;
	f.public_port_proven = proven;
	return tokgen_decide(&f);
}

/* Independent restatement of the specified tree (not the implementation). */
static enum tok_advert expected(int addr, int route, int ack, int concluded,
				int proven)
{
	if (!addr)
		return TOK_ADVERT_NONE;			/* (A) */
	if (proven)
		return TOK_ADVERT_ENDPOINT;		/* (B) */
	if (ack)
		return TOK_ADVERT_RENDEZVOUS;		/* (C) */
	if (!route || concluded)
		return TOK_ADVERT_NONE;			/* (D) */
	return TOK_ADVERT_PENDING;			/* (E) */
}

static void named_cases(void)
{
	/* Public and proven reachable: direct endpoint. */
	assert(decide(1, 1, 1, 1, 1) == TOK_ADVERT_ENDPOINT);
	/* Global but the port is not proven open (CGNAT, or no mapping):
	 * hand out a DHT rendezvous node instead. */
	assert(decide(1, 1, 1, 1, 0) == TOK_ADVERT_RENDEZVOUS);
	/* An ack is itself reach, so it needs no route of our own to confirm
	 * it. */
	assert(decide(1, 0, 1, 1, 0) == TOK_ADVERT_RENDEZVOUS);
	/* A route out and an attempt still running: nothing is decided. */
	assert(decide(1, 1, 0, 0, 0) == TOK_ADVERT_PENDING);
	/* The same family once the attempt has run its course without an ack
	 * (actually isolated: a broken gateway, filtered UDP). */
	assert(decide(1, 1, 0, 1, 0) == TOK_ADVERT_NONE);
	/* Deliberately isolated -- no default route -- settles at once, with no
	 * attempt to wait out. */
	assert(decide(1, 0, 0, 0, 0) == TOK_ADVERT_NONE);
	/* No usable address at all: nothing to host over on this family. */
	assert(decide(0, 0, 0, 0, 0) == TOK_ADVERT_NONE);
	assert(decide(0, 1, 1, 1, 1) == TOK_ADVERT_NONE);
	/* A prover proves reach, so a proven port stands whatever the local
	 * routing table says. */
	assert(decide(1, 0, 0, 0, 1) == TOK_ADVERT_ENDPOINT);
}

static void exhaustive(void)
{
	int addr, route, ack, concluded, proven;

	for (addr = 0; addr <= 1; addr++)
		for (route = 0; route <= 1; route++)
			for (ack = 0; ack <= 1; ack++)
				for (concluded = 0; concluded <= 1; concluded++)
					for (proven = 0; proven <= 1; proven++)
						assert(decide(addr, route, ack,
							      concluded, proven) ==
						       expected(addr, route, ack,
								concluded, proven));
}

/* The two families are decided independently; only an address on neither says
 * there is nothing to host over. These mirror common real-world mixes. */
static void host_cases(void)
{
	struct tokgen_facts global_proven = { 1, 1, 1, 1, 1 };
	struct tokgen_facts global_natted = { 1, 1, 1, 1, 0 };
	struct tokgen_facts linklocal_only = { 1, 0, 0, 0, 0 };
	struct tokgen_facts absent = { 0, 0, 0, 0, 0 };
	struct tokgen_result r;

	/* Global v4 (behind NAT) and only link-local v6: a rendezvous node for
	 * one family, nothing for the other. */
	assert(tokgen_decide_host(&global_natted, &linklocal_only, &r) == 0);
	assert(r.v4 == TOK_ADVERT_RENDEZVOUS && r.v6 == TOK_ADVERT_NONE);

	/* No v6 at all, global proven v4: still fine. */
	assert(tokgen_decide_host(&global_proven, &absent, &r) == 0);
	assert(r.v4 == TOK_ADVERT_ENDPOINT && r.v6 == TOK_ADVERT_NONE);

	/* An isolated LAN: both families NONE, and an address on each, which is
	 * the ordinary LAN-only host rather than a failure. */
	assert(tokgen_decide_host(&linklocal_only, &linklocal_only, &r) == 0);
	assert(r.v4 == TOK_ADVERT_NONE && r.v6 == TOK_ADVERT_NONE);

	/* Nothing on either family: the only -1. */
	assert(tokgen_decide_host(&absent, &absent, &r) == -1);
	assert(r.v4 == TOK_ADVERT_NONE && r.v6 == TOK_ADVERT_NONE);
}

int main(void)
{
	named_cases();
	exhaustive();
	host_cases();
	return 0;
}
