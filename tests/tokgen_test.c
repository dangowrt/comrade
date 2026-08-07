/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Exercises the endpoint-vs-rendezvous decision tree exhaustively. The named
 * cases document the intent; the loop then checks all 16 fact combinations
 * against an independent restatement of the tree, so a bug in either the
 * decision or this restatement is caught.
 */

#include <assert.h>

#include "tokgen.h"

static enum tok_advert decide(int addr, int route, int ack, int proven)
{
	struct tokgen_facts f;

	f.has_usable_addr = addr;
	f.has_default_route = route;
	f.dht_acked = ack;
	f.public_port_proven = proven;
	return tokgen_decide(&f);
}

/* Independent restatement of the specified tree (not the implementation). */
static enum tok_advert expected(int addr, int route, int ack, int proven)
{
	int global = addr && route && ack;		/* (A) */

	if (global)
		return proven ? TOK_ADVERT_ENDPOINT	/* (B1) yes */
			      : TOK_ADVERT_RENDEZVOUS;	/* (B1) no  */
	if (addr)
		return TOK_ADVERT_ENDPOINT;		/* (B2) yes */
	return TOK_ADVERT_NONE;				/* (B2) no -> abort */
}

static void named_cases(void)
{
	/* Public and proven reachable: direct endpoint. */
	assert(decide(1, 1, 1, 1) == TOK_ADVERT_ENDPOINT);
	/* Global but the port is not proven open (CGNAT, or no mapping):
	 * hand out a DHT rendezvous node instead. */
	assert(decide(1, 1, 1, 0) == TOK_ADVERT_RENDEZVOUS);
	/* Address and route but the DHT never acked -> treated as isolated,
	 * so advertise our own (LAN-reachable) endpoint. */
	assert(decide(1, 1, 0, 0) == TOK_ADVERT_ENDPOINT);
	/* Airgap with a LAN address: multicast-only, own endpoint. */
	assert(decide(1, 0, 0, 0) == TOK_ADVERT_ENDPOINT);
	/* No usable address at all: no connectivity, abort this family. */
	assert(decide(0, 0, 0, 0) == TOK_ADVERT_NONE);
	assert(decide(0, 1, 1, 1) == TOK_ADVERT_NONE);
	/* A proven-open port is meaningless without global connectivity;
	 * the isolated branch still governs. */
	assert(decide(1, 0, 0, 1) == TOK_ADVERT_ENDPOINT);
}

static void exhaustive(void)
{
	int addr, route, ack, proven;

	for (addr = 0; addr <= 1; addr++)
		for (route = 0; route <= 1; route++)
			for (ack = 0; ack <= 1; ack++)
				for (proven = 0; proven <= 1; proven++)
					assert(decide(addr, route, ack, proven) ==
					       expected(addr, route, ack, proven));
}

/* The two families are decided independently; only both-NONE aborts. These
 * mirror common real-world mixes. */
static void host_cases(void)
{
	struct tokgen_facts global_proven = { 1, 1, 1, 1 };
	struct tokgen_facts global_natted = { 1, 1, 1, 0 };
	struct tokgen_facts linklocal_only = { 1, 0, 0, 0 };
	struct tokgen_facts absent = { 0, 0, 0, 0 };
	struct tokgen_result r;

	/* Global v4 (behind NAT) and only link-local v6: both advertisable. */
	assert(tokgen_decide_host(&global_natted, &linklocal_only, &r) == 0);
	assert(r.v4 == TOK_ADVERT_RENDEZVOUS && r.v6 == TOK_ADVERT_ENDPOINT);

	/* No v6 at all, global proven v4: still fine. */
	assert(tokgen_decide_host(&global_proven, &absent, &r) == 0);
	assert(r.v4 == TOK_ADVERT_ENDPOINT && r.v6 == TOK_ADVERT_NONE);

	/* Only link-local v6, no v4 at all: fine, v6 endpoint over multicast. */
	assert(tokgen_decide_host(&absent, &linklocal_only, &r) == 0);
	assert(r.v4 == TOK_ADVERT_NONE && r.v6 == TOK_ADVERT_ENDPOINT);

	/* Nothing on either family: the only abort. */
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
