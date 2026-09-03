/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The serving-side resource limits, tested against the engine internals.
 * Rate limiting follows a real libtorrent node's dht dos_blocker: a source is
 * served up to a fixed count per window and banned past it; the ban then
 * widens across a prefix as offenders spread; a saturated table fails closed.
 * Store admission is tested directly on the eviction path. Includes bep44.c so
 * it can drive the static ban_ok / store_free_slot and read the tables.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "bep44.c"

static struct bep44_engine *E;

static struct bep44_engine *fresh(void)
{
	uint8_t myid[20];
	struct bep44_engine *e;

	memset(myid, 7, sizeof(myid));
	e = bep44_create(myid, INVALID_SOCK, INVALID_SOCK);
	if (e)
		bep44_serve(e, 1);	/* enables the limiter at its defaults */
	return e;
}

static int ask6(const uint8_t a[16])
{
	struct sockaddr_in6 s;

	memset(&s, 0, sizeof(s));
	s.sin6_family = AF_INET6;
	memcpy(&s.sin6_addr, a, 16);
	s.sin6_port = htons(6881);
	return ban_ok(E, (struct sockaddr *)&s, sizeof(s));
}

static int ask4(uint32_t a)
{
	struct sockaddr_in s;

	memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = htonl(a);
	s.sin_port = htons(6881);
	return ban_ok(E, (struct sockaddr *)&s, sizeof(s));
}

static int hammer6(const uint8_t a[16])
{
	int served = 0, i;

	for (i = 0; i < 300; i++)
		served += ask6(a);
	return served;
}

static void hammer4(uint32_t a)
{
	int i;

	for (i = 0; i < 300; i++)
		ask4(a);
}

static int banned_at(int family, int bits)
{
	int i, n = 0;

	for (i = 0; i < B44_BAN_MAX; i++)
		if (E->ban[i].family == family && E->ban[i].banned_until &&
		    E->ban[i].bits == bits)
			n++;
	return n;
}

static struct b44_ban *tracker6(const uint8_t a[16])
{
	int i;

	for (i = 0; i < B44_BAN_MAX; i++)
		if (E->ban[i].family == AF_INET6 && !E->ban[i].banned_until &&
		    E->ban[i].bits == 128 && !memcmp(E->ban[i].net, a, 16))
			return &E->ban[i];
	return NULL;
}

/* Served up to the window's limit, banned past it (libtorrent's dos_blocker). */
static void ban_at_limit(void)
{
	static const uint8_t a[16] = {
		0x20, 0x01, 0x0d, 0xb8, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 1 };
	int served = hammer6(a);

	assert(served == B44_BAN_RATE * 10 - 1);	/* 49 in a 10s window */
	assert(ask6(a) == 0);				/* the 50th onward: banned */
	assert(banned_at(AF_INET6, 128) == 1);
}

/* A source under the limit whose window rolls over is not banned. */
static void window_resets(void)
{
	static const uint8_t a[16] = {
		0x20, 0x01, 0x0d, 0xb8, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1 };
	struct b44_ban *t;
	int i;

	for (i = 0; i < B44_BAN_RATE * 10 - 1; i++)	/* 49: one short of a ban */
		assert(ask6(a) == 1);
	t = tracker6(a);
	assert(t && t->count == B44_BAN_RATE * 10 - 1);
	t->window_ms = 0;				/* force the window to have elapsed */
	assert(ask6(a) == 1);				/* new window: served, not banned */
	assert(banned_at(AF_INET6, 128) == 0);
}

/* 2 offenders in one /64 -> /64; a 3rd in a sibling /64 of the /56 -> /56. */
static void escalate_v6(void)
{
	uint8_t g1[16] = { 0x20, 1, 0x0d, 0xb8, 0xaa, 0xaa, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 };
	uint8_t g2[16] = { 0x20, 1, 0x0d, 0xb8, 0xaa, 0xaa, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2 };
	uint8_t h1[16] = { 0x20, 1, 0x0d, 0xb8, 0xaa, 0xaa, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1 };
	uint8_t inside[16] = { 0x20, 1, 0x0d, 0xb8, 0xaa, 0xaa, 0, 0x50, 0, 0, 0, 0, 0, 0, 0, 9 };

	hammer6(g1);
	hammer6(g2);
	assert(banned_at(AF_INET6, 64) == 1);
	assert(banned_at(AF_INET6, 128) == 0);

	hammer6(h1);
	assert(banned_at(AF_INET6, 56) == 1);
	assert(banned_at(AF_INET6, 64) == 0);

	assert(ask6(inside) == 0);			/* a fresh /64 in the /56 is covered */
}

/* Two lone offenders that share only a /32 must not widen to the /32. */
static void lone_pair_no_wide(void)
{
	uint8_t a[16] = { 0x20, 1, 0x0d, 0xb8, 0x11, 0x11, 0x22, 0x22, 0, 0, 0, 0, 0, 0, 0, 1 };
	uint8_t b[16] = { 0x20, 1, 0x0d, 0xb8, 0x33, 0x33, 0x44, 0x44, 0, 0, 0, 0, 0, 0, 0, 1 };

	hammer6(a);
	hammer6(b);
	assert(banned_at(AF_INET6, 128) == 2);
	assert(banned_at(AF_INET6, 32) == 0);
	assert(banned_at(AF_INET6, 56) == 0);
}

/* v4 widens in fine steps (/32 -> /30) and stops at /24. */
static void escalate_v4(void)
{
	uint32_t g = (203u << 24) | (0u << 16) | (113u << 8);

	assert(b44_ladder4[0] == 32);
	assert(b44_ladder4[sizeof(b44_ladder4) - 1] == 24);
	assert(b44_ladder6[0] == 128);
	assert(b44_ladder6[sizeof(b44_ladder6) - 1] == 32);

	hammer4(g + 0);
	hammer4(g + 1);
	assert(banned_at(AF_INET, 30) == 1);
	assert(banned_at(AF_INET, 32) == 0);
	assert(ask4(g + 2) == 0);
}

/* A saturated ban table stops answering unsolicited queries entirely. */
static void fail_closed(void)
{
	uint8_t a[16] = { 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	uint8_t clean[16] = { 0xfd, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 9 };
	int i;

	for (i = 0; i < B44_BAN_MAX; i++) {
		a[3] = (uint8_t)i;			/* distinct /32s: nothing merges */
		hammer6(a);
	}
	assert(banned_at(AF_INET6, 128) == B44_BAN_MAX);
	assert(E->block_all_until == 0);

	a[3] = 250;
	hammer6(a);
	assert(E->block_all_until != 0);
	assert(ask6(clean) == 0);
}

/*
 * Store admission: when the table is full a farther item is refused, and a
 * nearer one evicts the furthest. Driven on the eviction path directly, with a
 * small cap, rather than through hundreds of rate-limited puts.
 */
static void admission(void)
{
	uint64_t now = now_ms();
	uint8_t t[20], far_id[20], near_id[20];
	int i, slot;

	E->store_cap = 8;
	for (i = 0; i < E->store_cap; i++) {
		memcpy(t, E->myid, 20);
		t[19] ^= (uint8_t)(i + 1);		/* distance 1..8 from our id */
		E->store[i] = item_new(t, (const uint8_t *)"3:abc", 5, now);
		assert(E->store[i]);
	}
	memcpy(far_id, E->myid, 20);
	far_id[0] ^= 0xff;					/* far_id: high bit set */
	assert(store_free_slot(E, far_id) == -1);		/* not admitted */

	memcpy(near_id, E->myid, 20);			/* distance 0: nearer than all */
	slot = store_free_slot(E, near_id);
	assert(slot >= 0 && E->store[slot] == NULL);	/* the furthest was evicted */
}

/*
 * THE OTHER HALF OF THE LIMIT: WHAT WE SEND.
 *
 * Everything above is this node refusing to be flooded. The rendezvous nodes
 * are the other side of it -- a handful of foreign nodes that every operation
 * this engine runs asks, direct and convergent alike, with a read and a store
 * able to fall due in the same round. The node that decides we are flooding it
 * is then the one node whose answer the session cannot do without.
 *
 * Only the nodes we hold are budgeted, those being the only ones our own
 * traffic can pile up on.
 */
static void our_own_queries_to_one_node_are_budgeted(void)
{
	struct sockaddr_in a;
	uint64_t t = 100000;
	int i;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons(6881);
	a.sin_addr.s_addr = htonl(0x0a000001);

	/* Met once in the middle of a lookup and not held: not budgeted. */
	for (i = 0; i < 20; i++)
		assert(node_budget_ok(E, (struct sockaddr *)&a, sizeof(a), t));

	assert(!bep44_pin_add(E, NULL, (struct sockaddr *)&a, sizeof(a)));

	/* A ROUND'S BURST GOES OUT AT ONCE. Spacing these would buy nothing --
	 * the average over the window is what a node watches -- and would cost
	 * the latency of every rendezvous. */
	for (i = 0; i <= B44_NODE_BURST; i++)
		assert(node_budget_ok(E, (struct sockaddr *)&a, sizeof(a), t));
	assert(!node_budget_ok(E, (struct sockaddr *)&a, sizeof(a), t));

	/* And it drains at the sustained rate, so the next one waits for it. */
	assert(!node_budget_ok(E, (struct sockaddr *)&a, sizeof(a),
			       t + B44_NODE_COST_MS - 1));
	assert(node_budget_ok(E, (struct sockaddr *)&a, sizeof(a),
			      t + B44_NODE_COST_MS));

	/* Left alone, the bucket empties rather than banking credit: a quiet
	 * minute does not buy a flood. */
	t += 60000;
	for (i = 0; i <= B44_NODE_BURST; i++)
		assert(node_budget_ok(E, (struct sockaddr *)&a, sizeof(a), t));
	assert(!node_budget_ok(E, (struct sockaddr *)&a, sizeof(a), t));

	/*
	 * The whole point, stated as the node would measure it: over any ten
	 * seconds, burst and sustained together stay under what this engine
	 * itself would ban a source for.
	 */
	assert(B44_NODE_BURST + 10000 / B44_NODE_COST_MS <
	       B44_BAN_RATE * 10);
	/* Without squeezing the read-and-store pair a round already needs. */
	assert(B44_NODE_COST_MS <= 500);
}


int main(void)
{
	void (*tests[])(void) = {
		ban_at_limit, window_resets, escalate_v6, lone_pair_no_wide,
		escalate_v4, fail_closed, admission,
		our_own_queries_to_one_node_are_budgeted,
	};
	size_t i;

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		E = fresh();
		assert(E);
		tests[i]();
		bep44_free(E);
	}
	E = fresh();
	assert(ban_ok(E, NULL, 0) == 1);		/* no address -> not limited */
	bep44_free(E);
	return 0;
}
