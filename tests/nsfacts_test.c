/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "nsfacts.h"

static int count_kind(const struct nsfact *f, int n, int kind, int family)
{
	int i, k = 0;

	for (i = 0; i < n; i++)
		if (f[i].kind == kind && f[i].family == family)
			k++;
	return k;
}

static int index_of(const struct nsfact *f, int n, int kind, int family)
{
	int i;

	for (i = 0; i < n; i++)
		if (f[i].kind == kind && f[i].family == family)
			return i;
	return -1;
}

static void addr4(uint8_t out[4], int last)
{
	out[0] = 203;
	out[1] = 0;
	out[2] = 113;
	out[3] = (uint8_t)last;
}

/* One round asks every server in the pool, so the same answer arrives once per
 * reply. Queueing it once leaves the room for what else has something to say. */
static void answers_collapse(void)
{
	struct nsfact out[NSFACTS_OUT];
	struct nsfacts q;
	int n;

	nsfacts_init(&q);
	for (n = 0; n < 30; n++)
		nsfacts_post(&q, NSF_ROUNDTRIP, 4, 7);
	nsfacts_post(&q, NSF_PROBE_DONE, 4, 7);

	n = nsfacts_take(&q, out, NSFACTS_OUT);
	assert(n == 2);
	assert(count_kind(out, n, NSF_ROUNDTRIP, 4) == 1);
	assert(count_kind(out, n, NSF_PROBE_DONE, 4) == 1);
	/* what answered, then the round that ended */
	assert(index_of(out, n, NSF_ROUNDTRIP, 4) <
	       index_of(out, n, NSF_PROBE_DONE, 4));
	assert(nsfacts_take(&q, out, NSFACTS_OUT) == 0);
}

/*
 * The regression this queue exists for: a round's end is what lets the next
 * round start, so it is kept however full the queue is. Losing it once stops
 * probing for the rest of the session.
 */
static void round_end_outlives_a_full_queue(void)
{
	struct nsfact out[NSFACTS_OUT];
	struct nsfacts q;
	uint8_t a[4];
	int n, i;

	nsfacts_init(&q);
	for (i = 0; i < NSFACTS_MAX + 8; i++) {
		char text[32];

		addr4(a, i);
		snprintf(text, sizeof(text), "203.0.113.%d", i);
		nsfacts_post_addr(&q, 4, 3, a, text);
	}
	nsfacts_post(&q, NSF_PROBE_DONE, 4, 3);

	n = nsfacts_take(&q, out, NSFACTS_OUT);
	assert(count_kind(out, n, NSF_ADDR, 4) == NSFACTS_MAX);
	assert(count_kind(out, n, NSF_PROBE_DONE, 4) == 1);
	assert(out[n - 1].kind == NSF_PROBE_DONE);
	assert(out[n - 1].epoch == 3);
}

/* An address already queued for this network is already known. */
static void addresses_are_not_repeated(void)
{
	struct nsfact out[NSFACTS_OUT];
	struct nsfacts q;
	uint8_t a[4];
	int n;

	nsfacts_init(&q);
	addr4(a, 9);
	nsfacts_post_addr(&q, 4, 1, a, "203.0.113.9");
	nsfacts_post_addr(&q, 4, 1, a, "203.0.113.9");
	nsfacts_post_addr(&q, 4, 2, a, "203.0.113.9");	/* other network */
	addr4(a, 10);
	nsfacts_post_addr(&q, 4, 1, a, "203.0.113.10");

	n = nsfacts_take(&q, out, NSFACTS_OUT);
	assert(count_kind(out, n, NSF_ADDR, 4) == 3);
}

/* A family's facts are its own, and the epoch kept is the newest seen. */
static void families_and_epochs(void)
{
	struct nsfact out[NSFACTS_OUT];
	struct nsfacts q;
	int n, i;

	nsfacts_init(&q);
	nsfacts_post(&q, NSF_ROUNDTRIP, 4, 4);
	nsfacts_post(&q, NSF_ROUNDTRIP, 4, 5);	/* moved mid-burst */
	nsfacts_post(&q, NSF_ROUNDTRIP, 6, 2);
	nsfacts_post(&q, NSF_PROBE_DONE, 6, 2);

	n = nsfacts_take(&q, out, NSFACTS_OUT);
	assert(count_kind(out, n, NSF_ROUNDTRIP, 4) == 1);
	assert(count_kind(out, n, NSF_ROUNDTRIP, 6) == 1);
	assert(count_kind(out, n, NSF_PROBE_DONE, 4) == 0);
	assert(count_kind(out, n, NSF_PROBE_DONE, 6) == 1);
	i = index_of(out, n, NSF_ROUNDTRIP, 4);
	assert(out[i].epoch == 5);
}

/* A caller with less room than the queue holds leaves the rest queued; nothing
 * it could not carry is thrown away. */
static void a_short_take_keeps_the_rest(void)
{
	struct nsfact out[NSFACTS_OUT];
	struct nsfacts q;
	uint8_t a[4];
	int seen_done = 0, seen_addr = 0, n, i;

	nsfacts_init(&q);
	for (i = 0; i < 6; i++) {
		char text[32];

		addr4(a, i);
		snprintf(text, sizeof(text), "203.0.113.%d", i);
		nsfacts_post_addr(&q, 4, 1, a, text);
	}
	nsfacts_post(&q, NSF_PROBE_DONE, 4, 1);

	for (i = 0; i < 20 && !seen_done; i++) {
		n = nsfacts_take(&q, out, 2);
		assert(n <= 2);
		seen_addr += count_kind(out, n, NSF_ADDR, 4);
		seen_done += count_kind(out, n, NSF_PROBE_DONE, 4);
	}
	assert(seen_addr == 6);
	assert(seen_done == 1);
}

int main(void)
{
	answers_collapse();
	round_end_outlives_a_full_queue();
	addresses_are_not_repeated();
	families_and_epochs();
	a_short_take_keeps_the_rest();
	printf("nsfacts_test: ok\n");
	return 0;
}
