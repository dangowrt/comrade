/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * stream_tx_room bounds the unsent backlog. Two streams are wired back to
 * back over a rate-limited link on a virtual clock: a bulk sender that
 * honours tx_room saturates the link, and a small urgent write made
 * mid-saturation must still arrive within a bounded moment -- the whole
 * point of the gate. Also: a fresh stream has room, an unticked flood
 * closes it, draining reopens it.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "stream.h"

#define TICK_MS 10
#define LINK_PKTS_PER_TICK 2	/* ~240 KB/s of 1200-byte segments */
#define CHUNK 1200

static struct stream *sa, *sb;
static int a_budget;		/* packets the link still carries this tick */
static size_t b_got;		/* bytes B has received */

static int a_out(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	if (a_budget <= 0)
		return 0;	/* over the link rate: dropped, KCP resends */
	a_budget--;
	stream_input(sb, data, len);
	return (int)len;
}

static int b_out(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	stream_input(sa, data, len);	/* ACK path: unconstrained */
	return (int)len;
}

static void drain_b(void)
{
	uint8_t buf[4096];
	int n;

	while ((n = stream_recv(sb, buf, sizeof(buf))) > 0)
		b_got += (size_t)n;
}

static void tick(uint32_t *t)
{
	*t += TICK_MS;
	a_budget = LINK_PKTS_PER_TICK;
	stream_update(sa, *t);
	stream_update(sb, *t);
	drain_b();
}

int main(void)
{
	uint8_t chunk[CHUNK];
	uint32_t t = 1000;
	size_t sent = 0, mark_at = 0;
	uint32_t mark_t = 0, latency;
	int i, closed = 0;

	sa = stream_create(7, a_out, NULL);
	sb = stream_create(7, b_out, NULL);
	assert(sa && sb);
	memset(chunk, 'x', sizeof(chunk));

	/* A fresh stream has room; an unticked flood closes it. */
	assert(stream_tx_room(sa));
	for (i = 0; i < 64; i++)
		assert(stream_send(sa, chunk, sizeof(chunk)) >= 0);
	sent = 64 * sizeof(chunk);
	assert(!stream_tx_room(sa));

	/* Draining reopens it. */
	while (b_got < sent && t < 60000)
		tick(&t);
	assert(b_got == sent);
	assert(stream_tx_room(sa));

	/* Saturate honouring the gate for a virtual second... */
	while (t < 62000) {
		while (stream_tx_room(sa)) {
			assert(stream_send(sa, chunk, sizeof(chunk)) >= 0);
			sent += sizeof(chunk);
		}
		closed = 1;
		tick(&t);
	}
	assert(closed);

	/* ...then an urgent write must land promptly despite the backlog. */
	mark_at = sent + 16;
	mark_t = t;
	assert(stream_send(sa, chunk, 16) >= 0);
	sent += 16;
	while (b_got < mark_at && t < mark_t + 10000) {
		while (stream_tx_room(sa)) {
			assert(stream_send(sa, chunk, sizeof(chunk)) >= 0);
			sent += sizeof(chunk);
		}
		tick(&t);
	}
	latency = t - mark_t;
	if (b_got < mark_at || latency > 1500) {
		fprintf(stderr, "STREAM ROOM FAIL: urgent write took %ums "
			"(got %zu of %zu)\n", latency, b_got, mark_at);
		return 1;
	}

	stream_destroy(sa);
	stream_destroy(sb);
	printf("STREAM ROOM PASS: gate closed under flood, urgent write in "
	       "%ums over a saturated link\n", latency);
	return 0;
}
