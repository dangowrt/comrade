/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "probeplane.h"

#define MAGIC 0x50524250u

static const uint8_t base_key[32] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};

static const uint8_t half_a[KEYS_HALF_LEN] = { 0xa0, 0xa1, 0xa2, 0xa3 };
static const uint8_t half_b[KEYS_HALF_LEN] = { 0xb0, 0xb1, 0xb2, 0xb3 };

/* Both ends hold the same halves in the opposite order, which is what the
 * control channel gives them. */
static void pair_up(struct probeplane *x, struct probeplane *y)
{
	probeplane_bind(x, half_a, half_b);
	probeplane_bind(y, half_b, half_a);
}

static size_t ping(struct probeplane *pp, const char *ufrag, uint8_t *out)
{
	struct path_probe pr;

	memset(&pr, 0, sizeof(pr));
	pr.type = PROBE_PING;
	pr.nonce = 7;

	return probeplane_seal(pp, &pr, ufrag, out, PROBE_MAX);
}

/* Before a pair key exists, the establishment primitive is all there is, and
 * anybody holding it can be talked to. */
static void the_base_key_carries_until_a_pair_key_exists(void)
{
	struct probeplane a, b;
	struct path_probe got;
	uint8_t frame[PROBE_MAX];
	size_t n;

	probeplane_init(&a, MAGIC, base_key, 1000);
	probeplane_init(&b, MAGIC, base_key, 2000);
	n = ping(&a, "abcd", frame);
	assert(n);
	assert(path_probe_is(MAGIC, frame, n));
	assert(!probeplane_open(&b, &got, frame, n));
	assert(got.type == PROBE_PING);
	assert(!strcmp(got.ufrag, "abcd"));
	probeplane_destroy(&a);
	probeplane_destroy(&b);
}

/* Sealing waits for the peer to say it can open the pair key; opening does
 * not, because the peer may still be sealing under the base key. */
static void sealing_moves_only_once_the_peer_says_it_can_open(void)
{
	struct probeplane a, b, c;
	struct path_probe got;
	uint8_t frame[PROBE_MAX];
	size_t n;

	probeplane_init(&a, MAGIC, base_key, 1000);
	probeplane_init(&b, MAGIC, base_key, 2000);
	probeplane_init(&c, MAGIC, base_key, 3000);	/* the base key alone */
	pair_up(&a, &b);
	n = ping(&a, "abcd", frame);
	assert(n);
	assert(!probeplane_open(&c, &got, frame, n));	/* still the base key */
	assert(probeplane_tx_ready(&a));
	assert(!probeplane_tx_ready(&a));		/* it moves once */
	n = ping(&a, "abcd", frame);
	assert(n);
	assert(probeplane_open(&c, &got, frame, n));	/* this pair's alone */
	assert(!probeplane_open(&b, &got, frame, n));
	probeplane_destroy(&a);
	probeplane_destroy(&b);
	probeplane_destroy(&c);
}

/*
 * The first frame under the pair key spends the base key, and what a spent
 * base key still opens is one thing: the notice that the session is gone,
 * which comes from an end that shares no pair key with us.
 */
static void a_spent_base_key_opens_only_the_notice(void)
{
	struct probeplane a, b, c;
	struct path_probe pr, got;
	uint8_t frame[PROBE_MAX];
	size_t n;

	probeplane_init(&a, MAGIC, base_key, 1000);
	probeplane_init(&b, MAGIC, base_key, 2000);
	probeplane_init(&c, MAGIC, base_key, 3000);
	pair_up(&a, &b);
	assert(probeplane_tx_ready(&a));
	n = ping(&a, "abcd", frame);
	assert(n && !probeplane_open(&b, &got, frame, n));
	assert(!b.base_ok);				/* spent by that frame */

	n = ping(&c, "abcd", frame);			/* a stranger's ping */
	assert(n);
	assert(probeplane_open(&b, &got, frame, n));

	memset(&pr, 0, sizeof(pr));
	pr.type = PROBE_FRESH;
	n = probeplane_seal(&c, &pr, "abcd", frame, PROBE_MAX);
	assert(n);
	assert(!probeplane_open(&b, &got, frame, n));
	assert(got.type == PROBE_FRESH);
	probeplane_destroy(&a);
	probeplane_destroy(&b);
	probeplane_destroy(&c);
}

/* A fresh channel starts again from what the primitive gave both ends. */
static void a_reset_gives_the_base_key_back(void)
{
	struct probeplane a, b, c;
	struct path_probe got;
	uint8_t frame[PROBE_MAX];
	size_t n;

	probeplane_init(&a, MAGIC, base_key, 1000);
	probeplane_init(&b, MAGIC, base_key, 2000);
	probeplane_init(&c, MAGIC, base_key, 3000);
	pair_up(&a, &b);
	assert(probeplane_tx_ready(&a));
	n = ping(&a, "abcd", frame);
	assert(n && !probeplane_open(&b, &got, frame, n));
	probeplane_reset(&a);
	probeplane_reset(&b);
	n = ping(&a, "abcd", frame);
	assert(n);
	assert(!probeplane_open(&c, &got, frame, n));
	assert(!probeplane_open(&b, &got, frame, n));
	probeplane_destroy(&a);
	probeplane_destroy(&b);
	probeplane_destroy(&c);
}

/* Each sequence is acted on once, whatever opened it. */
static void a_sequence_is_acted_on_once(void)
{
	struct probeplane a, b;
	struct path_probe got;
	uint8_t frame[PROBE_MAX];
	size_t n;

	probeplane_init(&a, MAGIC, base_key, 1000);
	probeplane_init(&b, MAGIC, base_key, 2000);
	n = ping(&a, "abcd", frame);
	assert(n && !probeplane_open(&b, &got, frame, n));
	assert(probeplane_fresh(&b, &got));
	assert(!probeplane_fresh(&b, &got));
	probeplane_destroy(&a);
	probeplane_destroy(&b);
}

/* Counters start where the clock is, so a connection that replaces another
 * counts above the one it replaced rather than starting over. */
static void counters_start_where_they_were_told_to(void)
{
	struct probeplane a;
	struct path_probe pr;
	uint8_t frame[PROBE_MAX];

	probeplane_init(&a, MAGIC, base_key, 123456);
	memset(&pr, 0, sizeof(pr));
	pr.type = PROBE_PING;
	assert(probeplane_seal(&a, &pr, "abcd", frame, PROBE_MAX));
	assert(pr.seq == 123457);
	probeplane_destroy(&a);
}

/* The stream's datagrams travel under the same schedule and the same window. */
static void stream_datagrams_follow_the_same_schedule(void)
{
	uint8_t frame[256];
	struct probeplane a, b;
	const char *msg = "hello";
	size_t n, len;

	probeplane_init(&a, MAGIC, base_key, 1000);
	probeplane_init(&b, MAGIC, base_key, 2000);
	n = probeplane_wrap(&a, frame, sizeof(frame),
			    (const uint8_t *)msg, strlen(msg));
	assert(n);
	len = n;
	assert(!probeplane_unwrap(&b, frame, &len));
	assert(len == strlen(msg));
	assert(!memcmp(frame, msg, len));
	len = n;
	assert(probeplane_unwrap(&b, frame, &len));	/* once each */
	probeplane_destroy(&a);
	probeplane_destroy(&b);
}

int main(void)
{
	the_base_key_carries_until_a_pair_key_exists();
	sealing_moves_only_once_the_peer_says_it_can_open();
	a_spent_base_key_opens_only_the_notice();
	a_reset_gives_the_base_key_back();
	a_sequence_is_acted_on_once();
	counters_start_where_they_were_told_to();
	stream_datagrams_follow_the_same_schedule();
	printf("probeplane_test: ok\n");

	return 0;
}
