/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Congestion-control throughput over a shaped link on a virtual clock:
 * rate, one-way delay, a bottleneck queue that drops when full, seeded
 * random loss. Deterministic. Two scenarios that kcp's builtin Tahoe
 * controller fails hard (cwnd to 1 on any RTO, linear recovery):
 *
 *  - a 60 Mbit / 40 ms RTT path with 0.5% random loss (a CGNAT hairpin,
 *    a radio link): Tahoe delivers ~2 Mbit/s, the rate-based controller
 *    over 20;
 *  - a fast low-latency path (1 Gbit / 2 ms): Tahoe ~43 Mbit/s, paced
 *    delivery well over 100.
 *
 * Thresholds sit far from both sides so tuning drift does not flake.
 * Only built where the linked kcp has ikcp_setcc (the CMake gate).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stream.h"

#define CHUNK 1200
#define SIM_SECONDS 30
#define WARMUP_SECONDS 10
#define RING 65536

struct pkt {
	uint32_t due;
	int len;
	uint8_t data[1500];
};

struct shlink {
	struct pkt q[RING];
	unsigned head, tail;
	double free_at;		/* bottleneck finishes its backlog then */
	long rate_bpms;
	long owd_ms;
	long queue_max;
	long loss_pptt;		/* random loss, parts per ten thousand */
};

static uint32_t vnow;
static uint32_t rng_state;
static struct shlink ab, ba;
static struct stream *sa_, *sb_;
static size_t b_got;

static uint32_t rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static void link_push(struct shlink *l, const uint8_t *data, size_t len)
{
	double start, backlog;
	struct pkt *p;

	if (l->loss_pptt && rng() % 10000 < (uint32_t)l->loss_pptt)
		return;
	start = l->free_at > (double)vnow ? l->free_at : (double)vnow;
	backlog = (start - (double)vnow) * l->rate_bpms;
	if (backlog + (double)len > (double)l->queue_max)
		return;
	l->free_at = start + (double)len / l->rate_bpms;
	p = &l->q[l->tail++ % RING];
	p->due = (uint32_t)(l->free_at + l->owd_ms);
	p->len = (int)len;
	memcpy(p->data, data, len);
}

static void link_deliver(struct shlink *l, struct stream *dst)
{
	while (l->head != l->tail) {
		struct pkt *p = &l->q[l->head % RING];

		if ((uint32_t)(p->due - vnow) < 0x80000000u && p->due != vnow)
			break;
		stream_input(dst, p->data, (size_t)p->len);
		l->head++;
	}
}

static int a_out(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	link_push(&ab, data, len);
	return (int)len;
}

static int b_out(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	link_push(&ba, data, len);
	return (int)len;
}

/* Saturate A toward B honouring the gate; Mbit/s past the warm-up. */
static double run_shaped(long rate_bpms, long owd_ms, long queue_kb,
			 long loss_pptt)
{
	uint8_t chunk[CHUNK], buf[8192];
	size_t measured_from = 0;
	uint32_t end;
	int n;

	memset(&ab, 0, sizeof(ab));
	memset(&ba, 0, sizeof(ba));
	ab.rate_bpms = ba.rate_bpms = rate_bpms;
	ab.owd_ms = ba.owd_ms = owd_ms;
	ab.queue_max = ba.queue_max = queue_kb * 1024;
	ab.loss_pptt = ba.loss_pptt = loss_pptt;
	rng_state = 0x1234abcd;
	b_got = 0;
	vnow = 1000;

	sa_ = stream_create(11, a_out, NULL);
	sb_ = stream_create(11, b_out, NULL);
	if (!sa_ || !sb_)
		return -1.0;
	memset(chunk, 'x', sizeof(chunk));

	end = vnow + SIM_SECONDS * 1000;
	while (vnow < end) {
		vnow++;
		link_deliver(&ab, sb_);
		link_deliver(&ba, sa_);
		while (stream_tx_room(sa_))
			stream_send(sa_, chunk, sizeof(chunk));
		stream_update(sa_, vnow);
		stream_update(sb_, vnow);
		while ((n = stream_recv(sb_, buf, sizeof(buf))) > 0)
			b_got += (size_t)n;
		if (vnow == end - (SIM_SECONDS - WARMUP_SECONDS) * 1000)
			measured_from = b_got;
	}
	stream_destroy(sa_);
	stream_destroy(sb_);
	return (double)(b_got - measured_from) * 8 / 1000.0 /
	       (SIM_SECONDS - WARMUP_SECONDS) / 1000.0;
}

int main(void)
{
	double lossy, lan;
	int rc = 0;

	lossy = run_shaped(7500, 20, 64, 50);
	if (lossy < 10.0) {
		fprintf(stderr, "CC FAIL: lossy 60 Mbit path carried only "
			"%.2f Mbit/s (Tahoe-collapse territory)\n", lossy);
		rc = 1;
	}
	lan = run_shaped(125000, 1, 256, 0);
	if (lan < 60.0) {
		fprintf(stderr, "CC FAIL: clean fast path carried only "
			"%.2f Mbit/s\n", lan);
		rc = 1;
	}
	if (!rc)
		printf("CC PASS: lossy path %.1f Mbit/s, fast path %.1f "
		       "Mbit/s\n", lossy, lan);
	return rc;
}
