/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_NSFACTS_H
#define COMRADE_NSFACTS_H

#include <stddef.h>
#include <stdint.h>

/*
 * The crossing between the threads that learn something about this network and
 * the loop that owns the model (src/netstate.c): threads post, the loop takes.
 * Factored out of session.c so what survives a burst can be exercised without
 * threads, sockets or a clock.
 *
 * The queue is fixed-size and a burst is ordinary -- one probe round asks every
 * server in the pool, so a couple of dozen replies can land between two passes
 * of a loop that is busy rebuilding after a move. Which of them may be lost is
 * not a matter of room but of what they are:
 *
 *   - an observation that repeats is queued once. "Something answered us" says
 *     the same thing whether it arrives once or thirty times, and an address
 *     already queued is already known.
 *   - the end of a probe round is kept whatever else is waiting. It is the one
 *     fact that is a state change: it is what lets the next round start, so
 *     losing it stops probing for the rest of the session, leaving no egress
 *     pool to fan an offer across and one address named where the carrier maps
 *     several.
 *
 * Pure: no locks (the caller holds its own), no clock, no sockets.
 */

enum {
	NSF_ROUNDTRIP,			/* something answered us */
	NSF_PROBE_DONE,			/* a probe round ended, proving nothing */
	NSF_ADDR			/* and the address it said we are seen as */
};

#define NSFACTS_MAX 16			/* observations queued at once */
#define NSFACTS_OUT (NSFACTS_MAX + 4)	/* those plus what is never dropped */

struct nsfact {
	int kind;
	int family;
	uint32_t epoch;			/* which network it was learnt on */
	uint8_t addr[16];		/* NSF_ADDR: as bytes, and as printed */
	char text[64];
};

/*
 * Per family, an answer and a round's end are each their own slot rather than
 * a queue entry: one of them repeats and one of them must not be lost, and
 * neither needs room that an address is waiting for.
 */
struct nsfacts {
	struct nsfact q[NSFACTS_MAX];
	int n;
	int rt[2];			/* [0] v4, [1] v6: an answer is queued */
	uint32_t rt_epoch[2];
	int done[2];			/* a probe round has ended */
	uint32_t done_epoch[2];
};

void nsfacts_init(struct nsfacts *f);

/* NSF_ROUNDTRIP or NSF_PROBE_DONE; the newest epoch is the one kept. */
void nsfacts_post(struct nsfacts *f, int kind, int family, uint32_t epoch);

/* NSF_ADDR: dropped when the queue is full, since the next round says it
 * again. An address already queued for this family and epoch is not repeated. */
void nsfacts_post_addr(struct nsfacts *f, int family, uint32_t epoch,
		       const uint8_t *addr, const char *text);

/*
 * Everything queued, in the order it happened -- what answered, what it said,
 * then the round that ended -- emptying what is handed back. `out` holds `max`;
 * NSFACTS_OUT always takes the lot, and a smaller one leaves the rest queued
 * for the next call rather than dropping it.
 */
int nsfacts_take(struct nsfacts *f, struct nsfact *out, int max);

#endif
