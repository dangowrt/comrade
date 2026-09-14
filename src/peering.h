/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * THE ESTABLISHMENT ENGINE.
 *
 * A playbook differs from another only in what it holds a path OPEN FOR and in
 * what credential names the far end. Everything between those two is the same
 * problem: work out what this machine's network looks like, publish where it
 * can be reached, find where the other end says it is, punch, qualify the
 * paths that answer, and move between them as the network moves. That
 * machinery belongs here so there is one of it, because a second
 * implementation that merely agrees is the failure mode this file exists to
 * prevent.
 */
#ifndef COMRADE_PEERING_H
#define COMRADE_PEERING_H

#include <stdint.h>
#include <pthread.h>

#include "netstate.h"
#include "nsfacts.h"

/*
 * The crossing from the threads that learn something about this network to the
 * loop that owns the model: nsfacts under the lock the posting threads need.
 * A gather thread and the probe threads all post here, and a playbook that
 * merely forgot to post would be silent in exactly the way that matters, with
 * netstate going on believing a family it has never had an answer from is
 * simply young.
 */
struct peering_facts {
	pthread_mutex_t lock;
	struct nsfacts q;
};

void peering_facts_init(struct peering_facts *f);
void peering_facts_destroy(struct peering_facts *f);

/* NSF_ROUNDTRIP or NSF_PROBE_DONE, and the address a round was seen at, from
 * any thread. */
void peering_facts_post(struct peering_facts *f, int kind, int family,
			uint32_t epoch);
void peering_facts_post_addr(struct peering_facts *f, int family,
			     uint32_t epoch, const uint8_t *addr,
			     const char *text);

/*
 * Take everything queued, emptying it; NSFACTS_OUT always takes the lot.
 * Separate from feeding it in because the end of a round is also what reaps
 * the thread that posted it, and which threads a playbook runs is its own.
 */
int peering_facts_take(struct peering_facts *f, struct nsfact *out, int max);

/*
 * Feed one taken fact into a model under the epoch THAT model is on: a
 * playbook with one model was stamped with its epoch when it posted, one with
 * a model per peer stamps a fact with its own generation and hands it to every
 * model under that model's epoch. Returns 1 for a round's end, which is the
 * caller's cue to reap.
 */
int peering_facts_feed(struct netstate *ns, const struct nsfact *q,
		       uint32_t epoch, uint64_t now);

#endif
