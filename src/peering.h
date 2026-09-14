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
#include "stunprobe.h"

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

/*
 * THE EGRESS POOL: the distinct reflexive v4 addresses this machine has been
 * seen at.
 *
 * A carrier that hands out AN EGRESS ADDRESS PER DESTINATION is the case this
 * exists for, and it is not exotic: one of the routers this was built against
 * answers from three addresses in one /24 depending on who is asking. Naming
 * one of them in an offer is therefore a guess, and the peer that matters is
 * usually looking from somewhere that sees a different one. So every distinct
 * address is kept and every one is offered, and the pair that answers is the
 * one that survives, which is ICE's whole argument applied to a fact about the
 * carrier rather than about the host.
 *
 * Grown from the probe thread and the gather thread, read from the loop, so it
 * carries its own lock. The counts of what has been shown and what has been
 * posted belong to the loop alone and are outside it.
 */
/*
 * A subscriber's flows spread only as wide as the NAT group behind its session
 * anchor, never the operator's whole pool: paired pooling is the deployed
 * default (RFC 6888 REQ-2) and per-subscriber traceability pushes the same
 * way, so the measured three-member spray is already the pathology and eight
 * bounds it with headroom. The cap prices only observations: the wire carries
 * observed members alone, 12 bytes each against what a signalling value holds,
 * which the encoder answers with a failed post rather than a truncated one.
 */
#define PEERING_POOL4_MAX 8

struct peering_pool {
	pthread_mutex_t lock;
	uint8_t v4[PEERING_POOL4_MAX][4];
	int n;
	/* RFC 4787 mapping classification, from the same probe's responses. */
	struct stun_mapping map4;
	int reported;			/* members a watcher has been shown */
	int posted;			/* members the posted offer fans */
};

void peering_pool_init(struct peering_pool *p);
void peering_pool_destroy(struct peering_pool *p);

/*
 * From the probe thread or the gather thread: keep an address the first time
 * it is seen, and say how many the pool holds if it was kept. The unspecified
 * address is refused, a gathering agent emitting it as a placeholder and it
 * being nowhere a carrier maps this machine to, so fanning an offer across it
 * would spend every peer's checks on a destination that cannot answer.
 */
int peering_pool_note(struct peering_pool *p, const uint8_t addr[4]);

/* A snapshot for the loop thread, and how many were copied. */
int peering_pool_copy(struct peering_pool *p,
		      uint8_t out[PEERING_POOL4_MAX][4]);
int peering_pool_count(struct peering_pool *p);

/* One sample of this socket's mapping, and the verdict the samples reach:
 * STUN_MAPPING_*, and whether the reflexive PORT held across servers, which is
 * the one thing a fan across the pool cannot survive moving. */
void peering_pool_sample(struct peering_pool *p, const uint8_t addr[4],
			 uint16_t port);
int peering_pool_mapping(struct peering_pool *p);
int peering_pool_port_stable(struct peering_pool *p);

/*
 * Forget the samples: the top of a round. Every round opens a new socket, and
 * the mapping test asks whether two servers saw the same mapping for the SAME
 * socket. The POOL is not forgotten with them, because which addresses a
 * carrier maps us to is a fact about the carrier and accumulates, where a
 * socket's port is a fact about that socket.
 */
void peering_pool_round(struct peering_pool *p);

/* A move: every address seen before it belongs to the network we have left. */
void peering_pool_reset(struct peering_pool *p);

#endif
