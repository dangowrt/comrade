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

#include "ctlplane.h"
#include "ctlproto.h"
#include "netstate.h"
#include "obsemit.h"
#include "nsfacts.h"
#include "pathplane.h"
#include "probeplane.h"
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

/*
 * THE ROUNDS THAT FIND OUT.
 *
 * The v4 round asks every STUN server on the list through ONE socket: a
 * carrier that maps per destination shows a different public address to each
 * server, so the answers ARE the pool, and asking a subset leaves egress
 * addresses undiscovered that nothing can predict. Every answer is a round
 * trip and proves the family; the round's end is posted last, so the model
 * hears both.
 *
 * The v6 round asks a few of the same servers over a v6 socket, deliberately
 * independent of whether ICE ever gathers a v6 reflexive candidate: it does
 * not when a global host candidate already exists, so relying on that alone
 * misses real NAT66 and filtered hosts, and, more ordinarily, a global address
 * that simply goes unconfirmed.
 */
/*
 * The rounds run the moment a network is entered, so the members are on the
 * table when the first description posts rather than trickling in one gather
 * at a time (measured: one member per STUN name per agent, far too slow for a
 * punch on the first attempt). A handful of packets, once per network.
 */
#define PEERING_PROBE6_SERVERS 6	/* asked in one v6 round */
#define PEERING_PROBE_MS 3000		/* a round's whole budget */

struct peering_probe {
	pthread_t th;
	int running;
	volatile int stop;
	volatile uint32_t epoch;	/* stamped by the loop, read by the
					 * round as it reports */
	int start;			/* v6: where in the list it begins */
};

/* What belongs to this machine, whichever peer it is talking to. */
struct peering_net {
	struct peering_facts facts;
	struct peering_pool pool;
	struct peering_probe probe;	/* fills the pool, proves v4 */
	struct peering_probe probe6;	/* proves v6 */
	char *const *servers;		/* the STUN list, "host:port" each */
	int nservers;
	int auto_probe;			/* the list may be asked at all: an
					 * operator-pinned server is theirs
					 * alone to talk to */
};

/*
 * `servers` is borrowed and must outlive the machine. `auto_probe` says the
 * rounds may run at all; a playbook whose operator pinned one STUN server
 * passes 0, and no round of either kind ever starts.
 */
void peering_net_init(struct peering_net *m, char *const *servers,
		      int nservers, int auto_probe);

/* Ask both rounds to wind up and wait for them: teardown, before the machine
 * or anything a round posts into goes away. */
void peering_net_stop(struct peering_net *m);
void peering_net_destroy(struct peering_net *m);

/*
 * Stamp a family's epoch and start its round if one is not already running.
 * Returns non-zero if a round really started, which is what lets the model
 * tell a probe that is running from one that could not be. A round in flight
 * is asked to stop and never waited for: this is the loop that drives the
 * session, and a probe can be inside a name lookup with no timeout, and its
 * answers are dropped on arrival anyway. `start6` is where in the list the v6
 * round begins, so it walks in step with the agent's own rotation.
 */
int peering_net_kick(struct peering_net *m, int family, uint32_t epoch,
		     int start6);

/* Ask a family's round to wind up, without waiting. */
void peering_net_halt(struct peering_net *m, int family);

/* Join a round that has posted its end. Idempotent. */
void peering_net_reap(struct peering_net *m, int family);

/*
 * ONE MAILBOX.
 *
 * What one side of a rendezvous holds: the reachability model, where this end
 * is served and what it can reach as published for its peers, and the standing
 * requests a peer has made of it. A playbook keeps one per mailbox, and every
 * function that takes it runs on the thread that owns the mailbox.
 *
 * What the model has decided is published under the lock, because the peers'
 * channels run on threads of their own: a host's worker announces exactly what
 * the thread driving the signalling would. Only ever added to or replaced,
 * never retracted, since a peer holding a node this end has stopped being sure
 * of is better off than one holding none and the node keeps being served
 * either way. Reachability is the exception, retracted as freely as it is
 * raised, a family that has gone being exactly what the other end needs to
 * know.
 */

/* One end's rendezvous node for one family: where its mailbox is served, and
 * so where the other end reads it. */
struct peering_rdv {
	struct sockaddr_storage sa;
	socklen_t len;
	int have;
	int qualified;			/* proven here, or proven for us */
	int status;			/* CTL_RDVST_* as told to a peer */
};

struct peering_model {
	struct netstate ns;
	struct obsemit oe;		/* what the watcher has been told */

	pthread_mutex_t pub_lock;
	struct peering_rdv rdv[2];	/* [0] v4, [1] v6 */
	uint32_t rdv_gen;
	uint8_t reach[CTL_REACH_PLEN];
	uint32_t reach_gen;
	/*
	 * Families a peer has asked this end to rendezvous on for it, kept here
	 * as well as in the signaller because a rebuilt one starts with none
	 * and the peer's request stands until it has a node.
	 */
	int relay_fam[2];
	uint64_t relay_until_ms[2];	/* when an unrenewed request lapses */
};

void peering_model_init(struct peering_model *pm, int is_host,
			const struct session_obs *o, uint64_t now);
void peering_model_destroy(struct peering_model *pm);

/*
 * ONE PEER.
 *
 * The three planes a pair needs, in the one object, wired to each other: the
 * key schedule both of the others seal and open under, the paths that carry,
 * and the channel the pair talks over. They are built in that order because
 * each of the last two holds the first, and a playbook that assembled them
 * itself would have to know that.
 */
struct peering {
	struct probeplane pp;
	struct pathplane pl;
	struct ctlplane cp;
};

/*
 * `key` is the base key the establishment primitive derived and `magic` the
 * demux tag, both of which every holder of the primitive has. `seq0` is where
 * this end's counters start, and it is the clock rather than one: see
 * probeplane_init.
 */
void peering_init(struct peering *pr, uint32_t magic, const uint8_t key[32],
		  uint64_t seq0);
void peering_destroy(struct peering *pr);

/*
 * A fresh channel: the pair key belonged to the one that agreed it, and the
 * halves that made it are spent with it.
 */
void peering_reset(struct peering *pr);

#endif
