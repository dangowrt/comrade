/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * WHAT A PAIR TELLS EACH OTHER ONCE THEY CAN TALK.
 *
 * The path plane proves a way through; this is what the two ends then say over
 * it, and none of it is a property of what the session carries:
 *
 *   the key halves, so probes stop being sealed under a key every holder of
 *   the establishment primitive has and become this pair's alone;
 *   the rendezvous node each end is actually served from, so a peer that moves
 *   is found again without either end paying for a fresh convergent search;
 *   which families each end wants rendezvoused for;
 *   the endpoints each end has learnt about itself, so a new one becomes a
 *   path without waiting for a store to travel;
 *   and a ping, because a link that has gone quiet is otherwise
 *   indistinguishable from one nobody is typing on.
 *
 * The plane owns that state and the liveness verdict drawn from it. It does
 * not own the pipe: what carries a frame is the playbook's, and arrives
 * through the sinks.
 */
#ifndef COMRADE_CTLPLANE_H
#define COMRADE_CTLPLANE_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "wsock.h"

#include "ctlproto.h"
#include "keys.h"
#include "probeplane.h"

struct ctlplane_node {
	struct sockaddr_storage sa;
	socklen_t len;
	int have;
	int status;			/* CTL_RDVST_*, as the peer said */
};

struct ctlplane_sinks {
	/* Put one framed control message on this pair's channel. */
	void (*send)(void *arg, int type, const uint8_t *payload, size_t plen);
	/* An endpoint the peer says it can be reached at: one more path. */
	void (*offer_path)(void *arg, const struct sockaddr *sa, socklen_t len);
	/* Whether to answer this ping. NULL answers every one; a playbook that
	 * has to see a link go quiet on purpose says no from here. */
	int (*answer_ping)(void *arg);
	/* An answer came back, so the peer is there. NULL for none. */
	void (*pong)(void *arg);
	/* Whether the channel is there to carry anything at all. NULL for
	 * "always". */
	int (*ready)(void *arg);
	/* A message this plane does not own. NULL to ignore them. */
	void (*other)(void *arg, int type, const uint8_t *pl, size_t plen);
	void *arg;
};

/*
 * Liveness, as the ping and its answer see it. Every field is written under
 * the plane's lock by whichever thread reads the channel or a carrier, and
 * read as one snapshot by whichever judges the link.
 */
struct ctlplane_live {
	uint64_t last_pong_ms;		/* when a pong last came back */
	uint64_t last_heard_ms;		/* when anything authenticated last
					 * arrived from the peer */
	uint64_t lost_since_ms;		/* when the link was first seen lost,
					 * 0 while it is live */
	int rtt_ms;			/* round trip from the last pong */
	int pong_seen;			/* a pong has ever come back */
	unsigned live_gen;		/* the network generation this link
					 * was last proven on; older means we
					 * have no evidence about it here */
};

struct ctlplane {
	struct probeplane *pp;		/* what the halves bind */

	/* This pair's own key, half by half. Loop thread only. */
	uint8_t half_out[KEYS_HALF_LEN];
	uint8_t half_in[KEYS_HALF_LEN];
	int half_sent, half_seen;

	/*
	 * What the peer has said about itself and how the link is faring,
	 * written by whichever thread reads the channel or a carrier and taken
	 * by whichever owns the model.
	 */
	pthread_mutex_t lock;
	struct ctlplane_node rdv_in[2];		/* [0] v4, [1] v6 */
	int rdv_in_dirty;
	uint8_t reach_in[CTL_REACH_PLEN];
	int reach_in_seen;
	int reach_in_dirty;
	int rdvask_in;			/* families the peer asked us about:
					 * bit 0 v4, bit 1 v6 */
	int rdvask_out;			/* and the ones we owe it */
	struct ctlplane_live live;
};

void ctlplane_init(struct ctlplane *cp, struct probeplane *pp);
void ctlplane_destroy(struct ctlplane *cp);

/* Back to nothing agreed: a fresh channel starts the exchange again. */
void ctlplane_reset(struct ctlplane *cp);

/*
 * The link is up on entry: start the liveness clock as alive, with nothing
 * yet proven on it.
 */
void ctlplane_live_reset(struct ctlplane *cp, uint64_t now);

/* Something authenticated arrived from the peer, on any carrier. */
void ctlplane_heard(struct ctlplane *cp, uint64_t now);

/* One consistent view of the liveness fields. */
void ctlplane_liveness(struct ctlplane *cp, struct ctlplane_live *out);

/*
 * The link's verdict now, latching when it was first seen lost. The heartbeat
 * is end to end, so this says whether the session is getting through, never
 * which path carries it.
 */
int ctlplane_judge(struct ctlplane *cp, uint64_t now, uint64_t *quiet_since);

/* Whether the link is currently latched lost. */
int ctlplane_lost(struct ctlplane *cp);

/*
 * One decoded control message. Returns 1 when the plane owned it. `netgen` is
 * the network generation a pong proves the link on.
 */
int ctlplane_on_msg(struct ctlplane *cp, const struct ctlplane_sinks *k,
		    int type, const uint8_t *pl, size_t plen, unsigned netgen,
		    uint64_t now);

/*
 * Offer this end's half, once. The pair key exists only when both have
 * arrived, and only the peer decides when we may seal with it. Returns 1 when
 * the half went out on this call.
 */
int ctlplane_offer_key(struct ctlplane *cp, const struct ctlplane_sinks *k);

/* Say where this end is rendezvoused and what it knows about that node
 * (CTL_RDVST_*), what it can reach, and an endpoint it has learnt about
 * itself. */
void ctlplane_tell_rdv(struct ctlplane *cp, const struct ctlplane_sinks *k,
		       int family, const struct sockaddr *sa, int status);
void ctlplane_tell_cand(struct ctlplane *cp, const struct ctlplane_sinks *k,
			int family, const struct sockaddr *sa);
void ctlplane_tell_reach(struct ctlplane *cp, const struct ctlplane_sinks *k,
			 const uint8_t pl[CTL_REACH_PLEN]);
void ctlplane_ping(struct ctlplane *cp, const struct ctlplane_sinks *k,
		   uint64_t now);

/*
 * Note that this end owes the peer a request to rendezvous on `family`, and
 * send whatever is owed. Two calls because the decision is the model owner's
 * and the channel is the loop's: two threads writing one stream socket
 * interleave whatever they were framing.
 */
void ctlplane_ask_rdv(struct ctlplane *cp, int family);
void ctlplane_tell_asks(struct ctlplane *cp, const struct ctlplane_sinks *k);

/*
 * Both families' rendezvous nodes as the peer last named them, if anything
 * has arrived since this was last asked. Returns 0 when nothing has.
 */
int ctlplane_take_nodes(struct ctlplane *cp, struct ctlplane_node out[2]);

/* Families the peer has asked this end to rendezvous on for it, taken once. */
int ctlplane_take_asks(struct ctlplane *cp);

/* The peer's account of its own reachability, if it has changed since this
 * was last asked. Returns 0 when it has not. */
int ctlplane_take_reach(struct ctlplane *cp, uint8_t out[CTL_REACH_PLEN]);

/*
 * What the peer last said about its own reachability, without taking it: a
 * standing statement rather than an event. Returns 0 when the peer has said
 * nothing yet, in which case `out` is left alone, because a peer that has not
 * spoken must not be read as one that reported nothing.
 */
int ctlplane_peer_reach(struct ctlplane *cp, uint8_t out[CTL_REACH_PLEN]);

#endif
