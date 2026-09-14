/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * THE PATH PLANE.
 *
 * A connection holds several ways of reaching its peer and carries the session
 * over exactly one of them. Which one is decided by measurement and by nothing
 * else: a transport reporting a pair says only that packets move, so a path
 * carries the session only once a probe has round-tripped on it bearing this
 * end's own identity.
 *
 * The plane owns the table, the probe cadence and the answer handling. What it
 * does not own is the carriers, the agents and links the probes ride and which
 * of them may carry right now, because that is the playbook's. Those arrive
 * through the sinks.
 */
#ifndef COMRADE_PATHPLANE_H
#define COMRADE_PATHPLANE_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "wsock.h"

#include "path.h"
#include "probeplane.h"

struct nat_agent;

/* Carriers a playbook may name at once: its own, and whatever it has set
 * aside. */
#define PATHPLANE_LIVE_MAX 17

struct pathplane_sinks {
	/*
	 * Put a sealed probe on this path's carrier. `agent` is set for
	 * PATH_ICE and `to` for everything else, which is the whole of what
	 * tells the two apart here.
	 */
	void (*send)(void *arg, enum path_kind kind, struct nat_agent *agent,
		     const struct sockaddr_in6 *to, const uint8_t *b,
		     size_t n);
	/*
	 * This end's identity, which every probe carries and a probe carrying
	 * another is not ours. Copied out rather than held, because the
	 * playbook may mint a new one while a transport thread is reading it.
	 * An empty answer means there is nothing to probe under yet.
	 */
	void (*ident)(void *arg, char *out, size_t n);
	/*
	 * The carriers that can send at this moment, up to PATHPLANE_LIVE_MAX.
	 * Gathered before the table is locked, because an agent may not be
	 * asked anything under it. NULL for "every path can carry".
	 */
	int (*live)(void *arg, struct nat_agent **out, int max);
	/* The pair this agent has nominated, 0 on success. NULL for none. */
	int (*ice_ep)(void *arg, struct nat_agent *a, struct path_ep *ep);
	/* The test hook that takes a path away. NULL for none. */
	int (*blackholed)(void *arg, int kind, const struct sockaddr_in6 *to);
	/* Whether an endpoint is one of this node's own. NULL for "no". */
	int (*is_self)(void *arg, const struct path_ep *ep);
	/* How to classify a source off ICE. NULL for PATH_ROUTED. */
	enum path_kind (*kind_of)(void *arg, const struct path_ep *ep);
	/* Something arrived that authenticated to this pair. NULL for none. */
	void (*heard)(void *arg, uint64_t now);
	/* A path answered for the first time. NULL for none. */
	void (*qualified)(void *arg);
	/*
	 * Give this carrier and the context its callbacks were handed back.
	 * Called with the table unlocked and after the paths that borrowed it
	 * have been dropped, which is the moment nothing can still be inside
	 * those callbacks.
	 */
	void (*agent_free)(void *arg, struct nat_agent *a, void *ctx);
	/* Whether this carrier has given up. NULL for "never". */
	int (*agent_failed)(void *arg, struct nat_agent *a);
	/*
	 * A probe type the plane does not own, already opened and judged
	 * fresh. `held` says the path it arrived on is one this connection is
	 * actually carried over, which is what bounds a notice that cannot be
	 * refused any other way.
	 */
	void (*other)(void *arg, const struct path_probe *pr,
		      enum path_kind kind, int held);
	void *arg;
};

/*
 * A carrier set aside rather than destroyed. One being replaced is not known
 * to be dead: it stopped answering, which is also what a drop that ends in a
 * moment looks like. It stays with its paths in the table, so the ranking can
 * find it alive and go on sending over it, a punch costing a round trip to
 * rebuild and its bindings possibly still being perfectly good.
 *
 * Several at once, because punches launch in parallel and the ranking decides
 * which carries. Touched only by the thread that owns the plane's peer.
 */
#define PATHPLANE_HOLD_MAX 16

struct pathplane_hold {
	struct nat_agent *agent;
	void *ctx;			/* freed with it */
	uint64_t until_ms;		/* reaped past this, with nothing
					 * carrying it */
};

struct pathplane {
	struct path_table t;
	/*
	 * Covers the table and nothing else: a transport's receive thread, a
	 * host's demux and the owner's own loop all reach it. It is never held
	 * across a send, a seal or an agent call, and never nested with any
	 * lock of the owner's in either order.
	 */
	pthread_mutex_t lock;
	struct probeplane *pp;		/* the key schedule probes are sealed
					 * under, and the key path ids are
					 * taken with */
	uint64_t next_ice_ep_ms;	/* when to ask the agents again */
	struct pathplane_hold holds[PATHPLANE_HOLD_MAX];
};

void pathplane_init(struct pathplane *pl, struct probeplane *pp);
void pathplane_destroy(struct pathplane *pl);

/*
 * Let one carrier go, with the paths that borrowed it and the context its
 * callbacks were handed.
 */
void pathplane_free_agent(struct pathplane *pl, const struct pathplane_sinks *k,
			  struct nat_agent *agent, void *ctx);

/* Set a carrier aside until `until_ms`, or let it go if there is no room. */
void pathplane_hold_add(struct pathplane *pl, const struct pathplane_sinks *k,
			struct nat_agent *agent, void *ctx, uint64_t until_ms);

/* Whether anything is set aside, and which of them carries right now (-1 for
 * none). */
int pathplane_has_hold(const struct pathplane *pl);
int pathplane_hold_carrying(struct pathplane *pl);

/* The carriers set aside, for a playbook gathering the ones that can send. */
int pathplane_holds_agents(const struct pathplane *pl, struct nat_agent **out,
			   int max);

/* Let go of everything set aside, and of whatever is past its deadline with
 * nothing carrying it. */
void pathplane_holds_free_all(struct pathplane *pl,
			      const struct pathplane_sinks *k);
void pathplane_holds_reap(struct pathplane *pl,
			  const struct pathplane_sinks *k, uint64_t now);

/*
 * One punch per route, a route being the source and destination address pair
 * with the port ignored, it being a pinhole over the one physical path. When
 * two carriers this end owns nominated the same route the redundant one is let
 * go, so only distinct routes are maintained; `live` is the carrier the
 * playbook is using, which is never the one dropped, nor is whatever carries.
 * A different source address, a second interface, stays a route of its own.
 */
void pathplane_route_dedup(struct pathplane *pl,
			   const struct pathplane_sinks *k,
			   const struct nat_agent *live);

/* The path an agent carries. Idempotent per agent. */
void pathplane_add_ice(struct pathplane *pl, struct nat_agent *agent,
		       uint64_t now);

/*
 * Enter one endpoint on the shared socket as a path, or find the path already
 * naming it; its printable form goes to `label` when one is asked for. Returns
 * 0 when the plane holds the path afterwards.
 */
int pathplane_add_ep(struct pathplane *pl, const struct pathplane_sinks *k,
		     enum path_kind kind, const struct sockaddr_in6 *remote,
		     char *label, size_t label_len, uint64_t now);

/* Retire the ICE path before its agent goes: the path borrows the agent, it
 * does not own it. */
void pathplane_drop_ice(struct pathplane *pl);
void pathplane_drop_agent(struct pathplane *pl, struct nat_agent *agent);

/*
 * Enter an endpoint the peer advertised as one more path on the shared socket.
 *
 * A peer may say where it is; it may not say "everywhere". A group or
 * broadcast address here would have this end probing, and then carrying a
 * session to, every host listening on that port, so only a unicast address is
 * taken, and never this end's own, which would be a pair talking to itself.
 * The kind follows the address's scope through the sinks: filing a neighbour
 * on the same wire as routed makes it look like a stranger across the
 * internet, and ranks it that way.
 *
 * It is a claim and not evidence, nothing having been seen to arrive from it,
 * so it takes a free slot or a dead one and is otherwise declined.
 */
void pathplane_offer_path(struct pathplane *pl,
			  const struct pathplane_sinks *k,
			  const struct sockaddr_in6 *remote, uint64_t now);

/* Whether this plane already holds `ep` as a path: exact, or by port alone. */
int pathplane_holds_ep(struct pathplane *pl, const struct path_ep *ep,
		       int exact);

/* How many paths off ICE this plane holds; `routable_only` leaves out the
 * link-local endpoints a shared-socket send cannot reliably reach. */
int pathplane_lan_paths(struct pathplane *pl, int routable_only);

/* Whether anything has answered. */
int pathplane_any_qualified(struct pathplane *pl);

/*
 * The round trip on the path that carries, as its probes measured it on the
 * wire, so it is the figure ping would give. Returns 0 when nothing has
 * answered on it yet, in which case `out` is untouched and the caller has to
 * fall back on whatever weaker figure it has.
 */
int pathplane_carry_rtt(struct pathplane *pl, int *out);

/*
 * How many distinct paths a probe has ever qualified. Qualification latches
 * and never clears on silence, so this counts the endpoints this peer was
 * actually proven on, and stays stable as they later fall dead.
 */
int pathplane_proven(struct pathplane *pl);

/* What a caller needs of the path carrying right now, copied out under the
 * lock so nothing reaches into the table without it. */
struct pathplane_pick {
	int kind;			/* -1 when no path can carry one */
	int blackholed;			/* the test hook has taken this one away */
	int qualified;			/* something has actually answered on it */
	int srtt_ms;			/* its round trip, as the probes see it */
	struct sockaddr_in6 remote;
	struct nat_agent *agent;
	char label[PATH_LABEL_MAX];
	int nlive;			/* carriers that could send at all */
	int moved;			/* the carry changed on this call */
};

/*
 * Re-evaluate which path carries and report the choice, chosen purely by
 * measurement: the lowest cost in the best occupied warmth tier, ties to the
 * lowest id, both ends computing that from the same pair of published views.
 * Kind plays no part, a path off ICE winning because it measures lower and the
 * measurement being right where it does not.
 *
 * A carrier that has nominated no pair carries nothing at all, so it is marked
 * unusable rather than ranked; the carriers are asked before the lock, which
 * is never held across a call into one. Returns 0 when a path was chosen. A
 * change is logged with both ends' numbers, the one triage surface when a
 * switch looks wrong.
 */
int pathplane_pick(struct pathplane *pl, const struct pathplane_sinks *k,
		   uint64_t now, struct pathplane_pick *out);

/*
 * Can this path's transport carry a datagram right now? A path off ICE always
 * can; an ICE path only while the agent that owns it holds a pair. `live` is
 * what the playbook's own sink would answer, gathered before the table was
 * locked because an agent may not be asked anything under it.
 */
int pathplane_usable(const struct path *p, struct nat_agent *const *live,
		     int nlive);

/* One path's measurements, both ends' views of them, as the selection log
 * shows them. */
void pathplane_desc(const struct path *p, char *out, size_t n);

/*
 * Whether the frame carries this plane's probe tag: the cheap compare that
 * keeps ordinary stream data from ever reaching the seal or the budget.
 */
int pathplane_is_probe(const struct pathplane *pl, const uint8_t *data,
		       size_t len);

/*
 * May this datagram be opened at all?
 *
 * Only a frame carrying the probe tag is a candidate for adoption; anything
 * else is stream data, which the stream rejects for the cost of one compare. A
 * probe from a source this plane already holds is ordinary traffic and is
 * always admitted. One from any other source is admitted only while the budget
 * has a token, because opening it costs a decryption.
 *
 * `pl` may be NULL, which is a source no plane at all is known to hold.
 */
int pathplane_gate(struct pathplane *pl, struct path_adopt *a, uint32_t magic,
		   const struct path_ep *ep, const uint8_t *data, size_t len,
		   uint64_t now);

/*
 * Whether this plane is the one a probe from an unknown source belongs to, and
 * the ping it opened is one it would act on.
 *
 * The seal answers it and the identity inside has to agree: each pair has its
 * own key once it has bound one, and a plane that has bound will not open a
 * frame meant for another, which is the point of binding. So the source
 * address is irrelevant to the question, and a peer that has just moved is
 * recognised by what it knows rather than by where it is.
 */
int pathplane_claims(struct pathplane *pl, const struct pathplane_sinks *k,
		     const uint8_t *data, size_t len, struct path_probe *pr);

/*
 * One round: refresh what the agents have nominated, expire what has gone
 * quiet, and probe whatever is due. Nothing at all until this end has an
 * identity to probe under.
 */
void pathplane_tick(struct pathplane *pl, const struct pathplane_sinks *k,
		    uint64_t now);

/*
 * A probe that arrived on a carrier: the caller has already found the tag, see
 * pathplane_is_probe. Returns 1 when it opened, named this end's identity and
 * had not been acted on before, in which case it has been dealt with; 0 when
 * it was refused, which a caller judging liveness must not count.
 */
int pathplane_recv(struct pathplane *pl, const struct pathplane_sinks *k,
		   const uint8_t *data, size_t len, enum path_kind kind,
		   const struct sockaddr_in6 *src, struct nat_agent *agent,
		   uint64_t now);

/*
 * Act on a probe already opened and judged by pathplane_claims, which is how a
 * host hands one that arrived from a source no path of any connection names.
 */
void pathplane_apply(struct pathplane *pl, const struct pathplane_sinks *k,
		     const struct path_probe *pr, enum path_kind kind,
		     const struct sockaddr_in6 *src, struct nat_agent *agent,
		     uint64_t now);

#endif
