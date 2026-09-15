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

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "conn.h"
#include "ctlplane.h"
#include "ctlproto.h"
#include "netstate.h"
#include "hbeat.h"
#include "netmon.h"
#include "obsemit.h"
#include "sig.h"
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
 * Name the server an attempt gathers through, splitting host from port into
 * caller-owned storage that must outlive the agent, since a traversal library
 * keeps the pointer. `attempt` is the rotation count, so a server that does
 * not answer is not the only one ever asked.
 *
 * A pre-resolved address is preferred over the name: a name is re-resolved per
 * agent, and a dead one stalls the gather that a move can least afford. The
 * rounds warm that cache, so the name is only reached for on a cold start.
 * Returns 0 on success, -1 when there is no list to pick from.
 */
int peering_net_stun_pick(const struct peering_net *m, unsigned attempt,
			  char *host, size_t hostlen, uint16_t *port);
/*
 * Widen a description with the egress addresses this carrier maps us to, and
 * say how many the pool holds. Fewer than two is not a fan, so nothing is
 * written.
 *
 * A dependent mapping is the case this exists for, not a reason to skip it: a
 * carrier handing out an address per destination is exactly why naming one of
 * them is a guess. What the fan cannot survive is the PORT moving too, since
 * it names the pool's addresses against this description's own reflexive port,
 * so that, and only that, calls it off.
 */
int peering_net_fan(struct peering_net *m, char *sdp, size_t cap);

/*
 * Mint an identity to gather under. Fixed by this end rather than left to the
 * traversal library, so it survives a re-gather after a failed punch and the
 * peer keeps hammering one target.
 */
void peering_ice_gen(char *ufrag, size_t uflen, char *pwd, size_t pwlen);

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
	struct sig *sig;		/* borrowed; NULL before one exists */
	/*
	 * Which end of the mailbox this is. Read from here and never passed
	 * in: which end asks for a rendezvous and which end serves one is a
	 * property of the mailbox, and two copies of that answer is how two
	 * playbooks come to disagree about it.
	 */
	int is_host;
	int dht;			/* the mailbox is served by a DHT: a
					 * rendezvous can be named, and asked
					 * for */
	/*
	 * The key a claimant boxes its claim to, held here and not by the
	 * signaller: a signaller is rebuilt on every move, and the claim a
	 * peer had in flight when this end roamed is boxed to the old one.
	 */
	uint8_t claim_sk[32];
	int have_claim_sk;
	uint64_t dht_since_ms;		/* when this attempt began: armed with
					 * the signaller, so a rebuild is a
					 * fresh attempt and a fresh grace */

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

void peering_model_init(struct peering_model *pm, int is_host, int dht,
			const struct session_obs *o, uint64_t now);
void peering_model_destroy(struct peering_model *pm);

/*
 * What the playbook still has a say in while the model is settled: where a v6
 * round begins in the STUN list, so it walks in step with the agent's own
 * rotation, and whether a family is one this end is still looking for a node
 * on, which decides whether a watcher is shown it as being checked.
 */
struct peering_settle {
	int start6;
	int expect4, expect6;
};

/*
 * A SIGNALLER WAS ARMED, or the one held was discarded (NULL).
 *
 * A fresh one knows nothing, and it is created more often than once, every
 * move making one, so what the model already holds is told to it here, BEFORE
 * ANYTHING IS PUBLISHED: the claim key, since a claimant boxes to the key it
 * read in the offer and a fresh key would strand the claim in flight, the host
 * being unable to open it, calling the slot unreadable and releasing it,
 * erasing a claim that was perfectly good; which families are proven, since
 * what a signaller drives its convergence eagerness from is only ever
 * published when it changes, and a family that came through the move still
 * proven would otherwise sit in the slow tier for the rest of the session; and
 * a peer's standing request that this end rendezvous for it. Returns -1 when
 * the claim key could not be installed, which leaves the signaller unusable.
 *
 * The rendezvous itself is seeded separately, since where its node comes from
 * is the playbook's.
 */
int peering_model_sig(struct peering_model *pm, struct sig *sig, uint64_t now);

/*
 * ONE PASS OVER THE MODEL, in the only order the three model phases run in.
 *
 * Every peer's peering_absorb belongs immediately before this, so that what a
 * peer said is settled in the same pass it arrived and published in the same
 * pass it was settled. Which peers there are is the playbook's to iterate;
 * that the three below run in this order is not.
 */
void peering_advance(struct peering_model *pm, struct peering_net *net,
		     const struct peering_settle *cfg, uint64_t now);

/*
 * TAKE WHAT THE SIGNALLER HAS LEARNT into the model: which nodes answered,
 * which of them this end may choose between, and the acknowledgement that
 * proves a family's DHT is reachable at all.
 */
void peering_acks(struct peering_model *pm, uint64_t now);

/*
 * SETTLE WHAT THE MODEL DECIDES: feed it what the producer threads left, let
 * its clocks run, and carry out what it asks for. Every path that feeds the
 * model ends here, including the ones that run while a link is up and nothing
 * is watching the interfaces.
 */
void peering_settle(struct peering_model *pm, struct peering_net *net,
		    const struct peering_settle *cfg, uint64_t now);

/*
 * PUBLISH what the model holds, for this mailbox's peers to tell theirs: where
 * this end is rendezvoused, and what it can reach. Nothing is retracted from
 * the first, a peer holding a node this end has stopped being sure of being
 * better off than one holding none; the second is retracted as freely as it is
 * raised, a family that has gone being exactly what the other end needs to
 * know.
 */
void peering_publish(struct peering_model *pm);

/*
 * ONE PEER.
 *
 * The three planes a pair needs, in the one object, wired to each other: the
 * key schedule both of the others seal and open under, the paths that carry,
 * and the channel the pair talks over. They are built in that order because
 * each of the last two holds the first, and a playbook that assembled them
 * itself would have to know that.
 */
/*
 * This end's traversal to one peer: the identity it gathers under, fixed by
 * this end rather than left to the traversal library so it survives a
 * re-gather after a failed punch and the peer keeps hammering one target; the
 * carrier doing the gathering; and the context that carrier's callbacks were
 * handed, which is the playbook's own type and is only ever passed back to it.
 */
struct peering_ice {
	char ufrag[16];
	char pwd[40];
	struct nat_agent *agent;
	void *ctx;			/* freed with the agent */
	volatile int up;		/* the carrier is connected: published
					 * for threads that may not touch it,
					 * a turn out of date at most, which is
					 * what a status line is anyway */
};

struct peering {
	struct peering_model *pm;
	struct probeplane pp;
	struct pathplane pl;
	struct ctlplane cp;
	struct peering_ice ice;
	struct pathplane_sinks pk;	/* what carries its probes */
	struct ctlplane_sinks ck;	/* and what carries what it says */
	int id;				/* the row a watcher knows this peer by */
	uint64_t next_rdvask_ms[2];	/* when it may be asked again about
					 * each family; the model's thread */
	/* The cadences of what this end tells this peer; the channel's own
	 * thread. */
	uint64_t next_cand_ms;
	uint32_t rdv_told_gen;		/* published set this peer has been told */
	uint64_t next_rdv_tell_ms;	/* backstop repeat of that announcement */
	uint32_t reach_told_gen;	/* reachability this peer has been told */
	uint64_t next_reach_tell_ms;
	uint64_t next_hb_ms;		/* the next ping */
};

/*
 * `key` is the base key the establishment primitive derived and `magic` the
 * demux tag, both of which every holder of the primitive has. `seq0` is where
 * this end's counters start, and it is the clock rather than one: see
 * probeplane_init.
 */
void peering_init(struct peering *pr, struct peering_model *pm, uint32_t magic,
		  const uint8_t key[32], uint64_t seq0);
void peering_destroy(struct peering *pr);

/*
 * A fresh channel: the pair key belonged to the one that agreed it, and the
 * halves that made it are spent with it.
 */
void peering_reset(struct peering *pr);

/*
 * Rendezvous and reachability announcement backstops. Each end tells the other
 * the moment its set moves, a family newly qualified or a node replaced, so
 * nothing waits on a cadence to learn of it; the repeat is only there because
 * a control frame is written into the channel without waiting to watch it
 * leave.
 */
#define PEERING_RDV_TELL_MS 30000
#define PEERING_REACH_TELL_MS 30000
/*
 * Candidate advertisement cadence. Each end names its own local endpoints on
 * the shared socket, so both explore the full set rather than only the pair
 * admission produced, and a multi-homed end has its alternatives warm before
 * anything fails. Repeated on a period rather than sent once: an interface
 * brought up mid-session is then advertised within one, and a frame is 21
 * bytes.
 */
#define PEERING_CAND_TELL_MS 5000

/*
 * How often a host repeats a request that a peer rendezvous for it, and how
 * long an unrenewed one stands at the peer that was asked. Slow, because the
 * peer's own situation changes slowly and the request costs it a convergent
 * store; the hold is several periods so a single lost repeat does not drop it.
 */
#define PEERING_RDVASK_MS 60000
#define PEERING_RELAY_HOLD_MS (3 * PEERING_RDVASK_MS)

/*
 * TAKE WHAT THIS PEER HAS SAID, and act on it.
 *
 * The node it named becomes this end's anchor where the rules allow, its
 * account of itself is noted, and whichever of the two rendezvous favours this
 * end owes the other is decided: a host with no route to a family asks a
 * client that has one to place its mailbox there, and a client asked to do so
 * tells its signaller to. Which of those applies is read from the mailbox, not
 * passed in.
 *
 * Runs on the thread that owns the model. What it decides to SAY is left for
 * peering_say on the channel's own loop, because two threads writing one
 * stream socket interleave whatever they were framing.
 */
void peering_absorb(struct peering *pr, uint64_t now);

/*
 * What this playbook does for this peer, set once after init: where a frame
 * for a path goes, and what a control message rides.
 */
void peering_sinks(struct peering *pr, const struct pathplane_sinks *pk,
		   const struct ctlplane_sinks *ck);

/*
 * SAY THE STANDING THINGS, on their cadences.
 *
 * Where this end is rendezvoused, what it can reach, whatever rendezvous it
 * owes this peer a request for, the endpoints it has learnt about itself, its
 * half of the pair key, and a ping. Each is sent the moment it moves and
 * repeated rarely, the repeat being there only because a frame is written into
 * the channel without waiting to watch it leave.
 *
 * `cand_port` is the shared socket's, and the only transport able to send to
 * an arbitrary endpoint, so an advertised endpoint always becomes a path off
 * ICE. Zero advertises nothing, which is what an end with no such socket has
 * to say about where it is.
 *
 * Runs on the thread that owns the channel.
 */
void peering_say(struct peering *pr, uint16_t cand_port, uint64_t now);

/*
 * This peer is owed the whole standing set from `now`, whatever an earlier
 * connection on the same object was told: a channel that has just come up has
 * heard none of it.
 */
void peering_owed(struct peering *pr, uint64_t now);

/*
 * KEEP THE PATHS WARM: one round of the probe cadence, on the thread that owns
 * this peer.
 */
void peering_paths(struct peering *pr, uint64_t now);

/*
 * A frame that arrived on one of this peer's carriers and carries the probe
 * tag. Returns 1 when it was this peer's and has been dealt with, 0 when it
 * was refused, which a caller judging liveness must not count.
 */
int peering_recv(struct peering *pr, const uint8_t *data, size_t len,
		 enum path_kind kind, const struct sockaddr_in6 *src,
		 struct nat_agent *agent, uint64_t now);

/*
 * Whether a frame from a source no path of this peer's names is this peer's,
 * and if so act on it. Returns 0 when it is not, 1 when it was acted on, and
 * -1 when it was this peer's but had been acted on already, which is the
 * caller's cue to stop looking rather than offer it elsewhere.
 */
int peering_claims(struct peering *pr, const uint8_t *data, size_t len,
		   enum path_kind kind, const struct sockaddr_in6 *src,
		   uint64_t now);

/*
 * THIS PEER'S LINK, on the scale a watcher shows.
 *
 * The distinctions are about evidence, not about hope. Traffic arriving is the
 * only thing that proves a path, and it proves it for the network it arrived
 * on, so a move puts every peer back to unknown rather than leaving the last
 * network's verdict on screen, where it reads as a working link that simply is
 * not there. Between live and lost sits a stretch where the last thing heard
 * is old enough to notice and not old enough to give up on; showing that as
 * live is how a link that stopped looks fine until it is suddenly gone.
 *
 * `netgen` is the machine's generation now, and `carrier_up` whether a carrier
 * exists at all, which is what tells a peer being punched from one that has
 * not been reached yet. Returns a CONN_* state.
 */
/* The stretch between live and lost: old enough to notice, not old enough to
 * give up on. */
#define PEERING_LINK_LAG_MS 1200

int peering_link(struct peering *pr, unsigned netgen, int carrier_up,
		 uint64_t now);

/* This end's identity for this peer, and the carrier gathering under it. */
void peering_ice_ident(struct peering *pr);

/*
 * Take a carrier as this peer's, and give the one it holds back.
 *
 * Building it is the playbook's, since the callbacks and the context they are
 * handed are; what the engine owns is the bookkeeping around it, which is the
 * part that goes wrong: the path the carrier borrows has to appear with it and
 * be retired before it, and the context has to outlive every callback that
 * could still name it.
 */
void peering_ice_adopt(struct peering *pr, struct nat_agent *agent, void *ctx,
		       uint64_t now);
void peering_ice_stop(struct peering *pr, const struct pathplane_sinks *k);
struct nat_agent *peering_ice_agent(struct peering *pr);
int peering_ice_up(const struct peering *pr);

/* Which path carries this peer right now. */
int peering_pick(struct peering *pr, uint64_t now,
		 struct pathplane_pick *out);

/* Enter an endpoint as a path: one this end has been given, and one the peer
 * advertised. */
int peering_add_path(struct peering *pr, enum path_kind kind,
		     const struct sockaddr_in6 *remote, char *label,
		     size_t label_len, uint64_t now);
void peering_offer_path(struct peering *pr, const struct sockaddr_in6 *remote,
			uint64_t now);

/* Printable "addr:port" ("[v6]:port") for a sockaddr; empty on failure. */
void peering_sockaddr_text(const struct sockaddr *sa, socklen_t len, char *out,
			   size_t n);

#endif
