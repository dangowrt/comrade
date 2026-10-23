/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SIG_H
#define COMRADE_SIG_H

#include "wsock.h"
#include <stddef.h>
#include <stdint.h>

#include "rdv.h"
#include "sig_mcast.h"		/* struct sig_mcast_if */
#include "token.h"

/* Transports; combine with OR. */
#define SIG_DHT		0x1	/* BitTorrent mainline DHT (internet-wide) */
#define SIG_MCAST	0x2	/* link-local multicast (isolated LANs) */

struct sig;

enum sig_claim {
	SIG_CLAIM_UNKNOWN = 0,
	SIG_CLAIM_FREE,
	SIG_CLAIM_HELD,
	SIG_CLAIM_BUSY,
	SIG_CLAIM_ANSWERED,
	SIG_CLAIM_REFUSED
};

/* A peer's description, and the instance id (RDV_CID_LEN bytes) it came from. */
typedef void sig_recv_cb(void *arg, const uint8_t *cid, const uint8_t *data,
			 size_t len);

/* `auth` is the credential this end holds, `auth_ro` whether it is the read-only
 * one: a claimant's slot is sealed to its class, see keys_slot_key. */
struct sig *sig_create(const uint8_t rdv[TOKEN_RDV_LEN],
		       const uint8_t auth[TOKEN_AUTH_LEN], int auth_ro,
		       unsigned flags, int is_host);
void sig_destroy(struct sig *s);
/*
 * Destroy a signaller that is being replaced within this session, so its DHT
 * node is discarded rather than freed for good: another node follows it at once
 * and is the one worth persisting.
 */
void sig_discard(struct sig *s);

/* The state machine this signaller drives, owned above it so that its sequence
 * numbers outlive a rebuild; handed in before anything is published. */
void sig_rdv_host(struct sig *s, struct rdv_host *h);
void sig_rdv_client(struct sig *s, struct rdv_client *c);

const uint8_t *sig_instance_id(void);

int sig_prepare(struct sig *s, struct pollfd *fds, int maxfds, int *timeout_ms);
void sig_dispatch(struct sig *s, const struct pollfd *fds, int nfds);
int sig_ready(struct sig *s);

int sig_post(struct sig *s, const uint8_t *data, size_t len);
/* This end has minted a fresh ICE identity: an answer to the offer the next
 * one supersedes is addressed to credentials it has stopped presenting. */
void sig_ident_changed(struct sig *s);

/* Ask again, the description unchanged, under a number the host will read. */
void sig_reask(struct sig *s);

int sig_subscribe(struct sig *s, sig_recv_cb *cb, void *arg);

int sig_answer(struct sig *s, const uint8_t *cid, const uint8_t *data,
	       size_t len);
void sig_refuse(struct sig *s, const uint8_t *cid);
void sig_claimant_gone(struct sig *s, const uint8_t *cid);

int sig_refusal(struct sig *s);

void sig_withdraw(struct sig *s);

/*
 * Host: the session behind this invitation is over. Replaces the host slot in
 * the DHT with a tombstone, so a client that comes to join is told the session
 * has ended instead of announcing to a host that will never answer. One way; a
 * signaller does not go back to serving.
 *
 * Only the DHT carries this, because only the DHT holds anything once we are
 * gone. Link-local discovery is a conversation, not a store: a message left
 * there reaches whoever happens to be listening at that moment, which is the
 * peers already connected -- and those are told over the control channel
 * inside their own session, where the statement cannot be forged. On an
 * isolated LAN a session that has ended is simply a segment where nobody is
 * offering, which is also what a session that never started looks like, and
 * there is nothing truthful to say about the difference.
 *
 * sig_end_placed says the tombstone has reached somewhere a joiner will look,
 * which is what a host is waiting for before it exits. With no DHT there is
 * nothing to place and nothing to wait for.
 */
void sig_end(struct sig *s);
int sig_end_placed(struct sig *s);

/*
 * Client: the host slot says the session has ended.
 *
 * Not the first sight of a tombstone: every holder of the invitation can write
 * the host slot, so it is only believed once it has stood for a few rounds
 * with no host info read since. A host that is merely being lied about writes
 * its slot again within a second or so, which resets the judgement -- and is
 * why a forged tombstone costs a joiner a pause rather than the session.
 */
int sig_peer_ended(struct sig *s);

/*
 * That judgement on its own: a tombstone first seen at `tomb_ms` (0 = none
 * seen), against host info last seen at `info_ms` (0 = none), as of `now`.
 * Exported so the rule that ends a client's wait can be exercised without a
 * DHT, since being wrong either way is expensive: too eager refuses a live
 * session, too slow leaves the wait it exists to end.
 */
int sig_tomb_settled(uint64_t tomb_ms, uint64_t info_ms, uint64_t now);

/*
 * Link-local direct bypass (multicast only). Our own direct-transport port is
 * carried in the announcement; when the peer's announcement arrives from a
 * link-local source -- proving a clear layer-2 path that needs no ICE -- cb
 * fires with the peer's endpoint (that source address, keeping its zone id,
 * and the announced direct port). ICE still runs on the routable candidates in
 * the same announcement; the two race and whichever carries KCP first wins. The
 * sealed candpack is handed over with the endpoint: it is authenticated, so the
 * ICE ufrag inside it identifies the claimant across the direct and ICE paths
 * alike, and a host can tell that both are the same client.
 */
typedef void sig_direct_cb(void *arg, const struct sockaddr *peer,
			   socklen_t len, const uint8_t *sdp, size_t sdp_len);
void sig_set_direct_port(struct sig *s, uint16_t port);
int sig_subscribe_direct(struct sig *s, sig_direct_cb *cb, void *arg);

/*
 * Host only: this host demultiplexes the shared lanlink socket itself, so a
 * same-segment multicast claimant is served directly and must NOT also be fed to
 * the ICE turnstile (which would serve it twice). With this set, a sealed
 * multicast offer fires only the direct callback, not the ICE callback. Offers
 * read from the DHT are unaffected (they always feed the turnstile).
 */
void sig_set_mcast_claims(struct sig *s, int on);

/*
 * Rendezvous acceleration.
 *
 * All three engage the DHT, and all three refuse when SIG_DHT is not among the
 * transports this signaller was created with.
 *
 * sig_seed_node (client): plant a token's rendezvous node as a sticky DHT
 * hint, queried first, with the global DHT bootstrapping alongside as fallback.
 *
 * sig_locate (host): start capturing the fastest node that serves the host
 * slot back (the node to embed in the token). The candidates are the nodes that
 * stored our value; the get validates and ranks them, and sig_located returns
 * the fastest once known.
 */
int sig_seed_node(struct sig *s, const struct sockaddr *sa, socklen_t len);
int sig_locate(struct sig *s);
/*
 * Host: `family`'s connectivity is proven (a real STUN reply), or no longer
 * is (a network change). While up, a still-missing family's rendezvous node
 * is chased eagerly and indefinitely -- proof, not a timing guess, decides
 * how hard to keep trying.
 */
void sig_set_family_up(struct sig *s, int family, int up);

/* The network generation stamped into our own posted slot, and the one read
 * back from the peer's. A host bumps its own on every move so a peer can tell a
 * fresh offer that only rotated credentials from one that changed networks. */
void sig_set_gen(struct sig *s, uint32_t gen);
uint32_t sig_peer_gen(const struct sig *s);
/* Client: the host instance the host slot names, NULL until it has been read.
 * A restarted host keeps its generation and changes this. */
const uint8_t *sig_peer_cid(const struct sig *s);

/* Host: adopt an already-known rendezvous node (from a persisted token) as the
 * located anchor and keep it warm with the direct store, instead of locating a
 * fresh one -- so the token stays stable across idle re-attempts. */
int sig_reinforce(struct sig *s, int family, const struct sockaddr *sa,
		  socklen_t len);
/* The located rendezvous node for `family` (4 or 6), if one has been captured. */
int sig_located(struct sig *s, int family, struct sockaddr *out,
		socklen_t *out_len);

/*
 * The node that served a validated get for `family` since this was last
 * asked, if one has. Who answered is what says whether the rendezvous we hold
 * is still the rendezvous -- and whether this family reaches the DHT at all
 * on the network we are on now, which is a round trip and so is proof.
 */
int sig_take_ack(struct sig *s, int family, struct sockaddr *out,
		 socklen_t *out_len);

/* Whether the DHT is up enough to have asked anything. */
int sig_dht_ready(struct sig *s);

/*
 * Whether the node we hold for `family` has itself served a validated get
 * since this was last asked, and clear the record.
 *
 * Who answered *instead* is not information about it. The convergent store
 * places the value on every k-close node, so several hold it and whichever is
 * quickest replies -- reading another holder's reply as our node falling
 * silent condemns a perfectly live rendezvous, and does so within seconds of
 * the store that created the alternatives.
 */
int sig_take_anchor_seen(struct sig *s, int family);

/* Look for a replacement for `family`'s rendezvous node while continuing to
 * serve the one we hold; sig_reinforce with a new one ends the search. */
void sig_search_again(struct sig *s, int family);

/* Host: give up on `family`'s captured node entirely -- unpin it and return
 * the family to locating, so the next validating get can capture a fresh one.
 * For a node no token has ever named; one that qualified is only ever
 * replaced, never dropped (sig_search_again). */
void sig_forget(struct sig *s, int family);

/*
 * Client: establish a rendezvous on `family` for a peer that cannot reach it.
 *
 * The sequence is the one a host runs for itself -- store the host slot where
 * the key says it belongs, read it back, and let whichever node answered be
 * the rendezvous -- because a node found any other way would carry a weaker
 * promise than one the host found, while being indistinguishable from it
 * afterwards. In particular a node proven only by serving a read may still
 * refuse the write an offer is, and the offer would then fail silently against
 * an anchor that looked sound.
 *
 * What is stored is the host slot exactly as last read, and never over a copy
 * at a higher sequence. Ends by itself once the family has a node;
 * sig_relay(.., 0) ends it early.
 */
void sig_relay(struct sig *s, int family, int on);

/*
 * Host: still actively chasing `family`'s rendezvous node -- true once the
 * other family has proven the DHT reachable at all, until this one is
 * captured too, however long that takes: no fixed run length, since a slower
 * DHT converging is not distinguishable in advance from one that never will.
 * False for a family already captured, and false before any capture at all --
 * a caller waiting on an ack has only its own deadline to settle that family
 * by until then.
 */
int sig_locating(struct sig *s, int family);

/*
 * What the rendezvous is doing, for the view.
 *
 * Everything before the punch happens through its slots, so when a join stalls
 * this is the first place to look: whether our own slot ever reached the DHT,
 * whether the peer's has appeared, and how long since either moved. Without it
 * the operator has a spinner and no way to tell "the offer never got stored"
 * from "the answer never came back".
 */
struct sig_mailbox {
	int engaged;			/* the DHT is up and being asked */
	int stage;			/* RDV_*: cold, warmup, store, get, ready */
	int have_mine;			/* we have something to publish */
	int mine_stored;
	int peer_seen;
	int64_t seq;
	int gets;			/* validated reads so far */
	int puts;			/* stores that found a home */
	int claim;
	uint64_t last_get_ms;		/* 0 = never */
	uint64_t last_put_ms;
	uint64_t engaged_ms;		/* what a silence is measured from while
					 * last_get_ms is still 0 */
};
void sig_mailbox_state(struct sig *s, struct sig_mailbox *out);

/* Which network each family is on, as netstate counts it. An answer is evidence
 * about the network its query went out on, so one that arrives after a move is
 * not offered as proof of the network moved to. */
void sig_set_family_epoch(struct sig *s, int family, uint32_t epoch);

/* Which routes a slot may be worked through: a convergent store or get
 * walks the DHT and is worth nothing without a routing table, a direct one
 * addresses the rendezvous nodes already held and needs only one of them. */
#define SIG_ROUTE_DIRECT (1u << 0)
#define SIG_ROUTE_WIDE	 (1u << 1)
unsigned sig_routes_open(int node_ready, int rdv_held);

/*
 * Whether the rendezvous has gone unanswered for long enough to give up on the
 * signaller and build a fresh one. `idle_ms` is the age of the last validated
 * read, or of engaging where there has been none; `asking` is whether any route
 * is open at all, and `answered` whether one ever came back.
 *
 * Three verdicts, because there are three failures: a signaller asking nothing
 * is one no read can come back to, so only a dip between refreshes has to be
 * ruled out; one that is asking and was answered has a rendezvous that died
 * under it, which takes longer to tell from a slow round; and one that has
 * never been answered at all was built on a network that could not carry it.
 */
int sig_quiet_due(int asking, int answered, uint64_t idle_ms);

/* The same question against this signaller's own state. */
int sig_quiet(struct sig *s);

/* Rendezvous progress for `family`: 0 cold, 1 warmup, 2 store, 3 get, 4 ready
 * (matches the RDV_* enum). The store/get phases are engine-wide; only ready is
 * truly per-family. Advisory, for the view's spinner. */
int sig_rdv_stage(struct sig *s, int family);

/* The up, multicast-capable interfaces this signaller services (view only). */
int sig_link_ifaces(struct sig *s, struct sig_mcast_if *out, int max);

#endif
