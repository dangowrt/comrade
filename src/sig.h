/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SIG_H
#define COMRADE_SIG_H

#include "wsock.h"
#include <stddef.h>
#include <stdint.h>

#include "sig_mcast.h"		/* struct sig_mcast_if */
#include "token.h"

/*
 * Signalling over a single shared rendezvous mailbox.
 *
 * The two peers meet at ONE DHT mutable item: a small container with two
 * slots, the host's offer and the client's answer. Because a DHT stores a key
 * on the nodes closest to it, two different keys live on different nodes, so a
 * single shared key is the only way one rendezvous node can serve BOTH
 * directions. Each peer writes its own slot with compare-and-swap so neither
 * clobbers the other; a stale write loses the CAS and is retried after the
 * next read. On a LAN, multicast carries the two slots directly instead, with
 * no shared item.
 */

#define SIG_MAX_VALUE 440		/* plaintext per slot; two sealed slots
					 * plus framing fit one BEP44 value */

/* Transports; combine with OR. */
#define SIG_DHT		0x1	/* BitTorrent mainline DHT (internet-wide) */
#define SIG_MCAST	0x2	/* link-local multicast (isolated LANs) */

struct sig;

typedef void sig_recv_cb(void *arg, const uint8_t *data, size_t len);

/*
 * is_host selects which slot is ours: the host writes the offer and reads the
 * answer, the client the reverse. With both transports, multicast runs first
 * and the DHT is engaged once a grace has elapsed, whether or not the link
 * answered in it. A transport that cannot be brought up now is retried from
 * sig_dispatch, so NULL means only that the caller asked for no transport at
 * all.
 */
struct sig *sig_create(const uint8_t rdv[TOKEN_RDV_LEN], unsigned flags,
		       int is_host);
void sig_destroy(struct sig *s);
/*
 * Destroy a signaller that is being replaced within this session, so its DHT
 * node is discarded rather than freed for good: another node follows it at once
 * and is the one worth persisting.
 */
void sig_discard(struct sig *s);

int sig_prepare(struct sig *s, struct pollfd *fds, int maxfds, int *timeout_ms);
void sig_dispatch(struct sig *s, const struct pollfd *fds, int nfds);
int sig_ready(struct sig *s);

/* Post our endpoints into our mailbox slot; kept alive and merged via CAS. */
int sig_post(struct sig *s, const uint8_t *data, size_t len);

/* cb fires when the peer's slot appears or changes. */
int sig_subscribe(struct sig *s, sig_recv_cb *cb, void *arg);

/*
 * Multi-client turnstile. The mailbox is used as a
 * mutex: the host advertises one offer and clears the answer slot to release
 * it; a client claims by writing its answer only into an empty answer slot,
 * with CAS, so exactly one client ever holds a given offer. Which client that
 * is, though, is not something ICE can tell: the host answers a loser's
 * connectivity checks with the credentials every reader of the offer holds. The
 * transport probe (PROTOCOL.md, "Transport probe") is what settles it.
 */

/* The client's view of the answer slot in the last mailbox read. */
enum sig_claim {
	SIG_CLAIM_UNKNOWN = 0,	/* the mailbox has not been read yet */
	SIG_CLAIM_FREE,		/* answer slot empty -- claimable */
	SIG_CLAIM_HELD,		/* our own answer occupies the slot */
	SIG_CLAIM_BUSY		/* another client's answer occupies the slot */
};
enum sig_claim sig_claim_status(struct sig *s);

/* Client: stop advertising our answer, so a slot the host frees is not
 * re-claimed automatically (e.g. once we start punching or give up). A later
 * sig_post re-arms it. */
void sig_withdraw(struct sig *s);

/* Host: publish a fresh offer and release (clear) the answer slot in one
 * atomic rotate, readying the turnstile for the next client. */
int sig_rotate(struct sig *s, const uint8_t *offer, size_t len);

/*
 * Deliver the peer's slot again even if it has not changed. A peer slot is
 * delivered once per distinct value, so a side that discards what it was given
 * -- a client re-claiming after losing a turnstile round -- would otherwise wait
 * for an offer it has already consumed and the host has no reason to rewrite.
 */
void sig_redeliver(struct sig *s);

/* The tag the peer's slot last carried, "" if none. */
void sig_peer_tag(struct sig *s, char *out, size_t n);

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
 * the ICE turnstile (which would serve it twice). With this set, deliver of a
 * sealed multicast answer fires only the direct callback, not the ICE callback.
 * DHT answers are unaffected (they always feed the turnstile).
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
 * sig_locate (host): start capturing the fastest node that serves the mailbox
 * back (the node to embed in the token). The candidates are the nodes that
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
/* Host: adopt an already-known rendezvous node (from a persisted token) as the
 * located anchor and keep it warm with the direct store, instead of locating a
 * fresh one -- so the token stays stable across idle re-attempts. */
int sig_reinforce(struct sig *s, int family, const struct sockaddr *sa,
		  socklen_t len);
/* The located rendezvous node for `family` (4 or 6), if one has been captured. */
int sig_located(struct sig *s, int family, struct sockaddr *out,
		socklen_t *out_len);

/*
 * Whether the DHT has acknowledged our publish for `family` (4 or 6): true once
 * a validated GET has had a k-close node serve our value back, which is exactly
 * the tokgen "dht_acked" fact. A host with no reach on a family never sees this,
 * so it is the signal that the family is isolated (LAN-only).
 */
int sig_dht_acked(struct sig *s, int family);

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

/* Look for a replacement for `family`'s rendezvous node while continuing to
 * serve the one we hold; sig_reinforce with a new one ends the search. */
void sig_search_again(struct sig *s, int family);

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

/* Rendezvous progress for `family`: 0 cold, 1 warmup, 2 store, 3 get, 4 ready
 * (matches the RDV_* enum). The store/get phases are engine-wide; only ready is
 * truly per-family. Advisory, for the view's spinner. */
int sig_rdv_stage(struct sig *s, int family);

/* The up, multicast-capable interfaces this signaller services (view only). */
int sig_link_ifaces(struct sig *s, struct sig_mcast_if *out, int max);

#endif
