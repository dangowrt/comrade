/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_NETSTATE_H
#define COMRADE_NETSTATE_H

#include <stddef.h>
#include <stdint.h>

#include "netmon.h"		/* NETMON_CH_*: the mask a move is reported as */
#include "tokgen.h"

/*
 * What this host knows about its own reachability, per address family.
 *
 * A fact is about the network it was learnt on and no other: each family
 * carries an epoch, and an asynchronous fact stamped with a superseded one is
 * dropped. Only a round trip completed in the current epoch marks a family
 * reachable -- not a rendezvous node carried across a move, not a token minted
 * before it, not a route that merely exists.
 *
 * Pure: no sockets, no threads, no clock (now_ms is passed in, as netmon and
 * path do). What the outside world must do is returned as an action rather
 * than performed, so this cannot block a loop or reach past the controller
 * into the view. Addresses cross as bytes plus the caller's own text.
 *
 * Called only on the thread that owns sig, as sig.h requires.
 */

enum {					/* address scope for a local address */
	NET_SCOPE_LAN,			/* RFC1918 / ULA / link-local */
	NET_SCOPE_CGNAT,		/* 100.64/10 carrier-grade NAT */
	NET_SCOPE_GLOBAL		/* globally routable */
};
enum {					/* how a local address was learnt */
	NET_VIA_DIRECT,			/* locally gathered host candidate */
	NET_VIA_STUN			/* server-reflexive, learnt via STUN */
};
/* Bits, not an enum, so a later verdict (NAT type, filtering) can join UP. */
#define NET_CONN_UP	  (1 << 0)	/* proven: something answered us here */
#define NET_CONN_PENDING (1 << 1)	/* a route exists; not yet proven */
					/* 0: no route for this family at all */

#define NETSTATE_ADDR_MAX 64		/* an address as the caller printed it */
#define NETSTATE_SA_MAX 128		/* a sockaddr, opaque to this module */
#define NETSTATE_ROWS_MAX 12		/* local addresses held per family */

/* Quickly while there is no source (an RA or DHCPv6 still finishing), then
 * slowly but forever: an RFC 4941 address rotating changes what the kernel
 * sources from with no interface event to notice. */
#define NETSTATE_SRC_FAST_MS 500
#define NETSTATE_SRC_FAST_TRIES 30	/* ~15s, past any RA/DHCPv6 settle */
#define NETSTATE_SRC_SLOW_MS 5000

/*
 * How many separate answers a node must give before it goes into a token, and
 * how many answers from somewhere else it takes to give it up again.
 *
 * The asymmetry is the point. A token is shared by hand and lives in somebody
 * else's clipboard, so a rendezvous that turns out to be flaky cannot be
 * recalled -- whoever holds it is already pointed at it. Time spent qualifying
 * one before publishing costs only us; cycling through nodes afterwards costs
 * everyone who was given the old one, and is worst exactly during a move.
 */
#define NETSTATE_ANCHOR_QUALIFY 3
#define NETSTATE_ANCHOR_MISSES 3
#define NETSTATE_RDV_MS 2000		/* between re-validation attempts */

/*
 * Rounds a held node may leave unanswered, on a network this family has
 * proven, before an alternative is searched for alongside it.
 *
 * Silence alone says nothing -- it is equally the network. But the direct get
 * only ever asks the nodes already held, so if nothing is searched for, no
 * other node can answer, and the one piece of evidence that could replace a
 * dead node can never arrive. Searching is free and reversible: the held node
 * stays pinned, served and named by the token throughout, and only a different
 * node actually answering replaces it.
 */
#define NETSTATE_ANCHOR_QUIET 5

/* Prompt for a few rounds, then slowly but never not at all: a filtering
 * network cannot be told from a slow one in advance, and giving up is the one
 * answer that cannot be corrected. A move restarts the prompt rounds. */
#define NETSTATE_PROBE_ROUNDS 5
#define NETSTATE_PROBE_MS 4000		/* between the prompt rounds */
#define NETSTATE_PROBE_SLOW_MS 30000	/* and forever after, at this pace */

/* What the caller must do. Idempotent bits rather than a queue, so a second
 * move landing mid-work re-raises them with the newer epoch. */
#define NSA_SAMPLE_SRC	   (1u << 0)	/* ask the kernel for this family's
					 * outbound source, feed the answer back */
#define NSA_KICK_PROBE	   (1u << 1)	/* start this family's STUN check */
#define NSA_STOP_PROBE	   (1u << 2)	/* proven: stop spending packets */
#define NSA_EMIT_ROWS	   (1u << 3)	/* clear THIS family's rows in the view
					 * and re-emit netstate_rows() */
#define NSA_EMIT_CONN	   (1u << 4)	/* publish netstate_conn() */
#define NSA_EMIT_RDV	   (1u << 5)	/* re-report the anchor and whether it
					 * is confirmed */
#define NSA_RDV_PIN	   (1u << 6)	/* pin the anchor now held */
#define NSA_RDV_RELOCATE   (1u << 7)	/* quiet: look for one alongside it */
#define NSA_EMIT_TOKEN	   (1u << 8)	/* host only: the advert changed */

/* One local address, and whether it should be shown. Held rather than emitted
 * as it arrives, because whether a global v6 is ours to show is not knowable
 * until the source address is, which is often later. */
struct netstate_row {
	uint8_t addr[16];		/* the key; v4 in the low four bytes */
	uint8_t addr_len;		/* 4 or 16 */
	char text[NETSTATE_ADDR_MAX];	/* as the caller printed it */
	int scope;			/* NET_SCOPE_* */
	int via;			/* NET_VIA_* */
	int shown;			/* recomputed, never applied destructively */
};

struct netstate_fam {
	uint32_t epoch;

	uint8_t src[16];
	uint8_t src_len;		/* 0 = none held, else 4 or 16 */
	char src_text[NETSTATE_ADDR_MAX];
	uint32_t src_epoch;		/* src is offered only while this is
					 * current, so a move cannot leave the
					 * old address on the wire */
	uint64_t src_next_ms;
	int src_tries;
	int routed;

	int conn;			/* NET_CONN_* */
	uint32_t up_epoch;

	int probe_running;
	uint32_t probe_epoch;
	uint64_t probe_next_ms;
	int probe_rounds;

	uint8_t anchor[NETSTATE_SA_MAX];	/* opaque sockaddr bytes */
	uint8_t anchor_len;
	int anchor_confirmed;		/* adopting a node never confirms it */
	int anchor_acks;		/* separate answers from it, this epoch */
	int anchor_misses;		/* answers from somewhere else instead */
	int anchor_quiet;		/* rounds it left unanswered, while up */
	uint64_t anchor_next_ms;

	int has_addr;
	int dht_acked;
	int concluded;			/* pushed in: the rule reaches into sig */

	struct netstate_row rows[NETSTATE_ROWS_MAX];
	int nrows;
};

struct netstate {
	struct netstate_fam f[2];	/* [0] v4, [1] v6 */
	int is_host;			/* the only fork: NSA_EMIT_TOKEN */
	int primed;			/* netmon reports no change on the call
					 * that primes it, so take that one */
	unsigned pend[2];
};

struct netstate_actions {
	unsigned f[2];
	uint32_t epoch[2];		/* stamp what you start, hand it back */
};

void netstate_init(struct netstate *ns, int is_host, uint64_t now);

/* A family whose bit is clear keeps every fact it holds. have4/have6 must come
 * from the same snapshot as `changed`. */
void netstate_on_netmon(struct netstate *ns, unsigned changed, int have4,
			int have6, uint64_t now);

/* len 0 means no route -- not a reason to forget the address we hold. */
void netstate_on_src(struct netstate *ns, int family, uint32_t epoch,
		     const uint8_t *addr, int len, const char *text,
		     uint64_t now);

void netstate_on_probe_started(struct netstate *ns, int family, uint32_t epoch,
			       uint64_t now);
void netstate_on_probe_done(struct netstate *ns, int family, uint32_t epoch,
			    uint64_t now);

/* A round trip COMPLETED: the only thing that may assert NET_CONN_UP. */
void netstate_on_roundtrip(struct netstate *ns, int family, uint32_t epoch);

/*
 * A validated DHT get was served back by `node`. Proves the family, and
 * confirms the anchor -- or replaces it, but only once the held one has been
 * presumed gone, so a working rendezvous never changes underneath a token.
 */
void netstate_on_dht_ack(struct netstate *ns, int family, uint32_t epoch,
			 const uint8_t *node, int len, uint64_t now);

/* An anchor handed to us (a token slot, or the peer's): taken only where we
 * hold none, and never confirmed by the taking. */
void netstate_on_rdv_offered(struct netstate *ns, int family,
			     const uint8_t *node, int len);


void netstate_on_candidate(struct netstate *ns, int family, uint32_t epoch,
			   int scope, int via, const uint8_t *addr, int len,
			   const char *text);

void netstate_on_dht_concluded(struct netstate *ns, int family, int concluded);

void netstate_tick(struct netstate *ns, uint64_t now);

/* Take the actions owed, clearing them. Non-zero if any were. */
int netstate_take_actions(struct netstate *ns, struct netstate_actions *out);

int netstate_conn(const struct netstate *ns, int family);
uint32_t netstate_epoch(const struct netstate *ns, int family);

/* Empty while what we hold belongs to an older epoch. */
const char *netstate_src_text(const struct netstate *ns, int family);
int netstate_src(const struct netstate *ns, int family, uint8_t *out16);

/* Shown and hidden alike; emit the ones marked shown. */
int netstate_rows(const struct netstate *ns, int family,
		  const struct netstate_row **out);

void netstate_facts(const struct netstate *ns, int family,
		    struct tokgen_facts *out);

/* The anchor, and whether a round trip in this epoch confirmed it. */
int netstate_anchor(const struct netstate *ns, int family, uint8_t *out,
		    uint8_t *out_len, int *confirmed);

#endif
