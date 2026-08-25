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

/* Failed attempts, not elapsed time: this loop can stall for seconds, and a
 * clock would condemn a node that is answering for our own slowness. */
#define NETSTATE_ANCHOR_MISSES 3
#define NETSTATE_RDV_MS 2000		/* between re-validation attempts */

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
#define NSA_RDV_REVALIDATE (1u << 7)	/* a direct round trip to it */
#define NSA_RDV_RELOCATE   (1u << 8)	/* presumed gone: search for a fresh one */
#define NSA_EMIT_TOKEN	   (1u << 9)	/* host only: the advert changed */

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
	uint32_t epoch;			/* which network these facts are about */

	uint8_t src[16];		/* what the kernel sources outbound
					 * global traffic of this family from */
	uint8_t src_len;		/* 0 = none held, else 4 or 16 */
	char src_text[NETSTATE_ADDR_MAX];
	uint32_t src_epoch;		/* offered to callers only while this
					 * equals epoch, so a move cannot leave
					 * the previous network's address on the
					 * wire, while "survived the move" stays
					 * distinguishable from "not up yet" */
	uint64_t src_next_ms;
	int src_tries;			/* consecutive empty samples this epoch */
	int routed;			/* the last sample found a route: what
					 * PENDING rests on, and never UP */

	int conn;			/* NET_CONN_*, as last published */
	uint32_t up_epoch;		/* the epoch a round trip completed in;
					 * UP holds only while it is current */

	int probe_running;
	uint32_t probe_epoch;
	uint64_t probe_next_ms;
	int probe_rounds;

	uint8_t anchor[NETSTATE_SA_MAX];	/* opaque sockaddr bytes */
	uint8_t anchor_len;
	int anchor_confirmed;		/* a round trip to THIS node completed in
					 * the current epoch. Adopting a node
					 * never confirms it */
	int anchor_misses;
	uint64_t anchor_next_ms;

	int has_addr;			/* a usable address exists, from the
					 * same snapshot that set the epoch */
	int dht_acked;			/* a validated get was served back by a
					 * node of this family, this epoch */
	int concluded;			/* the DHT attempt has run its course;
					 * pushed in, since the rule reaches
					 * into sig */

	struct netstate_row rows[NETSTATE_ROWS_MAX];
	int nrows;
};

struct netstate {
	struct netstate_fam f[2];	/* [0] v4, [1] v6 */
	int is_host;			/* the only fork: whether a changed
					 * advert raises NSA_EMIT_TOKEN */
	int primed;			/* the first snapshot has been seen, so
					 * has_addr is known rather than assumed
					 * absent -- netmon reports no change on
					 * the call that primes it */
	unsigned pend[2];		/* actions owed, per family */
};

struct netstate_actions {
	unsigned f[2];			/* what is owed, per family */
	uint32_t epoch[2];		/* stamp whatever you start with this,
					 * and hand it back with the result */
};

void netstate_init(struct netstate *ns, int is_host, uint64_t now);

/*
 * The interface snapshot moved. `changed` is netmon's mask; a family whose bit
 * is clear keeps every fact it holds, untouched. have4/have6 come from the
 * SAME snapshot, so a family's epoch and its has_usable_addr fact can never
 * disagree.
 */
void netstate_on_netmon(struct netstate *ns, unsigned changed, int have4,
			int have6, uint64_t now);

/* The answer to NSA_SAMPLE_SRC. len 0 means the kernel had no route -- a fact
 * about routing, and not a reason to forget the address we hold. */
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

/* An NSA_RDV_REVALIDATE round produced nothing: one attempt, not one tick. */
void netstate_on_rdv_attempt(struct netstate *ns, int family, uint32_t epoch,
			     uint64_t now);

/* An anchor handed to us rather than earned -- a token's slot, or the peer's
 * over the control channel. Taken only where we hold none, and never confirmed
 * by the act of taking it. */
void netstate_on_rdv_offered(struct netstate *ns, int family,
			     const uint8_t *node, int len);

/* A local address the agent gathered. Whether it is shown is decided here, now
 * and again whenever the source address changes. */
void netstate_on_candidate(struct netstate *ns, int family, uint32_t epoch,
			   int scope, int via, const uint8_t *addr, int len,
			   const char *text);

/* The caller's own "an ack is no longer coming" rule, which reaches into sig. */
void netstate_on_dht_concluded(struct netstate *ns, int family, int concluded);

/* Raise whatever has fallen due. */
void netstate_tick(struct netstate *ns, uint64_t now);

/* Take the actions owed, clearing them. Non-zero if anything was owed. */
int netstate_take_actions(struct netstate *ns, struct netstate_actions *out);

int netstate_conn(const struct netstate *ns, int family);
uint32_t netstate_epoch(const struct netstate *ns, int family);

/* The LIVE source address: empty while what we hold belongs to an older epoch,
 * so a caller rewriting an offer can never name the network we have left. */
const char *netstate_src_text(const struct netstate *ns, int family);
int netstate_src(const struct netstate *ns, int family, uint8_t *out16);

/* This family's rows, shown and hidden alike; emit the ones marked shown. */
int netstate_rows(const struct netstate *ns, int family,
		  const struct netstate_row **out);

void netstate_facts(const struct netstate *ns, int family,
		    struct tokgen_facts *out);

/* The anchor, and whether a round trip in THIS epoch confirmed it. A caller
 * that reports "ready" on a non-zero return without reading *confirmed has
 * written the bug this module exists to make impossible. */
int netstate_anchor(const struct netstate *ns, int family, uint8_t *out,
		    uint8_t *out_len, int *confirmed);

#endif
