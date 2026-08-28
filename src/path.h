/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_PATH_H
#define COMRADE_PATH_H

#include "wsock.h"
#include <stddef.h>
#include <stdint.h>

#include "keys.h"

/*
 * The path model: everything about a path that is decidable without touching a
 * socket or a clock. A path is a pair (local transport instance, remote
 * endpoint) over which sealed datagrams for one connection can be sent; a
 * connection tracks up to PATH_TABLE_MAX of them and carries KCP over exactly one at
 * a time. See PROTOCOL.md, "Path model and transport probe".
 *
 * Everything here is pure: every entry point that needs the time takes it as an
 * argument, nothing sends, nothing allocates. The caller owns the transports
 * and does the I/O; this decides what to send where, and what a measurement
 * means.
 *
 * Management is symmetric and role-free. Both ends run this same code, over
 * measurements they both publish, and arrive at the same choice without either
 * deciding for the other.
 */

struct nat_agent;

/*
 * How a path was come by. A description, not a rank: it names the local
 * transport and nothing else, and plays no part in choosing between paths.
 */
enum path_kind {
	PATH_SEGMENT = 0,	/* shared lanlink socket, peer on the link */
	PATH_ROUTED,		/* shared lanlink socket, any other endpoint */
	PATH_ICE		/* a libjuice agent and its nominated pair */
};

/*
 * Warmth, ordered best first: the numeric order IS the preference order, so a
 * comparison needs no translation table. DEAD ranks below UNQUALIFIED because a
 * path that has fallen silent for PATH_DEAD_MS has been shown not to work,
 * where an untried one has not.
 */
enum path_warmth {
	PATH_WARM = 0,		/* answered within PATH_WARM_MS */
	PATH_COLD,		/* qualified once, silent beyond PATH_WARM_MS */
	PATH_UNQUALIFIED,	/* never answered */
	PATH_DEAD		/* silent beyond PATH_DEAD_MS */
};

#define PATH_TABLE_MAX 4			/* paths tracked per connection */
#define PROBE_EVERY_MS 200		/* probe period while unqualified */
#define PATH_KEEP_MS 1000		/* probe period once qualified */
#define PATH_WARM_MS 3000		/* WARM becomes COLD past this */
#define PATH_DEAD_MS 8000		/* COLD becomes DEAD past this */
#define PATH_LOSS_PENALTY_MS 200	/* cost added by total loss */
#define PATH_COST_QUANTUM_MS 5		/* ranking bucket width */
#define PATH_SWITCH_MARGIN 1		/* buckets a candidate must win by */
#define PATH_SWITCH_HOLD 2		/* evaluations it must hold that by */
#define PATH_ADOPT_RATE 8		/* unknown-source probes admitted a
					 * second, per listening socket */
#define PATH_ADOPT_DEPTH 8		/* that bucket's depth */
/*
 * A probe becomes a loss outcome only once it has been outstanding longer than
 * max(3 * srtt, PATH_LOSS_WAIT_MS). Scoring a superseded probe as lost the
 * moment the next one is sent would score total loss on any path whose round
 * trip exceeds the probe period, condemning a working path for being slow.
 */
#define PATH_LOSS_WAIT_MS 1000
#define PATH_LOSS_WINDOW 16		/* probe outcomes the ratio spans */

#define PATH_ID_LEN 8
#define PATH_EP_LEN 18			/* addr(16) || port(2), on the wire */
#define PATH_LABEL_MAX 80

/*
 * A canonical endpoint. IPv4 is always carried v4-mapped (::ffff:a.b.c.d),
 * exactly as lanlink_map_peer produces, so both ends name one endpoint the same
 * way whichever family it arrived over. The IPv6 zone id is deliberately
 * excluded: it is local to one host and does not travel, so it cannot be part
 * of a name both ends must agree on. All-zero means "not known yet".
 */
struct path_ep {
	uint8_t addr[16];
	uint16_t port;			/* host byte order */
};

int path_ep_from_sockaddr(struct path_ep *ep, const struct sockaddr *sa,
			  socklen_t len);
void path_ep_to_sockaddr(const struct path_ep *ep, struct sockaddr_in6 *out);
void path_ep_pack(const struct path_ep *ep, uint8_t out[PATH_EP_LEN]);
void path_ep_unpack(struct path_ep *ep, const uint8_t in[PATH_EP_LEN]);
int path_ep_eq(const struct path_ep *a, const struct path_ep *b);
int path_ep_any(const struct path_ep *ep);
int path_ep_is_v4(const struct path_ep *ep);
void path_ep_str(const struct path_ep *ep, char *out, size_t n);

/*
 * The probe frame.
 *
 *   [4 magic][seal(sig_key, plain)]
 *   plain = [1 type][8 nonce][8 seq][1 ulen][ulen claimant ufrag]  head
 *           [16 addr][2 port BE][2 srtt_ms BE][2 loss_ppt BE]      tail, optional
 *
 * The seal is not defending against the peer, who holds the token and is
 * trusted by construction; it stops a stranger who can guess an endpoint from
 * forging a reply. The nonce must be unpredictable, being the only thing that
 * stops a forged PONG.
 *
 * seq counts this sender's frames on this connection, from one. The seal says
 * a frame was written by somebody holding the key; it never said when, so a
 * copy taken off the wire opened again whenever its holder chose. The receiver
 * keeps a window (replay.h) and acts on each sequence once.
 *
 * The claimant ufrag ties a frame to one connection: a host worker answers only
 * for the claimant it was admitted for, and that single test separates the
 * winner of a turnstile round from the losers whose checks its agent answered
 * on the way past.
 *
 * The tail is present when the plaintext runs past 10 + ulen; a peer that omits
 * it merely shares no measurements, which costs accuracy and never correctness.
 * echo is the source this path's last inbound datagram was observed arriving
 * from, all-zero when nothing has arrived yet, so a prober reading a PONG
 * learns its own reflexive endpoint on that path for free.
 */
#define PROBE_MAGIC 0x434d5250U	/* "CMRP"; differs from SESSION_CONV */
#define PROBE_PING 1
#define PROBE_PONG 2
/*
 * The worker answering you is not the one you left. A host reaps a worker for
 * a client that has gone quiet and keeps serving, so a claim that comes back
 * is answered by a new one -- and every session shares a conversation id and a
 * sealing key, so from the returning client's side the path looks exactly as
 * it did. It carries the claimant's ufrag like any other probe, so it is
 * addressed rather than broadcast, and it is sealed like any other, so only
 * this session's peer can say it.
 */
#define PROBE_FRESH 3
#define PROBE_UFRAG_MAX 40
#define PROBE_TAIL_LEN 22
#define PROBE_HEAD_FIXED 18		/* type(1) nonce(8) seq(8) ulen(1) */
#define PROBE_PLAIN_MAX (PROBE_HEAD_FIXED + PROBE_UFRAG_MAX + PROBE_TAIL_LEN)
#define PROBE_MAX (4 + PROBE_PLAIN_MAX + SEAL_OVERHEAD)

struct path_probe {
	int type;
	uint64_t nonce;
	uint64_t seq;			/* the sender's frame count, from 1 */
	char ufrag[PROBE_UFRAG_MAX + 1];
	int have_tail;
	struct path_ep echo;
	int srtt_ms;
	int loss_ppt;
};

/* Does this datagram open with PROBE_MAGIC? Every KCP datagram opens with the
 * fixed SESSION_CONV instead, so the two are unambiguous. */
int path_probe_is(const uint8_t *data, size_t len);

/* Build one probe into out (>= PROBE_MAX); returns its length, or 0. */
size_t path_probe_build(uint8_t *out, size_t out_len, const uint8_t sig_key[32],
			const struct path_probe *pr);

/* Unseal one probe. Returns 0 and fills pr, or -1 if it is not ours. */
int path_probe_parse(struct path_probe *pr, const uint8_t sig_key[32],
		     const uint8_t *data, size_t len);

/*
 * Both ends must name a path identically without either being "first". Each
 * knows the remote endpoint directly and learns its own reflexive endpoint from
 * the PONG echo, so both hold the same unordered pair:
 *
 *   id(P) = cc_blake2b_keyed(sig_key, min(Ea,Eb) || max(Ea,Eb)), first 8 bytes
 *
 * min/max are plain byte comparisons over the packed 18 bytes, so the value is
 * order-free and no role appears in it. The digest is taken at its natural 32
 * bytes and truncated -- an 8-byte digest is not something every backend can
 * produce.
 *
 * The id labels a path; it never keys one. The table is keyed by (local
 * transport, remote endpoint), which is stable, where the id is taken over the
 * reflexive pair, which is not: an ICE re-nomination or a change of local
 * address moves it. Both ends still derive the same value from the same
 * observations, which is all a tie-break asks of it.
 */
void path_id_calc(uint8_t out[PATH_ID_LEN], const uint8_t sig_key[32],
		  const struct path_ep *a, const struct path_ep *b);

/*
 * One path. `remote` is the send target for the lanlink kinds and keeps the
 * IPv6 zone id that `peer_ep` drops; `agent` is borrowed, never owned, and is
 * the send target for PATH_ICE.
 *
 * `usable` says the local transport can carry a datagram at this moment: an ICE
 * agent that has nominated no pair cannot, and only the owner of the transports
 * can say so. It is a fact about the transport rather than a rank -- an
 * unusable path is no candidate at all, not a poor one.
 *
 * `qualified` latches once a probe has round-tripped: it is the "qualified
 * once" that separates COLD from UNQUALIFIED, and never clears on silence.
 */
struct path {
	int used;
	int usable;
	enum path_kind kind;
	struct sockaddr_in6 remote;
	struct nat_agent *agent;

	struct path_ep peer_ep;
	struct path_ep self_ep;		/* ours, learnt from the PONG echo */
	int have_self_ep;
	struct path_ep in_src;		/* where this path's last inbound
					 * datagram was seen coming from */
	uint8_t id[PATH_ID_LEN];

	uint64_t nonce;			/* the outstanding probe */
	uint64_t sent_ms;
	int outstanding;

	int srtt8;			/* smoothed round trip * 8 (EWMA 1/8) */
	int peer_srtt_ms;		/* the peer's own view, from the tail */
	int peer_loss_ppt;
	uint16_t loss_reg;		/* probe outcomes, newest in bit 0 */
	int loss_n;
	uint64_t last_pong_ms;
	uint64_t created_ms;
	uint64_t next_probe_ms;
	int qualified;

	char label[PATH_LABEL_MAX];	/* the remote endpoint, printable */
};

/*
 * A connection's paths, and the selection state that gives PATH_SWITCH_HOLD its
 * unit. Slot indices are stable across an eviction, so `sel` stays meaningful.
 */
struct path_table {
	struct path p[PATH_TABLE_MAX];
	int sel;			/* the path in use, -1 if none */
	int cand;			/* the challenger, -1 if none */
	int hold;			/* evaluations it has won the margin */
	uint64_t next_eval_ms;
};

void path_table_init(struct path_table *t);
int path_table_count(const struct path_table *t);
int path_index(const struct path_table *t, const struct path *p);

/*
 * Add, never replace. A new endpoint enters as one more candidate and ranking
 * decides whether it carries anything; it never displaces the endpoint in use.
 * Returns the existing path when one already names this endpoint, evicting the
 * worst (oldest DEAD first, never the path in use) when the table is full, or
 * NULL when nothing could be evicted.
 */
struct path *path_table_add(struct path_table *t, enum path_kind kind,
			    const struct sockaddr_in6 *remote,
			    struct nat_agent *agent, uint64_t now);

/*
 * An endpoint the peer advertised (CTLM_CAND) rather than one anything has been
 * seen to arrive from. It is a guess, so it takes a free slot or one a DEAD
 * path is holding and is otherwise declined: a probe that arrived is evidence
 * its source works, where an advertisement is only a claim, and a multi-homed
 * peer naming more endpoints than PATH_TABLE_MAX must not be able to churn the ones
 * that are answering. Returns the path, the existing one when an endpoint is
 * already named, or NULL when there is no room to spare for a guess.
 */
struct path *path_table_offer(struct path_table *t, enum path_kind kind,
			      const struct sockaddr_in6 *remote, uint64_t now);

struct path *path_table_find(struct path_table *t, enum path_kind kind,
			     const struct path_ep *ep);
struct path *path_table_find_ep(struct path_table *t, const struct path_ep *ep);
struct path *path_table_find_port(struct path_table *t, uint16_t port);
struct path *path_table_find_agent(struct path_table *t,
				   struct nat_agent *agent);
struct path *path_table_sel(struct path_table *t);

void path_table_clear(struct path_table *t);
void path_table_drop_kind(struct path_table *t, enum path_kind kind);
/* Drop every measurement and every proof, keeping the endpoints: what a probe
 * proved was proved for one claimant identity, and a re-claim mints a new
 * one. */
void path_table_reset_stats(struct path_table *t);
int path_table_any_qualified(const struct path_table *t);

/* Our own reflexive endpoint on this path, learnt from a PONG echo. Completes
 * the unordered pair the id is taken over. */
void path_set_self_ep(struct path *p, const struct path_ep *ep,
		      const uint8_t sig_key[32]);
/* The remote endpoint, where the transport names it rather than the caller: an
 * ICE agent's nominated pair, which is not known when the path is added. The
 * lanlink kinds are told theirs on the way in. */
void path_set_peer_ep(struct path *p, const struct path_ep *ep,
		      const uint8_t sig_key[32]);
/* Where an inbound datagram on this path was seen coming from. It is what the
 * tail echoes, so the far end learns its own reflexive endpoint for free. */
void path_saw_inbound(struct path *p, const struct path_ep *src);
/* This end's view of the path, into the tail of a probe about to go out. */
void path_fill_tail(const struct path *p, struct path_probe *pr);
/* The far end's view of the path, out of the tail of one that arrived. A peer
 * that omits the tail leaves both views standing: it shares no measurements,
 * which costs accuracy and never correctness. */
void path_apply_tail(struct path *p, const struct path_probe *pr,
		     const uint8_t sig_key[32]);

/* Is a probe due on this path? One is outstanding at a time, so a path whose
 * probe has neither been answered nor expired is not due, however long the
 * cadence says it has been. */
int path_probe_due(const struct path *p, uint64_t now);
void path_probe_sent(struct path *p, uint64_t nonce, uint64_t now);
/* Score an outstanding probe that has passed its loss deadline. */
void path_probe_expire(struct path *p, uint64_t now);
/* A PONG arrived. Returns 1 when it answered the outstanding probe (and the
 * round trip was recorded), 0 when it matched nothing. */
int path_probe_pong(struct path *p, uint64_t nonce, uint64_t now);
/* The peer's own view of this path, from a probe tail. */
void path_peer_view(struct path *p, int srtt_ms, int loss_ppt);

enum path_warmth path_warmth_of(const struct path *p, uint64_t now);
int path_srtt_ms(const struct path *p);
int path_loss_ppt(const struct path *p);

/*
 * Ranking is purely by measurement; class plays no part. Because a probe
 * measures a round trip, both ends observe roughly the same value for the same
 * path and each publishes its own view, so each ranks over the pair of views
 * through a commutative function and both compute the same number.
 *
 *   cost(P)   = max(srtt_local, srtt_peer)
 *               + PATH_LOSS_PENALTY_MS * max(loss_local, loss_peer) / 1000
 *   bucket(P) = ceil(cost(P) / PATH_COST_QUANTUM_MS)
 */
int path_cost_of(int srtt_a, int loss_a, int srtt_b, int loss_b);
int path_cost(const struct path *p);
int path_bucket_of(int cost);
int path_bucket(const struct path *p);

/*
 * The total order, so both ends always agree even before any measurement
 * exists: warmth tier first, then bucket, then the lowest id. At t=0 nothing is
 * qualified and no cost is known, so the order falls through to the id --
 * deterministic, role-free and identical on both ends. Returns < 0 when a ranks
 * ahead of b.
 */
int path_cmp(const struct path *a, const struct path *b, uint64_t now);
int path_best(const struct path_table *t, uint64_t now);

/*
 * Choose the path to carry the session, and return its index (-1 when no path
 * can carry one). Switching is immediate when the incumbent's warmth tier is
 * left behind -- a demotion of the incumbent must never wait, so a dying path
 * cannot hold the session for extra evaluations at exactly the wrong moment --
 * and immediate when the incumbent's transport can no longer send at all.
 * Within one tier a candidate must win by PATH_SWITCH_MARGIN buckets over
 * PATH_SWITCH_HOLD consecutive evaluations, one evaluation per PATH_KEEP_MS,
 * so near-equal paths cannot flap.
 */
int path_select(struct path_table *t, uint64_t now);

#endif
