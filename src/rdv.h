/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_RDV_H
#define COMRADE_RDV_H

#include <stddef.h>
#include <stdint.h>

#define RDV_VERSION 3
#define RDV_CID_LEN 8
/* The cell holds two sealed statements and the bencoded frame around them, so
 * the two places share BEP 44's one-kilobyte value (PROTOCOL.md 4). */
#define RDV_MAX_PAYLOAD 760
#define RDV_HOST_PAYLOAD 64
#define RDV_CELL_OVERHEAD 20
#define RDV_HDR_LEN (1 + 1 + 4 + RDV_CID_LEN + RDV_CID_LEN + 4 + 4 + 2)
#define RDV_MAX_MSG (RDV_HDR_LEN + RDV_MAX_PAYLOAD)
#define RDV_ERR_VERSION (-2)
#define RDV_HOST_MAX 16

enum rdv_kind {
	RDV_HOSTINFO = 1,
	RDV_OFFER,
	RDV_ANSWER,
	RDV_REFUSE,
	RDV_TOMB			/* the session is over */
};

enum rdv_refusal {
	RDV_REFUSE_NONE = 0,
	RDV_REFUSE_FULL,
	RDV_REFUSE_CLASH
};

struct rdv_msg {
	uint8_t kind;
	uint32_t gen;
	uint8_t from[RDV_CID_LEN];
	uint8_t to[RDV_CID_LEN];	/* all-zero addresses whoever reads */
	uint32_t seq;
	uint32_t re;			/* the offer this answers, 0 for none */
	uint8_t payload[RDV_MAX_PAYLOAD];
	uint16_t payload_len;
};

int rdv_encode(const struct rdv_msg *m, uint8_t *out, size_t max);
int rdv_decode(struct rdv_msg *m, const uint8_t *in, size_t len);
int rdv_addressed_to(const uint8_t to[RDV_CID_LEN],
		     const uint8_t cid[RDV_CID_LEN]);

/* Which key the statement is sealed under: the host's own under the session
 * key, which either class derives, a claimant's under its class key. */
enum rdv_seal {
	RDV_SEAL_INFO = 0,
	RDV_SEAL_CLASS
};

struct rdv_out {
	uint8_t msg[RDV_MAX_MSG];
	size_t len;
	uint8_t seal;
};

enum rdv_cstate {
	RDV_C_FREE = 0,
	RDV_C_HARVESTED,
	RDV_C_ANSWERED,
	RDV_C_REFUSED,
	RDV_C_GONE			/* served and gone; its sequence is kept */
};

struct rdv_claimant {
	uint8_t cid[RDV_CID_LEN];
	uint32_t last_seq;
	uint32_t answer_re;		/* the offer the pending answer is to */
	uint8_t state;
	uint8_t have_seq;
	uint8_t pending;
	uint8_t holds;			/* the cell carries the answer to it */
	uint8_t wide_ask;		/* its ask came by the convergent route */
	uint8_t refusal;
	uint8_t grade;			/* the credential class it opened under */
	uint8_t answer[RDV_MAX_PAYLOAD];
	uint16_t answer_len;
};

struct rdv_host {
	uint8_t cid[RDV_CID_LEN];
	uint32_t gen;
	uint32_t seq;
	int grant;			/* 0 is unlimited */
	int answered;
	struct rdv_claimant c[RDV_HOST_MAX];
	uint8_t info_pending;
	uint8_t turn_spent;		/* handed back, and nobody has taken it */
	uint8_t gone;
};

void rdv_host_init(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		   uint32_t gen, int grant);
void rdv_host_set_gen(struct rdv_host *h, uint32_t gen);
void rdv_host_entomb(struct rdv_host *h);
int rdv_host_slot(struct rdv_host *h, const struct rdv_msg *m);
/* Is a claimant engaged? */
int rdv_host_busy(const struct rdv_host *h);
/* May the host's next statement clear the turn? Only once, and only because
 * the turn was handed back and nobody has asked since: a statement written for
 * any other reason keeps whatever stands there. */
int rdv_host_turn_spent(const struct rdv_host *h);
void rdv_host_turn_kept(struct rdv_host *h);
/* The cell is the host's again: the claimant has the answer, or will ask for
 * another. Called once the claimant has been heard from, or its punch ends, so
 * the next claimant can take its turn without waiting on a clock. */
void rdv_host_release(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN]);
struct rdv_claimant *rdv_host_find(struct rdv_host *h,
				   const uint8_t cid[RDV_CID_LEN]);
void rdv_host_answer(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		     const uint8_t *payload, size_t len);
void rdv_host_refuse(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		     int reason);

/* Hand back an emission that never went out, so it is owed again. */
void rdv_host_unsent(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN]);
void rdv_host_keep(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN]);
void rdv_host_forget(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN]);
int rdv_host_next(struct rdv_host *h, const uint8_t *info, size_t info_len,
		  struct rdv_out *o);

enum rdv_clstate {
	RDV_CL_ANNOUNCING = 0,
	RDV_CL_OFFERED,
	RDV_CL_ANSWERED,
	RDV_CL_REFUSED
};

#define RDV_PREV_MAX 4

struct rdv_client {
	uint8_t cid[RDV_CID_LEN];
	uint8_t host_cid[RDV_CID_LEN];
	uint8_t prev_cid[RDV_PREV_MAX][RDV_CID_LEN];	/* host instances before */
	int64_t h_seq;			/* the cell's highest store sequence */
	uint32_t host_gen;
	uint32_t seq;
	uint32_t offer_seq;
	uint32_t prev_offer_seq;	/* the one it supersedes */
	uint32_t answer_seq;
	uint8_t state;
	uint8_t have_host;
	uint8_t have_answer_seq;
	uint8_t live;
	/* The offer left in the cell is gone, so the next one asks afresh
	 * rather than repeating a sequence the host has already seen. */
	uint8_t reask;
	uint8_t refusal;
	uint8_t host_gone;		/* the host said so, in its own slot */
	uint8_t nprev;
	uint8_t offer[RDV_MAX_PAYLOAD];
	uint16_t offer_len;
	uint8_t answer[RDV_MAX_PAYLOAD];
	uint16_t answer_len;
};

void rdv_client_init(struct rdv_client *c, const uint8_t cid[RDV_CID_LEN]);
/* The next offer carries fresh ICE credentials, so an answer to the one it
 * supersedes names an identity this end no longer presents. */
void rdv_client_ident_changed(struct rdv_client *c);

/* Why a statement in the turn place is not ours to take. The reasons are
 * distinct conditions, and naming the one that fired is the difference
 * between a usable log line and a misleading one. */
enum rdv_take {
	RDV_TAKE_OK = 0,
	RDV_TAKE_NOT_AN_ANSWER,
	RDV_TAKE_ADDRESSED_ELSEWHERE,
	RDV_TAKE_ANOTHER_HOST,
	RDV_TAKE_NOTHING_ASKED,
	RDV_TAKE_ANOTHER_OFFER,
	RDV_TAKE_ALREADY_TAKEN
};

int rdv_client_refusal(const struct rdv_client *c, const struct rdv_msg *m);
const char *rdv_client_refusal_name(int refusal);

/* May a claimant write its ask over what stands in the turn place? `opened`
 * is 0 where the statement could not be opened, as another credential class's
 * cannot be. The place is a doorbell, not a lock: the host keeps the queue. */
int rdv_client_may_replace(const struct rdv_client *c, const struct rdv_msg *m,
			   int opened);

/* `seq` is the store's sequence for the copy read, -1 where it has none. -1
 * back is a copy older than one already acted on, 1 a host new or moved. */
int rdv_client_host_slot(struct rdv_client *c, const struct rdv_msg *m,
			 int64_t seq);
/* Would this statement be taken as our answer? The test rdv_client_own_slot
 * applies, without applying it: what a claimant must not write over. */
int rdv_client_would_take(const struct rdv_client *c, const struct rdv_msg *m);
int rdv_client_own_slot(struct rdv_client *c, const struct rdv_msg *m);

/* Record an answer whose payload does not decode as spent, leaving us asking. */
void rdv_client_answer_unusable(struct rdv_client *c, const struct rdv_msg *m);
/* The cell's turn place is free, whoever emptied it; `seq` as above. */
void rdv_client_ask_gone(struct rdv_client *c, int64_t seq);
void rdv_client_set_live(struct rdv_client *c, int live);
int rdv_client_next(struct rdv_client *c, const uint8_t *offer,
		    size_t offer_len, struct rdv_out *o);

#endif
