/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_RDV_H
#define COMRADE_RDV_H

#include <stddef.h>
#include <stdint.h>

#define RDV_VERSION 1
#define RDV_CID_LEN 8
#define RDV_MAX_PAYLOAD 900
#define RDV_HDR_LEN (1 + 1 + 4 + RDV_CID_LEN + RDV_CID_LEN + 4 + 2)
#define RDV_MAX_MSG (RDV_HDR_LEN + RDV_MAX_PAYLOAD)
#define RDV_ERR_VERSION (-2)
#define RDV_HOST_MAX 16

enum rdv_kind {
	RDV_HOSTINFO = 1,
	RDV_BELL,
	RDV_OFFER,
	RDV_ANSWER,
	RDV_REFUSE,
	RDV_TOMB			/* host slot: the session is over */
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
	uint8_t payload[RDV_MAX_PAYLOAD];
	uint16_t payload_len;
};

int rdv_encode(const struct rdv_msg *m, uint8_t *out, size_t max);
int rdv_decode(struct rdv_msg *m, const uint8_t *in, size_t len);
int rdv_addressed_to(const uint8_t to[RDV_CID_LEN],
		     const uint8_t cid[RDV_CID_LEN]);

/* salt_kind/salt_cid name the slot, matching keys_slot_salt(). */
struct rdv_out {
	uint8_t msg[RDV_MAX_MSG];
	size_t len;
	char salt_kind;
	uint8_t salt_cid[RDV_CID_LEN];
	int have_salt_cid;
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
	uint8_t state;
	uint8_t have_seq;
	uint8_t pending;
	uint8_t refusal;
	uint8_t grade;			/* the credential class its slot opened under */
	uint8_t knock;			/* rang again: its slot is worth a read */
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
	uint8_t gone;
};

void rdv_host_init(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		   uint32_t gen, int grant);
void rdv_host_set_gen(struct rdv_host *h, uint32_t gen);
void rdv_host_entomb(struct rdv_host *h);
void rdv_host_bell(struct rdv_host *h, const struct rdv_msg *m);
int rdv_host_slot(struct rdv_host *h, const struct rdv_msg *m);
struct rdv_claimant *rdv_host_find(struct rdv_host *h,
				   const uint8_t cid[RDV_CID_LEN]);
void rdv_host_answer(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		     const uint8_t *payload, size_t len);
void rdv_host_refuse(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		     int reason);
void rdv_host_forget(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN]);
int rdv_host_next(struct rdv_host *h, const uint8_t *info, size_t info_len,
		  struct rdv_out *o);

enum rdv_clstate {
	RDV_CL_ANNOUNCING = 0,
	RDV_CL_OFFERED,
	RDV_CL_ANSWERED,
	RDV_CL_REFUSED
};

struct rdv_client {
	uint8_t cid[RDV_CID_LEN];
	uint8_t host_cid[RDV_CID_LEN];
	uint32_t host_gen;
	uint32_t seq;
	uint32_t offer_seq;
	uint32_t answer_seq;
	uint8_t state;
	uint8_t have_host;
	uint8_t have_answer_seq;
	uint8_t live;
	uint8_t turn;			/* alternates bell and offer */
	uint8_t refusal;
	uint8_t host_gone;		/* the host said so, in its own slot */
	uint8_t offer[RDV_MAX_PAYLOAD];
	uint16_t offer_len;
	uint8_t answer[RDV_MAX_PAYLOAD];
	uint16_t answer_len;
};

void rdv_client_init(struct rdv_client *c, const uint8_t cid[RDV_CID_LEN]);
int rdv_client_host_slot(struct rdv_client *c, const struct rdv_msg *m);
int rdv_client_own_slot(struct rdv_client *c, const struct rdv_msg *m);
void rdv_client_set_live(struct rdv_client *c, int live);
int rdv_client_next(struct rdv_client *c, const uint8_t *offer,
		    size_t offer_len, struct rdv_out *o);

#endif
