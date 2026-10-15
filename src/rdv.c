/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "bep44.h"
#include "keys.h"
#include "rdv.h"

_Static_assert(RDV_MAX_MSG + SEAL_OVERHEAD <= BEP44_MAX_VALUE,
	       "a sealed slot message must fit one mutable item");

static const uint8_t rdv_zero[RDV_CID_LEN];

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int rdv_encode(const struct rdv_msg *m, uint8_t *out, size_t max)
{
	size_t o = 0;

	if (m->payload_len > RDV_MAX_PAYLOAD)
		return -1;
	if (max < (size_t)RDV_HDR_LEN + m->payload_len)
		return -1;
	out[o++] = RDV_VERSION;
	out[o++] = m->kind;
	put32(out + o, m->gen);
	o += 4;
	memcpy(out + o, m->from, RDV_CID_LEN);
	o += RDV_CID_LEN;
	memcpy(out + o, m->to, RDV_CID_LEN);
	o += RDV_CID_LEN;
	put32(out + o, m->seq);
	o += 4;
	put32(out + o, m->re);
	o += 4;
	out[o++] = (uint8_t)(m->payload_len >> 8);
	out[o++] = (uint8_t)m->payload_len;
	memcpy(out + o, m->payload, m->payload_len);
	return (int)(o + m->payload_len);
}

int rdv_decode(struct rdv_msg *m, const uint8_t *in, size_t len)
{
	size_t o = 0;

	memset(m, 0, sizeof(*m));
	if (len < 1)
		return -1;
	if (in[0] != RDV_VERSION)
		return RDV_ERR_VERSION;
	if (len < (size_t)RDV_HDR_LEN)
		return -1;
	o = 1;
	m->kind = in[o++];
	if (m->kind < RDV_HOSTINFO || m->kind > RDV_TOMB)
		return -1;
	m->gen = get32(in + o);
	o += 4;
	memcpy(m->from, in + o, RDV_CID_LEN);
	o += RDV_CID_LEN;
	memcpy(m->to, in + o, RDV_CID_LEN);
	o += RDV_CID_LEN;
	m->seq = get32(in + o);
	o += 4;
	m->re = get32(in + o);
	o += 4;
	m->payload_len = (uint16_t)((in[o] << 8) | in[o + 1]);
	o += 2;
	if (m->payload_len > RDV_MAX_PAYLOAD || o + m->payload_len != len)
		return -1;
	memcpy(m->payload, in + o, m->payload_len);
	return 0;
}

int rdv_addressed_to(const uint8_t to[RDV_CID_LEN],
		     const uint8_t cid[RDV_CID_LEN])
{
	if (!memcmp(to, rdv_zero, RDV_CID_LEN))
		return 1;
	return !memcmp(to, cid, RDV_CID_LEN);
}

void rdv_host_init(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		   uint32_t gen, int grant)
{
	memset(h, 0, sizeof(*h));
	memcpy(h->cid, cid, RDV_CID_LEN);
	h->gen = gen;
	h->grant = grant;
	h->info_pending = 1;
}

void rdv_host_set_gen(struct rdv_host *h, uint32_t gen)
{
	if (gen == h->gen)
		return;
	h->gen = gen;
	h->info_pending = 1;
}

void rdv_host_entomb(struct rdv_host *h)
{
	h->gone = 1;
	h->info_pending = 1;
}

struct rdv_claimant *rdv_host_find(struct rdv_host *h,
				   const uint8_t cid[RDV_CID_LEN])
{
	int i;

	for (i = 0; i < RDV_HOST_MAX; i++)
		if (h->c[i].state != RDV_C_FREE &&
		    !memcmp(h->c[i].cid, cid, RDV_CID_LEN))
			return &h->c[i];
	return NULL;
}

static struct rdv_claimant *host_evict(struct rdv_host *h, int state)
{
	int i;

	for (i = 0; i < RDV_HOST_MAX; i++)
		if (h->c[i].state == state)
			return &h->c[i];
	return NULL;
}

/* An answered claimant is never evicted for a newcomer: it owns its slot. */
static struct rdv_claimant *host_admit(struct rdv_host *h,
				       const uint8_t cid[RDV_CID_LEN])
{
	struct rdv_claimant *c = rdv_host_find(h, cid);

	if (c)
		return c;
	c = host_evict(h, RDV_C_FREE);
	if (!c)
		c = host_evict(h, RDV_C_GONE);
	if (!c)
		c = host_evict(h, RDV_C_REFUSED);
	if (!c)
		return NULL;
	memset(c, 0, sizeof(*c));
	memcpy(c->cid, cid, RDV_CID_LEN);
	c->state = RDV_C_HARVESTED;
	return c;
}

/* Whose answer stands in the cell, if anyone's but this one's. */
static int answer_stands(const struct rdv_host *h, int skip)
{
	int i;

	for (i = 0; i < RDV_HOST_MAX; i++)
		if (i != skip && h->c[i].holds)
			return 1;
	return 0;
}

int rdv_host_cell_held(const struct rdv_host *h)
{
	return answer_stands(h, -1);
}

int rdv_host_busy(const struct rdv_host *h)
{
	int i;

	for (i = 0; i < RDV_HOST_MAX; i++)
		if (h->c[i].state == RDV_C_HARVESTED || h->c[i].pending ||
		    h->c[i].holds)
			return 1;
	return 0;
}

void rdv_host_release(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN])
{
	struct rdv_claimant *c = rdv_host_find(h, cid);

	if (c)
		c->holds = 0;
	if (c && c->pending)
		return;
	h->info_pending = 1;
}

int rdv_host_slot(struct rdv_host *h, const struct rdv_msg *m)
{
	struct rdv_claimant *c;

	if (m->kind != RDV_OFFER)
		return 0;
	if (!memcmp(m->from, rdv_zero, RDV_CID_LEN))
		return 0;
	if (!rdv_addressed_to(m->to, h->cid))
		return 0;
	c = host_admit(h, m->from);
	if (!c)
		return 0;
	/* Monotonic: a replayed or reordered offer changes nothing. */
	if (c->have_seq && m->seq <= c->last_seq)
		return 0;
	c->last_seq = m->seq;
	c->have_seq = 1;
	/* Its ask is in the cell, so whatever was answered there is gone. */
	c->holds = 0;
	if (c->state == RDV_C_ANSWERED) {
		/* It asks again, so the answer it holds is of no use to it. */
		c->state = RDV_C_HARVESTED;
		if (h->answered > 0)
			h->answered--;
	}
	if (c->state == RDV_C_GONE || c->state == RDV_C_REFUSED)
		c->state = RDV_C_HARVESTED;
	if (h->grant && h->answered >= h->grant) {
		c->state = RDV_C_REFUSED;
		c->refusal = RDV_REFUSE_FULL;
		c->pending = 1;
		c->answer_re = c->last_seq;
		return 0;
	}
	return 1;
}

void rdv_host_answer(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		     const uint8_t *payload, size_t len)
{
	struct rdv_claimant *c = rdv_host_find(h, cid);

	if (!c || len > RDV_MAX_PAYLOAD)
		return;
	if (c->state != RDV_C_ANSWERED)
		h->answered++;
	c->state = RDV_C_ANSWERED;
	c->refusal = RDV_REFUSE_NONE;
	c->pending = 1;
	c->answer_re = c->last_seq;
	if (payload && len)
		memcpy(c->answer, payload, len);
	c->answer_len = (uint16_t)len;
}

/* Given back: an emission the caller could not send leaves the cell carrying
 * nothing of ours, whatever it was told at the time. */
void rdv_host_unsent(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN])
{
	struct rdv_claimant *c = rdv_host_find(h, cid);

	if (!c || c->state == RDV_C_GONE)
		return;
	c->pending = 1;
	c->holds = 0;
}

void rdv_host_refuse(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN],
		     int reason)
{
	struct rdv_claimant *c = rdv_host_find(h, cid);

	if (!c)
		return;
	if (c->state == RDV_C_ANSWERED && h->answered > 0)
		h->answered--;
	c->state = RDV_C_REFUSED;
	c->refusal = (uint8_t)reason;
	c->pending = 1;
	c->answer_re = c->last_seq;
	c->answer_len = 0;
}

void rdv_host_keep(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN])
{
	struct rdv_claimant *c = rdv_host_find(h, cid);

	if (!c || c->state == RDV_C_GONE)
		return;
	/* Nothing was ever answered to it, so there is no answer to state
	 * again, and an empty one reads as malformed at the other end. */
	if (c->state != RDV_C_REFUSED && !c->answer_len)
		return;
	if (c->state != RDV_C_ANSWERED)
		h->answered++;
	c->state = RDV_C_ANSWERED;
	/* Reading its ask again means the cell has lost the answer to it, since
	 * one standing there would have been read instead. The same answer
	 * stands, so it is stated again, against the ask in hand now. An
	 * answer already owed stays owed: keeping cancels nothing. */
	if (!c->pending)
		c->pending = !c->holds;
	if (c->pending)
		c->answer_re = c->last_seq;
}

void rdv_host_forget(struct rdv_host *h, const uint8_t cid[RDV_CID_LEN])
{
	struct rdv_claimant *c = rdv_host_find(h, cid);

	if (!c)
		return;
	if (c->state == RDV_C_ANSWERED && h->answered > 0)
		h->answered--;
	c->state = RDV_C_GONE;
	c->pending = 0;
	c->holds = 0;
	c->answer_len = 0;
	h->info_pending = 1;
}

static void out_slot(struct rdv_out *o, int seal)
{
	o->seal = (uint8_t)seal;
}

int rdv_host_next(struct rdv_host *h, const uint8_t *info, size_t info_len,
		  struct rdv_out *o)
{
	struct rdv_msg m;
	int i, n;

	memset(o, 0, sizeof(*o));
	memset(&m, 0, sizeof(m));
	if (h->info_pending && (h->gone || !rdv_host_cell_held(h))) {
		if (info_len > RDV_MAX_PAYLOAD)
			return 0;
		m.kind = h->gone ? RDV_TOMB : RDV_HOSTINFO;
		m.gen = h->gen;
		memcpy(m.from, h->cid, RDV_CID_LEN);
		m.seq = ++h->seq;
		if (info && info_len) {
			memcpy(m.payload, info, info_len);
			m.payload_len = (uint16_t)info_len;
		}
		n = rdv_encode(&m, o->msg, sizeof(o->msg));
		if (n < 0)
			return 0;
		o->len = (size_t)n;
		out_slot(o, RDV_SEAL_INFO);
		h->info_pending = 0;
		return 1;
	}
	for (i = 0; i < RDV_HOST_MAX; i++) {
		if (!h->c[i].pending || answer_stands(h, i))
			continue;
		m.kind = h->c[i].state == RDV_C_REFUSED ? RDV_REFUSE :
							  RDV_ANSWER;
		m.gen = h->gen;
		memcpy(m.from, h->cid, RDV_CID_LEN);
		memcpy(m.to, h->c[i].cid, RDV_CID_LEN);
		m.seq = ++h->seq;
		m.re = h->c[i].answer_re;
		if (m.kind == RDV_REFUSE) {
			m.payload[0] = h->c[i].refusal;
			m.payload_len = 1;
		} else {
			memcpy(m.payload, h->c[i].answer, h->c[i].answer_len);
			m.payload_len = h->c[i].answer_len;
		}
		n = rdv_encode(&m, o->msg, sizeof(o->msg));
		if (n < 0)
			return 0;
		o->len = (size_t)n;
		out_slot(o, RDV_SEAL_CLASS);
		h->c[i].pending = 0;
		h->c[i].holds = 1;
		return 1;
	}
	return 0;
}

void rdv_client_init(struct rdv_client *c, const uint8_t cid[RDV_CID_LEN])
{
	memset(c, 0, sizeof(*c));
	memcpy(c->cid, cid, RDV_CID_LEN);
	c->state = RDV_CL_ANNOUNCING;
	c->h_seq = -1;
}

static int client_knew(const struct rdv_client *c, const uint8_t *cid)
{
	int i;

	if (c->have_host && !memcmp(c->host_cid, cid, RDV_CID_LEN))
		return 1;
	for (i = 0; i < c->nprev && i < RDV_PREV_MAX; i++)
		if (!memcmp(c->prev_cid[i], cid, RDV_CID_LEN))
			return 1;
	return 0;
}

/* A copy below the highest sequence seen is a replica that fell behind, and
 * from an instance already dealt with it says nothing new; a restarted host
 * can write below its predecessor, so an instance never met still counts. */
static int client_copy_acts(struct rdv_client *c, const struct rdv_msg *m,
			    int64_t seq)
{
	if (seq >= 0 && seq < c->h_seq && client_knew(c, m->from))
		return 0;
	if (seq > c->h_seq)
		c->h_seq = seq;
	return 1;
}

int rdv_client_host_slot(struct rdv_client *c, const struct rdv_msg *m,
			 int64_t seq)
{
	int moved, fresh;

	if (m->kind != RDV_TOMB && m->kind != RDV_HOSTINFO)
		return 0;
	if (!memcmp(m->from, rdv_zero, RDV_CID_LEN))
		return 0;
	fresh = seq < 0 || seq > c->h_seq;
	if (!client_copy_acts(c, m, seq))
		return -1;
	if (m->kind == RDV_TOMB) {
		/* The host says the session is over, so there is nothing to
		 * come back to and announcing again would never be answered. */
		c->host_gone = 1;
		return 0;
	}
	c->host_gone = 0;
	/* A statement written since we last looked, while we are still
	 * unanswered: the offer we left in the cell is gone, so asking again
	 * is a new question and not a replay of one already read. */
	if (fresh && c->state == RDV_CL_OFFERED)
		c->reask = 1;
	moved = !c->have_host || memcmp(c->host_cid, m->from, RDV_CID_LEN) ||
		m->gen != c->host_gen;
	if (!moved)
		return 0;
	/* The host is new or has moved, so whatever we were told is void and
	 * the slot it would answer in is one it no longer knows about. */
	if (c->have_host && memcmp(c->host_cid, m->from, RDV_CID_LEN)) {
		memcpy(c->prev_cid[c->nprev % RDV_PREV_MAX], c->host_cid,
		       RDV_CID_LEN);
		if (c->nprev < RDV_PREV_MAX)
			c->nprev++;
		/* A new instance numbers its statements from one. */
		c->have_answer_seq = 0;
	}
	memcpy(c->host_cid, m->from, RDV_CID_LEN);
	c->host_gen = m->gen;
	c->have_host = 1;
	c->state = RDV_CL_ANNOUNCING;
	c->answer_len = 0;
	c->offer_seq = 0;
	c->refusal = RDV_REFUSE_NONE;
	return 1;
}

int rdv_client_own_slot(struct rdv_client *c, const struct rdv_msg *m)
{
	if (m->kind != RDV_ANSWER && m->kind != RDV_REFUSE)
		return 0;
	if (!rdv_addressed_to(m->to, c->cid))
		return 0;
	if (memcmp(m->to, c->cid, RDV_CID_LEN))
		return 0;
	if (c->have_host && memcmp(m->from, c->host_cid, RDV_CID_LEN))
		return 0;
	/* The offer standing now, or the one it just superseded: a host that
	 * read the earlier ask answers it, and refusing that answer leaves
	 * both ends asking and answering past each other. Anything older is a
	 * replica serving a dead punch. */
	if (!c->offer_seq)
		return 0;
	if (m->re != c->offer_seq &&
	    !(c->prev_offer_seq && m->re == c->prev_offer_seq))
		return 0;
	if (c->have_answer_seq && m->seq <= c->answer_seq)
		return 0;
	c->answer_seq = m->seq;
	c->have_answer_seq = 1;
	if (m->kind == RDV_REFUSE) {
		c->state = RDV_CL_REFUSED;
		c->refusal = m->payload_len ? m->payload[0] : RDV_REFUSE_NONE;
		c->answer_len = 0;
		return 1;
	}
	c->state = RDV_CL_ANSWERED;
	c->refusal = RDV_REFUSE_NONE;
	memcpy(c->answer, m->payload, m->payload_len);
	c->answer_len = m->payload_len;
	return 1;
}

void rdv_client_set_live(struct rdv_client *c, int live)
{
	c->live = live ? 1 : 0;
	if (!live && c->state == RDV_CL_ANSWERED)
		c->state = RDV_CL_ANNOUNCING;
}

/* An unchanged offer keeps its sequence while it still stands, since the host
 * answers a sequence once; one the cell has lost is asked afresh instead, or
 * the host would read a replay and never answer it. */
static uint32_t offer_seq(struct rdv_client *c, const uint8_t *offer,
			  size_t offer_len)
{
	if (!c->reask && c->offer_seq && c->offer_len == offer_len &&
	    (!offer_len || !memcmp(c->offer, offer, offer_len)))
		return c->offer_seq;
	c->reask = 0;
	if (offer && offer_len)
		memcpy(c->offer, offer, offer_len);
	c->offer_len = (uint16_t)offer_len;
	c->prev_offer_seq = c->offer_seq;
	c->offer_seq = ++c->seq;
	return c->offer_seq;
}

int rdv_client_next(struct rdv_client *c, const uint8_t *offer,
		    size_t offer_len, struct rdv_out *o)
{
	struct rdv_msg m;
	int n;

	memset(o, 0, sizeof(*o));
	memset(&m, 0, sizeof(m));
	if (c->live || c->state == RDV_CL_REFUSED || c->host_gone)
		return 0;
	if (c->state == RDV_CL_ANSWERED)
		return 0;
	/* Replacing the host's own statement with an offer is the announcement:
	 * there is nothing to ring before the host has been read. */
	if (!c->have_host)
		return 0;
	if (offer_len > RDV_MAX_PAYLOAD)
		return 0;
	m.kind = RDV_OFFER;
	m.gen = c->host_gen;
	memcpy(m.from, c->cid, RDV_CID_LEN);
	memcpy(m.to, c->host_cid, RDV_CID_LEN);
	m.seq = offer_seq(c, offer, offer_len);
	if (offer && offer_len) {
		memcpy(m.payload, offer, offer_len);
		m.payload_len = (uint16_t)offer_len;
	}
	n = rdv_encode(&m, o->msg, sizeof(o->msg));
	if (n < 0)
		return 0;
	o->len = (size_t)n;
	out_slot(o, RDV_SEAL_CLASS);
	c->state = RDV_CL_OFFERED;
	return 1;
}
