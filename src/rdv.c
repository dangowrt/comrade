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

void rdv_host_bell(struct rdv_host *h, const struct rdv_msg *m)
{
	struct rdv_claimant *c;

	if (m->kind != RDV_BELL)
		return;
	if (!memcmp(m->from, rdv_zero, RDV_CID_LEN))
		return;
	if (!rdv_addressed_to(m->to, h->cid))
		return;
	c = rdv_host_find(h, m->from);
	if (c)
		c->knock = 1;
	else
		host_admit(h, m->from);
}

int rdv_host_slot(struct rdv_host *h, const struct rdv_msg *m)
{
	struct rdv_claimant *c;

	if (m->kind != RDV_OFFER)
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
	if (payload && len)
		memcpy(c->answer, payload, len);
	c->answer_len = (uint16_t)len;
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
	c->answer_len = 0;
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
	c->knock = 0;
	c->answer_len = 0;
}

static void out_slot(struct rdv_out *o, char kind, const uint8_t *cid)
{
	o->salt_kind = kind;
	o->have_salt_cid = cid ? 1 : 0;
	if (cid)
		memcpy(o->salt_cid, cid, RDV_CID_LEN);
}

int rdv_host_next(struct rdv_host *h, const uint8_t *info, size_t info_len,
		  struct rdv_out *o)
{
	struct rdv_msg m;
	int i, n;

	memset(o, 0, sizeof(*o));
	memset(&m, 0, sizeof(m));
	if (h->info_pending) {
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
		out_slot(o, 'h', NULL);
		h->info_pending = 0;
		return 1;
	}
	for (i = 0; i < RDV_HOST_MAX; i++) {
		if (!h->c[i].pending)
			continue;
		m.kind = h->c[i].state == RDV_C_REFUSED ? RDV_REFUSE :
							  RDV_ANSWER;
		m.gen = h->gen;
		memcpy(m.from, h->cid, RDV_CID_LEN);
		memcpy(m.to, h->c[i].cid, RDV_CID_LEN);
		m.seq = ++h->seq;
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
		out_slot(o, 'a', h->c[i].cid);
		h->c[i].pending = 0;
		return 1;
	}
	return 0;
}

void rdv_client_init(struct rdv_client *c, const uint8_t cid[RDV_CID_LEN])
{
	memset(c, 0, sizeof(*c));
	memcpy(c->cid, cid, RDV_CID_LEN);
	c->state = RDV_CL_ANNOUNCING;
}

int rdv_client_host_slot(struct rdv_client *c, const struct rdv_msg *m)
{
	int moved;

	if (m->kind == RDV_TOMB) {
		/* The host says the session is over, so there is nothing to
		 * come back to and announcing again would never be answered. */
		if (memcmp(m->from, rdv_zero, RDV_CID_LEN))
			c->host_gone = 1;
		return 0;
	}
	if (m->kind != RDV_HOSTINFO)
		return 0;
	if (!memcmp(m->from, rdv_zero, RDV_CID_LEN))
		return 0;
	moved = !c->have_host || memcmp(c->host_cid, m->from, RDV_CID_LEN) ||
		m->gen != c->host_gen;
	if (!moved)
		return 0;
	/* The host is new or has moved, so whatever we were told is void and
	 * the slot it would answer in is one it no longer knows about. */
	memcpy(c->host_cid, m->from, RDV_CID_LEN);
	c->host_gen = m->gen;
	c->have_host = 1;
	c->state = RDV_CL_ANNOUNCING;
	c->have_answer_seq = 0;
	c->answer_len = 0;
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

/* An unchanged offer keeps its sequence: the host answers a sequence once, and
 * a repeat is a refresh of what is stored, not a claimant asking again. */
static uint32_t offer_seq(struct rdv_client *c, const uint8_t *offer,
			  size_t offer_len)
{
	if (c->offer_seq && c->offer_len == offer_len &&
	    (!offer_len || !memcmp(c->offer, offer, offer_len)))
		return c->offer_seq;
	if (offer && offer_len)
		memcpy(c->offer, offer, offer_len);
	c->offer_len = (uint16_t)offer_len;
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
	/*
	 * The doorbell is last-writer-wins, so a bell rung once can be
	 * overwritten before the host ever reads it. Keep ringing until
	 * answered, alternating with the offer so one write goes out a round.
	 */
	c->turn = c->turn ? 0 : 1;
	if (!c->have_host || c->turn) {
		m.kind = RDV_BELL;
		memcpy(m.from, c->cid, RDV_CID_LEN);
		if (c->have_host)
			memcpy(m.to, c->host_cid, RDV_CID_LEN);
		m.seq = ++c->seq;
		n = rdv_encode(&m, o->msg, sizeof(o->msg));
		if (n < 0)
			return 0;
		o->len = (size_t)n;
		out_slot(o, 'd', NULL);
		return 1;
	}
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
	out_slot(o, 'c', c->cid);
	c->state = RDV_CL_OFFERED;
	return 1;
}
