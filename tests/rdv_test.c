/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "rdv.h"

#define SLOTS 24
#define HIST 4

struct slot {
	uint8_t v[HIST][RDV_MAX_MSG];
	uint8_t cid[RDV_CID_LEN];
	size_t len[HIST];
	char kind;
	int have_cid;
	int n;
};

struct store {
	struct slot s[SLOTS];
	unsigned long writes;
	int n;
};

static struct slot *slot_get(struct store *st, char kind, const uint8_t *cid)
{
	int i;

	for (i = 0; i < st->n; i++) {
		if (st->s[i].kind != kind)
			continue;
		if (!cid && !st->s[i].have_cid)
			return &st->s[i];
		if (cid && st->s[i].have_cid &&
		    !memcmp(st->s[i].cid, cid, RDV_CID_LEN))
			return &st->s[i];
	}
	if (st->n == SLOTS)
		return NULL;
	memset(&st->s[st->n], 0, sizeof(st->s[0]));
	st->s[st->n].kind = kind;
	if (cid) {
		memcpy(st->s[st->n].cid, cid, RDV_CID_LEN);
		st->s[st->n].have_cid = 1;
	}
	return &st->s[st->n++];
}

static void store_write(struct store *st, const struct rdv_out *o)
{
	struct slot *sl;
	int i;

	sl = slot_get(st, o->salt_kind, o->have_salt_cid ? o->salt_cid : NULL);
	if (!sl)
		return;
	for (i = HIST - 1; i > 0; i--) {
		memcpy(sl->v[i], sl->v[i - 1], sizeof(sl->v[0]));
		sl->len[i] = sl->len[i - 1];
	}
	memcpy(sl->v[0], o->msg, o->len);
	sl->len[0] = o->len;
	if (sl->n < HIST)
		sl->n++;
	st->writes++;
}

/* `back` revisions old: how a divergent replica is modelled. */
static int store_read(struct store *st, char kind, const uint8_t *cid,
		      int back, struct rdv_msg *m)
{
	struct slot *sl;

	sl = slot_get(st, kind, cid);
	if (!sl || !sl->n)
		return 0;
	if (back >= sl->n)
		back = sl->n - 1;
	return rdv_decode(m, sl->v[back], sl->len[back]) == 0;
}

static void cid_fill(uint8_t cid[RDV_CID_LEN], int base)
{
	int i;

	for (i = 0; i < RDV_CID_LEN; i++)
		cid[i] = (uint8_t)(base + i);
}

/* One host pass over the store: harvest the bell, read every claimant worth
 * reading, answer with `answer` where an offer asks for one. */
static int host_pass(struct rdv_host *h, struct store *st, int back,
		     const char *answer)
{
	int i, answered = 0;
	struct rdv_msg m;

	if (store_read(st, 'd', NULL, back, &m))
		rdv_host_bell(h, &m);
	for (i = 0; i < RDV_HOST_MAX; i++) {
		if (h->c[i].state == RDV_C_FREE)
			continue;
		if (h->c[i].state != RDV_C_HARVESTED && !h->c[i].knock)
			continue;
		h->c[i].knock = 0;
		if (!store_read(st, 'c', h->c[i].cid, back, &m))
			continue;
		if (rdv_host_slot(h, &m)) {
			rdv_host_answer(h, m.from, (const uint8_t *)answer,
					strlen(answer));
			answered++;
		}
	}
	return answered;
}

static void client_pass(struct rdv_client *c, struct store *st, int back,
			const char *offer, int *msgs)
{
	struct rdv_msg m;
	struct rdv_out o;

	if (store_read(st, 'h', NULL, back, &m))
		rdv_client_host_slot(c, &m);
	if (store_read(st, 'a', c->cid, back, &m))
		rdv_client_own_slot(c, &m);
	if (rdv_client_next(c, (const uint8_t *)offer, strlen(offer), &o)) {
		store_write(st, &o);
		store_write(st, &o);
		(*msgs)++;
	}
}

static void envelope_checks(void)
{
	uint8_t buf[RDV_MAX_MSG], cid[RDV_CID_LEN], other[RDV_CID_LEN];
	struct rdv_msg m, d;
	int n;

	cid_fill(cid, 1);
	cid_fill(other, 100);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_OFFER;
	m.gen = 0x11223344;
	memcpy(m.from, cid, RDV_CID_LEN);
	memcpy(m.to, other, RDV_CID_LEN);
	m.seq = 7;
	memcpy(m.payload, "SDP", 3);
	m.payload_len = 3;
	n = rdv_encode(&m, buf, sizeof(buf));
	assert(n == RDV_HDR_LEN + 3);
	assert(rdv_decode(&d, buf, (size_t)n) == 0);
	assert(d.kind == RDV_OFFER && d.gen == 0x11223344 && d.seq == 7);
	assert(!memcmp(d.from, cid, RDV_CID_LEN));
	assert(!memcmp(d.to, other, RDV_CID_LEN));
	assert(d.payload_len == 3 && !memcmp(d.payload, "SDP", 3));

	buf[0] = RDV_VERSION + 1;
	assert(rdv_decode(&d, buf, (size_t)n) == RDV_ERR_VERSION);
	buf[0] = 0xff;
	assert(rdv_decode(&d, buf, (size_t)n) == RDV_ERR_VERSION);
	buf[0] = RDV_VERSION;
	assert(rdv_decode(&d, buf, (size_t)n - 1) == -1);
	assert(rdv_decode(&d, buf, 0) == -1);
	assert(rdv_decode(&d, buf, 3) == -1);
	buf[1] = 99;
	assert(rdv_decode(&d, buf, (size_t)n) == -1);
	buf[1] = RDV_TOMB;
	assert(rdv_decode(&d, buf, (size_t)n) == 0 && d.kind == RDV_TOMB);

	assert(rdv_addressed_to(m.from, cid));
	assert(!rdv_addressed_to(m.from, other));
	memset(m.to, 0, RDV_CID_LEN);
	assert(rdv_addressed_to(m.to, cid) && rdv_addressed_to(m.to, other));
}

static void liveness_under_a_hostile_store(int nclients, int partition)
{
	uint8_t hcid[RDV_CID_LEN], cid[RDV_CID_LEN];
	int k, round, prev, cut, msgs;
	struct rdv_client cl[4];
	struct rdv_host h;
	struct rdv_out o;
	struct store st;

	msgs = 0;
	memset(&st, 0, sizeof(st));
	cid_fill(hcid, 0xA0);
	rdv_host_init(&h, hcid, 1, 0);
	for (k = 0; k < nclients; k++) {
		cid_fill(cid, 0x10 * (k + 1));
		rdv_client_init(&cl[k], cid);
	}

	for (round = 0; round < 40; round++) {
		cut = partition && round >= 10 && round < 16;

		/* Written twice: a duplicate must be a no-op. */
		while (rdv_host_next(&h, (const uint8_t *)"HOST", 4, &o)) {
			store_write(&st, &o);
			store_write(&st, &o);
			msgs++;
		}

		for (k = 0; k < nclients; k++) {
			if (cut && k == 0)
				continue;
			prev = cl[k].state;
			client_pass(&cl[k], &st, k % HIST, "OFFER", &msgs);
			assert(cl[k].state == RDV_CL_ANNOUNCING ||
			       cl[k].state >= prev ||
			       prev == RDV_CL_ANSWERED);
		}

		host_pass(&h, &st, round % HIST, "ANSWER");
	}

	for (k = 0; k < nclients; k++) {
		assert(cl[k].state == RDV_CL_ANSWERED);
		assert(cl[k].answer_len == 6 &&
		       !memcmp(cl[k].answer, "ANSWER", 6));
	}
	printf("rdv_test: %d claimant(s)%s answered, %d messages, %lu writes\n",
	       nclients, partition ? " across a partition" : "", msgs,
	       st.writes);
}

static void a_spent_grant_refuses_rather_than_waits(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], b[RDV_CID_LEN];
	struct rdv_client ca, cb;
	int round, msgs = 0;
	struct rdv_host h;
	struct rdv_out o;
	struct store st;

	memset(&st, 0, sizeof(st));
	cid_fill(hcid, 0xB0);
	cid_fill(a, 0x30);
	cid_fill(b, 0x40);
	rdv_host_init(&h, hcid, 1, 1);
	rdv_client_init(&ca, a);
	rdv_client_init(&cb, b);

	for (round = 0; round < 30; round++) {
		while (rdv_host_next(&h, (const uint8_t *)"H", 1, &o))
			store_write(&st, &o);
		client_pass(&ca, &st, 0, "OA", &msgs);
		client_pass(&cb, &st, 0, "OB", &msgs);
		host_pass(&h, &st, 0, "AN");
	}

	assert(ca.state == RDV_CL_ANSWERED || ca.state == RDV_CL_REFUSED);
	assert(cb.state == RDV_CL_ANSWERED || cb.state == RDV_CL_REFUSED);
	assert(ca.state != cb.state);
	if (ca.state == RDV_CL_REFUSED)
		assert(ca.refusal == RDV_REFUSE_FULL);
	else
		assert(cb.refusal == RDV_REFUSE_FULL);
}

/* The grant is the session's to judge: an unlimited host still refuses the
 * claimant it is told to, and says so in that claimant's slot. */
static void a_refusal_the_host_decides(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_client ca;
	int round, msgs = 0;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;
	struct store st;

	memset(&st, 0, sizeof(st));
	cid_fill(hcid, 0xC0);
	cid_fill(a, 0x50);
	rdv_host_init(&h, hcid, 1, 0);
	rdv_client_init(&ca, a);

	for (round = 0; round < 6; round++) {
		while (rdv_host_next(&h, NULL, 0, &o))
			store_write(&st, &o);
		client_pass(&ca, &st, 0, "OA", &msgs);
		if (store_read(&st, 'd', NULL, 0, &m))
			rdv_host_bell(&h, &m);
		if (store_read(&st, 'c', a, 0, &m) && rdv_host_slot(&h, &m))
			rdv_host_refuse(&h, a, RDV_REFUSE_FULL);
	}
	assert(ca.state == RDV_CL_REFUSED && ca.refusal == RDV_REFUSE_FULL);
	assert(rdv_client_next(&ca, (const uint8_t *)"OA", 2, &o) == 0);
}

static void each_claimant_gets_its_own_answer(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], b[RDV_CID_LEN];
	struct rdv_client ca, cb;
	int round, msgs = 0;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;
	struct store st;

	memset(&st, 0, sizeof(st));
	cid_fill(hcid, 0xD0);
	cid_fill(a, 0x60);
	cid_fill(b, 0x70);
	rdv_host_init(&h, hcid, 1, 0);
	rdv_client_init(&ca, a);
	rdv_client_init(&cb, b);

	for (round = 0; round < 12; round++) {
		while (rdv_host_next(&h, NULL, 0, &o))
			store_write(&st, &o);
		client_pass(&ca, &st, 0, "OA", &msgs);
		client_pass(&cb, &st, 0, "OB", &msgs);
		if (store_read(&st, 'd', NULL, 0, &m))
			rdv_host_bell(&h, &m);
		if (store_read(&st, 'c', a, 0, &m) && rdv_host_slot(&h, &m))
			rdv_host_answer(&h, a, (const uint8_t *)"AN-A", 4);
		if (store_read(&st, 'c', b, 0, &m) && rdv_host_slot(&h, &m))
			rdv_host_answer(&h, b, (const uint8_t *)"AN-B", 4);
	}
	assert(ca.state == RDV_CL_ANSWERED && cb.state == RDV_CL_ANSWERED);
	assert(ca.answer_len == 4 && !memcmp(ca.answer, "AN-A", 4));
	assert(cb.answer_len == 4 && !memcmp(cb.answer, "AN-B", 4));
}

static void an_unchanged_offer_is_answered_once(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_client ca;
	int answers = 0, i;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;

	cid_fill(hcid, 0xE0);
	cid_fill(a, 0x80);
	rdv_host_init(&h, hcid, 1, 0);
	rdv_client_init(&ca, a);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_HOSTINFO;
	m.gen = 1;
	memcpy(m.from, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_client_host_slot(&ca, &m) == 1);

	/* Bell, offer, bell, offer: the same offer under the same sequence. */
	for (i = 0; i < 6; i++) {
		assert(rdv_client_next(&ca, (const uint8_t *)"OA", 2, &o) == 1);
		assert(rdv_decode(&m, o.msg, o.len) == 0);
		if (m.kind == RDV_BELL) {
			rdv_host_bell(&h, &m);
			continue;
		}
		assert(m.kind == RDV_OFFER);
		if (rdv_host_slot(&h, &m)) {
			rdv_host_answer(&h, a, (const uint8_t *)"AN", 2);
			answers++;
		}
	}
	assert(answers == 1);

	/* A changed offer is a claimant asking again. */
	rdv_client_set_live(&ca, 0);
	for (i = 0; i < 2; i++) {
		assert(rdv_client_next(&ca, (const uint8_t *)"OB", 2, &o) == 1);
		assert(rdv_decode(&m, o.msg, o.len) == 0);
		if (m.kind == RDV_OFFER && rdv_host_slot(&h, &m))
			answers++;
	}
	assert(answers == 2);
}

static void a_gone_claimant_s_replay_is_ignored(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_claimant *c;
	struct rdv_host h;
	struct rdv_msg m;

	cid_fill(hcid, 0xF0);
	cid_fill(a, 0x90);
	rdv_host_init(&h, hcid, 1, 0);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_OFFER;
	memcpy(m.from, a, RDV_CID_LEN);
	memcpy(m.to, hcid, RDV_CID_LEN);
	m.seq = 3;
	assert(rdv_host_slot(&h, &m) == 1);
	rdv_host_answer(&h, a, (const uint8_t *)"AN", 2);
	assert(h.answered == 1);

	rdv_host_forget(&h, a);
	c = rdv_host_find(&h, a);
	assert(c && c->state == RDV_C_GONE && h.answered == 0);
	assert(rdv_host_slot(&h, &m) == 0);
	assert(c->state == RDV_C_GONE);

	m.kind = RDV_BELL;
	rdv_host_bell(&h, &m);
	assert(c->knock);

	m.kind = RDV_OFFER;
	m.seq = 4;
	assert(rdv_host_slot(&h, &m) == 1);
	assert(c->state == RDV_C_HARVESTED);
}

static void a_moved_host_is_re_announced_to(void)
{
	uint8_t h1[RDV_CID_LEN], h2[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_client c;
	struct rdv_msg m;
	struct rdv_out o;

	cid_fill(h1, 0x50);
	cid_fill(h2, 0x60);
	cid_fill(a, 0x70);
	rdv_client_init(&c, a);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_HOSTINFO;
	m.gen = 1;
	memcpy(m.from, h1, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_client_host_slot(&c, &m) == 1);
	assert(rdv_client_host_slot(&c, &m) == 0);

	c.state = RDV_CL_ANSWERED;
	rdv_client_set_live(&c, 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 0);

	m.gen = 2;
	m.seq = 2;
	assert(rdv_client_host_slot(&c, &m) == 1);
	assert(c.state == RDV_CL_ANNOUNCING);

	c.state = RDV_CL_ANSWERED;
	memcpy(m.from, h2, RDV_CID_LEN);
	m.seq = 3;
	assert(rdv_client_host_slot(&c, &m) == 1);
	assert(c.state == RDV_CL_ANNOUNCING);

	c.state = RDV_CL_ANSWERED;
	rdv_client_set_live(&c, 0);
	assert(c.state == RDV_CL_ANNOUNCING);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);

	/* A tombstone stops it: there is nothing left to be answered by. */
	m.kind = RDV_TOMB;
	m.seq = 4;
	rdv_client_host_slot(&c, &m);
	assert(c.host_gone);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 0);
}

static void stale_and_unaddressed_messages_are_no_ops(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], b[RDV_CID_LEN];
	struct rdv_client c;
	struct rdv_host h;
	struct rdv_msg m;
	int i;

	cid_fill(hcid, 0x80);
	cid_fill(a, 0x90);
	cid_fill(b, 0xa0);
	rdv_client_init(&c, a);
	rdv_host_init(&h, hcid, 1, 0);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_HOSTINFO;
	m.gen = 1;
	memcpy(m.from, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_client_host_slot(&c, &m) == 1);

	m.kind = RDV_ANSWER;
	memcpy(m.to, b, RDV_CID_LEN);
	m.seq = 5;
	assert(rdv_client_own_slot(&c, &m) == 0);
	assert(c.state == RDV_CL_ANNOUNCING);

	memcpy(m.to, a, RDV_CID_LEN);
	assert(rdv_client_own_slot(&c, &m) == 1);
	assert(c.state == RDV_CL_ANSWERED);

	assert(rdv_client_own_slot(&c, &m) == 0);
	m.seq = 4;
	assert(rdv_client_own_slot(&c, &m) == 0);
	assert(c.state == RDV_CL_ANSWERED);

	m.seq = 9;
	memcpy(m.from, b, RDV_CID_LEN);
	assert(rdv_client_own_slot(&c, &m) == 0);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_OFFER;
	memcpy(m.from, a, RDV_CID_LEN);
	memcpy(m.to, hcid, RDV_CID_LEN);
	m.seq = 3;
	assert(rdv_host_slot(&h, &m) == 1);
	assert(rdv_host_slot(&h, &m) == 0);
	m.seq = 2;
	assert(rdv_host_slot(&h, &m) == 0);
	m.seq = 4;
	assert(rdv_host_slot(&h, &m) == 1);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_BELL;
	rdv_host_bell(&h, &m);
	memcpy(m.from, b, RDV_CID_LEN);
	memcpy(m.to, a, RDV_CID_LEN);
	rdv_host_bell(&h, &m);
	for (i = 0; i < RDV_HOST_MAX; i++)
		assert(h.c[i].state == RDV_C_FREE ||
		       !memcmp(h.c[i].cid, a, RDV_CID_LEN));
}

int main(void)
{
	envelope_checks();
	stale_and_unaddressed_messages_are_no_ops();
	a_moved_host_is_re_announced_to();
	a_spent_grant_refuses_rather_than_waits();
	a_refusal_the_host_decides();
	each_claimant_gets_its_own_answer();
	an_unchanged_offer_is_answered_once();
	a_gone_claimant_s_replay_is_ignored();
	liveness_under_a_hostile_store(1, 0);
	liveness_under_a_hostile_store(3, 0);
	liveness_under_a_hostile_store(4, 0);
	liveness_under_a_hostile_store(3, 1);
	printf("rdv: envelope, addressing, liveness and refusal cases pass\n");
	return 0;
}
