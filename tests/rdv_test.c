/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "rdv.h"

#define SLOTS 12
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

static void envelope_checks(void)
{
	uint8_t buf[RDV_MAX_MSG], cid[RDV_CID_LEN], other[RDV_CID_LEN];
	struct rdv_msg m, d;
	int n, i;

	for (i = 0; i < RDV_CID_LEN; i++) {
		cid[i] = (uint8_t)(i + 1);
		other[i] = (uint8_t)(i + 100);
	}

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

	assert(rdv_addressed_to(m.from, cid));
	assert(!rdv_addressed_to(m.from, other));
	memset(m.to, 0, RDV_CID_LEN);
	assert(rdv_addressed_to(m.to, cid) && rdv_addressed_to(m.to, other));
}

static void liveness_under_a_hostile_store(int nclients, int partition)
{
	uint8_t hcid[RDV_CID_LEN], cid[RDV_CID_LEN];
	int i, k, round, prev, cut, back, msgs;
	struct rdv_client cl[4];
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;
	struct store st;

	msgs = 0;
	memset(&st, 0, sizeof(st));
	for (i = 0; i < RDV_CID_LEN; i++)
		hcid[i] = (uint8_t)(0xA0 + i);
	rdv_host_init(&h, hcid, 1, 0);
	for (k = 0; k < nclients; k++) {
		for (i = 0; i < RDV_CID_LEN; i++)
			cid[i] = (uint8_t)(0x10 * (k + 1) + i);
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
			back = k % HIST;
			if (cut && k == 0)
				continue;
			prev = cl[k].state;
			if (store_read(&st, 'h', NULL, back, &m))
				rdv_client_host_slot(&cl[k], &m);
			if (store_read(&st, 'c', cl[k].cid, back, &m))
				rdv_client_own_slot(&cl[k], &m);
			assert(cl[k].state == RDV_CL_ANNOUNCING ||
			       cl[k].state >= prev ||
			       prev == RDV_CL_ANSWERED);
			if (rdv_client_next(&cl[k], (const uint8_t *)"OFFER",
					    5, &o)) {
				store_write(&st, &o);
				store_write(&st, &o);
				msgs++;
			}
		}

		if (store_read(&st, 'd', NULL, round % HIST, &m))
			rdv_host_bell(&h, &m);
		for (i = 0; i < RDV_HOST_MAX; i++) {
			if (h.c[i].state == RDV_C_FREE)
				continue;
			if (!store_read(&st, 'c', h.c[i].cid, round % HIST, &m))
				continue;
			if (rdv_host_slot(&h, &m))
				rdv_host_answer(&h, m.from,
						(const uint8_t *)"ANSWER", 6);
		}
	}

	for (k = 0; k < nclients; k++)
		assert(cl[k].state == RDV_CL_ANSWERED ||
		       cl[k].state == RDV_CL_REFUSED);
	printf("rdv_test: %d claimant(s)%s answered, %d messages, %lu writes\n",
	       nclients, partition ? " across a partition" : "", msgs,
	       st.writes);
}

static void a_spent_grant_refuses_rather_than_waits(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], b[RDV_CID_LEN];
	struct rdv_client ca, cb;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;
	struct store st;
	int i, round;

	memset(&st, 0, sizeof(st));
	for (i = 0; i < RDV_CID_LEN; i++) {
		hcid[i] = (uint8_t)(0xB0 + i);
		a[i] = (uint8_t)(0x30 + i);
		b[i] = (uint8_t)(0x40 + i);
	}
	rdv_host_init(&h, hcid, 1, 1);
	rdv_client_init(&ca, a);
	rdv_client_init(&cb, b);

	for (round = 0; round < 30; round++) {
		while (rdv_host_next(&h, (const uint8_t *)"H", 1, &o))
			store_write(&st, &o);
		if (store_read(&st, 'h', NULL, 0, &m)) {
			rdv_client_host_slot(&ca, &m);
			rdv_client_host_slot(&cb, &m);
		}
		if (store_read(&st, 'c', ca.cid, 0, &m))
			rdv_client_own_slot(&ca, &m);
		if (store_read(&st, 'c', cb.cid, 0, &m))
			rdv_client_own_slot(&cb, &m);
		if (rdv_client_next(&ca, (const uint8_t *)"OA", 2, &o))
			store_write(&st, &o);
		if (rdv_client_next(&cb, (const uint8_t *)"OB", 2, &o))
			store_write(&st, &o);
		if (store_read(&st, 'd', NULL, 0, &m))
			rdv_host_bell(&h, &m);
		for (i = 0; i < RDV_HOST_MAX; i++) {
			if (h.c[i].state == RDV_C_FREE)
				continue;
			if (!store_read(&st, 'c', h.c[i].cid, 0, &m))
				continue;
			if (rdv_host_slot(&h, &m))
				rdv_host_answer(&h, m.from,
						(const uint8_t *)"AN", 2);
		}
	}

	assert(ca.state == RDV_CL_ANSWERED || ca.state == RDV_CL_REFUSED);
	assert(cb.state == RDV_CL_ANSWERED || cb.state == RDV_CL_REFUSED);
	assert(ca.state != cb.state);
	if (ca.state == RDV_CL_REFUSED)
		assert(ca.refusal == RDV_REFUSE_FULL);
	else
		assert(cb.refusal == RDV_REFUSE_FULL);
}

static void a_moved_host_is_re_announced_to(void)
{
	uint8_t h1[RDV_CID_LEN], h2[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_client c;
	struct rdv_msg m;
	struct rdv_out o;
	int i;

	for (i = 0; i < RDV_CID_LEN; i++) {
		h1[i] = (uint8_t)(0x50 + i);
		h2[i] = (uint8_t)(0x60 + i);
		a[i] = (uint8_t)(0x70 + i);
	}
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
}

static void stale_and_unaddressed_messages_are_no_ops(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], b[RDV_CID_LEN];
	struct rdv_client c;
	struct rdv_host h;
	struct rdv_msg m;
	int i;

	for (i = 0; i < RDV_CID_LEN; i++) {
		hcid[i] = (uint8_t)(0x80 + i);
		a[i] = (uint8_t)(0x90 + i);
		b[i] = (uint8_t)(0xa0 + i);
	}
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
	liveness_under_a_hostile_store(1, 0);
	liveness_under_a_hostile_store(3, 0);
	liveness_under_a_hostile_store(4, 0);
	liveness_under_a_hostile_store(3, 1);
	printf("rdv: envelope, addressing, liveness and refusal cases pass\n");
	return 0;
}
