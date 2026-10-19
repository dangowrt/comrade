/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "rdv.h"

#define HIST 4

struct place {
	uint8_t v[RDV_MAX_MSG];
	size_t len;
};

/* One token, one cell: the host's own statement and the one turn an exchange
 * takes, and the revisions behind are what a divergent replica still serves. */
struct rev {
	struct place host;
	struct place turn;
	int64_t seq;
};

struct store {
	struct rev r[HIST];
	int64_t writes;
	int n;
};

static int place_get(const struct place *p, struct rdv_msg *m)
{
	if (!p->len)
		return 0;
	return rdv_decode(m, p->v, p->len) == 0;
}

static void place_set(struct place *p, const struct rdv_out *o)
{
	memcpy(p->v, o->msg, o->len);
	p->len = o->len;
}

/* Free, an ask of its own under another number, an answer to someone else, or
 * one to an ask it has moved on from; never a rival's ask, and never an answer
 * it would still take (`c`, the claimant about to write). */
static int turn_is_ours(const struct store *st, const struct rdv_msg *mine,
			const struct rdv_client *c)
{
	struct rdv_msg held;

	if (!st->n || !place_get(&st->r[0].turn, &held))
		return 1;
	if (!memcmp(held.from, mine->from, RDV_CID_LEN))
		return held.seq != mine->seq;
	if (memcmp(held.from, mine->to, RDV_CID_LEN))
		return 0;
	if (!c)
		return 1;
	return !rdv_client_would_take(c, &held);
}

/* `free_turn` is the host handing the turn back, which only it may do. */
static void store_write(struct store *st, const struct rdv_out *o,
			int free_turn, const struct rdv_client *c)
{
	struct rdv_msg mine;
	int host_place, i;
	struct rev next;

	if (rdv_decode(&mine, o->msg, o->len))
		return;
	memset(&next, 0, sizeof(next));
	if (st->n)
		next = st->r[0];
	host_place = mine.kind == RDV_HOSTINFO || mine.kind == RDV_TOMB;
	if (mine.kind == RDV_OFFER && !turn_is_ours(st, &mine, c))
		return;
	if (!host_place) {
		place_set(&next.turn, o);
	} else {
		place_set(&next.host, o);
		if (mine.kind == RDV_TOMB || free_turn)
			next.turn.len = 0;
	}
	next.seq = ++st->writes;
	for (i = HIST - 1; i > 0; i--)
		st->r[i] = st->r[i - 1];
	st->r[0] = next;
	if (st->n < HIST)
		st->n++;
}

/* `back` revisions old: how a divergent replica is modelled. `seq` is the
 * store's sequence for the copy served, as a BEP 44 node reports it. */
static int store_read(const struct store *st, int back, int turn,
		      struct rdv_msg *m, int64_t *seq)
{
	if (!st->n)
		return 0;
	if (back >= st->n)
		back = st->n - 1;
	if (seq)
		*seq = st->r[back].seq;
	return place_get(turn ? &st->r[back].turn : &st->r[back].host, m);
}

static void cid_fill(uint8_t cid[RDV_CID_LEN], int base)
{
	int i;

	for (i = 0; i < RDV_CID_LEN; i++)
		cid[i] = (uint8_t)(base + i);
}

/* One host pass over the cell: whoever holds the turn is read and answered.
 * Handing the cell back is the caller's, on its own release condition. */
static int host_pass(struct rdv_host *h, struct store *st, int back,
		     const char *answer)
{
	struct rdv_msg m;

	if (!store_read(st, back, 1, &m, NULL))
		return 0;
	if (m.kind != RDV_OFFER)
		return 0;
	if (!rdv_host_slot(h, &m))
		return 0;
	rdv_host_answer(h, m.from, (const uint8_t *)answer, strlen(answer));
	return 1;
}

static void client_pass(struct rdv_client *c, struct store *st, int back,
			const char *offer, int *msgs)
{
	struct rdv_msg m;
	struct rdv_out o;
	int64_t seq = -1;

	if (store_read(st, back, 0, &m, &seq))
		rdv_client_host_slot(c, &m, seq);
	if (!store_read(st, back, 1, &m, NULL))
		rdv_client_ask_gone(c, seq);
	else if (memcmp(m.from, c->cid, RDV_CID_LEN) &&
		 !rdv_client_own_slot(c, &m))
		rdv_client_ask_gone(c, seq);
	if (rdv_client_next(c, (const uint8_t *)offer, strlen(offer), &o)) {
		store_write(st, &o, 0, c);
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
	m.re = 6;
	memcpy(m.payload, "SDP", 3);
	m.payload_len = 3;
	n = rdv_encode(&m, buf, sizeof(buf));
	assert(n == RDV_HDR_LEN + 3);
	assert(rdv_decode(&d, buf, (size_t)n) == 0);
	assert(d.kind == RDV_OFFER && d.gen == 0x11223344 && d.seq == 7);
	assert(d.re == 6);
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
	int j, k, round, prev, cut, msgs, rel[4], free_turn;
	uint8_t hcid[RDV_CID_LEN], cid[RDV_CID_LEN];
	struct rdv_client cl[4];
	struct rdv_host h;
	struct rdv_out o;
	struct store st;

	memset(rel, 0, sizeof(rel));
	msgs = 0;
	memset(&st, 0, sizeof(st));
	cid_fill(hcid, 0xA0);
	rdv_host_init(&h, hcid, 1, 0);
	for (k = 0; k < nclients; k++) {
		cid_fill(cid, 0x10 * (k + 1));
		rdv_client_init(&cl[k], cid);
	}

	for (round = 0; round < 200; round++) {
		cut = partition && round >= 10 && round < 16;

		/* One store at a time, as slot_inflight() enforces, so the
		 * resting state is observable between turns. Written twice: a
		 * duplicate must be a no-op. */
		free_turn = !rdv_host_busy(&h);
		if (rdv_host_next(&h, (const uint8_t *)"HOST", 4, &o)) {
			store_write(&st, &o, free_turn, NULL);
			store_write(&st, &o, free_turn, NULL);
			msgs++;
		}

		/* Rotated: clients poll on their own clocks, so no one of them
		 * is permanently first at the cell. */
		for (j = 0; j < nclients; j++) {
			k = (j + round) % nclients;
			if (cut && k == 0)
				continue;
			prev = cl[k].state;
			client_pass(&cl[k], &st, (k + round) % HIST, "OFFER",
				    &msgs);
			assert(cl[k].state == RDV_CL_ANNOUNCING ||
			       cl[k].state >= prev ||
			       prev == RDV_CL_ANSWERED);
		}

		host_pass(&h, &st, round % HIST, "ANSWER");
		/* A punch exists only once the claimant has taken its answer,
		 * so that is the earliest the cell can come back, and once
		 * each: a release every round starves the next statement. */
		for (k = 0; k < nclients; k++) {
			if (!cl[k].answer_len || rel[k])
				continue;
			rdv_host_release(&h, cl[k].cid);
			rel[k] = 1;
		}
	}

	for (k = 0; k < nclients; k++) {
		assert(cl[k].state == RDV_CL_ANSWERED);
		assert(cl[k].answer_len == 6 &&
		       !memcmp(cl[k].answer, "ANSWER", 6));
	}
	printf("rdv_test: %d claimant(s)%s answered, %d messages, %lu writes\n",
	       nclients, partition ? " across a partition" : "", msgs,
	       (unsigned long)st.writes);
}

static void a_spent_grant_refuses_rather_than_waits(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], b[RDV_CID_LEN];
	int round, msgs = 0, rel_a = 0, rel_b = 0;
	struct rdv_client ca, cb;
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

	for (round = 0; round < 60; round++) {
		if (rdv_host_next(&h, (const uint8_t *)"H", 1, &o))
			store_write(&st, &o, !rdv_host_busy(&h), NULL);
		client_pass(&ca, &st, 0, "OA", &msgs);
		client_pass(&cb, &st, 0, "OB", &msgs);
		host_pass(&h, &st, 0, "AN");
		/* Once each, on the transition: releasing every round keeps
		 * info_pending set and starves the statement behind it. */
		if (!rel_a && (ca.answer_len || ca.state == RDV_CL_REFUSED)) {
			rdv_host_release(&h, a);
			rel_a = 1;
		}
		if (!rel_b && (cb.answer_len || cb.state == RDV_CL_REFUSED)) {
			rdv_host_release(&h, b);
			rel_b = 1;
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

	for (round = 0; round < 30; round++) {
		if (rdv_host_next(&h, NULL, 0, &o))
			store_write(&st, &o, !rdv_host_busy(&h), NULL);
		client_pass(&ca, &st, 0, "OA", &msgs);
		if (store_read(&st, 0, 1, &m, NULL) && m.kind == RDV_OFFER &&
		    rdv_host_slot(&h, &m))
			rdv_host_refuse(&h, m.from, RDV_REFUSE_FULL);
	}
	assert(ca.state == RDV_CL_REFUSED && ca.refusal == RDV_REFUSE_FULL);
	assert(rdv_client_next(&ca, (const uint8_t *)"OA", 2, &o) == 0);
}

static void each_claimant_gets_its_own_answer(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], b[RDV_CID_LEN];
	static const uint8_t none[RDV_CID_LEN];
	uint8_t punched[RDV_CID_LEN] = { 0 };
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

	for (round = 0; round < 60; round++) {
		if (rdv_host_next(&h, NULL, 0, &o))
			store_write(&st, &o, !rdv_host_busy(&h), NULL);
		client_pass(&ca, &st, 0, "OA", &msgs);
		client_pass(&cb, &st, 0, "OB", &msgs);
		/* The punch for whoever was answered last pass has connected or
		 * ended, which is what hands the cell back. */
		if (memcmp(punched, none, RDV_CID_LEN)) {
			rdv_host_release(&h, punched);
			memset(punched, 0, RDV_CID_LEN);
		}
		if (store_read(&st, 0, 1, &m, NULL) && m.kind == RDV_OFFER &&
		    rdv_host_slot(&h, &m)) {
			rdv_host_answer(&h, m.from,
					!memcmp(m.from, a, RDV_CID_LEN) ?
					(const uint8_t *)"AN-A" :
					(const uint8_t *)"AN-B", 4);
			memcpy(punched, m.from, RDV_CID_LEN);
		}
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
	assert(rdv_client_host_slot(&ca, &m, 1) == 1);

	/* Offered again and again: the same offer under the same sequence. */
	for (i = 0; i < 6; i++) {
		assert(rdv_client_next(&ca, (const uint8_t *)"OA", 2, &o) == 1);
		assert(rdv_decode(&m, o.msg, o.len) == 0);
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

	m.kind = RDV_OFFER;
	m.seq = 4;
	assert(rdv_host_slot(&h, &m) == 1);
	assert(c->state == RDV_C_HARVESTED);
}

/* An answer the cell has lost is stated again, against the ask in hand. */
static void a_kept_claimant_is_answered_again(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_claimant *c;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;

	cid_fill(hcid, 0x20);
	cid_fill(a, 0x30);
	rdv_host_init(&h, hcid, 1, 0);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_OFFER;
	memcpy(m.from, a, RDV_CID_LEN);
	memcpy(m.to, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_host_slot(&h, &m) == 1);
	rdv_host_answer(&h, a, (const uint8_t *)"AN", 2);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_INFO);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_CLASS);
	assert(rdv_host_next(&h, NULL, 0, &o) == 0);

	m.seq = 2;
	assert(rdv_host_slot(&h, &m) == 1);
	c = rdv_host_find(&h, a);
	assert(c && c->state == RDV_C_HARVESTED && h.answered == 0);
	rdv_host_keep(&h, a);
	assert(c->state == RDV_C_ANSWERED && c->pending && h.answered == 1);
	assert(c->answer_re == 2);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_CLASS);
	assert(rdv_host_next(&h, NULL, 0, &o) == 0);
	rdv_host_release(&h, a);

	rdv_host_forget(&h, a);
	rdv_host_keep(&h, a);
	assert(c->state == RDV_C_GONE && h.answered == 0);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_INFO);
	assert(rdv_host_next(&h, NULL, 0, &o) == 0);
}

/* L3 in messages: the instance that replaces a host answers its claimant. */
static void a_restarted_host_answers_its_claimant_again(void)
{
	uint8_t h1[RDV_CID_LEN], h2[RDV_CID_LEN], a[RDV_CID_LEN];
	int round, msgs = 0, rel_a = 0, free_turn;
	struct rdv_client c;
	struct rdv_host h;
	struct rdv_out o;
	struct store st;

	memset(&st, 0, sizeof(st));
	cid_fill(h1, 0x40);
	cid_fill(h2, 0x50);
	cid_fill(a, 0x60);
	rdv_host_init(&h, h1, 1, 0);
	rdv_client_init(&c, a);

	for (round = 0; round < 40; round++) {
		free_turn = !rdv_host_busy(&h);
		if (rdv_host_next(&h, NULL, 0, &o)) {
			store_write(&st, &o, free_turn, NULL);
			msgs++;
		}
		client_pass(&c, &st, round % HIST, "OA", &msgs);
		host_pass(&h, &st, round % HIST, "AN1");
		if (c.answer_len && !rel_a) {
			rdv_host_release(&h, a);
			rel_a = 1;
		}
	}
	assert(c.state == RDV_CL_ANSWERED && !memcmp(c.host_cid, h1, RDV_CID_LEN));
	rdv_client_set_live(&c, 1);

	rdv_host_init(&h, h2, 1, 0);
	rdv_client_set_live(&c, 0);
	msgs = 0;
	for (round = 0; round < 40; round++) {
		free_turn = !rdv_host_busy(&h);
		if (rdv_host_next(&h, NULL, 0, &o)) {
			store_write(&st, &o, free_turn, NULL);
			store_write(&st, &o, free_turn, NULL);
			msgs++;
		}
		client_pass(&c, &st, round % HIST, "OA", &msgs);
		host_pass(&h, &st, round % HIST, "AN2");
		if (c.answer_len)
			rdv_host_release(&h, a);
	}
	assert(c.state == RDV_CL_ANSWERED);
	assert(!memcmp(c.host_cid, h2, RDV_CID_LEN));
	assert(!memcmp(c.prev_cid, h1, RDV_CID_LEN));
	assert(c.answer_len == 3 && !memcmp(c.answer, "AN2", 3));
	printf("rdv_test: a restarted host answered its claimant again, "
	       "%d messages\n", msgs);
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
	assert(rdv_client_host_slot(&c, &m, 1) == 1);
	assert(rdv_client_host_slot(&c, &m, 1) == 0);

	c.state = RDV_CL_ANSWERED;
	rdv_client_set_live(&c, 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 0);

	m.gen = 2;
	m.seq = 2;
	assert(rdv_client_host_slot(&c, &m, 2) == 1);
	assert(c.state == RDV_CL_ANNOUNCING);

	c.state = RDV_CL_ANSWERED;
	memcpy(m.from, h2, RDV_CID_LEN);
	m.seq = 3;
	assert(rdv_client_host_slot(&c, &m, 3) == 1);
	assert(c.state == RDV_CL_ANNOUNCING);

	/* A replica still serving the first host, below the sequence seen. */
	m.gen = 1;
	memcpy(m.from, h1, RDV_CID_LEN);
	assert(rdv_client_host_slot(&c, &m, 1) == -1);
	assert(!memcmp(c.host_cid, h2, RDV_CID_LEN) && c.host_gen == 2);
	memcpy(m.from, h2, RDV_CID_LEN);
	m.gen = 2;

	c.state = RDV_CL_ANSWERED;
	rdv_client_set_live(&c, 0);
	assert(c.state == RDV_CL_ANNOUNCING);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);

	/* A tombstone stops it, until the host it names writes again. */
	m.kind = RDV_TOMB;
	m.seq = 4;
	assert(rdv_client_host_slot(&c, &m, 4) == 0);
	assert(c.host_gone);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 0);
	m.kind = RDV_HOSTINFO;
	m.seq = 5;
	assert(rdv_client_host_slot(&c, &m, 5) == 0);
	assert(!c.host_gone);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
}

/* A replica still serving the answer to an earlier offer, after the host has
 * moved and the claimant offered again, must not prime a dead punch. */
static void an_answer_names_the_offer_it_answers(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_msg m, old;
	struct rdv_client c;
	struct rdv_out o;

	cid_fill(hcid, 0x70);
	cid_fill(a, 0x80);
	rdv_client_init(&c, a);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_HOSTINFO;
	m.gen = 1;
	memcpy(m.from, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_client_host_slot(&c, &m, 1) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	assert(c.state == RDV_CL_OFFERED);

	m.kind = RDV_ANSWER;
	memcpy(m.to, a, RDV_CID_LEN);
	m.seq = 2;
	m.re = c.offer_seq;
	memcpy(m.payload, "A1", 2);
	m.payload_len = 2;
	assert(rdv_client_own_slot(&c, &m) == 1);
	old = m;

	/* The same offer answered again with more in it is taken. */
	m.seq = 3;
	memcpy(m.payload, "A1+", 3);
	m.payload_len = 3;
	assert(rdv_client_own_slot(&c, &m) == 1);
	assert(c.answer_len == 3);

	m.kind = RDV_HOSTINFO;
	m.gen = 2;
	m.seq = 4;
	memset(m.to, 0, RDV_CID_LEN);
	assert(rdv_client_host_slot(&c, &m, 2) == 1);
	assert(c.state == RDV_CL_ANNOUNCING && c.answer_len == 0);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	assert(c.state == RDV_CL_OFFERED && c.offer_seq != old.re);

	assert(rdv_client_own_slot(&c, &old) == 0);
	assert(c.state == RDV_CL_OFFERED);
	m.kind = RDV_ANSWER;
	memcpy(m.to, a, RDV_CID_LEN);
	m.seq = 5;
	m.re = c.offer_seq;
	memcpy(m.payload, "A2", 2);
	m.payload_len = 2;
	assert(rdv_client_own_slot(&c, &m) == 1);
	assert(c.state == RDV_CL_ANSWERED && !memcmp(c.answer, "A2", 2));
}

/* The tolerance for the superseded offer carries an answer across a re-post,
 * and must not carry one across a fresh identity. */
static void an_answer_to_a_spent_identity_is_refused(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_msg m, first;
	struct rdv_client c;
	struct rdv_out o;

	cid_fill(hcid, 0x90);
	cid_fill(a, 0xa0);
	rdv_client_init(&c, a);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_HOSTINFO;
	m.gen = 1;
	memcpy(m.from, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_client_host_slot(&c, &m, 1) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O1", 2, &o) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O1", 2, &o) == 1);

	memset(&first, 0, sizeof(first));
	first.kind = RDV_ANSWER;
	memcpy(first.from, hcid, RDV_CID_LEN);
	memcpy(first.to, a, RDV_CID_LEN);
	first.re = c.offer_seq;
	first.seq = 2;
	memcpy(first.payload, "A1", 2);
	first.payload_len = 2;
	/* O1 answered while O2 stands: the credentials are the same. */
	assert(rdv_client_next(&c, (const uint8_t *)"O2", 2, &o) == 1);
	assert(c.prev_offer_seq == first.re);
	assert(rdv_client_would_take(&c, &first));

	assert(rdv_client_next(&c, (const uint8_t *)"O3", 2, &o) == 1);
	rdv_client_ident_changed(&c);
	assert(!c.prev_offer_seq);
	assert(!rdv_client_would_take(&c, &first));

	first.re = c.offer_seq;
	first.seq = 3;
	assert(rdv_client_would_take(&c, &first));
}

/* Each refusal is a distinct condition, and the one reported has to be the one
 * that fired: equal sequence numbers in an unrelated clause read as the cause
 * otherwise. */
static void a_refusal_names_the_clause_that_fired(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], other[RDV_CID_LEN];
	struct rdv_client c;
	struct rdv_msg m;
	struct rdv_out o;

	cid_fill(hcid, 0xb0);
	cid_fill(a, 0xc0);
	cid_fill(other, 0xd0);
	rdv_client_init(&c, a);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_HOSTINFO;
	m.gen = 1;
	memcpy(m.from, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_client_refusal(&c, &m) == RDV_TAKE_NOT_AN_ANSWER);
	assert(rdv_client_host_slot(&c, &m, 1) == 1);

	m.kind = RDV_ANSWER;
	memcpy(m.to, other, RDV_CID_LEN);
	assert(rdv_client_refusal(&c, &m) == RDV_TAKE_ADDRESSED_ELSEWHERE);

	memcpy(m.to, a, RDV_CID_LEN);
	assert(rdv_client_refusal(&c, &m) == RDV_TAKE_NOTHING_ASKED);

	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	m.re = c.offer_seq + 7;
	assert(rdv_client_refusal(&c, &m) == RDV_TAKE_ANOTHER_OFFER);

	m.re = c.offer_seq;
	m.seq = 9;
	assert(rdv_client_refusal(&c, &m) == RDV_TAKE_OK);
	assert(rdv_client_own_slot(&c, &m) == 1);
	/* Re-reading what we hold: the sequences are equal, and that is the
	 * reason, not the offer the answer names. */
	assert(rdv_client_refusal(&c, &m) == RDV_TAKE_ALREADY_TAKEN);
	assert(m.re == c.offer_seq);

	memcpy(m.from, other, RDV_CID_LEN);
	m.seq = 10;
	assert(rdv_client_refusal(&c, &m) == RDV_TAKE_ANOTHER_HOST);
	assert(!strcmp(rdv_client_refusal_name(RDV_TAKE_ALREADY_TAKEN),
		       "already taken"));
}

/* The turn place is a doorbell: a claimant leaves alone only its own standing
 * ask and an answer it would take, so a wedged one cannot hold it. */
static void a_claimant_may_replace_all_but_its_own_and_its_answer(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], other[RDV_CID_LEN];
	struct rdv_client c;
	struct rdv_msg m;
	struct rdv_out o;

	cid_fill(hcid, 0xe0);
	cid_fill(a, 0xf0);
	cid_fill(other, 0x11);
	rdv_client_init(&c, a);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_HOSTINFO;
	m.gen = 1;
	memcpy(m.from, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_client_host_slot(&c, &m, 1) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);

	assert(rdv_client_may_replace(&c, &m, 0));

	m.kind = RDV_OFFER;
	memcpy(m.from, other, RDV_CID_LEN);
	memcpy(m.to, hcid, RDV_CID_LEN);
	m.seq = 4;
	assert(rdv_client_may_replace(&c, &m, 1));

	m.kind = RDV_ANSWER;
	memcpy(m.from, hcid, RDV_CID_LEN);
	memcpy(m.to, other, RDV_CID_LEN);
	m.re = c.offer_seq;
	m.seq = 5;
	assert(rdv_client_may_replace(&c, &m, 1));

	memcpy(m.to, a, RDV_CID_LEN);
	assert(rdv_client_would_take(&c, &m));
	assert(!rdv_client_may_replace(&c, &m, 1));

	assert(rdv_client_own_slot(&c, &m) == 1);
	assert(rdv_client_may_replace(&c, &m, 1));

	m.kind = RDV_OFFER;
	memcpy(m.from, a, RDV_CID_LEN);
	memcpy(m.to, hcid, RDV_CID_LEN);
	m.seq = c.offer_seq;
	assert(!rdv_client_may_replace(&c, &m, 1));
	m.seq = c.offer_seq - 1;
	assert(rdv_client_may_replace(&c, &m, 1));
}

static void stale_and_unaddressed_messages_are_no_ops(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN], b[RDV_CID_LEN];
	struct rdv_client c;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;
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
	assert(rdv_client_host_slot(&c, &m, 1) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O", 1, &o) == 1);
	assert(c.state == RDV_CL_OFFERED && c.offer_seq);

	m.kind = RDV_ANSWER;
	memcpy(m.to, b, RDV_CID_LEN);
	m.seq = 5;
	m.re = c.offer_seq;
	assert(rdv_client_own_slot(&c, &m) == 0);
	assert(c.state == RDV_CL_OFFERED);

	memcpy(m.to, a, RDV_CID_LEN);
	m.re = c.offer_seq - 1;
	assert(rdv_client_own_slot(&c, &m) == 0);
	m.re = c.offer_seq;
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

	/* Nameless, or addressed to another host: admits nobody. */
	memset(&m, 0, sizeof(m));
	m.kind = RDV_OFFER;
	m.seq = 9;
	assert(rdv_host_slot(&h, &m) == 0);
	memcpy(m.from, b, RDV_CID_LEN);
	memcpy(m.to, a, RDV_CID_LEN);
	assert(rdv_host_slot(&h, &m) == 0);
	for (i = 0; i < RDV_HOST_MAX; i++)
		assert(h.c[i].state == RDV_C_FREE ||
		       !memcmp(h.c[i].cid, a, RDV_CID_LEN));
}

/* A host that never answered has no answer to state again, and an empty one
 * reads as malformed at the other end. */
static void a_claimant_never_answered_is_not_kept(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_claimant *c;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;

	cid_fill(hcid, 0x28);
	cid_fill(a, 0x38);
	rdv_host_init(&h, hcid, 1, 0);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_OFFER;
	memcpy(m.from, a, RDV_CID_LEN);
	memcpy(m.to, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_host_slot(&h, &m) == 1);
	rdv_host_keep(&h, a);
	c = rdv_host_find(&h, a);
	assert(c && c->state != RDV_C_ANSWERED && !c->pending);
	assert(h.answered == 0);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_INFO);
	assert(rdv_host_next(&h, NULL, 0, &o) == 0);

	rdv_host_answer(&h, a, (const uint8_t *)"AN", 2);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_CLASS);
	rdv_host_keep(&h, a);
	assert(c->state == RDV_C_ANSWERED && h.answered == 1);
}

/* An answer whose payload does not decode leaves the claimant asking: taking
 * it would guard the place against the only write that could free it. */
static void an_unreadable_answer_is_spent_not_taken(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_client c;
	struct rdv_msg m;
	struct rdv_out o;
	uint32_t asked;

	cid_fill(hcid, 0xe0);
	cid_fill(a, 0xe8);
	rdv_client_init(&c, a);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_HOSTINFO;
	m.gen = 1;
	memcpy(m.from, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_client_host_slot(&c, &m, 1) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O1", 2, &o) == 1);
	assert(rdv_client_next(&c, (const uint8_t *)"O1", 2, &o) == 1);
	asked = c.offer_seq;

	m.kind = RDV_ANSWER;
	memcpy(m.to, a, RDV_CID_LEN);
	m.re = asked;
	m.seq = 4;
	m.payload_len = 0;
	assert(rdv_client_would_take(&c, &m));
	assert(!rdv_client_may_replace(&c, &m, 1));

	rdv_client_answer_unusable(&c, &m);
	assert(c.state != RDV_CL_ANSWERED);
	assert(rdv_client_refusal(&c, &m) == RDV_TAKE_ALREADY_TAKEN);
	assert(rdv_client_may_replace(&c, &m, 1));
	assert(rdv_client_next(&c, (const uint8_t *)"O1", 2, &o) == 1);
	assert(c.offer_seq != asked);
}

/* An answer emitted but never sent is still owed, and the claimant asking
 * again with the ask it already made must not cancel it. */
static void a_deferred_answer_is_still_owed(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_claimant *c;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;

	cid_fill(hcid, 0x44);
	cid_fill(a, 0x54);
	rdv_host_init(&h, hcid, 1, 0);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_OFFER;
	memcpy(m.from, a, RDV_CID_LEN);
	memcpy(m.to, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_host_slot(&h, &m) == 1);
	rdv_host_answer(&h, a, (const uint8_t *)"AN", 2);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_INFO);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_CLASS);

	/* The cell was busy, so that emission never went out. */
	rdv_host_unsent(&h, a);
	c = rdv_host_find(&h, a);
	assert(c && c->pending && !c->holds);

	/* The claimant re-posts the ask it already made, so the host reads a
	 * replay and keeps it; the answer is still owed. */
	assert(rdv_host_slot(&h, &m) == 0);
	rdv_host_keep(&h, a);
	assert(c->pending);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_CLASS);
}

/* A fresh answer made while one already stands in the cell is owed, and a
 * replayed ask must not cancel that either. */
static void a_new_answer_outlives_a_replayed_ask(void)
{
	uint8_t hcid[RDV_CID_LEN], a[RDV_CID_LEN];
	struct rdv_claimant *c;
	struct rdv_host h;
	struct rdv_msg m;
	struct rdv_out o;

	cid_fill(hcid, 0x64);
	cid_fill(a, 0x74);
	rdv_host_init(&h, hcid, 1, 0);

	memset(&m, 0, sizeof(m));
	m.kind = RDV_OFFER;
	memcpy(m.from, a, RDV_CID_LEN);
	memcpy(m.to, hcid, RDV_CID_LEN);
	m.seq = 1;
	assert(rdv_host_slot(&h, &m) == 1);
	rdv_host_answer(&h, a, (const uint8_t *)"A1", 2);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_INFO);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_CLASS);
	c = rdv_host_find(&h, a);
	assert(c && c->holds && !c->pending);

	rdv_host_answer(&h, a, (const uint8_t *)"A2", 2);
	assert(c->pending);
	assert(rdv_host_slot(&h, &m) == 0);
	rdv_host_keep(&h, a);
	assert(c->pending);
	assert(rdv_host_next(&h, NULL, 0, &o) == 1 &&
	       o.seal == RDV_SEAL_CLASS);
	assert(rdv_decode(&m, o.msg, o.len) == 0);
	assert(m.payload_len == 2 && !memcmp(m.payload, "A2", 2));
}

int main(void)
{
	envelope_checks();
	stale_and_unaddressed_messages_are_no_ops();
	an_answer_names_the_offer_it_answers();
	an_answer_to_a_spent_identity_is_refused();
	a_refusal_names_the_clause_that_fired();
	a_claimant_may_replace_all_but_its_own_and_its_answer();
	a_moved_host_is_re_announced_to();
	a_spent_grant_refuses_rather_than_waits();
	a_refusal_the_host_decides();
	each_claimant_gets_its_own_answer();
	an_unchanged_offer_is_answered_once();
	a_gone_claimant_s_replay_is_ignored();
	a_kept_claimant_is_answered_again();
	a_claimant_never_answered_is_not_kept();
	a_deferred_answer_is_still_owed();
	a_new_answer_outlives_a_replayed_ask();
	an_unreadable_answer_is_spent_not_taken();
	a_restarted_host_answers_its_claimant_again();
	liveness_under_a_hostile_store(1, 0);
	liveness_under_a_hostile_store(3, 0);
	liveness_under_a_hostile_store(4, 0);
	liveness_under_a_hostile_store(3, 1);
	printf("rdv: envelope, addressing, liveness and refusal cases pass\n");
	return 0;
}
