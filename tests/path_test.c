/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The path model, offline and deterministic: every rule PROTOCOL.md states for
 * §9 is pinned here, so breaking one fails loudly rather than degrading into a
 * link that still works but no longer agrees with the far end.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "path.h"
#include "wsock.h"

static const uint8_t key[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static struct path_ep ep6(const char *addr, uint16_t port)
{
	struct path_ep e;

	memset(&e, 0, sizeof(e));
	assert(inet_pton(AF_INET6, addr, e.addr) == 1);
	e.port = port;
	return e;
}

static struct sockaddr_in6 sa4(const char *addr, uint16_t port)
{
	struct sockaddr_in a4;
	struct sockaddr_in6 out;
	struct path_ep e;

	memset(&a4, 0, sizeof(a4));
	a4.sin_family = AF_INET;
	a4.sin_port = htons(port);
	assert(inet_pton(AF_INET, addr, &a4.sin_addr) == 1);
	assert(path_ep_from_sockaddr(&e, (struct sockaddr *)&a4,
				     sizeof(a4)) == 0);
	path_ep_to_sockaddr(&e, &out);
	return out;
}

static struct sockaddr_in6 sa6(const char *addr, uint16_t port)
{
	struct sockaddr_in6 a6;

	memset(&a6, 0, sizeof(a6));
	a6.sin6_family = AF_INET6;
	a6.sin6_port = htons(port);
	assert(inet_pton(AF_INET6, addr, &a6.sin6_addr) == 1);
	return a6;
}

/* IPv4 is canonicalised v4-mapped, the IPv6 zone id is left out of the name,
 * and the packed form is the 18 bytes the id is taken over. */
static void endpoint_check(void)
{
	struct sockaddr_in a4;
	struct sockaddr_in6 a6, back;
	struct path_ep e, f, g;
	uint8_t packed[PATH_EP_LEN];
	char s[PATH_LABEL_MAX];

	memset(&a4, 0, sizeof(a4));
	a4.sin_family = AF_INET;
	a4.sin_port = htons(4242);
	assert(inet_pton(AF_INET, "192.0.2.7", &a4.sin_addr) == 1);
	assert(path_ep_from_sockaddr(&e, (struct sockaddr *)&a4,
				     sizeof(a4)) == 0);
	assert(path_ep_is_v4(&e));
	assert(e.port == 4242);
	assert(e.addr[10] == 0xff && e.addr[11] == 0xff);
	assert(e.addr[12] == 192 && e.addr[15] == 7);

	/* The same peer over the dual-stack socket is one endpoint. */
	a6 = sa4("192.0.2.7", 4242);
	assert(path_ep_from_sockaddr(&f, (struct sockaddr *)&a6,
				     sizeof(a6)) == 0);
	assert(path_ep_eq(&e, &f));

	/* A v4 endpoint prints as v4, a v6 one bracketed. */
	path_ep_str(&e, s, sizeof(s));
	assert(!strcmp(s, "192.0.2.7:4242"));
	f = ep6("2001:db8::1", 9);
	path_ep_str(&f, s, sizeof(s));
	assert(!strcmp(s, "[2001:db8::1]:9"));

	/* The zone id is local to one host and does not travel, so it is no
	 * part of a name both ends must agree on. */
	a6 = sa6("fe80::1", 5000);
	assert(path_ep_from_sockaddr(&f, (struct sockaddr *)&a6,
				     sizeof(a6)) == 0);
	a6.sin6_scope_id = 17;
	assert(path_ep_from_sockaddr(&g, (struct sockaddr *)&a6,
				     sizeof(a6)) == 0);
	assert(path_ep_eq(&f, &g));

	path_ep_pack(&e, packed);
	assert(packed[16] == (4242 >> 8) && packed[17] == (4242 & 0xff));
	path_ep_unpack(&g, packed);
	assert(path_ep_eq(&e, &g));
	path_ep_to_sockaddr(&e, &back);
	assert(back.sin6_family == AF_INET6 && back.sin6_port == htons(4242));

	memset(&e, 0, sizeof(e));
	assert(path_ep_any(&e));
	e.port = 1;
	assert(!path_ep_any(&e));
}

/* The head round-trips, the optional tail round-trips, and a frame that is not
 * ours is refused rather than half-parsed. */
static void probe_codec_check(void)
{
	struct path_probe out, in;
	uint8_t buf[PROBE_MAX];
	size_t n;

	assert(PROBE_PLAIN_MAX == 1 + 8 + 1 + 40 + 22);

	memset(&out, 0, sizeof(out));
	out.type = PROBE_PING;
	out.nonce = 0x0123456789abcdefULL;
	snprintf(out.ufrag, sizeof(out.ufrag), "a1b2c3d4");
	n = path_probe_build(buf, sizeof(buf), key, &out);
	assert(n > 4 && n <= PROBE_MAX);
	assert(path_probe_is(buf, n));
	assert(path_probe_parse(&in, key, buf, n) == 0);
	assert(in.type == PROBE_PING && in.nonce == out.nonce);
	assert(!strcmp(in.ufrag, "a1b2c3d4"));
	assert(!in.have_tail);

	/* A peer that omits the tail shares no measurements; one that sends it
	 * hands over its own view and the reflexive endpoint it observed. */
	out.type = PROBE_PONG;
	out.have_tail = 1;
	out.echo = ep6("2001:db8::99", 61000);
	out.srtt_ms = 37;
	out.loss_ppt = 125;
	n = path_probe_build(buf, sizeof(buf), key, &out);
	assert(n > 4 && n <= PROBE_MAX);
	assert(path_probe_parse(&in, key, buf, n) == 0);
	assert(in.type == PROBE_PONG && in.have_tail);
	assert(path_ep_eq(&in.echo, &out.echo));
	assert(in.srtt_ms == 37 && in.loss_ppt == 125);

	/* The longest ufrag still fits alongside the tail. */
	memset(out.ufrag, 'z', PROBE_UFRAG_MAX);
	out.ufrag[PROBE_UFRAG_MAX] = '\0';
	n = path_probe_build(buf, sizeof(buf), key, &out);
	assert(n == PROBE_MAX);
	assert(path_probe_parse(&in, key, buf, n) == 0);
	assert(strlen(in.ufrag) == PROBE_UFRAG_MAX && in.have_tail);

	/* Not a probe, and a probe a stranger could not have sealed. */
	assert(!path_probe_is(buf, 3));
	buf[0] ^= 0xff;
	assert(!path_probe_is(buf, n));
	assert(path_probe_parse(&in, key, buf, n) == -1);
	buf[0] ^= 0xff;
	buf[n - 1] ^= 0xff;
	assert(path_probe_parse(&in, key, buf, n) == -1);
}

/*
 * The id is taken over the unordered pair, so both ends name a path identically
 * without either being "first". The pinned vector catches a backend that cannot
 * produce the digest at all: an all-zero id would still compare and still sort,
 * and the failure would never be seen on the wire.
 */
static void id_check(void)
{
	struct path_ep a = ep6("2001:db8::1", 5000);
	struct path_ep b = ep6("2001:db8::2", 6000);
	static const uint8_t zero[PATH_ID_LEN] = { 0 };
	static const uint8_t pinned[PATH_ID_LEN] = {
		0xdb, 0x6f, 0xe1, 0xa4, 0xac, 0xe9, 0x88, 0x24
	};
	uint8_t ab[PATH_ID_LEN], ba[PATH_ID_LEN], other[PATH_ID_LEN];
	uint8_t key2[32];
	struct path_ep c;

	path_id_calc(ab, key, &a, &b);
	path_id_calc(ba, key, &b, &a);
	assert(!memcmp(ab, ba, PATH_ID_LEN));
	assert(memcmp(ab, zero, PATH_ID_LEN));
	assert(!memcmp(ab, pinned, PATH_ID_LEN));

	/* A different pair, and a different session, name a different path. */
	c = ep6("2001:db8::3", 6000);
	path_id_calc(other, key, &a, &c);
	assert(memcmp(ab, other, PATH_ID_LEN));
	c = ep6("2001:db8::2", 6001);
	path_id_calc(other, key, &a, &c);
	assert(memcmp(ab, other, PATH_ID_LEN));
	memcpy(key2, key, sizeof(key2));
	key2[0] ^= 1;
	path_id_calc(other, key2, &a, &b);
	assert(memcmp(ab, other, PATH_ID_LEN));
}

/* Both ends compute the same cost from the same pair of views, and the bucket
 * quantises at PATH_COST_QUANTUM_MS. */
static void cost_check(void)
{
	assert(path_cost_of(30, 0, 12, 0) == path_cost_of(12, 0, 30, 0));
	assert(path_cost_of(30, 250, 12, 40) == path_cost_of(12, 40, 30, 250));
	assert(path_cost_of(30, 0, 12, 0) == 30);
	assert(path_cost_of(0, 0, 0, 1000) == PATH_LOSS_PENALTY_MS);
	assert(path_cost_of(10, 500, 10, 0) == 10 + PATH_LOSS_PENALTY_MS / 2);

	assert(path_bucket_of(0) == 0);
	assert(path_bucket_of(1) == 1);
	assert(path_bucket_of(PATH_COST_QUANTUM_MS) == 1);
	assert(path_bucket_of(PATH_COST_QUANTUM_MS + 1) == 2);
	assert(path_bucket_of(2 * PATH_COST_QUANTUM_MS) == 2);
}

static struct path *add(struct path_table *t, const char *addr, uint16_t port,
			uint64_t now)
{
	struct sockaddr_in6 sa = sa6(addr, port);
	struct path *p = path_table_add(t, PATH_SEGMENT, &sa, NULL, now);

	assert(p);
	return p;
}

/* One PONG at `rtt` after the probe went out, at `now`. */
static void round_trip(struct path *p, uint64_t now, int rtt)
{
	assert(path_probe_due(p, now));
	path_probe_sent(p, 0xabcdef00ULL + now, now);
	assert(!path_probe_due(p, now));
	assert(path_probe_pong(p, p->nonce, now + (uint64_t)rtt) == 1);
}

static void table_check(void)
{
	struct path_table t;
	struct path_ep e;
	struct path *p, *q;
	int i;

	path_table_init(&t);
	assert(path_table_count(&t) == 0);
	assert(path_best(&t, 0) == -1);
	assert(path_select(&t, 0) == -1);

	p = add(&t, "2001:db8::1", 5000, 0);
	assert(path_table_count(&t) == 1);
	assert(!strcmp(p->label, "[2001:db8::1]:5000"));
	/* Add, never replace: the same endpoint is the same path. */
	assert(add(&t, "2001:db8::1", 5000, 10) == p);
	assert(path_table_count(&t) == 1);

	e = ep6("2001:db8::1", 5000);
	assert(path_table_find(&t, PATH_SEGMENT, &e) == p);
	assert(!path_table_find(&t, PATH_ICE, &e));
	assert(path_table_find_ep(&t, &e) == p);
	assert(path_table_find_port(&t, 5000) == p);
	assert(!path_table_find_port(&t, 5001));
	assert(path_index(&t, p) == 0);

	for (i = 1; i < PATH_TABLE_MAX; i++)
		add(&t, "2001:db8::1", (uint16_t)(5000 + i), 100 + i);
	assert(path_table_count(&t) == PATH_TABLE_MAX);

	/* Full: the oldest DEAD goes first, and never the path in use. */
	round_trip(p, 200, 1);
	assert(path_select(&t, 200) == 0);
	q = &t.p[2];
	q->qualified = 1;
	q->last_pong_ms = 0;
	assert(path_warmth_of(q, 200 + PATH_DEAD_MS + 1) == PATH_DEAD);
	p = add(&t, "2001:db8::9", 9999, 200 + PATH_DEAD_MS + 1);
	assert(p == q);
	assert(path_table_count(&t) == PATH_TABLE_MAX);
	assert(t.sel == 0);

	path_table_drop_kind(&t, PATH_SEGMENT);
	assert(path_table_count(&t) == 0);
	assert(t.sel == -1);
}

/* The four states, and the latch that separates "never answered" from
 * "qualified once, silent since". */
static void warmth_check(void)
{
	struct path_table t;
	struct path *p;

	path_table_init(&t);
	p = add(&t, "2001:db8::1", 5000, 0);

	/* Never answered stays UNQUALIFIED however long it is left. */
	assert(path_warmth_of(p, 0) == PATH_UNQUALIFIED);
	assert(path_warmth_of(p, 1000000) == PATH_UNQUALIFIED);
	assert(!path_table_any_qualified(&t));

	round_trip(p, 0, 4);
	assert(path_table_any_qualified(&t));
	assert(path_warmth_of(p, 4) == PATH_WARM);
	assert(path_warmth_of(p, 4 + PATH_WARM_MS) == PATH_WARM);
	assert(path_warmth_of(p, 5 + PATH_WARM_MS) == PATH_COLD);
	assert(path_warmth_of(p, 4 + PATH_DEAD_MS) == PATH_COLD);
	assert(path_warmth_of(p, 5 + PATH_DEAD_MS) == PATH_DEAD);

	/* A late answer warms it again without a rediscovery. */
	p->next_probe_ms = 20000;
	round_trip(p, 20000, 3);
	assert(path_warmth_of(p, 20003) == PATH_WARM);

	/* A re-claim mints a new identity, so every proof taken under the old
	 * one goes; the endpoints stay. */
	path_table_reset_stats(&t);
	assert(path_table_count(&t) == 1);
	assert(!path_table_any_qualified(&t));
	assert(path_warmth_of(p, 20003) == PATH_UNQUALIFIED);
	assert(path_srtt_ms(p) == 0);
}

/*
 * The two cadences: PROBE_EVERY_MS while unqualified, PATH_KEEP_MS once
 * qualified -- the path in use included, since the ctl heartbeat measures the
 * session end to end and not any individual path.
 */
static void cadence_check(void)
{
	struct path_table t;
	struct path *p;
	uint64_t now;

	path_table_init(&t);
	p = add(&t, "2001:db8::1", 5000, 0);

	assert(path_probe_due(p, 0));
	path_probe_sent(p, 1, 0);
	/* One outstanding at a time, so the cadence coming round is not enough:
	 * the next probe waits for this one to be answered or to expire. */
	assert(!path_probe_due(p, PROBE_EVERY_MS));
	path_probe_expire(p, PATH_LOSS_WAIT_MS + 1);
	assert(!p->outstanding);
	now = PATH_LOSS_WAIT_MS + 1;
	assert(path_probe_due(p, now));
	path_probe_sent(p, 2, now);
	assert(path_probe_pong(p, 2, now + 4) == 1);

	/* Qualified now, so the keep period, counted from the answer that
	 * qualified it rather than from the probe that was still an unqualified
	 * path's when it went out. */
	assert(!path_probe_due(p, now + 4 + PATH_KEEP_MS - 1));
	assert(path_probe_due(p, now + 4 + PATH_KEEP_MS));
	now += 4 + PATH_KEEP_MS;
	path_probe_sent(p, 3, now);
	assert(path_probe_pong(p, 3, now + 4) == 1);
	assert(!path_probe_due(p, now + PATH_KEEP_MS - 1));
	assert(path_probe_due(p, now + PATH_KEEP_MS));

	/* Falling silent does not put it back on the fast cadence: it qualified
	 * once, and only a fresh claimant identity takes that back. */
	now += PATH_KEEP_MS;
	path_probe_sent(p, 4, now);
	assert(!path_probe_due(p, now + PROBE_EVERY_MS));
	now += PATH_LOSS_WAIT_MS + 1;
	path_probe_expire(p, now);
	assert(!p->outstanding && path_loss_ppt(p) > 0);
	/* The keep period passed while that one was outstanding, so the next
	 * goes out as soon as it is scored rather than a period later. */
	assert(path_probe_due(p, now));
	assert(path_warmth_of(p, now + PATH_DEAD_MS) == PATH_DEAD);
}

/*
 * The smoothed round trip moves by a full eighth of the error each sample, and
 * the loss window spans the last PATH_LOSS_WINDOW outcomes and no more.
 */
static void measure_check(void)
{
	struct path_table t;
	struct path *p;
	uint64_t now = 0;
	int i;

	path_table_init(&t);
	p = add(&t, "2001:db8::1", 5000, 0);

	round_trip(p, now, 100);
	assert(path_srtt_ms(p) == 100);
	now = p->next_probe_ms;
	round_trip(p, now, 20);
	assert(path_srtt_ms(p) == 90);		/* 100 + (20 - 100) / 8 */
	now = p->next_probe_ms;
	round_trip(p, now, 20);
	assert(path_srtt_ms(p) == 81);		/* 90 + (20 - 90) / 8 */
	assert(path_loss_ppt(p) == 0);

	/* A PONG for a probe that is not outstanding answers nothing. */
	assert(path_probe_pong(p, 0xdeadbeefULL, now) == 0);

	/* Saturate the window with losses, then clear it with successes: the
	 * ratio is over the last PATH_LOSS_WINDOW outcomes, never more. */
	for (i = 0; i < PATH_LOSS_WINDOW * 2; i++) {
		now = p->next_probe_ms;
		path_probe_sent(p, 1000 + (uint64_t)i, now);
		path_probe_expire(p, now + 3 * (uint64_t)path_srtt_ms(p) +
				  PATH_LOSS_WAIT_MS + 1);
		assert(!p->outstanding);
	}
	assert(p->loss_n == PATH_LOSS_WINDOW);
	assert(path_loss_ppt(p) == 1000);
	for (i = 0; i < PATH_LOSS_WINDOW; i++) {
		now = p->next_probe_ms;
		round_trip(p, now, 1);
	}
	assert(path_loss_ppt(p) == 0);

	/* One loss in a full window is one part in PATH_LOSS_WINDOW. */
	now = p->next_probe_ms;
	path_probe_sent(p, 77, now);
	path_probe_expire(p, now + PATH_LOSS_WAIT_MS + 1);
	assert(path_loss_ppt(p) == 1000 / PATH_LOSS_WINDOW);
}

/*
 * A path whose round trip exceeds the probe period must not be condemned for
 * being slow: a probe becomes a loss only once it has been outstanding longer
 * than max(3 * srtt, PATH_LOSS_WAIT_MS), and while one is outstanding the next
 * is not sent, so no probe is ever scored the moment it is superseded.
 */
static void loss_outcome_check(void)
{
	struct path_table t;
	struct path *p;
	uint64_t now = 0;
	int i;

	path_table_init(&t);
	p = add(&t, "2001:db8::1", 5000, 0);

	for (i = 0; i < 8; i++) {
		assert(path_probe_due(p, now));
		path_probe_sent(p, 500 + (uint64_t)i, now);
		/* The cadence comes round several times over, and each of those
		 * ticks must leave the outstanding probe alone. */
		for (; now < p->sent_ms + 500; now += PROBE_EVERY_MS) {
			path_probe_expire(p, now);
			assert(!path_probe_due(p, now));
			assert(p->outstanding);
		}
		assert(path_probe_pong(p, p->nonce, p->sent_ms + 500) == 1);
		now = p->next_probe_ms;
	}
	assert(path_loss_ppt(p) == 0);
	assert(path_srtt_ms(p) == 500);
	assert(p->loss_n == 8);

	/* Past the deadline it is a loss, and only then. */
	assert(path_probe_due(p, now));
	path_probe_sent(p, 999, now);
	path_probe_expire(p, now + 3 * 500);
	assert(p->outstanding);
	assert(path_loss_ppt(p) == 0);
	path_probe_expire(p, now + 3 * 500 + 1);
	assert(!p->outstanding);
	assert(path_loss_ppt(p) == 1000 / 9);

	/* A probe superseded rather than answered is not a loss either: an
	 * outcome is what its deadline says, never what the next send says. */
	i = p->loss_n;
	now = p->next_probe_ms;
	path_probe_sent(p, 1234, now);
	path_probe_sent(p, 1235, now + PROBE_EVERY_MS);
	assert(p->loss_n == i);
	assert(p->nonce == 1235 && p->outstanding);
}

/*
 * The tail is one end's view of the path, and the echo in it is the other end's
 * reflexive endpoint: two ends that exchange one name the path identically
 * without either being first. A peer that omits the tail shares no
 * measurements, which costs accuracy and never correctness.
 */
static void tail_check(void)
{
	static const uint8_t zero[PATH_ID_LEN] = { 0 };
	struct path_ep ea = ep6("2001:db8::a", 4001);
	struct path_ep eb = ep6("2001:db8::b", 4002);
	struct path_probe out, in;
	struct path_table a, b;
	uint8_t buf[PROBE_MAX];
	struct path *pa, *pb;
	size_t n;

	path_table_init(&a);
	path_table_init(&b);
	pa = add(&a, "2001:db8::b", 4002, 0);	/* a's path to b */
	pb = add(&b, "2001:db8::a", 4001, 0);	/* b's path to a */
	assert(!pa->have_self_ep && !pb->have_self_ep);

	/* b answers a probe of a's, echoing the source it arrived from. */
	round_trip(pb, 0, 6);
	path_saw_inbound(pb, &ea);
	memset(&out, 0, sizeof(out));
	out.type = PROBE_PONG;
	out.nonce = 0x0102030405060708ULL;
	snprintf(out.ufrag, sizeof(out.ufrag), "%s", "c0ffee00");
	path_fill_tail(pb, &out);
	assert(out.have_tail && path_ep_eq(&out.echo, &ea) && out.srtt_ms == 6);
	n = path_probe_build(buf, sizeof(buf), key, &out);
	assert(n && path_probe_parse(&in, key, buf, n) == 0);
	assert(in.have_tail && path_ep_eq(&in.echo, &ea));
	path_apply_tail(pa, &in, key);
	assert(pa->have_self_ep && path_ep_eq(&pa->self_ep, &ea));
	assert(pa->peer_srtt_ms == 6);
	assert(memcmp(pa->id, zero, PATH_ID_LEN));
	assert(memcmp(pa->id, pb->id, PATH_ID_LEN));	/* only a has learnt */

	/* The same the other way round, after which both hold the same
	 * unordered pair and so compute the same id. */
	path_saw_inbound(pa, &eb);
	memset(&out, 0, sizeof(out));
	out.type = PROBE_PING;
	out.nonce = 9;
	path_fill_tail(pa, &out);
	n = path_probe_build(buf, sizeof(buf), key, &out);
	assert(n && path_probe_parse(&in, key, buf, n) == 0);
	path_apply_tail(pb, &in, key);
	assert(path_ep_eq(&pb->self_ep, &eb));
	assert(!memcmp(pa->id, pb->id, PATH_ID_LEN));

	/* A peer that omits the tail leaves every view standing. */
	memset(&out, 0, sizeof(out));
	out.type = PROBE_PING;
	out.nonce = 10;
	n = path_probe_build(buf, sizeof(buf), key, &out);
	assert(n && path_probe_parse(&in, key, buf, n) == 0);
	assert(!in.have_tail);
	path_apply_tail(pa, &in, key);
	assert(pa->peer_srtt_ms == 6 && path_ep_eq(&pa->self_ep, &ea));

	/* Nothing has arrived on a fresh path, so it echoes the all-zero
	 * endpoint rather than somebody else's. */
	path_table_init(&a);
	pa = add(&a, "2001:db8::c", 4003, 0);
	memset(&out, 0, sizeof(out));
	path_fill_tail(pa, &out);
	assert(out.have_tail && path_ep_any(&out.echo));
	assert(!out.srtt_ms && !out.loss_ppt);
}

/*
 * Ordering is total, so both ends always agree even before any measurement
 * exists: qualified before unqualified, then by cost, then by the lowest id.
 */
static void order_check(void)
{
	struct path_table a, b;
	static const char * const addr[3] = {
		"2001:db8::1", "2001:db8::2", "2001:db8::3"
	};
	uint8_t self[PATH_ID_LEN];
	struct path_ep me = ep6("2001:db8::a", 1);
	struct path_ep other;
	struct path *p;
	int i, ba, bb;

	/* At t=0 nothing is qualified and no cost is known, so the order falls
	 * through to the id -- and the id does not depend on the order the
	 * endpoints were learnt in, so the two ends pick the same path. */
	path_table_init(&a);
	path_table_init(&b);
	for (i = 0; i < 3; i++) {
		p = add(&a, addr[i], 5000, 0);
		path_set_self_ep(p, &me, key);
		p = add(&b, addr[2 - i], 5000, 0);
		path_set_self_ep(p, &me, key);
	}
	ba = path_best(&a, 0);
	bb = path_best(&b, 0);
	assert(ba >= 0 && bb >= 0);
	assert(!memcmp(a.p[ba].id, b.p[bb].id, PATH_ID_LEN));
	assert(path_ep_eq(&a.p[ba].peer_ep, &b.p[bb].peer_ep));
	for (i = 0; i < 3; i++)
		assert(memcmp(a.p[ba].id, a.p[i].id, PATH_ID_LEN) <= 0);

	/* The id is only agreed once both ends hold the same pair, which is
	 * what the reflexive echo in the PONG delivers. */
	memcpy(self, a.p[0].id, PATH_ID_LEN);
	other = ep6("2001:db8::b", 2);
	path_set_self_ep(&a.p[0], &other, key);
	assert(a.p[0].have_self_ep);
	assert(memcmp(self, a.p[0].id, PATH_ID_LEN));

	/* A qualified path outranks an unqualified one whatever it costs, and
	 * class plays no part: both of these are the same kind. */
	path_table_init(&a);
	p = add(&a, addr[0], 5000, 0);
	round_trip(p, 0, 40);
	p = add(&a, addr[1], 5000, 0);
	assert(path_best(&a, 40) == 0);
	assert(path_cmp(&a.p[0], &a.p[1], 40) < 0);

	/* Between two qualified paths the lower measurement wins. */
	round_trip(p, 40, 4);
	assert(path_best(&a, 44) == 1);

	/* Loss is measurement too: enough of it beats a lower round trip. */
	for (i = 0; i < 4; i++) {
		path_probe_sent(&a.p[1], 4000 + (uint64_t)i, 44);
		path_probe_expire(&a.p[1], 44 + 4 * PATH_LOSS_WAIT_MS);
	}
	assert(path_loss_ppt(&a.p[1]) == 800);
	a.p[1].last_pong_ms = 44;
	assert(path_bucket(&a.p[1]) > path_bucket(&a.p[0]));
	assert(path_best(&a, 100) == 0);

	/* The peer's view is taken into account through a commutative function,
	 * so a path the peer sees as bad is bad here too. */
	path_table_init(&a);
	p = add(&a, addr[0], 5000, 0);
	round_trip(p, 0, 10);
	p = add(&a, addr[1], 5000, 0);
	round_trip(p, 0, 12);
	assert(path_best(&a, 12) == 0);
	path_peer_view(&a.p[0], 300, 0);
	assert(path_best(&a, 12) == 1);
	assert(path_cost(&a.p[0]) == 300);
}

static void warm(struct path *p, uint64_t now)
{
	p->qualified = 1;
	p->last_pong_ms = now;
}

static void bucketed(struct path *p, int srtt_ms)
{
	p->srtt8 = srtt_ms * 8;
	p->peer_srtt_ms = 0;
	p->peer_loss_ppt = 0;
	p->loss_reg = 0;
	p->loss_n = 0;
}

/*
 * Near-equal paths must not flap: a candidate has to win by PATH_SWITCH_MARGIN
 * buckets over PATH_SWITCH_HOLD consecutive evaluations, one evaluation per
 * PATH_KEEP_MS, and a single miss resets the count. But hysteresis gates only a
 * contest inside one warmth tier -- a demotion of the incumbent moves the
 * session at once, so a dying path never holds it for extra evaluations at
 * exactly the wrong moment.
 */
static void hysteresis_check(void)
{
	struct path_table t;
	uint64_t now = 0;
	int i;

	path_table_init(&t);
	add(&t, "2001:db8::1", 5000, 0);
	add(&t, "2001:db8::2", 5000, 0);
	warm(&t.p[0], 0);
	warm(&t.p[1], 0);
	bucketed(&t.p[0], 40);
	bucketed(&t.p[1], 60);
	assert(path_select(&t, 0) == 0);

	/* The challenger takes the lead: one evaluation is not enough. */
	bucketed(&t.p[1], 10);
	for (i = 0; i < 2; i++) {
		now += PATH_KEEP_MS;
		warm(&t.p[0], now);
		warm(&t.p[1], now);
		assert(path_select(&t, now) == (i ? 1 : 0));
	}

	/* A single miss resets the count, so the wait starts over. */
	bucketed(&t.p[0], 5);
	now += PATH_KEEP_MS;
	warm(&t.p[0], now);
	warm(&t.p[1], now);
	assert(path_select(&t, now) == 1);	/* first winning evaluation */
	bucketed(&t.p[0], 10);			/* the margin is lost */
	now += PATH_KEEP_MS;
	warm(&t.p[0], now);
	warm(&t.p[1], now);
	assert(path_select(&t, now) == 1);
	bucketed(&t.p[0], 5);
	now += PATH_KEEP_MS;
	warm(&t.p[0], now);
	warm(&t.p[1], now);
	assert(path_select(&t, now) == 1);	/* counting starts again */
	now += PATH_KEEP_MS;
	warm(&t.p[0], now);
	warm(&t.p[1], now);
	assert(path_select(&t, now) == 0);

	/* Within a tier the evaluation period is what gives the hold its unit:
	 * calling ten times as often must not shorten the wait. */
	bucketed(&t.p[0], 40);
	bucketed(&t.p[1], 1);
	for (i = 0; i < 20; i++) {
		now += PATH_KEEP_MS / 10;
		warm(&t.p[0], now);
		warm(&t.p[1], now);
		assert(path_select(&t, now) == (i >= 19 ? 1 : 0));
	}

	/* Hysteresis does not gate warmth: the moment the incumbent falls out
	 * of the tier the session moves, mid-hold and mid-period. */
	path_table_init(&t);
	add(&t, "2001:db8::1", 5000, 0);
	add(&t, "2001:db8::2", 5000, 0);
	now = 100000;
	warm(&t.p[0], now);
	warm(&t.p[1], now);
	bucketed(&t.p[0], 1);
	bucketed(&t.p[1], 400);
	assert(path_select(&t, now) == 0);
	now += PATH_WARM_MS + 1;
	warm(&t.p[1], now);
	assert(path_warmth_of(&t.p[0], now) == PATH_COLD);
	assert(path_select(&t, now) == 1);

	/* A DEAD incumbent is left at once, even for an untried path. */
	path_table_init(&t);
	add(&t, "2001:db8::1", 5000, 0);
	now = 100000;
	warm(&t.p[0], now);
	bucketed(&t.p[0], 1);
	assert(path_select(&t, now) == 0);
	add(&t, "2001:db8::2", 5000, now);
	now += PATH_DEAD_MS + 1;
	assert(path_warmth_of(&t.p[0], now) == PATH_DEAD);
	assert(path_select(&t, now) == 1);
}

/*
 * A path whose local transport cannot carry a datagram at this moment is no
 * candidate at all rather than a poor one, and an incumbent that becomes one is
 * left at once: hysteresis gates a contest between paths, never a transport
 * that has gone.
 */
static void usable_check(void)
{
	struct path_table t;
	struct path *p;
	uint64_t now = 100000;

	path_table_init(&t);
	add(&t, "2001:db8::1", 5000, 0);
	add(&t, "2001:db8::2", 5000, 0);
	warm(&t.p[0], now);
	warm(&t.p[1], now);
	bucketed(&t.p[0], 1);
	bucketed(&t.p[1], 400);
	assert(path_select(&t, now) == 0);

	/* The best-measuring path is passed over while it cannot send, and the
	 * incumbent is left the moment it cannot. */
	t.p[0].usable = 0;
	assert(path_best(&t, now) == 1);
	assert(path_select(&t, now) == 1);

	/* Nothing usable is nothing selected, whatever the table holds. */
	t.p[1].usable = 0;
	assert(path_best(&t, now) == -1);
	assert(path_select(&t, now) == -1);

	/* And the best one is back the moment its transport is. */
	t.p[0].usable = 1;
	t.p[1].usable = 1;
	assert(path_select(&t, now) == 0);

	/* A path over a borrowed agent carries nothing until the owner of the
	 * agent says it has nominated a pair. */
	path_table_init(&t);
	p = path_table_add(&t, PATH_ICE, NULL, (struct nat_agent *)&t, 0);
	assert(p && !p->usable);
	assert(path_select(&t, 0) == -1);
	p->usable = 1;
	assert(path_select(&t, 0) == 0);
}

/*
 * Add, never replace. An endpoint seen for the first time mid-session enters as
 * one more candidate and ranking decides whether it ever carries anything; it
 * never displaces the endpoint in use, so a late datagram from an address that
 * has gone away cannot flap the binding. When the table is full it is the
 * worst-ranked path not carrying the session that goes, never the newcomer,
 * which arrived with evidence that it works.
 */
static void adopt_check(void)
{
	struct path_table t;
	struct path *p;
	uint64_t now = 100000;
	int i;

	path_table_init(&t);
	p = add(&t, "2001:db8::1", 5000, now);
	round_trip(p, now, 40);
	assert(path_select(&t, now) == 0);

	/* The newcomer joins the table without taking the session. */
	p = add(&t, "2001:db8::2", 5000, now);
	assert(path_table_count(&t) == 2);
	assert(path_warmth_of(p, now) == PATH_UNQUALIFIED);
	assert(path_select(&t, now) == 0);

	/* Nor does it take it the moment it measures better: the margin has to
	 * hold, so an endpoint turning up mid-session cannot yank the binding. */
	now += PATH_KEEP_MS;
	round_trip(p, now, 1);
	warm(&t.p[0], now);
	assert(path_bucket(&t.p[1]) < path_bucket(&t.p[0]));
	assert(path_select(&t, now) == 0);
	now += PATH_KEEP_MS;
	warm(&t.p[0], now);
	warm(&t.p[1], now);
	assert(path_select(&t, now) == 1);

	/* Full, and nothing DEAD: the worst-ranked path that is not carrying the
	 * session goes, oldest first between equals. */
	path_table_init(&t);
	for (i = 0; i < PATH_TABLE_MAX; i++) {
		p = add(&t, "2001:db8::1", (uint16_t)(5000 + i), now + i);
		warm(p, now);
		bucketed(p, 10 * (i + 1));
	}
	assert(path_select(&t, now) == 0);
	p = add(&t, "2001:db8::9", 9999, now);
	assert(p && path_index(&t, p) == 1);
	assert(path_table_count(&t) == PATH_TABLE_MAX);
	assert(t.sel == 0);
}

/*
 * An endpoint the peer advertises over CTLM_CAND is a claim, not evidence:
 * nothing has been seen to arrive from it. It therefore takes a free slot or
 * one a DEAD path is holding, and where there is neither it is declined --
 * a multi-homed peer naming more endpoints than PATH_TABLE_MAX must not be able to
 * churn the paths that are answering, and must never touch the one in use.
 */
static void offer_check(void)
{
	struct sockaddr_in6 sa;
	struct path_table t;
	struct path *p;
	uint64_t now = 100000;
	int i;

	path_table_init(&t);
	sa = sa6("2001:db8::1", 5000);
	p = path_table_offer(&t, PATH_ROUTED, &sa, now);
	assert(p && path_table_count(&t) == 1);
	/* An endpoint already named is the path already naming it, not a second
	 * one, so re-advertising costs nothing. */
	assert(path_table_offer(&t, PATH_ROUTED, &sa, now) == p);
	assert(path_table_count(&t) == 1);

	/* Full and everything answering: declined outright. */
	for (i = 1; i < PATH_TABLE_MAX; i++) {
		p = add(&t, "2001:db8::1", (uint16_t)(5000 + i), now);
		warm(p, now);
	}
	warm(&t.p[0], now);
	assert(path_select(&t, now) == 0);
	sa = sa6("2001:db8::9", 9999);
	assert(path_table_offer(&t, PATH_ROUTED, &sa, now) == NULL);
	assert(path_table_count(&t) == PATH_TABLE_MAX);

	/* A path that has gone DEAD is holding a slot nothing is using, and an
	 * advertised endpoint may have it. */
	now += PATH_DEAD_MS + 1;
	warm(&t.p[0], now);
	warm(&t.p[1], now);
	warm(&t.p[2], now);
	assert(path_warmth_of(&t.p[3], now) == PATH_DEAD);
	assert(path_select(&t, now) == 0);
	p = path_table_offer(&t, PATH_ROUTED, &sa, now);
	assert(p && path_index(&t, p) == 3);

	/* Never the path in use, even when it is the only DEAD one. */
	path_table_init(&t);
	for (i = 0; i < PATH_TABLE_MAX; i++)
		add(&t, "2001:db8::2", (uint16_t)(6000 + i), now);
	warm(&t.p[0], now);
	assert(path_select(&t, now) == 0);
	now += PATH_DEAD_MS + 1;
	for (i = 1; i < PATH_TABLE_MAX; i++)
		warm(&t.p[i], now);
	assert(path_warmth_of(&t.p[0], now) == PATH_DEAD);
	assert(t.sel == 0);
	sa = sa6("2001:db8::9", 9999);
	assert(path_table_offer(&t, PATH_ROUTED, &sa, now) == NULL);
}

int main(void)
{
	endpoint_check();
	probe_codec_check();
	id_check();
	cost_check();
	table_check();
	warmth_check();
	cadence_check();
	measure_check();
	loss_outcome_check();
	tail_check();
	order_check();
	hysteresis_check();
	usable_check();
	adopt_check();
	offer_check();
	return 0;
}
