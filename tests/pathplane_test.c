/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "pathplane.h"

#define MAGIC 0x50504c4eu

static const uint8_t base_key[32] = {
	9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};

/* One end: its key schedule, its plane, and what it last put on the wire. */
struct end {
	struct probeplane pp;
	struct pathplane pl;
	struct pathplane_sinks k;
	struct sockaddr_in6 here;	/* where the other end reaches it */
	uint8_t sent[PROBE_MAX];
	size_t sent_len;
	int sends;
	int qualified;
	int heard;
	int other;
	int other_held;
	int freed;			/* carriers this end let go */
	struct nat_agent *last_freed;
	void *last_ctx;
	int fail_agents;		/* every carrier says it has given up */
	const char *ident;
};

static void addr_of(struct sockaddr_in6 *sa, uint8_t last, uint16_t port)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons(port);
	sa->sin6_addr.s6_addr[0] = 0x20;
	sa->sin6_addr.s6_addr[1] = 0x01;
	sa->sin6_addr.s6_addr[15] = last;
}

static void on_send(void *arg, enum path_kind kind, struct nat_agent *agent,
		    const struct sockaddr_in6 *to, const uint8_t *b, size_t n)
{
	struct end *e = arg;

	(void)kind;
	(void)agent;
	(void)to;
	assert(n <= sizeof(e->sent));
	memcpy(e->sent, b, n);
	e->sent_len = n;
	e->sends++;
}

static void on_ident(void *arg, char *out, size_t n)
{
	struct end *e = arg;

	snprintf(out, n, "%s", e->ident ? e->ident : "");
}

static void on_qualified(void *arg)
{
	((struct end *)arg)->qualified++;
}

static void on_heard(void *arg, uint64_t now)
{
	(void)now;
	((struct end *)arg)->heard++;
}

static void on_other(void *arg, const struct path_probe *pr,
		     enum path_kind kind, int held)
{
	struct end *e = arg;

	(void)pr;
	(void)kind;
	e->other++;
	e->other_held = held;
}

/* Everything on the same wire, so an advertised neighbour is a segment. */
static enum path_kind on_kind_of(void *arg, const struct path_ep *ep)
{
	(void)arg;
	(void)ep;

	return PATH_SEGMENT;
}

static void on_agent_free(void *arg, struct nat_agent *a, void *ctx)
{
	struct end *e = arg;

	e->last_freed = a;
	e->last_ctx = ctx;
	e->freed++;
}

static int on_agent_failed(void *arg, struct nat_agent *a)
{
	(void)a;

	return ((struct end *)arg)->fail_agents;
}

static void end_init(struct end *e, uint8_t last, const char *ident)
{
	memset(e, 0, sizeof(*e));
	e->ident = ident;
	addr_of(&e->here, last, 5000 + last);
	probeplane_init(&e->pp, MAGIC, base_key, 1000 * last);
	pathplane_init(&e->pl, &e->pp);
	e->k.send = on_send;
	e->k.ident = on_ident;
	e->k.kind_of = on_kind_of;
	e->k.heard = on_heard;
	e->k.qualified = on_qualified;
	e->k.other = on_other;
	e->k.agent_free = on_agent_free;
	e->k.agent_failed = on_agent_failed;
	e->k.arg = e;
}

static void end_done(struct end *e)
{
	pathplane_destroy(&e->pl);
	probeplane_destroy(&e->pp);
}

/* Hand what `from` last sent to `to`, as arriving from `from`'s address. */
static int deliver(struct end *from, struct end *to, uint64_t now)
{
	assert(from->sent_len);

	return pathplane_recv(&to->pl, &to->k, from->sent, from->sent_len,
			      PATH_SEGMENT, &from->here, NULL, now);
}

/*
 * The round trip the whole plane exists for: a path is entered, probed, and
 * carries nothing until an answer has come back on it.
 */
static void a_path_qualifies_only_once_it_answers(void)
{
	struct end a, b;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");
	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	assert(!pathplane_any_qualified(&a.pl));

	pathplane_tick(&a.pl, &a.k, 1000);
	assert(a.sends == 1);
	assert(pathplane_is_probe(&b.pl, a.sent, a.sent_len));
	assert(deliver(&a, &b, 1010));		/* b answers the ping */
	assert(b.heard == 1);
	assert(b.sends == 1);
	assert(!a.qualified);

	assert(deliver(&b, &a, 1020));		/* and the pong comes back */
	assert(a.qualified == 1);
	assert(pathplane_any_qualified(&a.pl));
	end_done(&a);
	end_done(&b);
}

/* A probe carrying somebody else's identity is not ours, whatever key opened
 * it. */
static void a_probe_for_another_claimant_is_refused(void)
{
	struct end a, b;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "efgh");
	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	pathplane_tick(&a.pl, &a.k, 1000);
	assert(a.sends == 1);
	assert(!deliver(&a, &b, 1010));
	assert(!b.heard);
	assert(!b.sends);
	end_done(&a);
	end_done(&b);
}

/* The same frame twice is one frame: the second is a replay. */
static void a_probe_is_acted_on_once(void)
{
	struct end a, b;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");
	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	pathplane_tick(&a.pl, &a.k, 1000);
	assert(deliver(&a, &b, 1010));
	assert(!deliver(&a, &b, 1011));
	assert(b.sends == 1);
	end_done(&a);
	end_done(&b);
}

/*
 * A ping from a source no path names adds one: an end whose address changed
 * keeps the session by probing from the new one.
 */
static void a_ping_from_a_new_source_is_adopted(void)
{
	struct path_ep ep;
	struct end a, b;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");
	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	pathplane_tick(&a.pl, &a.k, 1000);
	assert(!path_ep_from_sockaddr(&ep, (struct sockaddr *)&a.here,
				      sizeof(a.here)));
	assert(!pathplane_holds_ep(&b.pl, &ep, 1));
	assert(deliver(&a, &b, 1010));
	assert(pathplane_holds_ep(&b.pl, &ep, 1));
	assert(pathplane_lan_paths(&b.pl, 0) == 1);
	end_done(&a);
	end_done(&b);
}

/* A peer may say where it is; it may not say "everywhere", and it may not name
 * this end. */
static void an_advertised_endpoint_must_be_one_other_host(void)
{
	struct sockaddr_in6 group, zero;
	struct path_ep ep;
	struct end a, b;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");

	memset(&group, 0, sizeof(group));
	group.sin6_family = AF_INET6;
	group.sin6_port = htons(5002);
	group.sin6_addr.s6_addr[0] = 0xff;	/* ff02::1, all nodes */
	group.sin6_addr.s6_addr[1] = 0x02;
	group.sin6_addr.s6_addr[15] = 1;
	pathplane_offer_path(&a.pl, &a.k, &group, 1000);
	assert(pathplane_lan_paths(&a.pl, 0) == 0);

	memset(&zero, 0, sizeof(zero));
	zero.sin6_family = AF_INET6;
	zero.sin6_port = htons(5002);
	pathplane_offer_path(&a.pl, &a.k, &zero, 1000);
	assert(pathplane_lan_paths(&a.pl, 0) == 0);

	pathplane_offer_path(&a.pl, &a.k, &b.here, 1000);
	assert(pathplane_lan_paths(&a.pl, 0) == 1);
	assert(!path_ep_from_sockaddr(&ep, (struct sockaddr *)&b.here,
				      sizeof(b.here)));
	assert(pathplane_holds_ep(&a.pl, &ep, 1));
	/* Offering it again names the path it already holds. */
	pathplane_offer_path(&a.pl, &a.k, &b.here, 1100);
	assert(pathplane_lan_paths(&a.pl, 0) == 1);
	end_done(&a);
	end_done(&b);
}

/*
 * Opening a frame costs a decryption, so a source no path names may only make
 * this end pay while the budget has a token.
 */
static void an_unknown_source_spends_a_budget(void)
{
	uint8_t frame[PROBE_MAX];
	struct path_adopt budget;
	struct path_ep held, ep;
	struct end a, b;
	int i, refused = 0;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");
	memset(&budget, 0, sizeof(budget));
	memset(&ep, 0, sizeof(ep));
	ep.port = 9999;
	ep.addr[15] = 42;
	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	pathplane_tick(&a.pl, &a.k, 1000);
	memcpy(frame, a.sent, a.sent_len);

	/* Stream data never reaches the budget at all. */
	assert(pathplane_gate(&a.pl, &budget, MAGIC, &ep, (uint8_t *)"xxxx", 4,
			      1000));

	assert(!path_ep_from_sockaddr(&held, (struct sockaddr *)&b.here,
				      sizeof(b.here)));
	/* A source the plane already holds is ordinary traffic. */
	for (i = 0; i < 64; i++)
		assert(pathplane_gate(&a.pl, &budget, MAGIC, &held, frame,
				      a.sent_len, 1000));

	for (i = 0; i < 64; i++)
		if (!pathplane_gate(&a.pl, &budget, MAGIC, &ep, frame,
				    a.sent_len, 1000))
			refused++;
	assert(refused);
	end_done(&a);
	end_done(&b);
}

/*
 * Which plane a frame from an unknown source belongs to is answered by which
 * key opens it and by the identity inside, never by where it came from.
 */
static void a_claim_is_answered_by_the_key_and_the_name(void)
{
	struct path_probe pr;
	struct end a, b, c;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");
	end_init(&c, 3, "efgh");
	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	pathplane_tick(&a.pl, &a.k, 1000);

	assert(pathplane_claims(&b.pl, &b.k, a.sent, a.sent_len, &pr) == 1);
	assert(pr.type == PROBE_PING);
	/* A second look at the same frame is a replay, not another claim. */
	assert(pathplane_claims(&b.pl, &b.k, a.sent, a.sent_len, &pr) == -1);
	/* And it was never c's. */
	assert(pathplane_claims(&c.pl, &c.k, a.sent, a.sent_len, &pr) == 0);
	end_done(&a);
	end_done(&b);
	end_done(&c);
}

/*
 * A probe the plane does not own goes to the playbook, with whether it arrived
 * where the session is actually carried.
 */
static void a_probe_the_plane_does_not_own_is_handed_on(void)
{
	struct path_probe pr;
	struct end a, b;
	size_t n;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");
	memset(&pr, 0, sizeof(pr));
	pr.type = PROBE_FRESH;
	pr.have_tail = 1;
	n = probeplane_seal(&a.pp, &pr, "abcd", a.sent, PROBE_MAX);
	assert(n);
	a.sent_len = n;

	assert(deliver(&a, &b, 1010));		/* from a source b has never
						 * heard from */
	assert(b.other == 1);
	assert(!b.other_held);

	assert(!pathplane_add_ep(&b.pl, &b.k, PATH_SEGMENT, &a.here, NULL, 0,
				 1000));
	pr.type = PROBE_FRESH;
	n = probeplane_seal(&a.pp, &pr, "abcd", a.sent, PROBE_MAX);
	assert(n);
	a.sent_len = n;
	assert(deliver(&a, &b, 1020));
	assert(b.other == 2);
	assert(b.other_held);
	end_done(&a);
	end_done(&b);
}

/* This end's own ping, reflected back, is not a question anyone asked it. */
static void our_own_outstanding_nonce_is_not_answered(void)
{
	struct end a;

	end_init(&a, 1, "abcd");
	addr_of(&a.here, 2, 5002);
	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &a.here, NULL, 0,
				 1000));
	pathplane_tick(&a.pl, &a.k, 1000);
	assert(a.sends == 1);
	assert(deliver(&a, &a, 1010));		/* opened, and then refused */
	assert(a.sends == 1);
	end_done(&a);
}

/* Nothing is probed under an identity this end does not have yet. */
static void nothing_is_probed_without_an_identity(void)
{
	struct end a, b;

	end_init(&a, 1, NULL);
	end_init(&b, 2, "abcd");
	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	pathplane_tick(&a.pl, &a.k, 1000);
	assert(!a.sends);
	a.ident = "abcd";
	pathplane_tick(&a.pl, &a.k, 1000);
	assert(a.sends == 1);
	end_done(&a);
	end_done(&b);
}

/*
 * The ranking is by measurement, and what is read off it says what has been
 * proven rather than what is merely held.
 */
static void the_carry_is_read_off_the_ranking(void)
{
	struct pathplane_pick pick;
	struct end a, b;
	int rtt = -1;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");
	assert(pathplane_pick(&a.pl, &a.k, 1000, &pick) == -1);
	assert(pick.kind == -1);		/* nothing to carry on */
	assert(!pathplane_proven(&a.pl));
	assert(!pathplane_carry_rtt(&a.pl, &rtt));

	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	assert(!pathplane_pick(&a.pl, &a.k, 1000, &pick));
	assert(pick.kind == PATH_SEGMENT);
	assert(pick.moved);			/* it began carrying here */
	assert(!pick.qualified);		/* but nothing has answered */
	assert(!pathplane_proven(&a.pl));
	assert(!pathplane_carry_rtt(&a.pl, &rtt));

	pathplane_tick(&a.pl, &a.k, 1000);
	assert(deliver(&a, &b, 1010));
	assert(deliver(&b, &a, 1020));
	assert(!pathplane_pick(&a.pl, &a.k, 1020, &pick));
	assert(pick.qualified);
	assert(!pick.moved);			/* the same path still */
	assert(pathplane_proven(&a.pl) == 1);
	assert(pathplane_carry_rtt(&a.pl, &rtt));
	assert(rtt >= 0);
	end_done(&a);
	end_done(&b);
}

/*
 * A carrier being replaced is set aside, not destroyed: it stopped answering,
 * which is also what a drop that ends in a moment looks like. It is let go
 * once its time is up, and at once if it says it has given up.
 */
static void a_carrier_set_aside_is_kept_until_its_time_is_up(void)
{
	struct nat_agent *a1 = (struct nat_agent *)0x1001;
	struct nat_agent *a2 = (struct nat_agent *)0x1002;
	struct nat_agent *held[PATHPLANE_HOLD_MAX];
	struct end a;

	end_init(&a, 1, "abcd");
	assert(!pathplane_has_hold(&a.pl));
	assert(pathplane_hold_carrying(&a.pl) == -1);

	pathplane_hold_add(&a.pl, &a.k, a1, (void *)0x2001, 5000);
	pathplane_hold_add(&a.pl, &a.k, a2, (void *)0x2002, 9000);
	assert(pathplane_has_hold(&a.pl));
	assert(pathplane_holds_agents(&a.pl, held, PATHPLANE_HOLD_MAX) == 2);
	assert(held[0] == a1 && held[1] == a2);
	assert(!a.freed);

	pathplane_holds_reap(&a.pl, &a.k, 4999);
	assert(!a.freed);			/* neither is out of time */
	pathplane_holds_reap(&a.pl, &a.k, 5000);
	assert(a.freed == 1);
	assert(a.last_freed == a1);
	assert(a.last_ctx == (void *)0x2001);
	assert(pathplane_holds_agents(&a.pl, held, PATHPLANE_HOLD_MAX) == 1);

	/* One that has given up goes without waiting for its deadline. */
	a.fail_agents = 1;
	pathplane_holds_reap(&a.pl, &a.k, 5001);
	assert(a.freed == 2);
	assert(a.last_freed == a2);
	assert(!pathplane_has_hold(&a.pl));
	end_done(&a);
}

/* The one that carries is never the one let go. */
static void the_carrier_that_carries_is_not_reaped(void)
{
	struct nat_agent *a1 = (struct nat_agent *)0x1001;
	struct end a;

	end_init(&a, 1, "abcd");
	pathplane_add_ice(&a.pl, a1, 1000);
	pathplane_hold_add(&a.pl, &a.k, a1, (void *)0x2001, 5000);
	/* Rank it: with no carriers named, every path can carry. */
	a.k.live = NULL;
	{
		struct pathplane_pick pick;

		assert(!pathplane_pick(&a.pl, &a.k, 1000, &pick));
		assert(pick.kind == PATH_ICE);
	}
	assert(pathplane_hold_carrying(&a.pl) == 0);

	a.fail_agents = 1;
	pathplane_holds_reap(&a.pl, &a.k, 9000);
	assert(!a.freed);			/* it is the one carrying */
	assert(pathplane_has_hold(&a.pl));

	pathplane_holds_free_all(&a.pl, &a.k);
	assert(a.freed == 1);
	assert(!pathplane_has_hold(&a.pl));
	end_done(&a);
}

/*
 * A path cannot be removed for real without CAP_NET_ADMIN, so the hook stops
 * this end sending on it: the probes that keep a path warm are ours, so it
 * falls silent at both ends.
 */
static void a_blackholed_path_stops_being_probed(void)
{
	struct pathplane_pick pick;
	struct end a, b;

	end_init(&a, 1, "abcd");
	end_init(&b, 2, "abcd");
	assert(pathplane_blackhole_kind(&a.pl) == -1);
	assert(!pathplane_blackhole_armed(&a.pl));
	assert(!pathplane_muted(&a.pl));

	assert(!pathplane_add_ep(&a.pl, &a.k, PATH_SEGMENT, &b.here, NULL, 0,
				 1000));
	pathplane_tick(&a.pl, &a.k, 1000);
	assert(a.sends == 1);

	pathplane_blackhole_arm(&a.pl, PATH_SEGMENT, &b.here);
	assert(pathplane_blackhole_kind(&a.pl) == PATH_SEGMENT);
	assert(pathplane_blackhole_armed(&a.pl));
	pathplane_tick(&a.pl, &a.k, 1000 + PATH_KEEP_MS);
	assert(a.sends == 1);			/* the probe was not sent */
	assert(!pathplane_pick(&a.pl, &a.k, 1000, &pick));
	assert(pick.blackholed);

	pathplane_blackhole_lift(&a.pl);
	assert(!pathplane_blackhole_armed(&a.pl));
	pathplane_tick(&a.pl, &a.k, 1000 + 2 * PATH_KEEP_MS);
	assert(a.sends == 2);

	/* Muting takes every path away, whatever kind it is. */
	pathplane_blackhole_mute(&a.pl, 1);
	assert(pathplane_muted(&a.pl));
	assert(pathplane_blackhole_armed(&a.pl));
	assert(pathplane_blackhole_kind(&a.pl) == -1);	/* none by path */
	pathplane_tick(&a.pl, &a.k, 1000 + 3 * PATH_KEEP_MS);
	assert(a.sends == 2);
	end_done(&a);
	end_done(&b);
}

int main(void)
{
	a_path_qualifies_only_once_it_answers();
	a_blackholed_path_stops_being_probed();
	a_carrier_set_aside_is_kept_until_its_time_is_up();
	the_carrier_that_carries_is_not_reaped();
	the_carry_is_read_off_the_ranking();
	a_probe_for_another_claimant_is_refused();
	a_probe_is_acted_on_once();
	a_ping_from_a_new_source_is_adopted();
	an_advertised_endpoint_must_be_one_other_host();
	an_unknown_source_spends_a_budget();
	a_claim_is_answered_by_the_key_and_the_name();
	a_probe_the_plane_does_not_own_is_handed_on();
	our_own_outstanding_nonce_is_not_answered();
	nothing_is_probed_without_an_identity();
	printf("pathplane_test: ok\n");

	return 0;
}
