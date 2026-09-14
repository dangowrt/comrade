/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctlplane.h"
#include "hbeat.h"

#define MAGIC 0x43544c50u

static const uint8_t base_key[32] = {
	3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3,
	2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3, 2, 7, 9, 5
};

/* One end: its key schedule, its plane, and the frames it has written. */
struct end {
	struct probeplane pp;
	struct ctlplane cp;
	struct ctlplane_sinks k;
	/* Every frame written, in order: a single slot would lose the half a
	 * KEYOK follows. */
	int type[8];
	uint8_t pl[8][64];
	size_t plen[8];
	int n;
	int sends;
	int pongs;
	int offers;
	int others;
	int other_type;
	int refuse_ping;
};

static void on_send(void *arg, int type, const uint8_t *payload, size_t plen)
{
	struct end *e = arg;

	assert(e->n < 8);
	assert(plen <= sizeof(e->pl[0]));
	e->type[e->n] = type;
	e->plen[e->n] = plen;
	if (plen)
		memcpy(e->pl[e->n], payload, plen);
	e->n++;
	e->sends++;
}

/* The type of the frame `from` wrote last. */
static int last_type(const struct end *e)
{
	assert(e->n);

	return e->type[e->n - 1];
}

static void on_offer_path(void *arg, const struct sockaddr *sa, socklen_t len)
{
	struct end *e = arg;

	(void)sa;
	(void)len;
	e->offers++;
}

static int on_answer_ping(void *arg)
{
	return !((struct end *)arg)->refuse_ping;
}

static void on_pong(void *arg)
{
	((struct end *)arg)->pongs++;
}

static void on_other(void *arg, int type, const uint8_t *pl, size_t plen)
{
	struct end *e = arg;

	(void)pl;
	(void)plen;
	e->others++;
	e->other_type = type;
}

static void end_init(struct end *e)
{
	memset(e, 0, sizeof(*e));
	probeplane_init(&e->pp, MAGIC, base_key, 1000);
	ctlplane_init(&e->cp, &e->pp);
	e->k.send = on_send;
	e->k.offer_path = on_offer_path;
	e->k.answer_ping = on_answer_ping;
	e->k.pong = on_pong;
	e->k.other = on_other;
	e->k.arg = e;
}

static void end_done(struct end *e)
{
	ctlplane_destroy(&e->cp);
	probeplane_destroy(&e->pp);
}

/* Hand every frame `from` has written since the last delivery to `to`. */
static int deliver(struct end *from, struct end *to, unsigned netgen,
		   uint64_t now)
{
	int owned = 0, i;

	assert(from->n);
	for (i = 0; i < from->n; i++)
		owned += ctlplane_on_msg(&to->cp, &to->k, from->type[i],
					 from->pl[i], from->plen[i], netgen,
					 now);
	from->n = 0;

	return owned;
}

static void addr_of(struct sockaddr_in6 *sa, uint8_t last, uint16_t port)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons(port);
	sa->sin6_addr.s6_addr[0] = 0x20;
	sa->sin6_addr.s6_addr[15] = last;
}

/*
 * Each end offers a half; the pair key exists only once both have arrived,
 * and neither seals with it until the other says it can open one.
 */
static void the_pair_key_is_agreed_half_by_half(void)
{
	struct end a, b;

	end_init(&a);
	end_init(&b);
	assert(ctlplane_offer_key(&a.cp, &a.k));
	assert(last_type(&a) == CTLM_KEY);
	assert(!ctlplane_offer_key(&a.cp, &a.k));	/* offered once */
	assert(!a.pp.pair_ready);

	assert(deliver(&a, &b, 0, 1000));		/* b has a's half */
	assert(!b.pp.pair_ready);			/* but not its own */
	assert(ctlplane_offer_key(&b.cp, &b.k));
	assert(b.pp.pair_ready);			/* both in, on b */
	assert(last_type(&b) == CTLM_KEYOK);
	/* b wrote its half and then the KEYOK; a takes both. */
	assert(deliver(&b, &a, 0, 1010));
	assert(a.pp.pair_ready);
	assert(a.pp.pair_tx);
	assert(last_type(&a) == CTLM_KEYOK);	/* and answers in kind */
	end_done(&a);
	end_done(&b);
}

/* A ping is answered, and the answer is what measures the link. */
static void a_ping_is_answered_and_the_answer_measures(void)
{
	struct ctlplane_live live;
	struct end a, b;

	end_init(&a);
	end_init(&b);
	ctlplane_live_reset(&a.cp, 1000);
	ctlplane_liveness(&a.cp, &live);
	assert(!live.pong_seen);

	ctlplane_ping(&a.cp, &a.k, 1000);
	assert(last_type(&a) == CTLM_PING);
	assert(deliver(&a, &b, 0, 1005));
	assert(last_type(&b) == CTLM_PONG);
	assert(deliver(&b, &a, 7, 1020));
	assert(a.pongs == 1);
	ctlplane_liveness(&a.cp, &live);
	assert(live.pong_seen);
	assert(live.rtt_ms == 20);
	assert(live.last_pong_ms == 1020);
	assert(live.live_gen == 7);
	end_done(&a);
	end_done(&b);
}

/* A playbook that has to watch a link go quiet says so from the sink. */
static void a_refused_ping_is_not_answered(void)
{
	struct end a, b;

	end_init(&a);
	end_init(&b);
	b.refuse_ping = 1;
	ctlplane_ping(&a.cp, &a.k, 1000);
	assert(deliver(&a, &b, 0, 1005));
	assert(!b.sends);
	end_done(&a);
	end_done(&b);
}

/*
 * The link is lost once nothing has been heard for longer than the window the
 * round trip earns it, and live again the moment anything arrives.
 */
static void silence_past_the_window_is_a_lost_link(void)
{
	struct ctlplane_live live;
	uint64_t quiet = 0;
	struct end a, b;

	end_init(&a);
	end_init(&b);
	ctlplane_live_reset(&a.cp, 1000);
	ctlplane_ping(&a.cp, &a.k, 1000);
	assert(deliver(&a, &b, 0, 1005));
	assert(deliver(&b, &a, 1, 1010));	/* rtt 10ms */

	assert(!ctlplane_judge(&a.cp, 1020, &quiet));
	assert(quiet == 1010);
	assert(!ctlplane_lost(&a.cp));

	assert(ctlplane_judge(&a.cp, 1010 + hb_lost_ms(10) + 1, NULL));
	assert(ctlplane_lost(&a.cp));
	ctlplane_liveness(&a.cp, &live);
	assert(live.lost_since_ms == 1010 + hb_lost_ms(10) + 1);

	/* Anything authenticated, on any carrier, is the link back. */
	ctlplane_heard(&a.cp, 1010 + hb_lost_ms(10) + 2);
	assert(!ctlplane_judge(&a.cp, 1010 + hb_lost_ms(10) + 3, NULL));
	assert(!ctlplane_lost(&a.cp));
	end_done(&a);
	end_done(&b);
}

/* Nothing is judged lost before a pong has ever come back: a link that was
 * never up never goes down. */
static void a_link_never_up_is_never_lost(void)
{
	struct end a;

	end_init(&a);
	ctlplane_live_reset(&a.cp, 1000);
	assert(!ctlplane_judge(&a.cp, 1000 + 10 * hb_lost_ms(0), NULL));
	end_done(&a);
}

/* What the peer says about its rendezvous is taken once, and what it says
 * about its reach stands until it says otherwise. */
static void what_the_peer_says_is_taken_once(void)
{
	uint8_t reach[CTL_REACH_PLEN], got[CTL_REACH_PLEN];
	struct ctlplane_node nodes[2];
	struct sockaddr_in6 node;
	struct end a, b;

	end_init(&a);
	end_init(&b);
	assert(!ctlplane_take_nodes(&b.cp, nodes));

	addr_of(&node, 9, 6881);
	ctlplane_tell_rdv(&a.cp, &a.k, 6, (struct sockaddr *)&node,
			  CTL_RDVST_PROVEN);
	assert(deliver(&a, &b, 0, 1000));
	assert(ctlplane_take_nodes(&b.cp, nodes));
	assert(nodes[1].have);
	assert(nodes[1].status == CTL_RDVST_PROVEN);
	assert(!nodes[0].have);
	assert(!ctlplane_take_nodes(&b.cp, nodes));	/* taken once */

	assert(!ctlplane_peer_reach(&b.cp, got));	/* it has not spoken */
	memset(reach, 0, sizeof(reach));
	reach[0] = CTL_REACH_UP;
	ctlplane_tell_reach(&a.cp, &a.k, reach);
	assert(deliver(&a, &b, 0, 1010));
	assert(ctlplane_take_reach(&b.cp, got));
	assert(!memcmp(got, reach, sizeof(got)));
	assert(!ctlplane_take_reach(&b.cp, got));	/* the event, once */
	assert(ctlplane_peer_reach(&b.cp, got));	/* the statement, always */
	assert(!memcmp(got, reach, sizeof(got)));
	end_done(&a);
	end_done(&b);
}

/*
 * A request to rendezvous is decided by one thread and sent by another, so it
 * is noted and drained rather than sent where it is decided.
 */
static void a_request_is_noted_then_sent(void)
{
	struct end a, b;

	end_init(&a);
	end_init(&b);
	ctlplane_tell_asks(&a.cp, &a.k);
	assert(!a.sends);			/* nothing owed */

	ctlplane_ask_rdv(&a.cp, 4);
	ctlplane_ask_rdv(&a.cp, 6);
	ctlplane_tell_asks(&a.cp, &a.k);
	assert(a.sends == 2);
	assert(last_type(&a) == CTLM_RDVASK);
	a.sends = 0;
	a.n = 0;
	ctlplane_tell_asks(&a.cp, &a.k);
	assert(!a.sends);			/* drained */

	assert(!ctlplane_take_asks(&b.cp));
	ctlplane_ask_rdv(&a.cp, 6);
	ctlplane_tell_asks(&a.cp, &a.k);
	assert(deliver(&a, &b, 0, 1000));
	assert(ctlplane_take_asks(&b.cp) == 2);
	assert(!ctlplane_take_asks(&b.cp));
	end_done(&a);
	end_done(&b);
}

/* An endpoint the peer names is one more path for the playbook to enter. */
static void an_advertised_endpoint_reaches_the_playbook(void)
{
	struct sockaddr_in6 here;
	struct end a, b;

	end_init(&a);
	end_init(&b);
	addr_of(&here, 3, 5003);
	ctlplane_tell_cand(&a.cp, &a.k, 6, (struct sockaddr *)&here);
	assert(last_type(&a) == CTLM_CAND);
	assert(deliver(&a, &b, 0, 1000));
	assert(b.offers == 1);
	end_done(&a);
	end_done(&b);
}

/* What the plane does not own goes to the playbook, and is not claimed. */
static void a_message_the_plane_does_not_own_is_handed_on(void)
{
	struct end a;

	end_init(&a);
	assert(!ctlplane_on_msg(&a.cp, &a.k, CTLM_BYE, NULL, 0, 0, 1000));
	assert(a.others == 1);
	assert(a.other_type == CTLM_BYE);
	/* A frame too short to mean what it claims is not the plane's either. */
	assert(!ctlplane_on_msg(&a.cp, &a.k, CTLM_PING, NULL, 0, 0, 1000));
	assert(a.others == 2);
	assert(!a.sends);
	end_done(&a);
}

int main(void)
{
	the_pair_key_is_agreed_half_by_half();
	a_ping_is_answered_and_the_answer_measures();
	a_refused_ping_is_not_answered();
	silence_past_the_window_is_a_lost_link();
	a_link_never_up_is_never_lost();
	what_the_peer_says_is_taken_once();
	a_request_is_noted_then_sent();
	an_advertised_endpoint_reaches_the_playbook();
	a_message_the_plane_does_not_own_is_handed_on();
	printf("ctlplane_test: ok\n");

	return 0;
}
