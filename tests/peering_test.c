/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "wsock.h"

#include "hbeat.h"
#include "peering.h"

/* What a producer thread posts, the loop takes, and nothing is left behind. */
static void what_is_posted_is_taken_once(void)
{
	struct nsfact out[NSFACTS_OUT];
	struct peering_facts f;
	uint8_t a[4] = { 198, 51, 100, 9 };

	peering_facts_init(&f);
	assert(!peering_facts_take(&f, out, NSFACTS_OUT));

	peering_facts_post(&f, NSF_ROUNDTRIP, 4, 3);
	peering_facts_post_addr(&f, 4, 3, a, "198.51.100.9");
	assert(peering_facts_take(&f, out, NSFACTS_OUT) == 2);
	assert(!peering_facts_take(&f, out, NSFACTS_OUT));
	peering_facts_destroy(&f);
}

/*
 * A fact is fed under the epoch the MODEL is on, not the one it was posted
 * with: a playbook holding a model per peer stamps what it learns with its own
 * generation and hands it to each of them under theirs.
 */
static void a_fact_is_fed_under_the_model_s_own_epoch(void)
{
	const struct netstate_row *rows;
	struct nsfact out[NSFACTS_OUT];
	struct peering_facts f;
	struct netstate ns;
	uint8_t a[4] = { 198, 51, 100, 9 };

	peering_facts_init(&f);
	netstate_init(&ns, 1, 1000);
	/* Posted under a generation of the machine's own, which is not the
	 * epoch this model counts in. */
	peering_facts_post_addr(&f, 4, 77, a, "198.51.100.9");
	assert(peering_facts_take(&f, out, NSFACTS_OUT) == 1);

	assert(!peering_facts_feed(&ns, &out[0], 77, 1000));
	assert(!netstate_rows(&ns, 4, &rows));	/* not this model's epoch */

	assert(!peering_facts_feed(&ns, &out[0], netstate_epoch(&ns, 4), 1000));
	assert(netstate_rows(&ns, 4, &rows) == 1);
	assert(!strcmp(rows[0].text, "198.51.100.9"));
	assert(rows[0].scope == NET_SCOPE_GLOBAL);
	peering_facts_destroy(&f);
}

/* An address is classified by scope as it is fed, since that is what the model
 * ranks it on. */
static void an_address_is_classified_as_it_is_fed(void)
{
	const struct netstate_row *rows;
	struct peering_facts f;
	struct nsfact q;
	struct netstate ns;
	uint8_t a[4] = { 100, 64, 0, 1 };

	peering_facts_init(&f);
	netstate_init(&ns, 1, 1000);
	memset(&q, 0, sizeof(q));
	q.kind = NSF_ADDR;
	q.family = 4;
	memcpy(q.addr, a, 4);
	snprintf(q.text, sizeof(q.text), "100.64.0.1");

	assert(!peering_facts_feed(&ns, &q, netstate_epoch(&ns, 4), 1000));
	assert(netstate_rows(&ns, 4, &rows) == 1);
	assert(rows[0].scope == NET_SCOPE_CGNAT);
	peering_facts_destroy(&f);
}

/*
 * Only the end of a round says so, because that is the caller's cue to reap
 * the thread that posted it.
 */
static void only_a_round_s_end_says_so(void)
{
	struct peering_facts f;
	struct nsfact q;
	struct netstate ns;

	peering_facts_init(&f);
	netstate_init(&ns, 1, 1000);
	memset(&q, 0, sizeof(q));
	q.family = 4;
	q.epoch = netstate_epoch(&ns, 4);

	q.kind = NSF_ROUNDTRIP;
	assert(!peering_facts_feed(&ns, &q, q.epoch, 1000));
	q.kind = NSF_PROBE_DONE;
	assert(peering_facts_feed(&ns, &q, q.epoch, 1000));
	peering_facts_destroy(&f);
}

/*
 * Every distinct egress address is kept, because a carrier that maps per
 * destination shows a different one to each server it is asked through.
 */
static void every_distinct_egress_address_is_kept(void)
{
	uint8_t out[PEERING_POOL4_MAX][4];
	struct peering_pool p;
	uint8_t a[4] = { 198, 51, 100, 1 };
	uint8_t b[4] = { 198, 51, 100, 2 };
	uint8_t zero[4] = { 0, 0, 0, 0 };
	int i;

	peering_pool_init(&p);
	assert(!peering_pool_count(&p));

	assert(peering_pool_note(&p, a) == 1);
	assert(!peering_pool_note(&p, a));	/* the same one, once */
	assert(peering_pool_note(&p, b) == 2);
	assert(peering_pool_count(&p) == 2);

	/* A placeholder is nowhere a carrier maps this machine to. */
	assert(!peering_pool_note(&p, zero));
	assert(peering_pool_count(&p) == 2);

	assert(peering_pool_copy(&p, out) == 2);
	assert(!memcmp(out[0], a, 4));
	assert(!memcmp(out[1], b, 4));

	/* The cap bounds what one network can make this machine remember. */
	for (i = 0; i < 32; i++) {
		uint8_t x[4] = { 198, 51, 101, 0 };

		x[3] = (uint8_t)(i + 1);
		peering_pool_note(&p, x);
	}
	assert(peering_pool_count(&p) == PEERING_POOL4_MAX);
	peering_pool_destroy(&p);
}

/*
 * The mapping verdict is about one socket, so it is forgotten at the top of a
 * round; the pool is about the carrier, so it is not.
 */
static void a_round_forgets_the_samples_and_keeps_the_pool(void)
{
	struct peering_pool p;
	uint8_t a[4] = { 198, 51, 100, 1 };
	uint8_t b[4] = { 198, 51, 100, 2 };

	peering_pool_init(&p);
	assert(peering_pool_mapping(&p) == STUN_MAPPING_UNKNOWN);

	peering_pool_note(&p, a);
	peering_pool_sample(&p, a, 4000);
	peering_pool_sample(&p, a, 4000);
	assert(peering_pool_mapping(&p) == STUN_MAPPING_INDEPENDENT);
	assert(peering_pool_port_stable(&p));

	peering_pool_round(&p);
	assert(peering_pool_mapping(&p) == STUN_MAPPING_UNKNOWN);
	assert(peering_pool_count(&p) == 1);	/* the carrier's, not the socket's */

	peering_pool_note(&p, b);
	peering_pool_sample(&p, a, 4000);
	peering_pool_sample(&p, b, 4001);
	assert(peering_pool_mapping(&p) == STUN_MAPPING_DEPENDENT);
	assert(!peering_pool_port_stable(&p));	/* and the fan cannot survive it */
	peering_pool_destroy(&p);
}

/* A move: every address seen before it belongs to the network we have left. */
static void a_move_empties_the_pool(void)
{
	struct peering_pool p;
	uint8_t a[4] = { 198, 51, 100, 1 };

	peering_pool_init(&p);
	peering_pool_note(&p, a);
	peering_pool_sample(&p, a, 4000);
	peering_pool_sample(&p, a, 4000);
	peering_pool_reset(&p);
	assert(!peering_pool_count(&p));
	assert(peering_pool_mapping(&p) == STUN_MAPPING_UNKNOWN);
	/* And it is the same address again on the next network, as news. */
	assert(peering_pool_note(&p, a) == 1);
	peering_pool_destroy(&p);
}

/*
 * The three planes a pair needs are wired to each other, in the order that
 * makes that possible: both of the others hold the key schedule.
 */
static void the_three_planes_are_wired_to_each_other(void)
{
	static const uint8_t key[32] = { 7, 7, 7 };
	static const uint8_t half_a[KEYS_HALF_LEN] = { 1 };
	static const uint8_t half_b[KEYS_HALF_LEN] = { 2 };
	struct peering_model pm;
	struct peering pr;

	peering_model_init(&pm, 1, 1, NULL, 1000);
	peering_init(&pr, &pm, 0x50454552u, key, 500);
	assert(pr.pm == &pm);
	assert(pr.pl.pp == &pr.pp);
	assert(pr.cp.pp == &pr.pp);
	assert(pr.pp.magic == 0x50454552u);
	assert(pr.pp.seq == 500 && pr.pp.data_seq == 500);
	assert(pr.pp.base_ok && !pr.pp.pair_ready);

	/* What the channel agrees is what the paths then seal under. */
	probeplane_bind(&pr.pp, half_a, half_b);
	assert(pr.pp.pair_ready);
	assert(probeplane_tx_ready(&pr.pp));

	peering_reset(&pr);
	assert(!pr.pp.pair_ready);	/* the pair key went with the channel */
	assert(!pr.pp.pair_tx);
	assert(pr.pp.base_ok);
	assert(!pr.cp.half_sent && !pr.cp.half_seen);
	peering_destroy(&pr);
	peering_model_destroy(&pm);
}

/* A peer's frames reach a plane with nothing to send them on. */
static void quiet_send(void *arg, int type, const uint8_t *payload,
		       size_t plen)
{
	(void)arg;
	(void)type;
	(void)payload;
	(void)plen;
}

static void peer_says(struct peering *pr, int type, const uint8_t *pl,
		      size_t plen)
{
	struct ctlplane_sinks k;

	memset(&k, 0, sizeof(k));
	k.send = quiet_send;
	assert(ctlplane_on_msg(&pr->cp, &k, type, pl, plen, 0, 1000));
}

static void v6_node_said(struct peering *pr, uint8_t last, int status)
{
	uint8_t pl[CTL_RDVST_PLEN];
	struct sockaddr_in6 sa;

	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(6881);
	sa.sin6_addr.s6_addr[0] = 0x20;
	sa.sin6_addr.s6_addr[1] = 0x01;
	sa.sin6_addr.s6_addr[15] = last;
	ctl_rdv_encode(pl, 6, (struct sockaddr *)&sa);
	pl[CTL_RDV_PLEN] = (uint8_t)status;
	peer_says(pr, CTLM_RDV, pl, sizeof(pl));
}

static int holds_node(struct peering_model *pm, int family)
{
	return netstate_anchor(&pm->ns, family, NULL, NULL, NULL);
}

/*
 * A client follows the host's word, the mailbox being the host's. A host takes
 * a peer's node only for a family it has none of its own for: its own is what
 * the token names and what it serves, and a client may not move it.
 */
static void which_end_may_adopt_is_read_from_the_mailbox(void)
{
	static const uint8_t key[32] = { 4 };
	struct peering_model host, client;
	struct peering hp, cp;

	peering_model_init(&host, 1, 1, NULL, 1000);
	peering_model_init(&client, 0, 1, NULL, 1000);
	peering_init(&hp, &host, 1, key, 1);
	peering_init(&cp, &client, 1, key, 1);

	v6_node_said(&cp, 9, CTL_RDVST_PROVEN);
	peering_absorb(&cp, 1000);
	assert(holds_node(&client, 6));		/* taken as it stands */

	v6_node_said(&hp, 9, CTL_RDVST_PROVEN);
	peering_absorb(&hp, 1000);
	assert(holds_node(&host, 6));		/* it had none of its own */

	/* And now that it has one, the peer may not move it. */
	v6_node_said(&hp, 11, CTL_RDVST_PROVEN);
	peering_absorb(&hp, 1100);
	{
		uint8_t node[NETSTATE_SA_MAX];
		uint8_t nlen = 0;

		assert(netstate_anchor(&host.ns, 6, node, &nlen, NULL));
		assert(((struct sockaddr_in6 *)node)->sin6_addr.s6_addr[15]
		       == 9);
	}
	peering_destroy(&hp);
	peering_destroy(&cp);
	peering_model_destroy(&host);
	peering_model_destroy(&client);
}

/*
 * A host with no route to a family asks a peer that has one, once a period,
 * and only a peer that says it is up.
 */
static void a_host_asks_a_reachable_peer_to_rendezvous(void)
{
	static const uint8_t key[32] = { 5 };
	uint8_t reach[CTL_REACH_PLEN];
	struct peering_model pm;
	struct peering pr;

	peering_model_init(&pm, 1, 1, NULL, 1000);
	peering_init(&pr, &pm, 1, key, 1);

	/* It has not spoken, so nothing is presumed of it. */
	peering_absorb(&pr, 1000);
	assert(!pr.cp.rdvask_out);

	memset(reach, 0, sizeof(reach));
	ctl_reach_encode(reach, 1, 0, 0);		/* v6 down */
	peer_says(&pr, CTLM_REACH, reach, sizeof(reach));
	peering_absorb(&pr, 1000);
	assert(!pr.cp.rdvask_out);		/* it cannot help either */

	ctl_reach_encode(reach, 1, CTL_REACH_UP, 0);
	peer_says(&pr, CTLM_REACH, reach, sizeof(reach));
	peering_absorb(&pr, 2000);
	assert(pr.cp.rdvask_out & 2);		/* v6 asked for */

	pr.cp.rdvask_out = 0;
	peering_absorb(&pr, 2001);
	assert(!pr.cp.rdvask_out);		/* and not again this period */
	peering_absorb(&pr, 2001 + PEERING_RDVASK_MS);
	assert(pr.cp.rdvask_out & 2);
	peering_destroy(&pr);
	peering_model_destroy(&pm);
}

/* A mailbox no DHT serves has no rendezvous to name or to ask for. */
static void a_mailbox_off_the_dht_asks_nobody(void)
{
	static const uint8_t key[32] = { 6 };
	uint8_t reach[CTL_REACH_PLEN];
	struct peering_model pm;
	struct peering pr;

	peering_model_init(&pm, 1, 0, NULL, 1000);
	peering_init(&pr, &pm, 1, key, 1);
	memset(reach, 0, sizeof(reach));
	ctl_reach_encode(reach, 1, CTL_REACH_UP, 0);
	peer_says(&pr, CTLM_REACH, reach, sizeof(reach));
	peering_absorb(&pr, 2000);
	assert(!pr.cp.rdvask_out);
	peering_destroy(&pr);
	peering_model_destroy(&pm);
}

/*
 * Which server an attempt gathers through, split into storage that outlives
 * the agent because the traversal library keeps the pointer. With nothing in
 * the resolver cache the name itself is handed over, which is the cold-start
 * path.
 */
static void the_server_an_attempt_asks_walks_the_list(void)
{
	static char *servers[] = { (char *)"a.invalid:1234",
				   (char *)"b.invalid",
				   (char *)"c.invalid:0" };
	struct peering_net m;
	char host[128];
	uint16_t port;

	peering_net_init(&m, NULL, 0, 1);
	assert(peering_net_stun_pick(&m, 0, host, sizeof(host), &port) == -1);
	peering_net_destroy(&m);

	peering_net_init(&m, servers, 3, 1);
	assert(!peering_net_stun_pick(&m, 0, host, sizeof(host), &port));
	assert(!strcmp(host, "a.invalid"));
	assert(port == 1234);

	/* No port named is the well-known one, and so is a nonsense one. */
	assert(!peering_net_stun_pick(&m, 1, host, sizeof(host), &port));
	assert(!strcmp(host, "b.invalid"));
	assert(port == 3478);
	assert(!peering_net_stun_pick(&m, 2, host, sizeof(host), &port));
	assert(!strcmp(host, "c.invalid"));
	assert(port == 3478);

	/* The rotation wraps, so one that does not answer is not the only one
	 * ever asked. */
	assert(!peering_net_stun_pick(&m, 3, host, sizeof(host), &port));
	assert(!strcmp(host, "a.invalid"));
	peering_net_destroy(&m);
}

/* An identity this end fixes itself, so it survives a re-gather and the peer
 * keeps hammering one target. */
static void an_identity_is_minted_to_gather_under(void)
{
	char uf[16], uf2[16], pwd[40];
	size_t i;

	memset(uf, 'x', sizeof(uf));
	memset(pwd, 'x', sizeof(pwd));
	peering_ice_gen(uf, sizeof(uf), pwd, sizeof(pwd));
	assert(strlen(uf) == 8);
	assert(strlen(pwd) == 32);
	for (i = 0; i < strlen(uf); i++)
		assert(strchr("0123456789abcdef", uf[i]));
	for (i = 0; i < strlen(pwd); i++)
		assert(strchr("0123456789abcdef", pwd[i]));

	/* A fresh one is a different one. */
	peering_ice_gen(uf2, sizeof(uf2), pwd, sizeof(pwd));
	assert(strcmp(uf, uf2));
}

/*
 * The link verdict is about evidence: nothing proves a path but traffic
 * arriving, and it proves it only for the network it arrived on.
 */
static void the_link_verdict_follows_the_evidence(void)
{
	static const uint8_t key[32] = { 8 };
	struct peering_model pm;
	struct peering pr;

	peering_model_init(&pm, 1, 1, NULL, 1000);
	peering_init(&pr, &pm, 1, key, 1);

	/* Nothing has answered: being punched and not being reached at all are
	 * told apart by whether a carrier exists. */
	assert(peering_link(&pr, 1, 0, 1000) == CONN_CONNECTING);
	assert(peering_link(&pr, 1, 1, 1000) == CONN_PUNCHING);

	/* A pong on generation 1. */
	pr.cp.live.pong_seen = 1;
	pr.cp.live.last_pong_ms = 1000;
	pr.cp.live.rtt_ms = 10;
	pr.cp.live.live_gen = 1;
	assert(peering_link(&pr, 1, 1, 1000) == CONN_LIVE);

	/* Old enough to notice, not old enough to give up on. */
	assert(peering_link(&pr, 1, 1, 1000 + PEERING_LINK_LAG_MS) ==
	       CONN_LAGGED);

	/* Proven, but somewhere else: a move puts it back to unknown rather
	 * than leaving the last network's verdict standing. */
	assert(peering_link(&pr, 2, 1, 1000) == CONN_UNKNOWN);

	/* Latched lost, and quiet for longer than the round trip earns it. */
	pr.cp.live.lost_since_ms = 1500;
	assert(peering_link(&pr, 1, 1, 1000 + hb_lost_ms(10)) == CONN_LOST);
	peering_destroy(&pr);
	peering_model_destroy(&pm);
}

/*
 * Rotating to the next server is for an attempt that has got far enough for
 * the server to be what is wrong with it, and it is bounded, so a network that
 * filters all STUN settles rather than churning offers for ever.
 */
static void rotating_to_the_next_server_is_earned_and_bounded(void)
{
	static char *servers[] = { (char *)"a.invalid", (char *)"b.invalid" };
	struct peering_net one, two, pinned;

	peering_net_init(&one, servers, 1, 1);
	peering_net_init(&two, servers, 2, 1);
	peering_net_init(&pinned, servers, 2, 0);	/* an operator's own */

	/* Nowhere to rotate to, and nobody else's server to rotate through. */
	one.have_priv4 = 1;
	two.have_priv4 = 1;
	pinned.have_priv4 = 1;
	assert(!peering_rotate_allowed(&one));
	assert(!peering_rotate_allowed(&pinned));

	/* Without a private address the attempt has not got far enough for the
	 * server to be the thing that is wrong. */
	two.have_priv4 = 0;
	assert(!peering_rotate_allowed(&two));
	two.have_priv4 = 1;
	assert(peering_rotate_allowed(&two));

	/* And the budget is spent eventually. */
	two.rotations = PEERING_ROTATE_MAX - 1;
	assert(peering_rotate_allowed(&two));
	two.rotations = PEERING_ROTATE_MAX;
	assert(!peering_rotate_allowed(&two));
	two.rotations = 0;

	/* Wanted only once it has stalled, and never once a public address has
	 * arrived, there being nothing left to look for. */
	assert(!peering_rotate_wanted(&two, 1000, 1000 + PEERING_ROTATE_MS));
	assert(peering_rotate_wanted(&two, 1000, 1001 + PEERING_ROTATE_MS));
	two.have_srflx4 = 1;
	assert(!peering_rotate_wanted(&two, 1000, 1001 + PEERING_ROTATE_MS));
	peering_net_destroy(&one);
	peering_net_destroy(&two);
	peering_net_destroy(&pinned);
}

/*
 * The gather thread stages a description, the loop takes it exactly once.
 * Taking it does not make it the loop's copy: that happens when the caller
 * hands the canonicalised text back.
 */
static void a_gathered_description_is_taken_once(void)
{
	struct peering_desc d;
	char raw[NAT_SDP_MAX];

	peering_desc_init(&d);
	assert(!peering_desc_have(&d));
	assert(!peering_desc_take(&d, raw, sizeof(raw)));

	peering_desc_gathered(&d, "v=0\na=candidate:1 1 udp 1 10.0.0.1 1 typ host\n");
	assert(peering_desc_take(&d, raw, sizeof(raw)) == 1);
	assert(!strncmp(raw, "v=0\n", 4));
	assert(!peering_desc_take(&d, raw, sizeof(raw)));
	assert(!peering_desc_have(&d));

	peering_desc_set(&d, raw);
	assert(peering_desc_have(&d));
	assert(!strcmp(peering_desc_local(&d), raw));
	peering_desc_destroy(&d);
}

/* Canonicalising in place is what the loop does, and marking it must survive
 * the description and the buffer being one and the same. */
static void the_local_copy_may_be_rewritten_in_place(void)
{
	struct peering_desc d;

	peering_desc_init(&d);
	peering_desc_gathered(&d, "v=0\n");
	assert(peering_desc_take(&d, peering_desc_local(&d), NAT_SDP_MAX));
	peering_desc_set(&d, peering_desc_local(&d));
	assert(peering_desc_have(&d));
	assert(!strcmp(peering_desc_local(&d), "v=0\n"));
	peering_desc_destroy(&d);
}

/* Candidates accumulate as they arrive and drain in one go, one per line. */
static void candidates_accumulate_until_drained(void)
{
	struct peering_desc d;
	char out[NAT_SDP_MAX];

	peering_desc_init(&d);
	assert(!peering_desc_drain(&d, out, sizeof(out)));

	peering_desc_candidate(&d, "a=candidate:1 1 udp 1 10.0.0.1 1 typ host");
	peering_desc_candidate(&d, "a=candidate:2 1 udp 1 10.0.0.2 1 typ srflx");
	assert(peering_desc_drain(&d, out, sizeof(out)) == 1);
	assert(strstr(out, "10.0.0.1") && strstr(out, "10.0.0.2"));
	assert(strchr(out, '\n'));
	assert(!peering_desc_drain(&d, out, sizeof(out)));
	peering_desc_destroy(&d);
}

/* A candidate that does not fit is dropped whole, never half-written: the
 * drain would otherwise hand a peer a truncated line to aim at. */
static void a_candidate_that_does_not_fit_is_dropped(void)
{
	char line[NAT_SDP_MAX / 2 + 8];
	struct peering_desc d;
	char out[NAT_SDP_MAX];
	size_t first;

	memset(line, 'c', sizeof(line) - 1);
	line[sizeof(line) - 1] = '\0';
	peering_desc_init(&d);
	peering_desc_candidate(&d, line);
	peering_desc_candidate(&d, line);
	peering_desc_candidate(&d, line);
	assert(peering_desc_drain(&d, out, sizeof(out)) == 1);
	first = strlen(line) + 1;
	assert(strlen(out) == first || strlen(out) == first * 2);
	peering_desc_destroy(&d);
}

/* Dropping forgets the description; clearing forgets what the old agent's
 * gather thread had left staged as well. */
static void a_move_forgets_the_staged_work_too(void)
{
	struct peering_desc d;
	char buf[NAT_SDP_MAX];

	peering_desc_init(&d);
	peering_desc_set(&d, "v=0\n");
	peering_desc_gathered(&d, "v=0\nstaged\n");
	peering_desc_candidate(&d, "a=candidate:1 1 udp 1 10.0.0.1 1 typ host");

	peering_desc_drop(&d);
	assert(!peering_desc_have(&d));
	assert(!peering_desc_local(&d)[0]);
	assert(peering_desc_take(&d, buf, sizeof(buf)) == 1);
	peering_desc_gathered(&d, "v=0\nstaged\n");

	peering_desc_clear(&d);
	assert(!peering_desc_have(&d));
	assert(!peering_desc_take(&d, buf, sizeof(buf)));
	assert(!peering_desc_drain(&d, buf, sizeof(buf)));
	peering_desc_destroy(&d);
}

/* An offer with nothing to aim at is what must never reach the mailbox. */
static void an_offer_with_nothing_to_aim_at_is_named(void)
{
	assert(!peering_sdp_has_candidate("v=0\no=- 0 0 IN IP4 0.0.0.0\n"));
	assert(!peering_sdp_has_candidate(""));
	assert(peering_sdp_has_candidate(
		"v=0\na=candidate:1 1 udp 1 10.0.0.1 1 typ host\n"));
}

/*
 * A fresh signaller is seeded from the anchor the model holds; the name the
 * playbook was started with is taken only where it holds none, since one
 * minted long ago can point at a node that has since gone.
 */
static void the_anchor_outranks_the_name_we_started_with(void)
{
	struct sockaddr_in tokn, anch;
	struct peering_seed seed[2];
	uint8_t out[NETSTATE_SA_MAX];
	struct peering_model pm;

	memset(seed, 0, sizeof(seed));
	memset(&tokn, 0, sizeof(tokn));
	tokn.sin_family = AF_INET;
	tokn.sin_port = htons(6881);
	assert(inet_pton(AF_INET, "198.51.100.7", &tokn.sin_addr) == 1);
	memcpy(seed[0].sa, &tokn, sizeof(tokn));
	seed[0].len = (int)sizeof(tokn);

	peering_model_init(&pm, 0, 1, NULL, 1000);

	/* Neither: nothing to plant, and v6 has nothing either way. */
	assert(!peering_seed_pick(&pm, 6, &seed[1], out, sizeof(out)));

	/* Only the name we were started with. */
	assert(peering_seed_pick(&pm, 4, &seed[0], out, sizeof(out)) ==
	       (int)sizeof(tokn));
	assert(!memcmp(out, &tokn, sizeof(tokn)));

	memset(&anch, 0, sizeof(anch));
	anch.sin_family = AF_INET;
	anch.sin_port = htons(6882);
	assert(inet_pton(AF_INET, "198.51.100.9", &anch.sin_addr) == 1);
	netstate_on_rdv_offered(&pm.ns, 4, (const uint8_t *)&anch,
				(int)sizeof(anch), 1000);

	/* Now the model holds one, and it wins. */
	assert(peering_seed_pick(&pm, 4, &seed[0], out, sizeof(out)) ==
	       (int)sizeof(anch));
	assert(!memcmp(out, &anch, sizeof(anch)));

	/* A destination too small is refused outright, never half-filled. */
	assert(!peering_seed_pick(&pm, 4, &seed[0], out, 1));
	peering_model_destroy(&pm);
}

/*
 * What arrives on a path is the engine's until it says otherwise: a wrapped
 * payload comes back unwrapped as the playbook's to carry, and a staged
 * outage swallows everything.
 */
static void a_datagram_is_the_engine_s_until_it_says_otherwise(void)
{
	static const uint8_t body[5] = { 'h', 'e', 'l', 'l', 'o' };
	static const uint8_t key[32] = { 9, 9 };
	struct peering_model pm;
	uint8_t wrapped[256];
	struct peering pr;
	size_t len;

	peering_model_init(&pm, 1, 1, NULL, 1000);
	peering_init(&pr, &pm, 0x50454552u, key, 500);

	len = probeplane_wrap(&pr.pp, wrapped, sizeof(wrapped), body,
			      sizeof(body));
	assert(len > sizeof(body));
	assert(!peering_datagram(&pr, wrapped, &len, PATH_SEGMENT, NULL, NULL,
				 1000));
	assert(len == sizeof(body));
	assert(!memcmp(wrapped, body, sizeof(body)));

	len = probeplane_wrap(&pr.pp, wrapped, sizeof(wrapped), body,
			      sizeof(body));
	pathplane_blackhole_mute(&pr.pl, 1);
	assert(pathplane_muted(&pr.pl));
	assert(peering_datagram(&pr, wrapped, &len, PATH_SEGMENT, NULL, NULL,
				1000) == 1);
	pathplane_blackhole_lift(&pr.pl);
	assert(!pathplane_muted(&pr.pl));

	peering_destroy(&pr);
	peering_model_destroy(&pm);
}

/*
 * A rotation is read against the identity that primed this carrier, so the
 * primed offer's own later candidates are not mistaken for a peer that has
 * moved on, and nothing counts as a rotation before anything has primed it.
 */
static void a_rotation_is_read_against_what_primed_us(void)
{
	static const uint8_t key[32] = { 3 };
	struct peering_model pm;
	struct peering pr;

	peering_model_init(&pm, 0, 1, NULL, 1000);
	peering_init(&pr, &pm, 1, key, 1000);

	assert(!peering_ice_rotated(&pr, "abcd"));

	snprintf(pr.ice.remote_ufrag, sizeof(pr.ice.remote_ufrag), "abcd");
	assert(!peering_ice_rotated(&pr, "abcd"));
	assert(peering_ice_rotated(&pr, "efgh"));

	peering_destroy(&pr);
	peering_model_destroy(&pm);
}

int main(void)
{
	what_is_posted_is_taken_once();
	a_rotation_is_read_against_what_primed_us();
	a_datagram_is_the_engine_s_until_it_says_otherwise();
	the_anchor_outranks_the_name_we_started_with();
	a_gathered_description_is_taken_once();
	the_local_copy_may_be_rewritten_in_place();
	candidates_accumulate_until_drained();
	a_candidate_that_does_not_fit_is_dropped();
	a_move_forgets_the_staged_work_too();
	an_offer_with_nothing_to_aim_at_is_named();
	rotating_to_the_next_server_is_earned_and_bounded();
	the_link_verdict_follows_the_evidence();
	the_server_an_attempt_asks_walks_the_list();
	an_identity_is_minted_to_gather_under();
	which_end_may_adopt_is_read_from_the_mailbox();
	a_host_asks_a_reachable_peer_to_rendezvous();
	a_mailbox_off_the_dht_asks_nobody();
	the_three_planes_are_wired_to_each_other();
	every_distinct_egress_address_is_kept();
	a_round_forgets_the_samples_and_keeps_the_pool();
	a_move_empties_the_pool();
	a_fact_is_fed_under_the_model_s_own_epoch();
	an_address_is_classified_as_it_is_fed();
	only_a_round_s_end_says_so();
	printf("peering_test: ok\n");

	return 0;
}
