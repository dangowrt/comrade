/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

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

int main(void)
{
	what_is_posted_is_taken_once();
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
