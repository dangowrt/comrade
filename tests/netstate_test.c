/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The per-family reachability machine, driven entirely from synthetic events:
 * no network, no clock, no threads. Each named case stands for a way a roaming
 * laptop was seen to contradict itself -- a family reported up on a network
 * with none of it, a source address from the previous access point, a
 * rendezvous node shown as validated that nothing had spoken to since the
 * move. The lattice and the epoch gate then state the two rules those all
 * violate, over every combination rather than the ones somebody thought of.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "wsock.h"

#include "netstate.h"

static uint64_t t;			/* the clock, advanced by hand */

static struct netstate_actions drain(struct netstate *ns)
{
	struct netstate_actions a;

	memset(&a, 0, sizeof(a));
	netstate_take_actions(ns, &a);
	return a;
}

static void fill(uint8_t *out, int len, uint8_t seed)
{
	int i;

	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(seed + i);
}

/* What the kernel reports, as the cases hand it over. */
static struct netmon_addr snap[NETMON_MAX_ADDRS];
static size_t nsnap;

static void snap_reset(void)
{
	memset(snap, 0, sizeof(snap));
	nsnap = 0;
}

static void snap_add(int fam, const uint8_t *a)
{
	struct netmon_addr *r = &snap[nsnap++];

	r->family = fam == 6 ? AF_INET6 : AF_INET;
	r->addrlen = fam == 6 ? 16 : 4;
	memcpy(r->addr, a, r->addrlen);
}

static void snap_drop(int fam, const uint8_t *a)
{
	int af = fam == 6 ? AF_INET6 : AF_INET;
	size_t len = fam == 6 ? 16 : 4;
	size_t i;

	for (i = 0; i < nsnap; i++) {
		if (snap[i].family != af || memcmp(snap[i].addr, a, len))
			continue;
		memmove(&snap[i], &snap[i + 1],
			sizeof(snap[0]) * (nsnap - 1 - i));
		memset(&snap[--nsnap], 0, sizeof(snap[0]));
		return;
	}
}

/* One address per family: what a case that says nothing about addresses gets. */
static const uint8_t dfl4[4] = { 192, 168, 1, 2 };
static const uint8_t dfl6[16] = {
	0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};

static void snap_default(int have4, int have6)
{
	snap_reset();
	if (have4)
		snap_add(4, dfl4);
	if (have6)
		snap_add(6, dfl6);
}

/* The set as it stands now, without touching it. */
static void netmon_again(struct netstate *ns, unsigned ch)
{
	netstate_on_netmon(ns, ch, snap, nsnap, t);
}

static void netmon(struct netstate *ns, unsigned ch, int have4, int have6)
{
	snap_default(have4, have6);
	netmon_again(ns, ch);
}

/* A primed machine on a dual-stack network, nothing proven yet. */
static void start(struct netstate *ns, int is_host)
{
	t = 1000;
	netstate_init(ns, is_host, t);
	netmon(ns, 0, 1, 1);
	drain(ns);
}

/* A node enters a token only after answering steadily for long enough. */
static void qualify(struct netstate *ns, int fam, const uint8_t *node)
{
	int i;

	for (i = 0; i < NETSTATE_ANCHOR_QUALIFY; i++) {
		netstate_on_dht_ack(ns, fam, netstate_epoch(ns, fam), node, 16, t);
		t += NETSTATE_ANCHOR_PROVE_MS / NETSTATE_ANCHOR_QUALIFY + 1;
	}
	netstate_on_dht_ack(ns, fam, netstate_epoch(ns, fam), node, 16, t);
	netstate_tick(ns, t);
}

/* `n` rounds in which the held node did not answer, on a network that is up. */
static void quiet_rounds(struct netstate *ns, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		t += NETSTATE_RDV_MS;
		netstate_tick(ns, t);
	}
}

static void give_src(struct netstate *ns, int fam, uint8_t seed)
{
	uint8_t a[16];
	int len = fam == 6 ? 16 : 4;

	fill(a, len, seed);
	netstate_on_src(ns, fam, netstate_epoch(ns, fam), a, len,
			NET_SCOPE_GLOBAL, "addr", t);
}

/* B14/R6: a v6 prefix arriving is not a v4 event. The whole v4 half of the
 * machine must come through byte-identical, or freshly gathered v4 facts are
 * thrown away every time an RA lands a few seconds after DHCPv4. */
static void v6_change_leaves_v4_alone(void)
{
	struct netstate ns;
	struct netstate_fam save;
	struct netstate_actions a;

	start(&ns, 1);
	give_src(&ns, 4, 10);
	netstate_on_roundtrip(&ns, 4, netstate_epoch(&ns, 4));
	assert(netstate_conn(&ns, 4) == NET_CONN_UP);
	drain(&ns);

	save = ns.f[0];
	netmon(&ns, NETMON_CH_V6, 1, 1);

	assert(!memcmp(&save, &ns.f[0], sizeof(save)));
	assert(netstate_conn(&ns, 4) == NET_CONN_UP);
	a = drain(&ns);
	assert(a.f[0] == 0);		/* nothing owed for v4 */
	assert(a.f[1] != 0);		/* and everything for v6 */
}

/* A gain on a network we already had an address on leaves what was proven
 * there standing; a loss, or the family's first address, does not. */
static void a_gained_address_is_not_a_move(void)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	struct netstate ns;
	uint8_t extra[16];
	int n, i, direct;

	start(&ns, 1);
	fill(extra, 16, 44);
	netstate_on_reflexive(&ns, 6, netstate_epoch(&ns, 6), dfl6, 16);
	netstate_on_roundtrip(&ns, 6, netstate_epoch(&ns, 6));
	give_src(&ns, 6, 20);
	drain(&ns);
	assert(netstate_conn(&ns, 6) == NET_CONN_UP);
	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 1 && rows[0].via == NET_VIA_DIRECT);

	snap_add(6, extra);
	netmon_again(&ns, NETMON_CH_V6);
	drain(&ns);
	assert(netstate_conn(&ns, 6) == NET_CONN_UP);
	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 2);
	for (i = 0, direct = 0; i < n; i++)
		if (rows[i].via == NET_VIA_DIRECT)
			direct++;
	assert(direct == 1);

	snap_drop(6, dfl6);
	netmon_again(&ns, NETMON_CH_V6);
	drain(&ns);
	assert(netstate_conn(&ns, 6) != NET_CONN_UP);
	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 1 && rows[0].via != NET_VIA_DIRECT);
}

/* B10/B5: a confirmed anchor survives a move and stays proven: the node did
 * not move, we did. Only the family's reachability drops, until it answers
 * here too. */
static void a_confirmed_anchor_survives_a_move(void)
{
	struct netstate ns;
	struct tokgen_facts fx;
	uint8_t node[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed = -1;

	start(&ns, 1);
	fill(node, 16, 70);
	give_src(&ns, 6, 20);
	qualify(&ns, 6, node);
	assert(netstate_conn(&ns, 6) == NET_CONN_UP);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);
	drain(&ns);

	netmon(&ns, NETMON_CH_V6, 1, 1);

	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, node, 16));	/* still ours */
	assert(confirmed);		/* still proven: we moved, not it */
	/* Reachability is a different fact from the anchor's proof, and it does
	 * drop: nothing has answered us on this network yet. */
	assert(netstate_conn(&ns, 6) != NET_CONN_UP);
	netstate_facts(&ns, 6, &fx);
	assert(!fx.dht_acked);
	assert(drain(&ns).f[1] & NSA_RDV_PIN);

	/* It re-validates when it answers here, which brings reachability back;
	 * the proof it never lost is unchanged. */
	qualify(&ns, 6, node);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);
	assert(netstate_conn(&ns, 6) == NET_CONN_UP);
}

/* R5/R7: an answer stamped with a network we have left proves nothing here. */
static void stale_roundtrip_never_marks_up(void)
{
	struct netstate ns;
	uint32_t old;

	start(&ns, 1);
	old = netstate_epoch(&ns, 4);
	netmon(&ns, NETMON_CH_V4, 1, 1);
	give_src(&ns, 4, 10);

	netstate_on_roundtrip(&ns, 4, old);
	assert(netstate_conn(&ns, 4) != NET_CONN_UP);
	netstate_on_roundtrip(&ns, 4, netstate_epoch(&ns, 4));
	assert(netstate_conn(&ns, 4) == NET_CONN_UP);
}

/* B6/B12: the move happens while the link is still coming up, so the first
 * sample finds no route. That is "not yet", not "there is none": the question
 * has to keep being asked until it is answered. */
static void src_survives_the_roam_window(void)
{
	struct netstate ns;
	uint8_t a[16];
	int i;

	start(&ns, 1);
	netmon(&ns, NETMON_CH_V6, 1, 1);
	assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);
	assert(netstate_src_text(&ns, 6)[0] == '\0');

	for (i = 0; i < 5; i++) {
		netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), NULL, 0, 0,
				NULL, t);
		assert(netstate_conn(&ns, 6) != NET_CONN_UP);
		t += NETSTATE_SRC_FAST_MS;
		netstate_tick(&ns, t);
		assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);	/* keeps asking */
	}

	fill(a, 16, 20);
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), a, 16,
			NET_SCOPE_GLOBAL, "the-addr", t);
	assert(!strcmp(netstate_src_text(&ns, 6), "the-addr"));
	assert(netstate_conn(&ns, 6) == NET_CONN_PENDING);

	/* An answer is what ends the hurry, not a count of tries: the next
	 * sample is not due for a slow interval. */
	t += NETSTATE_SRC_FAST_MS;
	netstate_tick(&ns, t);
	assert(!(drain(&ns).f[1] & NSA_SAMPLE_SRC));
	t += NETSTATE_SRC_SLOW_MS;
	netstate_tick(&ns, t);
	assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);
}

/* And where nothing ever answers, the hurry has an end: past the window an RA
 * could still arrive in, asking every half second says nothing new. */
static void an_address_that_never_comes_stops_being_hurried(void)
{
	struct netstate ns;
	int i;

	start(&ns, 1);
	netmon(&ns, NETMON_CH_V6, 1, 1);
	assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);

	for (i = 0; i < NETSTATE_SRC_FAST_TRIES; i++) {
		netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), NULL, 0, 0, NULL,
				t);
		t += NETSTATE_SRC_FAST_MS;
		netstate_tick(&ns, t);
		drain(&ns);
	}
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), NULL, 0, 0, NULL, t);
	t += NETSTATE_SRC_FAST_MS;
	netstate_tick(&ns, t);
	assert(!(drain(&ns).f[1] & NSA_SAMPLE_SRC));
	t += NETSTATE_SRC_SLOW_MS;
	netstate_tick(&ns, t);
	assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);
}

/*
 * A MULTI-HOMED IPv6 HOST IS NOT A ROW OF NATs.
 *
 * Nothing translates IPv6, so every global address ICE enumerates is
 * reflexive to itself and arrives looking server-reflexive. Named as
 * gathered, a host with a stable, a DHCPv6 and a privacy address reports
 * three NATs and not one plain global -- which is the opposite of the truth.
 *
 * Our own source address is what separates them: it is the one the world
 * already sees, the others are interface addresses we never send from, and
 * genuine NAT66 is the case where ours is not globally routable at all.
 */
/* The kernel answers fe80:: for a global destination while the global address
 * is tentative. Taken as the answer it ends the hurry and parks for the slow
 * interval, so a global arriving moments later is not seen for seconds. */
static void a_linklocal_is_not_a_source(void)
{
	uint8_t ll[16], g[16];
	struct netstate ns;

	start(&ns, 1);
	fill(g, 16, 20);
	memset(ll, 0, sizeof(ll));
	ll[0] = 0xfe;
	ll[1] = 0x80;
	ll[15] = 1;

	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), ll, 16, NET_SCOPE_LAN,
			"fe80::1", t);
	drain(&ns);
	assert(!*netstate_src_text(&ns, 6));
	assert(netstate_conn(&ns, 6) != NET_CONN_UP);

	t += NETSTATE_SRC_FAST_MS;
	netstate_tick(&ns, t);
	assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);

	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), g, 16, NET_SCOPE_GLOBAL,
			"2a00::14", t);
	drain(&ns);
	assert(!strcmp(netstate_src_text(&ns, 6), "2a00::14"));

	/* A ULA still is one: NAT66 is a real case, not a tentative address. */
	ll[0] = 0xfd;
	ll[1] = 0x00;
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), ll, 16, NET_SCOPE_LAN,
			"fd00::1", t);
	drain(&ns);
	assert(!strcmp(netstate_src_text(&ns, 6), "fd00::1"));
}

/* Which of the two an address is decided by membership of the kernel's set,
 * and nothing about the source address moves either verdict. */
static void a_shadow_address_is_not_a_translation(void)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	uint8_t src[16], shadow[16], nat[16];
	struct netstate ns;
	uint8_t ula[16];
	int n, i;

	fill(src, 16, 20);
	fill(shadow, 16, 60);
	fill(nat, 16, 120);
	t = 1000;
	netstate_init(&ns, 1, t);
	snap_default(1, 0);
	snap_add(6, src);
	snap_add(6, shadow);
	netmon_again(&ns, 0);
	drain(&ns);

	/* Enumerated, not proven: a shadow until an exchange says otherwise. */
	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 2);
	for (i = 0; i < n; i++)
		assert(rows[i].via == NET_VIA_SHADOW);

	/* The round sent from src and was seen at src: nothing translated it. */
	netstate_on_reflexive(&ns, 6, netstate_epoch(&ns, 6), src, 16);
	drain(&ns);
	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 2);
	for (i = 0; i < n; i++) {
		if (!memcmp(rows[i].addr, src, 16))
			assert(rows[i].via == NET_VIA_DIRECT);
		else
			assert(rows[i].via == NET_VIA_SHADOW);
	}

	/* Whatever the source becomes, including a ULA, the rows do not move:
	 * a verdict that is re-derived is a verdict that flaps. */
	fill(ula, 16, 90);
	ula[0] = 0xfd;
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), ula, 16, NET_SCOPE_LAN,
			"ula", t);
	drain(&ns);
	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 2);
	for (i = 0; i < n; i++) {
		if (!memcmp(rows[i].addr, src, 16))
			assert(rows[i].via == NET_VIA_DIRECT);
		else
			assert(rows[i].via == NET_VIA_SHADOW);
	}

	/* NAT66: seen at an address this machine does not have. */
	netstate_on_reflexive(&ns, 6, netstate_epoch(&ns, 6), nat, 16);
	drain(&ns);
	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 3);
	for (i = 0; i < n; i++)
		if (!memcmp(rows[i].addr, nat, 16))
			assert(rows[i].via == NET_VIA_STUN);
}

/*
 * A FAMILY THIS END CANNOT REACH IS STILL A RENDEZVOUS.
 *
 * Qualifying a node means a round trip to it, so a host with no IPv6 uplink
 * can never qualify an IPv6 rendezvous -- and that is precisely the one it
 * most needs, a dual-stack client being able to reach the node where it
 * cannot. A peer announces a node only once it has qualified it itself, so
 * its word is the proof, and the slot is worth naming in a token on the
 * strength of it: the slot says a node holds this key, never that we can
 * reach it.
 */
static void a_peers_vouch_qualifies_what_we_cannot_reach(void)
{
	struct netstate ns;
	struct tokgen_facts f;
	uint8_t node[16], out[NETSTATE_SA_MAX], olen = 0;
	int confirmed = 1;

	start(&ns, 1);
	fill(node, 16, 30);

	/* A token slot: adopted, and still owing us a proof. */
	netstate_on_rdv_offered(&ns, 6, node, 16, t);
	assert(netstate_anchor(&ns, 6, out, &olen, &confirmed));
	assert(!confirmed);
	netstate_facts(&ns, 6, &f);
	assert(!f.dht_acked);

	/* The same node, now named by a peer that qualified it. Nothing about
	 * this end has changed, and it still cannot reach the family. */
	netstate_on_rdv_vouched(&ns, 6, node, 16, t);
	assert(netstate_conn(&ns, 6) != NET_CONN_UP);
	assert(netstate_anchor(&ns, 6, out, &olen, &confirmed));
	assert(confirmed);
	netstate_facts(&ns, 6, &f);
	assert(f.dht_acked);

	/* A move of OURS does not take back what the peer proved: that was
	 * about the node, not about the network we have left. */
	netmon(&ns, NETMON_CH_V6, 1, 1);
	drain(&ns);
	netstate_facts(&ns, 6, &f);
	assert(f.dht_acked);
	assert(netstate_anchor(&ns, 6, out, &olen, &confirmed));
	assert(confirmed);

	/*
	 * AND IT STOPS STANDING IN ONCE WE CAN ASK FOR OURSELVES. Roaming onto
	 * a network where the family is up puts the round trip back within
	 * reach, so the node reads as being checked again rather than resting
	 * on a proof made on a network we have left. The token slot keeps it
	 * throughout: what the peer proved is that the node holds this key,
	 * which is all the slot ever claimed.
	 */
	netstate_on_roundtrip(&ns, 6, netstate_epoch(&ns, 6));
	assert(netstate_conn(&ns, 6) == NET_CONN_UP);
	assert(netstate_anchor(&ns, 6, out, &olen, &confirmed));
	assert(!confirmed);
	netstate_facts(&ns, 6, &f);
	assert(f.dht_acked);

	/* A different node replacing it starts over: the vouch was for the
	 * node that was vouched for, not for the slot. */
	fill(node, 16, 70);
	netstate_on_rdv_offered(&ns, 6, node, 16, t);
	assert(netstate_anchor(&ns, 6, out, &olen, &confirmed));
	assert(!confirmed);
	netstate_facts(&ns, 6, &f);
	assert(!f.dht_acked);
}

/* The source address decides nothing about the rows: an address the kernel
 * still has stays on the dashboard, and the one this machine happens to source
 * from is not thereby proven. */
static void the_source_neither_proves_nor_hides(void)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	uint8_t dhcp[16], priv[16];
	struct netstate_actions a;
	struct netstate ns;
	int n, i;

	fill(dhcp, 16, 40);
	fill(priv, 16, 80);
	t = 1000;
	netstate_init(&ns, 1, t);
	snap_default(1, 0);
	snap_add(6, dhcp);
	snap_add(6, priv);
	netmon_again(&ns, 0);
	drain(&ns);

	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 2);

	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), priv, 16,
			NET_SCOPE_GLOBAL, "priv", t);
	a = drain(&ns);
	assert(!(a.f[1] & NSA_EMIT_ROWS));
	assert(!(a.f[0] & NSA_EMIT_ROWS));

	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 2);
	for (i = 0; i < n; i++)
		assert(rows[i].via == NET_VIA_SHADOW);
}

/* The offer is rewritten to the source address, so a source belonging to the
 * network we have left would put that address in front of a peer. */
static void src_is_never_stale_on_the_wire(void)
{
	struct netstate ns;
	uint8_t a[16], out[16];

	start(&ns, 1);
	fill(a, 16, 20);
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), a, 16,
			NET_SCOPE_GLOBAL, "keep", t);
	assert(netstate_src(&ns, 6, out) == 16);

	netmon(&ns, NETMON_CH_V6, 1, 1);
	assert(netstate_src(&ns, 6, out) == 0);
	assert(netstate_src_text(&ns, 6)[0] == '\0');

	/* the same address, still assigned after the move, is offered again */
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), a, 16,
			NET_SCOPE_GLOBAL, "keep", t);
	assert(netstate_src(&ns, 6, out) == 16);
	assert(!strcmp(netstate_src_text(&ns, 6), "keep"));
}

/* R2: losing the rendezvous is worst exactly when a move needs it most, so it
 * is given up only once it has been asked and failed, and only for one that
 * has answered. */
/*
 * A client with a session up is never ticked -- nothing watches the interfaces
 * while a link holds -- so the answer that completes the case has to be what
 * confirms it. Until it did, such a client could hold a rendezvous it was
 * using and never be able to tell its peer where it was.
 */
static void an_answer_confirms_without_a_tick(void)
{
	struct netstate ns;
	uint8_t a[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed = 0, i;

	start(&ns, 1);
	fill(a, 16, 90);
	give_src(&ns, 6, 20);

	for (i = 0; i < NETSTATE_ANCHOR_QUALIFY; i++) {
		netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), a, 16, t);
		t += NETSTATE_ANCHOR_PROVE_MS / NETSTATE_ANCHOR_QUALIFY + 1;
	}
	/* The window has passed and the answers are in, but nothing has
	 * ticked. */
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!confirmed);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), a, 16, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);
	assert(!memcmp(got, a, 16));
}

/* And it is still the answers and the window that decide, not the arrival of
 * one more answer: too few, or too soon, confirms nothing. */
static void an_answer_alone_confirms_nothing(void)
{
	struct netstate ns;
	uint8_t a[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed = 1, i;

	start(&ns, 1);
	fill(a, 16, 91);
	give_src(&ns, 6, 20);

	/* Every answer this family will ever need, all inside the window. */
	for (i = 0; i < NETSTATE_ANCHOR_QUALIFY * 3; i++)
		netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), a, 16, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!confirmed);

	/* And the window on its own, with the answers already in, waits for
	 * the next one to say so. */
	t += NETSTATE_ANCHOR_PROVE_MS + 1;
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!confirmed);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), a, 16, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);
}

static void anchor_changes_only_on_replacement(void)
{
	struct netstate ns;
	uint8_t a[16], b[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed, i;

	start(&ns, 1);
	fill(a, 16, 70);
	fill(b, 16, 170);
	give_src(&ns, 6, 20);
	qualify(&ns, 6, a);
	drain(&ns);

	/*
	 * Answers from elsewhere -- however many, however long a run of them.
	 * The convergent store puts the value on every k-close node, so the
	 * others hold it too and the quickest replies; reading that as ours
	 * having died walked the rendezvous across three live nodes inside two
	 * minutes of starting, retracting a token already copied.
	 */
	for (i = 0; i < NETSTATE_ANCHOR_GONE * 3; i++)
		netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), b, 16, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, a, 16));
	assert(confirmed);		/* and it never stopped being the one */

	/*
	 * A node can genuinely die, and then its own silence says so -- minutes
	 * of it, on a network we can otherwise reach. Only then does another
	 * node take its place, and qualify from scratch like any other.
	 */
	quiet_rounds(&ns, NETSTATE_ANCHOR_GONE);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), b, 16, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, b, 16));
	assert(!confirmed);
}

/*
 * Nothing but another node answering in its place counts against a rendezvous.
 * Not time, not rounds that came back empty, not a move: a token is shared by
 * hand and cannot be recalled, so the node it names is given up only on
 * evidence that something else is serving the mailbox instead.
 */
static void only_another_answer_condemns(void)
{
	struct netstate ns;
	uint8_t a[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed, i;

	start(&ns, 1);
	fill(a, 16, 70);
	give_src(&ns, 6, 20);
	qualify(&ns, 6, a);
	drain(&ns);

	for (i = 0; i < 3600; i++) {		/* an hour of silence */
		t += 1000;
		netstate_tick(&ns, t);
		drain(&ns);
	}
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);
	assert(!memcmp(got, a, 16));

	/* and a move keeps it, proof and all: only another node answering
	 * counts against a node, never a move. */
	netmon(&ns, NETMON_CH_V6, 1, 1);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, a, 16));
	assert(confirmed);
}

/*
 * Silence must still start a search, or a genuinely dead node is permanent:
 * the direct get asks only the nodes already held, so unless something goes
 * looking, the different answer that is the sole grounds for replacing it can
 * never arrive. The search does not unseat it -- that still takes a different
 * node answering.
 */
static void quiet_searches_without_giving_up(void)
{
	struct netstate ns;
	uint8_t a[16], b[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed, i;

	start(&ns, 1);
	fill(a, 16, 70);
	fill(b, 16, 90);
	give_src(&ns, 6, 20);
	qualify(&ns, 6, a);
	drain(&ns);

	for (i = 0; i < NETSTATE_ANCHOR_QUIET; i++) {
		t += NETSTATE_RDV_MS;
		netstate_tick(&ns, t);
	}
	assert(drain(&ns).f[1] & NSA_RDV_RELOCATE);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);
	assert(!memcmp(got, a, 16));		/* still ours, still in the token */

	/* Answering again ends it: the counter is about this node, not the clock. */
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), a, 16, t);
	drain(&ns);
	for (i = 0; i < NETSTATE_ANCHOR_QUIET - 1; i++) {
		t += NETSTATE_RDV_MS;
		netstate_tick(&ns, t);
	}
	assert(!(drain(&ns).f[1] & NSA_RDV_RELOCATE));

	/* What the search is for. It still takes its own long silence to be
	 * replaced -- another node being heard is not what unseats it. */
	quiet_rounds(&ns, NETSTATE_ANCHOR_GONE);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), b, 16, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, b, 16));
	assert(!confirmed);			/* and it qualifies from scratch */
}

/* A family that has not proven this network is not entitled to an opinion
 * about the node: the silence is as likely ours, which is the whole reason a
 * bootstrapping DHT used to condemn its own rendezvous. */
static void quiet_says_nothing_until_the_family_is_up(void)
{
	struct netstate ns;
	uint8_t a[16];
	int i;

	start(&ns, 1);
	fill(a, 16, 70);
	give_src(&ns, 6, 20);
	netstate_on_rdv_offered(&ns, 6, a, 16, 0);
	drain(&ns);
	assert(netstate_conn(&ns, 6) != NET_CONN_UP);

	for (i = 0; i < NETSTATE_ANCHOR_QUIET * 4; i++) {
		t += NETSTATE_RDV_MS;
		netstate_tick(&ns, t);
		assert(!(drain(&ns).f[1] & NSA_RDV_RELOCATE));
	}
}

/* R5: two moves in quick succession, with the caller busy in between. The
 * later one wins and nothing is skipped for having arrived late. */
/*
 * A node that answered once and never again used to be held for the life of
 * the session: the panel said it was being checked for ever, and no other node
 * could take its place, since nothing was being looked for. Nobody has been
 * shown a candidate, so there is nothing to take back by dropping it.
 */
static void a_candidate_that_never_qualifies_is_dropped(void)
{
	struct netstate ns;
	struct netstate_actions a;
	uint8_t node[16];

	start(&ns, 1);
	give_src(&ns, 6, 20);
	fill(node, 16, 70);

	/* One answer, then silence. */
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), node, 16, t);
	drain(&ns);
	assert(netstate_anchor(&ns, 6, NULL, NULL, NULL));

	/* Still on trial while its time runs. */
	t += NETSTATE_ANCHOR_TRY_MS - 1;
	netstate_tick(&ns, t);
	assert(netstate_anchor(&ns, 6, NULL, NULL, NULL));

	t += 2;
	netstate_tick(&ns, t);
	a = drain(&ns);
	assert(!netstate_anchor(&ns, 6, NULL, NULL, NULL));
	/* And it is forgotten outright, so the family locates afresh: the
	 * direct get only ever asks the nodes already held. */
	assert(a.f[1] & NSA_RDV_DROP);
	assert(a.f[1] & NSA_EMIT_RDV);
	/* The other family is untouched by any of it. */
	assert(!(a.f[0] & NSA_RDV_DROP));

	/* And the next node to answer takes the empty place. */
	fill(node, 16, 90);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), node, 16, t);
	assert(netstate_anchor(&ns, 6, NULL, NULL, NULL));
}

/* A candidate that answers once and falls silent does not get to use up its
 * whole trial window: nobody has been shown it, so a few unanswered rounds on
 * a proven network are enough to move on. */
static void a_silent_candidate_is_dropped_quickly(void)
{
	struct netstate ns;
	struct netstate_actions a;
	uint8_t node[16];
	uint64_t began;

	start(&ns, 1);
	give_src(&ns, 6, 20);
	fill(node, 16, 70);

	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), node, 16, t);
	drain(&ns);
	assert(netstate_conn(&ns, 6) == NET_CONN_UP);
	began = t;

	quiet_rounds(&ns, NETSTATE_ANCHOR_QUIET);
	a = drain(&ns);
	assert(!netstate_anchor(&ns, 6, NULL, NULL, NULL));
	assert(a.f[1] & NSA_RDV_DROP);
	assert(t - began < NETSTATE_ANCHOR_TRY_MS);
}

/* Once it has qualified it may be in somebody's token, so the deadline stops
 * applying: from there it is only ever replaced, never dropped. */
static void a_qualified_node_outlives_the_deadline(void)
{
	struct netstate ns;
	uint8_t node[16], got[NETSTATE_SA_MAX];
	uint8_t glen = 0;

	start(&ns, 1);
	give_src(&ns, 6, 20);
	fill(node, 16, 70);
	qualify(&ns, 6, node);
	assert(netstate_anchor(&ns, 6, NULL, NULL, NULL));

	t += NETSTATE_ANCHOR_TRY_MS * 4;
	netstate_tick(&ns, t);
	assert(netstate_anchor(&ns, 6, got, &glen, NULL));
	assert(glen == 16 && !memcmp(got, node, 16));
}

/*
 * A node the peer handed over is not a candidate of ours either. Failing to
 * prove it here is not grounds to go looking somewhere else: it is where the
 * peer says it is, and following that is the whole point.
 */
static void an_offered_node_is_not_on_trial(void)
{
	struct netstate ns;
	uint8_t node[16], got[NETSTATE_SA_MAX];
	uint8_t glen = 0;

	start(&ns, 0);
	give_src(&ns, 6, 20);
	fill(node, 16, 70);
	netstate_on_rdv_offered(&ns, 6, node, 16, t);
	drain(&ns);

	t += NETSTATE_ANCHOR_TRY_MS * 4;
	netstate_tick(&ns, t);
	assert(netstate_anchor(&ns, 6, got, &glen, NULL));
	assert(glen == 16 && !memcmp(got, node, 16));
}

/*
 * A move restarts the trial rather than ending it: the candidate has a fresh
 * network to prove itself on and should not inherit a clock from the one we
 * have left.
 */
static void a_move_gives_a_candidate_a_fresh_run(void)
{
	struct netstate ns;
	uint8_t node[16];

	start(&ns, 1);
	give_src(&ns, 6, 20);
	fill(node, 16, 70);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), node, 16, t);
	drain(&ns);

	t += NETSTATE_ANCHOR_TRY_MS - 1;
	netmon(&ns, NETMON_CH_V6, 1, 1);
	drain(&ns);

	t += 2;				/* past the original deadline */
	netstate_tick(&ns, t);
	assert(netstate_anchor(&ns, 6, NULL, NULL, NULL));

	t += NETSTATE_ANCHOR_TRY_MS;	/* past the new one */
	netstate_tick(&ns, t);
	assert(!netstate_anchor(&ns, 6, NULL, NULL, NULL));
}

/* Answer `n` times from `node`, spread widely enough to clear the proving
 * window on the last of them. */
static void answers(struct netstate *ns, int fam, const uint8_t *node, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		netstate_on_dht_ack(ns, fam, netstate_epoch(ns, fam), node, 16, t);
		t += NETSTATE_ANCHOR_PROVE_MS / NETSTATE_ANCHOR_QUALIFY + 1;
	}
}

/*
 * The node we happened to latch onto first answers once and stops. Another is
 * answering all along -- the store put the value on several and the direct get
 * asks all of them -- and it takes the place as soon as it has earned it,
 * rather than after the dead one has used up its whole give-up window.
 */
static void a_dead_first_answer_does_not_hold_the_place(void)
{
	struct netstate ns;
	uint8_t dead[16], good[16], got[NETSTATE_SA_MAX];
	uint8_t glen = 0;
	uint64_t began;
	int confirmed = 0;

	start(&ns, 1);
	give_src(&ns, 6, 20);
	fill(dead, 16, 70);
	fill(good, 16, 90);
	began = t;

	/* One answer from the dead one: it is what we hold, unproven. */
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), dead, 16, t);
	drain(&ns);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, dead, 16) && !confirmed);

	/* The other one answers throughout, and wins on its own merits. */
	answers(&ns, 6, good, NETSTATE_ANCHOR_QUALIFY + 1);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(glen == 16 && !memcmp(got, good, 16));
	assert(confirmed);
	/* And well inside what waiting the dead one out would have cost. */
	assert(t - began < NETSTATE_ANCHOR_TRY_MS);
}

/*
 * Once a node has qualified it may be in somebody's token, so a livelier node
 * answering is not a reason to move: only its own long silence is.
 */
static void a_busy_candidate_does_not_unseat_a_proven_node(void)
{
	struct netstate ns;
	uint8_t held[16], other[16], got[NETSTATE_SA_MAX];
	uint8_t glen = 0;

	start(&ns, 1);
	give_src(&ns, 6, 20);
	fill(held, 16, 70);
	fill(other, 16, 90);
	qualify(&ns, 6, held);
	drain(&ns);

	answers(&ns, 6, other, NETSTATE_ANCHOR_QUALIFY * 3);
	assert(netstate_anchor(&ns, 6, got, &glen, NULL));
	assert(glen == 16 && !memcmp(got, held, 16));
}

/*
 * A client runs no trial at all: whoever answers, the rendezvous is the node
 * the host named. Being asked to find one is the exception, and turning that
 * on is the whole of the difference.
 */
static void a_client_holds_no_trial_until_it_is_asked(void)
{
	struct netstate ns;
	uint8_t node[16], got[NETSTATE_SA_MAX];
	uint8_t glen = 0;

	start(&ns, 0);
	give_src(&ns, 6, 20);
	fill(node, 16, 70);

	answers(&ns, 6, node, NETSTATE_ANCHOR_QUALIFY * 2);
	assert(!netstate_anchor(&ns, 6, NULL, NULL, NULL));

	netstate_set_picking(&ns, 6, 1);
	answers(&ns, 6, node, NETSTATE_ANCHOR_QUALIFY + 1);
	assert(netstate_anchor(&ns, 6, got, &glen, NULL));
	assert(glen == 16 && !memcmp(got, node, 16));

	/* And v4 is not swept along by v6 being asked for. */
	assert(!netstate_anchor(&ns, 4, NULL, NULL, NULL));
}

/*
 * The operator waits on this one: the invite is incomplete until a rendezvous
 * has qualified. A node answering at the direct get's own cadence has to be
 * decided within fifteen seconds of the store that placed the value, leaving
 * room inside that for the first answer to come back.
 */
static void qualifying_is_decided_within_fifteen_seconds(void)
{
	struct netstate ns;
	uint8_t node[16];
	uint64_t first;
	int confirmed = 0, i;

	start(&ns, 1);
	give_src(&ns, 6, 20);
	fill(node, 16, 70);
	first = t;

	/* One answer a second, which is what the direct get produces. */
	for (i = 0; i < 30; i++) {
		netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), node, 16, t);
		netstate_tick(&ns, t);
		if (netstate_anchor(&ns, 6, NULL, NULL, &confirmed) && confirmed)
			break;
		t += 1000;
	}
	assert(confirmed);
	assert(t - first <= 15000);

	/* And it is still a run of answers over time, not a count collected in
	 * an instant: the same number arriving at once does not qualify. */
	{
		struct netstate burst;
		int c2 = 0;

		start(&burst, 1);
		give_src(&burst, 6, 20);
		for (i = 0; i < NETSTATE_ANCHOR_QUALIFY * 3; i++)
			netstate_on_dht_ack(&burst, 6,
					    netstate_epoch(&burst, 6), node, 16,
					    t);
		netstate_tick(&burst, t);
		assert(netstate_anchor(&burst, 6, NULL, NULL, &c2));
		assert(!c2);
	}
}

static void latest_change_wins(void)
{
	struct netstate ns;
	struct netstate_actions a;
	uint32_t first, second;
	uint8_t addr[4];

	start(&ns, 1);
	netmon(&ns, NETMON_CH_V4, 1, 1);
	first = netstate_epoch(&ns, 4);
	netmon(&ns, NETMON_CH_V4, 1, 1);
	second = netstate_epoch(&ns, 4);
	assert(second != first);

	a = drain(&ns);
	assert(a.epoch[0] == second);
	assert(a.f[0] & NSA_SAMPLE_SRC);
	assert(a.f[0] & NSA_KICK_PROBE);

	fill(addr, 4, 10);
	netstate_on_src(&ns, 4, first, addr, 4, NET_SCOPE_GLOBAL, "old", t);
	assert(netstate_src_text(&ns, 4)[0] == '\0');
	netstate_on_src(&ns, 4, second, addr, 4, NET_SCOPE_GLOBAL, "new", t);
	assert(!strcmp(netstate_src_text(&ns, 4), "new"));
}

/* R1: over a node both roles were handed, host and client differ about the
 * token and nothing else. Any further host-only special case fails here rather
 * than in a roaming laptop's dashboard. */
static void host_and_client_agree_except_on_the_token(void)
{
	struct netstate h, c;
	uint8_t node[16];
	int i;

	start(&h, 1);
	start(&c, 0);
	fill(node, 16, 70);

	for (i = 0; i < 2; i++) {
		struct netstate *ns = i ? &c : &h;

		give_src(ns, 4, 10);
		give_src(ns, 6, 20);
		netstate_on_rdv_offered(ns, 6, node, 16, t);
		netstate_on_dht_ack(ns, 6, netstate_epoch(ns, 6), node, 16, t);
		netmon(ns, NETMON_CH_V6, 1, 0);
		netstate_on_dht_concluded(ns, 4, 1);
	}

	for (i = 4; i <= 6; i += 2) {
		struct tokgen_facts fh, fc;

		assert(netstate_conn(&h, i) == netstate_conn(&c, i));
		assert(netstate_epoch(&h, i) == netstate_epoch(&c, i));
		assert(!strcmp(netstate_src_text(&h, i), netstate_src_text(&c, i)));
		netstate_facts(&h, i, &fh);
		netstate_facts(&c, i, &fc);
		assert(!memcmp(&fh, &fc, sizeof(fh)));
	}
	for (i = 0; i < 2; i++)
		assert((h.pend[i] & ~(unsigned)NSA_EMIT_TOKEN) == c.pend[i]);
}

/*
 * The second and last divergence: who gets to choose the rendezvous. A host
 * discovers its own, so a node answering in place of the one it holds is
 * evidence. A client was told which node to use, and only that node's copy of
 * the mailbox is kept current by the host -- so another holder answering is a
 * stale copy, and following it reads an offer that never changes again.
 */
static void only_a_host_picks_its_own_rendezvous(void)
{
	struct netstate h, c;
	uint8_t a[16], b[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int i, k;

	start(&h, 1);
	start(&c, 0);
	fill(a, 16, 70);
	fill(b, 16, 90);

	for (k = 0; k < 2; k++) {
		struct netstate *ns = k ? &c : &h;

		give_src(ns, 6, 20);
		netstate_on_rdv_offered(ns, 6, a, 16, 0);
		qualify(ns, 6, a);
		drain(ns);
		quiet_rounds(ns, NETSTATE_ANCHOR_GONE);
		for (i = 0; i < 4; i++)
			netstate_on_dht_ack(ns, 6, netstate_epoch(ns, 6), b, 16,
					    t);
	}
	assert(netstate_anchor(&h, 6, got, &glen, NULL));
	assert(!memcmp(got, b, 16));		/* the host moved to it */
	assert(netstate_anchor(&c, 6, got, &glen, NULL));
	assert(!memcmp(got, a, 16));		/* the client stayed put */

	/* What does move a client is being told: the host announcing a node
	 * over the control channel outranks anything either has observed. */
	netstate_on_rdv_offered(&c, 6, b, 16, 0);
	assert(netstate_anchor(&c, 6, got, &glen, NULL));
	assert(!memcmp(got, b, 16));
}

/* Run one round if the model asks for one; whether it did. */
static int probe_round(struct netstate *ns, int fam)
{
	int k = fam == 6 ? 1 : 0;

	netstate_tick(ns, t);
	if (!(drain(ns).f[k] & NSA_KICK_PROBE))
		return 0;
	netstate_on_probe_started(ns, fam, netstate_epoch(ns, fam), t);
	netstate_on_probe_done(ns, fam, netstate_epoch(ns, fam), t);
	return 1;
}

/*
 * B2: a family that has not been proven keeps being asked. Promptly at first,
 * because the usual reasons to have missed clear in seconds -- then slowly,
 * but never not at all. Giving up outright is the one answer that cannot be
 * corrected when the network turns out to work after all.
 */
static void probe_slows_but_never_stops(void)
{
	struct netstate ns;
	int i;

	start(&ns, 1);
	for (i = 0; i < NETSTATE_PROBE_ROUNDS; i++) {
		assert(probe_round(&ns, 6));	/* one per prompt gap */
		t += NETSTATE_PROBE_MS;
	}
	/* the prompt ones are spent: another prompt gap buys nothing */
	assert(!probe_round(&ns, 6));

	for (i = 0; i < 5; i++) {		/* but it has not stopped */
		t += NETSTATE_PROBE_SLOW_MS;
		assert(probe_round(&ns, 6));
	}

	/* a move is a fresh network, and may not filter: prompt again */
	netmon(&ns, NETMON_CH_V6, 1, 1);
	assert(drain(&ns).f[1] & NSA_KICK_PROBE);
	netstate_on_probe_started(&ns, 6, netstate_epoch(&ns, 6), t);
	netstate_on_probe_done(&ns, 6, netstate_epoch(&ns, 6), t);
	t += NETSTATE_PROBE_MS;
	assert(probe_round(&ns, 6));

	/*
	 * And proof does NOT end it. A round answers two questions: whether the
	 * family is reachable, which the first reply settles, and which public
	 * addresses this NAT maps us to, which takes every server it asks. A
	 * host behind a per-destination CGNAT that stopped here would advertise
	 * one egress address of the several it actually has.
	 */
	netstate_on_roundtrip(&ns, 6, netstate_epoch(&ns, 6));
	drain(&ns);
	t += NETSTATE_PROBE_SLOW_MS;
	assert(probe_round(&ns, 6));
}

/* A round that could not start because the previous one was winding up is not
 * lost: it is due as that one ends, not a gap after it. */
static void a_deferred_round_is_due_at_once(void)
{
	struct netstate ns;
	uint32_t e;

	start(&ns, 1);
	e = netstate_epoch(&ns, 6);
	assert(probe_round(&ns, 6));

	t += 100;
	netstate_on_probe_started(&ns, 6, e, t);
	netstate_on_probe_deferred(&ns, 6, e);
	netstate_on_probe_done(&ns, 6, e, t);
	assert(drain(&ns).f[1] & NSA_KICK_PROBE);

	/* A deferral from a network we have left says nothing here. */
	netstate_on_probe_started(&ns, 6, netstate_epoch(&ns, 6), t);
	netstate_on_probe_deferred(&ns, 6, netstate_epoch(&ns, 6) - 1);
	netstate_on_probe_done(&ns, 6, netstate_epoch(&ns, 6), t);
	assert(!(drain(&ns).f[1] & NSA_KICK_PROBE));
}

/* B2a: a round is due when there is somewhere new to ask, not at the end of a
 * gap that was begun while there was nowhere. */
static void somewhere_new_makes_a_round_due(void)
{
	struct netstate ns;

	start(&ns, 1);
	assert(probe_round(&ns, 6));
	t += 100;
	netstate_tick(&ns, t);
	assert(!(drain(&ns).f[1] & NSA_KICK_PROBE));
	netstate_on_servers(&ns, 6, netstate_epoch(&ns, 6), t);
	assert(drain(&ns).f[1] & NSA_KICK_PROBE);

	/* Not from the network it was learnt on, so it says nothing here. */
	netmon(&ns, NETMON_CH_V6, 1, 1);
	drain(&ns);
	netstate_on_servers(&ns, 6, netstate_epoch(&ns, 6) - 1, t);
	assert(!(drain(&ns).f[1] & NSA_KICK_PROBE));
}

static void no_address_no_probe_no_pending(void)
{
	struct netstate ns;
	struct tokgen_facts fx;

	t = 1000;
	netstate_init(&ns, 1, t);
	netmon(&ns, 0, 1, 0);	/* v4 only */
	drain(&ns);

	give_src(&ns, 6, 20);			/* even a route proves nothing */
	assert(netstate_conn(&ns, 6) == 0);
	netstate_facts(&ns, 6, &fx);
	assert(!fx.has_usable_addr);
	netstate_tick(&ns, t);
	assert(!(drain(&ns).f[1] & NSA_KICK_PROBE));
}

/* Membership decides, not arrival order: an address the kernel reports is
 * proven by a reply naming it and stays proven however often it is re-offered,
 * and the derived text is the model's, not a producer's. */
static void membership_decides_not_arrival_order(void)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	uint8_t theirs[4] = { 198, 51, 100, 9 };
	uint8_t mine[4] = { 203, 0, 113, 7 };
	struct netstate ns;
	uint32_t e;
	int k;

	for (k = 0; k < 2; k++) {
		t = 1000;
		netstate_init(&ns, 1, t);
		snap_default(0, 1);
		snap_add(4, mine);
		netmon_again(&ns, 0);
		drain(&ns);
		e = netstate_epoch(&ns, 4);

		/* Either order, and twice over. */
		if (k)
			netstate_on_reflexive(&ns, 4, e, theirs, 4);
		netstate_on_reflexive(&ns, 4, e, mine, 4);
		if (!k)
			netstate_on_reflexive(&ns, 4, e, theirs, 4);
		netstate_on_reflexive(&ns, 4, e, mine, 4);
		netstate_on_reflexive(&ns, 4, e, theirs, 4);

		assert(netstate_rows(&ns, 4, rows, NETSTATE_ROWS_MAX) == 2);
		assert(!memcmp(rows[0].addr, mine, 4));
		assert(rows[0].via == NET_VIA_DIRECT);
		assert(!strcmp(rows[0].text, "203.0.113.7"));
		assert(rows[1].via == NET_VIA_STUN);
		assert(!strcmp(rows[1].text, "198.51.100.9"));
	}
}

/* A move is about the network, so the proofs go and the addresses stay, and
 * only for the family that moved. */
static void an_epoch_bump_demotes_rather_than_empties(void)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	uint8_t pub4[4] = { 203, 0, 113, 7 };
	struct netstate_fam save;
	struct netstate ns;

	t = 1000;
	netstate_init(&ns, 1, t);
	snap_default(0, 1);
	snap_add(4, pub4);
	netmon_again(&ns, 0);
	netstate_on_reflexive(&ns, 4, netstate_epoch(&ns, 4), pub4, 4);
	netstate_on_reflexive(&ns, 6, netstate_epoch(&ns, 6), dfl6, 16);
	drain(&ns);
	assert(netstate_rows(&ns, 4, rows, NETSTATE_ROWS_MAX) == 1);
	assert(rows[0].via == NET_VIA_DIRECT);
	assert(netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX) == 1);
	assert(rows[0].via == NET_VIA_DIRECT);

	save = ns.f[0];
	netmon_again(&ns, NETMON_CH_V6);

	assert(!memcmp(&save, &ns.f[0], sizeof(save)));
	assert(ns.f[1].nlocals == 1);		/* the address is the kernel's */
	assert(netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX) == 1);
	assert(rows[0].via == NET_VIA_SHADOW);	/* the proof was this network's */
	assert(drain(&ns).f[1] & NSA_EMIT_ROWS);

	netstate_on_reflexive(&ns, 6, netstate_epoch(&ns, 6), dfl6, 16);
	assert(netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX) == 1);
	assert(rows[0].via == NET_VIA_DIRECT);
}

static void rows_say(struct netstate *ns, const uint8_t *mine, int mine_via,
		     int theirs_seen)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	int n, i;

	n = netstate_rows(ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == 1 + theirs_seen);
	for (i = 0; i < n; i++)
		assert(rows[i].via == (!memcmp(rows[i].addr, mine, 16) ?
				       mine_via : NET_VIA_STUN));
}

/* Within one epoch no verdict moves, over every order of a repeated snapshot,
 * a reply naming one of ours, and a reply naming one we do not have. */
static void no_verdict_moves_within_an_epoch(void)
{
	static const int pow3[4] = { 1, 3, 9, 27 };
	int seq, step, ev, mine_via, seen;
	uint8_t mine[16], theirs[16];
	struct netstate ns;

	fill(mine, 16, 20);
	fill(theirs, 16, 120);
	for (seq = 0; seq < 81; seq++) {
		t = 1000;
		netstate_init(&ns, 1, t);
		snap_reset();
		snap_add(6, mine);
		netmon_again(&ns, 0);
		mine_via = NET_VIA_SHADOW;
		seen = 0;
		for (step = 0; step < 4; step++) {
			ev = (seq / pow3[step]) % 3;
			if (!ev)
				netmon_again(&ns, 0);
			else
				netstate_on_reflexive(&ns, 6,
						      netstate_epoch(&ns, 6),
						      ev == 1 ? mine : theirs,
						      16);
			if (ev == 1)
				mine_via = NET_VIA_DIRECT;
			if (ev == 2)
				seen = 1;
			rows_say(&ns, mine, mine_via, seen);
		}
	}
}

/* An address goes when the kernel stops reporting it, whether or not a family
 * moved with it, and a translation is not one of ours to prune. */
static void withdrawal_follows_the_kernel(void)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	struct netstate_actions a;
	uint8_t old6[16], nat[16];
	struct netstate ns;

	fill(old6, 16, 40);
	fill(nat, 16, 120);
	t = 1000;
	netstate_init(&ns, 1, t);
	snap_default(1, 1);
	snap_add(6, old6);
	netmon_again(&ns, 0);
	netstate_on_reflexive(&ns, 6, netstate_epoch(&ns, 6), nat, 16);
	drain(&ns);
	assert(netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX) == 3);

	snap_drop(6, old6);
	netmon_again(&ns, 0);
	a = drain(&ns);
	assert(a.f[1] & NSA_EMIT_ROWS);
	assert(netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX) == 2);
	assert(!netstate_has_local(&ns, 6, old6, 16));
	assert(ns.f[1].nxlats == 1);

	/* A roam onto a network with no v6 at all takes the rest of it. */
	netmon(&ns, NETMON_CH_V6, 1, 0);
	assert(!netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX));
	assert(!netstate_has_local(&ns, 6, dfl6, 16));
	assert(netstate_conn(&ns, 6) == 0);
}

/* The egress pool is on no interface, so no snapshot may prune it; it lives as
 * long as the network it was measured on, and a repeated sample says nothing. */
static void a_translation_outlives_every_snapshot(void)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	uint8_t egress[4] = { 198, 51, 100, 9 };
	struct netstate ns;
	int i;

	start(&ns, 1);
	netstate_on_reflexive(&ns, 4, netstate_epoch(&ns, 4), egress, 4);
	drain(&ns);
	for (i = 0; i < 20; i++) {
		netmon_again(&ns, 0);
		assert(!drain(&ns).f[0]);
		assert(netstate_rows(&ns, 4, rows, NETSTATE_ROWS_MAX) == 2);
	}
	assert(rows[0].via == NET_VIA_STUN);
	assert(!strcmp(rows[0].text, "198.51.100.9"));
	assert(rows[1].scope == NET_SCOPE_LAN);
	assert(!strcmp(rows[1].text, "192.168.1.2"));

	netmon_again(&ns, NETMON_CH_V6);	/* not this family's network */
	assert(netstate_rows(&ns, 4, rows, NETSTATE_ROWS_MAX) == 2);
	netmon_again(&ns, NETMON_CH_V4);
	assert(netstate_rows(&ns, 4, rows, NETSTATE_ROWS_MAX) == 1);
	assert(rows[0].scope == NET_SCOPE_LAN);
}

/* The two sets are disjoint, whichever way round an address reaches them: one
 * the kernel turns out to have stops being a translation, taking the reply that
 * named it along as its proof, and one row is all it ever gets. */
static void the_kernel_admitting_an_address_takes_it_back(void)
{
	static const uint8_t cgnat[4] = { 100, 64, 0, 1 };
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	struct netstate ns;

	t = 1000;
	netstate_init(&ns, 1, t);
	snap_default(1, 1);
	netmon_again(&ns, 0);
	netstate_on_reflexive(&ns, 4, netstate_epoch(&ns, 4), cgnat, 4);
	drain(&ns);
	assert(netstate_has_xlat(&ns, 4, cgnat, 4));
	assert(!netstate_has_local(&ns, 4, cgnat, 4));
	assert(netstate_rows(&ns, 4, rows, NETSTATE_ROWS_MAX) == 2);
	assert(!memcmp(rows[0].addr, cgnat, 4));
	assert(rows[0].via == NET_VIA_STUN);

	/* The kernel reports it, on a sample no family moved with. */
	snap_add(4, cgnat);
	netmon_again(&ns, 0);
	assert(drain(&ns).f[0] & NSA_EMIT_ROWS);
	assert(!netstate_has_xlat(&ns, 4, cgnat, 4));
	assert(netstate_has_local(&ns, 4, cgnat, 4));
	assert(netstate_rows(&ns, 4, rows, NETSTATE_ROWS_MAX) == 2);
	assert(!memcmp(rows[0].addr, cgnat, 4));
	assert(rows[0].via == NET_VIA_DIRECT);	/* the reply proved it */
	assert(rows[1].scope == NET_SCOPE_LAN);

	/* The proof was still this network's, and ends with it. */
	netmon_again(&ns, NETMON_CH_V4);
	assert(netstate_rows(&ns, 4, rows, NETSTATE_ROWS_MAX) == 2);
	assert(rows[0].scope == NET_SCOPE_LAN);
	assert(!memcmp(rows[1].addr, cgnat, 4));
	assert(rows[1].via == NET_VIA_SHADOW);
}

/* With less room than the model has addresses, what a view goes without is a
 * global address no exchange has confirmed, never the segment a peer on the
 * same link actually reaches this machine at. */
static void a_full_view_goes_without_the_unconfirmed(void)
{
	static const uint8_t ula[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					 0, 0, 0, 0, 0, 0, 0, 1 };
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	struct netstate ns;
	int i, n, lan = 0;
	uint8_t a[16];

	t = 1000;
	netstate_init(&ns, 1, t);
	snap_reset();
	for (i = 0; i < NETSTATE_ROWS_MAX + 4; i++) {
		fill(a, 16, (uint8_t)i);
		a[0] = 0x20;
		snap_add(6, a);
	}
	snap_add(6, ula);
	netmon_again(&ns, 0);

	n = netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX);
	assert(n == NETSTATE_ROWS_MAX);
	for (i = 0; i < n; i++)
		lan += rows[i].scope == NET_SCOPE_LAN;
	assert(lan == 1);
}

/* An address netmon leaves out of the fingerprint (APIPA, so that a DHCP
 * handover does not read as a move) still decides whether the family has one. */
static void an_address_with_no_change_bit_still_counts(void)
{
	static const uint8_t apipa[4] = { 169, 254, 3, 4 };
	struct tokgen_facts fx;
	struct netstate ns;

	t = 1000;
	netstate_init(&ns, 1, t);
	snap_default(0, 1);
	netmon_again(&ns, 0);
	drain(&ns);
	netstate_facts(&ns, 4, &fx);
	assert(!fx.has_usable_addr);
	assert(netstate_conn(&ns, 4) == 0);

	snap_add(4, apipa);
	netmon_again(&ns, 0);
	netstate_facts(&ns, 4, &fx);
	assert(fx.has_usable_addr);
	assert(drain(&ns).f[0] & NSA_EMIT_ROWS);
	assert(netstate_epoch(&ns, 4) == 1);	/* no network was entered */
}

/* Whatever netmon can report, the model holds. */
static void every_address_the_kernel_reports_is_held(void)
{
	struct netstate_row rows[NETSTATE_ROWS_MAX];
	struct netstate ns;
	uint8_t a[16];
	int i;

	t = 1000;
	netstate_init(&ns, 1, t);
	snap_reset();
	for (i = 0; i < NETMON_MAX_ADDRS; i++) {
		fill(a, 16, (uint8_t)i);
		a[0] = 0x20;
		snap_add(6, a);
	}
	netmon_again(&ns, 0);
	assert(ns.f[1].nlocals == NETMON_MAX_ADDRS);
	for (i = 0; i < NETMON_MAX_ADDRS; i++) {
		fill(a, 16, (uint8_t)i);
		a[0] = 0x20;
		assert(netstate_has_local(&ns, 6, a, 16));
	}
	/* A view is offered as many as it has room for. */
	assert(netstate_rows(&ns, 6, rows, NETSTATE_ROWS_MAX) ==
	       NETSTATE_ROWS_MAX);
}

/*
 * Build a family up into one of sixteen states, so the lattice below starts
 * from something worth preserving rather than from zero.
 */
static void build(struct netstate *ns, int fam, int bits)
{
	uint8_t node[16];
	uint8_t a[16];

	if (bits & 1)
		give_src(ns, fam, (uint8_t)(10 + fam));
	if (bits & 2)
		netstate_on_roundtrip(ns, fam, netstate_epoch(ns, fam));
	if (bits & 4) {
		fill(node, 16, (uint8_t)(70 + fam));
		netstate_on_dht_ack(ns, fam, netstate_epoch(ns, fam), node, 16, t);
	}
	if (bits & 8) {
		fill(a, 16, (uint8_t)(90 + fam));
		netstate_on_reflexive(ns, fam, netstate_epoch(ns, fam), a,
				      fam == 6 ? 16 : 4);
	}
}

/*
 * R6 stated completely: for every change mask and every starting state, the
 * family whose bit is clear comes through byte-identical. The memcmp is the
 * point -- a field added later that leaks across families fails here without
 * anyone remembering to extend this.
 */
static void family_independence_lattice(void)
{
	static const unsigned mask[4] = {
		0, NETMON_CH_V4, NETMON_CH_V6, NETMON_CH_V4 | NETMON_CH_V6
	};
	int m, other, bits;

	for (m = 0; m < 4; m++)
		for (other = 0; other < 2; other++) {
			unsigned bit = other ? NETMON_CH_V6 : NETMON_CH_V4;

			if (mask[m] & bit)
				continue;	/* it moved; nothing to preserve */
			for (bits = 0; bits < 16; bits++) {
				struct netstate ns;
				struct netstate_fam save;

				start(&ns, 1);
				build(&ns, 4, bits);
				build(&ns, 6, bits);
				drain(&ns);
				save = ns.f[other];

				netmon(&ns, mask[m], 1, 1);
				assert(!memcmp(&save, &ns.f[other],
					       sizeof(save)));
				assert(drain(&ns).f[other] == 0);
			}
		}
}

/*
 * R5 stated completely: every asynchronous fact is about the network it was
 * learnt on. One stamped with any other leaves the machine exactly as it was.
 */
static void epoch_gate_exhaustive(void)
{
	int kind, fam, delta;

	for (kind = 0; kind < 5; kind++)
		for (fam = 4; fam <= 6; fam += 2)
			for (delta = 0; delta <= 2; delta++) {
				struct netstate ns, before;
				uint8_t a[16], node[16];
				uint32_t e;

				start(&ns, 1);
				/*
				 * Enough state for every event to have
				 * somewhere to move, but nothing proven yet:
				 * an anchor taken as a hint rather than earned,
				 * so a round trip still has work to do.
				 */
				give_src(&ns, fam, 33);
				fill(node, 16, 70);
				netstate_on_rdv_offered(&ns, fam, node, 16, 0);
				netstate_on_probe_started(&ns, fam,
							  netstate_epoch(&ns, fam),
							  t);
				if (kind == 4)		/* an attempt only counts
							 * once the family is
							 * proven */
					netstate_on_roundtrip(&ns, fam,
							      netstate_epoch(&ns,
									     fam));
				drain(&ns);

				before = ns;
				e = netstate_epoch(&ns, fam) + (uint32_t)delta;
				fill(a, 16, 200);

				switch (kind) {
				case 0:
					netstate_on_roundtrip(&ns, fam, e);
					break;
				case 1:
					netstate_on_dht_ack(&ns, fam, e, a, 16,
							    t + 1);
					break;
				case 2:
					netstate_on_src(&ns, fam, e, a,
							fam == 6 ? 16 : 4,
							NET_SCOPE_GLOBAL, "z",
							t + 1);
					break;
				case 3:
					netstate_on_probe_done(&ns, fam, e,
							       t + 1);
					break;
				default:
					netstate_on_reflexive(&ns, fam, e, a,
							      fam == 6 ? 16 : 4);
					break;
				}
				if (delta)
					assert(!memcmp(&before, &ns,
						       sizeof(ns)));
				else
					assert(memcmp(&before, &ns,
						      sizeof(ns)));
			}
}

/*
 * The three laws, restated here against the event stream rather than against
 * the implementation, and checked after every one of a long pseudo-random
 * run. A seeded generator so a failure repeats.
 */
static uint32_t rng_state = 0x5eed1234u;

static uint32_t rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static void laws_hold_under_churn(void)
{
	struct netstate ns;
	uint32_t sh_epoch[2], sh_up[2];
	uint8_t sh_anchor[2][16];
	int sh_has[2], sh_routed[2], sh_alen[2], i, step;

	start(&ns, 1);
	for (i = 0; i < 2; i++) {
		sh_epoch[i] = netstate_epoch(&ns, i ? 6 : 4);
		sh_up[i] = 0;
		sh_has[i] = 1;
		sh_routed[i] = 0;
		sh_alen[i] = 0;
		memset(sh_anchor[i], 0, 16);
	}

	for (step = 0; step < 200000; step++) {
		int fam = (rng() & 1) ? 6 : 4;
		int k = fam == 6 ? 1 : 0;
		uint32_t e = netstate_epoch(&ns, fam);
		uint32_t r = rng();
		uint8_t a[16];

		fill(a, 16, (uint8_t)r);
		switch (r % 7) {
		case 0: {
			unsigned m = (r & 8) ? NETMON_CH_V4 : NETMON_CH_V6;
			int h4 = 1, h6 = 1;

			if (r & 16) {
				if (m == NETMON_CH_V4)
					h4 = 0;
				else
					h6 = 0;
			}
			netmon(&ns, m, h4, h6);
			k = (m == NETMON_CH_V6);
			sh_epoch[k]++;
			/* Both families: the set is the kernel's whether or
			 * not a family moved. */
			sh_has[0] = h4;
			sh_has[1] = h6;
			sh_routed[k] = 0;
			break;
		}
		case 1:
			netstate_on_src(&ns, fam, e, a, fam == 6 ? 16 : 4,
					NET_SCOPE_GLOBAL, "s", t);
			if (e == sh_epoch[k])
				sh_routed[k] = 1;
			break;
		case 2:
			netstate_on_src(&ns, fam, e, NULL, 0, 0, NULL, t);
			if (e == sh_epoch[k])
				sh_routed[k] = 0;
			break;
		case 3:
			netstate_on_roundtrip(&ns, fam, e);
			if (e == sh_epoch[k])
				sh_up[k] = e;
			break;
		case 4:
			netstate_on_dht_ack(&ns, fam, e, a, 16, t);
			if (e == sh_epoch[k]) {
				sh_up[k] = e;
				if (!sh_alen[k]) {
					memcpy(sh_anchor[k], a, 16);
					sh_alen[k] = 16;
				}
			}
			break;
		case 5:
			netstate_on_reflexive(&ns, fam, e, a,
					      fam == 6 ? 16 : 4);
			break;
		default:
			t += 250;
			netstate_tick(&ns, t);
			break;
		}
		drain(&ns);

		for (i = 0; i < 2; i++) {
			int want = !sh_has[i] ? 0 :
				   sh_up[i] == sh_epoch[i] ? NET_CONN_UP :
				   sh_routed[i] ? NET_CONN_PENDING : 0;
			uint8_t got[NETSTATE_SA_MAX];
			uint8_t glen = 0;

			/* Law 1: the verdict is exactly what the events say. */
			assert(netstate_conn(&ns, i ? 6 : 4) == want);
			/* Law 2: the anchor is never given up for nothing --
			 * once held, something is always held. */
			assert(netstate_anchor(&ns, i ? 6 : 4, got, &glen,
					       NULL) == (sh_alen[i] != 0));
			/* Law 3: a source is offered only for this network. */
			if (netstate_src_text(&ns, i ? 6 : 4)[0])
				assert(ns.f[i].src_epoch == ns.f[i].epoch);
		}
	}
}

int main(void)
{
	/* The model prints addresses through inet_ntop, and this case runs on
	 * Windows too, where the socket library comes up before anything else. */
	assert(!wsock_init());
	v6_change_leaves_v4_alone();
	a_gained_address_is_not_a_move();
	a_confirmed_anchor_survives_a_move();
	stale_roundtrip_never_marks_up();
	src_survives_the_roam_window();
	an_address_that_never_comes_stops_being_hurried();
	the_source_neither_proves_nor_hides();
	a_linklocal_is_not_a_source();
	a_shadow_address_is_not_a_translation();
	a_peers_vouch_qualifies_what_we_cannot_reach();
	src_is_never_stale_on_the_wire();
	an_answer_confirms_without_a_tick();
	an_answer_alone_confirms_nothing();
	anchor_changes_only_on_replacement();
	only_another_answer_condemns();
	quiet_searches_without_giving_up();
	quiet_says_nothing_until_the_family_is_up();
	a_candidate_that_never_qualifies_is_dropped();
	a_silent_candidate_is_dropped_quickly();
	a_qualified_node_outlives_the_deadline();
	an_offered_node_is_not_on_trial();
	a_move_gives_a_candidate_a_fresh_run();
	qualifying_is_decided_within_fifteen_seconds();
	a_dead_first_answer_does_not_hold_the_place();
	a_busy_candidate_does_not_unseat_a_proven_node();
	a_client_holds_no_trial_until_it_is_asked();
	latest_change_wins();
	host_and_client_agree_except_on_the_token();
	only_a_host_picks_its_own_rendezvous();
	probe_slows_but_never_stops();
	a_deferred_round_is_due_at_once();
	somewhere_new_makes_a_round_due();
	no_address_no_probe_no_pending();
	membership_decides_not_arrival_order();
	an_epoch_bump_demotes_rather_than_empties();
	no_verdict_moves_within_an_epoch();
	withdrawal_follows_the_kernel();
	a_translation_outlives_every_snapshot();
	the_kernel_admitting_an_address_takes_it_back();
	a_full_view_goes_without_the_unconfirmed();
	an_address_with_no_change_bit_still_counts();
	every_address_the_kernel_reports_is_held();
	family_independence_lattice();
	epoch_gate_exhaustive();
	laws_hold_under_churn();
	return 0;
}
