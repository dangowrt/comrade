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

/* A primed machine on a dual-stack network, nothing proven yet. */
static void start(struct netstate *ns, int is_host)
{
	t = 1000;
	netstate_init(ns, is_host, t);
	netstate_on_netmon(ns, 0, 1, 1, t);
	drain(ns);
}

static void give_src(struct netstate *ns, int fam, uint8_t seed)
{
	uint8_t a[16];
	int len = fam == 6 ? 16 : 4;

	fill(a, len, seed);
	netstate_on_src(ns, fam, netstate_epoch(ns, fam), a, len, "addr", t);
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
	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);

	assert(!memcmp(&save, &ns.f[0], sizeof(save)));
	assert(netstate_conn(&ns, 4) == NET_CONN_UP);
	a = drain(&ns);
	assert(a.f[0] == 0);		/* nothing owed for v4 */
	assert(a.f[1] != 0);		/* and everything for v6 */
}

/* B10/B5: the anchor survives a move so the token keeps naming it, but it is a
 * memory of the last network, not evidence about this one. */
static void preserved_anchor_is_not_proof(void)
{
	struct netstate ns;
	struct tokgen_facts fx;
	uint8_t node[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed = -1;

	start(&ns, 1);
	fill(node, 16, 70);
	give_src(&ns, 6, 20);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), node, 16, t);
	assert(netstate_conn(&ns, 6) == NET_CONN_UP);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);
	drain(&ns);

	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);

	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, node, 16));	/* still ours */
	assert(!confirmed);		/* but nothing has spoken to it here */
	assert(netstate_conn(&ns, 6) != NET_CONN_UP);
	netstate_facts(&ns, 6, &fx);
	assert(!fx.dht_acked);
	assert(drain(&ns).f[1] & NSA_RDV_REVALIDATE);

	/* and it earns its way back */
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), node, 16, t);
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
	netstate_on_netmon(&ns, NETMON_CH_V4, 1, 1, t);
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
	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);
	assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);
	assert(netstate_src_text(&ns, 6)[0] == '\0');

	for (i = 0; i < 5; i++) {
		netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), NULL, 0, NULL, t);
		assert(netstate_conn(&ns, 6) != NET_CONN_UP);
		t += NETSTATE_SRC_FAST_MS;
		netstate_tick(&ns, t);
		assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);	/* keeps asking */
	}

	fill(a, 16, 20);
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), a, 16, "the-addr", t);
	assert(!strcmp(netstate_src_text(&ns, 6), "the-addr"));
	assert(netstate_conn(&ns, 6) == NET_CONN_PENDING);
}

/* B6/B12, the visible half: the addresses arrive before the source does, so
 * whichever was shown first cannot be the answer. Once the source is known the
 * set is recomputed, which an append-only row list could never do. */
static void late_src_retracts_the_wrong_row(void)
{
	struct netstate ns;
	const struct netstate_row *rows;
	uint8_t dhcp[16], priv[16];
	struct netstate_actions a;
	int n, i, shown = 0;

	start(&ns, 1);
	fill(dhcp, 16, 40);
	fill(priv, 16, 80);
	netstate_on_candidate(&ns, 6, netstate_epoch(&ns, 6), NET_SCOPE_GLOBAL,
			      NET_VIA_DIRECT, dhcp, 16, "dhcp");
	netstate_on_candidate(&ns, 6, netstate_epoch(&ns, 6), NET_SCOPE_GLOBAL,
			      NET_VIA_DIRECT, priv, 16, "priv");
	drain(&ns);

	n = netstate_rows(&ns, 6, &rows);
	assert(n == 2);
	for (i = 0; i < n; i++)
		shown += rows[i].shown;
	assert(shown == 2);		/* nothing held back without a source */

	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), priv, 16, "priv", t);
	a = drain(&ns);
	assert(a.f[1] & NSA_EMIT_ROWS);
	assert(!(a.f[0] & NSA_EMIT_ROWS));	/* v4 untouched */

	n = netstate_rows(&ns, 6, &rows);
	assert(n == 2);
	for (i = 0; i < n; i++)
		assert(rows[i].shown == !memcmp(rows[i].addr, priv, 16));
}

/* The offer is rewritten to the source address, so a source belonging to the
 * network we have left would put that address in front of a peer. */
static void src_is_never_stale_on_the_wire(void)
{
	struct netstate ns;
	uint8_t a[16], out[16];

	start(&ns, 1);
	fill(a, 16, 20);
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), a, 16, "keep", t);
	assert(netstate_src(&ns, 6, out) == 16);

	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);
	assert(netstate_src(&ns, 6, out) == 0);
	assert(netstate_src_text(&ns, 6)[0] == '\0');

	/* the same address, still assigned after the move, is offered again */
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), a, 16, "keep", t);
	assert(netstate_src(&ns, 6, out) == 16);
	assert(!strcmp(netstate_src_text(&ns, 6), "keep"));
}

/* R2: losing the rendezvous is worst exactly when a move needs it most, so it
 * is given up only once it has been asked and failed, and only for one that
 * has answered. */
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
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), a, 16, t);
	drain(&ns);

	/* another node answering does not displace one that is answering */
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), b, 16, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, a, 16));

	for (i = 0; i < NETSTATE_ANCHOR_MISSES; i++)
		netstate_on_rdv_attempt(&ns, 6, netstate_epoch(&ns, 6), t);
	assert(drain(&ns).f[1] & NSA_RDV_RELOCATE);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, a, 16));	/* still the best we have */
	assert(!confirmed);

	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), b, 16, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);
	assert(!memcmp(got, b, 16));	/* replaced, now that one was found */
}

/*
 * A move is followed by seconds in which nothing works yet, and none of that
 * is the rendezvous node's doing. Until the family is proven reachable, a
 * round that came back empty says only that we could not ask.
 */
static void silence_before_proof_condemns_nothing(void)
{
	struct netstate ns;
	uint8_t a[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed, i;

	start(&ns, 1);
	fill(a, 16, 70);
	give_src(&ns, 6, 20);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), a, 16, t);
	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);
	give_src(&ns, 6, 20);			/* routed, but nothing proven */
	assert(netstate_conn(&ns, 6) == NET_CONN_PENDING);
	drain(&ns);

	for (i = 0; i < NETSTATE_ANCHOR_MISSES * 4; i++) {
		netstate_on_rdv_attempt(&ns, 6, netstate_epoch(&ns, 6), t);
		t += NETSTATE_RDV_MS;
	}
	assert(!(drain(&ns).f[1] & NSA_RDV_RELOCATE));
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, a, 16));		/* still ours */

	/* proven, and now silence is the node's */
	netstate_on_roundtrip(&ns, 6, netstate_epoch(&ns, 6));
	drain(&ns);
	for (i = 0; i < NETSTATE_ANCHOR_MISSES; i++)
		netstate_on_rdv_attempt(&ns, 6, netstate_epoch(&ns, 6), t);
	assert(drain(&ns).f[1] & NSA_RDV_RELOCATE);
}

/* R4: the loop this runs on stalls for seconds behind a slow resolver. Time
 * passing is not evidence a node is gone; only rounds that went out and came
 * back empty are. */
static void attempts_not_milliseconds(void)
{
	struct netstate ns;
	uint8_t a[16], got[NETSTATE_SA_MAX];
	uint8_t glen;
	int confirmed, i;

	start(&ns, 1);
	fill(a, 16, 70);
	give_src(&ns, 6, 20);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), a, 16, t);
	drain(&ns);

	for (i = 0; i < 3600; i++) {	/* an hour, and not one attempt */
		t += 1000;
		netstate_tick(&ns, t);
		drain(&ns);
	}
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && confirmed);

	for (i = 0; i < NETSTATE_ANCHOR_MISSES; i++)
		netstate_on_rdv_attempt(&ns, 6, netstate_epoch(&ns, 6), t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed) && !confirmed);
}

/* R5: two moves in quick succession, with the caller busy in between. The
 * later one wins and nothing is skipped for having arrived late. */
static void latest_change_wins(void)
{
	struct netstate ns;
	struct netstate_actions a;
	uint32_t first, second;
	uint8_t addr[4];

	start(&ns, 1);
	netstate_on_netmon(&ns, NETMON_CH_V4, 1, 1, t);
	first = netstate_epoch(&ns, 4);
	netstate_on_netmon(&ns, NETMON_CH_V4, 1, 1, t);
	second = netstate_epoch(&ns, 4);
	assert(second != first);

	a = drain(&ns);
	assert(a.epoch[0] == second);
	assert(a.f[0] & NSA_SAMPLE_SRC);
	assert(a.f[0] & NSA_KICK_PROBE);

	fill(addr, 4, 10);
	netstate_on_src(&ns, 4, first, addr, 4, "old", t);
	assert(netstate_src_text(&ns, 4)[0] == '\0');
	netstate_on_src(&ns, 4, second, addr, 4, "new", t);
	assert(!strcmp(netstate_src_text(&ns, 4), "new"));
}

/* R1: host and client differ over what to do with a token and nothing else.
 * Any future host-only special case fails here rather than in a roaming
 * laptop's dashboard. */
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
		netstate_on_dht_ack(ns, 6, netstate_epoch(ns, 6), node, 16, t);
		netstate_on_netmon(ns, NETMON_CH_V6, 1, 0, t);
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
	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);
	assert(drain(&ns).f[1] & NSA_KICK_PROBE);
	netstate_on_probe_started(&ns, 6, netstate_epoch(&ns, 6), t);
	netstate_on_probe_done(&ns, 6, netstate_epoch(&ns, 6), t);
	t += NETSTATE_PROBE_MS;
	assert(probe_round(&ns, 6));

	/* and proof ends it */
	netstate_on_roundtrip(&ns, 6, netstate_epoch(&ns, 6));
	assert(drain(&ns).f[1] & NSA_STOP_PROBE);
	t += NETSTATE_PROBE_SLOW_MS;
	assert(!probe_round(&ns, 6));		/* nothing left to prove */
}

static void no_address_no_probe_no_pending(void)
{
	struct netstate ns;
	struct tokgen_facts fx;

	t = 1000;
	netstate_init(&ns, 1, t);
	netstate_on_netmon(&ns, 0, 1, 0, t);	/* v4 only */
	drain(&ns);

	give_src(&ns, 6, 20);			/* even a route proves nothing */
	assert(netstate_conn(&ns, 6) == 0);
	netstate_facts(&ns, 6, &fx);
	assert(!fx.has_usable_addr);
	netstate_tick(&ns, t);
	assert(!(drain(&ns).f[1] & NSA_KICK_PROBE));
}

/* The same address reaching us both ways means nothing translated it: one row,
 * and not the one marked NAT. */
static void row_merge_direct_beats_stun(void)
{
	struct netstate ns;
	const struct netstate_row *rows;
	uint8_t a[4];
	uint32_t e;

	start(&ns, 1);
	fill(a, 4, 10);
	e = netstate_epoch(&ns, 4);
	netstate_on_candidate(&ns, 4, e, NET_SCOPE_GLOBAL, NET_VIA_STUN, a, 4, "x");
	netstate_on_candidate(&ns, 4, e, NET_SCOPE_GLOBAL, NET_VIA_DIRECT, a, 4, "x");
	assert(netstate_rows(&ns, 4, &rows) == 1);
	assert(rows[0].via == NET_VIA_DIRECT);

	netstate_on_candidate(&ns, 4, e, NET_SCOPE_GLOBAL, NET_VIA_STUN, a, 4, "x");
	assert(netstate_rows(&ns, 4, &rows) == 1);
	assert(rows[0].via == NET_VIA_DIRECT);
}

/*
 * Build a family up into one of sixteen states, so the lattice below starts
 * from something worth preserving rather than from zero.
 */
static void build(struct netstate *ns, int fam, int bits)
{
	uint8_t node[16];

	if (bits & 1)
		give_src(ns, fam, (uint8_t)(10 + fam));
	if (bits & 2)
		netstate_on_roundtrip(ns, fam, netstate_epoch(ns, fam));
	if (bits & 4) {
		fill(node, 16, (uint8_t)(70 + fam));
		netstate_on_dht_ack(ns, fam, netstate_epoch(ns, fam), node, 16, t);
	}
	if (bits & 8) {
		uint8_t a[16];
		int len = fam == 6 ? 16 : 4;

		fill(a, len, (uint8_t)(90 + fam));
		netstate_on_candidate(ns, fam, netstate_epoch(ns, fam),
				      NET_SCOPE_GLOBAL, NET_VIA_DIRECT, a, len,
				      "row");
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

				netstate_on_netmon(&ns, mask[m], 1, 1, t);
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
				netstate_on_rdv_offered(&ns, fam, node, 16);
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
							"z", t + 1);
					break;
				case 3:
					netstate_on_probe_done(&ns, fam, e,
							       t + 1);
					break;
				default:
					netstate_on_rdv_attempt(&ns, fam, e,
								t + 1);
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
			netstate_on_netmon(&ns, m, h4, h6, t);
			k = (m == NETMON_CH_V6);
			sh_epoch[k]++;
			sh_has[k] = k ? h6 : h4;
			sh_routed[k] = 0;
			break;
		}
		case 1:
			netstate_on_src(&ns, fam, e, a, fam == 6 ? 16 : 4,
					"s", t);
			if (e == sh_epoch[k])
				sh_routed[k] = 1;
			break;
		case 2:
			netstate_on_src(&ns, fam, e, NULL, 0, NULL, t);
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
			netstate_on_rdv_attempt(&ns, fam, e, t);
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
	v6_change_leaves_v4_alone();
	preserved_anchor_is_not_proof();
	stale_roundtrip_never_marks_up();
	src_survives_the_roam_window();
	late_src_retracts_the_wrong_row();
	src_is_never_stale_on_the_wire();
	anchor_changes_only_on_replacement();
	silence_before_proof_condemns_nothing();
	attempts_not_milliseconds();
	latest_change_wins();
	host_and_client_agree_except_on_the_token();
	probe_slows_but_never_stops();
	no_address_no_probe_no_pending();
	row_merge_direct_beats_stun();
	family_independence_lattice();
	epoch_gate_exhaustive();
	laws_hold_under_churn();
	return 0;
}
