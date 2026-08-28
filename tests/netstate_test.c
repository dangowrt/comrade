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
	qualify(&ns, 6, node);
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
	assert(drain(&ns).f[1] & NSA_RDV_PIN);

	/* and it earns its way back */
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
	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);
	assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);

	for (i = 0; i < NETSTATE_SRC_FAST_TRIES; i++) {
		netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), NULL, 0, NULL,
				t);
		t += NETSTATE_SRC_FAST_MS;
		netstate_tick(&ns, t);
		drain(&ns);
	}
	netstate_on_src(&ns, 6, netstate_epoch(&ns, 6), NULL, 0, NULL, t);
	t += NETSTATE_SRC_FAST_MS;
	netstate_tick(&ns, t);
	assert(!(drain(&ns).f[1] & NSA_SAMPLE_SRC));
	t += NETSTATE_SRC_SLOW_MS;
	netstate_tick(&ns, t);
	assert(drain(&ns).f[1] & NSA_SAMPLE_SRC);
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

	/* and a move keeps it, unconfirmed until it answers here too */
	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);
	assert(netstate_anchor(&ns, 6, got, &glen, &confirmed));
	assert(!memcmp(got, a, 16));
	assert(!confirmed);
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
	/* And the search that could turn up another one is asked for: the
	 * direct get only ever asks the nodes already held. */
	assert(a.f[1] & NSA_RDV_RELOCATE);
	assert(a.f[1] & NSA_EMIT_RDV);
	/* The other family is untouched by any of it. */
	assert(!(a.f[0] & NSA_RDV_RELOCATE));

	/* And the next node to answer takes the empty place. */
	fill(node, 16, 90);
	netstate_on_dht_ack(&ns, 6, netstate_epoch(&ns, 6), node, 16, t);
	assert(netstate_anchor(&ns, 6, NULL, NULL, NULL));
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
	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);
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
	netstate_on_netmon(&ns, NETMON_CH_V6, 1, 1, t);
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
							"z", t + 1);
					break;
				case 3:
					netstate_on_probe_done(&ns, fam, e,
							       t + 1);
					break;
				default:
					netstate_on_candidate(&ns, fam, e,
							      NET_SCOPE_GLOBAL,
							      NET_VIA_DIRECT, a,
							      fam == 6 ? 16 : 4,
							      "z");
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
			netstate_on_candidate(&ns, fam, e, NET_SCOPE_GLOBAL,
					      NET_VIA_DIRECT, a,
					      fam == 6 ? 16 : 4, "c");
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
	an_address_that_never_comes_stops_being_hurried();
	late_src_retracts_the_wrong_row();
	src_is_never_stale_on_the_wire();
	an_answer_confirms_without_a_tick();
	an_answer_alone_confirms_nothing();
	anchor_changes_only_on_replacement();
	only_another_answer_condemns();
	quiet_searches_without_giving_up();
	quiet_says_nothing_until_the_family_is_up();
	a_candidate_that_never_qualifies_is_dropped();
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
	no_address_no_probe_no_pending();
	row_merge_direct_beats_stun();
	family_independence_lattice();
	epoch_gate_exhaustive();
	laws_hold_under_churn();
	return 0;
}
