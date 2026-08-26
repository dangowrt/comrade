/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "netstate.h"

static int fam_idx(int family)
{
	return family == 6 ? 1 : 0;
}

static void raise_act(struct netstate *ns, int i, unsigned bits)
{
	ns->pend[i] |= bits;
}

static int conn_of(const struct netstate_fam *f)
{
	if (!f->has_addr)
		return 0;
	if (f->up_epoch == f->epoch)
		return NET_CONN_UP;
	return f->routed ? NET_CONN_PENDING : 0;
}

static void sync_conn(struct netstate *ns, int i)
{
	struct netstate_fam *f = &ns->f[i];
	int want = conn_of(f);

	if (want == f->conn)
		return;
	f->conn = want;
	raise_act(ns, i, NSA_EMIT_CONN);
}

static uint64_t probe_gap(const struct netstate_fam *f)
{
	return f->probe_rounds < NETSTATE_PROBE_ROUNDS ? NETSTATE_PROBE_MS :
							 NETSTATE_PROBE_SLOW_MS;
}

static void facts_moved(struct netstate *ns, int i)
{
	if (ns->is_host)
		raise_act(ns, i, NSA_EMIT_TOKEN);
}

/*
 * Which of this family's addresses belong on the dashboard, recomputed over
 * the whole set: whether a global v6 is ours to show turns on the source
 * address, routinely learnt after the addresses are.
 *
 * With a source known, one globally scoped v6 we gathered is shown -- the one
 * we source from; the rest are the stable and DHCPv6 addresses ICE also
 * enumerates, which we neither listen on nor punch from. With none known
 * nothing is held back. A server-reflexive v6 is always shown: behind NAT66 it
 * is the only address a peer could use.
 */
static int recompute_rows(struct netstate_fam *f)
{
	int have_src = f->src_epoch == f->epoch && f->src_len == 16;
	int moved = 0, i;

	for (i = 0; i < f->nrows; i++) {
		struct netstate_row *r = &f->rows[i];
		int show = 1;

		if (have_src && r->addr_len == 16 &&
		    r->scope == NET_SCOPE_GLOBAL && r->via == NET_VIA_DIRECT)
			show = !memcmp(r->addr, f->src, 16);
		if (show != r->shown) {
			r->shown = show;
			moved = 1;
		}
	}
	return moved;
}

void netstate_init(struct netstate *ns, int is_host, uint64_t now)
{
	int i;

	memset(ns, 0, sizeof(*ns));
	ns->is_host = is_host;
	for (i = 0; i < 2; i++) {
		ns->f[i].epoch = 1;	/* so a fact stamped zero is from no
					 * network we have been on */
		ns->f[i].src_next_ms = now;
		ns->f[i].probe_next_ms = now;
		ns->f[i].anchor_next_ms = now;
	}
}

void netstate_on_netmon(struct netstate *ns, unsigned changed, int have4,
			int have6, uint64_t now)
{
	int have[2], i;

	have[0] = have4;
	have[1] = have6;
	for (i = 0; i < 2; i++) {
		struct netstate_fam *f = &ns->f[i];
		unsigned bit = i ? NETMON_CH_V6 : NETMON_CH_V4;

		if (!(changed & bit)) {
			if (!ns->primed && f->has_addr != have[i]) {
				f->has_addr = have[i];
				sync_conn(ns, i);
				facts_moved(ns, i);
			}
			continue;
		}

		f->epoch++;
		f->has_addr = have[i];

		/* src is kept but stops being current: "unchanged across the
		 * move" has to stay distinguishable from "not up yet". */
		f->routed = 0;
		f->src_tries = 0;
		f->src_next_ms = now;

		f->anchor_confirmed = 0;
		f->anchor_acks = 0;
		f->anchor_first_ms = 0;
		f->anchor_quiet = 0;
		f->anchor_next_ms = now;

		f->dht_acked = 0;
		f->concluded = 0;

		f->probe_rounds = 0;
		f->probe_running = 0;	/* whatever is in flight was started
					 * for a network we have left */
		f->probe_next_ms = now;

		f->nrows = 0;
		f->conn = conn_of(f);

		raise_act(ns, i, NSA_SAMPLE_SRC | NSA_KICK_PROBE |
			  NSA_EMIT_ROWS | NSA_EMIT_CONN);
		if (f->anchor_len)
			raise_act(ns, i, NSA_RDV_PIN | NSA_EMIT_RDV);
		facts_moved(ns, i);
	}
	ns->primed = 1;
}

void netstate_on_src(struct netstate *ns, int family, uint32_t epoch,
		     const uint8_t *addr, int len, const char *text,
		     uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (epoch != f->epoch)
		return;

	if (len <= 0 || !addr) {
		/* No route yet is not a reason to forget the address we hold:
		 * usually an RA or DHCPv6 that has not finished. */
		f->src_tries++;
		f->src_next_ms = now +
			(f->src_tries < NETSTATE_SRC_FAST_TRIES ?
			 NETSTATE_SRC_FAST_MS : NETSTATE_SRC_SLOW_MS);
		if (f->routed) {
			f->routed = 0;
			sync_conn(ns, i);
			facts_moved(ns, i);
		}
		return;
	}

	f->src_tries = 0;
	f->src_next_ms = now + NETSTATE_SRC_SLOW_MS;
	if ((size_t)len > sizeof(f->src))
		len = (int)sizeof(f->src);
	if (f->src_epoch != f->epoch || f->src_len != (uint8_t)len ||
	    memcmp(f->src, addr, (size_t)len)) {
		memset(f->src, 0, sizeof(f->src));
		memcpy(f->src, addr, (size_t)len);
		f->src_len = (uint8_t)len;
		f->src_epoch = f->epoch;
		f->src_text[0] = '\0';
		if (text) {
			strncpy(f->src_text, text, sizeof(f->src_text) - 1);
			f->src_text[sizeof(f->src_text) - 1] = '\0';
		}
		if (recompute_rows(f))
			raise_act(ns, i, NSA_EMIT_ROWS);
	}
	if (!f->routed) {
		f->routed = 1;
		sync_conn(ns, i);
		facts_moved(ns, i);
	}
}

void netstate_on_probe_started(struct netstate *ns, int family, uint32_t epoch,
			       uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (epoch != f->epoch)
		return;
	f->probe_running = 1;
	f->probe_rounds++;
	f->probe_next_ms = now + probe_gap(f);
}

void netstate_on_probe_done(struct netstate *ns, int family, uint32_t epoch,
			    uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (epoch != f->epoch)
		return;
	f->probe_running = 0;
	if (f->probe_next_ms > now + probe_gap(f))
		f->probe_next_ms = now + probe_gap(f);
}

void netstate_on_roundtrip(struct netstate *ns, int family, uint32_t epoch)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (epoch != f->epoch)
		return;
	f->up_epoch = epoch;
	sync_conn(ns, i);
}

void netstate_on_dht_ack(struct netstate *ns, int family, uint32_t epoch,
			 const uint8_t *node, int len, uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (epoch != f->epoch)
		return;

	f->up_epoch = epoch;
	sync_conn(ns, i);
	if (!f->dht_acked) {
		f->dht_acked = 1;
		facts_moved(ns, i);
	}

	if (!node || len <= 0 || (size_t)len > sizeof(f->anchor))
		return;

	f->anchor_next_ms = now + NETSTATE_RDV_MS;
	if (f->anchor_len && f->anchor_len == (uint8_t)len &&
	    !memcmp(f->anchor, node, (size_t)len)) {
		f->anchor_quiet = 0;
		if (!f->anchor_acks)
			f->anchor_first_ms = now;
		if (f->anchor_acks < NETSTATE_ANCHOR_QUALIFY)
			f->anchor_acks++;
		return;			/* the tick confirms, once it has lasted */
	}
	/*
	 * A different node. A client does not get to pick: the rendezvous is
	 * whichever node the host named, and only the host keeps that one's copy
	 * of the mailbox current. Another node holding the key may well answer --
	 * the convergent store put it on several -- but with a copy that stopped
	 * being refreshed, so following it reads an offer that never changes
	 * again.
	 */
	if (!ns->is_host)
		return;
	/*
	 * This says nothing whatever about the node we hold. Several nodes hold
	 * the value by design and the quickest answers, so treating another
	 * holder's reply as ours falling silent walks the rendezvous from one
	 * live node to the next within a minute of starting -- retracting a
	 * token that had already been copied, which is the one failure this must
	 * never cause. Only the node's own silence, counted where it can be seen
	 * (netstate_on_anchor_seen), may unseat it.
	 */
	if (f->anchor_len && f->anchor_quiet < NETSTATE_ANCHOR_GONE)
		return;
	memset(f->anchor, 0, sizeof(f->anchor));
	memcpy(f->anchor, node, (size_t)len);
	f->anchor_len = (uint8_t)len;
	f->anchor_confirmed = 0;	/* it has answered once; that is not yet
					 * enough to put in front of anyone */
	f->anchor_acks = 1;
	f->anchor_first_ms = now;
	f->anchor_quiet = 0;
	raise_act(ns, i, NSA_RDV_PIN | NSA_EMIT_RDV);
}

void netstate_on_anchor_seen(struct netstate *ns, int family, uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (!f->anchor_len)
		return;
	f->anchor_quiet = 0;
	if (!f->anchor_acks)
		f->anchor_first_ms = now;
	if (f->anchor_acks < NETSTATE_ANCHOR_QUALIFY)
		f->anchor_acks++;
}

void netstate_on_rdv_offered(struct netstate *ns, int family,
			     const uint8_t *node, int len)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (!node || len <= 0 || (size_t)len > sizeof(f->anchor))
		return;
	if (f->anchor_len == (uint8_t)len &&
	    !memcmp(f->anchor, node, (size_t)len))
		return;
	memset(f->anchor, 0, sizeof(f->anchor));
	memcpy(f->anchor, node, (size_t)len);
	f->anchor_len = (uint8_t)len;
	f->anchor_confirmed = 0;
	f->anchor_acks = 0;
	f->anchor_first_ms = 0;
	f->anchor_quiet = 0;
	raise_act(ns, i, NSA_RDV_PIN | NSA_EMIT_RDV);
}

void netstate_on_candidate(struct netstate *ns, int family, uint32_t epoch,
			   int scope, int via, const uint8_t *addr, int len,
			   const char *text)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];
	struct netstate_row *r = NULL;
	int k;

	if (epoch != f->epoch || !addr || (len != 4 && len != 16))
		return;

	for (k = 0; k < f->nrows; k++)
		if (f->rows[k].addr_len == (uint8_t)len &&
		    !memcmp(f->rows[k].addr, addr, (size_t)len)) {
			r = &f->rows[k];
			break;
		}
	if (!r) {
		if (f->nrows >= NETSTATE_ROWS_MAX)
			return;
		r = &f->rows[f->nrows++];
		memset(r, 0, sizeof(*r));
		memcpy(r->addr, addr, (size_t)len);
		r->addr_len = (uint8_t)len;
		r->scope = scope;
		r->via = via;
		if (text) {
			strncpy(r->text, text, sizeof(r->text) - 1);
			r->text[sizeof(r->text) - 1] = '\0';
		}
	} else if (r->via == NET_VIA_STUN && via == NET_VIA_DIRECT) {
		/* Reached us both ways, so nothing translated it. */
		r->via = NET_VIA_DIRECT;
	} else {
		return;
	}
	recompute_rows(f);
	raise_act(ns, i, NSA_EMIT_ROWS);
}

void netstate_on_dht_concluded(struct netstate *ns, int family, int concluded)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (f->concluded == !!concluded)
		return;
	f->concluded = !!concluded;
	facts_moved(ns, i);
}

void netstate_tick(struct netstate *ns, uint64_t now)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct netstate_fam *f = &ns->f[i];

		if (now >= f->src_next_ms) {
			raise_act(ns, i, NSA_SAMPLE_SRC);
			f->src_next_ms = now +
				(f->src_tries < NETSTATE_SRC_FAST_TRIES ?
				 NETSTATE_SRC_FAST_MS : NETSTATE_SRC_SLOW_MS);
		}
		/* Reachability is one of two things a round answers. The other
		 * is which public addresses this NAT maps us to, which takes
		 * every server it asks and is not settled by the first reply,
		 * so being proven up is no reason to stop asking. */
		if (f->has_addr && !f->probe_running &&
		    now >= f->probe_next_ms) {
			raise_act(ns, i, NSA_KICK_PROBE);
			f->probe_next_ms = now + probe_gap(f);
		}
		/* Only on a network this family has proven: elsewhere the
		 * silence is as likely ours. Searching does not unseat the
		 * node -- it is what lets a different one answer at all. */
		if (f->anchor_len && now >= f->anchor_next_ms) {
			f->anchor_next_ms = now + NETSTATE_RDV_MS;
			if (f->conn == NET_CONN_UP &&
			    ++f->anchor_quiet >= NETSTATE_ANCHOR_QUIET)
				raise_act(ns, i, NSA_RDV_RELOCATE);
		}
		if (f->anchor_len && !f->anchor_confirmed &&
		    f->anchor_acks >= NETSTATE_ANCHOR_QUALIFY &&
		    now - f->anchor_first_ms >= NETSTATE_ANCHOR_PROVE_MS) {
			f->anchor_confirmed = 1;
			raise_act(ns, i, NSA_EMIT_RDV);
			facts_moved(ns, i);
		}
	}
}

void netstate_resync(struct netstate *ns)
{
	int i;

	for (i = 0; i < 2; i++)
		raise_act(ns, i, NSA_EMIT_ROWS | NSA_EMIT_CONN | NSA_EMIT_RDV);
}

int netstate_take_actions(struct netstate *ns, struct netstate_actions *out)
{
	int i, any = 0;

	for (i = 0; i < 2; i++) {
		out->f[i] = ns->pend[i];
		out->epoch[i] = ns->f[i].epoch;
		if (ns->pend[i])
			any = 1;
		ns->pend[i] = 0;
	}
	return any;
}

int netstate_conn(const struct netstate *ns, int family)
{
	return ns->f[fam_idx(family)].conn;
}

uint32_t netstate_epoch(const struct netstate *ns, int family)
{
	return ns->f[fam_idx(family)].epoch;
}

const char *netstate_src_text(const struct netstate *ns, int family)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];

	if (f->src_epoch != f->epoch || !f->src_len)
		return "";
	return f->src_text;
}

int netstate_src(const struct netstate *ns, int family, uint8_t *out16)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];

	if (f->src_epoch != f->epoch || !f->src_len)
		return 0;
	if (out16)
		memcpy(out16, f->src, sizeof(f->src));
	return f->src_len;
}

int netstate_rows(const struct netstate *ns, int family,
		  const struct netstate_row **out)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];

	if (out)
		*out = f->rows;
	return f->nrows;
}

void netstate_facts(const struct netstate *ns, int family,
		    struct tokgen_facts *out)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];

	memset(out, 0, sizeof(*out));
	out->has_usable_addr = f->has_addr;
	out->has_default_route = f->routed;
	/*
	 * A node we hold and can still reach counts, even before it has
	 * answered again here: a move clears the acknowledgement but not the
	 * rendezvous, and dropping the family to pending in that gap makes the
	 * token flap on every move. Reachability is the conjunct that matters
	 * -- advertising a meeting point this host cannot get to would strand
	 * whoever went there.
	 */
	out->dht_acked = f->anchor_confirmed && f->conn == NET_CONN_UP;
	out->dht_attempt_concluded = f->concluded;
	out->public_port_proven = 0;	/* no UPnP/NAT-PMP/PCP in the tree */
}

void netstate_reach(const struct netstate *ns, int family, int *conn,
		    int *dht_acked)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];

	if (conn)
		*conn = f->conn;
	if (dht_acked)
		*dht_acked = f->dht_acked;
}

int netstate_anchor(const struct netstate *ns, int family, uint8_t *out,
		    uint8_t *out_len, int *confirmed)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];

	if (!f->anchor_len)
		return 0;
	if (out)
		memcpy(out, f->anchor, f->anchor_len);
	if (out_len)
		*out_len = f->anchor_len;
	if (confirmed)
		*confirmed = f->anchor_confirmed;
	return 1;
}
