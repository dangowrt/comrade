/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "wsock.h"

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

static int addr_scope_raw(const uint8_t *b, int len)
{
	if (len == 16) {
		if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)	/* fe80::/10 */
			return NET_SCOPE_LAN;
		if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0)	/* fec0::/10 */
			return NET_SCOPE_LAN;
		if ((b[0] & 0xfe) == 0xfc)			/* fc00::/7 ULA */
			return NET_SCOPE_LAN;
		return NET_SCOPE_GLOBAL;
	}
	if (b[0] == 10 || (b[0] == 192 && b[1] == 168) ||
	    (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
	    (b[0] == 169 && b[1] == 254))
		return NET_SCOPE_LAN;
	if (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
		return NET_SCOPE_CGNAT;
	return NET_SCOPE_GLOBAL;
}

static int local_idx(const struct netstate_fam *f, const uint8_t *a, int len)
{
	int i;

	for (i = 0; i < f->nlocals; i++)
		if (f->locals[i].len == (uint8_t)len &&
		    !memcmp(f->locals[i].addr, a, (size_t)len))
			return i;
	return -1;
}

static int snap_has(const struct netmon_addr *addrs, size_t n, int af,
		    const uint8_t *a, int len)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (addrs[i].family == af && addrs[i].addrlen == (uint8_t)len &&
		    !memcmp(addrs[i].addr, a, (size_t)len))
			return 1;
	return 0;
}

/* Non-zero when it was held as one: the exchange that named it stands, so the
 * address takes its proof with it into the kernel's set. */
static int xlat_forget(struct netstate_fam *f, const uint8_t *a, int len)
{
	int i;

	for (i = 0; i < f->nxlats; i++) {
		if (f->xlats[i].len != (uint8_t)len ||
		    memcmp(f->xlats[i].addr, a, (size_t)len))
			continue;
		memmove(&f->xlats[i], &f->xlats[i + 1],
			sizeof(f->xlats[0]) * (size_t)(f->nxlats - 1 - i));
		memset(&f->xlats[--f->nxlats], 0, sizeof(f->xlats[0]));
		return 1;
	}
	return 0;
}

/* The kernel's set, taken as this family's; non-zero when it moved. Removals
 * walk down, so dropping one cannot skip an entry still to be tested. */
static int local_sync(struct netstate_fam *f, int af,
		      const struct netmon_addr *addrs, size_t n)
{
	int len = af == AF_INET6 ? 16 : 4;
	struct netstate_local *l;
	int moved = 0, k;
	size_t i;

	for (k = f->nlocals - 1; k >= 0; k--) {
		if (snap_has(addrs, n, af, f->locals[k].addr, f->locals[k].len))
			continue;
		memmove(&f->locals[k], &f->locals[k + 1],
			sizeof(f->locals[0]) * (size_t)(f->nlocals - 1 - k));
		memset(&f->locals[--f->nlocals], 0, sizeof(f->locals[0]));
		moved = 1;
	}
	for (i = 0; i < n && f->nlocals < NETSTATE_LOCAL_MAX; i++) {
		if (addrs[i].family != af || addrs[i].addrlen != (uint8_t)len)
			continue;
		if (local_idx(f, addrs[i].addr, len) >= 0)
			continue;
		l = &f->locals[f->nlocals++];
		memset(l, 0, sizeof(*l));
		memcpy(l->addr, addrs[i].addr, (size_t)len);
		l->len = (uint8_t)len;
		l->scope = (uint8_t)addr_scope_raw(addrs[i].addr, len);
		l->proven = (uint8_t)xlat_forget(f, addrs[i].addr, len);
		moved = 1;
	}
	return moved;
}

static void proofs_demote(struct netstate_fam *f)
{
	int i;

	for (i = 0; i < f->nlocals; i++)
		f->locals[i].proven = 0;
}

/* Non-zero when it was not held already, so a producer may re-offer freely. */
static int xlat_note(struct netstate_fam *f, const uint8_t *a, int len)
{
	struct netstate_xlat *x;
	int i;

	for (i = 0; i < f->nxlats; i++)
		if (f->xlats[i].len == (uint8_t)len &&
		    !memcmp(f->xlats[i].addr, a, (size_t)len))
			return 0;
	if (f->nxlats >= NETSTATE_XLAT_MAX)
		return 0;
	x = &f->xlats[f->nxlats++];
	memset(x, 0, sizeof(*x));
	memcpy(x->addr, a, (size_t)len);
	x->len = (uint8_t)len;
	x->scope = (uint8_t)addr_scope_raw(a, len);
	return 1;
}

void netstate_init(struct netstate *ns, int is_host, uint64_t now)
{
	int i;

	memset(ns, 0, sizeof(*ns));
	ns->is_host = is_host;
	for (i = 0; i < 2; i++) {
		ns->f[i].picking = is_host;	/* a client only while asked */
		ns->f[i].epoch = 1;	/* so a fact stamped zero is from no
					 * network we have been on */
		ns->f[i].src_next_ms = now;
		ns->f[i].probe_next_ms = now;
		ns->f[i].anchor_next_ms = now;
	}
}

void netstate_on_netmon(struct netstate *ns, unsigned changed,
			const struct netmon_addr *addrs, size_t naddrs,
			uint64_t now)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct netstate_fam *f = &ns->f[i];
		unsigned bit = i ? NETMON_CH_V6 : NETMON_CH_V4;

		if (local_sync(f, i ? AF_INET6 : AF_INET, addrs, naddrs))
			raise_act(ns, i, NSA_EMIT_ROWS);
		if (f->has_addr != !!f->nlocals) {
			f->has_addr = !!f->nlocals;
			sync_conn(ns, i);
			facts_moved(ns, i);
		}
		if (!(changed & bit))
			continue;

		f->epoch++;

		/* src is kept but stops being current: "unchanged across the
		 * move" has to stay distinguishable from "not up yet". */
		f->routed = 0;
		f->src_tries = 0;
		f->src_next_ms = now;

		/* A move bears on our reachability, not on the node: both
		 * proofs stay, and the quiet detector, counting only once the
		 * family is up again, may unseat it. Acks were per epoch. */
		f->anchor_acks = 0;
		/* A candidate gets its full run on the network it is now to
		 * prove itself on, rather than inheriting a clock from the one
		 * we have left. What has qualified stays not-a-candidate: it
		 * may be in a token, and moving does not take that back. */
		f->anchor_set_ms = now;
		f->anchor_first_ms = 0;
		f->anchor_quiet = 0;
		f->anchor_next_ms = now;
		f->ncands = 0;		/* they answered on a network we left */

		f->dht_acked = 0;
		f->concluded = 0;

		f->probe_rounds = 0;
		f->probe_wanted = 0;
		f->probe_running = 0;	/* whatever is in flight was started
					 * for a network we have left */
		f->probe_next_ms = now;

		/* A proof is about the network it was made on; the addresses
		 * are the kernel's and are not ours to forget. */
		proofs_demote(f);
		f->nxlats = 0;
		f->conn = conn_of(f);

		raise_act(ns, i, NSA_SAMPLE_SRC | NSA_KICK_PROBE |
			  NSA_EMIT_ROWS | NSA_EMIT_CONN);
		if (f->anchor_len)
			raise_act(ns, i, NSA_RDV_PIN | NSA_EMIT_RDV);
		facts_moved(ns, i);
	}
}

/* fe80::/10 reaches nothing off-link, so the kernel naming it as the source for
 * one means the global address is still tentative, not that we send from this.
 * Only v6: an APIPA v4 source is how a segment with no DHCP is served. */
static int src_unusable(const uint8_t *addr, int len)
{
	return len == 16 && addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80;
}

void netstate_on_src(struct netstate *ns, int family, uint32_t epoch,
		     const uint8_t *addr, int len, int scope, const char *text,
		     uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (epoch != f->epoch)
		return;

	if (len <= 0 || !addr || src_unusable(addr, len)) {
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
		f->src_scope = scope;
		f->src_epoch = f->epoch;
		f->src_text[0] = '\0';
		if (text) {
			strncpy(f->src_text, text, sizeof(f->src_text) - 1);
			f->src_text[sizeof(f->src_text) - 1] = '\0';
		}
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
	f->probe_wanted = 0;
	f->probe_rounds++;
	f->probe_next_ms = now + probe_gap(f);
}

void netstate_on_probe_deferred(struct netstate *ns, int family, uint32_t epoch)
{
	struct netstate_fam *f = &ns->f[fam_idx(family)];

	if (epoch != f->epoch)
		return;
	f->probe_wanted = 1;
}

void netstate_on_probe_done(struct netstate *ns, int family, uint32_t epoch,
			    uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (epoch != f->epoch)
		return;
	f->probe_running = 0;
	if (f->probe_wanted) {
		f->probe_wanted = 0;
		f->probe_next_ms = now;
		raise_act(ns, i, NSA_KICK_PROBE);
		return;
	}
	if (f->probe_next_ms > now + probe_gap(f))
		f->probe_next_ms = now + probe_gap(f);
}

void netstate_on_servers(struct netstate *ns, int family, uint32_t epoch,
			 uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	if (epoch != f->epoch || f->probe_running)
		return;
	f->probe_next_ms = now;
	raise_act(ns, i, NSA_KICK_PROBE);
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

/*
 * Record that `node` answered, as one of the nodes on trial for this family.
 * Answers 1 once it has answered often enough, and for long enough, to be
 * worth putting in front of anyone -- the same bar an anchor has to clear,
 * since a node chosen this way is indistinguishable from one chosen any other.
 *
 * The weakest entry gives way when the set is full: a node that has answered
 * more times, or begun answering sooner, is the better prospect, and a set
 * churning through every node that ever replies would never accumulate a run
 * from any of them.
 */
static int cand_ack(struct netstate_fam *f, const uint8_t *node, int len,
		    uint64_t now)
{
	struct netstate_cand *c = NULL;
	int i, worst = 0;

	for (i = 0; i < f->ncands; i++)
		if (f->cands[i].len == (uint8_t)len &&
		    !memcmp(f->cands[i].addr, node, (size_t)len)) {
			c = &f->cands[i];
			break;
		}
	if (!c) {
		if (f->ncands < NETSTATE_CANDS_MAX) {
			c = &f->cands[f->ncands++];
		} else {
			for (i = 1; i < f->ncands; i++)
				if (f->cands[i].acks < f->cands[worst].acks ||
				    (f->cands[i].acks == f->cands[worst].acks &&
				     f->cands[i].first_ms >
				     f->cands[worst].first_ms))
					worst = i;
			if (f->cands[worst].acks >= NETSTATE_ANCHOR_QUALIFY)
				return 0;	/* all of them are doing better */
			c = &f->cands[worst];
		}
		memset(c, 0, sizeof(*c));
		memcpy(c->addr, node, (size_t)len);
		c->len = (uint8_t)len;
		c->first_ms = now;
	}
	c->seen_ms = now;
	if (c->acks < NETSTATE_ANCHOR_QUALIFY)
		c->acks++;
	return c->acks >= NETSTATE_ANCHOR_QUALIFY &&
	       now - c->first_ms >= NETSTATE_ANCHOR_PROVE_MS;
}

/*
 * Take `node` as this family's anchor. `candidate` says whether it is ours on
 * trial (so the deadline applies) and `acks` how many answers it arrives with:
 * one for a node that just served us, none for one merely named to us.
 * Answers 1 when the anchor moved.
 */
static int anchor_set(struct netstate *ns, int i, const uint8_t *node, int len,
		      uint64_t now, int candidate, int acks)
{
	struct netstate_fam *f = &ns->f[i];

	if (!node || len <= 0 || (size_t)len > sizeof(f->anchor))
		return 0;
	if (f->anchor_len == (uint8_t)len &&
	    !memcmp(f->anchor, node, (size_t)len))
		return 0;
	memset(f->anchor, 0, sizeof(f->anchor));
	memcpy(f->anchor, node, (size_t)len);
	f->anchor_len = (uint8_t)len;
	f->anchor_confirmed = 0;	/* arriving is never qualifying */
	f->anchor_vouched = 0;
	f->anchor_candidate = candidate;
	f->anchor_acks = acks;
	f->anchor_set_ms = now;
	f->anchor_first_ms = acks ? now : 0;
	f->anchor_quiet = 0;
	raise_act(ns, i, NSA_RDV_PIN | NSA_EMIT_RDV);
	return 1;
}

/*
 * Has the anchor answered often enough, for long enough, to be named in a
 * token? Applied both on the tick and wherever an answer lands: a client with
 * a session up is not ticked -- nothing watches the interfaces while a link
 * holds -- so an anchor of its own could never qualify there, and it could
 * never tell its peer where it rendezvous.
 */
static void anchor_confirm(struct netstate *ns, int i, uint64_t now)
{
	struct netstate_fam *f = &ns->f[i];

	if (!f->anchor_len || f->anchor_confirmed)
		return;
	if (f->anchor_acks < NETSTATE_ANCHOR_QUALIFY ||
	    now - f->anchor_first_ms < NETSTATE_ANCHOR_PROVE_MS)
		return;
	f->anchor_confirmed = 1;
	/* From here it may be named in a token, so it stops being ours to drop
	 * and can only be replaced. */
	f->anchor_candidate = 0;
	raise_act(ns, i, NSA_EMIT_RDV);
	facts_moved(ns, i);
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
		anchor_confirm(ns, i, now);
		return;
	}
	/*
	 * A different node. A client does not get to pick: the rendezvous is
	 * whichever node the host named, and only the host keeps that one's copy
	 * of the mailbox current. Another node holding the key may well answer --
	 * the convergent store put it on several -- but with a copy that stopped
	 * being refreshed, so following it reads an offer that never changes
	 * again. Being asked to find one for the peer is the exception, and the
	 * only one.
	 */
	if (!f->picking)
		return;
	/*
	 * Nothing has qualified yet, so this node is on trial beside whatever
	 * else is answering, and the first to earn its place takes it. Waiting
	 * out one node at a time made the cost of a dead one the whole give-up
	 * window, repeated; they are all answering anyway.
	 */
	if (!f->anchor_confirmed && cand_ack(f, node, len, now)) {
		anchor_set(ns, i, node, len, now, 0, NETSTATE_ANCHOR_QUALIFY);
		f->anchor_confirmed = 1;
		f->ncands = 0;
		raise_act(ns, i, NSA_EMIT_RDV);
		facts_moved(ns, i);
		return;
	}
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
	/* It has answered once, which is not yet enough to put in front of
	 * anyone: ours, on trial, and not yet anybody's. */
	anchor_set(ns, i, node, len, now, 1, 1);
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
			     const uint8_t *node, int len, uint64_t now)
{
	/* Not a candidate: this is where the peer says it is, and following
	 * that is the point. Failing to prove it here is not grounds for us to
	 * pick somewhere else. */
	anchor_set(ns, fam_idx(family), node, len, now, 0, 0);
}

void netstate_on_rdv_vouched(struct netstate *ns, int family,
			     const uint8_t *node, int len, uint64_t now)
{
	int i = fam_idx(family);
	struct netstate_fam *f = &ns->f[i];

	anchor_set(ns, i, node, len, now, 0, 0);
	if (!f->anchor_len || f->anchor_vouched)
		return;
	f->anchor_vouched = 1;
	f->anchor_candidate = 0;	/* proven somewhere: no longer ours to
					 * drop, only to replace */
	raise_act(ns, i, NSA_EMIT_RDV);
	facts_moved(ns, i);
}

void netstate_set_picking(struct netstate *ns, int family, int on)
{
	struct netstate_fam *f = &ns->f[fam_idx(family)];

	if (f->picking == on)
		return;
	f->picking = on;
	if (!on)
		f->ncands = 0;
}

void netstate_on_reflexive(struct netstate *ns, int family, uint32_t epoch,
			   const uint8_t *addr, int len)
{
	struct netstate_fam *f = &ns->f[fam_idx(family)];
	int i = fam_idx(family);
	int k;

	if (epoch != f->epoch || !addr || len != (family == 6 ? 16 : 4))
		return;

	k = local_idx(f, addr, len);
	/* A LAN address never enters the proven/unproven distinction. */
	if (k >= 0 && (f->locals[k].proven ||
		       f->locals[k].scope == NET_SCOPE_LAN))
		return;
	if (k >= 0)
		f->locals[k].proven = 1;
	else if (!xlat_note(f, addr, len))
		return;
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

/* A candidate that did not earn its place: nobody has been shown it, so it
 * simply goes, and forgetting it is what lets another node be captured. */
static void cand_drop(struct netstate *ns, int i)
{
	struct netstate_fam *f = &ns->f[i];

	memset(f->anchor, 0, sizeof(f->anchor));
	f->anchor_len = 0;
	f->anchor_candidate = 0;
	f->anchor_confirmed = 0;
	f->anchor_acks = 0;
	f->anchor_first_ms = 0;
	f->anchor_quiet = 0;
	raise_act(ns, i, NSA_EMIT_RDV | NSA_RDV_DROP);
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
		 * silence is as likely ours. See NETSTATE_ANCHOR_QUIET for
		 * the candidate/qualified split. */
		if (f->anchor_len && now >= f->anchor_next_ms) {
			f->anchor_next_ms = now + NETSTATE_RDV_MS;
			if (f->conn == NET_CONN_UP &&
			    ++f->anchor_quiet >= NETSTATE_ANCHOR_QUIET) {
				if (f->anchor_candidate)
					cand_drop(ns, i);
				else
					raise_act(ns, i, NSA_RDV_RELOCATE);
			}
		}
		anchor_confirm(ns, i, now);
		/* The trial ceiling, for a candidate answering too rarely to
		 * ever qualify. */
		if (f->anchor_len && f->anchor_candidate &&
		    now - f->anchor_set_ms >= NETSTATE_ANCHOR_TRY_MS)
			cand_drop(ns, i);
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

static void row_of(struct netstate_row *r, const uint8_t *a, int len, int scope,
		   int via)
{
	memset(r, 0, sizeof(*r));
	memcpy(r->addr, a, (size_t)len);
	r->addr_len = (uint8_t)len;
	r->scope = scope;
	r->via = via;
	if (!inet_ntop(len == 16 ? AF_INET6 : AF_INET, a, r->text,
		       sizeof(r->text)))
		r->text[0] = '\0';
}

int netstate_rows(const struct netstate *ns, int family,
		  struct netstate_row *out, int max)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];
	const struct netstate_local *l;
	int n = 0, i;

	for (i = 0; i < f->nlocals && n < max; i++) {
		l = &f->locals[i];
		if (l->scope != NET_SCOPE_LAN && l->proven)
			row_of(&out[n++], l->addr, l->len, l->scope,
			       NET_VIA_DIRECT);
	}
	for (i = 0; i < f->nxlats && n < max; i++)
		row_of(&out[n++], f->xlats[i].addr, f->xlats[i].len,
		       f->xlats[i].scope, NET_VIA_STUN);
	for (i = 0; i < f->nlocals && n < max; i++) {
		l = &f->locals[i];
		if (l->scope == NET_SCOPE_LAN)
			row_of(&out[n++], l->addr, l->len, l->scope,
			       NET_VIA_DIRECT);
	}
	for (i = 0; i < f->nlocals && n < max; i++) {
		l = &f->locals[i];
		if (l->scope != NET_SCOPE_LAN && !l->proven)
			row_of(&out[n++], l->addr, l->len, l->scope,
			       NET_VIA_SHADOW);
	}
	return n;
}

int netstate_has_local(const struct netstate *ns, int family,
		       const uint8_t *addr, int len)
{
	return local_idx(&ns->f[fam_idx(family)], addr, len) >= 0;
}

int netstate_has_xlat(const struct netstate *ns, int family,
		      const uint8_t *addr, int len)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];
	int i;

	for (i = 0; i < f->nxlats; i++)
		if (f->xlats[i].len == (uint8_t)len &&
		    !memcmp(f->xlats[i].addr, addr, (size_t)len))
			return 1;
	return 0;
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
	out->dht_acked = (f->anchor_confirmed && f->conn == NET_CONN_UP) ||
			 f->anchor_vouched;
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

/*
 * Whether the anchor stands proven to a reader.
 *
 * A VOUCH IS A STAND-IN FOR A PROOF THIS END COULD NOT MAKE, so it holds only
 * while that is still so. On a network where the family is up the round trip
 * is available again and it is ours to make: the node goes back to being
 * checked until it answers here. Our own proof is about the node and survives
 * a move; the quiet detector, never the move, is what retires it.
 *
 * The token slot is a separate question and keeps the node either way (see
 * netstate_facts): what the peer proved is that the node holds this key, which
 * is all the slot ever claimed, and re-checking it here is no reason to stop
 * telling a client where to go.
 */
static int anchor_proven(const struct netstate_fam *f)
{
	return f->anchor_confirmed ||
	       (f->anchor_vouched && f->conn != NET_CONN_UP);
}

void netstate_anchor_state(const struct netstate *ns, int family, int *proven,
			   int *vouched, int *blind)
{
	const struct netstate_fam *f = &ns->f[fam_idx(family)];

	if (proven)
		*proven = f->anchor_confirmed;
	if (vouched)
		*vouched = f->anchor_vouched;
	if (blind)
		*blind = !(f->conn & (NET_CONN_UP | NET_CONN_PENDING));
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
		*confirmed = anchor_proven(f);
	return 1;
}

/* Classify a bare address string by reachability scope. */
int net_addr_scope(const char *addr)
{
	uint8_t b[16];

	if (strchr(addr, ':')) {
		if (inet_pton(AF_INET6, addr, b) != 1)
			return NET_SCOPE_GLOBAL;
		return addr_scope_raw(b, 16);
	}
	if (inet_pton(AF_INET, addr, b) != 1)
		return NET_SCOPE_GLOBAL;
	return addr_scope_raw(b, 4);
}
