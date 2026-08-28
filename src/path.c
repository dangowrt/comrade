/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <stdio.h>
#include <string.h>

#include "ccrypto.h"
#include "path.h"

static const uint8_t v4_prefix[12] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
};

int path_ep_is_v4(const struct path_ep *ep)
{
	return !memcmp(ep->addr, v4_prefix, sizeof(v4_prefix));
}

int path_ep_any(const struct path_ep *ep)
{
	static const uint8_t zero[16] = { 0 };

	return !ep->port && !memcmp(ep->addr, zero, sizeof(zero));
}

int path_ep_eq(const struct path_ep *a, const struct path_ep *b)
{
	return a->port == b->port && !memcmp(a->addr, b->addr, 16);
}

int path_ep_from_sockaddr(struct path_ep *ep, const struct sockaddr *sa,
			  socklen_t len)
{
	memset(ep, 0, sizeof(*ep));
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;

		if (len < (socklen_t)sizeof(*s6))
			return -1;
		memcpy(ep->addr, &s6->sin6_addr, 16);
		ep->port = ntohs(s6->sin6_port);
		return 0;
	}
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;

		if (len < (socklen_t)sizeof(*s4))
			return -1;
		memcpy(ep->addr, v4_prefix, sizeof(v4_prefix));
		memcpy(ep->addr + 12, &s4->sin_addr, 4);
		ep->port = ntohs(s4->sin_port);
		return 0;
	}
	return -1;
}

void path_ep_to_sockaddr(const struct path_ep *ep, struct sockaddr_in6 *out)
{
	memset(out, 0, sizeof(*out));
	out->sin6_family = AF_INET6;
	out->sin6_port = htons(ep->port);
	memcpy(&out->sin6_addr, ep->addr, 16);
}

void path_ep_pack(const struct path_ep *ep, uint8_t out[PATH_EP_LEN])
{
	memcpy(out, ep->addr, 16);
	out[16] = (uint8_t)(ep->port >> 8);
	out[17] = (uint8_t)ep->port;
}

void path_ep_unpack(struct path_ep *ep, const uint8_t in[PATH_EP_LEN])
{
	memcpy(ep->addr, in, 16);
	ep->port = (uint16_t)(((uint16_t)in[16] << 8) | in[17]);
}

void path_ep_str(const struct path_ep *ep, char *out, size_t n)
{
	char host[64];

	out[0] = '\0';
	if (path_ep_is_v4(ep)) {
		struct in_addr a4;

		memcpy(&a4, ep->addr + 12, 4);
		if (!inet_ntop(AF_INET, &a4, host, sizeof(host)))
			return;
		snprintf(out, n, "%s:%u", host, (unsigned)ep->port);
	} else {
		struct in6_addr a6;

		memcpy(&a6, ep->addr, 16);
		if (!inet_ntop(AF_INET6, &a6, host, sizeof(host)))
			return;
		snprintf(out, n, "[%s]:%u", host, (unsigned)ep->port);
	}
}

static void path_put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t path_get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void path_put16(uint8_t *p, int v)
{
	if (v < 0)
		v = 0;
	if (v > 0xffff)
		v = 0xffff;
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

int path_probe_is(const uint8_t *data, size_t len)
{
	return len >= 4 && path_get32(data) == PROBE_MAGIC;
}

size_t path_probe_build(uint8_t *out, size_t out_len, const uint8_t sig_key[32],
			const struct path_probe *pr)
{
	uint8_t plain[PROBE_PLAIN_MAX];
	size_t ul = strlen(pr->ufrag);
	size_t pl;
	int n, i;

	if (ul > PROBE_UFRAG_MAX || out_len < PROBE_MAX)
		return 0;
	plain[0] = (uint8_t)pr->type;
	for (i = 0; i < 8; i++)
		plain[1 + i] = (uint8_t)(pr->nonce >> (8 * (7 - i)));
	for (i = 0; i < 8; i++)
		plain[9 + i] = (uint8_t)(pr->seq >> (8 * (7 - i)));
	plain[17] = (uint8_t)ul;
	memcpy(plain + PROBE_HEAD_FIXED, pr->ufrag, ul);
	pl = PROBE_HEAD_FIXED + ul;
	if (pr->have_tail) {
		path_ep_pack(&pr->echo, plain + pl);
		path_put16(plain + pl + 18, pr->srtt_ms);
		path_put16(plain + pl + 20, pr->loss_ppt);
		pl += PROBE_TAIL_LEN;
	}
	path_put32(out, PROBE_MAGIC);
	n = msg_seal(out + 4, out_len - 4, sig_key, plain, pl);
	return n < 0 ? 0 : (size_t)n + 4;
}

int path_probe_parse(struct path_probe *pr, const uint8_t sig_key[32],
		     const uint8_t *data, size_t len)
{
	uint8_t plain[PROBE_PLAIN_MAX + 1];
	size_t ul;
	int n, i;

	memset(pr, 0, sizeof(*pr));
	if (!path_probe_is(data, len))
		return -1;
	n = msg_open(plain, sizeof(plain), sig_key, data + 4, len - 4);
	if (n < PROBE_HEAD_FIXED)
		return -1;
	pr->type = plain[0];
	for (i = 0; i < 8; i++)
		pr->nonce = (pr->nonce << 8) | plain[1 + i];
	for (i = 0; i < 8; i++)
		pr->seq = (pr->seq << 8) | plain[9 + i];
	ul = plain[17];
	if (ul > PROBE_UFRAG_MAX || (size_t)n < PROBE_HEAD_FIXED + ul)
		return -1;
	memcpy(pr->ufrag, plain + PROBE_HEAD_FIXED, ul);
	pr->ufrag[ul] = '\0';
	if ((size_t)n >= PROBE_HEAD_FIXED + ul + PROBE_TAIL_LEN) {
		const uint8_t *t = plain + PROBE_HEAD_FIXED + ul;

		path_ep_unpack(&pr->echo, t);
		pr->srtt_ms = ((int)t[18] << 8) | t[19];
		pr->loss_ppt = ((int)t[20] << 8) | t[21];
		pr->have_tail = 1;
	}
	return 0;
}

void path_id_calc(uint8_t out[PATH_ID_LEN], const uint8_t sig_key[32],
		  const struct path_ep *a, const struct path_ep *b)
{
	uint8_t ea[PATH_EP_LEN], eb[PATH_EP_LEN];
	uint8_t msg[2 * PATH_EP_LEN], d[32];

	path_ep_pack(a, ea);
	path_ep_pack(b, eb);
	if (memcmp(ea, eb, PATH_EP_LEN) <= 0) {
		memcpy(msg, ea, PATH_EP_LEN);
		memcpy(msg + PATH_EP_LEN, eb, PATH_EP_LEN);
	} else {
		memcpy(msg, eb, PATH_EP_LEN);
		memcpy(msg + PATH_EP_LEN, ea, PATH_EP_LEN);
	}
	cc_blake2b_keyed(d, sizeof(d), sig_key, 32, msg, sizeof(msg));
	memcpy(out, d, PATH_ID_LEN);
}

static void path_id_refresh(struct path *p, const uint8_t sig_key[32])
{
	path_id_calc(p->id, sig_key, &p->self_ep, &p->peer_ep);
}

void path_set_self_ep(struct path *p, const struct path_ep *ep,
		      const uint8_t sig_key[32])
{
	if (path_ep_any(ep) || (p->have_self_ep && path_ep_eq(&p->self_ep, ep)))
		return;
	p->self_ep = *ep;
	p->have_self_ep = 1;
	path_id_refresh(p, sig_key);
}

void path_set_peer_ep(struct path *p, const struct path_ep *ep,
		      const uint8_t sig_key[32])
{
	if (path_ep_any(ep) || path_ep_eq(&p->peer_ep, ep))
		return;
	p->peer_ep = *ep;
	path_ep_str(ep, p->label, sizeof(p->label));
	path_id_refresh(p, sig_key);
}

void path_saw_inbound(struct path *p, const struct path_ep *src)
{
	if (!path_ep_any(src))
		p->in_src = *src;
}

void path_fill_tail(const struct path *p, struct path_probe *pr)
{
	pr->have_tail = 1;
	pr->echo = p->in_src;
	pr->srtt_ms = path_srtt_ms(p);
	pr->loss_ppt = path_loss_ppt(p);
}

void path_apply_tail(struct path *p, const struct path_probe *pr,
		     const uint8_t sig_key[32])
{
	if (!pr->have_tail)
		return;
	path_set_self_ep(p, &pr->echo, sig_key);
	path_peer_view(p, pr->srtt_ms, pr->loss_ppt);
}

void path_table_init(struct path_table *t)
{
	memset(t, 0, sizeof(*t));
	t->sel = -1;
	t->cand = -1;
}

int path_table_count(const struct path_table *t)
{
	int i, n = 0;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (t->p[i].used)
			n++;
	return n;
}

int path_index(const struct path_table *t, const struct path *p)
{
	if (!p || p < t->p || p >= t->p + PATH_TABLE_MAX)
		return -1;
	return (int)(p - t->p);
}

static int kind_is_lanlink(enum path_kind k)
{
	return k == PATH_SEGMENT || k == PATH_ROUTED;
}

struct path *path_table_find(struct path_table *t, enum path_kind kind,
			     const struct path_ep *ep)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (t->p[i].used && t->p[i].kind == kind &&
		    path_ep_eq(&t->p[i].peer_ep, ep))
			return &t->p[i];
	return NULL;
}

struct path *path_table_find_ep(struct path_table *t, const struct path_ep *ep)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (t->p[i].used && kind_is_lanlink(t->p[i].kind) &&
		    path_ep_eq(&t->p[i].peer_ep, ep))
			return &t->p[i];
	return NULL;
}

struct path *path_table_find_port(struct path_table *t, uint16_t port)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (t->p[i].used && kind_is_lanlink(t->p[i].kind) &&
		    t->p[i].peer_ep.port == port)
			return &t->p[i];
	return NULL;
}

struct path *path_table_find_agent(struct path_table *t,
				   struct nat_agent *agent)
{
	int i;

	if (!agent)
		return NULL;
	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (t->p[i].used && t->p[i].agent == agent)
			return &t->p[i];
	return NULL;
}

struct path *path_table_sel(struct path_table *t)
{
	if (t->sel < 0 || !t->p[t->sel].used)
		return NULL;
	return &t->p[t->sel];
}

/*
 * The slot a new path may take: a free one, else the worst-ranked path that is
 * not carrying the session -- oldest DEAD first, since warmth orders worst-last
 * and creation time settles a tie. Returns -1 when nothing may go.
 */
static int path_table_evict(struct path_table *t, uint64_t now)
{
	int i, worst = -1;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (!t->p[i].used)
			return i;
	for (i = 0; i < PATH_TABLE_MAX; i++) {
		enum path_warmth w, ww;

		if (i == t->sel)
			continue;
		if (worst < 0) {
			worst = i;
			continue;
		}
		w = path_warmth_of(&t->p[i], now);
		ww = path_warmth_of(&t->p[worst], now);
		if (w > ww || (w == ww &&
			       t->p[i].created_ms < t->p[worst].created_ms))
			worst = i;
	}
	return worst;
}

struct path *path_table_add(struct path_table *t, enum path_kind kind,
			    const struct sockaddr_in6 *remote,
			    struct nat_agent *agent, uint64_t now)
{
	struct path_ep ep;
	struct path *p;
	int slot;

	memset(&ep, 0, sizeof(ep));
	if (remote &&
	    path_ep_from_sockaddr(&ep, (const struct sockaddr *)remote,
				  sizeof(*remote)))
		return NULL;
	if (agent) {
		p = path_table_find_agent(t, agent);
		if (p)
			return p;
	} else {
		p = path_table_find(t, kind, &ep);
		if (p)
			return p;
	}
	slot = path_table_evict(t, now);
	if (slot < 0)
		return NULL;
	p = &t->p[slot];
	if (t->cand == slot) {
		t->cand = -1;
		t->hold = 0;
	}
	memset(p, 0, sizeof(*p));
	p->used = 1;
	/* A path over a borrowed agent carries nothing until the agent has
	 * nominated a pair, which only its owner can say; one over the shared
	 * socket can from the moment it is named. */
	p->usable = agent == NULL;
	p->kind = kind;
	p->agent = agent;
	p->peer_ep = ep;
	if (remote)
		p->remote = *remote;
	p->created_ms = now;
	p->trying_since_ms = now;
	if (!path_ep_any(&ep))
		path_ep_str(&ep, p->label, sizeof(p->label));
	return p;
}

/*
 * Is there room for a path nothing has been seen to arrive from: a free slot,
 * or one a DEAD path is holding? The path in use is never the answer.
 */
static int path_table_spare(const struct path_table *t, uint64_t now)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (!t->p[i].used)
			return 1;
	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (i != t->sel && path_warmth_of(&t->p[i], now) == PATH_DEAD)
			return 1;
	return 0;
}

struct path *path_table_offer(struct path_table *t, enum path_kind kind,
			      const struct sockaddr_in6 *remote, uint64_t now)
{
	struct path_ep ep;
	struct path *p;

	if (!remote ||
	    path_ep_from_sockaddr(&ep, (const struct sockaddr *)remote,
				  sizeof(*remote)))
		return NULL;
	p = path_table_find_ep(t, &ep);
	if (p)
		return p;
	if (!path_table_spare(t, now))
		return NULL;
	return path_table_add(t, kind, remote, NULL, now);
}

void path_table_clear(struct path_table *t)
{
	path_table_init(t);
}

void path_table_drop_kind(struct path_table *t, enum path_kind kind)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++) {
		if (!t->p[i].used || t->p[i].kind != kind)
			continue;
		memset(&t->p[i], 0, sizeof(t->p[i]));
		if (t->sel == i)
			t->sel = -1;
		if (t->cand == i) {
			t->cand = -1;
			t->hold = 0;
		}
	}
}

void path_table_reset_stats(struct path_table *t, uint64_t now)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++) {
		struct path *p = &t->p[i];

		if (!p->used)
			continue;
		p->nonce = 0;
		p->sent_ms = 0;
		p->outstanding = 0;
		p->srtt8 = 0;
		p->peer_srtt_ms = 0;
		p->peer_loss_ppt = 0;
		p->loss_reg = 0;
		p->loss_n = 0;
		p->last_pong_ms = 0;
		p->next_probe_ms = 0;
		p->qualified = 0;
		/* On trial again from here: the endpoints are kept across a
		 * re-claim precisely so they can be tried under the new
		 * identity, and a path is only called dead for failing to
		 * answer while it was being asked. */
		p->trying_since_ms = now;
	}
	t->cand = -1;
	t->hold = 0;
	t->next_eval_ms = 0;
}

int path_table_any_qualified(const struct path_table *t)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (t->p[i].used && t->p[i].qualified)
			return 1;
	return 0;
}

enum path_warmth path_warmth_of(const struct path *p, uint64_t now)
{
	uint64_t silent;

	if (!p->qualified) {
		/*
		 * Untried, or tried and never once answered? The second is a
		 * path shown not to work as surely as one that fell silent,
		 * and until it was called that it held its slot for the life
		 * of the connection: probed every round, never reclaimed, and
		 * in the way of the next endpoint worth trying. An address
		 * that answers nothing is what a stranger's offer looks like,
		 * and what a peer's stale candidate looks like too.
		 */
		if (now > p->trying_since_ms &&
		    now - p->trying_since_ms > PATH_DEAD_MS)
			return PATH_DEAD;
		return PATH_UNQUALIFIED;
	}
	silent = now > p->last_pong_ms ? now - p->last_pong_ms : 0;
	if (silent > PATH_DEAD_MS)
		return PATH_DEAD;
	if (silent > PATH_WARM_MS)
		return PATH_COLD;
	return PATH_WARM;
}

int path_srtt_ms(const struct path *p)
{
	return p->srtt8 / 8;
}

int path_loss_ppt(const struct path *p)
{
	int i, lost = 0;

	if (!p->loss_n)
		return 0;
	for (i = 0; i < p->loss_n; i++)
		if (p->loss_reg & (uint16_t)(1u << i))
			lost++;
	return lost * 1000 / p->loss_n;
}

static void loss_record(struct path *p, int lost)
{
	p->loss_reg = (uint16_t)((p->loss_reg << 1) | (lost ? 1 : 0));
	if (p->loss_n < PATH_LOSS_WINDOW)
		p->loss_n++;
}

/* How long a probe must be outstanding before it counts as lost. */
static uint64_t loss_deadline(const struct path *p)
{
	int d = path_srtt_ms(p) * 3;

	return (uint64_t)(d > PATH_LOSS_WAIT_MS ? d : PATH_LOSS_WAIT_MS);
}

int path_probe_due(const struct path *p, uint64_t now)
{
	return p->used && !p->outstanding && now >= p->next_probe_ms;
}

void path_probe_sent(struct path *p, uint64_t nonce, uint64_t now)
{
	p->nonce = nonce;
	p->sent_ms = now;
	p->outstanding = 1;
	p->next_probe_ms = now +
		(uint64_t)(p->qualified ? PATH_KEEP_MS : PROBE_EVERY_MS);
}

void path_probe_expire(struct path *p, uint64_t now)
{
	if (!p->outstanding || now <= p->sent_ms ||
	    now - p->sent_ms <= loss_deadline(p))
		return;
	p->outstanding = 0;
	loss_record(p, 1);
}

int path_probe_pong(struct path *p, uint64_t nonce, uint64_t now)
{
	int rtt;

	if (!p->outstanding || nonce != p->nonce)
		return 0;
	p->outstanding = 0;
	rtt = now > p->sent_ms ? (int)(now - p->sent_ms) : 0;
	if (!p->qualified)
		p->srtt8 = rtt * 8;
	else
		p->srtt8 += rtt - p->srtt8 / 8;
	loss_record(p, 0);
	p->last_pong_ms = now;
	if (!p->qualified) {
		p->qualified = 1;
		p->next_probe_ms = now + PATH_KEEP_MS;
	}
	return 1;
}

void path_peer_view(struct path *p, int srtt_ms, int loss_ppt)
{
	int mine = path_srtt_ms(p);
	int cap = PATH_PEER_SRTT_MAX;

	if (srtt_ms < 0)
		srtt_ms = 0;
	if (loss_ppt < 0)
		loss_ppt = 0;
	if (loss_ppt > 1000)
		loss_ppt = 1000;	/* a proportion, not a number */
	if (p->qualified && mine > 0 && mine * PATH_PEER_SRTT_RATIO < cap)
		cap = mine * PATH_PEER_SRTT_RATIO;
	if (srtt_ms > cap)
		srtt_ms = cap;
	p->peer_srtt_ms = srtt_ms;
	p->peer_loss_ppt = loss_ppt;
}

int path_cost_of(int srtt_a, int loss_a, int srtt_b, int loss_b)
{
	int srtt = srtt_a > srtt_b ? srtt_a : srtt_b;
	int loss = loss_a > loss_b ? loss_a : loss_b;

	return srtt + PATH_LOSS_PENALTY_MS * loss / 1000;
}

int path_cost(const struct path *p)
{
	return path_cost_of(path_srtt_ms(p), path_loss_ppt(p),
			    p->peer_srtt_ms, p->peer_loss_ppt);
}

int path_bucket_of(int cost)
{
	return (cost + PATH_COST_QUANTUM_MS - 1) / PATH_COST_QUANTUM_MS;
}

int path_bucket(const struct path *p)
{
	return path_bucket_of(path_cost(p));
}

int path_cmp(const struct path *a, const struct path *b, uint64_t now)
{
	enum path_warmth wa = path_warmth_of(a, now);
	enum path_warmth wb = path_warmth_of(b, now);
	int ba, bb;

	if (wa != wb)
		return wa < wb ? -1 : 1;
	ba = path_bucket(a);
	bb = path_bucket(b);
	if (ba != bb)
		return ba < bb ? -1 : 1;
	return memcmp(a->id, b->id, PATH_ID_LEN);
}

int path_best(const struct path_table *t, uint64_t now)
{
	int i, best = -1;

	for (i = 0; i < PATH_TABLE_MAX; i++) {
		if (!t->p[i].used || !t->p[i].usable)
			continue;
		if (best < 0 || path_cmp(&t->p[i], &t->p[best], now) < 0)
			best = i;
	}
	return best;
}

int path_select(struct path_table *t, uint64_t now)
{
	int best = path_best(t, now);

	if (best < 0) {
		t->sel = -1;
		t->cand = -1;
		t->hold = 0;
		return -1;
	}
	if (t->sel < 0 || !t->p[t->sel].used || !t->p[t->sel].usable ||
	    path_warmth_of(&t->p[best], now) <
	    path_warmth_of(&t->p[t->sel], now)) {
		t->sel = best;
		t->cand = -1;
		t->hold = 0;
		t->next_eval_ms = now + PATH_KEEP_MS;
		return t->sel;
	}
	if (best == t->sel) {
		t->cand = -1;
		t->hold = 0;
		return t->sel;
	}
	if (now < t->next_eval_ms)
		return t->sel;
	t->next_eval_ms = now + PATH_KEEP_MS;
	if (path_bucket(&t->p[t->sel]) - path_bucket(&t->p[best]) <
	    PATH_SWITCH_MARGIN) {
		t->cand = -1;
		t->hold = 0;
		return t->sel;
	}
	if (t->cand != best) {
		t->cand = best;
		t->hold = 0;
	}
	t->hold++;
	if (t->hold >= PATH_SWITCH_HOLD) {
		t->sel = best;
		t->cand = -1;
		t->hold = 0;
	}
	return t->sel;
}
