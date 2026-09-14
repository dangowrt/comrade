/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>

#include "dbg.h"
#include "keys.h"
#include "pathplane.h"

void pathplane_init(struct pathplane *pl, struct probeplane *pp)
{
	memset(pl, 0, sizeof(*pl));
	pl->pp = pp;
	path_table_init(&pl->t);
	pthread_mutex_init(&pl->lock, NULL);
}

void pathplane_destroy(struct pathplane *pl)
{
	pthread_mutex_destroy(&pl->lock);
}

void pathplane_add_ice(struct pathplane *pl, struct nat_agent *agent,
		       uint64_t now)
{
	pthread_mutex_lock(&pl->lock);
	path_table_add(&pl->t, PATH_ICE, NULL, agent, now);
	pthread_mutex_unlock(&pl->lock);
}

void pathplane_drop_ice(struct pathplane *pl)
{
	pthread_mutex_lock(&pl->lock);
	path_table_drop_kind(&pl->t, PATH_ICE);
	pthread_mutex_unlock(&pl->lock);
}

void pathplane_drop_agent(struct pathplane *pl, struct nat_agent *agent)
{
	pthread_mutex_lock(&pl->lock);
	path_table_drop_agent(&pl->t, agent);
	pthread_mutex_unlock(&pl->lock);
}

static int is_self(const struct pathplane_sinks *k, const struct path_ep *ep)
{
	return k->is_self ? k->is_self(k->arg, ep) : 0;
}

int pathplane_add_ep(struct pathplane *pl, const struct pathplane_sinks *k,
		     enum path_kind kind, const struct sockaddr_in6 *remote,
		     char *label, size_t label_len, uint64_t now)
{
	struct path_ep ep;
	struct path *p;

	if (!path_ep_from_sockaddr(&ep, (const struct sockaddr *)remote,
				   sizeof(*remote)) && is_self(k, &ep)) {
		dbg_logf("path: declined, it is our own endpoint");
		return -1;
	}
	pthread_mutex_lock(&pl->lock);
	p = path_table_add(&pl->t, kind, remote, NULL, now);
	if (p && label)
		snprintf(label, label_len, "%s", p->label);
	pthread_mutex_unlock(&pl->lock);

	return p ? 0 : -1;
}

void pathplane_offer_path(struct pathplane *pl,
			  const struct pathplane_sinks *k,
			  const struct sockaddr_in6 *remote, uint64_t now)
{
	char added[PATH_LABEL_MAX];
	struct path_ep ep;
	struct path *p;
	int fresh;

	if (path_ep_from_sockaddr(&ep, (const struct sockaddr *)remote,
				  sizeof(*remote)))
		return;
	if (path_ep_any(&ep) || !ep.port)
		return;
	if (!path_ep_is_unicast(&ep)) {
		dbg_logf("path advertised: declined, not one host");
		return;
	}
	if (is_self(k, &ep)) {
		dbg_logf("path advertised: declined, it is our own endpoint");
		return;
	}
	added[0] = '\0';
	pthread_mutex_lock(&pl->lock);
	fresh = path_table_find_ep(&pl->t, &ep) == NULL;
	p = path_table_offer(&pl->t, k->kind_of ? k->kind_of(k->arg, &ep) :
						  PATH_ROUTED, remote, now);
	if (p && fresh)
		snprintf(added, sizeof(added), "%s", p->label);
	pthread_mutex_unlock(&pl->lock);
	if (added[0])
		dbg_logf("path advertised: %s", added);
}

int pathplane_holds_ep(struct pathplane *pl, const struct path_ep *ep,
		       int exact)
{
	int hit;

	pthread_mutex_lock(&pl->lock);
	hit = exact ? path_table_find_ep(&pl->t, ep) != NULL :
		      path_table_find_port(&pl->t, ep->port) != NULL;
	pthread_mutex_unlock(&pl->lock);

	return hit;
}

int pathplane_lan_paths(struct pathplane *pl, int routable_only)
{
	int i, n = 0;

	pthread_mutex_lock(&pl->lock);
	for (i = 0; i < PATH_TABLE_MAX; i++) {
		struct path *p = &pl->t.p[i];

		if (!p->used || p->kind == PATH_ICE)
			continue;
		if (routable_only &&
		    IN6_IS_ADDR_LINKLOCAL(&p->remote.sin6_addr))
			continue;
		n++;
	}
	pthread_mutex_unlock(&pl->lock);

	return n;
}

int pathplane_any_qualified(struct pathplane *pl)
{
	int yes;

	pthread_mutex_lock(&pl->lock);
	yes = path_table_any_qualified(&pl->t);
	pthread_mutex_unlock(&pl->lock);

	return yes;
}

int pathplane_is_probe(const struct pathplane *pl, const uint8_t *data,
		       size_t len)
{
	return path_probe_is(pl->pp->magic, data, len);
}

int pathplane_gate(struct pathplane *pl, struct path_adopt *a, uint32_t magic,
		   const struct path_ep *ep, const uint8_t *data, size_t len,
		   uint64_t now)
{
	if (!path_probe_is(magic, data, len))
		return 1;
	if (pl && pathplane_holds_ep(pl, ep, 1))
		return 1;

	return path_adopt_allow(a, ep, now);
}

/* The path a frame arrived on: the agent for ICE, which reports no source, and
 * the source endpoint for everything else. NULL when this plane holds no path
 * naming it, which is a source it has nothing to say about yet. Called with
 * the table locked. */
static struct path *recv_path(struct pathplane *pl, enum path_kind kind,
			      const struct path_ep *src,
			      struct nat_agent *agent)
{
	if (kind == PATH_ICE)
		return path_table_find_agent(&pl->t, agent);

	return path_table_find_ep(&pl->t, src);
}

/*
 * The path a nonce names: one was drawn for one probe on one path, so it
 * identifies the round trip being measured whatever source the answer came
 * back from, which a multi-homed peer's need not match. Called with the table
 * locked.
 */
static struct path *nonce_path(struct pathplane *pl, uint64_t nonce)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (pl->t.p[i].used && pl->t.p[i].outstanding &&
		    pl->t.p[i].nonce == nonce)
			return &pl->t.p[i];

	return NULL;
}

void pathplane_desc(const struct path *p, char *out, size_t n)
{
	snprintf(out, n, "%s bucket=%d srtt=%d/%d loss=%d/%d",
		 p->label[0] ? p->label : "ICE", path_bucket(p),
		 path_srtt_ms(p), p->peer_srtt_ms,
		 path_loss_ppt(p), p->peer_loss_ppt);
}

static int blackholed(const struct pathplane_sinks *k, int kind,
		      const struct sockaddr_in6 *to)
{
	return k->blackholed ? k->blackholed(k->arg, kind, to) : 0;
}

static int agent_listed(struct nat_agent *const *live, int n,
			const struct nat_agent *a)
{
	int i;

	for (i = 0; i < n; i++)
		if (live[i] == a)
			return 1;

	return 0;
}

int pathplane_usable(const struct path *p, struct nat_agent *const *live,
		     int nlive)
{
	if (p->kind != PATH_ICE)
		return 1;

	return agent_listed(live, nlive, p->agent);
}

void pathplane_tick(struct pathplane *pl, const struct pathplane_sinks *k,
		    uint64_t now)
{
	int kind[PATH_TABLE_MAX], drop[PATH_TABLE_MAX], due[PATH_TABLE_MAX];
	char wdesc[PATH_TABLE_MAX][PATH_LABEL_MAX + 64];
	int i, j, n = 0, m = 0, nw = 0, neps = 0, nlive = 0;
	struct nat_agent *live[PATHPLANE_LIVE_MAX];
	struct nat_agent *agent[PATH_TABLE_MAX];
	struct nat_agent *epa[PATHPLANE_LIVE_MAX];
	struct sockaddr_in6 to[PATH_TABLE_MAX];
	struct path_probe pr[PATH_TABLE_MAX];
	enum path_warmth wto[PATH_TABLE_MAX];
	struct path_ep eps[PATHPLANE_LIVE_MAX];
	uint64_t nonce[PATH_TABLE_MAX];
	uint8_t out[PROBE_MAX];
	char mine[PROBE_UFRAG_MAX + 1];
	size_t len;

	mine[0] = '\0';
	k->ident(k->arg, mine, sizeof(mine));
	if (!mine[0])
		return;
	if (k->live)
		nlive = k->live(k->arg, live, PATHPLANE_LIVE_MAX);
	/* Each agent names its own nominated pair, on the one cadence. */
	if (now >= pl->next_ice_ep_ms && k->ice_ep) {
		pl->next_ice_ep_ms = now + PATH_KEEP_MS;
		for (i = 0; i < nlive; i++)
			if (!k->ice_ep(k->arg, live[i], &eps[neps])) {
				epa[neps] = live[i];
				neps++;
			}
	}
	pthread_mutex_lock(&pl->lock);
	for (i = 0; i < PATH_TABLE_MAX; i++) {
		struct path *p = &pl->t.p[i];

		if (!p->used)
			continue;
		p->usable = k->live ? pathplane_usable(p, live, nlive) : 1;
		path_probe_expire(p, now);
		/* A qualified path's warmth changing is the silence verdict the
		 * selection acts on, so it is logged like the loss one. */
		if (p->qualified) {
			enum path_warmth w = path_warmth_of(p, now);

			if (w != (enum path_warmth)p->warmth_noted) {
				p->warmth_noted = (int)w;
				wto[nw] = w;
				pathplane_desc(p, wdesc[nw],
					       sizeof(wdesc[nw]));
				nw++;
			}
		}
		if (p->kind == PATH_ICE)
			for (j = 0; j < neps; j++)
				if (p->agent == epa[j]) {
					path_set_peer_ep(p, &eps[j],
							 pl->pp->base);
					break;
				}
		if (p->usable && path_probe_due(p, now))
			due[n++] = i;
	}
	pthread_mutex_unlock(&pl->lock);
	for (i = 0; i < nw; i++)
		dbg_logf("path %s: %s",
			 wto[i] == PATH_WARM ? "warm again" :
			 wto[i] == PATH_COLD ? "cold" : "dead", wdesc[i]);
	if (!n)
		return;
	if (random_bytes(nonce, n * sizeof(nonce[0])))
		return;			/* a guessable nonce is no probe at all */
	pthread_mutex_lock(&pl->lock);
	for (i = 0; i < n; i++) {
		struct path *p = &pl->t.p[due[i]];

		if (!p->usable || !path_probe_due(p, now))
			continue;
		memset(&pr[m], 0, sizeof(pr[m]));
		pr[m].type = PROBE_PING;
		pr[m].nonce = nonce[i];
		path_fill_tail(p, &pr[m]);
		path_probe_sent(p, nonce[i], now);
		kind[m] = (int)p->kind;
		agent[m] = p->agent;
		drop[m] = blackholed(k, kind[m], &p->remote);
		to[m] = p->remote;
		m++;
	}
	pthread_mutex_unlock(&pl->lock);
	for (i = 0; i < m; i++) {
		if (drop[i])
			continue;
		len = probeplane_seal(pl->pp, &pr[i], mine, out, PROBE_MAX);
		if (!len)
			return;
		k->send(k->arg, (enum path_kind)kind[i], agent[i], &to[i], out,
			len);
	}
}

/*
 * A ping is answered to the endpoint it came from, so a multi-homed peer is
 * answered where it asked, and the answer echoes that endpoint so the prober
 * learns its own reflexive address for free. It carries this end's view of the
 * path in its tail and takes the peer's from theirs.
 *
 * A ping from a source no path names adds one, whatever source that is: an end
 * whose address changed keeps the session by probing from the new one. Add,
 * never replace: it enters as one more candidate and ranking decides whether
 * it ever carries anything, so a late datagram from an address that has gone
 * away cannot flap the binding. It takes a free slot or a dead one and
 * displaces nothing, because the probe proves only that somebody holding the
 * key once sent it, which a replay satisfies too.
 *
 * Every probe this end sends carries its own identity, so one of ours
 * reflected back at us opens, passes for this connection and would be
 * answered, and that answer, sent back to us in turn, is a pong for a nonce we
 * really are waiting on. Two bounces and a path nobody has ever answered on is
 * qualified. Answering our own outstanding nonce is the step to refuse; a peer
 * never has cause to ask us the question we are asking it.
 */
static void apply_ping(struct pathplane *pl, const struct pathplane_sinks *k,
		       const struct path_probe *pr, enum path_kind kind,
		       const struct path_ep *from_in,
		       const struct sockaddr_in6 *src,
		       struct nat_agent *agent, const char *mine,
		       uint64_t now)
{
	char added[PATH_LABEL_MAX];
	struct path_ep from = *from_in;
	struct path_probe rp;
	uint8_t out[PROBE_MAX];
	enum path_kind srck;
	struct path *p;
	int drop;
	size_t o;

	srck = kind == PATH_ICE ? kind :
	       (k->kind_of ? k->kind_of(k->arg, &from) : PATH_ROUTED);
	added[0] = '\0';
	memset(&rp, 0, sizeof(rp));
	rp.type = PROBE_PONG;
	rp.nonce = pr->nonce;
	pthread_mutex_lock(&pl->lock);
	if (nonce_path(pl, pr->nonce)) {
		pthread_mutex_unlock(&pl->lock);
		dbg_logf("path: ping carries a nonce we are waiting on -- our "
			 "own, reflected");
		return;
	}
	p = recv_path(pl, kind, &from, agent);
	if (!p && src && kind != PATH_ICE && !is_self(k, &from)) {
		p = path_table_offer(&pl->t, srck, src, now);
		if (p)
			snprintf(added, sizeof(added), "%s", p->label);
	}
	drop = blackholed(k, (int)(p ? p->kind : srck), src);
	if (p) {
		if (path_ep_any(&from))
			from = p->peer_ep;	/* ICE: no source */
		path_saw_inbound(p, &from);
		path_apply_tail(p, pr, pl->pp->base);
		path_fill_tail(p, &rp);
	} else {
		rp.have_tail = 1;
		rp.echo = from;
	}
	pthread_mutex_unlock(&pl->lock);
	if (added[0])
		dbg_logf("path adopted: %s", added);
	if (drop)
		return;
	o = probeplane_seal(pl->pp, &rp, mine, out, PROBE_MAX);
	if (!o)
		return;
	k->send(k->arg, kind, agent, src, out, o);
}

/*
 * A pong is named by its nonce, records the round trip and qualifies the path.
 * The nonce names which question this answers, not who answered it: off ICE we
 * know where the question went, so the answer must come from there, or an
 * answer relayed from anywhere qualifies the path it was carried over, which
 * is how a path that has never carried a byte between the two ends can be made
 * to look like the best one.
 */
static void apply_pong(struct pathplane *pl, const struct pathplane_sinks *k,
		       const struct path_probe *pr, enum path_kind kind,
		       const struct path_ep *from_in,
		       const struct sockaddr_in6 *src, uint64_t now)
{
	struct path_ep from = *from_in;
	char label[PATH_LABEL_MAX];
	struct path *p;
	int rtt = -1;

	label[0] = '\0';
	pthread_mutex_lock(&pl->lock);
	p = nonce_path(pl, pr->nonce);
	if (p && kind != PATH_ICE && src && !path_ep_any(&from) &&
	    !path_ep_eq(&from, &p->peer_ep)) {
		pthread_mutex_unlock(&pl->lock);
		dbg_logf("path: pong for %s arrived from somewhere else",
			 p->label);
		return;
	}
	if (p) {
		int fresh = !p->qualified;

		if (path_ep_any(&from))
			from = p->peer_ep;
		path_saw_inbound(p, &from);
		path_apply_tail(p, pr, pl->pp->base);
		if (path_probe_pong(p, pr->nonce, now) && fresh) {
			rtt = path_srtt_ms(p);
			snprintf(label, sizeof(label), "%s", p->label);
		}
	}
	pthread_mutex_unlock(&pl->lock);
	if (rtt < 0)
		return;
	dbg_logf("path qualified: %s rtt~%dms", label[0] ? label : "ICE", rtt);
	if (k->qualified)
		k->qualified(k->arg);
}

void pathplane_apply(struct pathplane *pl, const struct pathplane_sinks *k,
		     const struct path_probe *pr, enum path_kind kind,
		     const struct sockaddr_in6 *src, struct nat_agent *agent,
		     uint64_t now)
{
	char mine[PROBE_UFRAG_MAX + 1];
	struct path_ep from;

	memset(&from, 0, sizeof(from));
	if (src)
		path_ep_from_sockaddr(&from, (const struct sockaddr *)src,
				      sizeof(*src));
	if (pr->type == PROBE_PING) {
		mine[0] = '\0';
		k->ident(k->arg, mine, sizeof(mine));
		apply_ping(pl, k, pr, kind, &from, src, agent, mine, now);
	} else if (pr->type == PROBE_PONG) {
		apply_pong(pl, k, pr, kind, &from, src, now);
	} else if (k->other) {
		int held;

		/*
		 * Only from where this session is actually being carried. The
		 * sequence window already refuses a copy of an old frame; this
		 * refuses one delivered down a path nothing has been seen to
		 * arrive from, which is what an address the peer never used
		 * looks like.
		 */
		pthread_mutex_lock(&pl->lock);
		held = kind == PATH_ICE ||
		       recv_path(pl, kind, &from, agent) != NULL;
		pthread_mutex_unlock(&pl->lock);
		k->other(k->arg, pr, kind, held);
	}
}

int pathplane_recv(struct pathplane *pl, const struct pathplane_sinks *k,
		   const uint8_t *data, size_t len, enum path_kind kind,
		   const struct sockaddr_in6 *src, struct nat_agent *agent,
		   uint64_t now)
{
	char mine[PROBE_UFRAG_MAX + 1];
	struct path_probe pr;

	if (probeplane_open(pl->pp, &pr, data, len))
		return 0;
	mine[0] = '\0';
	k->ident(k->arg, mine, sizeof(mine));
	if (strcmp(pr.ufrag, mine))
		return 0;		/* not the identity this plane serves */
	if (!probeplane_fresh(pl->pp, &pr))
		return 0;
	if (k->heard)
		k->heard(k->arg, now);
	pathplane_apply(pl, k, &pr, kind, src, agent, now);

	return 1;
}

int pathplane_claims(struct pathplane *pl, const struct pathplane_sinks *k,
		     const uint8_t *data, size_t len, struct path_probe *pr)
{
	char mine[PROBE_UFRAG_MAX + 1];

	if (probeplane_open(pl->pp, pr, data, len))
		return 0;
	mine[0] = '\0';
	k->ident(k->arg, mine, sizeof(mine));
	if (pr->type != PROBE_PING || !pr->ufrag[0] || strcmp(mine, pr->ufrag))
		return 0;

	return probeplane_fresh(pl->pp, pr) ? 1 : -1;
}

int pathplane_pick(struct pathplane *pl, const struct pathplane_sinks *k,
		   uint64_t now, struct pathplane_pick *out)
{
	char from[PATH_LABEL_MAX + 64], to[PATH_LABEL_MAX + 64];
	struct nat_agent *live[PATHPLANE_LIVE_MAX];
	int nlive = 0, i, prev, sel;

	if (k->live)
		nlive = k->live(k->arg, live, PATHPLANE_LIVE_MAX);
	memset(out, 0, sizeof(*out));
	out->kind = -1;
	out->nlive = nlive;
	from[0] = '\0';
	to[0] = '\0';
	pthread_mutex_lock(&pl->lock);
	for (i = 0; i < PATH_TABLE_MAX; i++)
		pl->t.p[i].usable = k->live ?
			pathplane_usable(&pl->t.p[i], live, nlive) : 1;
	prev = pl->t.sel;
	sel = path_select(&pl->t, now);
	if (sel >= 0) {
		struct path *p = &pl->t.p[sel];

		out->kind = (int)p->kind;
		out->remote = p->remote;
		out->agent = p->agent;
		out->qualified = p->qualified;
		out->srtt_ms = path_srtt_ms(p);
		out->blackholed = blackholed(k, out->kind, &p->remote);
		snprintf(out->label, sizeof(out->label), "%s", p->label);
		if (sel != prev) {
			pathplane_desc(p, to, sizeof(to));
			if (prev >= 0 && pl->t.p[prev].used)
				pathplane_desc(&pl->t.p[prev], from,
					       sizeof(from));
		}
	}
	pthread_mutex_unlock(&pl->lock);
	if (to[0]) {
		dbg_logf("path: carrying %s (was %s)", to,
			 from[0] ? from : "none");
		out->moved = 1;
	}

	return out->kind < 0 ? -1 : 0;
}

int pathplane_carry_rtt(struct pathplane *pl, int *out)
{
	int sel, known = 0;

	pthread_mutex_lock(&pl->lock);
	sel = pl->t.sel;
	if (sel >= 0 && pl->t.p[sel].qualified) {
		*out = path_srtt_ms(&pl->t.p[sel]);
		known = 1;
	}
	pthread_mutex_unlock(&pl->lock);

	return known;
}

int pathplane_proven(struct pathplane *pl)
{
	int i, n = 0;

	pthread_mutex_lock(&pl->lock);
	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (pl->t.p[i].used && pl->t.p[i].qualified)
			n++;
	pthread_mutex_unlock(&pl->lock);

	return n;
}

void pathplane_free_agent(struct pathplane *pl, const struct pathplane_sinks *k,
			  struct nat_agent *agent, void *ctx)
{
	if (agent)
		pathplane_drop_agent(pl, agent);
	if (k->agent_free)
		k->agent_free(k->arg, agent, ctx);
}

static void hold_clear(struct pathplane *pl, const struct pathplane_sinks *k,
		       int i)
{
	struct nat_agent *agent = pl->holds[i].agent;
	void *ctx = pl->holds[i].ctx;

	pl->holds[i].agent = NULL;
	pl->holds[i].ctx = NULL;
	pl->holds[i].until_ms = 0;
	pathplane_free_agent(pl, k, agent, ctx);
}

void pathplane_hold_add(struct pathplane *pl, const struct pathplane_sinks *k,
			struct nat_agent *agent, void *ctx, uint64_t until_ms)
{
	int i;

	for (i = 0; i < PATHPLANE_HOLD_MAX; i++)
		if (!pl->holds[i].agent) {
			pl->holds[i].agent = agent;
			pl->holds[i].ctx = ctx;
			pl->holds[i].until_ms = until_ms;
			return;
		}
	pathplane_free_agent(pl, k, agent, ctx);
}

int pathplane_has_hold(const struct pathplane *pl)
{
	int i;

	for (i = 0; i < PATHPLANE_HOLD_MAX; i++)
		if (pl->holds[i].agent)
			return 1;

	return 0;
}

int pathplane_hold_carrying(struct pathplane *pl)
{
	int sel, i, held = -1;

	pthread_mutex_lock(&pl->lock);
	sel = pl->t.sel;
	if (sel >= 0 && pl->t.p[sel].used && pl->t.p[sel].agent)
		for (i = 0; i < PATHPLANE_HOLD_MAX; i++)
			if (pl->holds[i].agent == pl->t.p[sel].agent) {
				held = i;
				break;
			}
	pthread_mutex_unlock(&pl->lock);

	return held;
}

int pathplane_holds_agents(const struct pathplane *pl, struct nat_agent **out,
			   int max)
{
	int i, n = 0;

	for (i = 0; i < PATHPLANE_HOLD_MAX && n < max; i++)
		if (pl->holds[i].agent)
			out[n++] = pl->holds[i].agent;

	return n;
}

void pathplane_holds_free_all(struct pathplane *pl,
			      const struct pathplane_sinks *k)
{
	int i;

	for (i = 0; i < PATHPLANE_HOLD_MAX; i++)
		if (pl->holds[i].agent)
			hold_clear(pl, k, i);
}

void pathplane_holds_reap(struct pathplane *pl,
			  const struct pathplane_sinks *k, uint64_t now)
{
	int carrying = pathplane_hold_carrying(pl);
	int i;

	for (i = 0; i < PATHPLANE_HOLD_MAX; i++) {
		if (!pl->holds[i].agent || i == carrying)
			continue;
		if (now < pl->holds[i].until_ms &&
		    !(k->agent_failed && k->agent_failed(k->arg,
							 pl->holds[i].agent)))
			continue;
		hold_clear(pl, k, i);
	}
}

void pathplane_route_dedup(struct pathplane *pl,
			   const struct pathplane_sinks *k,
			   const struct nat_agent *live)
{
	struct nat_agent *loser[PATHPLANE_HOLD_MAX];
	void *loser_ctx[PATHPLANE_HOLD_MAX];
	int nlose = 0, sel, i, j, h;
	struct nat_agent *drop;

	pthread_mutex_lock(&pl->lock);
	sel = pl->t.sel;
	for (i = 0; i < PATH_TABLE_MAX; i++) {
		if (!pl->t.p[i].used || pl->t.p[i].kind != PATH_ICE ||
		    path_ep_any(&pl->t.p[i].peer_ep))
			continue;
		for (j = i + 1; j < PATH_TABLE_MAX; j++) {
			if (!pl->t.p[j].used ||
			    pl->t.p[j].kind != PATH_ICE ||
			    !path_ep_same_addr(&pl->t.p[i].peer_ep,
					       &pl->t.p[j].peer_ep) ||
			    !pl->t.p[i].have_self_ep ||
			    !pl->t.p[j].have_self_ep ||
			    !path_ep_same_addr(&pl->t.p[i].self_ep,
					       &pl->t.p[j].self_ep))
				continue;
			drop = NULL;
			if (pl->t.p[j].agent != live && j != sel)
				drop = pl->t.p[j].agent;
			else if (pl->t.p[i].agent != live && i != sel)
				drop = pl->t.p[i].agent;
			for (h = 0; drop && h < PATHPLANE_HOLD_MAX; h++)
				if (pl->holds[h].agent == drop) {
					loser[nlose] = drop;
					loser_ctx[nlose++] = pl->holds[h].ctx;
					pl->holds[h].agent = NULL;
					pl->holds[h].ctx = NULL;
					pl->holds[h].until_ms = 0;
					break;
				}
		}
	}
	pthread_mutex_unlock(&pl->lock);
	for (i = 0; i < nlose; i++)
		pathplane_free_agent(pl, k, loser[i], loser_ctx[i]);
}
