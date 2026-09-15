/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdlib.h>
#include <string.h>

#include "wsock.h"

#include <stdio.h>

#include "candpolicy.h"
#include "dbg.h"
#include "hbeat.h"
#include "netroute.h"
#include "keys.h"
#include "peering.h"

void peering_facts_init(struct peering_facts *f)
{
	nsfacts_init(&f->q);
	pthread_mutex_init(&f->lock, NULL);
}

void peering_facts_destroy(struct peering_facts *f)
{
	pthread_mutex_destroy(&f->lock);
}

void peering_facts_post(struct peering_facts *f, int kind, int family,
			uint32_t epoch)
{
	pthread_mutex_lock(&f->lock);
	nsfacts_post(&f->q, kind, family, epoch);
	pthread_mutex_unlock(&f->lock);
}

void peering_facts_post_addr(struct peering_facts *f, int family,
			     uint32_t epoch, const uint8_t *addr,
			     const char *text)
{
	pthread_mutex_lock(&f->lock);
	nsfacts_post_addr(&f->q, family, epoch, addr, text);
	pthread_mutex_unlock(&f->lock);
}

int peering_facts_take(struct peering_facts *f, struct nsfact *out, int max)
{
	int n;

	pthread_mutex_lock(&f->lock);
	n = nsfacts_take(&f->q, out, max);
	pthread_mutex_unlock(&f->lock);

	return n;
}

int peering_facts_feed(struct netstate *ns, const struct nsfact *q,
		       uint32_t epoch, uint64_t now)
{
	if (q->kind == NSF_ROUNDTRIP) {
		netstate_on_roundtrip(ns, q->family, epoch);
		return 0;
	}
	if (q->kind == NSF_ADDR) {
		netstate_on_candidate(ns, q->family, epoch,
				      net_addr_scope(q->text), NET_VIA_STUN,
				      q->addr, q->family == 6 ? 16 : 4,
				      q->text);
		return 0;
	}
	netstate_on_probe_done(ns, q->family, epoch, now);

	return 1;
}

void peering_pool_init(struct peering_pool *p)
{
	memset(p, 0, sizeof(*p));
	pthread_mutex_init(&p->lock, NULL);
}

void peering_pool_destroy(struct peering_pool *p)
{
	pthread_mutex_destroy(&p->lock);
}

int peering_pool_note(struct peering_pool *p, const uint8_t addr[4])
{
	static const uint8_t zero[4] = { 0 };
	int added = 0, i;

	if (!memcmp(addr, zero, sizeof(zero)))
		return 0;
	pthread_mutex_lock(&p->lock);
	for (i = 0; i < p->n; i++)
		if (!memcmp(p->v4[i], addr, 4))
			break;
	if (i == p->n && i < PEERING_POOL4_MAX) {
		memcpy(p->v4[p->n++], addr, 4);
		added = p->n;
	}
	pthread_mutex_unlock(&p->lock);

	return added;
}

int peering_pool_copy(struct peering_pool *p,
		      uint8_t out[PEERING_POOL4_MAX][4])
{
	int n, i;

	pthread_mutex_lock(&p->lock);
	n = p->n;
	for (i = 0; i < n; i++)
		memcpy(out[i], p->v4[i], 4);
	pthread_mutex_unlock(&p->lock);

	return n;
}

int peering_pool_count(struct peering_pool *p)
{
	int n;

	pthread_mutex_lock(&p->lock);
	n = p->n;
	pthread_mutex_unlock(&p->lock);

	return n;
}

void peering_pool_sample(struct peering_pool *p, const uint8_t addr[4],
			 uint16_t port)
{
	pthread_mutex_lock(&p->lock);
	stun_mapping_add(&p->map4, addr, port);
	pthread_mutex_unlock(&p->lock);
}

int peering_pool_mapping(struct peering_pool *p)
{
	int st;

	pthread_mutex_lock(&p->lock);
	st = stun_mapping_result(&p->map4);
	pthread_mutex_unlock(&p->lock);

	return st;
}

int peering_pool_port_stable(struct peering_pool *p)
{
	int stable;

	pthread_mutex_lock(&p->lock);
	stable = stun_mapping_port_stable(&p->map4);
	pthread_mutex_unlock(&p->lock);

	return stable;
}

void peering_pool_round(struct peering_pool *p)
{
	pthread_mutex_lock(&p->lock);
	stun_mapping_reset(&p->map4);
	pthread_mutex_unlock(&p->lock);
}

void peering_pool_reset(struct peering_pool *p)
{
	pthread_mutex_lock(&p->lock);
	p->n = 0;
	stun_mapping_reset(&p->map4);
	pthread_mutex_unlock(&p->lock);
}

void peering_desc_init(struct peering_desc *d)
{
	memset(d, 0, sizeof(*d));
	pthread_mutex_init(&d->lock, NULL);
}

void peering_desc_destroy(struct peering_desc *d)
{
	pthread_mutex_destroy(&d->lock);
}

void peering_desc_gathered(struct peering_desc *d, const char *sdp)
{
	pthread_mutex_lock(&d->lock);
	snprintf(d->pending, sizeof(d->pending), "%s", sdp);
	d->pending_set = 1;
	pthread_mutex_unlock(&d->lock);
}

void peering_desc_candidate(struct peering_desc *d, const char *cand)
{
	size_t used, room, n = strlen(cand);

	pthread_mutex_lock(&d->lock);
	used = strlen(d->trickle);
	room = sizeof(d->trickle) - used - 1;
	if (n + 1 <= room) {
		memcpy(d->trickle + used, cand, n);
		d->trickle[used + n] = '\n';
		d->trickle[used + n + 1] = '\0';
		__atomic_store_n(&d->dirty, 1, __ATOMIC_RELAXED);
	}
	pthread_mutex_unlock(&d->lock);
}

int peering_desc_take(struct peering_desc *d, char *raw, size_t cap)
{
	int staged;

	pthread_mutex_lock(&d->lock);
	staged = d->pending_set;
	if (staged) {
		snprintf(raw, cap, "%s", d->pending);
		d->pending_set = 0;
	}
	pthread_mutex_unlock(&d->lock);
	return staged;
}

void peering_desc_set(struct peering_desc *d, const char *sdp)
{
	if (sdp != d->local)
		snprintf(d->local, sizeof(d->local), "%s", sdp);
	d->have_local = 1;
}

int peering_desc_drain(struct peering_desc *d, char *out, size_t cap)
{
	if (!__atomic_load_n(&d->dirty, __ATOMIC_RELAXED))
		return 0;
	pthread_mutex_lock(&d->lock);
	snprintf(out, cap, "%s", d->trickle);
	d->trickle[0] = '\0';
	__atomic_store_n(&d->dirty, 0, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&d->lock);
	return 1;
}

char *peering_desc_local(struct peering_desc *d)
{
	return d->local;
}

int peering_desc_have(const struct peering_desc *d)
{
	return d->have_local;
}

void peering_desc_drop(struct peering_desc *d)
{
	d->have_local = 0;
	d->local[0] = '\0';
}

void peering_desc_clear(struct peering_desc *d)
{
	peering_desc_drop(d);
	pthread_mutex_lock(&d->lock);
	d->trickle[0] = '\0';
	__atomic_store_n(&d->dirty, 0, __ATOMIC_RELAXED);
	d->pending_set = 0;
	pthread_mutex_unlock(&d->lock);
}

int peering_sdp_has_candidate(const char *sdp)
{
	return strstr(sdp, "a=candidate:") != NULL;
}

static void probe_hit(void *arg, const uint8_t addr[4], uint16_t port)
{
	struct peering_net *m = arg;
	int added = peering_pool_note(&m->pool, addr);

	if (added)
		dbg_logf("stun: egress +%u.%u.%u.%u (pool now %d)", addr[0],
			 addr[1], addr[2], addr[3], added);
	peering_pool_sample(&m->pool, addr, port);
	peering_facts_post(&m->facts, NSF_ROUNDTRIP, 4,
			   __atomic_load_n(&m->probe.epoch, __ATOMIC_RELAXED));
}

static void *probe_thread(void *arg)
{
	struct peering_net *m = arg;
	uint8_t seed[STUN_PROBE_TXID_LEN];
	uint32_t epoch = __atomic_load_n(&m->probe.epoch, __ATOMIC_RELAXED);
	int st, stable, npool;

	peering_pool_round(&m->pool);
	random_bytes(seed, sizeof(seed));
	stun_probe_run(m->servers, m->nservers, PEERING_PROBE_MS, seed,
		       &m->probe.stop, probe_hit, m);
	st = peering_pool_mapping(&m->pool);
	stable = peering_pool_port_stable(&m->pool);
	npool = peering_pool_count(&m->pool);
	/* The verdict this round reached, and the pool it reached it against.
	 * Which way this goes decides whether the offer names every egress
	 * address or one of them, and until it was said out loud the difference
	 * was visible only as a punch that sometimes worked. */
	dbg_logf("stun: round done -- mapping %s, port %s, "
		 "%d egress address(es) known",
		 st == STUN_MAPPING_DEPENDENT ? "per-destination" :
		 st == STUN_MAPPING_INDEPENDENT ? "one for all" :
						  "not yet known",
		 stable ? "stable" : "moves with the destination", npool);
	peering_facts_post(&m->facts, NSF_PROBE_DONE, 4, epoch);

	return NULL;
}

/* v6's proof and the address that carried it. Often the only v6 address
 * anything sees, ICE gathering no v6 reflexive candidate when a global host
 * candidate already exists. */
static void probe6_hit(void *arg, const uint8_t addr[16], uint16_t port)
{
	struct peering_net *m = arg;
	uint32_t epoch;
	char ip[64];

	(void)port;
	epoch = __atomic_load_n(&m->probe6.epoch, __ATOMIC_RELAXED);
	peering_facts_post(&m->facts, NSF_ROUNDTRIP, 6, epoch);
	if (inet_ntop(AF_INET6, addr, ip, sizeof(ip)))
		peering_facts_post_addr(&m->facts, 6, epoch, addr, ip);
}

static void *probe6_thread(void *arg)
{
	struct peering_net *m = arg;
	char *targets[PEERING_PROBE6_SERVERS];
	uint8_t seed[STUN_PROBE_TXID_LEN];
	uint32_t epoch = __atomic_load_n(&m->probe6.epoch, __ATOMIC_RELAXED);
	int n = 0, i;

	for (i = 0; i < m->nservers && n < PEERING_PROBE6_SERVERS; i++)
		targets[n++] = m->servers[(m->probe6.start + i) % m->nservers];
	random_bytes(seed, sizeof(seed));
	stun_probe_check(targets, n, AF_INET6, PEERING_PROBE_MS, seed,
			 &m->probe6.stop, probe6_hit, m);
	peering_facts_post(&m->facts, NSF_PROBE_DONE, 6, epoch);

	return NULL;
}

void peering_net_init(struct peering_net *m, char *const *servers,
		      int nservers, int auto_probe)
{
	memset(m, 0, sizeof(*m));
	m->servers = servers;
	m->nservers = nservers;
	m->auto_probe = auto_probe;
	peering_facts_init(&m->facts);
	peering_desc_init(&m->desc);
	peering_pool_init(&m->pool);
}

void peering_net_halt(struct peering_net *m, int family)
{
	struct peering_probe *p = family == 6 ? &m->probe6 : &m->probe;

	if (p->running)
		__atomic_store_n(&p->stop, 1, __ATOMIC_RELAXED);
}

void peering_net_reap(struct peering_net *m, int family)
{
	struct peering_probe *p = family == 6 ? &m->probe6 : &m->probe;

	if (!p->running)
		return;
	pthread_join(p->th, NULL);
	p->running = 0;
}

void peering_net_stop(struct peering_net *m)
{
	peering_net_halt(m, 4);
	peering_net_halt(m, 6);
	peering_net_reap(m, 4);
	peering_net_reap(m, 6);
}

void peering_net_renew(struct peering_net *m)
{
	uint8_t rb[2];

	peering_desc_clear(&m->desc);
	peering_pool_reset(&m->pool);
	m->pool.reported = 0;
	m->pool.posted = 0;
	m->rotations = 0;
	if (m->nservers > 0) {
		random_bytes(rb, 2);
		__atomic_store_n(&m->ice_attempt,
				 ((rb[0] << 8) | rb[1]) % m->nservers,
				 __ATOMIC_RELAXED);
	}
	__atomic_store_n(&m->have_priv4, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&m->have_srflx4, 0, __ATOMIC_RELAXED);
	m->mapping_reported = 0;
}

void peering_net_destroy(struct peering_net *m)
{
	peering_facts_destroy(&m->facts);
	peering_desc_destroy(&m->desc);
	peering_pool_destroy(&m->pool);
}

int peering_net_kick(struct peering_net *m, int family, uint32_t epoch,
		     int start6)
{
	struct peering_probe *p = family == 6 ? &m->probe6 : &m->probe;

	__atomic_store_n(&p->epoch, epoch, __ATOMIC_RELAXED);
	if (!m->auto_probe || m->nservers < 1)
		return 0;
	if (p->running) {
		__atomic_store_n(&p->stop, 1, __ATOMIC_RELAXED);
		return 0;
	}
	p->start = start6;
	__atomic_store_n(&p->stop, 0, __ATOMIC_RELAXED);
	if (pthread_create(&p->th, NULL,
			   family == 6 ? probe6_thread : probe_thread, m))
		return 0;
	p->running = 1;
	if (family == 4)
		dbg_logf("stun: v4 probe round started");

	return 1;
}

void peering_init(struct peering *pr, struct peering_model *pm, uint32_t magic,
		  const uint8_t key[32], uint64_t seq0)
{
	memset(pr, 0, sizeof(*pr));
	pr->pm = pm;
	probeplane_init(&pr->pp, magic, key, seq0);
	pathplane_init(&pr->pl, &pr->pp);
	ctlplane_init(&pr->cp, &pr->pp);
}

void peering_destroy(struct peering *pr)
{
	ctlplane_destroy(&pr->cp);
	pathplane_destroy(&pr->pl);
	probeplane_destroy(&pr->pp);
}

void peering_reset(struct peering *pr)
{
	probeplane_reset(&pr->pp);
	ctlplane_reset(&pr->cp);
}

void peering_model_init(struct peering_model *pm, int is_host, int dht,
			const struct session_obs *o, uint64_t now)
{
	memset(pm, 0, sizeof(*pm));
	pm->is_host = is_host;
	pm->dht = dht;
	netstate_init(&pm->ns, is_host, now);
	obsemit_init(&pm->oe, o, &pm->ns);
	pthread_mutex_init(&pm->pub_lock, NULL);
}

void peering_model_destroy(struct peering_model *pm)
{
	pthread_mutex_destroy(&pm->pub_lock);
}

void peering_sockaddr_text(const struct sockaddr *sa, socklen_t len, char *out,
			   size_t n)
{
	char host[64], serv[8];		/* serv is NI_NUMERICSERV: 5 digits max */

	out[0] = '\0';
	if (getnameinfo(sa, len, host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV))
		return;
	if (strchr(host, ':'))
		snprintf(out, n, "[%s]:%s", host, serv);
	else
		snprintf(out, n, "%s:%s", host, serv);
}

/*
 * Take this peer's announcement.
 *
 * A client takes it as it stands. The mailbox is the host's, and the node the
 * host names is the only one whose copy of it the host keeps current, so
 * following the host's word is the whole of how a client stays reachable
 * through a rendezvous that changed under a token already handed out.
 *
 * A host takes one only for a family it has no node of its own for: its own is
 * what the token names and what it serves, and a client may not move it.
 *
 * Adopting means the node becomes this end's anchor, pinned for the direct
 * get, shown on the panel, seeded into the next signaller, and not a note kept
 * aside for a reconnection.
 */
static void rdv_adopt(struct peering *pr, uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	struct peering_model *pm = pr->pm;
	struct ctlplane_node in[2];
	int i;

	if (!ctlplane_take_nodes(&pr->cp, in))
		return;
	for (i = 0; i < 2; i++) {
		uint8_t node[NETSTATE_SA_MAX], nlen = 0;
		char b[80];

		if (!in[i].have)
			continue;
		peering_sockaddr_text((struct sockaddr *)&in[i].sa, in[i].len,
				      b, sizeof(b));
		dbg_logf("rdv: peer names v%d %s", famv[i], b);
		if (netstate_anchor(&pm->ns, famv[i], node, &nlen, NULL)) {
			if (pm->is_host)
				continue;
			if (nlen == in[i].len &&
			    !memcmp(node, &in[i].sa, nlen)) {
				/* The same node by our own route. Nothing to
				 * adopt, and the end state is what matters, so
				 * say it rather than leave the two ways of
				 * arriving at it looking different. */
				dbg_logf("rdv: already holding the peer's v%d "
					 "node %s", famv[i], b);
				continue;
			}
		}
		/*
		 * Only a node the peer stands behind is a vouch. It names the
		 * ones it has not proven as well, they being where it is
		 * meeting and this end perhaps able to prove what it cannot,
		 * but taking its word for one it has not got would put a claim
		 * behind a node nobody has ever made.
		 */
		if (in[i].status & (CTL_RDVST_PROVEN | CTL_RDVST_VOUCHED))
			netstate_on_rdv_vouched(&pm->ns, famv[i],
						(const uint8_t *)&in[i].sa,
						(int)in[i].len, now);
		else
			netstate_on_rdv_offered(&pm->ns, famv[i],
						(const uint8_t *)&in[i].sa,
						(int)in[i].len, now);
		dbg_logf("rdv: adopted the peer's v%d node %s (%s%s)", famv[i],
			 b, in[i].status & CTL_RDVST_PROVEN ? "proven" :
			    in[i].status & CTL_RDVST_VOUCHED ? "vouched" :
			    "unproven",
			 in[i].status & CTL_RDVST_BLIND ? ", peer is blind" :
							  "");
	}
}

/* Take this peer's account of itself. Kept per peer, since each one is a
 * different machine on a different network. */
static void reach_take(struct peering *pr)
{
	static const int famv[2] = { 4, 6 };
	uint8_t pl[CTL_REACH_PLEN];
	int i;

	if (!ctlplane_take_reach(&pr->cp, pl))
		return;
	for (i = 0; i < 2; i++) {
		int state = 0, flags = 0;

		ctl_reach_decode(pl, sizeof(pl), i, &state, &flags);
		dbg_logf("reach: peer %d v%d state=%d dht=%d", pr->id, famv[i],
			 state, !!(flags & CTL_REACHF_DHT));
	}
}

/*
 * Whether this end can look after `family`'s rendezvous itself: it reaches the
 * DHT there, or it already holds a node. Either way there is nobody to ask.
 */
static int self_sufficient(struct peering_model *pm, int family)
{
	int conn = 0, acked = 0;

	netstate_reach(&pm->ns, family, &conn, &acked);
	if (conn != NET_CONN_UP)
		return 0;

	return acked || netstate_anchor(&pm->ns, family, NULL, NULL, NULL);
}

/*
 * Ask this peer to establish the rendezvous this end cannot.
 *
 * A host with no global connectivity on a family has no way to place its
 * mailbox where a peer arriving on that family would look, and no way to
 * recover a node it lost when it moved. A client that still has the family has
 * both, and is already trusted with the mailbox, holding the same key and
 * writing to the same item. So it is asked, and what it finds comes back as an
 * ordinary announcement.
 *
 * Asked, not told: the client answers with a node or it does not, and the host
 * is no worse off either way. Repeated on a slow cadence for as long as the
 * family is missing, since the client's own situation may improve, and stopped
 * the moment a node arrives from anywhere at all.
 */
static void rdv_ask(struct peering *pr, uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	struct peering_model *pm = pr->pm;
	uint8_t reach[CTL_REACH_PLEN];
	int i;

	if (!pm->is_host || !pm->dht)
		return;
	if (!ctlplane_peer_reach(&pr->cp, reach))
		return;			/* it has not said, so do not presume */
	for (i = 0; i < 2; i++) {
		int state = 0, flags = 0;

		if (now < pr->next_rdvask_ms[i])
			continue;
		if (self_sufficient(pm, famv[i]))
			continue;
		ctl_reach_decode(reach, sizeof(reach), i, &state, &flags);
		/*
		 * Proven reachable is enough to be worth asking. Its DHT having
		 * already answered there would be the stronger claim, but it is
		 * not one to wait for: a client has no reason to have exercised
		 * the DHT over a family it was not using, so requiring it left
		 * exactly the dual-stack client a v4-only host needs looking
		 * unqualified, and the request was never made at all.
		 *
		 * Asking costs the client a convergent store and nothing if it
		 * turns out it cannot; the flag still travels, and still says
		 * which client to prefer once there is a choice.
		 */
		if (state != CTL_REACH_UP)
			continue;
		pr->next_rdvask_ms[i] = now + PEERING_RDVASK_MS;
		ctlplane_ask_rdv(&pr->cp, famv[i]);
		dbg_logf("rdv: asking peer %d to rendezvous on v%d", pr->id,
			 famv[i]);
	}
}

/*
 * Act on a peer's request that this end rendezvous for it.
 *
 * Standing rather than one-shot, because the search runs until it succeeds and
 * a single answer would strand a host whose first request was lost. It lapses
 * all the same: the host repeats it only while it still lacks the family, so a
 * peer that has recovered stops being worked for within a few periods.
 */
static void rdv_serve_ask(struct peering *pr, uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	struct peering_model *pm = pr->pm;
	int ask, i;

	if (pm->is_host || !pm->sig)
		return;
	ask = ctlplane_take_asks(&pr->cp);
	for (i = 0; i < 2; i++) {
		if (ask & (i ? 2 : 1)) {
			pm->relay_until_ms[i] = now + PEERING_RELAY_HOLD_MS;
			if (!pm->relay_fam[i]) {
				pm->relay_fam[i] = 1;
				sig_relay(pm->sig, famv[i], 1);
				dbg_logf("rdv: rendezvousing on v%d for the "
					 "peer", famv[i]);
			}
			continue;
		}
		if (pm->relay_fam[i] && now >= pm->relay_until_ms[i]) {
			pm->relay_fam[i] = 0;
			sig_relay(pm->sig, famv[i], 0);
			dbg_logf("rdv: no longer asked to rendezvous on v%d",
				 famv[i]);
		}
	}
}

void peering_absorb(struct peering *pr, uint64_t now)
{
	rdv_adopt(pr, now);
	reach_take(pr);
	rdv_serve_ask(pr, now);
	rdv_ask(pr, now);
}

void peering_sinks(struct peering *pr, const struct pathplane_sinks *pk,
		   const struct ctlplane_sinks *ck)
{
	pr->pk = *pk;
	pr->ck = *ck;
}

void peering_paths(struct peering *pr, uint64_t now)
{
	pathplane_tick(&pr->pl, &pr->pk, now);
}

int peering_recv(struct peering *pr, const uint8_t *data, size_t len,
		 enum path_kind kind, const struct sockaddr_in6 *src,
		 struct nat_agent *agent, uint64_t now)
{
	return pathplane_recv(&pr->pl, &pr->pk, data, len, kind, src, agent,
			      now);
}

void peering_ctl(struct peering *pr, int type, const uint8_t *pl, size_t plen,
		 unsigned netgen, uint64_t now)
{
	ctlplane_on_msg(&pr->cp, &pr->ck, type, pl, plen, netgen, now);
}

int peering_datagram(struct peering *pr, const uint8_t *data, size_t *len,
		     enum path_kind kind, const struct sockaddr_in6 *src,
		     struct nat_agent *agent, uint64_t now)
{
	if (pathplane_muted(&pr->pl))
		return 1;
	if (pathplane_is_probe(&pr->pl, data, *len)) {
		peering_recv(pr, data, *len, kind, src, agent, now);
		return 1;
	}

	return probeplane_unwrap(&pr->pp, data, len) ? 1 : 0;
}

int peering_claims(struct peering *pr, const uint8_t *data, size_t len,
		   enum path_kind kind, const struct sockaddr_in6 *src,
		   uint64_t now)
{
	struct path_probe probe;
	int claimed;

	claimed = pathplane_claims(&pr->pl, &pr->pk, data, len, &probe);
	if (claimed > 0)
		pathplane_apply(&pr->pl, &pr->pk, &probe, kind, src, NULL, now);

	return claimed;
}

int peering_pick(struct peering *pr, uint64_t now,
		 struct pathplane_pick *out)
{
	return pathplane_pick(&pr->pl, &pr->pk, now, out);
}

int peering_add_path(struct peering *pr, enum path_kind kind,
		     const struct sockaddr_in6 *remote, char *label,
		     size_t label_len, uint64_t now)
{
	return pathplane_add_ep(&pr->pl, &pr->pk, kind, remote, label,
				label_len, now);
}

void peering_offer_path(struct peering *pr, const struct sockaddr_in6 *remote,
			uint64_t now)
{
	pathplane_offer_path(&pr->pl, &pr->pk, remote, now);
}

/*
 * Advertise this end's own endpoints on the shared socket, so the peer probes
 * and holds them rather than exploring only what admission produced. The
 * addresses come from the interface snapshot, which already leaves out
 * loopback, naming this machine to nobody else, and IPv6 link-local, which
 * travels without the zone id it cannot be reached without.
 */
static void cand_tell(struct peering *pr, uint16_t cand_port, uint64_t now)
{
	struct netmon_addr addrs[NETMON_MAX_ADDRS];
	size_t naddrs, i;

	if (now < pr->next_cand_ms)
		return;
	pr->next_cand_ms = now + PEERING_CAND_TELL_MS;
	if (!cand_port)
		return;
	naddrs = netmon_snapshot(addrs, NETMON_MAX_ADDRS);
	for (i = 0; i < naddrs; i++) {
		struct sockaddr_storage sa;
		int fam = netmon_addr_sockaddr(&addrs[i], cand_port, &sa);

		if (!fam)
			continue;
		ctlplane_tell_cand(&pr->cp, &pr->ck, fam,
				   (struct sockaddr *)&sa);
	}
}

/*
 * Say where this end is rendezvoused, so a peer that loses its own way back
 * has somewhere to look. Unproven nodes too: one this end cannot prove is
 * still where it is meeting, and a peer that can reach the family may be able
 * to prove it, which is the whole of how an end with no route to a family
 * keeps a rendezvous on it. The status byte is what lets the peer tell the
 * cases apart.
 */
static void rdv_tell(struct peering *pr, uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	struct peering_model *pm = pr->pm;
	struct peering_rdv pub[2];
	uint32_t gen;
	int i;

	pthread_mutex_lock(&pm->pub_lock);
	memcpy(pub, pm->rdv, sizeof(pub));
	gen = pm->rdv_gen;
	pthread_mutex_unlock(&pm->pub_lock);

	if (gen == pr->rdv_told_gen && now < pr->next_rdv_tell_ms)
		return;
	pr->rdv_told_gen = gen;
	pr->next_rdv_tell_ms = now + PEERING_RDV_TELL_MS;
	for (i = 0; i < 2; i++) {
		if (!pub[i].have)
			continue;
		ctlplane_tell_rdv(&pr->cp, &pr->ck, famv[i],
				  (struct sockaddr *)&pub[i].sa,
				  pub[i].status);
	}
}

/*
 * Tell this peer what this end can reach, whenever that is no longer what it
 * was told. A peer starts owed it, so it knows the moment it is connected and
 * again on every move.
 */
static void reach_tell(struct peering *pr, uint64_t now)
{
	struct peering_model *pm = pr->pm;
	uint8_t pl[CTL_REACH_PLEN];
	uint32_t gen;

	pthread_mutex_lock(&pm->pub_lock);
	memcpy(pl, pm->reach, sizeof(pl));
	gen = pm->reach_gen;
	pthread_mutex_unlock(&pm->pub_lock);

	if (!gen)			/* nothing observed to report yet */
		return;
	if (gen == pr->reach_told_gen && now < pr->next_reach_tell_ms)
		return;
	pr->reach_told_gen = gen;
	pr->next_reach_tell_ms = now + PEERING_REACH_TELL_MS;
	ctlplane_tell_reach(&pr->cp, &pr->ck, pl);
}

void peering_say(struct peering *pr, uint16_t cand_port, uint64_t now)
{
	cand_tell(pr, cand_port, now);
	rdv_tell(pr, now);
	reach_tell(pr, now);
	ctlplane_tell_asks(&pr->cp, &pr->ck);
	/*
	 * The half is offered only once the channel can actually carry it: a
	 * frame written into one that is not there yet would be dropped, and
	 * the half would be spent with nothing having heard it.
	 */
	if (!pr->ck.ready || pr->ck.ready(pr->ck.arg))
		ctlplane_offer_key(&pr->cp, &pr->ck);
	if (now < pr->next_hb_ms)
		return;
	pr->next_hb_ms = now + HB_INTERVAL_MS;
	ctlplane_ping(&pr->cp, &pr->ck, now);
}

void peering_owed(struct peering *pr, uint64_t now)
{
	pr->next_cand_ms = now;
	pr->rdv_told_gen = 0;
	pr->next_rdv_tell_ms = now;
	pr->reach_told_gen = 0;
	pr->next_reach_tell_ms = now;
	pr->next_rdvask_ms[0] = now;
	pr->next_rdvask_ms[1] = now;
	pr->next_hb_ms = now;
}

void peering_acks(struct peering_model *pm, uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	int i;

	if (!pm->sig)
		return;
	for (i = 0; i < 2; i++) {
		struct sockaddr_storage sa;
		socklen_t sl = sizeof(sa);

		/* Taken first and separately: a get answered by the node this
		 * end holds and then by another holder would otherwise be read
		 * as ours having gone quiet, which is how a live rendezvous
		 * used to be given up seconds after being chosen. */
		if (sig_take_anchor_seen(pm->sig, famv[i]))
			netstate_on_anchor_seen(&pm->ns, famv[i], now);
		/*
		 * Rendezvousing for the peer on this family is precisely being
		 * allowed to choose one, so the ordinary trial runs and the
		 * node that wins it becomes this end's anchor by the rules
		 * every other node goes through. The peer must not be able to
		 * tell one found this way from one found for ourselves.
		 */
		netstate_set_picking(&pm->ns, famv[i],
				     pm->is_host || pm->relay_fam[i]);
		memset(&sa, 0, sizeof(sa));
		if (!sig_take_ack(pm->sig, famv[i], (struct sockaddr *)&sa, &sl))
			continue;
		netstate_on_dht_ack(&pm->ns, famv[i],
				    netstate_epoch(&pm->ns, famv[i]),
				    (const uint8_t *)&sa, (int)sl, now);
	}
}

/* Which address this machine would send from on `family`, as the kernel
 * answers it now. */
static void sample_src(struct peering_model *pm, int family, uint32_t epoch,
		       uint64_t now)
{
	int af = family == 6 ? AF_INET6 : AF_INET;
	uint8_t raw[16];
	char text[64];
	int len = 0;

	if (net_source_addr(af, text, sizeof(text), raw, &len))
		len = 0;
	netstate_on_src(&pm->ns, family, epoch, len ? raw : NULL, len,
			len ? net_addr_scope(text) : 0, len ? text : NULL, now);
}

static void apply(struct peering_model *pm, struct peering_net *net,
		  const struct peering_settle *cfg,
		  const struct netstate_actions *a, uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	int i;

	for (i = 0; i < 2; i++) {
		unsigned act = a->f[i];
		int family = famv[i];

		if (act & NSA_SAMPLE_SRC)
			sample_src(pm, family, a->epoch[i], now);
		if (act & NSA_KICK_PROBE) {
			if (peering_net_kick(net, family, a->epoch[i],
					     cfg->start6))
				netstate_on_probe_started(&pm->ns, family,
							  a->epoch[i], now);
		}
		if (act & NSA_EMIT_ROWS)
			obsemit_rows(&pm->oe, family);
		if (act & NSA_EMIT_CONN) {
			int conn = netstate_conn(&pm->ns, family);

			if (pm->sig)
				sig_set_family_up(pm->sig, family,
						  conn == NET_CONN_UP);
			obsemit_conn(&pm->oe, family, conn);
		}
		if (act & NSA_RDV_PIN) {
			uint8_t node[NETSTATE_SA_MAX];
			uint8_t nlen = 0;

			if (pm->sig && netstate_anchor(&pm->ns, family, node,
						       &nlen, NULL))
				sig_reinforce(pm->sig, family,
					      (const struct sockaddr *)node,
					      (socklen_t)nlen);
		}
		if (act & NSA_RDV_RELOCATE && pm->sig)
			sig_search_again(pm->sig, family);
		if (act & NSA_RDV_DROP && pm->sig)
			sig_forget(pm->sig, family);
		if (act & NSA_EMIT_RDV)
			obsemit_rendezvous(&pm->oe, cfg->expect4, cfg->expect6);
		/* NSA_EMIT_TOKEN is advisory: what a token says is recomputed
		 * on its own cadence, which is what stops one churning through
		 * the transient states a move passes through. */
	}
}

void peering_settle(struct peering_model *pm, struct peering_net *net,
		    const struct peering_settle *cfg, uint64_t now)
{
	struct nsfact f[NSFACTS_OUT];
	struct netstate_actions a;
	int n, i;

	n = peering_facts_take(&net->facts, f, NSFACTS_OUT);
	for (i = 0; i < n; i++) {
		/* A round's end is said as its last act, so this does not
		 * wait. */
		if (f[i].kind == NSF_PROBE_DONE)
			peering_net_reap(net, f[i].family);
		peering_facts_feed(&pm->ns, &f[i], f[i].epoch, now);
	}
	netstate_tick(&pm->ns, now);
	if (netstate_take_actions(&pm->ns, &a))
		apply(pm, net, cfg, &a, now);
}

void peering_publish(struct peering_model *pm)
{
	static const int famv[2] = { 4, 6 };
	uint8_t pl[CTL_REACH_PLEN];
	int i, told = 0, moved;

	if (pm->dht)
		for (i = 0; i < 2; i++) {
			uint8_t node[NETSTATE_SA_MAX], nlen = 0;
			int confirmed = 0, same, proven = 0, vouched = 0;
			int blind = 0, status;

			if (!netstate_anchor(&pm->ns, famv[i], node, &nlen,
					     &confirmed) || !nlen)
				continue;
			netstate_anchor_state(&pm->ns, famv[i], &proven,
					      &vouched, &blind);
			status = (proven ? CTL_RDVST_PROVEN : 0) |
				 (vouched ? CTL_RDVST_VOUCHED : 0) |
				 (blind ? CTL_RDVST_BLIND : 0);
			pthread_mutex_lock(&pm->pub_lock);
			same = pm->rdv[i].have && pm->rdv[i].len == nlen &&
			       !memcmp(&pm->rdv[i].sa, node, nlen);
			if (!same || pm->rdv[i].qualified != confirmed ||
			    pm->rdv[i].status != status) {
				memset(&pm->rdv[i].sa, 0, sizeof(pm->rdv[i].sa));
				memcpy(&pm->rdv[i].sa, node, nlen);
				pm->rdv[i].len = nlen;
				pm->rdv[i].have = 1;
				pm->rdv[i].qualified = confirmed;
				pm->rdv[i].status = status;
				pm->rdv_gen++;
				told = 1;
			}
			pthread_mutex_unlock(&pm->pub_lock);
		}
	if (told) {
		char b4[80], b6[80];

		/* Named, because "published" alone cannot distinguish the
		 * family that was already known from the one somebody is
		 * waiting to be told about. */
		b4[0] = b6[0] = '\0';
		pthread_mutex_lock(&pm->pub_lock);
		if (pm->rdv[0].have)
			peering_sockaddr_text((struct sockaddr *)&pm->rdv[0].sa,
					      pm->rdv[0].len, b4, sizeof(b4));
		if (pm->rdv[1].have)
			peering_sockaddr_text((struct sockaddr *)&pm->rdv[1].sa,
					      pm->rdv[1].len, b6, sizeof(b6));
		pthread_mutex_unlock(&pm->pub_lock);
		dbg_logf("rdv: publishing set %u: v4 %s v6 %s",
			 (unsigned)pm->rdv_gen, b4[0] ? b4 : "-",
			 b6[0] ? b6 : "-");
	}

	/*
	 * A verdict alone would not be enough to act on: NET_CONN_UP is
	 * asserted by a STUN round trip as readily as by the DHT, and it is
	 * the DHT a peer would be relying on if it asked this end to
	 * rendezvous for it. So the DHT's own answer travels beside the
	 * verdict rather than folded into it.
	 */
	memset(pl, 0, sizeof(pl));
	for (i = 0; i < 2; i++) {
		int conn = 0, acked = 0, state;

		netstate_reach(&pm->ns, famv[i], &conn, &acked);
		state = conn == NET_CONN_UP ? CTL_REACH_UP :
			conn == NET_CONN_PENDING ? CTL_REACH_PENDING :
						   CTL_REACH_DOWN;
		ctl_reach_encode(pl, i, state, acked ? CTL_REACHF_DHT : 0);
	}
	pthread_mutex_lock(&pm->pub_lock);
	moved = memcmp(pm->reach, pl, sizeof(pl)) != 0;
	if (moved) {
		memcpy(pm->reach, pl, sizeof(pl));
		pm->reach_gen++;
	}
	pthread_mutex_unlock(&pm->pub_lock);
	if (moved)
		dbg_logf("reach: v4 %u/%u v6 %u/%u", pl[0], pl[1], pl[2],
			 pl[3]);
}

void peering_advance(struct peering_model *pm, struct peering_net *net,
		     const struct peering_settle *cfg, uint64_t now)
{
	peering_acks(pm, now);
	peering_settle(pm, net, cfg, now);
	peering_publish(pm);
}

int peering_model_sig(struct peering_model *pm, struct sig *sig, uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	int i;

	pm->sig = sig;
	if (!sig)
		return 0;
	if (pm->have_claim_sk) {
		if (sig_use_claim_key(sig, pm->claim_sk))
			return -1;
	} else if (!sig_claim_key(sig, pm->claim_sk)) {
		pm->have_claim_sk = 1;
	}
	pm->dht_since_ms = now;
	for (i = 0; i < 2; i++) {
		sig_set_family_up(sig, famv[i],
				  netstate_conn(&pm->ns, famv[i]) ==
				  NET_CONN_UP);
		if (pm->relay_fam[i])
			sig_relay(sig, famv[i], 1);
	}

	return 0;
}

int peering_seed_pick(struct peering_model *pm, int family,
		      const struct peering_seed *fallback,
		      uint8_t *out, size_t cap)
{
	uint8_t node[NETSTATE_SA_MAX];
	uint8_t nlen = 0;

	if (netstate_anchor(&pm->ns, family, node, &nlen, NULL) && nlen &&
	    (size_t)nlen <= cap) {
		memcpy(out, node, nlen);
		return nlen;
	}
	if (fallback && fallback->len > 0 && (size_t)fallback->len <= cap) {
		memcpy(out, fallback->sa, (size_t)fallback->len);
		return fallback->len;
	}
	return 0;
}

void peering_seed_rendezvous(struct peering_model *pm,
			     const struct peering_seed fallback[2],
			     uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	int i;

	for (i = 0; i < 2; i++) {
		struct sockaddr_storage ss;
		int len;

		len = peering_seed_pick(pm, famv[i],
					fallback ? &fallback[i] : NULL,
					(uint8_t *)&ss, sizeof(ss));
		if (!len)
			continue;
		if (pm->is_host)
			sig_reinforce(pm->sig, famv[i], (struct sockaddr *)&ss,
				      (socklen_t)len);
		else if (sig_seed_node(pm->sig, (struct sockaddr *)&ss,
				       (socklen_t)len))
			continue;
		netstate_on_rdv_offered(&pm->ns, famv[i], (const uint8_t *)&ss,
					len, now);
	}
}

int peering_net_stun_pick(const struct peering_net *m, unsigned attempt,
			  char *host, size_t hostlen, uint16_t *port)
{
	const char *cand, *colon, *e;
	int i, picked = 0;
	char ip[64];
	size_t hl;

	if (m->nservers < 1)
		return -1;
	e = m->servers[attempt % (unsigned)m->nservers];
	for (i = 0; i < m->nservers && !picked; i++) {
		cand = m->servers[(attempt + (unsigned)i) %
				  (unsigned)m->nservers];
		if (stun_server_ip4(cand, ip, sizeof(ip), 0)) {
			e = cand;
			picked = 1;
		}
	}
	colon = strrchr(e, ':');
	*port = colon ? (uint16_t)atoi(colon + 1) : 3478;
	if (!*port)
		*port = 3478;
	if (picked) {
		snprintf(host, hostlen, "%s", ip);
		return 0;
	}
	hl = colon ? (size_t)(colon - e) : strlen(e);
	if (hl >= hostlen)
		hl = hostlen - 1;
	memcpy(host, e, hl);
	host[hl] = '\0';

	return 0;
}

void peering_ice_gen(char *ufrag, size_t uflen, char *pwd, size_t pwlen)
{
	static const char hx[] = "0123456789abcdef";
	uint8_t rb[16];
	size_t i;

	random_bytes(rb, 4);
	for (i = 0; i + 1 < uflen && i < 8; i++)
		ufrag[i] = hx[i & 1 ? (rb[i / 2] & 0xf) : (rb[i / 2] >> 4)];
	ufrag[i] = '\0';
	random_bytes(rb, 16);
	for (i = 0; i + 1 < pwlen && i < 32; i++)
		pwd[i] = hx[i & 1 ? (rb[i / 2] & 0xf) : (rb[i / 2] >> 4)];
	pwd[i] = '\0';
}

int peering_link(struct peering *pr, unsigned netgen, int carrier_up,
		 uint64_t now)
{
	struct ctlplane_live live;

	ctlplane_liveness(&pr->cp, &live);
	if (!live.pong_seen)
		return carrier_up ? CONN_PUNCHING : CONN_CONNECTING;
	if (live.lost_since_ms &&
	    now - live.last_pong_ms >= hb_lost_ms(live.rtt_ms))
		return CONN_LOST;
	if (live.live_gen != netgen)
		return CONN_UNKNOWN;	/* proven, but somewhere else */
	if (now - live.last_pong_ms >= PEERING_LINK_LAG_MS)
		return CONN_LAGGED;

	return CONN_LIVE;
}

void peering_ice_ident(struct peering *pr)
{
	peering_ice_gen(pr->ice.ufrag, sizeof(pr->ice.ufrag), pr->ice.pwd,
			sizeof(pr->ice.pwd));
}

struct nat_agent *peering_ice_agent(struct peering *pr)
{
	return pr->ice.agent;
}

int peering_ice_up(const struct peering *pr)
{
	return __atomic_load_n(&pr->ice.up, __ATOMIC_RELAXED);
}

void peering_ice_adopt(struct peering *pr, struct nat_agent *agent, void *ctx,
		       uint64_t now)
{
	pr->ice.agent = agent;
	pr->ice.ctx = ctx;
	pathplane_add_ice(&pr->pl, agent, now);
}

void peering_ice_stop(struct peering *pr, const struct pathplane_sinks *k)
{
	struct nat_agent *agent = pr->ice.agent;
	void *ctx = pr->ice.ctx;

	pr->ice.agent = NULL;
	pr->ice.ctx = NULL;
	pathplane_drop_ice(&pr->pl);
	pathplane_free_agent(&pr->pl, k, agent, ctx);
}

int peering_ice_prime(struct peering *pr, const char *sdp, const char *ufrag,
		      const char *pwd)
{
	if (nat_set_remote_description(pr->ice.agent, sdp))
		return -1;
	snprintf(pr->ice.remote_ufrag, sizeof(pr->ice.remote_ufrag), "%s",
		 ufrag);
	if (pwd)
		snprintf(pr->ice.remote_pwd, sizeof(pr->ice.remote_pwd), "%s",
			 pwd);

	return 0;
}

void peering_ice_amend(struct peering *pr, const char *sdp)
{
	if (!pr->ice.agent || nat_connected(pr->ice.agent))
		return;
	nat_set_remote_description(pr->ice.agent, sdp);
}

int peering_ice_rotated(const struct peering *pr, const char *offer_ufrag)
{
	return pr->ice.remote_ufrag[0] &&
	       strcmp(offer_ufrag, pr->ice.remote_ufrag) != 0;
}

int peering_ice_failed(const struct peering *pr)
{
	return nat_failed(pr->ice.agent);
}

int peering_ice_moved(const struct peering *pr, uint32_t peer_gen)
{
	return peer_gen > pr->ice.remote_gen;
}

int peering_offer_judge(struct peering *pr, const uint8_t *data, size_t len,
			char *out, size_t cap, char *ufrag, size_t uflen)
{
	if (len >= cap)
		len = cap - 1;
	memcpy(out, data, len);
	out[len] = '\0';
	cand_sdp_ufrag(out, ufrag, uflen);

	return !peering_ice_rotated(pr, ufrag);
}

int peering_net_fan(struct peering_net *m, char *sdp, size_t cap)
{
	uint8_t pool[PEERING_POOL4_MAX][4];
	int n, moves;

	n = peering_pool_copy(&m->pool, pool);
	moves = !peering_pool_port_stable(&m->pool);
	if (n >= 2)
		cand_sdp_fan_v4(sdp, cap, pool, (size_t)n, moves);

	return n;
}

int peering_rotate_allowed(const struct peering_net *m)
{
	if (!m->auto_probe || m->nservers < 2)
		return 0;
	if (!__atomic_load_n(&m->have_priv4, __ATOMIC_RELAXED))
		return 0;

	return m->rotations < PEERING_ROTATE_MAX;
}

int peering_rotate_wanted(const struct peering_net *m, uint64_t since_ms,
			  uint64_t now)
{
	if (!peering_rotate_allowed(m) ||
	    __atomic_load_n(&m->have_srflx4, __ATOMIC_RELAXED))
		return 0;

	return now - since_ms > PEERING_ROTATE_MS;
}
