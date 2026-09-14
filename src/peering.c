/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "wsock.h"

#include "dbg.h"
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

void peering_net_destroy(struct peering_net *m)
{
	peering_facts_destroy(&m->facts);
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
