/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

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
