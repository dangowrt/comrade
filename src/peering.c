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
