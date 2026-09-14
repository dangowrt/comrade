/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>

#include "dbg.h"
#include "probeplane.h"

void probeplane_init(struct probeplane *pp, uint32_t magic,
		     const uint8_t base[32], uint64_t seq0)
{
	memset(pp, 0, sizeof(*pp));
	pp->magic = magic;
	pp->seq = seq0;
	pp->data_seq = seq0;
	memcpy(pp->base, base, sizeof(pp->base));
	pp->base_ok = 1;
	pthread_mutex_init(&pp->lock, NULL);
}

void probeplane_destroy(struct probeplane *pp)
{
	pthread_mutex_destroy(&pp->lock);
	memset(pp, 0, sizeof(*pp));
}

void probeplane_reset(struct probeplane *pp)
{
	pthread_mutex_lock(&pp->lock);
	pp->pair_ready = 0;
	pp->pair_tx = 0;
	pp->base_ok = 1;
	pthread_mutex_unlock(&pp->lock);
}

void probeplane_bind(struct probeplane *pp,
		     const uint8_t half_out[KEYS_HALF_LEN],
		     const uint8_t half_in[KEYS_HALF_LEN])
{
	pthread_mutex_lock(&pp->lock);
	keys_conn_key(pp->pair, pp->base, half_out, half_in);
	pp->pair_ready = 1;
	pthread_mutex_unlock(&pp->lock);
}

int probeplane_tx_ready(struct probeplane *pp)
{
	int moved = 0;

	pthread_mutex_lock(&pp->lock);
	if (pp->pair_ready && !pp->pair_tx) {
		pp->pair_tx = 1;
		moved = 1;
	}
	pthread_mutex_unlock(&pp->lock);

	return moved;
}

/* The keys in force, taken together so a frame is judged against one
 * consistent view of them. */
struct keys_now {
	uint8_t tx[32];
	uint8_t rx[32];
	int have_rx;
	int base_ok;
};

static void keys_take(struct probeplane *pp, struct keys_now *k)
{
	pthread_mutex_lock(&pp->lock);
	memcpy(k->rx, pp->pair, sizeof(k->rx));
	k->have_rx = pp->pair_ready;
	k->base_ok = pp->base_ok;
	memcpy(k->tx, pp->pair_tx ? pp->pair : pp->base, sizeof(k->tx));
	pthread_mutex_unlock(&pp->lock);
}

/* A frame opened under the pair key: the base key is spent here. */
static void saw_pair(struct probeplane *pp)
{
	pthread_mutex_lock(&pp->lock);
	if (pp->base_ok) {
		pp->base_ok = 0;
		dbg_logf("path: the invitation's key is done on this "
			 "connection");
	}
	pthread_mutex_unlock(&pp->lock);
}

size_t probeplane_seal(struct probeplane *pp, struct path_probe *pr,
		       const char *ufrag, uint8_t *out, size_t out_len)
{
	uint8_t tx[32];

	snprintf(pr->ufrag, sizeof(pr->ufrag), "%s", ufrag ? ufrag : "");
	pthread_mutex_lock(&pp->lock);
	pr->seq = ++pp->seq;
	memcpy(tx, pp->pair_tx ? pp->pair : pp->base, sizeof(tx));
	pthread_mutex_unlock(&pp->lock);

	return path_probe_build(out, out_len, pp->magic, tx, pr);
}

int probeplane_open(struct probeplane *pp, struct path_probe *pr,
		    const uint8_t *data, size_t len)
{
	struct keys_now k;

	keys_take(pp, &k);
	if (k.have_rx && !path_probe_parse(pr, pp->magic, k.rx, data, len)) {
		saw_pair(pp);
		return 0;
	}
	if (path_probe_parse(pr, pp->magic, pp->base, data, len))
		return -1;
	if (k.base_ok)
		return 0;

	return pr->type == PROBE_FRESH ? 0 : -1;
}

size_t probeplane_wrap(struct probeplane *pp, uint8_t *out, size_t out_max,
		       const uint8_t *data, size_t len)
{
	struct keys_now k;
	uint64_t seq;

	keys_take(pp, &k);
	pthread_mutex_lock(&pp->lock);
	seq = ++pp->data_seq;
	pthread_mutex_unlock(&pp->lock);

	return dataauth_wrap(out, out_max, k.tx, data, len, seq);
}

int probeplane_unwrap(struct probeplane *pp, const uint8_t *data, size_t *len)
{
	struct keys_now k;
	uint64_t seq;
	size_t body;
	int ok;

	keys_take(pp, &k);
	if (k.have_rx && !dataauth_open(k.rx, data, *len, &body, &seq)) {
		saw_pair(pp);
	} else if (!k.base_ok ||
		   dataauth_open(pp->base, data, *len, &body, &seq)) {
		return -1;
	}
	pthread_mutex_lock(&pp->lock);
	ok = replay_ok(&pp->data_rx, seq);
	pthread_mutex_unlock(&pp->lock);
	if (!ok)
		return -1;
	*len = body;

	return 0;
}

int probeplane_fresh(struct probeplane *pp, const struct path_probe *pr)
{
	int ok;

	pthread_mutex_lock(&pp->lock);
	ok = replay_ok(&pp->rx, pr->seq);
	pthread_mutex_unlock(&pp->lock);
	if (!ok)
		dbg_logf("path: probe %llu again -- dropped",
			 (unsigned long long)pr->seq);

	return ok;
}
