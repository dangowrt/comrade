/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "ctlplane.h"
#include "dbg.h"
#include "hbeat.h"
#include "keys.h"

void ctlplane_init(struct ctlplane *cp, struct probeplane *pp)
{
	memset(cp, 0, sizeof(*cp));
	cp->pp = pp;
	pthread_mutex_init(&cp->lock, NULL);
}

void ctlplane_destroy(struct ctlplane *cp)
{
	pthread_mutex_destroy(&cp->lock);
}

void ctlplane_reset(struct ctlplane *cp)
{
	cp->half_sent = 0;
	cp->half_seen = 0;
}

void ctlplane_live_reset(struct ctlplane *cp, uint64_t now)
{
	pthread_mutex_lock(&cp->lock);
	cp->live.last_pong_ms = now;
	__atomic_store_n(&cp->live.last_heard_ms, now, __ATOMIC_RELAXED);
	cp->live.pong_seen = 0;
	cp->live.lost_since_ms = 0;
	pthread_mutex_unlock(&cp->lock);
}

/*
 * Liveness is the whole traffic and not the pong alone, a pong crossing the
 * same queues as bulk data and arriving late on a busy link, but it has to be
 * traffic that authenticated: a datagram anyone can send is not evidence a
 * peer is there, and taking it as such lets a spoofed packet every couple of
 * seconds hold a dead session open.
 *
 * The unlocked read only coarsens the update to ~100ms; the store is what the
 * verdict reads, and it is taken under the lock.
 */
void ctlplane_heard(struct ctlplane *cp, uint64_t now)
{
	if (now - __atomic_load_n(&cp->live.last_heard_ms,
				  __ATOMIC_RELAXED) < 100)
		return;
	pthread_mutex_lock(&cp->lock);
	__atomic_store_n(&cp->live.last_heard_ms, now, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&cp->lock);
}

void ctlplane_liveness(struct ctlplane *cp, struct ctlplane_live *out)
{
	pthread_mutex_lock(&cp->lock);
	*out = cp->live;
	out->last_heard_ms = __atomic_load_n(&cp->live.last_heard_ms,
					     __ATOMIC_RELAXED);
	pthread_mutex_unlock(&cp->lock);
}

int ctlplane_judge(struct ctlplane *cp, uint64_t now, uint64_t *quiet_since)
{
	uint64_t lp;
	int lost;

	pthread_mutex_lock(&cp->lock);
	lp = cp->live.last_pong_ms;
	if (__atomic_load_n(&cp->live.last_heard_ms, __ATOMIC_RELAXED) > lp)
		lp = __atomic_load_n(&cp->live.last_heard_ms, __ATOMIC_RELAXED);
	if (cp->live.pong_seen) {
		if (now - lp > hb_lost_ms(cp->live.rtt_ms)) {
			if (!cp->live.lost_since_ms)
				cp->live.lost_since_ms = now;
		} else {
			cp->live.lost_since_ms = 0;
		}
	}
	lost = cp->live.lost_since_ms != 0;
	pthread_mutex_unlock(&cp->lock);
	if (quiet_since)
		*quiet_since = lp;

	return lost;
}

int ctlplane_lost(struct ctlplane *cp)
{
	int lost;

	pthread_mutex_lock(&cp->lock);
	lost = cp->live.lost_since_ms != 0;
	pthread_mutex_unlock(&cp->lock);

	return lost;
}

/*
 * Both halves are in: this pair's probes leave the establishment key behind.
 * We can open under the new one now; the far end may not be able to yet, and
 * it is the one that decides when we may seal with it.
 */
static void key_bind(struct ctlplane *cp, const struct ctlplane_sinks *k)
{
	if (cp->pp->pair_ready || !cp->half_sent || !cp->half_seen)
		return;
	probeplane_bind(cp->pp, cp->half_out, cp->half_in);
	k->send(k->arg, CTLM_KEYOK, NULL, 0);
	dbg_logf("path: keyed to this connection, telling the peer");
}

int ctlplane_offer_key(struct ctlplane *cp, const struct ctlplane_sinks *k)
{
	if (cp->half_sent || random_bytes(cp->half_out, KEYS_HALF_LEN))
		return 0;
	k->send(k->arg, CTLM_KEY, cp->half_out, CTL_KEY_PLEN);
	cp->half_sent = 1;
	key_bind(cp, k);

	return 1;
}

void ctlplane_tell_rdv(struct ctlplane *cp, const struct ctlplane_sinks *k,
		       int family, const struct sockaddr *sa, int status)
{
	uint8_t pl[CTL_RDVST_PLEN];

	(void)cp;
	ctl_rdv_encode(pl, family, sa);
	pl[CTL_RDV_PLEN] = (uint8_t)status;
	k->send(k->arg, CTLM_RDV, pl, sizeof(pl));
}

void ctlplane_tell_cand(struct ctlplane *cp, const struct ctlplane_sinks *k,
			int family, const struct sockaddr *sa)
{
	uint8_t pl[CTL_RDV_PLEN];

	(void)cp;
	ctl_rdv_encode(pl, family, sa);
	k->send(k->arg, CTLM_CAND, pl, sizeof(pl));
}

void ctlplane_tell_reach(struct ctlplane *cp, const struct ctlplane_sinks *k,
			 const uint8_t pl[CTL_REACH_PLEN])
{
	(void)cp;
	k->send(k->arg, CTLM_REACH, pl, CTL_REACH_PLEN);
}

void ctlplane_ping(struct ctlplane *cp, const struct ctlplane_sinks *k,
		   uint64_t now)
{
	uint8_t ts[CTL_TS_LEN];

	(void)cp;
	ctl_put_u64(ts, now);
	k->send(k->arg, CTLM_PING, ts, sizeof(ts));
}

void ctlplane_ask_rdv(struct ctlplane *cp, int family)
{
	pthread_mutex_lock(&cp->lock);
	cp->rdvask_out |= family == 6 ? 2 : 1;
	pthread_mutex_unlock(&cp->lock);
}

void ctlplane_tell_asks(struct ctlplane *cp, const struct ctlplane_sinks *k)
{
	static const int famv[2] = { 4, 6 };
	uint8_t pl[CTL_RDVASK_PLEN];
	int ask, i;

	pthread_mutex_lock(&cp->lock);
	ask = cp->rdvask_out;
	cp->rdvask_out = 0;
	pthread_mutex_unlock(&cp->lock);
	for (i = 0; i < 2; i++) {
		if (!(ask & (i ? 2 : 1)))
			continue;
		pl[0] = (uint8_t)famv[i];
		k->send(k->arg, CTLM_RDVASK, pl, sizeof(pl));
	}
}

int ctlplane_take_nodes(struct ctlplane *cp, struct ctlplane_node out[2])
{
	pthread_mutex_lock(&cp->lock);
	if (!cp->rdv_in_dirty) {
		pthread_mutex_unlock(&cp->lock);
		return 0;
	}
	memcpy(out, cp->rdv_in, 2 * sizeof(out[0]));
	cp->rdv_in_dirty = 0;
	pthread_mutex_unlock(&cp->lock);

	return 1;
}

int ctlplane_take_asks(struct ctlplane *cp)
{
	int ask;

	pthread_mutex_lock(&cp->lock);
	ask = cp->rdvask_in;
	cp->rdvask_in = 0;
	pthread_mutex_unlock(&cp->lock);

	return ask;
}

int ctlplane_take_reach(struct ctlplane *cp, uint8_t out[CTL_REACH_PLEN])
{
	pthread_mutex_lock(&cp->lock);
	if (!cp->reach_in_dirty) {
		pthread_mutex_unlock(&cp->lock);
		return 0;
	}
	cp->reach_in_dirty = 0;
	memcpy(out, cp->reach_in, CTL_REACH_PLEN);
	pthread_mutex_unlock(&cp->lock);

	return 1;
}

int ctlplane_peer_reach(struct ctlplane *cp, uint8_t out[CTL_REACH_PLEN])
{
	int seen;

	pthread_mutex_lock(&cp->lock);
	seen = cp->reach_in_seen;
	if (seen)
		memcpy(out, cp->reach_in, CTL_REACH_PLEN);
	pthread_mutex_unlock(&cp->lock);

	return seen;
}

static void on_pong(struct ctlplane *cp, const struct ctlplane_sinks *k,
		    const uint8_t *pl, unsigned netgen, uint64_t now)
{
	pthread_mutex_lock(&cp->lock);
	cp->live.last_pong_ms = now;
	cp->live.rtt_ms = (int)(now - ctl_get_u64(pl));
	cp->live.pong_seen = 1;
	/* Traffic arriving is the only thing that proves a path on the network
	 * we are on now. */
	cp->live.live_gen = netgen;
	pthread_mutex_unlock(&cp->lock);
	if (k->pong)
		k->pong(k->arg);
}

static void on_rdv(struct ctlplane *cp, const uint8_t *pl, size_t plen)
{
	struct sockaddr_storage sa;
	socklen_t sl = 0;
	int fam = ctl_rdv_decode(pl, plen, &sa, &sl);
	int i;

	if (!fam)
		return;
	i = fam == 6 ? 1 : 0;
	pthread_mutex_lock(&cp->lock);
	cp->rdv_in[i].sa = sa;
	cp->rdv_in[i].len = sl;
	cp->rdv_in[i].have = 1;
	cp->rdv_in[i].status = plen >= CTL_RDVST_PLEN ? pl[CTL_RDV_PLEN] : 0;
	cp->rdv_in_dirty = 1;
	pthread_mutex_unlock(&cp->lock);
}

int ctlplane_on_msg(struct ctlplane *cp, const struct ctlplane_sinks *k,
		    int type, const uint8_t *pl, size_t plen, unsigned netgen,
		    uint64_t now)
{
	if (type == CTLM_PING && plen >= CTL_TS_LEN) {
		if (!k->answer_ping || k->answer_ping(k->arg))
			k->send(k->arg, CTLM_PONG, pl, CTL_TS_LEN);
	} else if (type == CTLM_PONG && plen >= CTL_TS_LEN) {
		on_pong(cp, k, pl, netgen, now);
	} else if (type == CTLM_RDV && plen >= CTL_RDV_PLEN) {
		on_rdv(cp, pl, plen);
	} else if (type == CTLM_REACH && plen >= CTL_REACH_PLEN) {
		pthread_mutex_lock(&cp->lock);
		memcpy(cp->reach_in, pl, CTL_REACH_PLEN);
		cp->reach_in_seen = 1;
		cp->reach_in_dirty = 1;
		pthread_mutex_unlock(&cp->lock);
	} else if (type == CTLM_KEY && plen >= CTL_KEY_PLEN) {
		memcpy(cp->half_in, pl, CTL_KEY_PLEN);
		cp->half_seen = 1;
		key_bind(cp, k);
	} else if (type == CTLM_KEYOK) {
		if (probeplane_tx_ready(cp->pp))
			dbg_logf("path: sealing to this connection");
	} else if (type == CTLM_RDVASK && plen >= CTL_RDVASK_PLEN) {
		if (pl[0] == 4 || pl[0] == 6) {
			pthread_mutex_lock(&cp->lock);
			cp->rdvask_in |= pl[0] == 6 ? 2 : 1;
			pthread_mutex_unlock(&cp->lock);
		}
	} else if (type == CTLM_CAND && plen >= CTL_RDV_PLEN) {
		struct sockaddr_storage sa;
		socklen_t sl = 0;

		if (ctl_rdv_decode(pl, plen, &sa, &sl) && k->offer_path)
			k->offer_path(k->arg, (struct sockaddr *)&sa, sl);
	} else {
		if (k->other)
			k->other(k->arg, type, pl, plen);
		return 0;
	}

	return 1;
}
