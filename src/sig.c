/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bencode.h"
#include "bep44.h"
#include "dhtnode.h"
#include "keys.h"
#include "sig.h"
#include "sig_mcast.h"

#define SIG_MAX_CHAN 8
#define SIG_SALT_MAX (BEP44_MAX_SALT + 1)
#define SIG_DHT_PUT_MS 4000
#define SIG_DHT_GET_MS 2000
#define SIG_MCAST_ANN_MS 1000
#define SIG_DHT_GRACE_MS 2000

struct sig_pub {
	int in_use;
	char salt[SIG_SALT_MAX];
	uint8_t sealed[SIG_MAX_VALUE + SEAL_OVERHEAD];
	size_t sealed_len;
	int64_t seq;
	uint64_t next_dht_ms;
	uint64_t next_mcast_ms;
};

struct sig_sub {
	int in_use;
	char salt[SIG_SALT_MAX];
	sig_recv_cb *cb;
	void *arg;
	uint64_t next_get_ms;
	uint8_t last[SIG_MAX_VALUE];
	size_t last_len;
	int have_last;
	struct sig *owner;
};

struct sig {
	unsigned flags;
	struct session_keys keys;
	uint64_t start_ms;

	int dht_engaged;
	struct dhtnode *node;
	struct bep44_engine *engine;

	struct sig_mcast *mc;
	int mcast_delivered;

	struct sig_pub pub[SIG_MAX_CHAN];
	struct sig_sub sub[SIG_MAX_CHAN];
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static int engage_dht(struct sig *s)
{
	s->node = dhtnode_create();
	if (!s->node)
		return -1;
	s->engine = dhtnode_engine(s->node);
	s->dht_engaged = 1;
	return 0;
}

struct sig *sig_create(const uint8_t rdv[TOKEN_RDV_LEN], unsigned flags)
{
	struct sig *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	keys_derive(&s->keys, rdv);
	s->flags = flags;
	s->start_ms = now_ms();

	if (flags & SIG_MCAST) {
		s->mc = sig_mcast_open();
		if (!s->mc)
			s->flags &= ~SIG_MCAST;
	}
	/* DHT engages immediately only when multicast is not also in play;
	 * otherwise it is deferred so a fast LAN discovery avoids it. */
	if ((s->flags & SIG_DHT) && !(s->flags & SIG_MCAST)) {
		if (engage_dht(s)) {
			sig_destroy(s);
			return NULL;
		}
	}
	if (!(s->flags & (SIG_DHT | SIG_MCAST))) {
		sig_destroy(s);
		return NULL;
	}
	return s;
}

void sig_destroy(struct sig *s)
{
	if (!s)
		return;
	if (s->node)
		dhtnode_free(s->node);
	if (s->mc)
		sig_mcast_close(s->mc);
	free(s);
}

int sig_prepare(struct sig *s, struct pollfd *fds, int maxfds, int *timeout_ms)
{
	int nfds = 0, t;

	if (s->dht_engaged)
		nfds += dhtnode_prepare(s->node, fds + nfds, maxfds - nfds, &t);
	if (s->mc)
		nfds += sig_mcast_prepare(s->mc, fds + nfds, maxfds - nfds);
	*timeout_ms = 100;
	return nfds;
}

int sig_ready(struct sig *s)
{
	if (s->mc)
		return 1;
	return s->dht_engaged && dhtnode_ready(s->node);
}

static struct sig_pub *pub_find(struct sig *s, const char *channel)
{
	int i, slot = -1;

	for (i = 0; i < SIG_MAX_CHAN; i++) {
		if (s->pub[i].in_use) {
			if (!strcmp(s->pub[i].salt, channel))
				return &s->pub[i];
		} else if (slot < 0) {
			slot = i;
		}
	}
	if (slot < 0)
		return NULL;
	memset(&s->pub[slot], 0, sizeof(s->pub[slot]));
	s->pub[slot].in_use = 1;
	strncpy(s->pub[slot].salt, channel, SIG_SALT_MAX - 1);
	return &s->pub[slot];
}

int sig_publish(struct sig *s, const char *channel, const uint8_t *data, size_t len)
{
	struct sig_pub *p;
	int slen;

	if (len > SIG_MAX_VALUE || strlen(channel) > BEP44_MAX_SALT)
		return -1;
	p = pub_find(s, channel);
	if (!p)
		return -1;

	slen = msg_seal(p->sealed, sizeof(p->sealed), s->keys.sig_key, data, len);
	if (slen < 0)
		return -1;
	p->sealed_len = (size_t)slen;
	p->next_dht_ms = 0;
	p->next_mcast_ms = 0;
	return 0;
}

static int deliver_to_sub(struct sig_sub *sub, const uint8_t *sealed, size_t len)
{
	uint8_t plain[SIG_MAX_VALUE];
	int n = msg_open(plain, sizeof(plain), sub->owner->keys.sig_key, sealed, len);

	if (n < 0)
		return 0;
	if (sub->have_last && sub->last_len == (size_t)n &&
	    !memcmp(sub->last, plain, (size_t)n))
		return 0;
	memcpy(sub->last, plain, (size_t)n);
	sub->last_len = (size_t)n;
	sub->have_last = 1;
	sub->cb(sub->arg, plain, (size_t)n);
	return 1;
}

static void on_dht_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq)
{
	struct sig_sub *sub = arg;
	const uint8_t *sealed;
	size_t sealed_len;

	(void)seq;
	if (!v || benc_str_get(v, v_len, &sealed, &sealed_len))
		return;
	deliver_to_sub(sub, sealed, sealed_len);
}

static void on_mcast_recv(void *arg, const char *salt, const uint8_t *data, size_t len)
{
	struct sig *s = arg;
	int i;

	for (i = 0; i < SIG_MAX_CHAN; i++) {
		if (!s->sub[i].in_use || strcmp(s->sub[i].salt, salt))
			continue;
		if (deliver_to_sub(&s->sub[i], data, len))
			s->mcast_delivered = 1;
	}
}

int sig_subscribe(struct sig *s, const char *channel, sig_recv_cb *cb, void *arg)
{
	int i;

	if (strlen(channel) > BEP44_MAX_SALT)
		return -1;
	for (i = 0; i < SIG_MAX_CHAN; i++) {
		if (s->sub[i].in_use)
			continue;
		memset(&s->sub[i], 0, sizeof(s->sub[i]));
		s->sub[i].in_use = 1;
		strncpy(s->sub[i].salt, channel, SIG_SALT_MAX - 1);
		s->sub[i].cb = cb;
		s->sub[i].arg = arg;
		s->sub[i].owner = s;
		return 0;
	}
	return -1;
}

static void dht_pump(struct sig *s, uint64_t now)
{
	int i;

	if (!dhtnode_ready(s->node))
		return;
	for (i = 0; i < SIG_MAX_CHAN; i++) {
		struct sig_pub *p = &s->pub[i];
		uint8_t value[BEP44_MAX_VALUE];
		struct benc_buf vb;

		if (!p->in_use || !p->sealed_len || now < p->next_dht_ms)
			continue;
		benc_buf_init(&vb, value, sizeof(value));
		benc_str_add(&vb, p->sealed, p->sealed_len);
		if (!vb.err)
			bep44_put(s->engine, s->keys.bep44_sk, s->keys.bep44_pk,
				  p->salt, value, vb.len, ++p->seq, NULL, NULL);
		p->next_dht_ms = now + SIG_DHT_PUT_MS;
	}
	for (i = 0; i < SIG_MAX_CHAN; i++) {
		struct sig_sub *sub = &s->sub[i];

		if (!sub->in_use || now < sub->next_get_ms)
			continue;
		bep44_get(s->engine, s->keys.bep44_pk, sub->salt, on_dht_get, sub);
		sub->next_get_ms = now + SIG_DHT_GET_MS;
	}
}

static void mcast_pump(struct sig *s, uint64_t now)
{
	int i;

	for (i = 0; i < SIG_MAX_CHAN; i++) {
		struct sig_pub *p = &s->pub[i];

		if (!p->in_use || !p->sealed_len || now < p->next_mcast_ms)
			continue;
		sig_mcast_send(s->mc, p->salt, p->sealed, p->sealed_len);
		p->next_mcast_ms = now + SIG_MCAST_ANN_MS;
	}
}

void sig_dispatch(struct sig *s, const struct pollfd *fds, int nfds)
{
	uint64_t now = now_ms();

	if (s->mc) {
		sig_mcast_dispatch(s->mc, fds, nfds, on_mcast_recv, s);
		mcast_pump(s, now);
	}

	if ((s->flags & SIG_DHT) && !s->dht_engaged && !s->mcast_delivered &&
	    now - s->start_ms > SIG_DHT_GRACE_MS)
		engage_dht(s);

	if (s->dht_engaged) {
		dhtnode_dispatch(s->node, fds, nfds);
		dht_pump(s, now);
	}
}
