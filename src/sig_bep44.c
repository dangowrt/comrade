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

#define SIG_MAX_CHAN 8
#define SIG_SALT_MAX (BEP44_MAX_SALT + 1)
#define SIG_PUT_INTERVAL_MS 4000
#define SIG_GET_INTERVAL_MS 2000

struct sig_pub {
	int in_use;
	char salt[SIG_SALT_MAX];
	uint8_t value[BEP44_MAX_VALUE];
	size_t value_len;
	int64_t seq;
	uint64_t next_put_ms;
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
	struct dhtnode *node;
	struct bep44_engine *engine;
	struct session_keys keys;
	struct sig_pub pub[SIG_MAX_CHAN];
	struct sig_sub sub[SIG_MAX_CHAN];
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

struct sig *sig_create(const uint8_t rdv[TOKEN_RDV_LEN])
{
	struct sig *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	keys_derive(&s->keys, rdv);
	s->node = dhtnode_create();
	if (!s->node) {
		free(s);
		return NULL;
	}
	s->engine = dhtnode_engine(s->node);
	return s;
}

void sig_destroy(struct sig *s)
{
	if (!s)
		return;
	if (s->node)
		dhtnode_free(s->node);
	free(s);
}

int sig_prepare(struct sig *s, struct pollfd *fds, int maxfds, int *timeout_ms)
{
	int nfds = dhtnode_prepare(s->node, fds, maxfds, timeout_ms);

	if (*timeout_ms > 200)
		*timeout_ms = 200;
	return nfds;
}

int sig_ready(struct sig *s)
{
	return dhtnode_ready(s->node);
}

static struct sig_pub *pub_find(struct sig *s, const char *channel)
{
	int i, free_slot = -1;

	for (i = 0; i < SIG_MAX_CHAN; i++) {
		if (s->pub[i].in_use) {
			if (!strcmp(s->pub[i].salt, channel))
				return &s->pub[i];
		} else if (free_slot < 0) {
			free_slot = i;
		}
	}
	if (free_slot < 0)
		return NULL;
	memset(&s->pub[free_slot], 0, sizeof(s->pub[free_slot]));
	s->pub[free_slot].in_use = 1;
	strncpy(s->pub[free_slot].salt, channel, SIG_SALT_MAX - 1);
	return &s->pub[free_slot];
}

int sig_publish(struct sig *s, const char *channel, const uint8_t *data, size_t len)
{
	struct sig_pub *p;
	uint8_t sealed[SIG_MAX_VALUE + SEAL_OVERHEAD];
	struct benc_buf vb;
	int slen;

	if (len > SIG_MAX_VALUE || strlen(channel) > BEP44_MAX_SALT)
		return -1;
	p = pub_find(s, channel);
	if (!p)
		return -1;

	slen = msg_seal(sealed, sizeof(sealed), s->keys.sig_key, data, len);
	if (slen < 0)
		return -1;
	benc_buf_init(&vb, p->value, sizeof(p->value));
	benc_str_add(&vb, sealed, (size_t)slen);
	if (vb.err)
		return -1;
	p->value_len = vb.len;
	p->next_put_ms = 0;
	return 0;
}

static void on_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq)
{
	struct sig_sub *sub = arg;
	const uint8_t *sealed;
	size_t sealed_len;
	uint8_t plain[SIG_MAX_VALUE];
	int n;

	(void)seq;
	if (!v || benc_str_get(v, v_len, &sealed, &sealed_len))
		return;
	n = msg_open(plain, sizeof(plain), sub->owner->keys.sig_key, sealed, sealed_len);
	if (n < 0)
		return;
	if (sub->have_last && sub->last_len == (size_t)n &&
	    !memcmp(sub->last, plain, (size_t)n))
		return;
	memcpy(sub->last, plain, (size_t)n);
	sub->last_len = (size_t)n;
	sub->have_last = 1;
	sub->cb(sub->arg, plain, (size_t)n);
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

void sig_dispatch(struct sig *s, const struct pollfd *fds, int nfds)
{
	uint64_t now;
	int i;

	dhtnode_dispatch(s->node, fds, nfds);
	if (!dhtnode_ready(s->node))
		return;

	now = now_ms();
	for (i = 0; i < SIG_MAX_CHAN; i++) {
		struct sig_pub *p = &s->pub[i];

		if (!p->in_use || !p->value_len || now < p->next_put_ms)
			continue;
		bep44_put(s->engine, s->keys.bep44_sk, s->keys.bep44_pk, p->salt,
			  p->value, p->value_len, ++p->seq, NULL, NULL);
		p->next_put_ms = now + SIG_PUT_INTERVAL_MS;
	}
	for (i = 0; i < SIG_MAX_CHAN; i++) {
		struct sig_sub *sub = &s->sub[i];

		if (!sub->in_use || now < sub->next_get_ms)
			continue;
		bep44_get(s->engine, s->keys.bep44_pk, sub->salt, on_get, sub);
		sub->next_get_ms = now + SIG_GET_INTERVAL_MS;
	}
}
