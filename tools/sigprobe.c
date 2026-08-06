/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base64.h"
#include "bencode.h"
#include "bep44.h"
#include "dhtnode.h"
#include "keys.h"
#include "token.h"

static int put_done, put_ok;
static int get_done, get_ok;
static uint8_t want_val[64];
static size_t want_len;

static void on_put(void *arg, int stored)
{
	(void)arg;
	put_done = 1;
	put_ok = stored;
	printf("put complete: stored on %d nodes\n", stored);
}

static void on_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq,
		   const struct sockaddr *node, socklen_t node_len)
{
	(void)arg;
	(void)node;
	(void)node_len;
	get_done = 1;
	if (v && v_len == want_len && !memcmp(v, want_val, v_len)) {
		get_ok = 1;
		printf("get complete: recovered %zu bytes, seq %lld (MATCH)\n",
		       v_len, (long long)seq);
	} else if (v) {
		printf("get complete: %zu bytes, seq %lld (MISMATCH)\n",
		       v_len, (long long)seq);
	} else {
		printf("get complete: no value found\n");
	}
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void pump(struct dhtnode *n, uint64_t until_ms)
{
	while (now_ms() < until_ms) {
		struct pollfd fds[2];
		int timeout, nfds;

		nfds = dhtnode_prepare(n, fds, 2, &timeout);
		poll(fds, (nfds_t)nfds, timeout);
		dhtnode_dispatch(n, fds, nfds);
	}
}

int main(int argc, char **argv)
{
	struct dhtnode *n;
	struct bep44_engine *e;
	struct session_keys keys;
	uint8_t rdv[TOKEN_RDV_LEN];
	uint8_t vbuf[BEP44_MAX_VALUE];
	uint8_t plain[16];
	uint8_t sealed[16 + SEAL_OVERHEAD];
	struct benc_buf vb;
	int sealed_len;
	size_t vlen;
	uint64_t start, deadline;
	int mode_get_only = argc > 1 && !strcmp(argv[1], "get");
	const char *rdv_arg = mode_get_only ? (argc > 2 ? argv[2] : NULL)
					    : (argc > 1 ? argv[1] : NULL);

	if (rdv_arg) {
		if (base64url_decode(rdv_arg, strlen(rdv_arg), rdv,
				     sizeof(rdv)) != (int)sizeof(rdv)) {
			fprintf(stderr, "invalid rendezvous secret\n");
			return 2;
		}
	} else if (random_bytes(rdv, sizeof(rdv))) {
		return 2;
	}

	{
		char rdvb64[32];

		base64url_encode(rdv, sizeof(rdv), rdvb64, sizeof(rdvb64));
		printf("rendezvous secret: %s\n", rdvb64);
	}

	keys_derive(&keys, rdv);

	n = dhtnode_create();
	if (!n) {
		fprintf(stderr, "dhtnode_create failed\n");
		return 1;
	}
	e = dhtnode_engine(n);

	printf("bootstrapping DHT...\n");
	start = now_ms();
	deadline = start + 60000;
	while (!dhtnode_ready(n) && now_ms() < deadline)
		pump(n, now_ms() + 500);
	if (!dhtnode_ready(n)) {
		fprintf(stderr, "DHT did not bootstrap within 60s\n");
		dhtnode_free(n);
		return 1;
	}
	printf("DHT ready after %llu ms\n", (unsigned long long)(now_ms() - start));
	printf("warming routing table (3s)...\n");
	pump(n, now_ms() + 3000);

	memcpy(plain, "comrade-sigprobe!!", 16);
	if (random_bytes(plain, 8))
		return 2;
	sealed_len = msg_seal(sealed, sizeof(sealed), keys.sig_key,
			      plain, sizeof(plain));
	if (sealed_len < 0)
		return 2;

	benc_buf_init(&vb, vbuf, sizeof(vbuf));
	benc_str_add(&vb, sealed, (size_t)sealed_len);
	if (vb.err)
		return 2;
	vlen = vb.len;
	want_len = vlen;
	memcpy(want_val, vbuf, vlen);

	if (!mode_get_only) {
		printf("putting sealed value (%zu bencoded bytes)...\n", vlen);
		bep44_put(e, keys.bep44_sk, keys.bep44_pk, "offer",
			  vbuf, vlen, 1, on_put, NULL);
		deadline = now_ms() + 30000;
		while (!put_done && now_ms() < deadline)
			pump(n, now_ms() + 200);
		if (!put_ok) {
			fprintf(stderr, "PUT FAILED: no node accepted the store\n");
			dhtnode_free(n);
			return 1;
		}
		printf("waiting 3s for propagation...\n");
		pump(n, now_ms() + 3000);
	}

	{
		int attempt;

		for (attempt = 1; attempt <= 4 && !get_ok; attempt++) {
			printf("getting value back (attempt %d)...\n", attempt);
			get_done = 0;
			bep44_get(e, keys.bep44_pk, "offer", on_get, NULL);
			deadline = now_ms() + 30000;
			while (!get_done && now_ms() < deadline)
				pump(n, now_ms() + 200);
			if (!get_ok)
				pump(n, now_ms() + 2000);
		}
	}

	dhtnode_free(n);
	if (!get_ok) {
		fprintf(stderr, "ROUND-TRIP FAILED\n");
		return 1;
	}
	printf("ROUND-TRIP OK\n");
	return 0;
}
