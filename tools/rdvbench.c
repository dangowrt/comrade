/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Rendezvous benchmark. Measures the payoff of embedding a DHT node address
 * in the token (the RENDEZVOUS hint) versus a cold DHT join.
 *
 * Phase 1 (host): bootstrap, publish the mailbox, then get it straight back
 * and record whichever node answered first -- a node we now know for certain
 * both holds the value and is fast to reply. That is the address a host would
 * put in the token.
 *
 * Phase 2 (cold client): a fresh node bootstraps from the public routers and
 * times how long until it recovers the value.
 *
 * Phase 3 (rendezvous client): a fresh node with NO bootstrap is handed just
 * that one node and times the same recovery.
 *
 * The nodes run one at a time (jech's dht keeps global state and binds a
 * fixed port), which is fine: the value lives on remote storage nodes
 * throughout, so a later fresh node can still fetch it.
 */

#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include "base64.h"
#include "bencode.h"
#include "bep44.h"
#include "dhtnode.h"
#include "keys.h"
#include "token.h"

static int put_done, put_ok;
static int get_done, get_ok;
static uint8_t want_val[128];
static size_t want_len;
static struct sockaddr_storage fast_node;
static socklen_t fast_node_len;

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void on_put(void *arg, int stored, const struct sockaddr *node,
		   socklen_t node_len)
{
	(void)arg;
	(void)node;
	(void)node_len;
	put_done = 1;
	put_ok = stored;
}

static void on_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq,
		   const struct sockaddr *node, socklen_t node_len)
{
	(void)arg;
	(void)seq;
	get_done = 1;
	if (v && v_len == want_len && !memcmp(v, want_val, v_len)) {
		get_ok = 1;
		if (node && node_len && node_len <= sizeof(fast_node)) {
			memcpy(&fast_node, node, node_len);
			fast_node_len = node_len;
		}
	}
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

static void nodestr(const struct sockaddr *sa, socklen_t len,
		    char *out, size_t outlen)
{
	char host[128], serv[32];

	if (getnameinfo(sa, len, host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV) != 0)
		snprintf(out, outlen, "(unprintable)");
	else if (sa->sa_family == AF_INET6)
		snprintf(out, outlen, "[%s]:%s", host, serv);
	else
		snprintf(out, outlen, "%s:%s", host, serv);
}

/* Patiently recover the value once (warming/reseeding between tries) so the
 * host reliably learns a fast-replying node. Returns 0 and fills fast_node. */
static int learn_fast_node(struct dhtnode *n, const uint8_t pk[32])
{
	uint64_t deadline = now_ms() + 90000;
	int attempt;

	for (attempt = 0; attempt < 30 && !fast_node_len && now_ms() < deadline;
	     attempt++) {
		get_done = 0;
		bep44_get(dhtnode_engine(n), pk, "offer", on_get, NULL);
		while (!get_done && now_ms() < deadline)
			pump(n, now_ms() + 100);
		if (!fast_node_len)
			pump(n, now_ms() + 3000);
	}
	return fast_node_len ? 0 : -1;
}

/* Time from now until the value is recovered on n, or -1 on timeout. */
static long time_to_value(struct dhtnode *n, const uint8_t pk[32], int wait_ready)
{
	uint64_t t0 = now_ms();
	uint64_t deadline = t0 + 60000;
	int attempt;

	if (wait_ready)
		while (!dhtnode_ready(n) && now_ms() < deadline)
			pump(n, now_ms() + 200);

	for (attempt = 0; attempt < 20 && !get_ok && now_ms() < deadline; attempt++) {
		get_done = 0;
		bep44_get(dhtnode_engine(n), pk, "offer", on_get, NULL);
		while (!get_done && now_ms() < deadline)
			pump(n, now_ms() + 100);
		if (!get_ok)
			pump(n, now_ms() + 400);
	}
	if (!get_ok)
		return -1;
	return (long)(now_ms() - t0);
}

int main(int argc, char **argv)
{
	struct dhtnode *n;
	struct session_keys keys;
	uint8_t rdv[TOKEN_RDV_LEN];
	uint8_t vbuf[BEP44_MAX_VALUE];
	uint8_t plain[16];
	uint8_t sealed[16 + SEAL_OVERHEAD];
	struct benc_buf vb;
	char rdvb64[32];
	char nodebuf[160];
	long t_cold, t_seed;
	uint64_t start, deadline;
	int sealed_len;
	size_t vlen;

	if (argc > 1) {
		if (base64url_decode(argv[1], strlen(argv[1]), rdv,
				     sizeof(rdv)) != (int)sizeof(rdv)) {
			fprintf(stderr, "invalid rendezvous secret\n");
			return 2;
		}
	} else if (random_bytes(rdv, sizeof(rdv))) {
		return 2;
	}
	base64url_encode(rdv, sizeof(rdv), rdvb64, sizeof(rdvb64));
	printf("rendezvous secret: %s\n", rdvb64);

	keys_derive(&keys, rdv);

	memcpy(plain, "comrade-rdvbench!!", 16);
	if (random_bytes(plain, 8))
		return 2;
	sealed_len = msg_seal(sealed, sizeof(sealed), keys.sig_key, plain,
			      sizeof(plain));
	if (sealed_len < 0)
		return 2;
	benc_buf_init(&vb, vbuf, sizeof(vbuf));
	benc_str_add(&vb, sealed, (size_t)sealed_len);
	if (vb.err)
		return 2;
	vlen = vb.len;
	want_len = vlen;
	memcpy(want_val, vbuf, vlen);

	/* Phase 1: publish, then learn the fastest node that serves it back. */
	printf("\n[phase 1] host: bootstrap, publish, find the fastest node\n");
	n = dhtnode_create();
	if (!n)
		return 1;
	start = now_ms();
	deadline = start + 60000;
	while (!dhtnode_ready(n) && now_ms() < deadline)
		pump(n, now_ms() + 300);
	if (!dhtnode_ready(n)) {
		fprintf(stderr, "DHT did not bootstrap\n");
		dhtnode_free(n);
		return 1;
	}
	printf("  bootstrapped in %llu ms\n",
	       (unsigned long long)(now_ms() - start));
	pump(n, now_ms() + 3000);
	bep44_put(dhtnode_engine(n), keys.bep44_sk, keys.bep44_pk, "offer",
		  vbuf, vlen, 1, -1, on_put, NULL);
	deadline = now_ms() + 30000;
	while (!put_done && now_ms() < deadline)
		pump(n, now_ms() + 200);
	if (!put_ok) {
		fprintf(stderr, "PUT FAILED\n");
		dhtnode_free(n);
		return 1;
	}
	printf("  published (stored on %d nodes)\n", put_ok);
	pump(n, now_ms() + 3000);
	if (learn_fast_node(n, keys.bep44_pk)) {
		fprintf(stderr, "could not read back a node to use as rendezvous\n");
		dhtnode_free(n);
		return 1;
	}
	nodestr((struct sockaddr *)&fast_node, fast_node_len, nodebuf,
		sizeof(nodebuf));
	printf("  rendezvous node (for the token): %s\n", nodebuf);
	dhtnode_free(n);

	/* Phase 2: cold client. */
	printf("\n[phase 2] cold client: bootstrap then recover the value\n");
	get_ok = 0;
	n = dhtnode_create();
	if (!n)
		return 1;
	t_cold = time_to_value(n, keys.bep44_pk, 1);
	dhtnode_free(n);
	if (t_cold < 0)
		printf("  cold recovery: TIMED OUT (>60s)\n");
	else
		printf("  cold recovery: %ld ms\n", t_cold);

	/* Phase 3: rendezvous client, no bootstrap, just the one node. */
	printf("\n[phase 3] rendezvous client: seed one node, recover the value\n");
	get_ok = 0;
	n = dhtnode_create_seeded();
	if (!n)
		return 1;
	if (dhtnode_pin(n, (struct sockaddr *)&fast_node, fast_node_len)) {
		fprintf(stderr, "pin failed\n");
		dhtnode_free(n);
		return 1;
	}
	t_seed = time_to_value(n, keys.bep44_pk, 0);
	dhtnode_free(n);
	if (t_seed < 0)
		printf("  rendezvous recovery: TIMED OUT (>60s)\n");
	else
		printf("  rendezvous recovery: %ld ms\n", t_seed);

	printf("\n[result] cold=%ldms rendezvous=%ldms\n", t_cold, t_seed);
	if (t_cold > 0 && t_seed >= 0 && t_seed < t_cold)
		printf("  rendezvous saved %ld ms (%.1fx faster)\n",
		       t_cold - t_seed,
		       t_seed ? (double)t_cold / (double)t_seed : 0.0);
	return 0;
}
