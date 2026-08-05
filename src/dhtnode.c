/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <monocypher.h>

#include "dht.h"
#include "bep44.h"
#include "dhtnode.h"
#include "keys.h"
#include "netmon.h"

#define DHTNODE_SEED_INTERVAL_MS 1000
#define DHTNODE_BOOTSTRAP_INTERVAL_MS 10000
#define DHTNODE_DHT_PORT 0

static const struct {
	const char *host;
	const char *port;
} bootstrap_hosts[] = {
	{ "router.bittorrent.com", "6881" },
	{ "dht.transmissionbt.com", "6881" },
	{ "router.utorrent.com", "6881" },
	{ "dht.libtorrent.org", "25401" },
};

struct dhtnode {
	int s4;
	int s6;
	uint8_t myid[20];
	struct bep44_engine *engine;
	int dht_ready;
	uint64_t next_dht_ms;
	uint64_t next_seed_ms;
	uint64_t next_bootstrap_ms;
	int bootstrap_done;
	struct netmon netmon;
	unsigned netgen;
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static int udp_socket(int af, uint16_t port)
{
	struct sockaddr_storage ss;
	socklen_t sslen;
	int s = socket(af, SOCK_DGRAM, 0);
	int flags;

	if (s < 0)
		return -1;
	flags = fcntl(s, F_GETFL, 0);
	if (flags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0)
		goto fail;

	memset(&ss, 0, sizeof(ss));
	if (af == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		int on = 1;

		setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		sslen = sizeof(*sin6);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;

		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		sslen = sizeof(*sin);
	}
	if (bind(s, (struct sockaddr *)&ss, sslen) < 0)
		goto fail;
	return s;
fail:
	close(s);
	return -1;
}

static void bootstrap_resolve(struct dhtnode *n)
{
	size_t i;

	for (i = 0; i < sizeof(bootstrap_hosts) / sizeof(bootstrap_hosts[0]); i++) {
		struct addrinfo hints, *res, *ai;

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_family = AF_UNSPEC;
		if (getaddrinfo(bootstrap_hosts[i].host, bootstrap_hosts[i].port,
				&hints, &res))
			continue;
		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family == AF_INET && n->s4 >= 0)
				dht_ping_node(ai->ai_addr, ai->ai_addrlen);
			else if (ai->ai_family == AF_INET6 && n->s6 >= 0)
				dht_ping_node(ai->ai_addr, ai->ai_addrlen);
		}
		freeaddrinfo(res);
	}
	n->bootstrap_done = 1;
}

static void dht_event(void *closure, int event, const unsigned char *info_hash,
		      const void *data, size_t data_len)
{
	(void)closure;
	(void)event;
	(void)info_hash;
	(void)data;
	(void)data_len;
}

static void seed_from_dht(struct dhtnode *n)
{
	struct sockaddr_in sin[16];
	struct sockaddr_in6 sin6[16];
	int num = 16, num6 = 16, i;

	dht_get_nodes(sin, &num, sin6, &num6);
	for (i = 0; i < num; i++)
		bep44_seed_add(n->engine, NULL, (struct sockaddr *)&sin[i],
			       sizeof(sin[i]));
	for (i = 0; i < num6; i++)
		bep44_seed_add(n->engine, NULL, (struct sockaddr *)&sin6[i],
			       sizeof(sin6[i]));
}

struct dhtnode *dhtnode_create(void)
{
	struct dhtnode *n = calloc(1, sizeof(*n));

	if (!n)
		return NULL;
	n->s4 = udp_socket(AF_INET, DHTNODE_DHT_PORT);
	n->s6 = udp_socket(AF_INET6, DHTNODE_DHT_PORT);
	if (n->s4 < 0 && n->s6 < 0)
		goto fail;
	if (random_bytes(n->myid, sizeof(n->myid)))
		goto fail;

	if (dht_init(n->s4, n->s6, n->myid, NULL) < 0)
		goto fail;
	n->dht_ready = 1;

	n->engine = bep44_create(n->myid, n->s4, n->s6);
	if (!n->engine)
		goto fail;

	netmon_init(&n->netmon);
	bootstrap_resolve(n);
	n->next_bootstrap_ms = now_ms() + DHTNODE_BOOTSTRAP_INTERVAL_MS;
	n->next_seed_ms = 0;
	return n;
fail:
	dhtnode_free(n);
	return NULL;
}

void dhtnode_free(struct dhtnode *n)
{
	if (!n)
		return;
	if (n->engine)
		bep44_free(n->engine);
	if (n->dht_ready)
		dht_uninit();
	if (n->s4 >= 0)
		close(n->s4);
	if (n->s6 >= 0)
		close(n->s6);
	free(n);
}

struct bep44_engine *dhtnode_engine(struct dhtnode *n)
{
	return n->engine;
}

unsigned dhtnode_netgen(struct dhtnode *n)
{
	return n->netgen;
}

int dhtnode_ready(struct dhtnode *n)
{
	int good = 0, dubious = 0;

	(void)n;
	dht_nodes(AF_INET, &good, &dubious, NULL, NULL);
	if (good < 2) {
		int g6 = 0, d6 = 0;

		dht_nodes(AF_INET6, &g6, &d6, NULL, NULL);
		good += g6;
		dubious += d6;
	}
	return good >= 2;
}

static int is_bep44_reply(const uint8_t *buf, size_t len)
{
	static const char needle[] = "1:t4:pm";
	size_t nlen = sizeof(needle) - 1;
	size_t i;

	if (len < nlen)
		return 0;
	for (i = 0; i + nlen <= len; i++) {
		if (!memcmp(buf + i, needle, nlen))
			return 1;
	}
	return 0;
}

static void packet_route(struct dhtnode *n, uint8_t *buf, size_t len,
			 const struct sockaddr *from, socklen_t fromlen)
{
	time_t tosleep = 0;

	buf[len] = '\0';
	if (is_bep44_reply(buf, len)) {
		bep44_input(n->engine, buf, len);
		return;
	}
	dht_periodic(buf, len, from, fromlen, &tosleep, dht_event, n);
	n->next_dht_ms = now_ms() + (uint64_t)tosleep * 1000;
}

static void netchange(struct dhtnode *n)
{
	n->netgen++;
	n->bootstrap_done = 0;
	n->next_bootstrap_ms = 0;
	n->next_seed_ms = 0;
	n->next_dht_ms = 0;
}

static void housekeep(struct dhtnode *n)
{
	uint64_t now = now_ms();
	int b44_timeout = 1000;

	if (netmon_changed(&n->netmon, now))
		netchange(n);

	if (now >= n->next_dht_ms) {
		time_t tosleep = 0;

		dht_periodic(NULL, 0, NULL, 0, &tosleep, dht_event, n);
		if (tosleep < 1)
			tosleep = 1;
		n->next_dht_ms = now + (uint64_t)tosleep * 1000;
	}
	if (now >= n->next_seed_ms) {
		seed_from_dht(n);
		n->next_seed_ms = now + DHTNODE_SEED_INTERVAL_MS;
	}
	if (!n->bootstrap_done && now >= n->next_bootstrap_ms) {
		bootstrap_resolve(n);
		n->next_bootstrap_ms = now + DHTNODE_BOOTSTRAP_INTERVAL_MS;
	}
	bep44_periodic(n->engine, &b44_timeout);
}

int dhtnode_prepare(struct dhtnode *n, struct pollfd *fds, int maxfds,
		    int *timeout_ms)
{
	uint64_t now = now_ms();
	int nfds = 0;
	int64_t wait;

	if (n->s4 >= 0 && nfds < maxfds) {
		fds[nfds].fd = n->s4;
		fds[nfds].events = POLLIN;
		nfds++;
	}
	if (n->s6 >= 0 && nfds < maxfds) {
		fds[nfds].fd = n->s6;
		fds[nfds].events = POLLIN;
		nfds++;
	}

	wait = (int64_t)(n->next_dht_ms - now);
	if (wait < 0)
		wait = 0;
	if (wait > 200)
		wait = 200;
	*timeout_ms = (int)wait;
	return nfds;
}

void dhtnode_dispatch(struct dhtnode *n, const struct pollfd *fds, int nfds)
{
	uint8_t buf[2048];
	int i;

	for (i = 0; i < nfds; i++) {
		int s = fds[i].fd;

		if (!(fds[i].revents & POLLIN))
			continue;
		if (s != n->s4 && s != n->s6)
			continue;
		for (;;) {
			struct sockaddr_storage from;
			socklen_t fromlen = sizeof(from);
			ssize_t rc = recvfrom(s, buf, sizeof(buf) - 1, 0,
					      (struct sockaddr *)&from, &fromlen);

			if (rc <= 0)
				break;
			packet_route(n, buf, (size_t)rc,
				     (struct sockaddr *)&from, fromlen);
		}
	}
	housekeep(n);
}

int dht_sendto(int sockfd, const void *buf, int len, int flags,
	       const struct sockaddr *to, int tolen)
{
	return (int)sendto(sockfd, buf, (size_t)len, flags, to, (socklen_t)tolen);
}

int dht_blacklisted(const struct sockaddr *sa, int salen)
{
	(void)sa;
	(void)salen;
	return 0;
}

void dht_hash(void *hash_return, int hash_size,
	      const void *v1, int len1,
	      const void *v2, int len2,
	      const void *v3, int len3)
{
	crypto_blake2b_ctx ctx;
	uint8_t out[64];
	size_t want = hash_size > 64 ? 64 : (size_t)hash_size;

	crypto_blake2b_init(&ctx, 64);
	crypto_blake2b_update(&ctx, v1, (size_t)len1);
	crypto_blake2b_update(&ctx, v2, (size_t)len2);
	crypto_blake2b_update(&ctx, v3, (size_t)len3);
	crypto_blake2b_final(&ctx, out);

	memcpy(hash_return, out, want);
	if ((size_t)hash_size > want)
		memset((uint8_t *)hash_return + want, 0, (size_t)hash_size - want);
}

int dht_random_bytes(void *buf, size_t size)
{
	if (random_bytes(buf, size))
		return -1;
	return (int)size;
}
