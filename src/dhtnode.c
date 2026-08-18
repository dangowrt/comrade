/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "ccrypto.h"

#include "appdir.h"
#include "dht.h"
#include "bep44.h"
#include "dhtnode.h"
#include "keys.h"
#include "netmon.h"

#define DHTNODE_SEED_INTERVAL_MS 1000
#define DHTNODE_BOOTSTRAP_INTERVAL_MS 10000
#define DHTNODE_WARMCHECK_MS 2000		/* poll for the one warm-up cache write */
#define DHTNODE_DHT_PORT 0

/*
 * Only overwrite a family's on-disk node cache once we have a worthwhile set,
 * so a short-lived run cannot clobber a good cache with a handful of nodes.
 * v6 is sparse, so its bar is lower.
 */
#define DHTNODE_SAVE_MIN4 8
#define DHTNODE_SAVE_MIN6 2
#define DHTNODE_CACHE_MAX 64

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
	uint64_t next_cache_ms;		/* next warm-up cache-write check */
	int bootstrap_done;
	/*
	 * The bootstrap routers are resolved on a side thread: getaddrinfo can
	 * block for many seconds on a slow uplink, and doing it inline would freeze
	 * the whole client (a black screen) before anything is drawn. The thread
	 * only resolves; the main loop does the DHT pings, since jech/dht is not
	 * thread-safe.
	 */
	pthread_t resolver;
	int resolver_on;
	pthread_mutex_t boot_lock;
	struct sockaddr_storage boot_addr[16];
	socklen_t boot_len[16];
	int boot_n;
	int boot_ready;
	int cache_enabled;		/* persist/restore good nodes across runs */
	int cache_was_empty;		/* no on-disk cache at start */
	int cache_primed;		/* the one warm-up write has been done */
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

/* Side thread: resolve the routers (blocking getaddrinfo) into boot_addr. */
static void *resolver_fn(void *arg)
{
	struct dhtnode *n = arg;
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
			if (ai->ai_family == AF_INET6) {
				const struct sockaddr_in6 *a6 =
					(const struct sockaddr_in6 *)ai->ai_addr;

				/* A v4-only router's AAAA is a v4-mapped address,
				 * not a real v6 node; it only pollutes the (small)
				 * v6 bootstrap set and slows convergence. */
				if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
					continue;
			} else if (ai->ai_family != AF_INET) {
				continue;
			}
			pthread_mutex_lock(&n->boot_lock);
			if (n->boot_n < (int)(sizeof(n->boot_addr) /
					      sizeof(n->boot_addr[0]))) {
				memcpy(&n->boot_addr[n->boot_n], ai->ai_addr,
				       ai->ai_addrlen);
				n->boot_len[n->boot_n] = ai->ai_addrlen;
				n->boot_n++;
			}
			pthread_mutex_unlock(&n->boot_lock);
		}
		freeaddrinfo(res);
	}
	pthread_mutex_lock(&n->boot_lock);
	n->boot_ready = 1;
	pthread_mutex_unlock(&n->boot_lock);
	return NULL;
}

/*
 * Main thread: once the resolver has produced addresses, ping the routers and
 * seed the bep44 engine from them (so its lookups have responsive entry points
 * at once), then mark bootstrap done. Runs on the DHT thread, as jech/dht
 * requires. No-op until the resolver is finished.
 */
static void bootstrap_ping(struct dhtnode *n)
{
	struct sockaddr_storage addr[16];
	socklen_t len[16];
	int cnt, i;

	pthread_mutex_lock(&n->boot_lock);
	if (!n->boot_ready) {
		pthread_mutex_unlock(&n->boot_lock);
		return;
	}
	cnt = n->boot_n;
	memcpy(addr, n->boot_addr, sizeof(addr));
	memcpy(len, n->boot_len, sizeof(len));
	pthread_mutex_unlock(&n->boot_lock);

	for (i = 0; i < cnt; i++) {
		int fam = addr[i].ss_family;

		if ((fam == AF_INET && n->s4 < 0) ||
		    (fam == AF_INET6 && n->s6 < 0))
			continue;
		dht_ping_node((struct sockaddr *)&addr[i], len[i]);
		bep44_bootstrap_add(n->engine, (struct sockaddr *)&addr[i],
				    len[i]);
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

/*
 * On-disk DHT node cache: good nodes from a previous run, kept per family in
 * separate files next to the STUN list. They seed the table AND the bep44
 * engine on start, IN ADDITION to the curated bootstrap routers -- so warming
 * (especially the sparse v6 side) has a head start, while the always-on routers
 * remain the safety net for a client that has been idle for months and whose
 * cached nodes have all gone. Records are compact: 6 bytes for v4 (address then
 * port, both network order), 18 for v6.
 *
 * To spare flash on OpenWrt devices the cache is written at most twice per run:
 * once after warm-up, but only if it was empty at start (so a first-ever run
 * leaves something behind), and once when the session ends.
 */
static void cache_path(int af, char *out, size_t n)
{
	snprintf(out, n, "%s/dht_nodes_v%d", appdir_data(), af == AF_INET6 ? 6 : 4);
}

/* Load one family's cache; returns how many nodes it seeded. */
static int cache_load_family(struct dhtnode *n, int af)
{
	char path[600];
	uint8_t rec[18];
	size_t rl = af == AF_INET6 ? 18 : 6;
	int loaded = 0;
	FILE *f;

	cache_path(af, path, sizeof(path));
	f = fopen(path, "rb");
	if (!f)
		return 0;
	while (fread(rec, 1, rl, f) == rl) {
		struct sockaddr_storage ss;
		socklen_t sl;

		memset(&ss, 0, sizeof(ss));
		if (af == AF_INET6) {
			struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;

			s6->sin6_family = AF_INET6;
			memcpy(&s6->sin6_addr, rec, 16);
			memcpy(&s6->sin6_port, rec + 16, 2);
			sl = sizeof(*s6);
		} else {
			struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;

			s4->sin_family = AF_INET;
			memcpy(&s4->sin_addr, rec, 4);
			memcpy(&s4->sin_port, rec + 4, 2);
			sl = sizeof(*s4);
		}
		dht_ping_node((struct sockaddr *)&ss, sl);
		bep44_bootstrap_add(n->engine, (struct sockaddr *)&ss, sl);
		loaded++;
	}
	fclose(f);
	return loaded;
}

static void dhtcache_load(struct dhtnode *n)
{
	int loaded = 0;

	if (n->s4 >= 0)
		loaded += cache_load_family(n, AF_INET);
	if (n->s6 >= 0)
		loaded += cache_load_family(n, AF_INET6);
	n->cache_was_empty = loaded == 0;
}

/* Write one family's nodes; returns 1 if a file was written, 0 otherwise. */
static int cache_write4(const struct sockaddr_in *sin, int num)
{
	char path[600], tmp[610];
	FILE *f;
	int i;

	if (num < DHTNODE_SAVE_MIN4)
		return 0;
	cache_path(AF_INET, path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	f = fopen(tmp, "wb");
	if (!f)
		return 0;
	for (i = 0; i < num; i++) {
		fwrite(&sin[i].sin_addr, 1, 4, f);
		fwrite(&sin[i].sin_port, 1, 2, f);
	}
	fclose(f);
	if (rename(tmp, path)) {
		unlink(tmp);
		return 0;
	}
	return 1;
}

static int cache_write6(const struct sockaddr_in6 *sin6, int num)
{
	char path[600], tmp[610];
	FILE *f;
	int i;

	if (num < DHTNODE_SAVE_MIN6)
		return 0;
	cache_path(AF_INET6, path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	f = fopen(tmp, "wb");
	if (!f)
		return 0;
	for (i = 0; i < num; i++) {
		fwrite(&sin6[i].sin6_addr, 1, 16, f);
		fwrite(&sin6[i].sin6_port, 1, 2, f);
	}
	fclose(f);
	if (rename(tmp, path)) {
		unlink(tmp);
		return 0;
	}
	return 1;
}

/* Persist the current good set; returns 1 if anything was written to flash. */
static int dhtcache_save(struct dhtnode *n)
{
	struct sockaddr_in sin[DHTNODE_CACHE_MAX];
	struct sockaddr_in6 sin6[DHTNODE_CACHE_MAX];
	int num = DHTNODE_CACHE_MAX, num6 = DHTNODE_CACHE_MAX;
	int wrote = 0;

	if (!n->cache_enabled)
		return 0;
	dht_get_nodes(sin, &num, sin6, &num6);
	if (n->s4 >= 0)
		wrote |= cache_write4(sin, num);
	if (n->s6 >= 0)
		wrote |= cache_write6(sin6, num6);
	return wrote;
}

static struct dhtnode *dhtnode_create_impl(int do_bootstrap)
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
	if (do_bootstrap) {
		/* Resolve the routers off-thread so getaddrinfo cannot stall the
		 * client's startup; the main loop pings them once they are ready. */
		if (!pthread_mutex_init(&n->boot_lock, NULL) &&
		    !pthread_create(&n->resolver, NULL, resolver_fn, n))
			n->resolver_on = 1;
		else
			pthread_mutex_destroy(&n->boot_lock);
		/* Cached nodes seed alongside the curated routers, not instead. */
		n->cache_enabled = 1;
		dhtcache_load(n);
		n->next_bootstrap_ms = now_ms();
		n->next_cache_ms = now_ms() + DHTNODE_WARMCHECK_MS;
	} else {
		/* Rendezvous-only: no public routers, the caller injects the
		 * one node it was handed via dhtnode_seed(). */
		n->bootstrap_done = 1;
	}
	n->next_seed_ms = 0;
	return n;
fail:
	dhtnode_free(n);
	return NULL;
}

struct dhtnode *dhtnode_create(void)
{
	return dhtnode_create_impl(1);
}

struct dhtnode *dhtnode_create_seeded(void)
{
	return dhtnode_create_impl(0);
}

int dhtnode_seed(struct dhtnode *n, const struct sockaddr *sa, socklen_t len)
{
	return bep44_seed_add(n->engine, NULL, sa, len);
}

int dhtnode_pin(struct dhtnode *n, const struct sockaddr *sa, socklen_t len)
{
	return bep44_pin_add(n->engine, NULL, sa, len);
}

void dhtnode_free(struct dhtnode *n)
{
	if (!n)
		return;
	if (n->resolver_on) {
		pthread_join(n->resolver, NULL);
		pthread_mutex_destroy(&n->boot_lock);
	}
	if (n->cache_enabled && n->dht_ready)
		dhtcache_save(n);	/* flush the freshest good set on the way out */
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
		bep44_input(n->engine, buf, len, from, fromlen);
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
	if (!n->bootstrap_done)
		bootstrap_ping(n);	/* no-op until the resolver thread is ready,
					 * then pings the routers once and is done */
	/*
	 * One warm-up write, and only if we started with no cache: keep probing
	 * until the table is warm enough that a save actually lands (the writers
	 * hold their per-family minimums), then stop. The other write is on
	 * teardown. This bounds flash writes to at most two per run.
	 */
	if (n->cache_enabled && n->cache_was_empty && !n->cache_primed &&
	    now >= n->next_cache_ms) {
		if (dhtnode_ready(n) && dhtcache_save(n))
			n->cache_primed = 1;
		n->next_cache_ms = now + DHTNODE_WARMCHECK_MS;
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
	struct cc_blake2b ctx;
	uint8_t out[64];
	size_t want = hash_size > 64 ? 64 : (size_t)hash_size;

	if (cc_blake2b_init(&ctx, 64)) {
		memset(hash_return, 0, (size_t)hash_size);
		return;
	}
	cc_blake2b_update(&ctx, v1, (size_t)len1);
	cc_blake2b_update(&ctx, v2, (size_t)len2);
	cc_blake2b_update(&ctx, v3, (size_t)len3);
	cc_blake2b_final(&ctx, out);

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
