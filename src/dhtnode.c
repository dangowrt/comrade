/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ccrypto.h"

#include "appdir.h"
#include "dht.h"
#include "bep44.h"
#include "dhtnode.h"

/* Bound a drain that keeps erroring; see lanlink.c for why it does not stop. */
#define DRAIN_MAX_ERRS 16
#include "keys.h"
#include "netmon.h"
#include "netroute.h"
#include "oscompat.h"

#define DHTNODE_SEED_INTERVAL_MS 1000
#define DHTNODE_RESOLVE_POLL_MS 200		/* while the resolver thread runs */
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

/*
 * Where to bootstrap from, when it should not be the public mainline DHT:
 * COMRADE_DHT_BOOTSTRAP=host:port[,host:port...] replaces the routers above.
 *
 * This exists for the tests. Driving them through the real DHT made their
 * outcome depend on how busy and how reachable the internet was at that
 * moment, so a run that went red said nothing about the code -- the same tree
 * passed and failed within the hour, and failed on a different test each time.
 * Pointed at a private swarm they answer about comrade instead, which is the
 * only thing a test is for. Whether the real DHT converges is a question for
 * a deliberate run against it, not for every build.
 */
#define BOOTSTRAP_MAX 8

static struct {
	char host[128];
	char port[8];
} bootstrap_env[BOOTSTRAP_MAX];
static int bootstrap_env_n;		/* 0 = use the routers above */

/*
 * PARSED ONCE FOR THE PROCESS, not once per node.
 *
 * Every node creation used to re-run this, starting by setting the count back
 * to zero -- while the resolver thread of a node created earlier was still
 * reading it. A rebuild makes a node beside a live one and every move makes a
 * rebuild, so this was not a corner: a resolver reading the count in that
 * window sees none configured and goes to the public routers instead of the
 * bootstrap it was given, which on a private swarm is the wrong network
 * entirely.
 *
 * The environment cannot change under a running process, so there is nothing
 * to re-read. Parsing once removes the write rather than guarding it.
 */
static void bootstrap_env_parse(void)
{
	const char *e = getenv("COMRADE_DHT_BOOTSTRAP");
	const char *p;

	bootstrap_env_n = 0;
	if (!e || !*e)
		return;
	for (p = e; *p && bootstrap_env_n < BOOTSTRAP_MAX; ) {
		const char *comma = strchr(p, ',');
		size_t len = comma ? (size_t)(comma - p) : strlen(p);
		const char *colon = memchr(p, ':', len);
		size_t hl = colon ? (size_t)(colon - p) : len;

		if (hl && hl < sizeof(bootstrap_env[0].host)) {
			memcpy(bootstrap_env[bootstrap_env_n].host, p, hl);
			bootstrap_env[bootstrap_env_n].host[hl] = '\0';
			snprintf(bootstrap_env[bootstrap_env_n].port,
				 sizeof(bootstrap_env[0].port), "%.*s",
				 colon ? (int)(len - hl - 1) : 4,
				 colon ? colon + 1 : "6881");
			bootstrap_env_n++;
		}
		if (!comma)
			break;
		p = comma + 1;
	}
}

static pthread_once_t bootstrap_env_once = PTHREAD_ONCE_INIT;

static void bootstrap_env_load(void)
{
	pthread_once(&bootstrap_env_once, bootstrap_env_parse);
}

/*
 * The bootstrap routers are resolved on a side thread: getaddrinfo can block
 * for many seconds on a slow uplink, and doing it inline would freeze the whole
 * client (a black screen) before anything is drawn. The thread only resolves;
 * the main loop does the DHT pings, since jech/dht is not thread-safe. The
 * results are held in their own reference-counted allocation, so a node freed
 * while a resolve is still running detaches the thread and drops its reference
 * rather than waiting: getaddrinfo cannot be cancelled, and the loop that frees
 * the node is the one pumping every live connection.
 */
struct resolver {
	pthread_mutex_t lock;
	int refs;
	struct sockaddr_storage addr[16];
	socklen_t len[16];
	int n;
	int ready;
};

struct dhtnode {
	sock_t s4;
	sock_t s6;
	uint8_t myid[20];
	struct bep44_engine *engine;
	int dht_ready;
	uint64_t next_dht_ms;
	uint64_t next_seed_ms;
	uint64_t next_bootstrap_ms;
	uint64_t bootstrap_backoff_ms;	/* 0 until the first round has gone out */
	uint64_t next_cache_ms;		/* next warm-up cache-write check */
	int no_bootstrap;		/* rendezvous-only: never ping the routers */
	pthread_t resolver;
	int resolver_on;
	struct resolver *boot;
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

static sock_t udp_socket(int af, uint16_t port)
{
	struct sockaddr_storage ss;
	socklen_t sslen;
	sock_t s;

	if (wsock_init())
		return INVALID_SOCK;
	s = socket(af, SOCK_DGRAM, 0);
	if (!sock_valid(s))
		return INVALID_SOCK;
	if (sock_udp_disable_connreset(s))
		goto fail;
	if (sock_set_nonblock(s))
		goto fail;

	memset(&ss, 0, sizeof(ss));
	if (af == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		int on = 1;

		setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&on,
			   sizeof(on));
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
	sock_close(s);
	return INVALID_SOCK;
}

static struct resolver *resolver_new(void)
{
	struct resolver *r = calloc(1, sizeof(*r));

	if (!r)
		return NULL;
	if (pthread_mutex_init(&r->lock, NULL)) {
		free(r);
		return NULL;
	}
	r->refs = 1;
	return r;
}

static void resolver_put(struct resolver *r)
{
	int last;

	pthread_mutex_lock(&r->lock);
	last = !--r->refs;
	pthread_mutex_unlock(&r->lock);
	if (!last)
		return;
	pthread_mutex_destroy(&r->lock);
	free(r);
}

/* Side thread: resolve the routers (blocking getaddrinfo) into r->addr. */
static void *resolver_fn(void *arg)
{
	struct resolver *r = arg;
	size_t i;

	for (i = 0; i < (bootstrap_env_n ? (size_t)bootstrap_env_n :
			sizeof(bootstrap_hosts) / sizeof(bootstrap_hosts[0]));
	     i++) {
		const char *host = bootstrap_env_n ? bootstrap_env[i].host :
						     bootstrap_hosts[i].host;
		const char *port = bootstrap_env_n ? bootstrap_env[i].port :
						     bootstrap_hosts[i].port;
		struct addrinfo hints, *res, *ai;

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_family = AF_UNSPEC;
		if (getaddrinfo(host, port, &hints, &res))
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
			pthread_mutex_lock(&r->lock);
			if (r->n < (int)(sizeof(r->addr) / sizeof(r->addr[0]))) {
				memcpy(&r->addr[r->n], ai->ai_addr,
				       ai->ai_addrlen);
				r->len[r->n] = ai->ai_addrlen;
				r->n++;
			}
			pthread_mutex_unlock(&r->lock);
		}
		freeaddrinfo(res);
	}
	pthread_mutex_lock(&r->lock);
	r->ready = 1;
	pthread_mutex_unlock(&r->lock);
	resolver_put(r);
	return NULL;
}

/*
 * Main thread: once the resolver has produced addresses, ping the routers and
 * seed the bep44 engine from them, so its lookups have responsive entry points
 * at once. Runs on the DHT thread, as jech/dht requires. Returns whether a
 * round actually went out: until the resolver thread has finished there is
 * nothing to ping, and a round that never happened must not be counted as one
 * that was ignored.
 */
static int bootstrap_ping(struct dhtnode *n)
{
	struct sockaddr_storage addr[16];
	socklen_t len[16];
	int cnt, i;

	if (!n->boot)
		return 0;
	pthread_mutex_lock(&n->boot->lock);
	if (!n->boot->ready) {
		pthread_mutex_unlock(&n->boot->lock);
		return 0;
	}
	cnt = n->boot->n;
	memcpy(addr, n->boot->addr, sizeof(addr));
	memcpy(len, n->boot->len, sizeof(len));
	pthread_mutex_unlock(&n->boot->lock);

	for (i = 0; i < cnt; i++) {
		int fam = addr[i].ss_family;

		if ((fam == AF_INET && !sock_valid(n->s4)) ||
		    (fam == AF_INET6 && !sock_valid(n->s6)))
			continue;
		dht_ping_node((struct sockaddr *)&addr[i], len[i]);
		bep44_bootstrap_add(n->engine, (struct sockaddr *)&addr[i],
				    len[i]);
	}
	return 1;
}

/* Good nodes this family holds now. Asked per family and never summed: a table
 * that never filled is invisible in a total the other family is carrying. */
static int family_good(int family)
{
	int good = 0, dubious = 0;

	dht_nodes(family, &good, &dubious, NULL, NULL);
	return good;
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
 * leaves something behind), and once when a node is freed for good, which is
 * the freshest good set of the run. A node discarded because it is being
 * replaced writes nothing, so a move onto a new network costs no write and
 * cannot spend the run's teardown write on an early set.
 */
static int cache_flushed;		/* the run's teardown write is done */

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

	if (sock_valid(n->s4))
		loaded += cache_load_family(n, AF_INET);
	if (sock_valid(n->s6))
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
	if (os_rename_replace(tmp, path)) {
		remove(tmp);
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
	if (os_rename_replace(tmp, path)) {
		remove(tmp);
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
	if (sock_valid(n->s4))
		wrote |= cache_write4(sin, num);
	if (sock_valid(n->s6))
		wrote |= cache_write6(sin6, num6);
	return wrote;
}

static struct dhtnode *dhtnode_create_impl(int do_bootstrap)
{
	struct dhtnode *n = calloc(1, sizeof(*n));

	if (!n)
		return NULL;
	/*
	 * A socket for a family only where that family goes somewhere, asked
	 * the same way for both (netroute.h). This is not politeness: jech/dht
	 * runs bucket maintenance for both families and only reaches the
	 * neighbourhood maintenance that GROWS the table when NEITHER had work,
	 * so a family that cannot answer starves the family that can. Its node
	 * addresses keep arriving in the other family's replies, go into
	 * buckets, and are pinged for ever by a host that cannot reach them, so
	 * it never settles and never stops claiming the round.
	 *
	 * Measured both ways round. On a v4-only router the v6 half did it:
	 * neighbourhood maintenance ran once in twenty-three rounds against
	 * nineteen in twenty on a dual-stack host, and three unanswering nodes
	 * were enough. Forcing the same condition here, the v4 neighbourhood
	 * search fell to three rounds in twenty and its table to four good
	 * nodes, against nineteen and eleven once the DHT's own scheduling
	 * stopped letting one family gate the other.
	 *
	 * Which is where the cure belongs, not here. This catches a host with
	 * no route for a family, which is the measured case and the common one.
	 * It cannot catch a route that leads nowhere useful, and no local
	 * observation can: netroute.h has why. So this is a mitigation, and it
	 * is worth having only because it is free -- being wrong costs a family
	 * that would not have worked anyway, and the decision is taken again on
	 * the next network change.
	 */
	n->s4 = net_family_routed(AF_INET) ?
		udp_socket(AF_INET, DHTNODE_DHT_PORT) : INVALID_SOCK;
	n->s6 = net_family_routed(AF_INET6) ?
		udp_socket(AF_INET6, DHTNODE_DHT_PORT) : INVALID_SOCK;
	if (!sock_valid(n->s4) && !sock_valid(n->s6))
		goto fail;
	if (random_bytes(n->myid, sizeof(n->myid)))
		goto fail;

	/*
	 * jech/dht's public API takes plain ints, and its own Windows support
	 * does the same. Windows socket handles are documented as values whose
	 * upper 32 bits are always clear, so the narrowing is safe -- but it is
	 * the one place in comrade where a SOCKET is not carried as sock_t, so
	 * it is spelled out rather than left to an implicit conversion.
	 */
	if (dht_init((int)n->s4, (int)n->s6, n->myid, NULL) < 0)
		goto fail;
	n->dht_ready = 1;

	n->engine = bep44_create(n->myid, n->s4, n->s6);
	if (!n->engine)
		goto fail;
	/* Hold items for other peers and answer their get/put, so this node is
	 * a full participant in BEP 44 storage rather than only a client of it
	 * (and a peer that lands the mailbox here reaches it in one round-trip
	 * instead of a lookup). */
	bep44_serve(n->engine, 1);

	netmon_init(&n->netmon);
	if (do_bootstrap) {
		/* Resolve the routers off-thread so getaddrinfo cannot stall the
		 * client's startup; the main loop pings them once they are ready. */
		bootstrap_env_load();	/* before the thread that reads it */
		n->boot = resolver_new();
		if (n->boot) {
			n->boot->refs++;	/* the thread's own reference */
			if (pthread_create(&n->resolver, NULL, resolver_fn,
					   n->boot))
				n->boot->refs--;
			else
				n->resolver_on = 1;
		}
		/* Cached nodes seed alongside the curated routers, not instead. */
		n->cache_enabled = 1;
		dhtcache_load(n);
		n->next_bootstrap_ms = now_ms();
		n->next_cache_ms = now_ms() + DHTNODE_WARMCHECK_MS;
	} else {
		/* Rendezvous-only: no public routers, the caller injects the
		 * one node it was handed via dhtnode_seed(). */
		n->no_bootstrap = 1;
	}
	n->next_seed_ms = 0;
	return n;
fail:
	dhtnode_discard(n);
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

static void dhtnode_free_impl(struct dhtnode *n, int persist)
{
	if (!n)
		return;
	if (n->resolver_on)
		pthread_detach(n->resolver);
	if (n->boot)
		resolver_put(n->boot);
	if (persist && n->cache_enabled && n->dht_ready && !cache_flushed)
		cache_flushed = dhtcache_save(n);
	if (n->engine)
		bep44_free(n->engine);
	if (n->dht_ready)
		dht_uninit();
	if (sock_valid(n->s4))
		sock_close(n->s4);
	if (sock_valid(n->s6))
		sock_close(n->s6);
	free(n);
}

void dhtnode_free(struct dhtnode *n)
{
	dhtnode_free_impl(n, 1);
}

void dhtnode_discard(struct dhtnode *n)
{
	dhtnode_free_impl(n, 0);
}

struct bep44_engine *dhtnode_engine(struct dhtnode *n)
{
	return n->engine;
}

unsigned dhtnode_netgen(struct dhtnode *n)
{
	return n->netgen;
}

uint16_t dhtnode_port(struct dhtnode *n, int family)
{
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	sock_t s = family == 6 ? n->s6 : n->s4;

	if (!sock_valid(s) || getsockname(s, (struct sockaddr *)&ss, &sl))
		return 0;
	if (ss.ss_family == AF_INET6)
		return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
	return ntohs(((struct sockaddr_in *)&ss)->sin_port);
}

int dhtnode_bootstrap_wanted(int have4, int good4, int have6, int good6)
{
	if (have4 && good4 < DHTNODE_BOOTSTRAP_MIN_GOOD)
		return 1;
	if (have6 && good6 < DHTNODE_BOOTSTRAP_MIN_GOOD)
		return 1;
	return 0;
}

uint64_t dhtnode_bootstrap_backoff(uint64_t prev_ms)
{
	uint64_t next = prev_ms ? prev_ms * 2 : DHTNODE_BOOTSTRAP_FIRST_MS;

	return next > DHTNODE_BOOTSTRAP_MAX_MS ? DHTNODE_BOOTSTRAP_MAX_MS : next;
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

/*
 * jech/dht speaks BEP 5 and nothing else, so the BEP 44 engine gets first
 * refusal on every datagram: it claims its own replies and the get/put queries
 * it serves, and returns everything else here for the BEP 5 engine. A packet is
 * therefore answered by exactly one of them, never both.
 */
static void packet_route(struct dhtnode *n, uint8_t *buf, size_t len,
			 const struct sockaddr *from, socklen_t fromlen)
{
	time_t tosleep = 0;

	buf[len] = '\0';
	if (bep44_input(n->engine, buf, len, from, fromlen))
		return;
	dht_periodic(buf, len, from, fromlen, &tosleep, dht_event, n);
	n->next_dht_ms = now_ms() + (uint64_t)tosleep * 1000;
}

static void netchange(struct dhtnode *n)
{
	n->netgen++;
	/* The routers are worth asking again at the opening cadence: a move is
	 * the one moment a set that answered nothing before plausibly will. */
	n->bootstrap_backoff_ms = 0;
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
	if (!n->no_bootstrap && now >= n->next_bootstrap_ms) {
		if (!dhtnode_bootstrap_wanted(sock_valid(n->s4),
					      family_good(AF_INET),
					      sock_valid(n->s6),
					      family_good(AF_INET6))) {
			/* Every family this node speaks has enough. Look again
			 * on the opening cadence rather than never: a table
			 * that empties under us is the same problem arriving
			 * later, and asking costs no packets. */
			n->bootstrap_backoff_ms = 0;
			n->next_bootstrap_ms = now + DHTNODE_BOOTSTRAP_FIRST_MS;
		} else if (bootstrap_ping(n)) {
			n->bootstrap_backoff_ms =
				dhtnode_bootstrap_backoff(n->bootstrap_backoff_ms);
			n->next_bootstrap_ms = now + n->bootstrap_backoff_ms;
		} else {
			/* The resolver has not finished. That is not a round
			 * that went unanswered, so it must not spend one. */
			n->next_bootstrap_ms = now + DHTNODE_RESOLVE_POLL_MS;
		}
	}
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

	if (sock_valid(n->s4) && nfds < maxfds) {
		fds[nfds].fd = n->s4;
		fds[nfds].events = POLLIN;
		nfds++;
	}
	if (sock_valid(n->s6) && nfds < maxfds) {
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
	int i, errs;

	for (i = 0; i < nfds; i++) {
		sock_t s = fds[i].fd;

		/* WSAPoll raises POLLHUP/POLLERR without POLLIN, so a socket in
		 * that state has to be drained here or the loop spins on it. */
		if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
			continue;
		if (s != n->s4 && s != n->s6)
			continue;
		for (errs = 0; ; ) {
			struct sockaddr_storage from;
			socklen_t fromlen = sizeof(from);
			int rc = recvfrom(s, (char *)buf, (int)sizeof(buf) - 1, 0,
					  (struct sockaddr *)&from, &fromlen);

			if (rc < 0) {
				if (sock_err_would_block(sock_errno()))
					break;
				if (++errs >= DRAIN_MAX_ERRS)
					break;
				continue;
			}
			if (rc == 0)
				continue;
			packet_route(n, buf, (size_t)rc,
				     (struct sockaddr *)&from, fromlen);
		}
	}
	housekeep(n);
}

/* One of the four callbacks jech/dht leaves for the application. Its int
 * sockfd is the narrowed SOCKET from dht_init; see the comment there. */
int dht_sendto(int sockfd, const void *buf, int len, int flags,
	       const struct sockaddr *to, int tolen)
{
	return (int)sendto((sock_t)sockfd, (const char *)buf, len, flags, to,
			   (socklen_t)tolen);
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
