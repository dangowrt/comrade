/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oscompat.h"
#include "stunprobe.h"

#define STUN_MAGIC 0x2112a442u
#define STUN_BINDING_REQ 0x0001
#define STUN_BINDING_OK 0x0101
#define STUN_ATTR_MAPPED 0x0001
#define STUN_ATTR_XOR_MAPPED 0x0020

#define PROBE_RESEND_MS 1000
#define PROBE_TICK_MS 100

void stun_probe_build(uint8_t out[STUN_PROBE_REQ_LEN],
		      const uint8_t txid[STUN_PROBE_TXID_LEN])
{
	out[0] = STUN_BINDING_REQ >> 8;
	out[1] = STUN_BINDING_REQ & 0xff;
	out[2] = 0;
	out[3] = 0;
	out[4] = STUN_MAGIC >> 24;
	out[5] = (STUN_MAGIC >> 16) & 0xff;
	out[6] = (STUN_MAGIC >> 8) & 0xff;
	out[7] = STUN_MAGIC & 0xff;
	memcpy(out + 8, txid, STUN_PROBE_TXID_LEN);
}

/*
 * The caller's wind-up flag, read the way one thread may read what another
 * writes. It is set once and never cleared while a round is in flight, so
 * relaxed is all the ordering this needs -- what the round produced is
 * published by the join that follows, not by this flag. Plain reads of it are
 * a data race all the same, and a race detector is right to say so.
 */
static int sb_flag(volatile int *f)
{
	return __atomic_load_n(f, __ATOMIC_RELAXED);
}

/* Shared STUN response validation: success type, magic cookie, and our seed
 * in the transaction id (all but its per-server last byte, which numbers
 * whichever server answered). Returns the attribute block's length, or -1
 * if any of that does not hold. */
static int stun_reply_ok(const uint8_t *pkt, size_t len,
			 const uint8_t seed[STUN_PROBE_TXID_LEN])
{
	unsigned mlen;

	if (len < 20)
		return -1;
	if (((pkt[0] << 8) | pkt[1]) != STUN_BINDING_OK)
		return -1;
	mlen = (pkt[2] << 8) | pkt[3];
	if (20 + (size_t)mlen > len)
		return -1;
	if (pkt[4] != (STUN_MAGIC >> 24) || pkt[5] != ((STUN_MAGIC >> 16) & 0xff) ||
	    pkt[6] != ((STUN_MAGIC >> 8) & 0xff) || pkt[7] != (STUN_MAGIC & 0xff))
		return -1;
	if (memcmp(pkt + 8, seed, STUN_PROBE_TXID_LEN - 1))
		return -1;
	return (int)mlen;
}

/* The mapped address for wire family `want_fam` (0x01 v4, 0x02 v6). The v6
 * mask is the magic cookie plus the reply's own transaction id (RFC 5389
 * 15.2), hence read from the packet rather than the seed. */
int stun_probe_mapped_fam(const uint8_t *pkt, size_t len,
			  const uint8_t seed[STUN_PROBE_TXID_LEN], int want_fam,
			  uint8_t addr[16], uint16_t *port)
{
	size_t i = 20, alen = want_fam == 0x02 ? 16 : 4;
	int mlen = stun_reply_ok(pkt, len, seed);

	if (mlen < 0)
		return -1;

	while (i + 4 <= 20 + (size_t)mlen) {
		unsigned at = (pkt[i] << 8) | pkt[i + 1];
		unsigned al = (pkt[i + 2] << 8) | pkt[i + 3];
		const uint8_t *v = pkt + i + 4;

		if (i + 4 + al > len)
			return -1;
		if ((at == STUN_ATTR_XOR_MAPPED || at == STUN_ATTR_MAPPED) &&
		    al >= 4 + alen && v[1] == want_fam) {
			if (at == STUN_ATTR_XOR_MAPPED) {
				size_t k;

				*port = (uint16_t)(((v[2] << 8) | v[3]) ^
						   (STUN_MAGIC >> 16));
				addr[0] = v[4] ^ (STUN_MAGIC >> 24);
				addr[1] = v[5] ^ ((STUN_MAGIC >> 16) & 0xff);
				addr[2] = v[6] ^ ((STUN_MAGIC >> 8) & 0xff);
				addr[3] = v[7] ^ (STUN_MAGIC & 0xff);
				for (k = 4; k < alen; k++)
					addr[k] = v[4 + k] ^ pkt[4 + k];
			} else {
				*port = (uint16_t)((v[2] << 8) | v[3]);
				memcpy(addr, v + 4, alen);
			}
			return 0;
		}
		i += 4 + ((al + 3) & ~3u);
	}
	return -1;
}

int stun_probe_mapped4(const uint8_t *pkt, size_t len,
		       const uint8_t seed[STUN_PROBE_TXID_LEN],
		       uint8_t addr[4], uint16_t *port)
{
	uint8_t a[16];

	if (stun_probe_mapped_fam(pkt, len, seed, 0x01, a, port))
		return -1;
	memcpy(addr, a, 4);
	return 0;
}

/*
 * Resolved STUN addresses, kept for the life of the process. Moving does not
 * move the servers, and the resolver is routinely the last thing to answer
 * after a move, so a probe that has run once goes straight out instead of
 * sitting through a DNS timeout per name.
 *
 * Keyed on the name, so a server that changes address is not noticed until
 * restart -- a fair trade for a probe that asks several at once.
 */
#define STUN_CACHE_MAX 256	/* names times the addresses each carries */
#define STUN_WARM_ADDRS 16	/* cache every A record a name carries, not one */
#define STUN_WARM_REFRESH_S (6 * 3600)	/* re-resolve, so a server that moves
					 * does not bite a very long session */
#define STUN_WARM_SETTLE_S 10		/* long enough for a pass to fail: a
					 * resolver with no uplink times out */
#define STUN_WARM_RETRY_S 15		/* first retry while nothing resolved */
#define STUN_WARM_RETRY_MAX_S 300

struct stun_cache_entry {
	char name[128];
	int family;
	struct sockaddr_storage sa;
	socklen_t len;
};

static struct stun_cache_entry stun_cache[STUN_CACHE_MAX];
static int stun_cache_n;
static pthread_mutex_t stun_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Names the resolver has said do not exist, skipped so a dead pool entry is
 * not handed to libjuice to stall the gather on. Held with an expiry rather
 * than for the life of the process: a resolver that answers NXDOMAIN for
 * everything, a captive portal among them, would otherwise write the pool off
 * permanently for a session that merely passed through it.
 */
#define STUN_NEG_MS (10 * 60 * 1000)

struct stun_neg_entry {
	char name[128];
	uint64_t until_ms;
	int family;
};

static struct stun_neg_entry stun_neg[STUN_CACHE_MAX];
static int stun_neg_n;

/* Every address held for `name` of `family`, in insertion order; how many
 * were written. A name carries several records of each family and a NAT that
 * maps per destination answers differently for each, so all of them count. */
static int cache_get_all(const char *name, int family,
			 struct sockaddr_storage *out, socklen_t *outlen,
			 int max)
{
	int i, n = 0;

	pthread_mutex_lock(&stun_cache_lock);
	for (i = 0; i < stun_cache_n && n < max; i++) {
		if (stun_cache[i].family != family ||
		    strcmp(stun_cache[i].name, name))
			continue;
		memcpy(&out[n], &stun_cache[i].sa, sizeof(out[0]));
		outlen[n++] = stun_cache[i].len;
	}
	pthread_mutex_unlock(&stun_cache_lock);
	return n;
}


/* Whether anything at all has resolved: the warm pass judges itself on this. */
static int cache_any(void)
{
	int n;

	pthread_mutex_lock(&stun_cache_lock);
	n = stun_cache_n;
	pthread_mutex_unlock(&stun_cache_lock);
	return n > 0;
}

static void cache_put(const char *name, int family,
		      const struct sockaddr_storage *sa, socklen_t len)
{
	struct stun_cache_entry *e;
	int i;

	if (strlen(name) >= sizeof(e->name))
		return;
	pthread_mutex_lock(&stun_cache_lock);
	/* One row per address, so a name with several keeps them all. */
	for (i = 0; i < stun_cache_n; i++)
		if (stun_cache[i].family == family &&
		    !strcmp(stun_cache[i].name, name) &&
		    stun_cache[i].len == len &&
		    !memcmp(&stun_cache[i].sa, sa, (size_t)len))
			break;
	if (i == stun_cache_n && stun_cache_n < STUN_CACHE_MAX)
		stun_cache_n++;
	if (i < STUN_CACHE_MAX) {
		e = &stun_cache[i];
		strcpy(e->name, name);
		e->family = family;
		memcpy(&e->sa, sa, sizeof(e->sa));
		e->len = len;
	}
	pthread_mutex_unlock(&stun_cache_lock);
}

/* Swap in a freshly resolved set for a name under one lock, so a reader never
 * sees it empty and a failed resolve leaves the last good set in place (the
 * caller calls this only once cnt > 0). */
static void cache_replace(const char *name, const struct sockaddr_storage *sa,
			  const socklen_t *len, const int *fam, int cnt)
{
	struct stun_cache_entry *e;
	int i;

	if (strlen(name) >= sizeof(e->name))
		return;
	pthread_mutex_lock(&stun_cache_lock);
	for (i = 0; i < stun_cache_n; ) {
		if (!strcmp(stun_cache[i].name, name))
			stun_cache[i] = stun_cache[--stun_cache_n];
		else
			i++;
	}
	for (i = 0; i < cnt && stun_cache_n < STUN_CACHE_MAX; i++) {
		e = &stun_cache[stun_cache_n++];
		strcpy(e->name, name);
		e->family = fam[i];
		memcpy(&e->sa, &sa[i], sizeof(e->sa));
		e->len = len[i];
	}
	pthread_mutex_unlock(&stun_cache_lock);
}

static int neg_has(const char *name, int family)
{
	uint64_t now = os_mono_ms();
	int i, hit = 0;

	pthread_mutex_lock(&stun_cache_lock);
	for (i = 0; i < stun_neg_n; i++)
		if (stun_neg[i].family == family &&
		    !strcmp(stun_neg[i].name, name)) {
			hit = now < stun_neg[i].until_ms;
			break;
		}
	pthread_mutex_unlock(&stun_cache_lock);
	return hit;
}

static void neg_put(const char *name, int family)
{
	uint64_t until = os_mono_ms() + STUN_NEG_MS;
	int i;

	if (strlen(name) >= sizeof(stun_neg[0].name))
		return;
	pthread_mutex_lock(&stun_cache_lock);
	for (i = 0; i < stun_neg_n; i++)
		if (stun_neg[i].family == family &&
		    !strcmp(stun_neg[i].name, name))
			break;
	if (i == stun_neg_n && stun_neg_n < STUN_CACHE_MAX) {
		strcpy(stun_neg[stun_neg_n].name, name);
		stun_neg[stun_neg_n++].family = family;
	}
	if (i < stun_neg_n)
		stun_neg[i].until_ms = until;
	pthread_mutex_unlock(&stun_cache_lock);
}

/*
 * Every address of `family` that "host[:port]" names, not just the first, and
 * 3478 where the port is absent or unparsable. A name behind several records
 * is several destinations, and a NAT that maps per destination may hand out a
 * different public address for each, so taking one record would hide egress
 * addresses exactly as asking one server would.
 */
#define PROBE_ADDRS_PER_NAME 8

static int resolve_name(const char *server, int family,
			struct sockaddr_storage *out, socklen_t *outlen,
			int max)
{
	const char *colon = strrchr(server, ':');
	struct addrinfo hints, *res, *ai;
	const char *port = "3478";
	char host[128];
	int n, i, rc;
	size_t hl;

	hl = colon ? (size_t)(colon - server) : strlen(server);
	n = cache_get_all(server, family, out, outlen, max);
	if (n)
		return n;
	if (neg_has(server, family))
		return 0;
	if (hl >= sizeof(host))
		return 0;
	memcpy(host, server, hl);
	host[hl] = '\0';
	if (colon && colon[1])
		port = colon + 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	rc = getaddrinfo(host, port, &hints, &res);
	if (rc || !res) {
		/* A resolver that could not be reached is about the uplink,
		 * not about the name: writing the pool off for that leaves a
		 * roam onto a dead link with no STUN once it recovers. */
		if (rc == EAI_NONAME)
			neg_put(server, family);
		return 0;
	}
	for (ai = res; ai && n < max; ai = ai->ai_next) {
		if (ai->ai_family != family ||
		    (size_t)ai->ai_addrlen > sizeof(out[0]))
			continue;
		for (i = 0; i < n; i++)	/* getaddrinfo may repeat one */
			if (outlen[i] == ai->ai_addrlen &&
			    !memcmp(&out[i], ai->ai_addr, (size_t)outlen[i]))
				break;
		if (i < n)
			continue;
		memset(&out[n], 0, sizeof(out[0]));
		memcpy(&out[n], ai->ai_addr, (size_t)ai->ai_addrlen);
		outlen[n] = (socklen_t)ai->ai_addrlen;
		cache_put(server, family, &out[n], outlen[n]);
		n++;
	}
	freeaddrinfo(res);
	return n;
}

int stun_server_ip4(const char *server, char *out, size_t outn, int allow_net)
{
	const struct sockaddr_in *sin;
	struct sockaddr_storage ss;
	socklen_t len;
	int n;

	n = cache_get_all(server, AF_INET, &ss, &len, 1);
	if (!n && allow_net)
		n = resolve_name(server, AF_INET, &ss, &len, 1);
	if (n < 1)
		return 0;
	sin = (const struct sockaddr_in *)&ss;
	return inet_ntop(AF_INET, &sin->sin_addr, out, (socklen_t)outn) ? 1 : 0;
}

/* Resolve every v4 and v6 address a server carries into the cache, replacing
 * what was there only once the lookup succeeds so a transient failure keeps the
 * last good set. Blocking; runs off the probe threads (stun_warm_one). */
static void warm_resolve(const char *server)
{
	struct sockaddr_storage sa[STUN_WARM_ADDRS];
	const char *colon = strrchr(server, ':');
	struct addrinfo hints, *res, *ai;
	socklen_t len[STUN_WARM_ADDRS];
	const char *port = "3478";
	int fam[STUN_WARM_ADDRS];
	char host[128];
	int cnt = 0;
	size_t hl;

	hl = colon ? (size_t)(colon - server) : strlen(server);
	if (hl >= sizeof(host))
		return;
	memcpy(host, server, hl);
	host[hl] = '\0';
	if (colon && colon[1])
		port = colon + 1;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(host, port, &hints, &res) || !res)
		return;			/* keep the last good set */
	for (ai = res; ai && cnt < STUN_WARM_ADDRS; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if ((size_t)ai->ai_addrlen > sizeof(sa[0]))
			continue;
		memset(&sa[cnt], 0, sizeof(sa[cnt]));
		memcpy(&sa[cnt], ai->ai_addr, (size_t)ai->ai_addrlen);
		len[cnt] = (socklen_t)ai->ai_addrlen;
		fam[cnt] = ai->ai_family;
		cnt++;
	}
	freeaddrinfo(res);
	if (cnt > 0)
		cache_replace(server, sa, len, fam, cnt);
}

struct stun_warm_one {
	char name[128];
};

static void *stun_warm_one(void *arg)
{
	struct stun_warm_one *j = arg;

	warm_resolve(j->name);
	free(j);
	return NULL;
}

struct stun_warm {
	char *const *servers;
	volatile int *stop;
	int n;
};

/* Interruptible; 1 when asked to stop. */
static int warm_sleep(const struct stun_warm *w, int secs)
{
	int slept;

	for (slept = 0; slept < secs; slept++) {
		if (sb_flag(w->stop))
			return 1;
		os_msleep(1000);
	}
	return 0;
}

/* Warm the whole pool at once (a dead name cannot hold up the rest), then
 * re-resolve every STUN_WARM_REFRESH_S so a moved server is picked up.
 *
 * Until something resolves there are no STUN destinations at all, for either
 * family, since this is the only thing that fills the cache the rounds read.
 * An uplink that is down fails every name, so a pass that resolved nothing is
 * retried on a short backoff instead of sitting out the refresh interval. */
static void *stun_warm_loop(void *arg)
{
	struct stun_warm *w = arg;
	struct stun_warm_one *j;
	int i, wait, back = 0;
	pthread_t th;

	for (;;) {
		for (i = 0; i < w->n; i++) {
			if (strlen(w->servers[i]) >= sizeof(j->name))
				continue;
			j = malloc(sizeof(*j));
			if (!j)
				continue;
			strcpy(j->name, w->servers[i]);
			if (pthread_create(&th, NULL, stun_warm_one, j)) {
				free(j);
				continue;
			}
			pthread_detach(th);
		}
		if (warm_sleep(w, STUN_WARM_SETTLE_S))
			break;
		if (cache_any()) {
			back = 0;
			wait = STUN_WARM_REFRESH_S - STUN_WARM_SETTLE_S;
		} else {
			back = back ? back * 2 : STUN_WARM_RETRY_S;
			if (back > STUN_WARM_RETRY_MAX_S)
				back = STUN_WARM_RETRY_MAX_S;
			wait = back;
		}
		if (warm_sleep(w, wait))
			break;
	}
	free(w);
	return NULL;
}

int stun_pool_warm_start(char *const *servers, int nservers, volatile int *stop,
			 pthread_t *th)
{
	struct stun_warm *w;

	if (nservers < 1)
		return -1;
	w = malloc(sizeof(*w));
	if (!w)
		return -1;
	w->servers = servers;
	w->stop = stop;
	w->n = nservers;
	if (pthread_create(th, NULL, stun_warm_loop, w)) {
		free(w);
		return -1;
	}
	return 0;
}

/* Ask one server, naming it in the transaction id's last byte (which the
 * reply check ignores, so any server's answer still validates). */
static void probe_ask(sock_t fd, uint8_t seed[STUN_PROBE_TXID_LEN], int i,
		      const struct sockaddr_storage *dst, socklen_t dlen)
{
	uint8_t req[STUN_PROBE_REQ_LEN];

	seed[STUN_PROBE_TXID_LEN - 1] = (uint8_t)i;
	stun_probe_build(req, seed);
	sendto(fd, (const char *)req, sizeof(req), 0,
	       (const struct sockaddr *)dst, dlen);
}

/*
 * Ask every server in the list, all of them in flight at once on one socket.
 * How many public addresses a NAT that maps per destination will show is a
 * property of the carrier, not something a fixed fan-out can be chosen to
 * cover, so there is no fan-out to choose: the answer is as complete as the
 * list.
 */
void stun_probe_run(int family, char *const *servers, int nservers,
		    int total_ms, uint8_t seed[STUN_PROBE_TXID_LEN],
		    volatile int *stop, stun_probe_hit *hit, void *arg)
{
	int i, n = nservers, nres = 0, ndst = 0, max, got;
	int want_fam = family == AF_INET6 ? 0x02 : 0x01;
	struct sockaddr_storage *dst;
	uint64_t t0, next_send = 0;
	socklen_t *dlen;
	sock_t fd;

	if (n <= 0)
		return;
	max = n * PROBE_ADDRS_PER_NAME;
	if (max > 255)			/* the txid byte that names the target */
		max = 255;
	dst = calloc((size_t)max, sizeof(*dst));
	dlen = calloc((size_t)max, sizeof(*dlen));
	fd = socket(family, SOCK_DGRAM, 0);
	if (!dst || !dlen || !sock_valid(fd)) {
		if (sock_valid(fd))
			sock_close(fd);
		free(dst);
		free(dlen);
		return;
	}

	t0 = os_mono_ms();
	while (!(stop && sb_flag(stop)) &&
	       os_mono_ms() - t0 < (uint64_t)total_ms) {
		struct pollfd pf;
		uint64_t now = os_mono_ms();

		/* Cache only: getaddrinfo has no timeout, so a slow name run
		 * here would hold the round (and probe_running) open past
		 * total_ms, wedging every later round. stun_pool_warm resolves
		 * off this thread; a name not cached yet waits for the next round. */
		if (nres < n && ndst < max) {
			got = cache_get_all(servers[nres++], family, &dst[ndst],
					    &dlen[ndst], max - ndst);

			for (i = 0; i < got; i++)
				probe_ask(fd, seed, ndst + i, &dst[ndst + i],
					  dlen[ndst + i]);
			ndst += got;
			now = os_mono_ms();
		}

		if (now >= next_send) {
			for (i = 0; i < ndst; i++)
				probe_ask(fd, seed, i, &dst[i], dlen[i]);
			next_send = now + PROBE_RESEND_MS;
		}

		pf.fd = fd;
		pf.events = POLLIN;
		pf.revents = 0;
		if (sock_poll(&pf, 1, nres < n ? 0 : PROBE_TICK_MS) > 0 &&
		    (pf.revents & POLLIN)) {
			uint8_t buf[512], addr[16];
			uint16_t port;
			int r = recvfrom(fd, (char *)buf, sizeof(buf), 0,
					 NULL, NULL);

			if (r > 0 &&
			    !stun_probe_mapped_fam(buf, (size_t)r, seed,
						   want_fam, addr, &port))
				hit(arg, family, addr, port);
		}
	}
	sock_close(fd);
	free(dst);
	free(dlen);
}

/* A server's cached target of `family` ("host:port"); cache only, so a slow
 * name never holds the probe round open (see stun_probe_run). stun_pool_warm
 * fills the cache off this thread. */


void stun_mapping_reset(struct stun_mapping *m)
{
	memset(m, 0, sizeof(*m));
}

void stun_mapping_add(struct stun_mapping *m, const uint8_t addr[4],
		      uint16_t port)
{
	if (m->nsamples == 0) {
		memcpy(m->addr, addr, 4);
		m->port = port;
		m->agree = 1;
		m->addr_agree = 1;
		m->port_agree = 1;
	} else {
		/* Tracked apart: which of the two moved is what decides
		 * whether a peer can still be told where to aim. */
		if (memcmp(m->addr, addr, 4))
			m->addr_agree = 0;
		if (m->port != port)
			m->port_agree = 0;
		m->agree = m->addr_agree && m->port_agree;
	}
	m->nsamples++;
}

int stun_mapping_result(const struct stun_mapping *m)
{
	if (m->nsamples < 2)
		return STUN_MAPPING_UNKNOWN;
	return m->agree ? STUN_MAPPING_INDEPENDENT : STUN_MAPPING_DEPENDENT;
}

int stun_mapping_port_stable(const struct stun_mapping *m)
{
	return m->nsamples < 1 || m->port_agree;
}
