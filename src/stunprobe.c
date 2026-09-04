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

/* Shared STUN response validation: success type, magic cookie, and our seed
 * in the transaction id (all but its per-server last byte, which numbers
 * whichever server answered). Returns the attribute block's length, or -1
 * if any of that does not hold. */
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

struct stun_cache_entry {
	char name[128];
	int family;
	struct sockaddr_storage sa;
	socklen_t len;
};

static struct stun_cache_entry stun_cache[STUN_CACHE_MAX];
static int stun_cache_n;
static pthread_mutex_t stun_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* Every address held for `name`, in insertion order; how many were written. */
static int cache_get_all(const char *name, int family,
			 struct sockaddr_in *out, int max)
{
	int i, n = 0;

	pthread_mutex_lock(&stun_cache_lock);
	for (i = 0; i < stun_cache_n && n < max; i++) {
		if (stun_cache[i].family != family ||
		    strcmp(stun_cache[i].name, name))
			continue;
		memcpy(&out[n++], &stun_cache[i].sa, sizeof(out[0]));
	}
	pthread_mutex_unlock(&stun_cache_lock);
	return n;
}

static int cache_get(const char *name, int family,
		     struct sockaddr_storage *out, socklen_t *outlen)
{
	int i, hit = 0;

	pthread_mutex_lock(&stun_cache_lock);
	for (i = 0; i < stun_cache_n; i++) {
		if (stun_cache[i].family != family ||
		    strcmp(stun_cache[i].name, name))
			continue;
		memcpy(out, &stun_cache[i].sa, sizeof(*out));
		*outlen = stun_cache[i].len;
		hit = 1;
		break;
	}
	pthread_mutex_unlock(&stun_cache_lock);
	return hit;
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

/* "host:port" resolved to a v4 target; 3478 with no or unparsable port. */

/*
 * Every IPv4 address `server` names, not just the first. A name behind several
 * A records is several destinations, and a NAT that maps per destination may
 * hand out a different public address for each -- so taking one record would
 * hide egress addresses exactly as asking one server would.
 */
#define PROBE_ADDRS_PER_NAME 8

static int resolve4_all(const char *server, struct sockaddr_in *out, int max)
{
	struct addrinfo hints, *res, *ai;
	struct sockaddr_storage ss;
	const char *colon = strrchr(server, ':');
	char host[128];
	const char *port = "3478";
	size_t hl = colon ? (size_t)(colon - server) : strlen(server);
	int n, i;

	n = cache_get_all(server, AF_INET, out, max);
	if (n)
		return n;
	if (hl >= sizeof(host))
		return 0;
	memcpy(host, server, hl);
	host[hl] = '\0';
	if (colon && colon[1])
		port = colon + 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(host, port, &hints, &res) || !res)
		return 0;
	for (ai = res; ai && n < max; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET ||
		    ai->ai_addrlen < (socklen_t)sizeof(out[0]))
			continue;
		for (i = 0; i < n; i++)	/* getaddrinfo may repeat one */
			if (!memcmp(&out[i], ai->ai_addr, sizeof(out[0])))
				break;
		if (i < n)
			continue;
		memcpy(&out[n], ai->ai_addr, sizeof(out[0]));
		memset(&ss, 0, sizeof(ss));
		memcpy(&ss, ai->ai_addr, sizeof(out[0]));
		cache_put(server, AF_INET, &ss, (socklen_t)sizeof(out[0]));
		n++;
	}
	freeaddrinfo(res);
	return n;
}

/* Ask one server, naming it in the transaction id's last byte (which the
 * reply check ignores, so any server's answer still validates). */
static void probe_ask(sock_t fd, uint8_t seed[STUN_PROBE_TXID_LEN], int i,
		      const struct sockaddr_in *dst)
{
	uint8_t req[STUN_PROBE_REQ_LEN];

	seed[STUN_PROBE_TXID_LEN - 1] = (uint8_t)i;
	stun_probe_build(req, seed);
	sendto(fd, (const char *)req, sizeof(req), 0,
	       (const struct sockaddr *)dst, sizeof(*dst));
}

/*
 * Ask every server in the list, all of them in flight at once on one socket.
 * How many public addresses a NAT that maps per destination will show is a
 * property of the carrier, not something a fixed fan-out can be chosen to
 * cover, so there is no fan-out to choose: the answer is as complete as the
 * list.
 */
void stun_probe_run(char *const *servers, int nservers, int total_ms,
		    uint8_t seed[STUN_PROBE_TXID_LEN], volatile int *stop,
		    stun_probe_hit *hit, void *arg)
{
	struct sockaddr_in *dst;
	uint64_t t0, next_send = 0;
	sock_t fd;
	int i, n = nservers, nres = 0, ndst = 0, max;

	if (n <= 0)
		return;
	max = n * PROBE_ADDRS_PER_NAME;
	if (max > 255)			/* the txid byte that names the target */
		max = 255;
	dst = calloc((size_t)max, sizeof(*dst));
	if (!dst)
		return;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock_valid(fd)) {
		free(dst);
		return;
	}

	t0 = os_mono_ms();
	while (!(stop && sb_flag(stop)) &&
	       os_mono_ms() - t0 < (uint64_t)total_ms) {
		struct pollfd pf;
		uint64_t now = os_mono_ms();

		/* One name per pass: getaddrinfo has no timeout, so resolving
		 * the list up front let one slow name hold up every server
		 * behind it. Each address it yields is asked as it arrives,
		 * rather than re-asking every target whenever one resolves. */
		if (nres < n && ndst < max) {
			int got = resolve4_all(servers[nres++], &dst[ndst],
					       max - ndst);

			for (i = 0; i < got; i++)
				probe_ask(fd, seed, ndst + i, &dst[ndst + i]);
			ndst += got;
			now = os_mono_ms();
		}

		if (now >= next_send) {
			for (i = 0; i < ndst; i++)
				probe_ask(fd, seed, i, &dst[i]);
			next_send = now + PROBE_RESEND_MS;
		}

		pf.fd = fd;
		pf.events = POLLIN;
		pf.revents = 0;
		if (sock_poll(&pf, 1, nres < n ? 0 : PROBE_TICK_MS) > 0 &&
		    (pf.revents & POLLIN)) {
			uint8_t buf[512], addr[4];
			uint16_t port;
			int r = recvfrom(fd, (char *)buf, sizeof(buf), 0,
					 NULL, NULL);

			if (r > 0 &&
			    !stun_probe_mapped4(buf, (size_t)r, seed, addr,
						&port))
				hit(arg, addr, port);
		}
	}
	sock_close(fd);
	free(dst);
}

/* "host:port" resolved to a target of `family`; 3478 with no or unparsable
 * port. Unlike resolve4_all, keeps whatever sockaddr length getaddrinfo hands
 * back, since a v6 target is a different size. */
static int resolve_stun(const char *server, int family,
			struct sockaddr_storage *out, socklen_t *outlen)
{
	struct addrinfo hints, *res;
	const char *colon = strrchr(server, ':');
	char host[128];
	const char *port = "3478";
	size_t hl = colon ? (size_t)(colon - server) : strlen(server);

	*outlen = sizeof(*out);
	if (cache_get(server, family, out, outlen))
		return 0;
	if (hl >= sizeof(host))
		return -1;
	memcpy(host, server, hl);
	host[hl] = '\0';
	if (colon && colon[1])
		port = colon + 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(host, port, &hints, &res) || !res)
		return -1;
	memcpy(out, res->ai_addr, (size_t)res->ai_addrlen);
	*outlen = (socklen_t)res->ai_addrlen;
	freeaddrinfo(res);
	cache_put(server, family, out, *outlen);
	return 0;
}

void stun_probe_check(char *const *servers, int nservers, int family,
		      int total_ms, uint8_t seed[STUN_PROBE_TXID_LEN],
		      volatile int *stop, stun_probe_check_hit *hit, void *arg)
{
	struct sockaddr_storage dst[16];
	socklen_t dlen[16];
	int have[16];
	uint64_t t0, next_send = 0;
	sock_t fd;
	int i, n = nservers, nres = 0;
	int want_fam = family == AF_INET6 ? 0x02 : 0x01;

	if (n > 16)
		n = 16;
	fd = socket(family, SOCK_DGRAM, 0);
	if (!sock_valid(fd))
		return;

	memset(have, 0, sizeof(have));
	t0 = os_mono_ms();
	while (!(stop && sb_flag(stop)) &&
	       os_mono_ms() - t0 < (uint64_t)total_ms) {
		struct pollfd pf;
		uint64_t now = os_mono_ms();

		/* One name per pass; see stun_probe_run for why the list is not
		 * resolved up front. */
		if (nres < n) {
			have[nres] = resolve_stun(servers[nres], family,
						  &dst[nres], &dlen[nres]) == 0;
			nres++;
			next_send = 0;
			now = os_mono_ms();
		}

		if (now >= next_send) {
			for (i = 0; i < nres; i++) {
				uint8_t req[STUN_PROBE_REQ_LEN];

				if (!have[i])
					continue;
				seed[STUN_PROBE_TXID_LEN - 1] = (uint8_t)i;
				stun_probe_build(req, seed);
				sendto(fd, (const char *)req, sizeof(req), 0,
				       (struct sockaddr *)&dst[i], dlen[i]);
			}
			next_send = now + PROBE_RESEND_MS;
		}

		pf.fd = fd;
		pf.events = POLLIN;
		pf.revents = 0;
		if (sock_poll(&pf, 1, PROBE_TICK_MS) > 0 &&
		    (pf.revents & POLLIN)) {
			uint8_t buf[512], addr[16];
			uint16_t port;
			int r = recvfrom(fd, (char *)buf, sizeof(buf), 0,
					 NULL, NULL);

			if (r > 0 && !stun_probe_mapped_fam(buf, (size_t)r,
							    seed, want_fam,
							    addr, &port)) {
				hit(arg, addr, port);
				break;
			}
		}
	}
	sock_close(fd);
}

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
