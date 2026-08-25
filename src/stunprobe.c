/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <pthread.h>
#include <stdio.h>
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

/*
 * The mapped address a validated reply carries for the wire-format family byte
 * `want_fam` (0x01 v4, 0x02 v6): four bytes of `addr` for v4, sixteen for v6.
 * XOR-MAPPED-ADDRESS is preferred and MAPPED-ADDRESS accepted; the v6 mask is
 * the magic cookie followed by the reply's own transaction id, per RFC 5389
 * 15.2, which is why it is read from the packet rather than from the seed.
 */
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
 * Addresses already resolved for a STUN server, kept for the life of the
 * process.
 *
 * Moving does not move the servers, and the resolver is routinely the last
 * thing to answer again after a move -- so a probe run on the new link would
 * otherwise sit through a DNS timeout per name before sending anything, and
 * often send nothing at all because nothing resolved. Having done this once,
 * it can go straight out and be answered in the time one lookup would have
 * taken to fail.
 *
 * Entries are keyed on the name as written, so a list replaced by `comrade
 * stun-update` simply misses and resolves afresh; a server that keeps its name
 * and changes its address is not noticed until the process restarts, which is
 * a fair trade for a probe that asks several servers at once and needs only
 * one of them to answer.
 */
#define STUN_CACHE_MAX 64

struct stun_cache_entry {
	char name[128];
	int family;
	struct sockaddr_storage sa;
	socklen_t len;
};

static struct stun_cache_entry stun_cache[STUN_CACHE_MAX];
static int stun_cache_n;
static pthread_mutex_t stun_cache_lock = PTHREAD_MUTEX_INITIALIZER;

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
	for (i = 0; i < stun_cache_n; i++)
		if (stun_cache[i].family == family &&
		    !strcmp(stun_cache[i].name, name))
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
static int resolve4(const char *server, struct sockaddr_in *out)
{
	struct addrinfo hints, *res;
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	const char *colon = strrchr(server, ':');
	char host[128];
	const char *port = "3478";
	size_t hl = colon ? (size_t)(colon - server) : strlen(server);

	if (cache_get(server, AF_INET, &ss, &sl)) {
		memcpy(out, &ss, sizeof(*out));
		return 0;
	}
	if (hl >= sizeof(host))
		return -1;
	memcpy(host, server, hl);
	host[hl] = '\0';
	if (colon && colon[1])
		port = colon + 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(host, port, &hints, &res) || !res)
		return -1;
	memcpy(out, res->ai_addr, sizeof(*out));
	freeaddrinfo(res);
	memcpy(&ss, out, sizeof(*out));
	cache_put(server, AF_INET, &ss, (socklen_t)sizeof(*out));
	return 0;
}

void stun_probe_run(char *const *servers, int nservers, int total_ms,
		    uint8_t seed[STUN_PROBE_TXID_LEN], volatile int *stop,
		    stun_probe_hit *hit, void *arg)
{
	struct sockaddr_in dst[16];
	int have[16];
	uint64_t t0, next_send = 0;
	sock_t fd;
	int i, n = nservers, nres = 0;

	if (n > 16)
		n = 16;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock_valid(fd))
		return;

	memset(have, 0, sizeof(have));
	t0 = os_mono_ms();
	while (!(stop && *stop) && os_mono_ms() - t0 < (uint64_t)total_ms) {
		struct pollfd pf;
		uint64_t now = os_mono_ms();

		/*
		 * One name per pass, so the first server is asked as soon as it
		 * is known rather than after every other name has been looked
		 * up. getaddrinfo has no timeout and the resolver is often the
		 * last thing to come back after a move, so resolving the whole
		 * list up front let one dead or slow name hold up every server
		 * behind it -- and the answer we want is usually the first one.
		 */
		if (nres < n) {
			have[nres] = resolve4(servers[nres], &dst[nres]) == 0;
			nres++;
			next_send = 0;		/* ask the new one at once */
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
				       (struct sockaddr *)&dst[i],
				       sizeof(dst[i]));
			}
			next_send = now + PROBE_RESEND_MS;
		}

		pf.fd = fd;
		pf.events = POLLIN;
		pf.revents = 0;
		if (sock_poll(&pf, 1, PROBE_TICK_MS) > 0 &&
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
}

/* "host:port" resolved to a target of `family`; 3478 with no or unparsable
 * port. Unlike resolve4, keeps whatever sockaddr length getaddrinfo hands
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
	while (!(stop && *stop) && os_mono_ms() - t0 < (uint64_t)total_ms) {
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
	} else if (memcmp(m->addr, addr, 4) || m->port != port) {
		m->agree = 0;
	}
	m->nsamples++;
}

int stun_mapping_result(const struct stun_mapping *m)
{
	if (m->nsamples < 2)
		return STUN_MAPPING_UNKNOWN;
	return m->agree ? STUN_MAPPING_INDEPENDENT : STUN_MAPPING_DEPENDENT;
}
