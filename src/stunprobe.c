/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
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

int stun_probe_mapped4(const uint8_t *pkt, size_t len,
		       const uint8_t seed[STUN_PROBE_TXID_LEN],
		       uint8_t addr[4], uint16_t *port)
{
	size_t i = 20;
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
		    al >= 8 && v[1] == 0x01) {
			if (at == STUN_ATTR_XOR_MAPPED) {
				*port = (uint16_t)(((v[2] << 8) | v[3]) ^
						   (STUN_MAGIC >> 16));
				addr[0] = v[4] ^ (STUN_MAGIC >> 24);
				addr[1] = v[5] ^ ((STUN_MAGIC >> 16) & 0xff);
				addr[2] = v[6] ^ ((STUN_MAGIC >> 8) & 0xff);
				addr[3] = v[7] ^ (STUN_MAGIC & 0xff);
			} else {
				*port = (uint16_t)((v[2] << 8) | v[3]);
				memcpy(addr, v + 4, 4);
			}
			return 0;
		}
		i += 4 + ((al + 3) & ~3u);
	}
	return -1;
}

/* "host:port" resolved to a v4 target; 3478 with no or unparsable port. */
static int resolve4(const char *server, struct sockaddr_in *out)
{
	struct addrinfo hints, *res;
	const char *colon = strrchr(server, ':');
	char host[128];
	const char *port = "3478";
	size_t hl = colon ? (size_t)(colon - server) : strlen(server);

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
	int i, n = nservers;

	if (n > 16)
		n = 16;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock_valid(fd))
		return;

	memset(have, 0, sizeof(have));
	for (i = 0; i < n; i++) {
		if (stop && *stop)
			break;
		have[i] = resolve4(servers[i], &dst[i]) == 0;
	}

	t0 = os_mono_ms();
	while (!(stop && *stop) && os_mono_ms() - t0 < (uint64_t)total_ms) {
		struct pollfd pf;
		uint64_t now = os_mono_ms();

		if (now >= next_send) {
			for (i = 0; i < n; i++) {
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

/* Whether a validated reply (stun_reply_ok) also carries a mapped-address
 * attribute of the wire-format family byte `want_fam` (0x01 v4, 0x02 v6).
 * The address itself is not decoded: proof needs only that this family's
 * server answered, nothing kept. */
static int stun_reply_has_family(const uint8_t *pkt, size_t len,
				 const uint8_t seed[STUN_PROBE_TXID_LEN],
				 int want_fam)
{
	size_t i = 20;
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
		    al >= 4 && v[1] == want_fam)
			return 0;
		i += 4 + ((al + 3) & ~3u);
	}
	return -1;
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
	return 0;
}

void stun_probe_check(char *const *servers, int nservers, int family,
		      int total_ms, uint8_t seed[STUN_PROBE_TXID_LEN],
		      volatile int *stop, void (*hit)(void *arg), void *arg)
{
	struct sockaddr_storage dst[16];
	socklen_t dlen[16];
	int have[16];
	uint64_t t0, next_send = 0;
	sock_t fd;
	int i, n = nservers;
	int want_fam = family == AF_INET6 ? 0x02 : 0x01;

	if (n > 16)
		n = 16;
	fd = socket(family, SOCK_DGRAM, 0);
	if (!sock_valid(fd))
		return;

	memset(have, 0, sizeof(have));
	for (i = 0; i < n; i++) {
		if (stop && *stop)
			break;
		have[i] = resolve_stun(servers[i], family, &dst[i],
				       &dlen[i]) == 0;
	}

	t0 = os_mono_ms();
	while (!(stop && *stop) && os_mono_ms() - t0 < (uint64_t)total_ms) {
		struct pollfd pf;
		uint64_t now = os_mono_ms();

		if (now >= next_send) {
			for (i = 0; i < n; i++) {
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
			uint8_t buf[512];
			int r = recvfrom(fd, (char *)buf, sizeof(buf), 0,
					 NULL, NULL);

			if (r > 0 && !stun_reply_has_family(buf, (size_t)r,
							    seed, want_fam)) {
				hit(arg);
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
