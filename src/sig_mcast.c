/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wsock.h"

#include "sig_mcast.h"

#ifdef _WIN32

/*
 * Link-local discovery is off on Windows for now.
 *
 * Nothing here is impossible -- Windows has IP_ADD_MEMBERSHIP and
 * IPV6_JOIN_GROUP, and GetAdaptersAddresses supplies the interface list that
 * netmon.c already walks. What it does not have is Linux's `struct ip_mreqn`,
 * whose imr_ifindex is how this module joins and sources per interface: on
 * Winsock the v4 join takes an interface *address*, so every interface's IPv4
 * address has to be collected and threaded through open4()/sig_mcast_send()
 * as well as its index. That is a real change to the module's shape, and it
 * cannot be tested here without a second machine on the segment.
 *
 * Returning NULL is a supported outcome: sig_create() drops SIG_MCAST and
 * engages the DHT immediately (see sig.c), which is the path a client on a
 * different network takes anyway. The cost on Windows is that two peers on one
 * LAN take the DHT/STUN route instead of the direct one.
 */
struct sig_mcast *sig_mcast_open(void)
{
	return NULL;
}

void sig_mcast_close(struct sig_mcast *m)
{
	(void)m;
}

int sig_mcast_ifaces(struct sig_mcast *m, struct sig_mcast_if *out, int max)
{
	(void)m;
	(void)out;
	(void)max;
	return 0;
}

int sig_mcast_send(struct sig_mcast *m, const char *salt,
		   const uint8_t *data, size_t len)
{
	(void)m;
	(void)salt;
	(void)data;
	(void)len;
	return -1;
}

int sig_mcast_prepare(struct sig_mcast *m, struct pollfd *fds, int maxfds)
{
	(void)m;
	(void)fds;
	(void)maxfds;
	return 0;
}

void sig_mcast_dispatch(struct sig_mcast *m, const struct pollfd *fds, int nfds,
			sig_mcast_recv_cb *cb, void *arg)
{
	(void)m;
	(void)fds;
	(void)nfds;
	(void)cb;
	(void)arg;
}

#else /* !_WIN32 */

#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>

#define MCAST_PORT 47654
#define MCAST_V4 "224.0.0.224"
#define MCAST_V6 "ff02::da7a"
#define MCAST_MAGIC "pMc1"
#define MCAST_MAGIC_LEN 4
#define MCAST_MAX_IF 16
#define MCAST_MAX_SALT 64
#define MCAST_MAX_PKT 1300

struct sig_mcast {
	int s4;
	int s6;
	unsigned ifidx[MCAST_MAX_IF];
	uint8_t ifhas4[MCAST_MAX_IF];	/* interface carries a v4 address */
	uint8_t ifhas6[MCAST_MAX_IF];	/* interface carries a v6 address */
	int nif;
};

static void set_nonblock(int s)
{
	int f = fcntl(s, F_GETFL, 0);

	if (f >= 0)
		fcntl(s, F_SETFL, f | O_NONBLOCK);
}

static void collect_ifaces(struct sig_mcast *m)
{
	struct ifaddrs *ifa, *p;
	unsigned idx;
	int i, slot, fam;

	if (getifaddrs(&ifa))
		return;
	/* One getifaddrs entry per interface address, so an interface appears
	 * once per family. Record, per interface, which families it carries, so
	 * a send never goes out a family the interface lacks (its source would
	 * be the unspecified address). */
	for (p = ifa; p; p = p->ifa_next) {
		if (!p->ifa_addr)
			continue;
		if (!(p->ifa_flags & IFF_UP) || !(p->ifa_flags & IFF_MULTICAST) ||
		    (p->ifa_flags & IFF_LOOPBACK))
			continue;
		fam = p->ifa_addr->sa_family;
		if (fam != AF_INET && fam != AF_INET6)
			continue;
		idx = if_nametoindex(p->ifa_name);
		if (!idx)
			continue;
		slot = -1;
		for (i = 0; i < m->nif; i++)
			if (m->ifidx[i] == idx)
				slot = i;
		if (slot < 0) {
			if (m->nif >= MCAST_MAX_IF)
				continue;
			slot = m->nif++;
			m->ifidx[slot] = idx;
		}
		if (fam == AF_INET)
			m->ifhas4[slot] = 1;
		else
			m->ifhas6[slot] = 1;
	}
	freeifaddrs(ifa);
}

static int open4(struct sig_mcast *m)
{
	struct sockaddr_in a;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	int on = 1, i;
	unsigned char ttl = 1, loop = 1;

	if (s < 0)
		return -1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_port = htons(MCAST_PORT);
	if (bind(s, (struct sockaddr *)&a, sizeof(a))) {
		close(s);
		return -1;
	}
	setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	for (i = 0; i < m->nif; i++) {
		struct ip_mreqn mr;

		memset(&mr, 0, sizeof(mr));
		inet_pton(AF_INET, MCAST_V4, &mr.imr_multiaddr);
		mr.imr_ifindex = (int)m->ifidx[i];
		setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr));
	}
	set_nonblock(s);
	return s;
}

static int open6(struct sig_mcast *m)
{
	struct sockaddr_in6 a;
	int s = socket(AF_INET6, SOCK_DGRAM, 0);
	int on = 1, hops = 1, loop = 1, i;

	if (s < 0)
		return -1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
	memset(&a, 0, sizeof(a));
	a.sin6_family = AF_INET6;
	a.sin6_addr = in6addr_any;
	a.sin6_port = htons(MCAST_PORT);
	if (bind(s, (struct sockaddr *)&a, sizeof(a))) {
		close(s);
		return -1;
	}
	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop));
	for (i = 0; i < m->nif; i++) {
		struct ipv6_mreq mr;

		memset(&mr, 0, sizeof(mr));
		inet_pton(AF_INET6, MCAST_V6, &mr.ipv6mr_multiaddr);
		mr.ipv6mr_interface = m->ifidx[i];
		setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr, sizeof(mr));
	}
	set_nonblock(s);
	return s;
}

struct sig_mcast *sig_mcast_open(void)
{
	struct sig_mcast *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	m->s4 = -1;
	m->s6 = -1;
	collect_ifaces(m);
	if (!m->nif) {
		free(m);
		return NULL;
	}
	m->s4 = open4(m);
	m->s6 = open6(m);
	if (m->s4 < 0 && m->s6 < 0) {
		free(m);
		return NULL;
	}
	return m;
}

void sig_mcast_close(struct sig_mcast *m)
{
	if (!m)
		return;
	if (m->s4 >= 0)
		close(m->s4);
	if (m->s6 >= 0)
		close(m->s6);
	free(m);
}

int sig_mcast_ifaces(struct sig_mcast *m, struct sig_mcast_if *out, int max)
{
	int i, n = 0;

	for (i = 0; i < m->nif && n < max; i++) {
		if (!if_indextoname(m->ifidx[i], out[n].name))
			snprintf(out[n].name, sizeof(out[n].name), "if%u",
				 m->ifidx[i]);
		out[n].has4 = m->ifhas4[i];
		out[n].has6 = m->ifhas6[i];
		n++;
	}
	return n;
}

static size_t pkt_build(uint8_t *buf, size_t buflen, const char *salt,
			const uint8_t *data, size_t len)
{
	size_t salt_len = strlen(salt);
	size_t total = MCAST_MAGIC_LEN + 1 + salt_len + len;

	if (salt_len > MCAST_MAX_SALT || total > buflen)
		return 0;
	memcpy(buf, MCAST_MAGIC, MCAST_MAGIC_LEN);
	buf[MCAST_MAGIC_LEN] = (uint8_t)salt_len;
	memcpy(buf + MCAST_MAGIC_LEN + 1, salt, salt_len);
	memcpy(buf + MCAST_MAGIC_LEN + 1 + salt_len, data, len);
	return total;
}

int sig_mcast_send(struct sig_mcast *m, const char *salt,
		   const uint8_t *data, size_t len)
{
	uint8_t buf[MCAST_MAX_PKT];
	size_t n = pkt_build(buf, sizeof(buf), salt, data, len);
	int i, sent = 0;

	if (!n)
		return -1;
	for (i = 0; i < m->nif; i++) {
		if (m->s4 >= 0 && m->ifhas4[i]) {
			struct sockaddr_in d;
			struct ip_mreqn mif;

			memset(&mif, 0, sizeof(mif));
			mif.imr_ifindex = (int)m->ifidx[i];
			setsockopt(m->s4, IPPROTO_IP, IP_MULTICAST_IF, &mif, sizeof(mif));
			memset(&d, 0, sizeof(d));
			d.sin_family = AF_INET;
			d.sin_port = htons(MCAST_PORT);
			inet_pton(AF_INET, MCAST_V4, &d.sin_addr);
			if (sendto(m->s4, buf, n, 0, (struct sockaddr *)&d, sizeof(d)) > 0)
				sent = 1;
		}
		if (m->s6 >= 0 && m->ifhas6[i]) {
			struct sockaddr_in6 d;
			unsigned idx = m->ifidx[i];

			setsockopt(m->s6, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, sizeof(idx));
			memset(&d, 0, sizeof(d));
			d.sin6_family = AF_INET6;
			d.sin6_port = htons(MCAST_PORT);
			d.sin6_scope_id = idx;
			inet_pton(AF_INET6, MCAST_V6, &d.sin6_addr);
			if (sendto(m->s6, buf, n, 0, (struct sockaddr *)&d, sizeof(d)) > 0)
				sent = 1;
		}
	}
	return sent ? 0 : -1;
}

int sig_mcast_prepare(struct sig_mcast *m, struct pollfd *fds, int maxfds)
{
	int nfds = 0;

	if (m->s4 >= 0 && nfds < maxfds) {
		fds[nfds].fd = m->s4;
		fds[nfds].events = POLLIN;
		nfds++;
	}
	if (m->s6 >= 0 && nfds < maxfds) {
		fds[nfds].fd = m->s6;
		fds[nfds].events = POLLIN;
		nfds++;
	}
	return nfds;
}

static void drain(int s, sig_mcast_recv_cb *cb, void *arg)
{
	uint8_t buf[MCAST_MAX_PKT + 1];
	char salt[MCAST_MAX_SALT + 1];

	for (;;) {
		struct sockaddr_storage src;
		socklen_t srclen = sizeof(src);
		ssize_t rc = recvfrom(s, buf, sizeof(buf), 0,
				      (struct sockaddr *)&src, &srclen);
		size_t salt_len, payload;

		if (rc <= MCAST_MAGIC_LEN + 1)
			break;
		if (memcmp(buf, MCAST_MAGIC, MCAST_MAGIC_LEN))
			continue;
		salt_len = buf[MCAST_MAGIC_LEN];
		if (salt_len == 0 || salt_len > MCAST_MAX_SALT ||
		    (size_t)rc < MCAST_MAGIC_LEN + 1 + salt_len)
			continue;
		memcpy(salt, buf + MCAST_MAGIC_LEN + 1, salt_len);
		salt[salt_len] = '\0';
		payload = (size_t)rc - MCAST_MAGIC_LEN - 1 - salt_len;
		cb(arg, salt, buf + MCAST_MAGIC_LEN + 1 + salt_len, payload,
		   (struct sockaddr *)&src, srclen);
	}
}

void sig_mcast_dispatch(struct sig_mcast *m, const struct pollfd *fds, int nfds,
			sig_mcast_recv_cb *cb, void *arg)
{
	int i;

	for (i = 0; i < nfds; i++) {
		if (!(fds[i].revents & POLLIN))
			continue;
		if (fds[i].fd == m->s4 || fds[i].fd == m->s6)
			drain(fds[i].fd, cb, arg);
	}
}

#endif /* _WIN32 */
