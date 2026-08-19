/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wsock.h"

#include "sig_mcast.h"

/*
 * Interface enumeration is the only genuinely platform-specific part: getifaddrs
 * on POSIX, GetAdaptersAddresses on Windows (already linked by netmon.c). Both
 * fill the same table -- per interface, its v6 index, its primary v4 address and
 * which families it carries -- and everything else (socket setup, the
 * address-based v4 join and index-based v6 join, send, receive) is one sock_t /
 * wsock body shared by both. The Windows branch cannot be exercised on Linux; it
 * is validated on the Windows VM (W1-W4). sig_mcast_open returning NULL stays a
 * supported fallback on every OS (sig.c drops SIG_MCAST).
 */

#ifdef _WIN32
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

#define MCAST_PORT 47654
#define MCAST_V4 "224.0.0.224"
#define MCAST_V6 "ff02::da7a"
#define MCAST_MAGIC "pMc1"
#define MCAST_MAGIC_LEN 4
#define MCAST_MAX_IF 16
#define MCAST_MAX_SALT 64
#define MCAST_MAX_PKT 1300
#define DRAIN_MAX_ERRS 16	/* see lanlink.c: bound a drain that keeps erroring */

struct sig_mcast {
	sock_t s4;
	sock_t s6;
	unsigned ifidx[MCAST_MAX_IF];		/* v6 interface index (join/source) */
	struct in_addr ifaddr4[MCAST_MAX_IF];	/* primary v4 address, for the
						 * address-based join / source */
	char ifname[MCAST_MAX_IF][64];		/* Windows only: display name */
	uint8_t ifhas4[MCAST_MAX_IF];	/* interface carries a v4 address */
	uint8_t ifhas6[MCAST_MAX_IF];	/* interface carries a v6 address */
	int nif;
};

#ifdef _WIN32

static void collect_ifaces(struct sig_mcast *m)
{
	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
		      GAA_FLAG_SKIP_DNS_SERVER;
	IP_ADAPTER_ADDRESSES *aa, *a;
	ULONG size = 0;
	int slot;

	if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &size) !=
	    ERROR_BUFFER_OVERFLOW)
		return;
	aa = malloc(size);
	if (!aa)
		return;
	if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, aa, &size) != NO_ERROR) {
		free(aa);
		return;
	}
	for (a = aa; a && m->nif < MCAST_MAX_IF; a = a->Next) {
		IP_ADAPTER_UNICAST_ADDRESS *u;

		/* Loopback kept for same-host linking (see the POSIX branch). */
		if (a->OperStatus != IfOperStatusUp ||
		    (a->Flags & IP_ADAPTER_NO_MULTICAST))
			continue;
		slot = m->nif;
		m->ifhas4[slot] = 0;
		m->ifhas6[slot] = 0;
		m->ifaddr4[slot].s_addr = 0;
		for (u = a->FirstUnicastAddress; u; u = u->Next) {
			SOCKADDR *sa = u->Address.lpSockaddr;

			if (!sa)
				continue;
			if (sa->sa_family == AF_INET && !m->ifhas4[slot]) {
				m->ifhas4[slot] = 1;
				m->ifaddr4[slot] =
					((struct sockaddr_in *)sa)->sin_addr;
			} else if (sa->sa_family == AF_INET6) {
				m->ifhas6[slot] = 1;
			}
		}
		if (!m->ifhas4[slot] && !m->ifhas6[slot])
			continue;
		/* One index per adapter: the v6 index drives the v6 join and the
		 * v6 source select; the v4 path is address-based, not index-based. */
		m->ifidx[slot] = a->Ipv6IfIndex ? a->Ipv6IfIndex : a->IfIndex;
		if (a->FriendlyName)
			WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
					    m->ifname[slot],
					    (int)sizeof(m->ifname[slot]),
					    NULL, NULL);
		m->nif++;
	}
	free(aa);
}

#else /* !_WIN32 */

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
	 * be the unspecified address). The v4 address is kept too: the group
	 * join and IP_MULTICAST_IF select the interface by address (portable to
	 * macOS and Windows), where the Linux-only ip_mreqn selected by index. */
	for (p = ifa; p; p = p->ifa_next) {
		if (!p->ifa_addr)
			continue;
		/* Loopback is kept, not skipped: two comrade instances on one host
		 * must link over multicast however (or whether) the box is connected
		 * externally, and the loopback interface always delivers a multicast
		 * datagram to local joiners even when the only physical interface
		 * cannot send one (a NAT/SLIRP guest, a sandboxed CI host). */
		if (!(p->ifa_flags & IFF_UP) || !(p->ifa_flags & IFF_MULTICAST))
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
		if (fam == AF_INET) {
			m->ifhas4[slot] = 1;
			m->ifaddr4[slot] =
				((struct sockaddr_in *)p->ifa_addr)->sin_addr;
		} else {
			m->ifhas6[slot] = 1;
		}
	}
	freeifaddrs(ifa);
}

#endif /* _WIN32 */

static sock_t open4(struct sig_mcast *m)
{
	struct sockaddr_in a;
	sock_t s = socket(AF_INET, SOCK_DGRAM, 0);
	int on = 1, i, joined = 0;
	unsigned char ttl = 1, loop = 1;

	if (!sock_valid(s))
		return INVALID_SOCK;
	if (sock_udp_disable_connreset(s)) {
		sock_close(s);
		return INVALID_SOCK;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&on, sizeof(on));
#endif
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_port = htons(MCAST_PORT);
	if (bind(s, (struct sockaddr *)&a, sizeof(a))) {
		sock_close(s);
		return INVALID_SOCK;
	}
	setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&ttl,
		   sizeof(ttl));
	setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&loop,
		   sizeof(loop));
	/*
	 * Join on each interface by its own v4 address (struct ip_mreq), which
	 * every OS accepts; the Linux ip_mreqn/imr_ifindex idiom silently no-ops
	 * on macOS. Count the joins that took, and treat a socket that joined
	 * nowhere as v4 being unavailable.
	 */
	for (i = 0; i < m->nif; i++) {
		struct ip_mreq mr;

		if (!m->ifhas4[i])
			continue;
		memset(&mr, 0, sizeof(mr));
		inet_pton(AF_INET, MCAST_V4, &mr.imr_multiaddr);
		mr.imr_interface = m->ifaddr4[i];
		if (!setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				(const char *)&mr, sizeof(mr)))
			joined++;
	}
	if (!joined) {
		sock_close(s);
		return INVALID_SOCK;
	}
	sock_set_nonblock(s);
	return s;
}

static sock_t open6(struct sig_mcast *m)
{
	struct sockaddr_in6 a;
	sock_t s = socket(AF_INET6, SOCK_DGRAM, 0);
	int on = 1, hops = 1, loop = 1, i, joined = 0;

	if (!sock_valid(s))
		return INVALID_SOCK;
	if (sock_udp_disable_connreset(s)) {
		sock_close(s);
		return INVALID_SOCK;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&on, sizeof(on));
#endif
	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&on, sizeof(on));
	memset(&a, 0, sizeof(a));
	a.sin6_family = AF_INET6;
	a.sin6_addr = in6addr_any;
	a.sin6_port = htons(MCAST_PORT);
	if (bind(s, (struct sockaddr *)&a, sizeof(a))) {
		sock_close(s);
		return INVALID_SOCK;
	}
	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&hops,
		   sizeof(hops));
	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&loop,
		   sizeof(loop));
	/* v6 joins by interface index (portable across all three OSes). */
	for (i = 0; i < m->nif; i++) {
		struct ipv6_mreq mr;

		if (!m->ifhas6[i])
			continue;
		memset(&mr, 0, sizeof(mr));
		inet_pton(AF_INET6, MCAST_V6, &mr.ipv6mr_multiaddr);
		mr.ipv6mr_interface = m->ifidx[i];
		if (!setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
				(const char *)&mr, sizeof(mr)))
			joined++;
	}
	if (!joined) {
		sock_close(s);
		return INVALID_SOCK;
	}
	sock_set_nonblock(s);
	return s;
}

struct sig_mcast *sig_mcast_open(void)
{
	struct sig_mcast *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	if (wsock_init()) {
		free(m);
		return NULL;
	}
	m->s4 = INVALID_SOCK;
	m->s6 = INVALID_SOCK;
	collect_ifaces(m);
	if (!m->nif) {
		free(m);
		return NULL;
	}
	m->s4 = open4(m);
	m->s6 = open6(m);
	if (!sock_valid(m->s4) && !sock_valid(m->s6)) {
		free(m);
		return NULL;
	}
	return m;
}

void sig_mcast_close(struct sig_mcast *m)
{
	if (!m)
		return;
	if (sock_valid(m->s4))
		sock_close(m->s4);
	if (sock_valid(m->s6))
		sock_close(m->s6);
	free(m);
}

int sig_mcast_ifaces(struct sig_mcast *m, struct sig_mcast_if *out, int max)
{
	int i, n = 0;

	for (i = 0; i < m->nif && n < max; i++) {
#ifdef _WIN32
		snprintf(out[n].name, sizeof(out[n].name), "%.31s", m->ifname[i]);
#else
		if (!if_indextoname(m->ifidx[i], out[n].name))
			snprintf(out[n].name, sizeof(out[n].name), "if%u",
				 m->ifidx[i]);
#endif
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
		if (sock_valid(m->s4) && m->ifhas4[i]) {
			struct sockaddr_in d;

			setsockopt(m->s4, IPPROTO_IP, IP_MULTICAST_IF,
				   (const char *)&m->ifaddr4[i],
				   sizeof(m->ifaddr4[i]));
			memset(&d, 0, sizeof(d));
			d.sin_family = AF_INET;
			d.sin_port = htons(MCAST_PORT);
			inet_pton(AF_INET, MCAST_V4, &d.sin_addr);
			if (sendto(m->s4, (const char *)buf, (int)n, 0,
				   (struct sockaddr *)&d, sizeof(d)) > 0)
				sent = 1;
		}
		if (sock_valid(m->s6) && m->ifhas6[i]) {
			struct sockaddr_in6 d;
			unsigned idx = m->ifidx[i];

			setsockopt(m->s6, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				   (const char *)&idx, sizeof(idx));
			memset(&d, 0, sizeof(d));
			d.sin6_family = AF_INET6;
			d.sin6_port = htons(MCAST_PORT);
			d.sin6_scope_id = idx;
			inet_pton(AF_INET6, MCAST_V6, &d.sin6_addr);
			if (sendto(m->s6, (const char *)buf, (int)n, 0,
				   (struct sockaddr *)&d, sizeof(d)) > 0)
				sent = 1;
		}
	}
	return sent ? 0 : -1;
}

int sig_mcast_prepare(struct sig_mcast *m, struct pollfd *fds, int maxfds)
{
	int nfds = 0;

	if (sock_valid(m->s4) && nfds < maxfds) {
		fds[nfds].fd = m->s4;
		fds[nfds].events = POLLIN;
		nfds++;
	}
	if (sock_valid(m->s6) && nfds < maxfds) {
		fds[nfds].fd = m->s6;
		fds[nfds].events = POLLIN;
		nfds++;
	}
	return nfds;
}

static void drain(sock_t s, sig_mcast_recv_cb *cb, void *arg)
{
	uint8_t buf[MCAST_MAX_PKT + 1];
	char salt[MCAST_MAX_SALT + 1];
	int errs = 0;

	for (;;) {
		struct sockaddr_storage src;
		socklen_t srclen = sizeof(src);
		int rc = recvfrom(s, (char *)buf, (int)sizeof(buf), 0,
				  (struct sockaddr *)&src, &srclen);
		size_t salt_len, payload;

		if (rc < 0) {
			if (sock_err_would_block(sock_errno()))
				break;
			if (++errs >= DRAIN_MAX_ERRS)
				break;
			continue;
		}
		if (rc <= MCAST_MAGIC_LEN + 1)
			continue;
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
