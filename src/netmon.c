/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdlib.h>
#include <string.h>

#include "wsock.h"

#ifdef _WIN32
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

#include "ccrypto.h"

#include "netmon.h"

static int addr_cmp(const void *a, const void *b)
{
	const struct netmon_addr *x = a, *y = b;
	int c = strncmp(x->ifname, y->ifname, sizeof(x->ifname));

	if (c)
		return c;
	if (x->family != y->family)
		return x->family - y->family;
	return memcmp(x->addr, y->addr, sizeof(x->addr));
}

#ifdef _WIN32

/*
 * Windows has no getifaddrs; GetAdaptersAddresses walks the same ground and
 * also carries the operational state, so the IFF_UP/IFF_RUNNING test becomes
 * OperStatus == IfOperStatusUp. The buffer is sized by asking once with a
 * generous guess and growing on ERROR_BUFFER_OVERFLOW, as the API expects.
 */
size_t netmon_snapshot(struct netmon_addr *out, size_t max)
{
	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
		      GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
	IP_ADAPTER_ADDRESSES *aa = NULL, *a;
	ULONG size = 16384;
	size_t n = 0;
	int tries;

	for (tries = 0; tries < 4; tries++) {
		ULONG rc;

		aa = malloc(size);
		if (!aa)
			return 0;
		rc = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, aa, &size);
		if (rc == NO_ERROR)
			break;
		free(aa);
		aa = NULL;
		if (rc != ERROR_BUFFER_OVERFLOW)
			return 0;
	}
	if (!aa)
		return 0;

	for (a = aa; a && n < max; a = a->Next) {
		IP_ADAPTER_UNICAST_ADDRESS *u;

		if (a->OperStatus != IfOperStatusUp)
			continue;
		if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			continue;
		for (u = a->FirstUnicastAddress; u && n < max; u = u->Next) {
			struct sockaddr *sa = u->Address.lpSockaddr;
			struct netmon_addr *rec = &out[n];

			if (!sa)
				continue;
			memset(rec, 0, sizeof(*rec));
			/*
			 * The adapter name is the GUID string; it is stable
			 * across a run, which is all the fingerprint needs (it
			 * is never persisted or sent -- see netmon_fingerprint).
			 */
			strncpy(rec->ifname, a->AdapterName,
				sizeof(rec->ifname) - 1);
			rec->family = sa->sa_family;
			if (rec->family == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)sa;

				memcpy(rec->addr, &sin->sin_addr, 4);
				rec->addrlen = 4;
			} else if (rec->family == AF_INET6) {
				struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;

				if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr))
					continue;
				memcpy(rec->addr, &s6->sin6_addr, 16);
				rec->addrlen = 16;
			} else {
				continue;
			}
			n++;
		}
	}
	free(aa);
	return n;
}

#else /* !_WIN32 */

size_t netmon_snapshot(struct netmon_addr *out, size_t max)
{
	struct ifaddrs *ifa, *p;
	size_t n = 0;

	if (getifaddrs(&ifa))
		return 0;

	for (p = ifa; p && n < max; p = p->ifa_next) {
		struct netmon_addr *rec;

		if (!p->ifa_addr)
			continue;
		if (!(p->ifa_flags & IFF_UP) || !(p->ifa_flags & IFF_RUNNING))
			continue;
		if (p->ifa_flags & IFF_LOOPBACK)
			continue;

		rec = &out[n];
		memset(rec, 0, sizeof(*rec));
		strncpy(rec->ifname, p->ifa_name, sizeof(rec->ifname) - 1);
		rec->family = p->ifa_addr->sa_family;

		if (rec->family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;

			memcpy(rec->addr, &sin->sin_addr, 4);
			rec->addrlen = 4;
		} else if (rec->family == AF_INET6) {
			struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)p->ifa_addr;

			if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr))
				continue;
			memcpy(rec->addr, &s6->sin6_addr, 16);
			rec->addrlen = 16;
		} else {
			continue;
		}
		n++;
	}

	freeifaddrs(ifa);
	return n;
}

#endif /* _WIN32 */

/* The fingerprints are process-local roam state, never persisted or sent, so
 * they need not be stable across builds or backends (and with the OpenSSL
 * backend they are truncated BLAKE2b-512, not BLAKE2b-256). Keep it that way:
 * putting one on the wire or on disk would turn the backend choice into an
 * interop break. */
void netmon_fingerprint(uint8_t fp4[32], uint8_t fp6[32], uint8_t fpif[32],
			struct netmon_addr *addrs, size_t n)
{
	struct cc_blake2b c4, c6, cif;
	size_t i;

	qsort(addrs, n, sizeof(*addrs), addr_cmp);
	if (cc_blake2b_init(&c4, 32) || cc_blake2b_init(&c6, 32) ||
	    cc_blake2b_init(&cif, 32)) {
		memset(fp4, 0, 32);
		memset(fp6, 0, 32);
		memset(fpif, 0, 32);
		return;
	}
	for (i = 0; i < n; i++) {
		struct netmon_addr *a = &addrs[i];
		size_t al = a->addrlen > sizeof(a->addr) ?
			    sizeof(a->addr) : a->addrlen;
		struct cc_blake2b *c = a->family == AF_INET6 ? &c6 : &c4;
		uint8_t fb = a->family == AF_INET6 ? 6 : 4;

		cc_blake2b_update(c, (const uint8_t *)a->ifname,
				  sizeof(a->ifname));
		cc_blake2b_update(c, &a->addr[0], al);
		/* One (interface, family) pair each: addr_cmp has already put
		 * an interface's addresses of one family next to each other, so
		 * a repeat is the previous record. */
		if (i && a->family == addrs[i - 1].family &&
		    !strncmp(a->ifname, addrs[i - 1].ifname, sizeof(a->ifname)))
			continue;
		cc_blake2b_update(&cif, (const uint8_t *)a->ifname,
				  sizeof(a->ifname));
		cc_blake2b_update(&cif, &fb, 1);
	}
	cc_blake2b_final(&c4, fp4);
	cc_blake2b_final(&c6, fp6);
	cc_blake2b_final(&cif, fpif);
}

void netmon_init(struct netmon *m)
{
	m->have_fp = 0;
	m->next_check_ms = 0;
}

unsigned netmon_changed_fam_fp(struct netmon *m, uint64_t now_ms,
			       const uint8_t fp4[32], const uint8_t fp6[32],
			       const uint8_t fpif[32])
{
	unsigned ch = 0;

	if (now_ms < m->next_check_ms)
		return 0;
	m->next_check_ms = now_ms + NETMON_POLL_MS;

	if (!m->have_fp) {
		memcpy(m->fp4, fp4, sizeof(m->fp4));
		memcpy(m->fp6, fp6, sizeof(m->fp6));
		memcpy(m->fpif, fpif, sizeof(m->fpif));
		m->have_fp = 1;
		return 0;
	}
	if (memcmp(m->fp4, fp4, sizeof(m->fp4))) {
		memcpy(m->fp4, fp4, sizeof(m->fp4));
		ch |= NETMON_CH_V4;
	}
	if (memcmp(m->fp6, fp6, sizeof(m->fp6))) {
		memcpy(m->fp6, fp6, sizeof(m->fp6));
		ch |= NETMON_CH_V6;
	}
	if (memcmp(m->fpif, fpif, sizeof(m->fpif))) {
		memcpy(m->fpif, fpif, sizeof(m->fpif));
		ch |= NETMON_CH_IFACE;
	}
	return ch;
}

unsigned netmon_changed_fam(struct netmon *m, uint64_t now_ms)
{
	struct netmon_addr addrs[NETMON_MAX_ADDRS];
	uint8_t fp4[32], fp6[32], fpif[32];
	size_t n;

	/* Sample only when the interval is due; netmon_changed_fam_fp makes
	 * the same test before it decides anything. */
	if (now_ms < m->next_check_ms)
		return 0;

	n = netmon_snapshot(addrs, NETMON_MAX_ADDRS);
	netmon_fingerprint(fp4, fp6, fpif, addrs, n);

	return netmon_changed_fam_fp(m, now_ms, fp4, fp6, fpif);
}

int netmon_changed(struct netmon *m, uint64_t now_ms)
{
	return netmon_changed_fam(m, now_ms) != 0;
}
