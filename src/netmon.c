#include <ifaddrs.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <monocypher.h>

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

void netmon_fingerprint(uint8_t fp[32], struct netmon_addr *addrs, size_t n)
{
	crypto_blake2b_ctx ctx;
	size_t i;

	qsort(addrs, n, sizeof(*addrs), addr_cmp);
	crypto_blake2b_init(&ctx, 32);
	for (i = 0; i < n; i++) {
		crypto_blake2b_update(&ctx, (const uint8_t *)addrs[i].ifname,
				      sizeof(addrs[i].ifname));
		crypto_blake2b_update(&ctx, &addrs[i].addr[0], addrs[i].addrlen);
	}
	crypto_blake2b_final(&ctx, fp);
}

void netmon_init(struct netmon *m)
{
	m->have_fp = 0;
	m->next_check_ms = 0;
}

int netmon_changed(struct netmon *m, uint64_t now_ms)
{
	struct netmon_addr addrs[NETMON_MAX_ADDRS];
	uint8_t fp[32];
	size_t n;

	if (now_ms < m->next_check_ms)
		return 0;
	m->next_check_ms = now_ms + NETMON_POLL_MS;

	n = netmon_snapshot(addrs, NETMON_MAX_ADDRS);
	netmon_fingerprint(fp, addrs, n);

	if (!m->have_fp) {
		memcpy(m->fp, fp, sizeof(fp));
		m->have_fp = 1;
		return 0;
	}
	if (!memcmp(m->fp, fp, sizeof(fp)))
		return 0;
	memcpy(m->fp, fp, sizeof(fp));
	return 1;
}
