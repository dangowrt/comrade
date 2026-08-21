/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "netmon.h"

static struct netmon_addr mk(const char *ifn, int fam, uint8_t seed)
{
	struct netmon_addr a;
	size_t i;

	memset(&a, 0, sizeof(a));
	strncpy(a.ifname, ifn, sizeof(a.ifname) - 1);
	a.family = fam;
	a.addrlen = fam == 2 ? 4 : 16;
	for (i = 0; i < a.addrlen; i++)
		a.addr[i] = (uint8_t)(seed + i);
	return a;
}

static void order_independence(void)
{
	struct netmon_addr a[3], b[3];
	uint8_t fa[32], fb[32];

	a[0] = mk("eth0", 2, 10);
	a[1] = mk("wlan0", 2, 20);
	a[2] = mk("eth0", 10, 30);
	b[0] = a[2];
	b[1] = a[0];
	b[2] = a[1];

	netmon_fingerprint(fa, a, 3);
	netmon_fingerprint(fb, b, 3);
	assert(!memcmp(fa, fb, 32));
}

static void sensitivity(void)
{
	struct netmon_addr a[2], b[2];
	uint8_t fa[32], fb[32];

	a[0] = mk("eth0", 2, 10);
	a[1] = mk("wlan0", 2, 20);
	memcpy(b, a, sizeof(a));
	b[1] = mk("wlan0", 2, 21);

	netmon_fingerprint(fa, a, 2);
	netmon_fingerprint(fb, b, 2);
	assert(memcmp(fa, fb, 32));
}

static void empty_stable(void)
{
	uint8_t fa[32], fb[32];

	netmon_fingerprint(fa, NULL, 0);
	netmon_fingerprint(fb, NULL, 0);
	assert(!memcmp(fa, fb, 32));
}

static void live_snapshot_stable(void)
{
	struct netmon_addr s1[NETMON_MAX_ADDRS], s2[NETMON_MAX_ADDRS];
	uint8_t f1[32], f2[32];
	size_t n1, n2;

	n1 = netmon_snapshot(s1, NETMON_MAX_ADDRS);
	n2 = netmon_snapshot(s2, NETMON_MAX_ADDRS);
	assert(n1 == n2);
	netmon_fingerprint(f1, s1, n1);
	netmon_fingerprint(f2, s2, n2);
	assert(!memcmp(f1, f2, 32));
}

static void changed_gate(void)
{
	struct netmon m;

	netmon_init(&m);
	assert(netmon_changed(&m, 1000) == 0);
	assert(netmon_changed(&m, 1500) == 0);
	assert(netmon_changed(&m, 4000) == 0);
}

/* The sequence the three sig_rebuild sites in session.c depend on, driven from
 * fingerprints rather than the interfaces this machine happens to have. A
 * change seen inside the poll window is deferred to the next sample, never
 * dropped: an SSHC_RECONNECT rejoin lands here right after the link died, and
 * would otherwise keep signalling bound to the network that has gone. */
static void changed_transitions(void)
{
	uint8_t a[32], b[32];
	struct netmon m;
	size_t i;

	for (i = 0; i < 32; i++) {
		a[i] = (uint8_t)(i + 1);
		b[i] = (uint8_t)(200 - i);
	}

	netmon_init(&m);
	assert(netmon_changed_fp(&m, 0, a) == 0);	/* primes; not a roam */
	assert(netmon_changed_fp(&m, 1000, a) == 0);	/* inside the window */
	assert(netmon_changed_fp(&m, 1500, b) == 0);	/* deferred, not lost */
	assert(netmon_changed_fp(&m, 2500, b) == 1);	/* and reported next */
	assert(netmon_changed_fp(&m, 5000, b) == 0);	/* adopted, once only */
	assert(netmon_changed_fp(&m, 8000, a) == 1);	/* moving back is a move */
}

int main(void)
{
	order_independence();
	sensitivity();
	empty_stable();
	live_snapshot_stable();
	changed_gate();
	changed_transitions();
	return 0;
}
