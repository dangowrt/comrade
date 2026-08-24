/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "netmon.h"

struct fp {
	uint8_t v4[32];
	uint8_t v6[32];
	uint8_t iface[32];
};

static struct netmon_addr mk(const char *ifn, int fam, uint8_t seed)
{
	struct netmon_addr a;
	size_t i;

	memset(&a, 0, sizeof(a));
	strncpy(a.ifname, ifn, sizeof(a.ifname) - 1);
	a.family = fam;
	a.addrlen = fam == AF_INET ? 4 : 16;
	for (i = 0; i < a.addrlen; i++)
		a.addr[i] = (uint8_t)(seed + i);
	return a;
}

static void print(struct fp *f, struct netmon_addr *a, size_t n)
{
	netmon_fingerprint(f->v4, f->v6, f->iface, a, n);
}

static void order_independence(void)
{
	struct netmon_addr a[3], b[3];
	struct fp fa, fb;

	a[0] = mk("eth0", AF_INET, 10);
	a[1] = mk("wlan0", AF_INET, 20);
	a[2] = mk("eth0", AF_INET6, 30);
	b[0] = a[2];
	b[1] = a[0];
	b[2] = a[1];

	print(&fa, a, 3);
	print(&fb, b, 3);
	assert(!memcmp(&fa, &fb, sizeof(fa)));
}

static void sensitivity(void)
{
	struct netmon_addr a[2], b[2];
	struct fp fa, fb;

	a[0] = mk("eth0", AF_INET, 10);
	a[1] = mk("wlan0", AF_INET, 20);
	memcpy(b, a, sizeof(a));
	b[1] = mk("wlan0", AF_INET, 21);

	print(&fa, a, 2);
	print(&fb, b, 2);
	assert(memcmp(fa.v4, fb.v4, 32));
	/* A different address on an interface that still has the same families
	 * is not a change to the interface set. */
	assert(!memcmp(fa.iface, fb.iface, 32));
}

/* The property the families are split for: renumbering one leaves the other's
 * fingerprint alone, so a late DHCPv6/RA cannot present itself as a v4 move. */
static void families_are_independent(void)
{
	struct netmon_addr a[2], b[2];
	struct fp fa, fb;

	a[0] = mk("eth0", AF_INET, 10);
	a[1] = mk("eth0", AF_INET6, 20);
	memcpy(b, a, sizeof(a));
	b[1] = mk("eth0", AF_INET6, 99);	/* a new v6 prefix, v4 untouched */

	print(&fa, a, 2);
	print(&fb, b, 2);
	assert(!memcmp(fa.v4, fb.v4, 32));
	assert(memcmp(fa.v6, fb.v6, 32));
	assert(!memcmp(fa.iface, fb.iface, 32));
}

/* The interface set moves when one appears, and when one gains or loses a
 * family -- both of which change what the dashboard's LINK rows should say. */
static void iface_set_tracks_interfaces(void)
{
	struct netmon_addr a[2], b[3], c[1];
	struct fp fa, fb, fc;

	a[0] = mk("wlan0", AF_INET, 10);
	a[1] = mk("wlan0", AF_INET6, 20);
	memcpy(b, a, sizeof(a));
	b[2] = mk("eth0", AF_INET, 30);		/* a cable went in */
	c[0] = a[0];				/* wlan0 lost its v6 */

	print(&fa, a, 2);
	print(&fb, b, 3);
	print(&fc, c, 1);
	assert(memcmp(fa.iface, fb.iface, 32));
	assert(memcmp(fa.iface, fc.iface, 32));
}

static void empty_stable(void)
{
	struct fp fa, fb;

	print(&fa, NULL, 0);
	print(&fb, NULL, 0);
	assert(!memcmp(&fa, &fb, sizeof(fa)));
}

static void live_snapshot_stable(void)
{
	struct netmon_addr s1[NETMON_MAX_ADDRS], s2[NETMON_MAX_ADDRS];
	struct fp f1, f2;
	size_t n1, n2;

	n1 = netmon_snapshot(s1, NETMON_MAX_ADDRS);
	n2 = netmon_snapshot(s2, NETMON_MAX_ADDRS);
	assert(n1 == n2);
	print(&f1, s1, n1);
	print(&f2, s2, n2);
	assert(!memcmp(&f1, &f2, sizeof(f1)));
}

static void changed_gate(void)
{
	struct netmon m;

	netmon_init(&m);
	assert(netmon_changed(&m, 1000) == 0);
	assert(netmon_changed(&m, 1500) == 0);
	assert(netmon_changed(&m, 4000) == 0);
}

/* The sequence the roam sites in session.c depend on, driven from fingerprints
 * rather than the interfaces this machine happens to have. A change seen
 * inside the poll window is deferred to the next sample, never dropped: an
 * SSHC_RECONNECT rejoin lands here right after the link died, and would
 * otherwise keep signalling bound to the network that has gone. */
static void changed_transitions(void)
{
	uint8_t a[32], b[32], z[32];
	struct netmon m;
	size_t i;

	for (i = 0; i < 32; i++) {
		a[i] = (uint8_t)(i + 1);
		b[i] = (uint8_t)(200 - i);
		z[i] = 0;
	}

	netmon_init(&m);
	/* primes; not a roam */
	assert(netmon_changed_fam_fp(&m, 0, a, a, z) == 0);
	/* inside the window */
	assert(netmon_changed_fam_fp(&m, 1000, a, a, z) == 0);
	/* deferred, not lost */
	assert(netmon_changed_fam_fp(&m, 1500, b, b, z) == 0);
	/* and reported next */
	assert(netmon_changed_fam_fp(&m, 2500, b, b, z) ==
	       (NETMON_CH_V4 | NETMON_CH_V6));
	/* adopted, once only */
	assert(netmon_changed_fam_fp(&m, 5000, b, b, z) == 0);
	/* moving back is a move */
	assert(netmon_changed_fam_fp(&m, 8000, a, a, z) ==
	       (NETMON_CH_V4 | NETMON_CH_V6));
}

/* One family moving is reported as that family alone, and adopting it does not
 * arm the window against the other: both are decided in the same sample. */
static void one_family_at_a_time(void)
{
	uint8_t a[32], b[32], z[32];
	struct netmon m;
	size_t i;

	for (i = 0; i < 32; i++) {
		a[i] = (uint8_t)(i + 1);
		b[i] = (uint8_t)(200 - i);
		z[i] = 0;
	}

	netmon_init(&m);
	assert(netmon_changed_fam_fp(&m, 0, a, a, z) == 0);
	/* DHCPv4 lands first */
	assert(netmon_changed_fam_fp(&m, 2500, b, a, z) == NETMON_CH_V4);
	/* then RA, seconds later: its own event, not a second v4 one */
	assert(netmon_changed_fam_fp(&m, 5000, b, b, z) == NETMON_CH_V6);
	/* a cable, with neither family's addresses moving */
	assert(netmon_changed_fam_fp(&m, 7500, b, b, a) == NETMON_CH_IFACE);
	assert(netmon_changed_fam_fp(&m, 10000, b, b, a) == 0);
	/* netmon_changed keeps its old meaning for callers with no per-family
	 * state to protect */
	assert(netmon_changed_fam_fp(&m, 12500, a, b, a) == NETMON_CH_V4);
}

int main(void)
{
	order_independence();
	sensitivity();
	families_are_independent();
	iface_set_tracks_interfaces();
	empty_stable();
	live_snapshot_stable();
	changed_gate();
	changed_transitions();
	one_family_at_a_time();
	return 0;
}
