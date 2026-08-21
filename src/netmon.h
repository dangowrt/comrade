/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_NETMON_H
#define COMRADE_NETMON_H

#include <stddef.h>
#include <stdint.h>

#define NETMON_MAX_ADDRS 64
#define NETMON_POLL_MS 2000

struct netmon_addr {
	char ifname[16];
	int family;
	uint8_t addr[16];
	uint8_t addrlen;
};

struct netmon {
	uint8_t fp[32];
	int have_fp;
	uint64_t next_check_ms;
};

void netmon_init(struct netmon *m);
int netmon_changed(struct netmon *m, uint64_t now_ms);
/*
 * The decision half of netmon_changed, over a fingerprint the caller already
 * holds: the poll interval is enforced here, so a change seen inside the window
 * is deferred to the next sample rather than lost.
 */
int netmon_changed_fp(struct netmon *m, uint64_t now_ms, const uint8_t fp[32]);

size_t netmon_snapshot(struct netmon_addr *out, size_t max);
void netmon_fingerprint(uint8_t fp[32], struct netmon_addr *addrs, size_t n);

#endif
