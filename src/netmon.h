/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_NETMON_H
#define COMRADE_NETMON_H

#include <stddef.h>
#include <stdint.h>

#include "wsock.h"

#define NETMON_MAX_ADDRS 64
#define NETMON_POLL_MS 2000

/*
 * What moved. The families are tracked apart because they move apart: a v6
 * prefix is renumbered on its own schedule, and DHCPv4 and DHCPv6/RA do not
 * land together. NETMON_CH_IFACE is raised when an interface appears, goes
 * away, or gains or loses a family; netmon_snapshot walks addresses, so one
 * carrying none is invisible here.
 */
#define NETMON_CH_V4	(1u << 0)
#define NETMON_CH_V6	(1u << 1)
#define NETMON_CH_IFACE	(1u << 2)

struct netmon_addr {
	char ifname[16];
	int family;
	uint8_t addr[16];
	uint8_t addrlen;
};

struct netmon {
	uint8_t fp4[32];		/* per family, so one family moving is */
	uint8_t fp6[32];		/* not reported as the other moving too */
	uint8_t fpif[32];		/* the (interface, family) set */
	int have_fp;
	uint64_t next_check_ms;		/* ONE window for all three: a v4 change
					 * that armed its own interval would
					 * swallow a v6 change seen in the same
					 * sample */
	int ev_ok;			/* set once the source opens; else poll */
#ifdef _WIN32
	sock_t ev_rd;
	sock_t ev_wr;
	void *ev_h_addr;
	void *ev_h_iface;
#else
	sock_t ev_fd;
#endif
};

void netmon_init(struct netmon *m);
/* Whether anything moved: for a caller with no per-family state to keep. */
int netmon_changed(struct netmon *m, uint64_t now_ms);
unsigned netmon_changed_fam(struct netmon *m, uint64_t now_ms);
/*
 * The decision half of netmon_changed_fam, over fingerprints the caller
 * already holds: the poll interval is enforced here, so a change seen inside
 * the window is deferred to the next sample rather than lost. All three
 * fingerprints are adopted in the same step, or a family reported once would
 * be reported again on the next sample.
 */
unsigned netmon_changed_fam_fp(struct netmon *m, uint64_t now_ms,
			       const uint8_t fp4[32], const uint8_t fp6[32],
			       const uint8_t fpif[32]);

size_t netmon_snapshot(struct netmon_addr *out, size_t max);
void netmon_fingerprint(uint8_t fp4[32], uint8_t fp6[32], uint8_t fpif[32],
			struct netmon_addr *addrs, size_t n);

/* Best-effort kernel change-notification source: 0 on success, -1 on failure
 * (the caller then keeps polling). prepare/dispatch are no-ops until open. */
int netmon_src_open(struct netmon *m);
void netmon_src_close(struct netmon *m);
int netmon_prepare(struct netmon *m, struct pollfd *fds, int maxfds);
/* Non-blocking drain of the event fd; zeros next_check_ms so the next
 * netmon_changed* samples at once rather than waiting out the poll interval. */
void netmon_drain_event(struct netmon *m);

#endif
