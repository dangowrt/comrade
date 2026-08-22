/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CANDPOLICY_H
#define COMRADE_CANDPOLICY_H

#include <stddef.h>

#include "netmon.h"

struct cand_policy {
	int allow_private_v4;
	int allow_ula;
	int allow_overlay;
	int allow_eui64;
	int allow_linklocal;
};

void cand_policy_default(struct cand_policy *p);

int cand_addr_keep(const char *addr, int family_filter,
		   const struct cand_policy *p, int *family_out);

void cand_sdp_filter(const char *in, int family_filter,
		     const struct cand_policy *p, char *out, size_t outlen);

/*
 * Drop remote host candidates that name one of our own local addresses --
 * a peer cannot be reachable at an address that is ours, so the candidate is
 * worse than useless whatever produced it (an overlapping virtual/NAT subnet,
 * misdirected signalling). srflx/prflx/relay candidates are left alone even
 * on a match: two peers sharing one public address behind the same NAT/CGNAT
 * is ordinary and still worth trying.
 */
void cand_sdp_drop_self(const char *in, const struct netmon_addr *local,
			size_t nlocal, char *out, size_t outlen);

/*
 * Append, in place, a server-reflexive variant for every pool address not
 * already advertised, carrying the description's own reflexive v4 port. A
 * carrier NAT that maps one subscriber across a pool of public addresses
 * picks the member per destination, so the address a STUN server reported is
 * usually not the one the peer's checks must meet: the peer has to aim at
 * every member. `pool` is the set of public v4 addresses the caller has seen
 * this network's NAT translating its sockets to. Variants rank below the
 * observed candidate, addresses already present are not repeated, and a
 * description whose reflexive candidates disagree on the port is left alone
 * -- the mapping is per-destination in the port too, and no variant can be
 * named.
 */
void cand_sdp_fan_v4(char *sdp, size_t cap, const uint8_t (*pool)[4],
		     size_t npool);

#endif
