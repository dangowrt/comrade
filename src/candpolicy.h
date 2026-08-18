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

#endif
