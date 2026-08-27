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
 * Whether `addr` names one of this machine's own addresses.
 *
 * Used where a peer is taken at its word: an endpoint advertised over the
 * segment is probed on the shared socket with nothing having been seen to
 * arrive from it, so our own address on our own port must be refused --
 * both ends of one session hold the same key, so we would answer ourselves
 * and the path would look alive while carrying nothing. ICE needs no such
 * rule: its checks carry credentials, so a pair aimed at ourselves fails on
 * its own, and two peers that really share a machine have no other way to
 * meet.
 */
int cand_addr_is_local(const char *addr, const struct netmon_addr *local,
		       size_t nlocal);

/* The same question for an address already in the v6-mapped form paths hold;
 * a v4-mapped one is compared against this machine's v4 addresses. */
int cand_ep_is_local(const uint8_t addr[16], const struct netmon_addr *local,
		     size_t nlocal);

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
 * named. `mapping_dependent` lets a caller who already knows the answer
 * (e.g. from a STUN probe that queried several servers) skip the fan
 * proactively, before any candidate is even scanned -- useful with only one
 * srflx candidate gathered so far, when the reactive disagreement check
 * above has nothing yet to compare against.
 */
void cand_sdp_fan_v4(char *sdp, size_t cap, const uint8_t (*pool)[4],
		     size_t npool, int mapping_dependent);

/*
 * Whether a description names an address a peer off this segment could aim at:
 * a server-reflexive candidate, or a host candidate that is globally routable
 * (which is how IPv6 usually arrives -- no srflx is gathered when a global
 * host candidate already exists). A description of private host candidates
 * alone is an offer only to the segment it was gathered on.
 */
int cand_sdp_reaches_off_segment(const char *sdp);

#endif
