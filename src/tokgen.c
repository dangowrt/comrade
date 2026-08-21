/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "tokgen.h"

/*
 * The tree, in order. Each arm is a fact that settles the family:
 *
 * (A) No usable (non-loopback) address: nothing to advertise, and nothing the
 *     DHT could carry either, so the family is NONE at once.
 * (B) A public port PROVEN open from the outside -- an unsolicited packet from
 *     a stranger arrived at the mapped port, not merely a UPnP / NAT-PMP / PCP
 *     mapping reporting success, which a CGNAT gateway happily does on an
 *     address nothing can reach. Tested before the route, because a prover
 *     proves reach: our own view of the routing table adds nothing to it.
 * (C) The DHT acknowledged our publish, so the family reaches the rendezvous:
 *     hand out the node and keep our own address out of the token.
 * (D) No default route (deliberately isolated), or the DHT attempt has run its
 *     course without an ack (actually isolated): NONE.
 * (E) Otherwise the route is there and the attempt is still running, so
 *     nothing is decided yet.
 */
enum tok_advert tokgen_decide(const struct tokgen_facts *f)
{
	if (!f->has_usable_addr)
		return TOK_ADVERT_NONE;
	if (f->public_port_proven)
		return TOK_ADVERT_ENDPOINT;
	if (f->dht_acked)
		return TOK_ADVERT_RENDEZVOUS;
	if (!f->has_default_route || f->dht_attempt_concluded)
		return TOK_ADVERT_NONE;
	return TOK_ADVERT_PENDING;
}

int tokgen_decide_host(const struct tokgen_facts *v4,
		       const struct tokgen_facts *v6,
		       struct tokgen_result *out)
{
	/* Each family stands on its own facts. */
	out->v4 = tokgen_decide(v4);
	out->v6 = tokgen_decide(v6);

	/* Both families NONE is an ordinary LAN-only host. Only an address on
	 * neither family leaves nothing to host over. */
	if (!v4->has_usable_addr && !v6->has_usable_addr)
		return -1;
	return 0;
}
