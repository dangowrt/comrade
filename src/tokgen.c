/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "tokgen.h"

/*
 * (A) Global connectivity for this family: a usable (non-loopback) local
 * address, a default route out, AND the DHT actually acknowledged our
 * publish. Missing any one of the three means we are offline / isolated /
 * airgapped as far as this family is concerned, and the only transport left
 * is link-local multicast.
 */
static int has_global_connectivity(const struct tokgen_facts *f)
{
	return f->has_usable_addr && f->has_default_route && f->dht_acked;
}

enum tok_advert tokgen_decide(const struct tokgen_facts *f)
{
	if (has_global_connectivity(f)) {
		/*
		 * (B1) On the global internet. Advertise a direct ENDPOINT
		 * only if a public port is actually reachable, and only when
		 * that is PROVEN from the outside: a UPnP / NAT-PMP / PCP
		 * mapping reporting success is not enough, because CGNAT
		 * gateways happily report a mapping on an address that is not
		 * reachable, so we require an unsolicited packet from a
		 * stranger to have arrived at the mapped port. Otherwise we
		 * are reachable only through the two-way DHT mailbox, so we
		 * advertise a RENDEZVOUS node and keep our own address out of
		 * the token.
		 */
		if (f->public_port_proven)
			return TOK_ADVERT_ENDPOINT;
		return TOK_ADVERT_RENDEZVOUS;
	}

	/*
	 * No global connectivity: isolated / airgap / LAN-only. The DHT is
	 * unreachable, discovery is purely link-local multicast, and the token
	 * can only carry our own address.
	 *
	 * (B2) Advertise that ENDPOINT if some interface has a usable address;
	 * if there is none at all there is no connectivity of any kind and
	 * token generation must abort for this family.
	 */
	if (f->has_usable_addr)
		return TOK_ADVERT_ENDPOINT;
	return TOK_ADVERT_NONE;
}

int tokgen_decide_host(const struct tokgen_facts *v4,
		       const struct tokgen_facts *v6,
		       struct tokgen_result *out)
{
	/* Each family stands on its own facts. */
	out->v4 = tokgen_decide(v4);
	out->v6 = tokgen_decide(v6);

	/* Abort only when neither family has anything to advertise. A single
	 * advertisable family is enough. */
	if (out->v4 == TOK_ADVERT_NONE && out->v6 == TOK_ADVERT_NONE)
		return -1;
	return 0;
}
