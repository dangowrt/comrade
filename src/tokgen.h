/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_TOKGEN_H
#define COMRADE_TOKGEN_H

/*
 * What a host advertises in a token, decided independently for each address
 * family (v4 and v6). The choice is security-sensitive and must be readable
 * straight off the decision tree in tokgen_decide(), so it is a PURE function
 * of already-observed facts: all the runtime probing (address and route
 * enumeration, waiting for a DHT ack, proving a port open from the outside)
 * is done by the caller and handed in as plain facts. This keeps the tree
 * auditable and exhaustively testable in isolation.
 *
 * The result maps onto the token like this:
 *   TOK_ADVERT_ENDPOINT   -> put our own address in the family's endpoint
 *                            slot, TOKEN_FLAG_EPx_RDV clear.
 *   TOK_ADVERT_RENDEZVOUS -> put a DHT node address in the slot, EPx_RDV set.
 *   TOK_ADVERT_NONE       -> leave the family's slot empty; if BOTH families
 *                            are NONE the host has no connectivity and token
 *                            generation aborts.
 */

enum tok_advert {
	TOK_ADVERT_ENDPOINT,
	TOK_ADVERT_RENDEZVOUS,
	TOK_ADVERT_NONE,
};

/*
 * Per-family facts, each an observation the caller has already made. A
 * "usable address" is any assigned address that is not loopback: outside
 * 127.0.0.0/8 for v4, and not ::1 (nor other loopback) for v6.
 */
struct tokgen_facts {
	int has_usable_addr;	/* some interface has a non-loopback address */
	int has_default_route;	/* a default route exists for this family */
	int dht_acked;		/* the DHT acknowledged our publish within time */
	int public_port_proven;	/* a mapped port was proven open FROM THE OUTSIDE:
				 * an unsolicited packet from a stranger arrived,
				 * not merely a UPnP/NAT-PMP/PCP success reply */
};

enum tok_advert tokgen_decide(const struct tokgen_facts *f);

#endif
