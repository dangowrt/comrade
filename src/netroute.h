/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_NETROUTE_H
#define COMRADE_NETROUTE_H

#include <stddef.h>
#include <stdint.h>

/*
 * The address this host would send from, if it sent to that family at all.
 *
 * A connected UDP socket is the question asked of the routing table without
 * sending anything: the kernel picks the route, binds the source it would use,
 * and getsockname reads it back. No packet leaves, so it costs nothing and
 * cannot be blocked.
 *
 * The answer is about a ROUTE and not about an address. A host can hold two
 * global IPv6 addresses and have no default route for them, which is an
 * ordinary state on a router whose upstream advertises a prefix and no
 * gateway, and it is the state in which every IPv6 socket succeeds and nothing
 * on IPv6 ever answers. Anything deciding whether to speak a family must ask
 * this rather than count addresses, or it will believe a family this host
 * cannot reach.
 *
 * `af` is AF_INET or AF_INET6. `text` receives the printable source (may be
 * NULL), `raw` its bytes and `rawlen` their length, 4 or 16 (both may be
 * NULL). Returns 0 when this host has a source for that family, non-zero when
 * it has none -- which is the whole of the question when the caller only wants
 * to know whether the family is worth opening.
 */
int net_source_addr(int af, char *text, size_t textlen, uint8_t *raw,
		    int *rawlen);

/*
 * Whether this host has any route for `af` at all.
 *
 * That is the whole of what can be answered here, and the limit is worth
 * stating because a stronger test looks available and is not. connect() on a
 * datagram socket does a route lookup and sends nothing, so what comes back is
 * "the kernel would use this source", never "something out there answers".
 *
 * In particular DO NOT judge the source's address class, in either family.
 * A unique-local IPv6 source looks like a host that cannot reach the internet
 * and is equally a host behind NAT66 -- QEMU's user-mode networking, Docker's
 * IPv6 NAT, any ULA-internal home router. An RFC1918 IPv4 source is the same
 * statement behind NAT44, which nobody would think to call unreachable. The
 * two families are not different problems and must not get different rules:
 * in both, a private source behind a translator reaches the world, a
 * link-local or loopback source reaches nothing, and neither case is
 * distinguishable from here, because they differ only in what happens to a
 * packet after it leaves.
 *
 * A host can be v6-only exactly as it can be v4-only, and multi-homed in
 * either. Anything here that treats one family as the ordinary case and the
 * other as the exception is a bug waiting for the host that inverts it.
 *
 * The distinction that IS observable, and the one this is for, is a host with
 * no route for a family whatsoever: connect() fails with ENETUNREACH. That is
 * the case a v4-only router presents for IPv6, and a v6-only host presents for
 * IPv4, and in both it costs a DHT node the other family's routing table (see
 * dhtnode.c).
 *
 * Anything wanting more than this needs a completed round trip, which is a
 * fact about the network rather than about the host, and belongs to whatever
 * is already making round trips.
 *
 * EVERY ANSWER HERE IS MOMENTARY, IN BOTH DIRECTIONS, and that is what decides
 * where one may be used. A yes says a packet sent now would go somewhere, not
 * that anything answers and not that the path survives the next second. A no
 * is no more durable: it commonly means an RA or a DHCPv6 exchange has not
 * finished yet, and the family comes up a moment later. Neither polarity is
 * conclusive about anything but the instant it was taken.
 *
 * So what matters is not the strength of the observation but the LIFETIME OF
 * THE DECISION it feeds. Acting on this is sound where the decision is taken
 * again; it is unsound wherever one answer is fixed for the life of something
 * longer than the answer.
 *
 * In this tree that condition is met rather than assumed. netmon polls every
 * two seconds and reports per family; a change bumps that family's epoch in
 * netstate and invalidates what was derived from the old network, and a
 * network change rebuilds the signaller (session.c, sig_rebuild on
 * net_changed), which builds a fresh DHT node and asks this again. So a host
 * that gains a route thirty seconds after launch, or loses one on a roam, is
 * re-decided rather than living with whatever happened to be true at startup.
 * Anything reusing this must check it has that property before acting on
 * either answer.
 */
int net_family_routed(int af);

#endif
