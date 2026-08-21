/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_LANLINK_H
#define COMRADE_LANLINK_H

#include "wsock.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Direct UDP transport for the shared layer-2 segment. On the same link there
 * is no NAT to punch, so ICE is pure overhead -- and libjuice refuses the
 * link-local addresses a segment-local rendezvous relies on. This is a plain
 * dual-stack UDP socket: we announce its port over multicast, learn the peer's
 * (source address, port) from that sealed announcement, and carry KCP straight
 * between the two. The seal authenticates the endpoint exchange; SSH (host-key
 * pinned, token-authenticated) secures the session.
 */

struct lanlink;

/*
 * One shared socket carries several peers on a host. A received datagram is
 * handed up with its source, so the host can demultiplex it into the owning
 * connection's stream; a send names its peer explicitly.
 */
typedef void lanlink_recv_cb(void *arg, const struct sockaddr *src,
			     socklen_t srclen, const uint8_t *data, size_t len);

/*
 * port: the UDP port to bind, or 0 for an ephemeral one. A host that carries a
 * direct endpoint token forward across re-serves asks for that token's port so
 * the already-printed token stays valid; if it is taken the bind falls back to
 * ephemeral (the caller then re-mints).
 */
struct lanlink *lanlink_create(lanlink_recv_cb *on_recv, void *arg,
			       uint16_t port);
void lanlink_destroy(struct lanlink *l);

/* The bound UDP port, to announce so the peer can reach us. */
uint16_t lanlink_port(struct lanlink *l);

/*
 * Map a peer endpoint (its source address and announced port) into a v4-mapped
 * sockaddr_in6 for the dual-stack socket, so both client and host fill a
 * connection's lan_peer identically. Returns 0 on success.
 */
int lanlink_map_peer(const struct sockaddr *sa, socklen_t len,
		     struct sockaddr_in6 *out);

int lanlink_prepare(struct lanlink *l, struct pollfd *fds, int maxfds,
		    int *timeout_ms);
void lanlink_dispatch(struct lanlink *l, const struct pollfd *fds, int nfds);

/* Send to a specific peer over the shared socket. Safe to call from several
 * worker threads at once: each datagram is independent, no shared socket state
 * is mutated. */
int lanlink_send(struct lanlink *l, const struct sockaddr_in6 *peer,
		 const uint8_t *data, size_t len);

#endif
