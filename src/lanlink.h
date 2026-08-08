/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_LANLINK_H
#define COMRADE_LANLINK_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

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

typedef void lanlink_recv_cb(void *arg, const uint8_t *data, size_t len);

struct lanlink *lanlink_create(lanlink_recv_cb *on_recv, void *arg);
void lanlink_destroy(struct lanlink *l);

/* The bound UDP port, to announce so the peer can reach us. */
uint16_t lanlink_port(struct lanlink *l);

/* The peer's endpoint, learned from the announcement (its source address and
 * announced port); a v4 peer is kept v4-mapped for the dual-stack socket. */
int lanlink_set_peer(struct lanlink *l, const struct sockaddr *peer,
		     socklen_t len);
int lanlink_have_peer(struct lanlink *l);

int lanlink_prepare(struct lanlink *l, struct pollfd *fds, int maxfds,
		    int *timeout_ms);
void lanlink_dispatch(struct lanlink *l, const struct pollfd *fds, int nfds);
int lanlink_send(struct lanlink *l, const uint8_t *data, size_t len);

#endif
