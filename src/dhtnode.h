/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_DHTNODE_H
#define COMRADE_DHTNODE_H

#include "wsock.h"

struct bep44_engine;
struct dhtnode;

struct dhtnode *dhtnode_create(void);
/*
 * Skips the public-router bootstrap; the caller injects one node with
 * dhtnode_seed() and queries it directly. This is for MEASUREMENT (isolating
 * the rendezvous fast path). In production the rendezvous node is only an
 * accelerant and may be offline, so a real client uses dhtnode_create()
 * (which keeps bootstrapping) AND dhtnode_seed(), so a stale hint falls back
 * to a normal global DHT search rather than failing.
 */
struct dhtnode *dhtnode_create_seeded(void);
int dhtnode_seed(struct dhtnode *n, const struct sockaddr *sa, socklen_t len);
/*
 * Pin a rendezvous node: sticky (never aged or overwritten) and used on every
 * DHT query. This is what sig_seed_node() plants from a token, alongside a
 * normally-bootstrapping node so a stale hint falls back to the global DHT.
 */
int dhtnode_pin(struct dhtnode *n, const struct sockaddr *sa, socklen_t len);
/* Free a node for good: the freshest good set is persisted on the way out. */
void dhtnode_free(struct dhtnode *n);
/*
 * Free a node that is being replaced within this run: another node follows it
 * immediately, so it is neither the freshest good set nor worth the run's one
 * teardown write to flash.
 */
void dhtnode_discard(struct dhtnode *n);
struct bep44_engine *dhtnode_engine(struct dhtnode *n);
int dhtnode_prepare(struct dhtnode *n, struct pollfd *fds, int maxfds,
		    int *timeout_ms);
void dhtnode_dispatch(struct dhtnode *n, const struct pollfd *fds, int nfds);
int dhtnode_ready(struct dhtnode *n);
unsigned dhtnode_netgen(struct dhtnode *n);

#endif
