/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_DHTNODE_H
#define COMRADE_DHTNODE_H

#include <poll.h>

struct bep44_engine;
struct dhtnode;

struct dhtnode *dhtnode_create(void);
void dhtnode_free(struct dhtnode *n);
struct bep44_engine *dhtnode_engine(struct dhtnode *n);
int dhtnode_prepare(struct dhtnode *n, struct pollfd *fds, int maxfds,
		    int *timeout_ms);
void dhtnode_dispatch(struct dhtnode *n, const struct pollfd *fds, int nfds);
int dhtnode_ready(struct dhtnode *n);
unsigned dhtnode_netgen(struct dhtnode *n);

#endif
