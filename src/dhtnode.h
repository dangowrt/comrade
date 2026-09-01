/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_DHTNODE_H
#define COMRADE_DHTNODE_H

#include <stdint.h>

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

/*
 * Bootstrapping the routers is not a thing done once.
 *
 * The curated routers are a handful of hosts, and whether any of them answers
 * in a given second is not ours to arrange: two of the four carry no AAAA at
 * all, and the two that do have been observed answering intermittently, so the
 * IPv6 half of the set is the thin half. A single round that goes unanswered
 * would otherwise leave an empty table for the life of the process, silently,
 * with nothing to notice it by.
 *
 * The two rules below are pure and exported for the same reason
 * sig_tomb_settled is: being wrong either way is expensive, and neither can be
 * exercised against a live DHT without waiting for the internet to misbehave
 * in exactly the right way.
 */
#define DHTNODE_BOOTSTRAP_FIRST_MS 10000	/* the first retry */
#define DHTNODE_BOOTSTRAP_MAX_MS 600000		/* and the slowest one */
#define DHTNODE_BOOTSTRAP_MIN_GOOD 2		/* enough nodes for a family */

/*
 * Whether a bootstrap round is still wanted, given what each family has and
 * whether it has a socket at all.
 *
 * Per family, and deliberately not a sum. A node with a full IPv4 table and an
 * empty IPv6 one has every reason to keep asking on IPv6 and none to keep
 * asking on IPv4, and adding the two together says the opposite -- which is the
 * shape of the failure this exists to prevent, since the family that goes
 * quiet is the one whose routers are thin.
 */
int dhtnode_bootstrap_wanted(int have4, int good4, int have6, int good6);

/*
 * How long to wait before the next round, given how long we waited before
 * (0 = none yet). It doubles to a ceiling rather than repeating, because a box
 * with no path to the DHT at all would otherwise ask for ever at the opening
 * cadence, and a rendezvous tool asking the same four hosts every ten seconds
 * for a year is the kind of traffic that gets a protocol blocked. A network
 * change puts it back to the beginning, which is when a fresh answer is
 * actually likely.
 */
uint64_t dhtnode_bootstrap_backoff(uint64_t prev_ms);
/* The UDP port this node bound for `family` (4 or 6), 0 if it has none. The
 * port is ephemeral, so a private swarm has to be told where its members
 * actually are. */
uint16_t dhtnode_port(struct dhtnode *n, int family);
unsigned dhtnode_netgen(struct dhtnode *n);

#endif
