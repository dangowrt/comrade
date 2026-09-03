/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_BEP44_H
#define COMRADE_BEP44_H

#include <stddef.h>
#include <stdint.h>
#include "wsock.h"

#define BEP44_MAX_VALUE 1000
#define BEP44_MAX_SALT 64

struct bep44_engine;

/*
 * On a put, node/node_len identify the closest node that acknowledged storing
 * the value, known at store time: the rendezvous node a host embeds in a
 * token without any separate get. NULL when nothing stored.
 */
typedef void bep44_put_cb(void *arg, int stored, const struct sockaddr *node,
			  socklen_t node_len);
/*
 * On a get, node/node_len identify the DHT node that first served the winning
 * value: proven to hold it and fastest to answer, so the right rendezvous
 * hint to embed in a token. Invoked once per address family that served it,
 * since a single winner would starve the slower family's node of the answers
 * that prove it. NULL when no value was found.
 */
typedef void bep44_get_cb(void *arg, const uint8_t *v, size_t v_len, int64_t seq,
			  const struct sockaddr *node, socklen_t node_len);

struct bep44_engine *bep44_create(const uint8_t myid[20], sock_t s4, sock_t s6);
void bep44_free(struct bep44_engine *e);
int bep44_bootstrap_add(struct bep44_engine *e, const struct sockaddr *sa,
			socklen_t salen);
int bep44_seed_add(struct bep44_engine *e, const uint8_t id[20],
		   const struct sockaddr *sa, socklen_t salen);
/*
 * Pin a node (a token rendezvous hint) permanently: unlike a seed it is never
 * overwritten and never aged, and it is injected into the initial node set of
 * EVERY subsequent op, so it is tried on every query for the life of the
 * engine (with the global DHT as fallback). id may be NULL (address only,
 * which is all a token carries).
 */
int bep44_pin_add(struct bep44_engine *e, const uint8_t id[20],
		  const struct sockaddr *sa, socklen_t salen);
/* Unpin a node given up on, freeing its never-aged slot for a replacement. */
void bep44_pin_del(struct bep44_engine *e, const struct sockaddr *sa,
		   socklen_t salen);
int bep44_input(struct bep44_engine *e, const uint8_t *buf, size_t len,
		const struct sockaddr *from, socklen_t fromlen);
int bep44_periodic(struct bep44_engine *e, int *timeout_ms);
int bep44_put(struct bep44_engine *e, const uint8_t sk[64], const uint8_t pk[32],
	      const char *salt, const uint8_t *v, size_t v_len, int64_t seq,
	      int64_t cas, bep44_put_cb *cb, void *arg);
int bep44_get(struct bep44_engine *e, const uint8_t pk[32], const char *salt,
	      bep44_get_cb *cb, void *arg);

/*
 * Merge callback for bep44_update: cur/cur_len is the value currently stored
 * (NULL if none), and `seq` its sequence, -1 where there is none. Write the
 * value to store into out (up to max) and set *out_len. Return 0 to proceed
 * with the put, non-zero to abort.
 *
 * The sequence is passed because the responding nodes are not the whole store:
 * they are whoever answered this lookup, and their copy can be older than one
 * the caller has already read elsewhere. Only the caller knows that, so only
 * the caller can decide what of it is still worth merging.
 */
typedef int bep44_merge_fn(void *arg, const uint8_t *cur, size_t cur_len,
			   int64_t seq, uint8_t *out, size_t *out_len,
			   size_t max);

/*
 * Read-modify-write a mutable item the mainline way: get the current value and
 * the responding nodes' write tokens, call merge to build the new value, and
 * put it back onto those same token-bearing nodes with seq+1 and cas. The
 * right primitive for a shared mailbox that two peers both update, and it
 * reuses the tokens the get already earned instead of a second lookup.
 */
int bep44_update(struct bep44_engine *e, const uint8_t sk[64],
		 const uint8_t pk[32], const char *salt, bep44_merge_fn *merge,
		 void *merge_arg, bep44_put_cb *cb, void *arg);

/*
 * Direct (rendezvous) variants of get/update. They address only the pinned
 * and retained nodes -- the shared rendezvous the host converged to once and
 * put in the token -- and never converge toward the target again. Every query
 * is still an ordinary compliant get/put to those foreign nodes; only our own
 * redundant re-lookup is skipped. Use these on both ends after the rendezvous
 * node is known, so a rendezvous costs a round-trip instead of a full lookup.
 */
int bep44_get_direct(struct bep44_engine *e, const uint8_t pk[32],
		     const char *salt, bep44_get_cb *cb, void *arg);
int bep44_update_direct(struct bep44_engine *e, const uint8_t sk[64],
			const uint8_t pk[32], const char *salt,
			bep44_merge_fn *merge, void *merge_arg,
			bep44_put_cb *cb, void *arg);

/*
 * Serve BEP 44 to the network: hold items other peers store here and answer
 * their get and put. Off until enabled, so an embedder that only reads and
 * writes its own items stores nothing for anybody else.
 */
int bep44_serve(struct bep44_engine *e, int enable);

/*
 * Tune the per-source rate limiter (libtorrent's dht_block_ratelimit /
 * dht_block_timeout). The default when serving is on is a real node's; pass
 * ban_seconds 0 to disable it, as a black-box conformance harness must.
 */
void bep44_ratelimit(struct bep44_engine *e, int per_source_rate,
		     int ban_seconds);

/*
 * Immutable items: the value is its own name, so there is no key, salt, seq or
 * signature, and no way to change what a target resolves to. A get reports
 * seq -1. The value passed to put is already bencoded, as for bep44_put.
 */
int bep44_put_immutable(struct bep44_engine *e, const uint8_t *v, size_t v_len,
			bep44_put_cb *cb, void *arg);
int bep44_get_immutable(struct bep44_engine *e, const uint8_t target[20],
			bep44_get_cb *cb, void *arg);

size_t bep44_sig_buffer(uint8_t *dst, size_t dst_len, const char *salt,
			int64_t seq, const uint8_t *v, size_t v_len);
void bep44_target(uint8_t target[20], const uint8_t pk[32], const char *salt);
void bep44_immutable_target(uint8_t target[20], const uint8_t *v, size_t v_len);

#endif
