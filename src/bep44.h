/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_BEP44_H
#define COMRADE_BEP44_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

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
 * hint to embed in a token. NULL when no value was found.
 */
typedef void bep44_get_cb(void *arg, const uint8_t *v, size_t v_len, int64_t seq,
			  const struct sockaddr *node, socklen_t node_len);

struct bep44_engine *bep44_create(const uint8_t myid[20], int s4, int s6);
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
int bep44_input(struct bep44_engine *e, const uint8_t *buf, size_t len,
		const struct sockaddr *from, socklen_t fromlen);
int bep44_periodic(struct bep44_engine *e, int *timeout_ms);
int bep44_put(struct bep44_engine *e, const uint8_t sk[64], const uint8_t pk[32],
	      const char *salt, const uint8_t *v, size_t v_len, int64_t seq,
	      int64_t cas, bep44_put_cb *cb, void *arg);
int bep44_get(struct bep44_engine *e, const uint8_t pk[32], const char *salt,
	      bep44_get_cb *cb, void *arg);

size_t bep44_sig_buffer(uint8_t *dst, size_t dst_len, const char *salt,
			int64_t seq, const uint8_t *v, size_t v_len);
void bep44_target(uint8_t target[20], const uint8_t pk[32], const char *salt);

#endif
