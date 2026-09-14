/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * THE PATH PLANE'S KEY SCHEDULE.
 *
 * A path carries a session only once a probe has round-tripped on it under a
 * key the pair agreed, and that is true whatever established the pair. Only
 * the primitive that derives the base key differs, so only that is passed in.
 *
 * TWO KEYS, AND THE ORDER MATTERS. Until both ends have traded a half over
 * their control channel there is only the base key, which every holder of the
 * establishment primitive has. After that the key is this pair's alone and no
 * other holder can reach the path plane of this connection. The base key stays
 * acceptable until the first frame arrives under the new one, because the far
 * end cannot seal with a key it has not derived yet, and it derives it from a
 * half that travels over the channel the base key protects.
 */
#ifndef COMRADE_PROBEPLANE_H
#define COMRADE_PROBEPLANE_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "dataauth.h"
#include "keys.h"
#include "path.h"
#include "replay.h"

struct probeplane {
	uint32_t magic;			/* this session's demux tag */
	uint8_t base[32];		/* what the establishment primitive
					 * derived: every holder of it has this */
	uint8_t pair[32];		/* this pair's own, once bound */
	int pair_ready;			/* it exists and opens frames */
	int pair_tx;			/* the peer can open it, so seal with it */
	int base_ok;			/* the base key still opens frames */
	uint64_t seq;			/* our own probes, from the clock */
	struct replay_win rx;		/* and the peer's, each acted on once */
	uint64_t data_seq;		/* and the same for stream datagrams */
	struct replay_win data_rx;
	/*
	 * Held to copy a key out, to move the state along, and to count: a loop
	 * thread binds while a transport thread may be opening a frame, and the
	 * connection's own loop and a host's main thread both seal probes for
	 * one connection, so the increment is a read-modify-write from two
	 * threads. Two probes handed the same number is one of them dropped as
	 * a replay, which on a segment where the pair have just met is the
	 * direct path failing to prove for no visible reason.
	 */
	pthread_mutex_t lock;
};

/*
 * `seq0` is where this end's counters start, and it is the clock rather than
 * one. A peer that replaces a connection while the far end keeps the one it
 * had would otherwise send counters the far end's window has already seen, and
 * a counter that started over is exactly what a replayed frame looks like.
 * Starting from the clock means every new connection counts above the one it
 * replaced, and every copy of an old frame counts below.
 */
void probeplane_init(struct probeplane *pp, uint32_t magic,
		     const uint8_t base[32], uint64_t seq0);
void probeplane_destroy(struct probeplane *pp);

/*
 * Back to the base key alone. The pair key belongs to the channel that agreed
 * it, so a fresh channel starts again from what the primitive gave both ends.
 */
void probeplane_reset(struct probeplane *pp);

/* Both halves are in: the pair key exists and opens frames here. */
void probeplane_bind(struct probeplane *pp,
		     const uint8_t half_out[KEYS_HALF_LEN],
		     const uint8_t half_in[KEYS_HALF_LEN]);

/* The peer says it can open the pair key, so seal with it from now on.
 * Returns non-zero the first time, for a caller that wants to say so. */
int probeplane_tx_ready(struct probeplane *pp);

/*
 * Seal a probe under whichever key is in force, stamping it with this end's
 * identity and the next sequence. Returns the length, 0 if it will not fit.
 */
size_t probeplane_seal(struct probeplane *pp, struct path_probe *pr,
		       const char *ufrag, uint8_t *out, size_t out_len);

/*
 * Open one addressed to this connection. Zero on success.
 *
 * Once the base key is spent it still opens exactly one thing: the notice that
 * the session this connection belonged to is gone, which comes from an end
 * that shares no pair key with us and so cannot say it any other way. A probe
 * of any other type under a spent base key is refused, because that is the
 * whole of what binding bought.
 */
int probeplane_open(struct probeplane *pp, struct path_probe *pr,
		    const uint8_t *data, size_t len);

/*
 * The stream's own datagrams, wrapped and opened under the same schedule.
 * They are authenticated to the same pair and change hands at the same moment,
 * so a second copy of the rule would be a second thing to get wrong.
 */
size_t probeplane_wrap(struct probeplane *pp, uint8_t *out, size_t out_max,
		       const uint8_t *data, size_t len);
int probeplane_unwrap(struct probeplane *pp, const uint8_t *data, size_t *len);

/* Whether this sequence has been acted on already. */
int probeplane_fresh(struct probeplane *pp, const struct path_probe *pr);

#endif
