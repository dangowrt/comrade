/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "replay.h"

/* The case it exists for: the same frame, twice. */
static void a_repeat_is_refused(void)
{
	struct replay_win w;

	memset(&w, 0, sizeof(w));
	assert(replay_ok(&w, 1));
	assert(!replay_ok(&w, 1));
	assert(replay_ok(&w, 2));
	assert(!replay_ok(&w, 2));
	assert(!replay_ok(&w, 1));
}

/* Probes for several paths go out together and arrive as the networks under
 * them decide, so a frame that is merely late is not a repeat. */
static void reordering_is_not_replay(void)
{
	struct replay_win w;

	memset(&w, 0, sizeof(w));
	assert(replay_ok(&w, 10));
	assert(replay_ok(&w, 7));
	assert(replay_ok(&w, 9));
	assert(replay_ok(&w, 8));
	assert(!replay_ok(&w, 9));	/* but only once each */
	assert(replay_ok(&w, 11));
}

/* Past the window there is nothing left to vouch with, so the answer is no. */
static void the_window_has_an_edge(void)
{
	struct replay_win w;

	memset(&w, 0, sizeof(w));
	assert(replay_ok(&w, 1000));
	assert(replay_ok(&w, 1000 - REPLAY_WINDOW + 1));
	assert(!replay_ok(&w, 1000 - REPLAY_WINDOW));
	assert(!replay_ok(&w, 1));
}

/* A jump clears what it leaves behind, and does not carry a stale bit into
 * the new window. */
static void a_jump_leaves_nothing_behind(void)
{
	struct replay_win w;

	memset(&w, 0, sizeof(w));
	assert(replay_ok(&w, 5));
	assert(replay_ok(&w, 5 + REPLAY_WINDOW * 2));
	assert(!replay_ok(&w, 5));
	assert(replay_ok(&w, 5 + REPLAY_WINDOW * 2 - 1));
	assert(!replay_ok(&w, 5 + REPLAY_WINDOW * 2 - 1));
}

/* Zero is what a frame carrying no sequence at all looks like. */
static void zero_is_never_new(void)
{
	struct replay_win w;

	memset(&w, 0, sizeof(w));
	assert(!replay_ok(&w, 0));
	assert(replay_ok(&w, 1));
	assert(!replay_ok(&w, 0));
}

/* A long honest run, with no false refusals. */
static void a_steady_sender_is_never_refused(void)
{
	struct replay_win w;
	uint64_t i;

	memset(&w, 0, sizeof(w));
	for (i = 1; i < 10000; i++)
		assert(replay_ok(&w, i));
}

int main(void)
{
	a_repeat_is_refused();
	reordering_is_not_replay();
	the_window_has_an_edge();
	a_jump_leaves_nothing_behind();
	zero_is_never_new();
	a_steady_sender_is_never_refused();
	printf("replay_test: ok\n");
	return 0;
}
