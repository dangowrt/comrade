/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_REPLAY_H
#define COMRADE_REPLAY_H

#include <stdint.h>

/*
 * A sliding window over a peer's sequence numbers, so a datagram that opens
 * is only acted on once.
 *
 * The seal says a frame was written by somebody holding the session key. It
 * does not say when, and nothing on the raw path ever did: a copy taken off
 * the wire opens again an hour later exactly as it did the first time. That
 * is enough to end a session, to hold a dead one open, or to have a path
 * offered from an address of the attacker's choosing, none of which needs the
 * key at all -- only a copy of one datagram.
 *
 * The sender counts its frames; this remembers the highest counter seen and a
 * bitmap of the ones just below it, so anything already seen is refused and
 * anything older than the window is too. The window makes room for ordinary
 * reordering, which is real here: probes for several paths go out together
 * and arrive as the networks under them decide.
 */

#define REPLAY_WINDOW 64		/* frames of reordering tolerated */

struct replay_win {
	uint64_t hi;			/* highest sequence accepted, 0 = none */
	uint64_t seen;			/* bitmap of hi-1 .. hi-REPLAY_WINDOW */
};

/*
 * Answers 1 when `seq` is new and records it, 0 when it is a repeat, older
 * than the window, or zero (which no sender ever sends, so it can mean "no
 * sequence" without ambiguity).
 */
int replay_ok(struct replay_win *w, uint64_t seq);

#endif /* COMRADE_REPLAY_H */
