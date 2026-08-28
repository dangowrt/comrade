/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "replay.h"

int replay_ok(struct replay_win *w, uint64_t seq)
{
	uint64_t back;

	if (!seq)
		return 0;
	if (seq > w->hi) {
		uint64_t step = seq - w->hi;

		if (step >= REPLAY_WINDOW)
			w->seen = 0;
		else
			w->seen = (w->seen << step) |
				  (w->hi ? (uint64_t)1 << (step - 1) : 0);
		w->hi = seq;
		return 1;
	}
	back = w->hi - seq;
	if (back >= REPLAY_WINDOW)
		return 0;		/* older than we can vouch for */
	if (!back)
		return 0;		/* the highest one, already taken */
	if (w->seen & ((uint64_t)1 << (back - 1)))
		return 0;
	w->seen |= (uint64_t)1 << (back - 1);
	return 1;
}
