/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * A peer row is nobody else's. Rows shift up as peers leave, so the slot a new
 * peer lands in may be holding what its last occupant's link was doing when it
 * went -- and the link report is only made when the state or the round trip
 * CHANGES, so an inherited one is what the row goes on showing. It took a
 * client typing (which moves the round trip) to correct it, and a read-only
 * guest never does.
 *
 * Includes ui.c to drive the model the dashboard draws from, with no terminal.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ui.c"

int main(void)
{
	struct ui u;

	memset(&u, 0, sizeof(u));
	u.anim = 1;		/* the dashboard keeps rows; the log does not */

	/* A peer arrives, its link is reported, and it leaves. */
	um_peer(&u, 1, SESSION_PEER_LIVE, "10.0.0.1:1");
	um_peer_link(&u, 1, CONN_UNKNOWN, 42);
	assert(u.npeer == 1 && u.peer[0].link == CONN_UNKNOWN);
	um_peer(&u, 1, SESSION_PEER_GONE, "");
	assert(u.npeer == 0);

	/* The next one lands in that slot and must inherit none of it. */
	um_peer(&u, 2, SESSION_PEER_LIVE, "10.0.0.2:2");
	assert(u.npeer == 1);
	assert(u.peer[0].link == CONN_CONNECTING);
	assert(u.peer[0].rtt_ms == -1);

	printf("ui: a new peer row inherits nothing from the slot's last "
	       "occupant\n");
	return 0;
}
