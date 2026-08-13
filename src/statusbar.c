/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <unistd.h>

#include "statusbar.h"

static const char *state_word(int s)
{
	switch (s) {
	case CONN_GATHERING:
		return "gathering";
	case CONN_PUNCHING:
		return "punching";
	case CONN_LIVE:
		return "live";
	case CONN_LOST:
		return "link lost";
	default:
		return "connecting";
	}
}

void statusbar_render(int fd, int rows, int cols, const struct conn_status *st)
{
	char text[256], bar[256], out[320];
	int p, w = cols, n;

	if (rows < 1 || w < 1)
		return;

	/* Data -> display text (ASCII, so the width maths below stay simple). */
	p = snprintf(text, sizeof(text), "comrade  %s", state_word(st->state));
	if (p > 0 && p < (int)sizeof(text) && st->peer[0])
		p += snprintf(text + p, sizeof(text) - p, "  peer %s", st->peer);
	if (p > 0 && p < (int)sizeof(text) && st->rdv[0])
		p += snprintf(text + p, sizeof(text) - p, "  rdv %s", st->rdv);
	if (p > 0 && p < (int)sizeof(text) && st->state == CONN_LIVE &&
	    st->rtt_ms > 0)
		p += snprintf(text + p, sizeof(text) - p, "  rtt %dms",
			      st->rtt_ms);

	if (w > (int)sizeof(bar) - 1)
		w = (int)sizeof(bar) - 1;
	snprintf(bar, sizeof(bar), "%-*.*s", w, w, text);
	/* save cursor; go to bottom-left; reverse video; text; reset; restore. */
	n = snprintf(out, sizeof(out), "\0337\033[%d;1H\033[7m%s\033[0m\0338",
		     rows, bar);
	if (n > 0) {
		ssize_t r = write(fd, out, (size_t)n);

		(void)r;
	}
}
