/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>

#include "statusbar.h"
#include "tty.h"

/* Above this smoothed RTT the bar goes amber to flag a sluggish link. */
#define RTT_WARN_MS 250

/* ws_col is an unsigned short (up to 65535); cap the paint width at a
 * generous but bounded column count rather than sizing off the message
 * buffer, so wide terminals don't get truncated status bars. */
#define BAR_MAX_COLS 1024

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

/*
 * Colour by health so the state reads at a glance and keeps updating even while
 * the link is down: green when live, amber when live but slow (RTT over the
 * warn threshold), red when the link is lost, blue while still connecting.
 */
static const char *state_sgr(const struct conn_status *st)
{
	if (st->state == CONN_LOST)
		return "\033[41;97m";			/* red bg, bright white */
	if (st->state == CONN_LIVE)
		return st->rtt_ms > RTT_WARN_MS ?
			"\033[43;30m" :			/* amber bg, black */
			"\033[42;30m";			/* green bg, black */
	return "\033[44;97m";				/* blue bg: connecting */
}

void statusbar_render(int rows, int cols, const struct conn_status *st)
{
	char text[384], bar[BAR_MAX_COLS + 1], out[BAR_MAX_COLS + 64];
	int p, w = cols, n;

	if (rows < 1 || w < 1)
		return;

	/* Data -> display text (ASCII, so the width maths below stay simple). The
	 * view-only badge sits right after the name so it survives truncation on a
	 * narrow terminal. */
	p = snprintf(text, sizeof(text), "comrade%s  %s",
		     st->read_only ? " [view-only]" : "", state_word(st->state));
	if (p > 0 && p < (int)sizeof(text) && st->since_s > 0 &&
	    st->state == CONN_LOST)
		p += snprintf(text + p, sizeof(text) - p, " %ds", st->since_s);
	if (p > 0 && p < (int)sizeof(text) && st->peer[0])
		p += snprintf(text + p, sizeof(text) - p, "  peer %s", st->peer);
	/* The path in use, and what it would move to: a roam is a reordering of
	 * paths already warm, so the alternative is worth seeing before it is
	 * needed. Only the best one is named; the count carries the rest. */
	if (p > 0 && p < (int)sizeof(text) && st->alt[0]) {
		p += snprintf(text + p, sizeof(text) - p, "  alt %s", st->alt);
		if (p > 0 && p < (int)sizeof(text) && st->warm_alt > 1)
			p += snprintf(text + p, sizeof(text) - p, " +%d",
				      st->warm_alt - 1);
	}
	if (p > 0 && p < (int)sizeof(text) && st->rdv[0])
		p += snprintf(text + p, sizeof(text) - p, "  rdv4 %s", st->rdv);
	if (p > 0 && p < (int)sizeof(text) && st->rdv6[0])
		p += snprintf(text + p, sizeof(text) - p, "  rdv6 %s", st->rdv6);
	if (p > 0 && p < (int)sizeof(text) && st->state == CONN_LIVE &&
	    st->rtt_known) {
		char ms[16];

		/* Timed in whole milliseconds, so a link that answers in under
		 * one says so rather than reading zero. */
		if (st->rtt_ms > 0)
			snprintf(ms, sizeof(ms), "%dms", st->rtt_ms);
		else
			snprintf(ms, sizeof(ms), "<1ms");
		p += snprintf(text + p, sizeof(text) - p, "  rtt %s", ms);
	}
	if (p > 0 && p < (int)sizeof(text) && st->state == CONN_LOST)
		p += snprintf(text + p, sizeof(text) - p,
			      "  [ESC or ^C to quit]");

	if (w > (int)sizeof(bar) - 1)
		w = (int)sizeof(bar) - 1;
	snprintf(bar, sizeof(bar), "%-*.*s", w, w, text);
	/* save cursor; go to bottom-left; colour; text; reset; restore. */
	n = snprintf(out, sizeof(out), "\0337\033[%d;1H%s%s\033[0m\0338",
		     rows, state_sgr(st), bar);
	if (n > 0) {
		int r = tty_write(out, (size_t)n);

		(void)r;
	}
}
