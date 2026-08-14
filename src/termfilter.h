/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_TERMFILTER_H
#define COMRADE_TERMFILTER_H

#include <stddef.h>

/*
 * tmux does not trust the pty size alone: on attach (and on redraw) it asks the
 * real terminal for its character size with "CSI 18 t", and the terminal
 * answers "CSI 8 ; rows ; cols t". tmux then uses that answer, which undoes the
 * one-row-shorter pty comrade hands it to reserve the bottom status row.
 *
 * This filter sits on the terminal-to-tmux byte stream and rewrites that one
 * answer so tmux sees `reserve` fewer rows, leaving the bottom row to comrade --
 * while a real resize still flows through (the new size, minus the reserve). All
 * other bytes pass untouched. The answer may be split across reads, so the
 * filter keeps a small amount of state between calls.
 */
struct termfilter {
	int reserve;
	char pend[32];		/* a partial escape sequence held across calls */
	int npend;
};

void termfilter_init(struct termfilter *f, int reserve);

/*
 * Filter in[len] into out, returning the number of bytes written. Rewriting
 * never lengthens the stream, but a sequence held from a previous call is
 * emitted here, so out must have room for len + sizeof(pend) bytes.
 */
size_t termfilter_run(struct termfilter *f, const char *in, size_t len,
		      char *out);

#endif
