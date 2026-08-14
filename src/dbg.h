/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_DBG_H
#define COMRADE_DBG_H

/*
 * Opt-in diagnostics. Does nothing unless COMRADE_DEBUG is set in the
 * environment; then each call appends one timestamped line to that file
 * (COMRADE_DEBUG="1" means /tmp/comrade-debug.log). Used to trace terminal
 * sizing across the host and client without disturbing the display.
 */
void dbg_logf(const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 1, 2)))
#endif
	;

#endif
