/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_DBG_H
#define COMRADE_DBG_H

#include <stddef.h>

/* Opt-in diagnostics: with COMRADE_DEBUG set, each call appends one
 * timestamped line to that file ("1" means comrade-debug.log in the
 * temporary directory). */
void dbg_logf(const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 1, 2)))
#endif
	;

/* The file the log goes to, with the "1" shorthand resolved into buf; NULL
 * where no log is asked for. */
const char *dbg_path(char *buf, size_t n);

#endif
