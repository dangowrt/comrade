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

/* Libjuice log level from COMRADE_ICE_LOG (juice_log_level_t: 0 verbose ..
 * 6 none), or -1 (silent) when unset. */
int dbg_ice_level(void);

/* Non-zero when COMRADE_MAILBOX_LOG asks for byte-exact BEP44 mailbox dumps. */
int dbg_mailbox_on(void);

/* Append one line: "<what>: <len>B hex=<hex>" (hex capped for long blobs). */
void dbg_hex(const char *what, const void *buf, size_t len);

#endif
