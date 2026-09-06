/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_APPDIR_H
#define COMRADE_APPDIR_H

/*
 * Per-user application data directory, created if absent: $XDG_DATA_HOME/comrade
 * (else ~/.local/share/comrade, else a /tmp fallback). Holds the managed STUN
 * list and the cached DHT nodes. Returns a static path string.
 */
const char *appdir_data(void);

/* The DHT node cache's own directory beneath it, created if absent: the one
 * part of the data directory a confined process may write (sandbox.h). */
const char *appdir_cache(void);

#endif
