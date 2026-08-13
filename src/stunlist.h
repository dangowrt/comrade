/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_STUNLIST_H
#define COMRADE_STUNLIST_H

/*
 * The STUN server pool. A default set is baked in at build time from the
 * always-online-stun submodule (its RFC 5780-capable list, which also serves
 * for plain reflexive gathering). `comrade stun-update` fetches a fresh copy
 * into the user's data folder, which then takes precedence -- so the list can
 * be refreshed without rebuilding, and nothing is fetched unless asked for.
 * Entries are "host:port" strings.
 */

/*
 * Load the pool into a malloc'd array of malloc'd "host:port" strings, with the
 * count in *n. The user's updated list is used if present and non-empty, else
 * the built-in bundle. Free with stunlist_free. Returns NULL on failure.
 */
char **stunlist_load(int *n);
void stunlist_free(char **list, int n);

/*
 * Fetch the latest RFC 5780-capable list into the data folder using an external
 * fetcher (wget or curl). On success returns 0 and, if count is non-NULL, the
 * number of servers written; returns -1 on failure. Prints progress to stderr.
 */
int stunlist_update(int *count);

/* Absolute path of the data-folder list file (static buffer). */
const char *stunlist_path(void);

/* The URL stun-update fetches from (for messages). */
const char *stunlist_url(void);

#endif
