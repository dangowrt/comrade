/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_TMUXPATH_H
#define COMRADE_TMUXPATH_H

#ifdef _WIN32

/*
 * Finding tmux on Windows.
 *
 * comrade.exe is one portable file and stays that way; tmux is the single
 * separate piece, and only for hosting -- joining a session never needs it.
 * That makes "tmux is missing" a first-run experience, not an error path, so
 * this module is as much about the message as the search.
 *
 * Search order, most specific first:
 *   1. %COMRADE_TMUX%                     -- explicit override, always wins
 *   2. <dir of comrade.exe>\tmux\tmux.exe -- the portable bundle, dropped
 *   3. <dir of comrade.exe>\tmux.exe         next to the executable
 *   4. C:\msys64\usr\bin\tmux.exe         -- the default MSYS2 install
 *   5. tmux.exe on %PATH%
 *   6. the usual scoop / winget / Cygwin / relocated-MSYS2 locations
 */

/* Absolute path to a usable tmux.exe, or NULL. Cached after the first call. */
const char *tmux_path(void);

/*
 * Print the copy-pasteable route from "no tmux" to "hosting works", tailored
 * to what is actually installed on this machine.
 */
void tmux_missing_help(void);

/*
 * Offer to install tmux and do it if the operator agrees: one keypress when a
 * package manager comrade recognises is already present (MSYS2's pacman,
 * scoop), or a fetch of the portable bundle when one is configured. Returns 1
 * if tmux is available afterwards, 0 otherwise. Never prompts when stdin is
 * not a terminal (the detached service, a pipe): it just returns 0.
 */
int tmux_offer_install(void);

#endif /* _WIN32 */

#endif
