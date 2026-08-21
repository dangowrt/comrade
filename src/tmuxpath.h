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
 *   2. <dir of comrade.exe>\tmux.exe      -- dropped next to the executable
 *      (also \tmux\tmux.exe and the MSYS2 \tmux\usr\bin\tmux.exe layout)
 *   3. the winget package dir            -- arndawg.tmux-windows, the native
 *      MSVC/ConPTY tmux 3.6a: the primary path, and the one comrade offers
 *      to install. User scope, then machine scope, then the winget Links alias
 *   4. C:\msys64\usr\bin\tmux.exe         -- MSYS2, a silent fallback
 *   5. tmux.exe on %PATH%
 *   6. Cygwin / relocated-MSYS2 / scoop shims
 */

/* Absolute path to a usable tmux.exe, or NULL. Cached after the first call. */
const char *tmux_path(void);

/*
 * Print the copy-pasteable route from "no tmux" to "hosting works", tailored
 * to what is actually installed on this machine.
 */
void tmux_missing_help(void);

/*
 * Offer to install tmux and do it if the operator agrees: one keypress runs
 * `winget install --id arndawg.tmux-windows`, and MSYS2's pacman is offered
 * after it on a machine that has one. Returns 1 if tmux is available
 * afterwards, 0 otherwise. Never prompts when stdin is not a terminal (the
 * detached service, a pipe): it just returns 0.
 */
int tmux_offer_install(void);

#endif /* _WIN32 */

#endif
