/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_STATUSBAR_H
#define COMRADE_STATUSBAR_H

#include "conn.h"

/*
 * View for comrade's local connection line. Each side reserves the bottom
 * terminal row (by running tmux one row shorter) and this paints its own status
 * there, so it stays live even while the link -- and thus the shared tmux -- is
 * down. It owns the display: it turns the controller's structured conn_status
 * into text and writes the ANSI itself.
 *
 * Formats st and paints it as a reverse-video bar on the bottom row (1-indexed
 * `rows`) of the terminal on fd, truncated/padded to `cols`. Saves and restores
 * the cursor so the full-screen application above (tmux) is undisturbed.
 */
void statusbar_render(int fd, int rows, int cols, const struct conn_status *st);

#endif
