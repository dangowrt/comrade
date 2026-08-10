/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_UI_H
#define COMRADE_UI_H

#include "session.h"

/*
 * The view. This is the ONLY module that touches the terminal: every escape
 * sequence, spinner, colour and the power-on zap live here. It renders the
 * controller's progress (struct session_obs) and knows nothing of the DHT,
 * ICE, or KCP -- only the semantic events it is handed.
 */

enum { UI_AUTO, UI_ANIM, UI_VERBOSE };		/* rendering mode */
enum { UI_ROLE_HOST, UI_ROLE_CLIENT };

struct ui;

/* mode UI_AUTO animates on a real terminal and logs otherwise. */
struct ui *ui_create(int role, int mode);
void ui_destroy(struct ui *u);

/* Bind the view's callbacks into obs so a session drives it directly (the
 * client, inline; or the host foreground rendering its own service events). */
void ui_bind(struct ui *u, struct session_obs *obs);

/*
 * Host runs the connection in a detached service, so its view spans two
 * processes. Both halves of that bridge -- the wire framing and the render
 * loop -- stay here in the view layer.
 *
 * ui_emitter: service side. Fills obs to serialise each event to fd (the write
 * end of a pipe to the foreground). ui_emitter_token posts the minted invite.
 */
void ui_emitter(struct session_obs *obs, int fd);
void ui_emitter_token(const struct session_obs *obs, const char *token_str);

/*
 * ui_host_wait: foreground side. Render events read from fd until the operator
 * acts. Returns 1 to enter (ENTER/SPACE, which plays the zap), -1 to abort
 * (ESC / Ctrl-C / SIGTERM -- the caller tears the service down), or 0 if the
 * pipe closed first. The terminal is restored on every path.
 */
int ui_host_wait(struct ui *u, int fd);

#endif
