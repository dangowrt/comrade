/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_HOST_H
#define COMRADE_HOST_H

/*
 * ui_mode: UI_AUTO / UI_VERBOSE (see ui.h); no_mcast: drop link-local
 * discovery; no_dht: drop the DHT, leaving link-local discovery alone.
 */
int host_run(int ui_mode, int no_mcast, int no_dht, int no_fwd);
int host_show(int what);		/* a SHOWFMT_* shape */

#ifdef _WIN32
/*
 * The detached service half of the Windows host, re-entered as
 * `comrade --win-service <socket handle>`. Not a user-facing command: the
 * operator's process spawns it with an inherited socketpair end, hands the
 * session state down it, and reads the dashboard events back. It never
 * returns. See src/host_win.c for why the split has to work this way.
 */
int host_win_service(const char *handle_arg);
#endif

#endif
