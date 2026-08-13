/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_HOST_H
#define COMRADE_HOST_H

/* ui_mode: UI_AUTO / UI_VERBOSE (see ui.h); no_mcast: drop link-local discovery */
int host_run(int ui_mode, int no_mcast);
int host_show(void);

#endif
