/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_HOST_H
#define COMRADE_HOST_H

int host_run(int ui_mode);	/* ui_mode: UI_AUTO / UI_VERBOSE (see ui.h) */
int host_show(void);

#endif
