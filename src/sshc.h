/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SSHC_H
#define COMRADE_SSHC_H

struct token;

int sshc_run(const struct token *tok);

#endif
