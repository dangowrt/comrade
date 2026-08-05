/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SSHD_H
#define COMRADE_SSHD_H

struct token;

int sshd_run(const struct token *tok, int fd);

#endif
