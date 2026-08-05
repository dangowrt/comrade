/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <errno.h>

#include "sshd.h"

int sshd_run(const struct token *tok, int fd)
{
	(void)tok;
	(void)fd;
	errno = ENOSYS;
	return -1;
}
