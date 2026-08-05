/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>

#include "sshc.h"

int sshc_run(const struct token *tok)
{
	(void)tok;
	fprintf(stderr, "comrade: connecting is not implemented yet\n");
	return 1;
}
