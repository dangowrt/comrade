/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "claimlog.h"

int claim_made(const char *conn_pwd, const char *claim_pwd)
{
	if (!conn_pwd || !claim_pwd || !conn_pwd[0] || !claim_pwd[0])
		return 0;
	return !strcmp(conn_pwd, claim_pwd);
}
