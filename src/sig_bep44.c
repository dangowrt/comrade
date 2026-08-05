/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <errno.h>
#include <stddef.h>

#include "sig.h"

struct sig_backend *sig_bep44_create(void)
{
	errno = ENOSYS;
	return NULL;
}
