/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dbg.h"
#include "oscompat.h"

void dbg_logf(const char *fmt, ...)
{
	const char *path = getenv("COMRADE_DEBUG");
	char dflt[512];
	struct timespec ts;
	FILE *f;
	va_list ap;

	if (!path || !path[0])
		return;
	if (!strcmp(path, "1")) {
		snprintf(dflt, sizeof(dflt), "%s/comrade-debug.log", os_tmpdir());
		path = dflt;
	}
	f = fopen(path, "a");
	if (!f)
		return;
	clock_gettime(CLOCK_REALTIME, &ts);
	fprintf(f, "[%ld.%03ld pid %ld] ", (long)ts.tv_sec,
		ts.tv_nsec / 1000000, os_pid());
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fclose(f);
}
