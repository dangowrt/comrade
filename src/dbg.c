/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dbg.h"
#include "oscompat.h"

const char *dbg_path(char *buf, size_t n)
{
	const char *path = getenv("COMRADE_DEBUG");

	if (!path || !path[0])
		return NULL;
	if (strcmp(path, "1"))
		return path;
	snprintf(buf, n, "%s/comrade-debug.log", os_tmpdir());
	return buf;
}

void dbg_logf(const char *fmt, ...)
{
	struct timespec ts;
	const char *path;
	char dflt[512];
	va_list ap;
	FILE *f;

	path = dbg_path(dflt, sizeof(dflt));
	if (!path)
		return;
	f = fopen(path, "a");
	if (!f)
		return;
	/*
	 * This log carries every endpoint the session touches, and its default
	 * home is the shared temporary directory, where anyone with an account
	 * can read what the mode allows. Nobody but its owner has business in
	 * it.
	 */
	os_chmod_private(path);
	clock_gettime(CLOCK_REALTIME, &ts);
	fprintf(f, "[%ld.%03ld pid %ld] ", (long)ts.tv_sec,
		ts.tv_nsec / 1000000, os_pid());
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fclose(f);
}
