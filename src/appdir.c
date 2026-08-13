/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "appdir.h"

/* mkdir every component of path (best effort, mode 0700). */
static void mkdir_p(const char *path)
{
	char tmp[512];
	char *p;

	snprintf(tmp, sizeof(tmp), "%s", path);
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(tmp, 0700);
			*p = '/';
		}
	}
	mkdir(tmp, 0700);
}

const char *appdir_data(void)
{
	static char dir[512];
	const char *base = getenv("XDG_DATA_HOME");
	const char *home = getenv("HOME");

	if (base && *base)
		snprintf(dir, sizeof(dir), "%s/comrade", base);
	else if (home && *home)
		snprintf(dir, sizeof(dir), "%s/.local/share/comrade", home);
	else
		snprintf(dir, sizeof(dir), "/tmp/comrade-%u/data",
			 (unsigned)getuid());
	mkdir_p(dir);
	return dir;
}
