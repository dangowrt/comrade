/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

#include "appdir.h"
#include "oscompat.h"

#ifdef _WIN32
#define appdir_mkdir(p) _mkdir(p)
#else
#define appdir_mkdir(p) mkdir((p), 0700)
#endif

/* mkdir every component of path (best effort, mode 0700 where that exists). */
static void mkdir_p(const char *path)
{
	char tmp[512];
	char *p;

	snprintf(tmp, sizeof(tmp), "%s", path);
	for (p = tmp + 1; *p; p++) {
		if (*p == '/' || *p == '\\') {
			char sep = *p;

			*p = '\0';
			appdir_mkdir(tmp);
			*p = sep;
		}
	}
	appdir_mkdir(tmp);
}

const char *appdir_data(void)
{
	static char dir[512];
#ifdef _WIN32
	/*
	 * The Windows equivalent of XDG_DATA_HOME. %LOCALAPPDATA% (not
	 * %APPDATA%) because the DHT node cache and STUN list are machine-local
	 * state that has no business roaming with the profile.
	 */
	const char *base = getenv("LOCALAPPDATA");

	if (base && *base)
		snprintf(dir, sizeof(dir), "%s\\comrade", base);
	else
		snprintf(dir, sizeof(dir), "%s\\comrade", os_tmpdir());
#else
	const char *base = getenv("XDG_DATA_HOME");
	const char *home = getenv("HOME");

	if (base && *base)
		snprintf(dir, sizeof(dir), "%s/comrade", base);
	else if (home && *home)
		snprintf(dir, sizeof(dir), "%s/.local/share/comrade", home);
	else
		snprintf(dir, sizeof(dir), "%s/comrade-%u/data", os_tmpdir(),
			 (unsigned)getuid());
#endif
	mkdir_p(dir);
	return dir;
}
