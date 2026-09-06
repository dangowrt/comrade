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
#define APPDIR_SEP "\\"
#else
#define appdir_mkdir(p) mkdir((p), 0700)
#define APPDIR_SEP "/"
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

const char *appdir_cache(void)
{
	const char *base = appdir_data();
	static char dir[560];
	char from[600];
	char to[600];
	int af;

	snprintf(dir, sizeof(dir), "%s%sdht", base, APPDIR_SEP);
	appdir_mkdir(dir);
	/* A cache an earlier layout left beside the directory moves in; from
	 * a confined process the rename is refused, and the cache is cold. */
	for (af = 4; af <= 6; af += 2) {
		snprintf(from, sizeof(from), "%s%sdht_nodes_v%d", base,
			 APPDIR_SEP, af);
		snprintf(to, sizeof(to), "%s%snodes_v%d", dir, APPDIR_SEP, af);
		rename(from, to);
	}
	return dir;
}
