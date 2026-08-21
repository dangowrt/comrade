/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tmuxpath.h"

#ifdef _WIN32

#include "tty.h"
#include "win_proc.h"

/*
 * Where a prebuilt portable tmux would be fetched from. Empty in this tree:
 * nothing is hosted yet, so comrade prints the exact one-command install for
 * whatever the machine already has instead of offering a download. Setting it
 * (a .zip laid out as tmux.exe plus its runtime, extracted next to
 * comrade.exe) is the only change needed to turn the offer on.
 */
#ifndef COMRADE_TMUX_BUNDLE_URL
#define COMRADE_TMUX_BUNDLE_URL ""
#endif

#define MSYS2_TMUX "C:\\msys64\\usr\\bin\\tmux.exe"
#define MSYS2_PACMAN "C:\\msys64\\usr\\bin\\pacman.exe"

static char found[MAX_PATH];
static int searched;

static int is_file(const char *p)
{
	DWORD a = GetFileAttributesA(p);

	return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/* Directory holding comrade.exe, without a trailing separator. */
static const char *exe_dir(void)
{
	static char dir[MAX_PATH];
	char *slash;

	if (dir[0])
		return dir;
	if (!GetModuleFileNameA(NULL, dir, sizeof(dir))) {
		dir[0] = '\0';
		return dir;
	}
	slash = strrchr(dir, '\\');
	if (slash)
		*slash = '\0';
	return dir;
}

static int try_path(const char *p)
{
	if (!p || !*p || !is_file(p))
		return 0;
	snprintf(found, sizeof(found), "%s", p);
	return 1;
}

static int try_join(const char *dir, const char *tail)
{
	char p[MAX_PATH];

	if (!dir || !*dir)
		return 0;
	snprintf(p, sizeof(p), "%s%s", dir, tail);
	return try_path(p);
}

const char *tmux_path(void)
{
	static const char *fixed[] = {
		MSYS2_TMUX,
		"C:\\msys32\\usr\\bin\\tmux.exe",
		"C:\\tools\\msys64\\usr\\bin\\tmux.exe",
		"C:\\cygwin64\\bin\\tmux.exe",
		NULL
	};
	char buf[MAX_PATH];
	const char *env;
	int i;

	if (searched)
		return found[0] ? found : NULL;
	searched = 1;

	env = getenv("COMRADE_TMUX");
	if (try_path(env))
		return found;
	/*
	 * The portable bundle, first. It has to be laid out as usr\bin +
	 * usr\share because that is where the msys runtime looks for the
	 * terminfo database: it infers its root from its own DLL's path, and a
	 * flat directory of binaries leaves tmux exiting with "can't find
	 * terminfo database". Measured, and the reason the bundle is shaped
	 * the way it is rather than as a handful of files in one folder.
	 */
	if (try_join(exe_dir(), "\\tmux\\usr\\bin\\tmux.exe"))
		return found;
	if (try_join(exe_dir(), "\\tmux\\tmux.exe"))
		return found;
	if (try_join(exe_dir(), "\\tmux.exe"))
		return found;
	for (i = 0; fixed[i]; i++)
		if (try_path(fixed[i]))
			return found;
	if (SearchPathA(NULL, "tmux.exe", NULL, sizeof(buf), buf, NULL) &&
	    try_path(buf))
		return found;
	if (try_join(getenv("USERPROFILE"), "\\scoop\\shims\\tmux.exe"))
		return found;
	if (try_join(getenv("LOCALAPPDATA"), "\\Microsoft\\WinGet\\Links\\tmux.exe"))
		return found;
	return NULL;
}

/* Forget the cached answer, so an install can be re-checked in place. */
static void tmux_rescan(void)
{
	searched = 0;
	found[0] = '\0';
}

static int have_pacman(void)
{
	return is_file(MSYS2_PACMAN);
}

static int have_scoop(void)
{
	char p[MAX_PATH];
	const char *home = getenv("USERPROFILE");

	if (!home)
		return 0;
	snprintf(p, sizeof(p), "%s\\scoop\\shims\\scoop.cmd", home);
	return is_file(p);
}

void tmux_missing_help(void)
{
	fprintf(stderr,
"comrade: hosting needs tmux, and there is none on this machine.\n"
"\n"
"  Only hosting needs it -- joining a session (`comrade <token>`) never does,\n"
"  and comrade itself stays one portable .exe. tmux is the one separate piece.\n"
"\n");
	if (have_pacman())
		fprintf(stderr,
"  You already have MSYS2. One command installs it, no admin needed:\n"
"      %s -S --needed --noconfirm tmux\n"
"\n", MSYS2_PACMAN);
	else if (have_scoop())
		fprintf(stderr,
"  You already have scoop. One command installs MSYS2 (which carries tmux):\n"
"      scoop install msys2\n"
"      C:\\Users\\...\\scoop\\apps\\msys2\\current\\usr\\bin\\pacman -S tmux\n"
"\n");
	else
		fprintf(stderr,
"  Pick one, no admin needed for either:\n"
"      winget install MSYS2.MSYS2\n"
"      C:\\msys64\\usr\\bin\\pacman -S --needed --noconfirm tmux\n"
"  or, if you would rather not install MSYS2, unpack a portable tmux next to\n"
"  comrade.exe -- tmux.exe with its msys-*.dll runtime and a shell in\n"
"  usr\\bin, and the terminfo database in usr\\share:\n"
"      %s\\tmux\\usr\\bin\\tmux.exe\n"
"\n", exe_dir());
	fprintf(stderr,
"  comrade looks for tmux in %%COMRADE_TMUX%%, next to comrade.exe, in\n"
"  %s, and on %%PATH%%.\n", MSYS2_TMUX);
}

/* One y/n question on the operator's terminal. Returns 1 for yes. */
static int confirm(const char *question)
{
	char line[16];

	if (!tty_isatty_in() || !tty_isatty_out())
		return 0;
	fprintf(stderr, "%s [Y/n] ", question);
	fflush(stderr);
	if (!fgets(line, sizeof(line), stdin))
		return 0;
	return line[0] == '\0' || line[0] == '\n' || line[0] == 'y' ||
	       line[0] == 'Y' || line[0] == '\r';
}

/* Fetch and unpack the portable bundle with PowerShell, which every Windows
 * has -- so the download costs comrade neither a new DLL import nor a zip
 * reader. Only reachable when a bundle URL is configured at build time. */
static int fetch_bundle(void)
{
	const char *url = COMRADE_TMUX_BUNDLE_URL;
	char script[1024], dest[MAX_PATH], zip[MAX_PATH];
	char *argv[6];
	const char *tmp = getenv("TEMP");

	if (!*url)
		return 0;
	snprintf(dest, sizeof(dest), "%s\\tmux", exe_dir());
	snprintf(zip, sizeof(zip), "%s\\comrade-tmux.zip", tmp ? tmp : ".");
	snprintf(script, sizeof(script),
		 "$ErrorActionPreference='Stop';"
		 "Invoke-WebRequest -UseBasicParsing -Uri '%s' -OutFile '%s';"
		 "Expand-Archive -Force -Path '%s' -DestinationPath '%s';"
		 "Remove-Item -Force '%s'", url, zip, zip, dest, zip);
	argv[0] = "powershell.exe";
	argv[1] = "-NoProfile";
	argv[2] = "-ExecutionPolicy";
	argv[3] = "Bypass";
	argv[4] = "-Command";
	argv[5] = script;
	fprintf(stderr, "comrade: fetching a portable tmux into %s ...\n", dest);
	{
		char *a[7];
		int i;

		for (i = 0; i < 6; i++)
			a[i] = argv[i];
		a[6] = NULL;
		if (win_run(a))
			return 0;
	}
	tmux_rescan();
	return tmux_path() != NULL;
}

static int run_pacman(void)
{
	char *argv[] = { MSYS2_PACMAN, "-S", "--needed", "--noconfirm",
			 "tmux", NULL };
	char err[256];

	fprintf(stderr, "comrade: installing tmux with MSYS2 pacman ...\n");
	if (win_run_capture(argv, err, sizeof(err))) {
		if (err[0])
			fprintf(stderr, "comrade: pacman failed: %s\n", err);
		return 0;
	}
	tmux_rescan();
	return tmux_path() != NULL;
}

int tmux_offer_install(void)
{
	if (tmux_path())
		return 1;
	if (*COMRADE_TMUX_BUNDLE_URL &&
	    confirm("comrade: download a portable tmux next to comrade.exe?") &&
	    fetch_bundle())
		return 1;
	if (have_pacman() &&
	    confirm("comrade: install tmux with MSYS2 pacman now?") &&
	    run_pacman())
		return 1;
	return 0;
}

#endif /* _WIN32 */
