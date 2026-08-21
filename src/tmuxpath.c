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
 * tmux on Windows comes from winget. `arndawg.tmux-windows` is a native
 * MSVC/ConPTY build of tmux 3.6a (ISC): one 1.3 MB tmux.exe importing
 * KERNEL32, WS2_32, ADVAPI32 and bcrypt and nothing else -- no msys-2.0.dll,
 * no terminfo database to lay out, no bundled shell (its default-shell is
 * cmd.exe). It installs per-user, needs no admin, and drives every command
 * comrade sends it. That is why it is looked for first and is the only thing
 * offered.
 *
 * MSYS2's tmux keeps working and is still found, silently, for the many
 * developers who already have MSYS2 -- it is a Cygwin program with a DLL
 * closure and a terminfo database, but comrade only CreateProcess()es tmux,
 * so either is fine.
 *
 * winget lays a portable package down as
 *   %LOCALAPPDATA%\Microsoft\WinGet\Packages\<id>_<source-hash>\tmux.exe
 * (machine scope: %ProgramFiles%\WinGet\Packages\...). The trailing hash names
 * the source the package came from, so the directory is matched with a
 * wildcard rather than spelled out; the version appears nowhere in the path.
 */
#define WINGET_TMUX_ID "arndawg.tmux-windows"
#define WINGET_PKG_GLOB WINGET_TMUX_ID "_*"

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

/*
 * Look for tmux.exe under one winget Packages root. The zip this package
 * ships is flat -- <pkgdir>\tmux.exe -- but one level of subdirectory is
 * searched too, so a future layout with a top-level folder still resolves
 * without a code change.
 */
static int try_winget_packages(const char *pkgroot)
{
	WIN32_FIND_DATAA fd, sd;
	HANDLE h, h2;
	char pat[MAX_PATH], dir[MAX_PATH], sub[MAX_PATH];

	if (!pkgroot || !*pkgroot)
		return 0;
	snprintf(pat, sizeof(pat), "%s\\%s", pkgroot, WINGET_PKG_GLOB);
	h = FindFirstFileA(pat, &fd);
	if (h == INVALID_HANDLE_VALUE)
		return 0;
	do {
		if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			continue;
		snprintf(dir, sizeof(dir), "%s\\%s", pkgroot, fd.cFileName);
		if (try_join(dir, "\\tmux.exe")) {
			FindClose(h);
			return 1;
		}
		snprintf(sub, sizeof(sub), "%s\\*", dir);
		h2 = FindFirstFileA(sub, &sd);
		if (h2 == INVALID_HANDLE_VALUE)
			continue;
		do {
			if (!(sd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
			    sd.cFileName[0] == '.')
				continue;
			snprintf(sub, sizeof(sub), "%s\\%s", dir, sd.cFileName);
			if (try_join(sub, "\\tmux.exe")) {
				FindClose(h2);
				FindClose(h);
				return 1;
			}
		} while (FindNextFileA(h2, &sd));
		FindClose(h2);
	} while (FindNextFileA(h, &fd));
	FindClose(h);
	return 0;
}

/* The native winget tmux, user scope then machine scope. */
static int try_winget_tmux(void)
{
	const char *lad = getenv("LOCALAPPDATA");
	const char *pf = getenv("ProgramFiles");
	char root[MAX_PATH];

	if (lad && *lad) {
		snprintf(root, sizeof(root), "%s\\Microsoft\\WinGet\\Packages",
			 lad);
		if (try_winget_packages(root))
			return 1;
	}
	if (pf && *pf) {
		snprintf(root, sizeof(root), "%s\\WinGet\\Packages", pf);
		if (try_winget_packages(root))
			return 1;
	}
	/* The command alias winget drops on PATH: a symlink to the real exe.
	 * Only consulted if the package scan found nothing, because any
	 * package providing a `tmux` alias lands here. */
	if (try_join(lad, "\\Microsoft\\WinGet\\Links\\tmux.exe"))
		return 1;
	if (try_join(pf, "\\WinGet\\Links\\tmux.exe"))
		return 1;
	return 0;
}

const char *tmux_path(void)
{
	static const char *msys[] = {
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
	 * A tmux.exe placed next to comrade.exe by hand outranks anything
	 * installed, for the same reason %COMRADE_TMUX% does: it is a
	 * deliberate act. The usr\bin form is the MSYS2 layout, kept because
	 * that runtime finds its terminfo database relative to its own DLL and
	 * will not start from a flat directory; a native tmux.exe needs
	 * neither and can simply sit there.
	 */
	if (try_join(exe_dir(), "\\tmux.exe"))
		return found;
	if (try_join(exe_dir(), "\\tmux\\tmux.exe"))
		return found;
	if (try_join(exe_dir(), "\\tmux\\usr\\bin\\tmux.exe"))
		return found;
	if (try_winget_tmux())
		return found;
	for (i = 0; msys[i]; i++)
		if (try_path(msys[i]))
			return found;
	if (SearchPathA(NULL, "tmux.exe", NULL, sizeof(buf), buf, NULL) &&
	    try_path(buf))
		return found;
	if (try_join(getenv("USERPROFILE"), "\\scoop\\shims\\tmux.exe"))
		return found;
	return NULL;
}

/* Forget the cached answer, so an install can be re-checked in place. */
static void tmux_rescan(void)
{
	searched = 0;
	found[0] = '\0';
}

/* winget.exe, or NULL on a Windows without App Installer. */
static const char *winget_exe(void)
{
	static char p[MAX_PATH];
	static int done;
	const char *lad;

	if (done)
		return p[0] ? p : NULL;
	done = 1;
	lad = getenv("LOCALAPPDATA");
	if (lad && *lad) {
		snprintf(p, sizeof(p),
			 "%s\\Microsoft\\WindowsApps\\winget.exe", lad);
		if (is_file(p))
			return p;
	}
	if (SearchPathA(NULL, "winget.exe", NULL, sizeof(p), p, NULL) &&
	    is_file(p))
		return p;
	p[0] = '\0';
	return NULL;
}

static int have_pacman(void)
{
	return is_file(MSYS2_PACMAN);
}

void tmux_missing_help(void)
{
	fprintf(stderr,
"comrade: hosting needs tmux, and there is none on this machine.\n"
"\n"
"  Only hosting needs it -- joining a session (`comrade <token>`) never does,\n"
"  and comrade itself stays one portable .exe. tmux is the one separate piece.\n"
"\n"
"  One command, no admin needed:\n"
"      winget install --id " WINGET_TMUX_ID "\n"
"\n"
"  That is a native build of tmux 3.6a: a single tmux.exe, no Cygwin runtime,\n"
"  no terminfo database, and it runs cmd.exe as its shell.\n"
"\n");
	if (have_pacman())
		fprintf(stderr,
"  You also have MSYS2, whose tmux works just as well if you prefer it:\n"
"      %s -S --needed --noconfirm tmux\n"
"\n", MSYS2_PACMAN);
	else
		fprintf(stderr,
"  MSYS2 users can use theirs instead:\n"
"      %s -S --needed --noconfirm tmux\n"
"\n", MSYS2_PACMAN);
	fprintf(stderr,
"  comrade looks for tmux in %%COMRADE_TMUX%%, next to comrade.exe, in the\n"
"  winget package directory, in %s, and on %%PATH%%.\n", MSYS2_TMUX);
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

/*
 * Both installers are judged by whether a tmux appears, not by the exit code:
 * winget in particular reports failure for "already installed" and for a
 * source-update hiccup that did not stop the package landing.
 */
static int run_winget(void)
{
	char *argv[] = { NULL, "install", "--id", WINGET_TMUX_ID,
			 "--accept-package-agreements",
			 "--accept-source-agreements",
			 "--disable-interactivity", NULL };
	char err[256];
	int rc;

	argv[0] = (char *)winget_exe();
	if (!argv[0])
		return 0;
	fprintf(stderr, "comrade: installing tmux with winget (%s) ...\n",
		WINGET_TMUX_ID);
	rc = win_run_capture(argv, err, sizeof(err));
	tmux_rescan();
	if (tmux_path())
		return 1;
	if (err[0])
		fprintf(stderr, "comrade: winget failed: %s\n", err);
	else
		fprintf(stderr, "comrade: winget install failed (%d)\n", rc);
	return 0;
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
	if (winget_exe() &&
	    confirm("comrade: install tmux with winget now?") &&
	    run_winget())
		return 1;
	if (have_pacman() &&
	    confirm("comrade: install tmux with MSYS2 pacman instead?") &&
	    run_pacman())
		return 1;
	return 0;
}

#endif /* _WIN32 */
