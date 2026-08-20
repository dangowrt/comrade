/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_OSCOMPAT_H
#define COMRADE_OSCOMPAT_H

#include <stddef.h>

/*
 * The handful of non-socket, non-terminal OS calls whose Windows spelling
 * differs enough to matter. Small on purpose: everything else in comrade is
 * either plain C or already covered by wsock.h / tty.h.
 */

/*
 * Atomically replace dst with tmp. POSIX rename(2) does this by definition;
 * Windows rename() *fails* when the destination exists, which would silently
 * turn every cache and status write into a no-op after the first run. Uses
 * MoveFileEx(MOVEFILE_REPLACE_EXISTING) there. Returns 0 on success.
 */
int os_rename_replace(const char *tmp, const char *dst);

/*
 * Run argv to completion and return its exit status (-1 if it could not be
 * started). fork+execvp+waitpid on POSIX; _spawnvp(_P_WAIT) on Windows, which
 * is a CreateProcess wrapper in the CRT and needs no fork.
 */
int os_spawn_wait(char *const argv[]);

/* Writable scratch directory, no trailing slash ("/tmp", or %TEMP%). */
const char *os_tmpdir(void);

/* Process id, for log lines. */
long os_pid(void);

/* Sleep, in milliseconds. */
void os_msleep(int ms);

/*
 * memmem(3). A GNU extension: glibc and the BSDs have it, the Windows CRT
 * does not. The needles here are short literals, so the naive scan costs
 * nothing worth optimising.
 */
const void *os_memmem(const void *hay, size_t haylen,
		      const void *needle, size_t needlelen);

#endif
