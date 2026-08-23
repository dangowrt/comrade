/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oscompat.h"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <process.h>

int os_rename_replace(const char *tmp, const char *dst)
{
	return MoveFileExA(tmp, dst, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
}

long os_getpid(void)
{
	return (long)GetCurrentProcessId();
}

int os_spawn_wait(char *const argv[])
{
	intptr_t rc = _spawnvp(_P_WAIT, argv[0], (const char *const *)argv);

	return rc < 0 ? -1 : (int)rc;
}

const char *os_tmpdir(void)
{
	const char *t = getenv("TEMP");

	if (!t || !*t)
		t = getenv("TMP");
	if (!t || !*t)
		t = "C:\\Windows\\Temp";
	return t;
}

long os_pid(void)
{
	return (long)GetCurrentProcessId();
}

void os_msleep(int ms)
{
	Sleep((DWORD)ms);
}

uint64_t os_mono_ms(void)
{
	return (uint64_t)GetTickCount64();
}

#else /* !_WIN32 */

#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

int os_rename_replace(const char *tmp, const char *dst)
{
	return rename(tmp, dst);
}

long os_getpid(void)
{
	return (long)getpid();
}

int os_spawn_wait(char *const argv[])
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;
	if (pid == 0) {
		execvp(argv[0], argv);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

const char *os_tmpdir(void)
{
	const char *t = getenv("TMPDIR");

	return (t && *t) ? t : "/tmp";
}

long os_pid(void)
{
	return (long)getpid();
}

void os_msleep(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

uint64_t os_mono_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)(t.tv_nsec / 1000000);
}

#endif /* _WIN32 */

const void *os_memmem(const void *hay, size_t haylen,
		      const void *needle, size_t needlelen)
{
#ifdef _WIN32
	const unsigned char *h = hay;
	size_t i;

	if (!needlelen)
		return hay;
	if (haylen < needlelen)
		return NULL;
	for (i = 0; i + needlelen <= haylen; i++)
		if (!memcmp(h + i, needle, needlelen))
			return h + i;
	return NULL;
#else
	return memmem(hay, haylen, needle, needlelen);
#endif
}
