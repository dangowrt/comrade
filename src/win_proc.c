/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdlib.h>
#include <string.h>

#include "win_proc.h"

#ifdef _WIN32

#include <pthread.h>

/* ---- command line quoting (see the header) ---- */

static int needs_quote(const char *a)
{
	if (!*a)
		return 1;
	return strpbrk(a, " \t\n\v\"") != NULL;
}

int win_quote_append(char *buf, size_t cap, const char *arg)
{
	size_t n = strlen(buf);
	size_t i;

	if (n && n + 1 < cap)
		buf[n++] = ' ';
	if (!needs_quote(arg)) {
		size_t l = strlen(arg);

		if (n + l + 1 > cap)
			return -1;
		memcpy(buf + n, arg, l + 1);
		return 0;
	}
	if (n + 1 >= cap)
		return -1;
	buf[n++] = '"';
	for (i = 0; arg[i]; i++) {
		size_t bs = 0;

		while (arg[i] == '\\') {	/* backslashes are literal unless
						 * they precede a quote, where they
						 * must be doubled */
			bs++;
			i++;
		}
		if (!arg[i]) {
			bs *= 2;
			while (bs--) {
				if (n + 2 >= cap)
					return -1;
				buf[n++] = '\\';
			}
			break;
		}
		if (arg[i] == '"')
			bs = bs * 2 + 1;
		while (bs--) {
			if (n + 2 >= cap)
				return -1;
			buf[n++] = '\\';
		}
		if (n + 2 >= cap)
			return -1;
		buf[n++] = arg[i];
	}
	if (n + 2 > cap)
		return -1;
	buf[n++] = '"';
	buf[n] = '\0';
	return 0;
}

int win_cmdline(char *buf, size_t cap, char *const argv[])
{
	int i;

	if (!cap)
		return -1;
	buf[0] = '\0';
	for (i = 0; argv[i]; i++)
		if (win_quote_append(buf, cap, argv[i]))
			return -1;
	return 0;
}

int win_split(const char *cmd, char **argv, int maxv, char *store, size_t storecap)
{
	size_t o = 0;
	int n = 0;

	while (*cmd) {
		int q = 0;

		while (*cmd == ' ' || *cmd == '\t')
			cmd++;
		if (!*cmd)
			break;
		if (n + 1 >= maxv)
			return -1;
		argv[n++] = store + o;
		while (*cmd && (q || (*cmd != ' ' && *cmd != '\t'))) {
			size_t bs = 0;

			while (*cmd == '\\') {	/* count a backslash run */
				bs++;
				cmd++;
			}
			if (*cmd == '"') {
				/* Invert win_quote_append: 2n backslashes then
				 * a quote are n literal backslashes and a quote
				 * that toggles; 2n+1 are n backslashes and a
				 * literal quote. */
				size_t half = bs / 2;

				while (half--) {
					if (o + 1 >= storecap)
						return -1;
					store[o++] = '\\';
				}
				if (bs & 1) {
					if (o + 1 >= storecap)
						return -1;
					store[o++] = '"';
				} else {
					q = !q;
				}
				cmd++;
			} else {
				while (bs--) {	/* backslashes not before a quote
						 * are literal */
					if (o + 1 >= storecap)
						return -1;
					store[o++] = '\\';
				}
				if (*cmd && (q || (*cmd != ' ' && *cmd != '\t'))) {
					if (o + 1 >= storecap)
						return -1;
					store[o++] = *cmd++;
				}
			}
		}
		if (o + 1 > storecap)
			return -1;
		store[o++] = '\0';
	}
	argv[n] = NULL;
	return n;
}

/* ---- environment ---- */

char *win_env_with_term(const char *term)
{
	char *src = GetEnvironmentStringsA();
	char *out, *p, *w;
	size_t len = 0, add;

	if (!src)
		return NULL;
	for (p = src; *p; p += strlen(p) + 1)
		len += strlen(p) + 1;
	add = (term && *term) ? strlen("TERM=") + strlen(term) + 1 : 0;
	out = malloc(len + add + 2);
	if (!out) {
		FreeEnvironmentStringsA(src);
		return NULL;
	}
	w = out;
	for (p = src; *p; p += strlen(p) + 1) {
		if (!_strnicmp(p, "TERM=", 5))
			continue;		/* replaced (or dropped) below */
		strcpy(w, p);
		w += strlen(p) + 1;
	}
	FreeEnvironmentStringsA(src);
	if (add) {
		strcpy(w, "TERM=");
		strcat(w, term);
		w += add;
	}
	*w = '\0';				/* the block's terminating NUL */
	return out;
}

/* ---- running a child to completion ---- */

static HANDLE open_nul(int write)
{
	SECURITY_ATTRIBUTES sa;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	return CreateFileA("NUL", write ? GENERIC_WRITE : GENERIC_READ,
			   FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
			   OPEN_EXISTING, 0, NULL);
}

/* Strip trailing CR/LF, the shape run_capture's callers print. */
static void chomp(char *s)
{
	size_t l = strlen(s);

	while (l && (s[l - 1] == '\n' || s[l - 1] == '\r'))
		s[--l] = '\0';
}

int win_run_capture(char *const argv[], char *err, size_t errcap)
{
	char cmd[2048];
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE nul_in = INVALID_HANDLE_VALUE, nul_out = INVALID_HANDLE_VALUE;
	HANDLE er = NULL, ew = NULL;
	size_t got = 0;
	DWORD code = (DWORD)-1;
	int rc = -1;

	if (err && errcap)
		err[0] = '\0';
	if (win_cmdline(cmd, sizeof(cmd), argv))
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	nul_in = open_nul(0);
	nul_out = open_nul(1);
	if (err && errcap > 1) {
		if (!CreatePipe(&er, &ew, &sa, 0))
			er = ew = NULL;
		else
			SetHandleInformation(er, HANDLE_FLAG_INHERIT, 0);
	}

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = nul_in;
	si.hStdOutput = nul_out;
	si.hStdError = ew ? ew : nul_out;
	memset(&pi, 0, sizeof(pi));

	if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
			    CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
		goto out;
	if (ew) {
		CloseHandle(ew);
		ew = NULL;
	}
	/*
	 * Never read to EOF: `tmux new-session -d` leaves a server holding this
	 * pipe's write end for the life of the session, so EOF may never come.
	 * Poll instead, and stop when the process we started has exited.
	 */
	for (;;) {
		DWORD avail = 0, n = 0;
		int done = WaitForSingleObject(pi.hProcess, 20) == WAIT_OBJECT_0;

		if (er && PeekNamedPipe(er, NULL, 0, NULL, &avail, NULL) && avail) {
			if (avail > errcap - 1 - got)
				avail = (DWORD)(errcap - 1 - got);
			if (avail && ReadFile(er, err + got, avail, &n, NULL)) {
				got += n;
				err[got] = '\0';
			}
			if (got < errcap - 1)
				continue;	/* more may be waiting */
		}
		if (done)
			break;
	}
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	rc = (int)code;
	if (err)
		chomp(err);
out:
	if (er)
		CloseHandle(er);
	if (ew)
		CloseHandle(ew);
	if (nul_in != INVALID_HANDLE_VALUE)
		CloseHandle(nul_in);
	if (nul_out != INVALID_HANDLE_VALUE)
		CloseHandle(nul_out);
	return rc;
}

int win_run(char *const argv[])
{
	return win_run_capture(argv, NULL, 0);
}

HANDLE win_spawn_detached(char *const argv[], HANDLE *inherit, int ninherit)
{
	char cmd[2048];
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T asz = 0;
	HANDLE nul_in, nul_out, ret = NULL;
	HANDLE hl[8];
	int nhl = 0, i;

	if (ninherit > (int)(sizeof(hl) / sizeof(hl[0])) - 2)
		return NULL;
	if (win_cmdline(cmd, sizeof(cmd), argv))
		return NULL;

	nul_in = open_nul(0);
	nul_out = open_nul(1);
	if (nul_in == INVALID_HANDLE_VALUE || nul_out == INVALID_HANDLE_VALUE)
		goto out_nul;

	memset(&si, 0, sizeof(si));
	si.StartupInfo.cb = sizeof(si);
	si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
	si.StartupInfo.hStdInput = nul_in;
	si.StartupInfo.hStdOutput = nul_out;
	si.StartupInfo.hStdError = nul_out;

	hl[nhl++] = nul_in;
	hl[nhl++] = nul_out;
	for (i = 0; i < ninherit; i++) {
		SetHandleInformation(inherit[i], HANDLE_FLAG_INHERIT,
				     HANDLE_FLAG_INHERIT);
		hl[nhl++] = inherit[i];
	}

	InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
	si.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, asz);
	if (!si.lpAttributeList)
		goto out_nul;
	if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &asz) ||
	    !UpdateProcThreadAttribute(si.lpAttributeList, 0,
				       PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
				       hl, (SIZE_T)nhl * sizeof(HANDLE),
				       NULL, NULL))
		goto out_attr;

	memset(&pi, 0, sizeof(pi));
	if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
			   DETACHED_PROCESS | CREATE_NO_WINDOW |
			   EXTENDED_STARTUPINFO_PRESENT,
			   NULL, NULL, &si.StartupInfo, &pi)) {
		CloseHandle(pi.hThread);
		ret = pi.hProcess;
	}

out_attr:
	DeleteProcThreadAttributeList(si.lpAttributeList);
	HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
out_nul:
	if (nul_in != INVALID_HANDLE_VALUE)
		CloseHandle(nul_in);
	if (nul_out != INVALID_HANDLE_VALUE)
		CloseHandle(nul_out);
	return ret;
}

/* ---- process exit as a pollable socket ---- */

struct exit_watch {
	HANDLE proc;
	sock_t s;
};

static void *exit_watch_fn(void *arg)
{
	struct exit_watch *w = arg;

	WaitForSingleObject(w->proc, INFINITE);
	CloseHandle(w->proc);
	/* Shutting the write side down is what the reader sees: POLLHUP and a
	 * 0-byte read, i.e. exactly the EOF a Unix pipe would have given. */
	sock_shutdown(w->s, SHUT_WR);
	sock_close(w->s);
	free(w);
	return NULL;
}

sock_t win_proc_exit_sock(HANDLE proc)
{
	struct exit_watch *w;
	pthread_t th;
	sock_t sv[2];

	if (!proc || proc == INVALID_HANDLE_VALUE)
		return INVALID_SOCK;
	w = malloc(sizeof(*w));
	if (!w)
		return INVALID_SOCK;
	if (sock_pair(sv)) {
		free(w);
		return INVALID_SOCK;
	}
	w->proc = proc;
	w->s = sv[1];
	if (pthread_create(&th, NULL, exit_watch_fn, w)) {
		sock_close(sv[0]);
		sock_close(sv[1]);
		free(w);
		return INVALID_SOCK;
	}
	pthread_detach(th);
	return sv[0];
}

#endif /* _WIN32 */
