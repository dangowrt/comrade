/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "cpty.h"

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include "dbg.h"
#include "tmuxpath.h"
#include "win_proc.h"

/*
 * The pseudoconsole half of cpty.h. See that header for why this exists and
 * what invariant the caller relies on.
 *
 * ConPTY is resolved at run time rather than imported: CreatePseudoConsole
 * arrived in Windows 10 1809, and a statically imported one would stop
 * comrade.exe from *loading at all* on anything older -- including for
 * joining, which needs none of this. Resolved dynamically, an old Windows
 * simply cannot host, and says so.
 */

typedef HRESULT (WINAPI *pfn_create_pc)(COORD, HANDLE, HANDLE, DWORD, HPCON *);
typedef HRESULT (WINAPI *pfn_resize_pc)(HPCON, COORD);
typedef void (WINAPI *pfn_close_pc)(HPCON);

static pfn_create_pc pc_create;
static pfn_resize_pc pc_resize;
static pfn_close_pc pc_close;
static int pc_looked_up;

static int conpty_available(void)
{
	HMODULE k;

	if (!pc_looked_up) {
		pc_looked_up = 1;
		k = GetModuleHandleA("kernel32.dll");
		if (k) {
			pc_create = (pfn_create_pc)(void (*)(void))
				GetProcAddress(k, "CreatePseudoConsole");
			pc_resize = (pfn_resize_pc)(void (*)(void))
				GetProcAddress(k, "ResizePseudoConsole");
			pc_close = (pfn_close_pc)(void (*)(void))
				GetProcAddress(k, "ClosePseudoConsole");
		}
	}
	return pc_create && pc_resize && pc_close;
}

struct cpty {
	HPCON pc;			/* NULL when running on plain pipes */
	HANDLE proc;
	HANDLE h_write;			/* -> the child's input */
	HANDLE h_read;			/* <- the child's output */
	sock_t app_in, br_in;		/* caller writes app_in; thread drains br_in */
	sock_t app_out, br_out;		/* thread fills br_out; caller reads app_out */
	pthread_t th_in, th_out;
	int have_in, have_out;
	volatile int stop;
};

/* socket -> child. */
static void *pump_to_child(void *arg)
{
	struct cpty *p = arg;
	char buf[4096];

	while (!p->stop) {
		int n = recv(p->br_in, buf, sizeof(buf), 0);
		DWORD off = 0;

		if (n <= 0)
			break;
		while (off < (DWORD)n) {
			DWORD w = 0;

			if (!WriteFile(p->h_write, buf + off, (DWORD)n - off,
				       &w, NULL) || !w)
				return NULL;
			off += w;
		}
	}
	return NULL;
}

/* child -> socket. */
static void *pump_from_child(void *arg)
{
	struct cpty *p = arg;
	char buf[4096];

	for (;;) {
		DWORD n = 0;
		int off = 0;

		if (!ReadFile(p->h_read, buf, sizeof(buf), &n, NULL) || !n)
			break;
		while (off < (int)n) {
			int w = send(p->br_out, buf + off, (int)n - off, 0);

			if (w <= 0)
				goto done;
			off += w;
		}
	}
done:
	/* The caller's poll sees POLLHUP and a 0-byte read: the EOF a pty
	 * master would have given when its child went away. */
	sock_shutdown(p->br_out, SHUT_WR);
	return NULL;
}

static int bridges_up(struct cpty *p)
{
	sock_t a[2], b[2];

	if (sock_pair(a))
		return -1;
	if (sock_pair(b)) {
		sock_close(a[0]);
		sock_close(a[1]);
		return -1;
	}
	p->app_in = a[0];
	p->br_in = a[1];
	p->app_out = b[0];
	p->br_out = b[1];
	/* Both caller-facing ends are polled, never blocked on. */
	sock_set_nonblock(p->app_in);
	sock_set_nonblock(p->app_out);
	if (pthread_create(&p->th_in, NULL, pump_to_child, p))
		return -1;
	p->have_in = 1;
	if (pthread_create(&p->th_out, NULL, pump_from_child, p))
		return -1;
	p->have_out = 1;
	return 0;
}

/*
 * comrade builds its own command lines ("tmux -S <path> attach -t comrade"),
 * so the only word that ever needs resolving is a leading bare `tmux`: there
 * is no shell here to search PATH, and on Windows tmux is rarely on it.
 */
static int resolve_argv0(char **argv)
{
	const char *base = argv[0];
	const char *slash = strrchr(base, '\\');

	if (slash)
		return 0;			/* already a path: use it */
	if (_stricmp(base, "tmux") && _stricmp(base, "tmux.exe"))
		return 0;
	argv[0] = (char *)tmux_path();
	return argv[0] ? 0 : -1;
}

static HANDLE spawn_conpty(struct cpty *p, char *cmd, char *env,
			   int rows, int cols)
{
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T asz = 0;
	HANDLE in_r = NULL, out_w = NULL, ret = NULL;
	COORD sz;

	sz.X = (SHORT)(cols > 0 ? cols : 80);
	sz.Y = (SHORT)(rows > 0 ? rows : 24);

	if (!CreatePipe(&in_r, &p->h_write, NULL, 0))
		return NULL;
	if (!CreatePipe(&p->h_read, &out_w, NULL, 0)) {
		CloseHandle(in_r);
		return NULL;
	}
	if (pc_create(sz, in_r, out_w, 0, &p->pc) != S_OK)
		p->pc = NULL;
	CloseHandle(in_r);			/* the pseudoconsole owns them now */
	CloseHandle(out_w);
	if (!p->pc)
		return NULL;

	memset(&si, 0, sizeof(si));
	si.StartupInfo.cb = sizeof(si);
	/*
	 * The one non-obvious line in this file. Without STARTF_USESTDHANDLES
	 * the child keeps whatever stdio the *parent* had, and the
	 * pseudoconsole is attached but unused: tmux then writes to a pipe
	 * nobody reads and Cygwin reports "not a tty". NULL handles plus the
	 * flag is what makes the console subsystem hand the child the
	 * pseudoconsole's own handles. Measured, not guessed -- a host started
	 * from the detached service (no console of its own) fails exactly this
	 * way otherwise.
	 */
	si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
	si.StartupInfo.hStdInput = NULL;
	si.StartupInfo.hStdOutput = NULL;
	si.StartupInfo.hStdError = NULL;

	InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
	si.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, asz);
	if (!si.lpAttributeList)
		return NULL;
	if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &asz) ||
	    !UpdateProcThreadAttribute(si.lpAttributeList, 0,
				       PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
				       p->pc, sizeof(p->pc), NULL, NULL))
		goto out;

	memset(&pi, 0, sizeof(pi));
	if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
			   EXTENDED_STARTUPINFO_PRESENT, env, NULL,
			   &si.StartupInfo, &pi)) {
		CloseHandle(pi.hThread);
		ret = pi.hProcess;
	}
out:
	DeleteProcThreadAttributeList(si.lpAttributeList);
	HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
	return ret;
}

/* No terminal wanted: plain anonymous pipes, stdout and stderr joined, which
 * is what the POSIX side's pipe path does too. */
static HANDLE spawn_pipes(struct cpty *p, char *cmd, char *env)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE in_r = NULL, out_w = NULL, ret = NULL;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&in_r, &p->h_write, &sa, 0))
		return NULL;
	if (!CreatePipe(&p->h_read, &out_w, &sa, 0)) {
		CloseHandle(in_r);
		return NULL;
	}
	SetHandleInformation(p->h_write, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(p->h_read, HANDLE_FLAG_INHERIT, 0);

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = in_r;
	si.hStdOutput = out_w;
	si.hStdError = out_w;
	memset(&pi, 0, sizeof(pi));
	if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
			   env, NULL, &si, &pi)) {
		CloseHandle(pi.hThread);
		ret = pi.hProcess;
	}
	CloseHandle(in_r);
	CloseHandle(out_w);
	return ret;
}

struct cpty *cpty_spawn(const char *command, int use_pty, int rows, int cols,
			const char *term)
{
	const char *base = command ? command : "tmux new-session -A -s comrade";
	char store[1024], cmd[2048];
	char *argv[64];
	struct cpty *p;
	char *env;

	if (use_pty && !conpty_available()) {
		fprintf(stderr, "comrade: this Windows has no ConPTY "
			"(needs Windows 10 1809 or newer) -- cannot host\n");
		return NULL;
	}
	if (win_split(base, argv, 64, store, sizeof(store)) < 1)
		return NULL;
	if (resolve_argv0(argv)) {
		tmux_missing_help();
		return NULL;
	}
	if (win_cmdline(cmd, sizeof(cmd), argv))
		return NULL;

	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->app_in = p->br_in = p->app_out = p->br_out = INVALID_SOCK;

	dbg_logf("cpty spawn: use_pty=%d size=%dx%d TERM=[%s] cmd=[%s]",
		 use_pty, rows, cols, term ? term : "", cmd);

	env = win_env_with_term(term);
	p->proc = use_pty ? spawn_conpty(p, cmd, env, rows, cols)
			  : spawn_pipes(p, cmd, env);
	free(env);
	if (!p->proc || bridges_up(p)) {
		cpty_close(p);
		return NULL;
	}
	return p;
}

sock_t cpty_in(const struct cpty *p)
{
	return p ? p->app_in : INVALID_SOCK;
}

sock_t cpty_out(const struct cpty *p)
{
	return p ? p->app_out : INVALID_SOCK;
}

void cpty_resize(struct cpty *p, int rows, int cols)
{
	COORD sz;

	if (!p || !p->pc || rows <= 0 || cols <= 0)
		return;
	sz.X = (SHORT)cols;
	sz.Y = (SHORT)rows;
	pc_resize(p->pc, sz);
}

int cpty_exited(const struct cpty *p)
{
	if (!p || !p->proc)
		return 1;
	return WaitForSingleObject(p->proc, 0) == WAIT_OBJECT_0;
}

int cpty_close(struct cpty *p)
{
	DWORD code = 0;

	if (!p)
		return 0;
	p->stop = 1;

	/*
	 * Order matters. Stop the child first, so ClosePseudoConsole has no
	 * attached client to wait for; only then close the pseudoconsole, which
	 * breaks the output pipe and releases the reader thread. Closing the
	 * pseudoconsole while the child is alive and the reader is not draining
	 * is the documented way to hang here.
	 */
	if (p->proc) {
		if (WaitForSingleObject(p->proc, 0) != WAIT_OBJECT_0)
			TerminateProcess(p->proc, 1);
		WaitForSingleObject(p->proc, 2000);
		GetExitCodeProcess(p->proc, &code);
		CloseHandle(p->proc);
		p->proc = NULL;
	}
	if (p->pc) {
		pc_close(p->pc);
		p->pc = NULL;
	}
	if (p->h_write) {
		CloseHandle(p->h_write);
		p->h_write = NULL;
	}
	if (p->have_in) {
		/* Parked in recv() on the bridge end; closing the caller's end
		 * is not enough, shut this one down explicitly. */
		sock_shutdown(p->br_in, SHUT_RDWR);
		pthread_join(p->th_in, NULL);
	}
	if (p->have_out)
		pthread_join(p->th_out, NULL);
	if (p->h_read)
		CloseHandle(p->h_read);
	if (sock_valid(p->app_in))
		sock_close(p->app_in);
	if (sock_valid(p->br_in))
		sock_close(p->br_in);
	if (sock_valid(p->app_out))
		sock_close(p->app_out);
	if (sock_valid(p->br_out))
		sock_close(p->br_out);
	free(p);
	return (int)(code == STILL_ACTIVE ? 0 : code);
}

#endif /* _WIN32 */
