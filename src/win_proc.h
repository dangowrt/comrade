/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_WIN_PROC_H
#define COMRADE_WIN_PROC_H

#ifdef _WIN32

#include <stddef.h>

#include "wsock.h"		/* pulls windows.h, and sock_t for the exit socket */

/*
 * Child processes, Windows-side. This is the fork()/execvp()/waitpid() corner
 * of the host path, gathered in one file so host.c's Windows twin and the
 * ConPTY layer share exactly one spelling of "run a program".
 *
 * Three things that have no Unix counterpart and bite if improvised:
 *
 *  1. CreateProcess takes a *command line*, not an argv, and re-splits it with
 *     the CommandLineToArgvW rules. Every path comrade passes to tmux comes
 *     from %TEMP%, which routinely contains a space ("C:\Users\Jane Doe\..."),
 *     so quoting is not optional. win_cmdline() quotes; win_split() is its
 *     inverse, for the one place (sshd's command string) where comrade's own
 *     shell-shaped command has to become an argv again.
 *  2. A child that daemonises keeps the stderr pipe open forever -- `tmux
 *     new-session -d` leaves exactly that behind -- so reading a captured pipe
 *     to EOF hangs. win_run_capture() drains with PeekNamedPipe and stops when
 *     the *process* exits, never on pipe EOF.
 *  3. There is no SIGCHLD and no waitpid. A process HANDLE is waitable, which
 *     is better, but not by poll(): win_proc_exit_sock() converts one into a
 *     socket that becomes readable when the child exits, so child death joins
 *     the single WSAPoll set the rest of the port is built around.
 */

/* Append `arg` to `buf` as one CommandLineToArgvW-parseable word (quoting and
 * backslash-doubling as needed). Returns 0 on success, -1 if it would not fit. */
int win_quote_append(char *buf, size_t cap, const char *arg);

/* NULL-terminated argv -> one quoted command line. Returns 0 on success. */
int win_cmdline(char *buf, size_t cap, char *const argv[]);

/*
 * Split a command string into argv, honouring "..." (and \" inside it). The
 * pieces are copied into `store`; argv[] points into it and is NULL-terminated.
 * Returns the argument count, or -1 if it would not fit.
 */
int win_split(const char *cmd, char **argv, int maxv, char *store, size_t storecap);

/*
 * An environment block that is this process's environment with TERM set to
 * `term` (and, when `term` is NULL or empty, with TERM removed). Returned
 * block is malloc'd, in CreateProcess's double-NUL form; free() it. NULL means
 * "could not build one", for which the caller passes NULL and inherits.
 */
char *win_env_with_term(const char *term);

/*
 * Run argv to completion with stdin/stdout/stderr on NUL. Returns the child's
 * exit code, or -1 if it could not be started. When `err` is non-NULL the
 * child's stderr is captured into it instead (NUL-terminated, newlines
 * stripped) so a failure can be reported with its real cause.
 */
int win_run(char *const argv[]);
int win_run_capture(char *const argv[], char *err, size_t errcap);

/*
 * Spawn argv detached: DETACHED_PROCESS|CREATE_NO_WINDOW, so it survives the
 * operator's console going away -- the setsid() of this port. stdio goes to
 * NUL. Exactly the handles in `inherit` are inherited (PROC_THREAD_ATTRIBUTE_
 * HANDLE_LIST), so a stray inheritable handle elsewhere in the process cannot
 * leak into the service. Returns the process HANDLE (CloseHandle it) or NULL.
 */
HANDLE win_spawn_detached(char *const argv[], HANDLE *inherit, int ninherit);

/*
 * A socket that becomes readable (POLLHUP, then a 0-byte read) exactly when
 * `proc` exits: the SIGCHLD/waitpid replacement for every poll loop here. A
 * watcher thread owns `proc` and closes it. Returns INVALID_SOCK on failure,
 * in which case the caller still owns `proc`.
 */
sock_t win_proc_exit_sock(HANDLE proc);

#endif /* _WIN32 */

#endif
