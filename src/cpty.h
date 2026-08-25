/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CPTY_H
#define COMRADE_CPTY_H

#include "wsock.h"

/*
 * A command running on its own terminal: the thing the host serves.
 *
 * On POSIX that is forkpty() plus /bin/sh -c, and the two ends the caller
 * bridges are both the pty master fd. On Windows it is a pseudoconsole
 * (CreatePseudoConsole + STARTUPINFOEX/PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE)
 * whose input and output pipes are HANDLEs -- which WSAPoll will not accept,
 * and which libssh's connectors therefore cannot take either. So the Windows
 * half pumps those HANDLEs to and from a socket each, and hands the sockets
 * back. Either way the caller sees the same shape it always did: one readable
 * end, one writable end, both pollable, both accepted by ssh_connector_set_*_fd.
 *
 * That is the whole point of this file. sshd.c and the host's local attach
 * both drive a terminal-backed child, and neither contains a single #ifdef:
 * the platform difference is spawning, resizing and reaping, and it is here.
 *
 * One Windows subtlety worth recording, because it fails silently otherwise:
 * a ConPTY child only receives the pseudoconsole as its standard handles if
 * the parent passes STARTF_USESTDHANDLES with NULL handles. Without that the
 * child inherits the *parent's* stdio -- so a host started from anything but
 * an interactive console (the detached service, exactly) would run tmux
 * writing to a pipe nobody reads, and Cygwin would report "not a tty". See
 * cpty_win.c.
 */

struct cpty;

/*
 * Run `command` on a terminal `rows` x `cols` (0 for a default), with TERM set
 * to `term` when non-empty so the child renders for the client's real
 * terminal. `command` is a /bin/sh command line; NULL means comrade's default,
 * `tmux new-session -A -s comrade`. use_pty == 0 runs it on plain pipes with
 * no terminal at all. Returns NULL if the child could not be started.
 *
 * On Windows there is no shell, so the command is re-split with the usual
 * quoting rules and run directly, and a leading bare `tmux` is resolved to the
 * tmux.exe this machine actually has (see tmuxpath.h).
 */
struct cpty *cpty_spawn(const char *command, int use_pty, int rows, int cols,
			const char *term);

/* The end to write toward the child, and the end to read from it. On POSIX
 * with a pty these are the same descriptor. */
sock_t cpty_in(const struct cpty *p);
sock_t cpty_out(const struct cpty *p);

/* Terminal resize (SSH window-change): TIOCSWINSZ / ResizePseudoConsole. */
void cpty_resize(struct cpty *p, int rows, int cols);

/* Has the child exited? Non-blocking: waitpid(WNOHANG) /
 * WaitForSingleObject(0). This is the SIGCHLD the port does not have.
 *
 * On POSIX the child IS reaped here, and its status kept for cpty_close.
 * Asking without reaping would want WNOWAIT, which waitpid does not accept
 * -- it belongs to waitid, and waitpid answers EINVAL to it, so the question
 * came back "still running" however long the child had been dead. */
int cpty_exited(struct cpty *p);

/* Stop the child if it is still running, reap it, release everything, and
 * return its exit status (0 if unknown). */
int cpty_close(struct cpty *p);

#endif
