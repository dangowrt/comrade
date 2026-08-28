/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "cpty.h"

#ifndef _WIN32

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <signal.h>
#ifdef __APPLE__
#include <util.h>			/* forkpty lives here, not in pty.h */
#else
#include <pty.h>
#endif
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include "dbg.h"
#include "spawner.h"

/*
 * The POSIX half: exactly the forkpty()/fork()+pipe() this used to be inside
 * sshd.c, moved behind cpty.h so the Windows pseudoconsole can take the same
 * shape. Nothing about the behaviour changed.
 */

struct cpty {
	pid_t pid;
	int in;				/* write toward the child */
	int out;			/* read from the child */
	int pty;			/* in == out == the pty master */
	int reaped;			/* cpty_exited took its status */
	int status;
	struct spawner *sp;		/* non-NULL: child lives in the spawner */
	int handle;			/* the spawner's handle for it */
	int exit_fd;			/* readable (1 byte) when it exits */
};

struct cpty *cpty_spawn(const char *command, int use_pty, int rows, int cols,
			const char *term)
{
	const char *base = command ? command : "tmux new-session -A -s comrade";
	struct winsize ws, *wsp = NULL;
	struct cpty *p;
	char cmd[768];
	pid_t c;

	/*
	 * TERM is set through the shell rather than with setenv() after the
	 * fork, which is not async-signal-safe in a threaded process. The
	 * terminal type has already been charset-checked by the caller.
	 */
	if (term && term[0])
		snprintf(cmd, sizeof(cmd), "TERM=%s %s", term, base);
	else
		snprintf(cmd, sizeof(cmd), "%s", base);

	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->in = p->out = -1;

	if (rows > 0 && cols > 0) {
		memset(&ws, 0, sizeof(ws));
		ws.ws_row = (unsigned short)rows;
		ws.ws_col = (unsigned short)cols;
		wsp = &ws;
	}
	dbg_logf("cpty spawn: use_pty=%d size=%dx%d TERM=[%s]", use_pty, rows,
		 cols, term ? term : "");

	if (use_pty) {
		int master;

		c = forkpty(&master, NULL, NULL, wsp);
		if (c < 0) {
			free(p);
			return NULL;
		}
		if (c == 0) {
			execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
			_exit(127);
		}
		p->pid = c;
		p->in = p->out = master;
		p->pty = 1;
		return p;
	} else {
		int in[2], out[2];

		if (pipe(in)) {
			free(p);
			return NULL;
		}
		if (pipe(out)) {
			close(in[0]);
			close(in[1]);
			free(p);
			return NULL;
		}
		c = fork();
		if (c < 0) {
			close(in[0]); close(in[1]);
			close(out[0]); close(out[1]);
			free(p);
			return NULL;
		}
		if (c == 0) {
			dup2(in[0], STDIN_FILENO);
			dup2(out[1], STDOUT_FILENO);
			dup2(out[1], STDERR_FILENO);
			close(in[0]); close(in[1]);
			close(out[0]); close(out[1]);
			execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
			_exit(127);
		}
		close(in[0]);
		close(out[1]);
		p->pid = c;
		p->in = in[1];
		p->out = out[0];
		return p;
	}
}

struct cpty *cpty_spawn_sp(struct spawner *sp, int ro, int use_pty, int rows,
			   int cols, const char *term)
{
	struct cpty *p;
	sock_t in = INVALID_SOCK, out = INVALID_SOCK, ex = INVALID_SOCK;
	int h = -1, fl;

	if (!sp)
		return NULL;
	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->in = p->out = p->exit_fd = -1;
	dbg_logf("cpty spawn_sp: ro=%d use_pty=%d size=%dx%d TERM=[%s]", ro,
		 use_pty, rows, cols, term ? term : "");
	if (spawner_spawn(sp, ro, use_pty, rows, cols, term, &in, &out, &ex,
			  &h) != 0) {
		free(p);
		return NULL;
	}
	/* cpty_exited polls the exit fd without blocking. */
	fl = fcntl(ex, F_GETFL);
	if (fl >= 0)
		fcntl(ex, F_SETFL, fl | O_NONBLOCK);
	p->sp = sp;
	p->handle = h;
	p->in = in;
	p->out = out;
	p->exit_fd = ex;
	p->pty = use_pty ? 1 : 0;
	return p;
}

sock_t cpty_in(const struct cpty *p)
{
	return p ? p->in : INVALID_SOCK;
}

sock_t cpty_out(const struct cpty *p)
{
	return p ? p->out : INVALID_SOCK;
}

void cpty_resize(struct cpty *p, int rows, int cols)
{
	struct winsize ws;

	if (!p || !p->pty || rows <= 0 || cols <= 0)
		return;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = (unsigned short)rows;
	ws.ws_col = (unsigned short)cols;
	ioctl(p->in, TIOCSWINSZ, &ws);
}

int cpty_exited(struct cpty *p)
{
	int status = 0;

	if (!p)
		return 1;
	if (p->reaped)
		return 1;
	if (p->sp) {
		unsigned char b;
		ssize_t r;

		if (p->exit_fd < 0)
			return 1;
		r = read(p->exit_fd, &b, 1);
		if (r == 1) {
			p->reaped = 1;
			p->status = b;
			return 1;
		}
		if (r == 0) {			/* closed without a byte */
			p->reaped = 1;
			return 1;
		}
		return 0;			/* EAGAIN: still running */
	}
	if (p->pid <= 0)
		return 1;
	if (waitpid(p->pid, &status, WNOHANG) != p->pid)
		return 0;
	p->reaped = 1;
	p->status = WIFEXITED(status) ? WEXITSTATUS(status) : 0;
	return 1;
}

int cpty_close(struct cpty *p)
{
	int status = 0;

	if (!p)
		return 0;
	if (p->sp) {
		/* Ask the spawner to stop it, then block for its exit byte
		 * (bounded by the spawner's hang-up-then-kill grace). */
		if (p->reaped) {
			status = p->status;
		} else {
			unsigned char b;
			ssize_t r;
			int fl;

			spawner_close(p->sp, p->handle);
			if (p->exit_fd >= 0) {
				fl = fcntl(p->exit_fd, F_GETFL);
				if (fl >= 0)
					fcntl(p->exit_fd, F_SETFL,
					      fl & ~O_NONBLOCK);
				do {
					r = read(p->exit_fd, &b, 1);
				} while (r < 0 && errno == EINTR);
				if (r == 1)
					status = b;
			}
		}
		if (p->in >= 0)
			close(p->in);
		if (p->out >= 0 && p->out != p->in)
			close(p->out);
		if (p->exit_fd >= 0)
			close(p->exit_fd);
		free(p);
		return status;
	}
	if (p->in >= 0)
		close(p->in);
	if (p->out >= 0 && p->out != p->in)
		close(p->out);
	if (p->reaped) {
		status = p->status;
	} else if (p->pid > 0) {
		kill(p->pid, SIGHUP);
		waitpid(p->pid, &status, 0);
		status = WIFEXITED(status) ? WEXITSTATUS(status) : 0;
	}
	free(p);
	return status;
}

#endif /* !_WIN32 */
