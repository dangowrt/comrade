/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "spawner.h"

#ifndef _WIN32

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>
#include <poll.h>
#ifdef __APPLE__
#include <util.h>			/* forkpty lives here, not in pty.h */
#else
#include <pty.h>
#endif
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "dbg.h"

/*
 * The wire is fixed-size messages so there is never a length to frame: a
 * request is always a struct sp_req, a reply always a struct sp_rep, and the
 * descriptors a reply carries ride along as SCM_RIGHTS ancillary data. The
 * service holds a mutex across each send-then-receive, and the spawner answers
 * in arrival order, so a reply -- and its passed fds -- can only reach the
 * caller that asked.
 */

enum {
	SP_ALIVE = 1,			/* -> alive 0/1 */
	SP_KILL,			/* tmux kill-server */
	SP_ENDMON,			/* -> handle + 1 fd (session-end read end) */
	SP_SPAWN,			/* -> handle + io fds + exit-notify fd */
	SP_CLOSE			/* stop a handle */
};

struct sp_req {
	uint8_t op;
	uint8_t ro;
	uint8_t use_pty;
	uint8_t pad;
	uint16_t rows;
	uint16_t cols;
	uint32_t handle;
	char term[64];
};

struct sp_rep {
	uint8_t ok;
	uint8_t use_pty;
	uint8_t alive;
	uint8_t nfds;
	uint32_t handle;
};

#define SP_MAX_FDS 3

struct spawner {
	pid_t pid;			/* the spawner child */
	int ctl;			/* our end of the control socketpair */
	pthread_mutex_t mtx;
	int dead;			/* the child has been seen gone */
};

/* ---- shared small I/O helpers ---- */

static int write_all(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	ssize_t w;

	while (n > 0) {
		w = write(fd, p, n);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (w == 0)
			return -1;
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

/* Read exactly n bytes plus any descriptors that arrive with them. Returns 0 on
 * success, -1 on error or a closed peer; *nfds is set to the count received. */
static int recv_msg(int fd, void *buf, size_t n, int *fds, int maxfds, int *nfds)
{
	char cbuf[CMSG_SPACE(SP_MAX_FDS * sizeof(int))];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *c;
	char *p = buf;
	size_t left = n;
	ssize_t r;

	*nfds = 0;
	while (left > 0) {
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = p;
		iov.iov_len = left;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		r = recvmsg(fd, &msg, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return -1;	/* peer closed */
		for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
			if (c->cmsg_level == SOL_SOCKET &&
			    c->cmsg_type == SCM_RIGHTS) {
				int got = (int)((c->cmsg_len -
						 CMSG_LEN(0)) / sizeof(int));
				int k;

				for (k = 0; k < got; k++) {
					int nf;

					memcpy(&nf, CMSG_DATA(c) + k *
					       sizeof(int), sizeof(int));
					if (*nfds < maxfds)
						fds[(*nfds)++] = nf;
					else
						close(nf);
				}
			}
		}
		p += r;
		left -= (size_t)r;
	}
	return 0;
}

/* Send n bytes plus nfds descriptors (which attach to the first byte). */
static int send_msg(int fd, const void *buf, size_t n, const int *fds, int nfds)
{
	char cbuf[CMSG_SPACE(SP_MAX_FDS * sizeof(int))];
	struct msghdr msg;
	struct iovec iov;
	ssize_t w;

	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	iov.iov_base = (void *)buf;
	iov.iov_len = n;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (nfds > 0) {
		struct cmsghdr *c;

		msg.msg_control = cbuf;
		msg.msg_controllen = CMSG_SPACE(nfds * sizeof(int));
		c = CMSG_FIRSTHDR(&msg);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(nfds * sizeof(int));
		memcpy(CMSG_DATA(c), fds, nfds * sizeof(int));
	}
	do {
		w = sendmsg(fd, &msg, 0);
	} while (w < 0 && errno == EINTR);
	if (w != (ssize_t)n)
		return -1;		/* the small header is sent atomically */
	return 0;
}

/* ================= the spawner child ================= */

static uint64_t mono_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)(t.tv_nsec / 1000000);
}

/* TERM is spliced into a shell command line, so only a safe alphabet passes. */
static int safe_term(const char *t)
{
	size_t i;

	if (!t || !t[0] || strlen(t) >= 40)
		return 0;
	for (i = 0; t[i]; i++) {
		char c = t[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '.' ||
		      c == '_' || c == '+'))
			return 0;
	}
	return 1;
}

#define SP_MAX_HANDLES 40
#define SP_KILL_GRACE_MS 250

struct sp_child {
	int used;
	uint32_t id;
	pid_t pid;
	int exit_wfd;			/* write the exit byte here, or -1 */
	uint64_t kill_at;		/* SIGKILL deadline, 0 = none */
};

struct sp_state {
	int ctl;
	const char *sock;
	char attach[600];
	char attach_ro[600];
	struct sp_child kids[SP_MAX_HANDLES];
	uint32_t next_id;
};

static struct sp_child *sp_slot(struct sp_state *s)
{
	int i;

	for (i = 0; i < SP_MAX_HANDLES; i++)
		if (!s->kids[i].used)
			return &s->kids[i];
	return NULL;
}

static struct sp_child *sp_find(struct sp_state *s, uint32_t id)
{
	int i;

	for (i = 0; i < SP_MAX_HANDLES; i++)
		if (s->kids[i].used && s->kids[i].id == id)
			return &s->kids[i];
	return NULL;
}

/* Run one tmux argv to completion, silencing its stderr; return exit status. */
static int sp_run(char *const argv[])
{
	pid_t c = fork();
	int st;

	if (c < 0)
		return -1;
	if (c == 0) {
		int nul = open("/dev/null", O_WRONLY);

		if (nul >= 0) {
			dup2(nul, STDERR_FILENO);
			if (nul > STDERR_FILENO)
				close(nul);
		}
		execvp(argv[0], argv);
		_exit(127);
	}
	while (waitpid(c, &st, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Spawn `tmux wait-for`; return the readable end of its stdout (EOF when the
 * session ends) and the child pid. */
static int sp_endmon(struct sp_state *s, pid_t *pid)
{
	char *argv[] = { "tmux", "-S", (char *)0, "wait-for",
			 "comrade-session", (char *)0 };
	int p[2];
	pid_t c;

	argv[2] = (char *)s->sock;
	if (pipe(p))
		return -1;
	c = fork();
	if (c < 0) {
		close(p[0]);
		close(p[1]);
		return -1;
	}
	if (c == 0) {
		int nul = open("/dev/null", O_RDWR);

		if (nul >= 0) {
			dup2(nul, STDIN_FILENO);
			dup2(nul, STDERR_FILENO);
			if (nul > STDERR_FILENO)
				close(nul);
		}
		dup2(p[1], STDOUT_FILENO);
		close(p[0]);
		close(p[1]);
		execvp("tmux", argv);
		_exit(127);
	}
	close(p[1]);
	*pid = c;
	return p[0];
}

/*
 * Spawn a tmux attach on a pty (or pipes); fill io[] with the fd(s) to bridge
 * (one for a pty, two for pipes) and *pid. TERM is set through the shell, which
 * is not async-signal-safe to do after the fork in a threaded process --
 * although the spawner is single-threaded, the shell path is kept for parity.
 */
static int sp_attach(struct sp_state *s, int ro, int use_pty, int rows, int cols,
		     const char *term, int io[2], int *npty, pid_t *pid)
{
	const char *base = ro ? s->attach_ro : s->attach;
	char cmd[720];
	pid_t c;

	if (safe_term(term))
		snprintf(cmd, sizeof(cmd), "TERM=%s %s", term, base);
	else
		snprintf(cmd, sizeof(cmd), "%s", base);

	if (use_pty) {
		struct winsize ws, *wsp = NULL;
		int master;

		if (rows > 0 && cols > 0) {
			memset(&ws, 0, sizeof(ws));
			ws.ws_row = (unsigned short)rows;
			ws.ws_col = (unsigned short)cols;
			wsp = &ws;
		}
		c = forkpty(&master, NULL, NULL, wsp);
		if (c < 0)
			return -1;
		if (c == 0) {
			execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
			_exit(127);
		}
		io[0] = master;
		*npty = 1;
		*pid = c;
		return 0;
	} else {
		int in[2], out[2];

		if (pipe(in))
			return -1;
		if (pipe(out)) {
			close(in[0]);
			close(in[1]);
			return -1;
		}
		c = fork();
		if (c < 0) {
			close(in[0]); close(in[1]);
			close(out[0]); close(out[1]);
			return -1;
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
		io[0] = in[1];
		io[1] = out[0];
		*npty = 2;
		*pid = c;
		return 0;
	}
}

/* Reap any exited spawn/endmon children, delivering the exit byte for those
 * that carry an exit-notify pipe. */
static void sp_reap(struct sp_state *s)
{
	pid_t c;
	int st;

	while ((c = waitpid(-1, &st, WNOHANG)) > 0) {
		struct sp_child *k = NULL;
		int i;

		for (i = 0; i < SP_MAX_HANDLES; i++) {
			if (s->kids[i].used && s->kids[i].pid == c) {
				k = &s->kids[i];
				break;
			}
		}
		if (!k)
			continue;
		if (k->exit_wfd >= 0) {
			unsigned char b = (unsigned char)
				(WIFEXITED(st) ? WEXITSTATUS(st) : 0);

			(void)write(k->exit_wfd, &b, 1);	/* reader may be gone */
			close(k->exit_wfd);
		}
		k->used = 0;
	}
}

/*
 * A child's exit wakes the poll loop at once through this self-pipe, so a
 * reaped terminal's exit byte reaches the waiting worker without the latency of
 * the loop's timeout. The handler only nudges the pipe; the reaping is done in
 * the loop, and stays clear of the synchronous waits the alive/kill handlers do
 * on their own children (those complete before the loop runs sp_reap).
 */
static volatile sig_atomic_t g_chld_w = -1;

static void on_sigchld(int sig)
{
	char b = 1;
	ssize_t n;

	(void)sig;
	if (g_chld_w >= 0) {
		n = write((int)g_chld_w, &b, 1);
		(void)n;
	}
}

/* SIGKILL any handle whose hang-up grace has elapsed. */
static void sp_escalate(struct sp_state *s)
{
	uint64_t now = mono_ms();
	int i;

	for (i = 0; i < SP_MAX_HANDLES; i++) {
		if (s->kids[i].used && s->kids[i].kill_at &&
		    now >= s->kids[i].kill_at) {
			kill(s->kids[i].pid, SIGKILL);
			s->kids[i].kill_at = 0;
		}
	}
}

static void sp_handle(struct sp_state *s, const struct sp_req *req)
{
	struct sp_rep rep;
	int fds[SP_MAX_FDS];
	int nfds = 0;

	memset(&rep, 0, sizeof(rep));

	switch (req->op) {
	case SP_ALIVE: {
		char *a[] = { "tmux", "-S", (char *)s->sock, "has-session",
			      "-t", "comrade", (char *)0 };

		a[2] = (char *)s->sock;
		rep.ok = 1;
		rep.alive = (sp_run(a) == 0) ? 1 : 0;
		break;
	}
	case SP_KILL: {
		char *a[] = { "tmux", "-S", (char *)s->sock, "kill-server",
			      (char *)0 };

		a[2] = (char *)s->sock;
		sp_run(a);
		rep.ok = 1;
		break;
	}
	case SP_ENDMON: {
		struct sp_child *k = sp_slot(s);
		pid_t pid;
		int rfd;

		if (!k) {
			rep.ok = 0;
			break;
		}
		rfd = sp_endmon(s, &pid);
		if (rfd < 0) {
			rep.ok = 0;
			break;
		}
		k->used = 1;
		k->id = ++s->next_id;
		k->pid = pid;
		k->exit_wfd = -1;
		k->kill_at = 0;
		rep.ok = 1;
		rep.handle = k->id;
		fds[nfds++] = rfd;
		break;
	}
	case SP_SPAWN: {
		struct sp_child *k = sp_slot(s);
		int io[2], npty = 0, ep[2];
		pid_t pid;

		if (!k) {
			rep.ok = 0;
			break;
		}
		if (pipe(ep)) {
			rep.ok = 0;
			break;
		}
		if (sp_attach(s, req->ro, req->use_pty, req->rows, req->cols,
			      req->term, io, &npty, &pid)) {
			close(ep[0]);
			close(ep[1]);
			rep.ok = 0;
			break;
		}
		k->used = 1;
		k->id = ++s->next_id;
		k->pid = pid;
		k->exit_wfd = ep[1];
		k->kill_at = 0;
		rep.ok = 1;
		rep.use_pty = (uint8_t)(npty == 1);
		rep.handle = k->id;
		fds[nfds++] = io[0];
		if (npty == 2)
			fds[nfds++] = io[1];
		fds[nfds++] = ep[0];
		break;
	}
	case SP_CLOSE: {
		struct sp_child *k = sp_find(s, req->handle);

		if (k) {
			kill(k->pid, SIGHUP);
			k->kill_at = mono_ms() + SP_KILL_GRACE_MS;
		}
		rep.ok = 1;
		break;
	}
	default:
		rep.ok = 0;
		break;
	}

	rep.nfds = (uint8_t)nfds;
	if (send_msg(s->ctl, &rep, sizeof(rep), fds, nfds) != 0) {
		/* The service is gone; drop the fds we were about to hand it. */
		int i;

		for (i = 0; i < nfds; i++)
			close(fds[i]);
	} else {
		int i;

		/* The service now holds copies; release ours. */
		for (i = 0; i < nfds; i++)
			close(fds[i]);
	}
}

/* The spawner's whole life: serve requests, reap children, escalate kills,
 * exit when the control channel closes. Never returns. */
static void sp_child_main(int ctl, const char *sock)
{
	struct sp_state s;
	struct pollfd pfd[2];
	struct sigaction sa;
	int devnull, fd, maxfd, sig_p[2], sig_r, nfd;

	/* Hygiene: shed every inherited descriptor but the control channel,
	 * blind the standard ones, ignore the signals that would kill it, and
	 * make its inherited memory undumpable. */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
#ifdef __linux__
	prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

	devnull = open("/dev/null", O_RDWR);
	maxfd = (int)sysconf(_SC_OPEN_MAX);
	if (maxfd < 0 || maxfd > 4096)
		maxfd = 4096;
	for (fd = 3; fd < maxfd; fd++) {
		if (fd != ctl && fd != devnull)
			close(fd);
	}
	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}

	memset(&s, 0, sizeof(s));
	s.ctl = ctl;
	s.sock = sock;
	snprintf(s.attach, sizeof(s.attach), "tmux -S %s attach -t comrade",
		 sock);
	snprintf(s.attach_ro, sizeof(s.attach_ro),
		 "tmux -S %s attach -r -t comrade", sock);
	for (fd = 0; fd < SP_MAX_HANDLES; fd++)
		s.kids[fd].exit_wfd = -1;

	/* A self-pipe fed by SIGCHLD, so an exited child wakes the loop at once. */
	sig_r = -1;
	if (pipe(sig_p) == 0) {
		fcntl(sig_p[0], F_SETFL, fcntl(sig_p[0], F_GETFL) | O_NONBLOCK);
		fcntl(sig_p[1], F_SETFL, fcntl(sig_p[1], F_GETFL) | O_NONBLOCK);
		g_chld_w = sig_p[1];
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_sigchld;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
		sigaction(SIGCHLD, &sa, NULL);
		sig_r = sig_p[0];
	}

	for (;;) {
		int rc;

		pfd[0].fd = ctl;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = sig_r;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
		nfd = (sig_r >= 0) ? 2 : 1;
		rc = poll(pfd, nfd, SP_KILL_GRACE_MS);
		if (rc < 0 && errno != EINTR)
			break;
		if (rc > 0 && sig_r >= 0 && (pfd[1].revents & POLLIN)) {
			char drain[64];

			while (read(sig_r, drain, sizeof(drain)) > 0)
				;	/* just a wakeup; the reap is below */
		}
		if (rc > 0 && (pfd[0].revents & POLLIN)) {
			struct sp_req req;
			int fds[SP_MAX_FDS], nfds;

			if (recv_msg(ctl, &req, sizeof(req), fds, SP_MAX_FDS,
				     &nfds) != 0)
				break;		/* service gone */
			sp_handle(&s, &req);
		} else if (rc > 0 && (pfd[0].revents & (POLLHUP | POLLERR))) {
			break;
		}
		sp_reap(&s);
		sp_escalate(&s);
	}

	/* Bring the children down with the service. */
	for (fd = 0; fd < SP_MAX_HANDLES; fd++)
		if (s.kids[fd].used)
			kill(s.kids[fd].pid, SIGKILL);
	_exit(0);
}

/* ================= the service side ================= */

struct spawner *spawner_create(const char *tmux_sock)
{
	struct spawner *sp;
	int sv[2];
	pid_t pid;

	if (!tmux_sock || !tmux_sock[0])
		return NULL;
	sp = calloc(1, sizeof(*sp));
	if (!sp)
		return NULL;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		free(sp);
		return NULL;
	}
	pid = fork();
	if (pid < 0) {
		close(sv[0]);
		close(sv[1]);
		free(sp);
		return NULL;
	}
	if (pid == 0) {
		close(sv[0]);
		sp_child_main(sv[1], tmux_sock);	/* never returns */
		_exit(0);
	}
	close(sv[1]);
	/* Neither the tmux we exec into nor a re-exec should inherit our end. */
	fcntl(sv[0], F_SETFD, FD_CLOEXEC);
	sp->pid = pid;
	sp->ctl = sv[0];
	sp->dead = 0;
	pthread_mutex_init(&sp->mtx, NULL);
	return sp;
}

/* One request/reply transaction under the lock. Returns 0 on success, with the
 * reply in *rep and any descriptors in fds[] (count in *nfds); -1, and the
 * spawner marked dead, on a channel error. */
static int sp_txn(struct spawner *sp, const struct sp_req *req,
		  struct sp_rep *rep, int *fds, int *nfds)
{
	int rc;

	*nfds = 0;
	pthread_mutex_lock(&sp->mtx);
	if (sp->dead) {
		pthread_mutex_unlock(&sp->mtx);
		return -1;
	}
	if (write_all(sp->ctl, req, sizeof(*req)) != 0 ||
	    recv_msg(sp->ctl, rep, sizeof(*rep), fds, SP_MAX_FDS, nfds) != 0) {
		sp->dead = 1;
		rc = -1;
	} else {
		rc = 0;
	}
	pthread_mutex_unlock(&sp->mtx);
	return rc;
}

int spawner_alive(struct spawner *sp)
{
	struct sp_req req;
	struct sp_rep rep;
	int fds[SP_MAX_FDS], nfds;

	if (!sp)
		return SPAWNER_GONE;
	memset(&req, 0, sizeof(req));
	req.op = SP_ALIVE;
	if (sp_txn(sp, &req, &rep, fds, &nfds) != 0) {
		dbg_logf("spawner: gone (alive query failed)");
		return SPAWNER_GONE;
	}
	return rep.alive ? SPAWNER_ALIVE : SPAWNER_NO_SESSION;
}

void spawner_kill_server(struct spawner *sp)
{
	struct sp_req req;
	struct sp_rep rep;
	int fds[SP_MAX_FDS], nfds;

	if (!sp)
		return;
	memset(&req, 0, sizeof(req));
	req.op = SP_KILL;
	sp_txn(sp, &req, &rep, fds, &nfds);
}

sock_t spawner_endmon(struct spawner *sp, int *handle)
{
	struct sp_req req;
	struct sp_rep rep;
	int fds[SP_MAX_FDS], nfds;

	if (!sp)
		return INVALID_SOCK;
	memset(&req, 0, sizeof(req));
	req.op = SP_ENDMON;
	if (sp_txn(sp, &req, &rep, fds, &nfds) != 0 || !rep.ok || nfds < 1) {
		int i;

		for (i = 0; i < nfds; i++)
			close(fds[i]);
		return INVALID_SOCK;
	}
	if (handle)
		*handle = (int)rep.handle;
	return fds[0];
}

int spawner_spawn(struct spawner *sp, int ro, int use_pty, int rows, int cols,
		  const char *term, sock_t *in, sock_t *out, sock_t *exit_fd,
		  int *handle)
{
	struct sp_req req;
	struct sp_rep rep;
	int fds[SP_MAX_FDS], nfds, want, i;

	if (!sp)
		return -1;
	memset(&req, 0, sizeof(req));
	req.op = SP_SPAWN;
	req.ro = (uint8_t)(ro ? 1 : 0);
	req.use_pty = (uint8_t)(use_pty ? 1 : 0);
	req.rows = (uint16_t)(rows > 0 ? rows : 0);
	req.cols = (uint16_t)(cols > 0 ? cols : 0);
	if (term)
		snprintf(req.term, sizeof(req.term), "%s", term);
	if (sp_txn(sp, &req, &rep, fds, &nfds) != 0 || !rep.ok) {
		for (i = 0; i < nfds; i++)
			close(fds[i]);
		return -1;
	}
	want = rep.use_pty ? 2 : 3;	/* io(1|2) + exit-notify */
	if (nfds != want) {
		for (i = 0; i < nfds; i++)
			close(fds[i]);
		return -1;
	}
	if (rep.use_pty) {
		*in = fds[0];
		*out = fds[0];
		*exit_fd = fds[1];
	} else {
		*in = fds[0];
		*out = fds[1];
		*exit_fd = fds[2];
	}
	if (handle)
		*handle = (int)rep.handle;
	return 0;
}

void spawner_close(struct spawner *sp, int handle)
{
	struct sp_req req;
	struct sp_rep rep;
	int fds[SP_MAX_FDS], nfds;

	if (!sp)
		return;
	memset(&req, 0, sizeof(req));
	req.op = SP_CLOSE;
	req.handle = (uint32_t)handle;
	sp_txn(sp, &req, &rep, fds, &nfds);
}

void spawner_destroy(struct spawner *sp)
{
	if (!sp)
		return;
	if (sp->ctl >= 0)
		close(sp->ctl);		/* EOF makes the child exit */
	if (sp->pid > 0)
		waitpid(sp->pid, NULL, 0);
	pthread_mutex_destroy(&sp->mtx);
	free(sp);
}

#endif /* !_WIN32 */
