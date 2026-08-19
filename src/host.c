/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>

#include "host.h"

#ifndef COMRADE_HAVE_SESSION

int host_run(int ui_mode, int no_mcast, int no_fwd)
{
	(void)ui_mode;
	(void)no_mcast;
	(void)no_fwd;
	fprintf(stderr, "comrade: built without the session stack\n");
	return 1;
}

int host_show(void)
{
	fprintf(stderr, "comrade: built without the session stack\n");
	return 1;
}

#else

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#ifdef __APPLE__
#include <util.h>			/* forkpty lives here, not in pty.h */
#else
#include <pty.h>
#endif
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "conn.h"
#include "dbg.h"
#include "keys.h"
#include "session.h"
#include "sig.h"
#include "sshd.h"
#include "statusbar.h"
#include "termfilter.h"
#include "token.h"
#include "ui.h"

/*
 * The host is tmate-like. It runs a private, randomly-named tmux server so
 * concurrent comrade hosts never collide on a session, and so a remote client
 * can never reach the operator's own tmux. A backgrounded connection service
 * (setsid, so it outlives the foreground) serves that session over the punched
 * link and records the current token; because that service is detached from
 * the terminal, it streams its progress to the foreground over a pipe, where
 * the view (src/ui.c) renders the dashboard and waits for the operator to
 * enter. Detaching leaves the service running; `comrade` again re-attaches a
 * live session, and a session ends when its tmux server dies.
 */

#define ID_LEN 12			/* hex chars of the per-session id */

struct svc {
	struct token tok;
	char sock[512];
	char tokfile[512];
	char statusfile[512];
	int no_fwd;			/* decline all client port forwarding */
	struct session_obs obs;		/* view-event emitter to the foreground */
};

/* Per-user runtime directory for comrade session state; created if absent. */
static const char *state_dir(void)
{
	static char dir[512];
	const char *base = getenv("XDG_RUNTIME_DIR");
	char fallback[400];

	if (!base || !*base) {
		snprintf(fallback, sizeof(fallback), "/tmp/comrade-%u",
			 (unsigned)getuid());
		base = fallback;
		mkdir(base, 0700);
	}
	snprintf(dir, sizeof(dir), "%s/comrade", base);
	mkdir(dir, 0700);
	return dir;
}

static void sock_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s/%s.sock", state_dir(), id);
}

static void tok_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s/%s.tok", state_dir(), id);
}

/* The connection-status line file (tmpfs), written by the service, read by the
 * operator's foreground to paint the local status row. */
static void status_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s/%s.status", state_dir(), id);
}

static void gen_id(char *out)
{
	static const char hx[] = "0123456789abcdef";
	uint8_t rb[ID_LEN / 2];
	int i;

	random_bytes(rb, sizeof(rb));
	for (i = 0; i < ID_LEN / 2; i++) {
		out[i * 2] = hx[rb[i] >> 4];
		out[i * 2 + 1] = hx[rb[i] & 0xf];
	}
	out[ID_LEN] = '\0';
}

/* Run argv to completion; return its exit status, or -1 on spawn failure. */
static int run_wait(char *const argv[])
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

/*
 * Like run_wait, but capture the child's stderr into err (NUL-terminated, one
 * line, trailing newline stripped) so a failure can be reported with its real
 * cause instead of a guess.
 */
static int run_capture(char *const argv[], char *err, size_t cap)
{
	int p[2];
	pid_t pid;
	int status;

	if (err && cap)
		err[0] = '\0';
	if (pipe(p))
		return -1;
	pid = fork();
	if (pid < 0) {
		close(p[0]);
		close(p[1]);
		return -1;
	}
	if (pid == 0) {
		dup2(p[1], STDERR_FILENO);
		close(p[0]);
		close(p[1]);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(p[1]);
	if (err && cap > 1) {
		ssize_t n = read(p[0], err, cap - 1);
		char drain[256];

		err[n > 0 ? n : 0] = '\0';
		while (read(p[0], drain, sizeof(drain)) > 0)
			;
		while (*err && (err[strlen(err) - 1] == '\n' ||
			        err[strlen(err) - 1] == '\r'))
			err[strlen(err) - 1] = '\0';
	}
	close(p[0]);
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int tmux_alive(const char *sock)
{
	char *argv[] = { "tmux", "-S", (char *)sock, "has-session",
			 "-t", "comrade", NULL };
	int fd = open("/dev/null", O_WRONLY);
	int saved = -1, rc;

	if (fd >= 0) {			/* silence has-session's stderr */
		saved = dup(STDERR_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
	}
	rc = run_wait(argv);
	if (saved >= 0) {
		dup2(saved, STDERR_FILENO);
		close(saved);
	}
	return rc == 0;
}

/*
 * Spawn a light end-of-session monitor. `tmux wait-for <channel>` connects to
 * the server and blocks until that channel is signalled -- which we never do --
 * so it simply blocks until the server dies, i.e. until the shared session
 * ends. It attaches no client and emits no output, so the only event on its
 * stdout pipe is EOF when it exits with the session. The readable end of that
 * pipe is the event-driven end-of-session signal handed to sshd; it releases a
 * connected client at once instead of after a poll interval. Returns the
 * readable fd (and the pid to reap), or -1 on failure.
 */
static int spawn_end_monitor(const char *sock, pid_t *pid)
{
	int p[2];
	pid_t c;

	if (pipe(p))
		return -1;
	c = fork();
	if (c < 0) {
		close(p[0]);
		close(p[1]);
		return -1;
	}
	if (c == 0) {
		char *argv[] = { "tmux", "-S", (char *)sock, "wait-for",
				 "comrade-session", NULL };
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

/* Newest live session id into id[ID_LEN+1]; returns 1 if one was found. */
/* Remove socket/token files whose tmux server is gone, so stale state from an
 * earlier run cannot linger or confuse a fresh start. */
static void sweep_stale(void)
{
	DIR *d = opendir(state_dir());
	struct dirent *e;

	if (!d)
		return;
	while ((e = readdir(d))) {
		char cand[ID_LEN + 1], sock[512], tok[512];

		if (strlen(e->d_name) != ID_LEN + 5 ||
		    strcmp(e->d_name + ID_LEN, ".sock"))
			continue;
		memcpy(cand, e->d_name, ID_LEN);
		cand[ID_LEN] = '\0';
		sock_path(sock, sizeof(sock), cand);
		if (tmux_alive(sock))
			continue;		/* a live session: leave it */
		unlink(sock);
		tok_path(tok, sizeof(tok), cand);
		unlink(tok);
		status_path(tok, sizeof(tok), cand);
		unlink(tok);
	}
	closedir(d);
}

static int find_live(char *id)
{
	DIR *d = opendir(state_dir());
	struct dirent *e;
	time_t best = 0;
	int found = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		char cand[ID_LEN + 1], sock[512], path[512];
		struct stat st;

		if (strlen(e->d_name) != ID_LEN + 5 ||
		    strcmp(e->d_name + ID_LEN, ".sock"))
			continue;
		memcpy(cand, e->d_name, ID_LEN);
		cand[ID_LEN] = '\0';
		sock_path(sock, sizeof(sock), cand);
		if (!tmux_alive(sock))
			continue;
		snprintf(path, sizeof(path), "%s/%s", state_dir(), e->d_name);
		if (!stat(path, &st) && st.st_mtime >= best) {
			best = st.st_mtime;
			memcpy(id, cand, ID_LEN + 1);
			found = 1;
		}
	}
	closedir(d);
	return found;
}

static volatile sig_atomic_t g_winch;

static void on_winch(int sig)
{
	(void)sig;
	g_winch = 1;
}

static uint64_t mono_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)(t.tv_nsec / 1000000);
}

/* Exec tmux directly, taking over this process (no local status row). */
static int exec_tmux(char *const argv[])
{
	execvp(argv[0], argv);
	fprintf(stderr, "comrade: could not run tmux\n");
	return 1;
}

/* Confine the terminal scroll region to the rows above the reserved status row
 * so nothing scrolling in the tmux area can push into it; on == 0 restores the
 * full-screen region. */
static void scroll_guard(int rows, int reserve, int on)
{
	char b[32];
	int n;

	if (!reserve)
		return;
	if (on)
		n = snprintf(b, sizeof(b), "\033[1;%dr", rows - 1);
	else
		n = snprintf(b, sizeof(b), "\033[r");
	if (n > 0 && write(STDOUT_FILENO, b, (size_t)n)) {
		/* best effort */
	}
}

/*
 * Attach the operator to the shared tmux, reserving the bottom terminal row for
 * comrade's own status line -- run tmux in a pty one row shorter and paint the
 * status (read from the service's tmpfs file) on the freed row ourselves, so it
 * stays live even while the link is down. The view (statusbar) does the drawing;
 * we only bridge bytes and reserve the row. Falls back to a plain exec when
 * there is no usable tty.
 */
static int attach(const char *id)
{
	char sock[512], statuspath[512];
	char *argv[] = { "tmux", "-S", sock, "attach", "-t", "comrade", NULL };
	struct termios orig, raw;
	struct sigaction sa, oldwinch;
	struct winsize ws, cws;
	int rows, cols, master, alive = 1;
	pid_t child;
	uint64_t last_paint = 0;
	struct conn_status cur, prev;
	struct termfilter tf;

	sock_path(sock, sizeof(sock), id);
	status_path(statuspath, sizeof(statuspath), id);

	if (!isatty(STDIN_FILENO) || ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) ||
	    ws.ws_row < 2 || tcgetattr(STDIN_FILENO, &orig))
		return exec_tmux(argv);
	rows = ws.ws_row;
	cols = ws.ws_col;

	cws = ws;
	cws.ws_row = (unsigned short)(rows - 1);	/* tmux gets one row less */
	dbg_logf("host attach: terminal rows=%d cols=%d -> tmux gets %d rows",
		 rows, cols, rows - 1);
	child = forkpty(&master, NULL, &orig, &cws);
	if (child < 0)
		return exec_tmux(argv);
	if (child == 0) {
		execvp(argv[0], argv);
		_exit(127);
	}

	raw = orig;
	cfmakeraw(&raw);
	tcsetattr(STDIN_FILENO, TCSANOW, &raw);
	scroll_guard(rows, 1, 1);
	termfilter_init(&tf, 1);	/* keep tmux one row shorter than the tty */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_winch;
	sigaction(SIGWINCH, &sa, &oldwinch);
	memset(&prev, 0, sizeof(prev));

	while (alive) {
		struct pollfd fds[2];
		char buf[4096];
		ssize_t n;
		uint64_t now;

		fds[0].fd = STDIN_FILENO;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = master;
		fds[1].events = POLLIN;
		fds[1].revents = 0;
		poll(fds, 2, 200);

		if (g_winch) {
			g_winch = 0;
			if (!ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) &&
			    ws.ws_row >= 2) {
				rows = ws.ws_row;
				cols = ws.ws_col;
				cws = ws;
				cws.ws_row = (unsigned short)(rows - 1);
				ioctl(master, TIOCSWINSZ, &cws);
				scroll_guard(rows, 1, 1);
				dbg_logf("host resize: rows=%d cols=%d -> tmux "
					 "%d rows", rows, cols, rows - 1);
				memset(&prev, 0, sizeof(prev));
			}
		}
		if (fds[0].revents & POLLIN) {
			n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n > 0) {
				char fb[sizeof(buf) + sizeof(tf.pend)];
				size_t fn = termfilter_run(&tf, buf, (size_t)n,
							   fb);
				ssize_t w = write(master, fb, fn);

				(void)w;
			}
		}
		if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
			n = read(master, buf, sizeof(buf));
			if (n > 0) {
				ssize_t w = write(STDOUT_FILENO, buf, (size_t)n);

				(void)w;
			} else if (n == 0 ||
				   (n < 0 && errno != EAGAIN && errno != EINTR)) {
				alive = 0;	/* tmux exited */
			}
		}
		now = mono_ms();
		memset(&cur, 0, sizeof(cur));
		conn_read(statuspath, &cur);	/* zeroed = "connecting" if absent */
		if (memcmp(&cur, &prev, sizeof(cur)) || now - last_paint > 2000) {
			statusbar_render(STDOUT_FILENO, rows, cols, &cur);
			prev = cur;
			last_paint = now;
		}
	}

	scroll_guard(rows, 1, 0);
	tcsetattr(STDIN_FILENO, TCSANOW, &orig);
	sigaction(SIGWINCH, &oldwinch, NULL);
	close(master);
	waitpid(child, NULL, 0);
	return 0;
}

/* Called (in the service) once the rendezvous is ready; write the full token
 * so the foreground can print it and so `comrade show` can read it. */
static void on_rendezvous(void *arg, const struct sockaddr *sa, socklen_t len)
{
	struct svc *v = arg;
	char tokbuf[TOKEN_STR_LEN + 1];
	int fd;

	(void)len;
	if (sa && sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		memcpy(v->tok.ep6_addr, &a->sin6_addr, TOKEN_EP6_LEN);
		v->tok.ep6_port = ntohs(a->sin6_port);
		v->tok.flags |= TOKEN_FLAG_EP6_RDV;
	} else if (sa && sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		memcpy(v->tok.ep4_addr, &a->sin_addr, TOKEN_EP4_LEN);
		v->tok.ep4_port = ntohs(a->sin_port);
		v->tok.flags |= TOKEN_FLAG_EP4_RDV;
	}
	if (token_encode(&v->tok, tokbuf, sizeof(tokbuf)))
		return;
	fd = open(v->tokfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0) {
		dprintf(fd, "%s\n", tokbuf);
		close(fd);
	}
	ui_emitter_token(&v->obs, tokbuf);	/* show it in the foreground */
}

/* The backgrounded connection service: serve the shared tmux over the punched
 * link, again after each client, until the tmux server is gone. */
static void run_service(struct svc *v, void *hostkey, int wfd, int no_mcast)
{
	char cmd[600];
	struct session_cfg cfg;
	int devnull;
	int end_fd;
	pid_t end_pid = -1;

	setsid();
	signal(SIGPIPE, SIG_IGN);	/* foreground may exec away mid-session */
	devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}
	snprintf(cmd, sizeof(cmd), "tmux -S %s attach -t comrade", v->sock);
	end_fd = spawn_end_monitor(v->sock, &end_pid);

	ui_emitter(&v->obs, wfd);	/* progress -> the foreground view */

	memset(&cfg, 0, sizeof(cfg));
	cfg.is_host = 1;
	cfg.tok = v->tok;
	cfg.sig_flags = SIG_DHT | (no_mcast ? 0 : SIG_MCAST);
	cfg.stun_port = 3478;
	cfg.stun_auto = 1;
	cfg.log_level = -1;
	cfg.connect_timeout_s = 60;
	cfg.hostkey = hostkey;
	cfg.ssh_command = cmd;
	cfg.use_pty = 1;
	cfg.ssh_end_fd = end_fd > 0 ? end_fd : 0;
	cfg.no_fwd = v->no_fwd;
	cfg.status_path = v->statusfile;
	cfg.on_rendezvous = on_rendezvous;
	cfg.arg = v;
	cfg.obs = &v->obs;

	while (tmux_alive(v->sock)) {
		cfg.tok = v->tok;	/* carry the located anchor forward, so the
					 * next idle attempt reinforces it rather
					 * than locating (and churning) a new one */
		session_run(&cfg);
	}
	if (end_fd > 0)
		close(end_fd);
	if (end_pid > 0) {
		kill(end_pid, SIGTERM);
		waitpid(end_pid, NULL, 0);
	}
	unlink(v->tokfile);
	unlink(v->statusfile);
	_exit(0);
}

/* Abort path: stop the detached service and drop its tmux session and state. */
static void teardown(pid_t svc, const char *sock, const char *tokfile)
{
	char *k[] = { "tmux", "-S", (char *)sock, "kill-server", NULL };

	kill(svc, SIGTERM);
	waitpid(svc, NULL, 0);
	run_wait(k);
	unlink(tokfile);
	unlink(sock);
}

static int start_new(int ui_mode, int no_mcast, int no_fwd)
{
	struct svc v;
	char id[ID_LEN + 1];
	void *hostkey;
	struct ui *ui;
	pid_t pid;
	int pfd[2], enter;

	memset(&v, 0, sizeof(v));
	v.no_fwd = no_fwd;
	gen_id(id);
	sock_path(v.sock, sizeof(v.sock), id);
	tok_path(v.tokfile, sizeof(v.tokfile), id);
	status_path(v.statusfile, sizeof(v.statusfile), id);

	v.tok.version = TOKEN_VERSION;
	hostkey = sshd_hostkey_new(v.tok.hostpub);
	if (!hostkey) {
		fprintf(stderr, "comrade: host key generation failed\n");
		return 1;
	}
	random_bytes(v.tok.rdv, TOKEN_RDV_LEN);
	random_bytes(v.tok.auth, TOKEN_AUTH_LEN);

	{
		char *mk[] = { "tmux", "-S", v.sock, "new-session", "-d",
			       "-s", "comrade",
			       ";", "set", "-g", "status-position", "top",
			       ";", "set", "-g", "window-size", "smallest",
			       NULL };
		char err[256];

		if (run_capture(mk, err, sizeof(err))) {
			if (err[0])
				fprintf(stderr, "comrade: could not start tmux: %s\n",
					err);
			else
				fprintf(stderr, "comrade: could not start tmux "
					"(is it installed?)\n");
			return 1;
		}
	}

	/* Close-on-exec so neither the tmux we exec into nor the service's tmux
	 * helpers inherit the pipe; the service ignores the resulting SIGPIPE. */
	if (pipe(pfd)) {
		fprintf(stderr, "comrade: pipe failed\n");
		return 1;
	}
	fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
	fcntl(pfd[1], F_SETFD, FD_CLOEXEC);

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "comrade: fork failed\n");
		return 1;
	}
	if (pid == 0) {
		close(pfd[0]);
		run_service(&v, hostkey, pfd[1], no_mcast);	/* never returns */
	}
	close(pfd[1]);
	sshd_hostkey_free(hostkey);		/* the service has its own copy */

	/* The view renders the service's progress and blocks until the operator
	 * enters (1, playing the zap), aborts (-1), or the service exits (0). */
	ui = ui_create(UI_ROLE_HOST, ui_mode);
	enter = ui ? ui_host_wait(ui, pfd[0]) : 0;
	ui_destroy(ui);
	close(pfd[0]);

	if (enter == 1)
		return attach(id);		/* foreground; execs tmux */
	if (enter < 0) {			/* operator aborted */
		teardown(pid, v.sock, v.tokfile);
		fprintf(stderr, "comrade: aborted.\n");
		return 0;
	}
	fprintf(stderr, "comrade: session ended before you entered "
		"(token: `comrade show`)\n");
	return 1;
}

int host_run(int ui_mode, int no_mcast, int no_fwd)
{
	char id[ID_LEN + 1];

	sweep_stale();
	if (find_live(id)) {
		fprintf(stderr, "comrade: re-attaching to your running session"
			" (its token: `comrade show`)\n");
		return attach(id);
	}
	return start_new(ui_mode, no_mcast, no_fwd);
}

int host_show(void)
{
	DIR *d = opendir(state_dir());
	struct dirent *e;
	int shown = 0;

	if (d) {
		while ((e = readdir(d))) {
			char cand[ID_LEN + 1], sock[512], tf[512];
			char tok[TOKEN_STR_LEN + 8];
			FILE *f;

			if (strlen(e->d_name) != ID_LEN + 5 ||
			    strcmp(e->d_name + ID_LEN, ".sock"))
				continue;
			memcpy(cand, e->d_name, ID_LEN);
			cand[ID_LEN] = '\0';
			sock_path(sock, sizeof(sock), cand);
			if (!tmux_alive(sock))
				continue;
			tok_path(tf, sizeof(tf), cand);
			f = fopen(tf, "r");
			if (f) {
				if (fgets(tok, sizeof(tok), f)) {
					printf("%s", tok);
					shown = 1;
				}
				fclose(f);
			}
		}
		closedir(d);
	}
	if (!shown) {
		fprintf(stderr, "comrade: no running session\n");
		return 1;
	}
	return 0;
}

#endif
