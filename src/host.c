/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>

#include "host.h"
#include "showfmt.h"

/*
 * Hosting is the half of comrade that is genuinely Unix-shaped: it forks, it
 * runs a command under a pty (forkpty), it detaches a service with setsid, and
 * the command it runs is tmux. Every one of those has a Windows answer --
 * CreateProcess, CreatePseudoConsole, DETACHED_PROCESS, and a separately
 * installed tmux.exe -- but they are different enough in shape (no fork means
 * the service is a *new* process, not a copy of this one) that the Windows
 * host is its own file: src/host_win.c. This one stays the POSIX host it
 * always was, with no #ifdefs in it.
 */
#ifdef _WIN32

/* host_run/host_show live in host_win.c. */

#else

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
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

#include "appdir.h"
#include "conn.h"
#include "mview.h"
#include "dbg.h"
#include "keys.h"
#include "oscompat.h"
#include "sandbox.h"
#include "session.h"
#include "sig.h"
#include "spawner.h"
#include "sshd.h"
#include "statusbar.h"
#include "termfilter.h"
#include "token.h"
#include "ui.h"

/*
 * The host is tmate-like. It runs a private, randomly-named tmux server so
 * concurrent comrade hosts never collide on a session, and so a remote client
 * can never reach the operator's own tmux. A connection service is forked off
 * to serve that session over the punched link and record the current token; it
 * is setsid so the terminal's own signals are not its business, and because it
 * has no terminal it streams its progress to the foreground over a pipe, where
 * the view (src/ui.c) renders the dashboard and waits for the operator.
 *
 * The service does not outlive the operator. That is the rule the whole
 * lifecycle hangs on: a shared terminal running with nothing on screen to say
 * so is a machine handed out and forgotten, so a live session is always either
 * the shared tmux or the dashboard in front of the operator who started it.
 * Detaching tmux therefore lands back on the dashboard rather than at the
 * shell, and leaving the dashboard ends the session rather than backgrounding
 * it -- there is nothing to come back to, and `comrade` starts a new session
 * rather than adopting one. The service holds the far end of the event pipe
 * open and ends the session the moment it closes (hangup_watch), which covers
 * the ways a terminal can go that a foreground never gets to act on: a hangup,
 * a closed window, a kill.
 *
 * A session ends when its tmux server dies -- the last shell exiting, on
 * whichever side, or the operator leaving the dashboard -- and the service
 * leaves a tombstone on the rendezvous before it goes, so a client holding the
 * invitation is told the session has ended instead of waiting for a host that
 * will never answer.
 */

#define ID_LEN 12			/* hex chars of a generated session id */
#define ID_MAX 32			/* longest id, generated or named */

struct svc {
	int serve_max;			/* bounded grant: sessions to serve */
	int admit_max;			/* and claimants to admit */
	struct token tok;
	char last_tok[TOKEN_STR_LEN + 1];	/* the token last written out */
	char sock[512];
	char tokfile[512];
	char statusfile[512];
	char svcfile[512];		/* this service's pid, while it runs */
	int no_fwd;			/* decline all client port forwarding */
	int forward_only;		/* serve no shell/tmux, forwarding only */
	volatile int stop;		/* forward-only: end the serve loop */
	sock_t stop_wfd;		/* shut to release the turnstile promptly */
	int obs_fd;			/* the operator's end of the event pipe;
					 * its closing is the operator leaving */
	struct session_obs obs;		/* view-event emitter to the foreground */
	struct spawner *sp;		/* runs tmux for the sandboxed service */
};

/* True only for a real directory we own with no group/other access -- not a
 * symlink, not another user's -- so a pre-existing state directory is reused
 * only if another user could not have planted it. */
static int dir_ok(const char *path)
{
	struct stat st;

	if (lstat(path, &st))
		return 0;
	return S_ISDIR(st.st_mode) && st.st_uid == getuid() &&
	       (st.st_mode & 077) == 0;
}

/* mkdir the directory 0700 and insist we own it exclusively, so a state dir
 * another user could have planted (or symlinked) is refused, never reused. */
static const char *state_ok(char *dir)
{
	if (mkdir(dir, 0700) && (errno != EEXIST || !dir_ok(dir))) {
		/* Says where to put it instead, because the usual way to meet
		 * this is not an attack but a namespace: inside one this
		 * process is root, takes the path root is pinned to, and finds
		 * it belongs to the user outside. */
		fprintf(stderr, "comrade: refusing unsafe state dir %s\n"
			"comrade: it must be a directory we own with no group "
			"or other access; set COMRADE_STATE_DIR to one\n", dir);
		exit(1);
	}
	return dir;
}

/*
 * The directory holding comrade session state, created if absent.
 *
 * COMRADE_STATE_DIR overrides everything. Otherwise root is pinned to a
 * stable /var/run/comrade regardless of XDG_RUNTIME_DIR: this is the one
 * process whose two entry points -- an operator at the console and a
 * supervisor such as luci-app-remoteassist -- must always coincide, or a
 * grant made through one is invisible (and unstoppable) through the other,
 * and the console is exactly where you go to end a stranger's shell when the
 * web UI is unreachable. A pinned path an env var cannot perturb is also the
 * only thing an ACL can name literally. Non-root keeps the per-user path
 * (XDG_RUNTIME_DIR, else /tmp/comrade-$UID), where no such second door exists.
 */
static const char *state_dir(void)
{
	static char dir[256];
	const char *fixed = getenv("COMRADE_STATE_DIR");
	const char *base = getenv("XDG_RUNTIME_DIR");
	char parent[200];

	if (fixed && *fixed) {
		snprintf(dir, sizeof(dir), "%s", fixed);
		return state_ok(dir);
	}
	if (getuid() == 0) {
		/* /var is tmpfs on OpenWrt (a symlink to /tmp) and /run
		 * elsewhere: either way session state belongs on tmpfs. */
		snprintf(dir, sizeof(dir), "/var/run/comrade");
		return state_ok(dir);
	}
	if (base && *base) {
		snprintf(dir, sizeof(dir), "%s/comrade", base);
		return state_ok(dir);
	}
	snprintf(parent, sizeof(parent), "/tmp/comrade-%u", (unsigned)getuid());
	state_ok(parent);
	snprintf(dir, sizeof(dir), "%s/comrade", parent);
	return state_ok(dir);
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

/* The machine view's state document and the headless service's pidfile. */
static void json_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s/%s.json", state_dir(), id);
}

static void pid_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s/%s.pid", state_dir(), id);
}

/*
 * The interactive session's connection service, by pid.
 *
 * Distinct from the headless pidfile, which marks a session as a supervisor's
 * rather than an operator's. This says something narrower: that the service
 * behind this shared tmux is still running. It is what tells a session somebody
 * is hosting from a live tmux server left standing by a service that was killed
 * outright -- which nothing else can, since the tmux server answers just the
 * same either way, and which matters because the two call for opposite things:
 * leave the first alone, collect the second.
 */
static void svc_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s/%s.svc", state_dir(), id);
}

/* A supervisor-chosen id: path-safe, bounded, never empty. */
static int valid_id(const char *id)
{
	size_t i, n = strlen(id);

	if (!n || n > ID_MAX)
		return 0;
	for (i = 0; i < n; i++) {
		char c = id[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_'))
			return 0;
	}
	return 1;
}

static int tmux_alive(const char *sock);

/* The pid a file names, still alive; 0 if the file is absent or it is not. */
static long pid_in(const char *pp)
{
	FILE *f;
	long pid = 0;

	f = fopen(pp, "r");
	if (!f)
		return 0;
	if (fscanf(f, "%ld", &pid) != 1)
		pid = 0;
	fclose(f);
	return (pid > 0 && kill((pid_t)pid, 0) == 0) ? pid : 0;
}

/* The service pid a session's pidfile names, alive; 0 if none or dead. */
static long pid_of(const char *id)
{
	char pp[512];

	pid_path(pp, sizeof(pp), id);
	return pid_in(pp);
}

/* Likewise for the interactive service; 0 for a session with none running. */
static long svc_of(const char *id)
{
	char pp[512];

	svc_path(pp, sizeof(pp), id);
	return pid_in(pp);
}

/*
 * A session is live if its tmux server answers (interactive or tmux-headless)
 * or its headless service pid is alive (forward-only has no tmux, so the pid
 * is its only liveness). Enumeration and the machine verbs use this so a
 * forward-only session is as manageable as any other.
 */
static int session_live(const char *id)
{
	char sock[512];

	sock_path(sock, sizeof(sock), id);
	if (tmux_alive(sock))
		return 1;
	return pid_of(id) != 0;
}

/*
 * Visit every session id once (deduped): a tmux socket names one, and so do a
 * headless pidfile and an interactive service's pidfile, and one session may
 * have all three. Iterate in that order, skipping ids an earlier pass carried,
 * so each id is seen once.
 */
static void each_session(void (*fn)(const char *id, void *arg), void *arg)
{
	const char *suf[3] = { ".pid", ".sock", ".svc" };
	int pass;

	for (pass = 0; pass < 3; pass++) {
		DIR *d = opendir(state_dir());
		struct dirent *e;
		size_t sl = strlen(suf[pass]);

		if (!d)
			return;
		while ((e = readdir(d))) {
			char id[ID_MAX + 1], pp[512];
			size_t nl = strlen(e->d_name);

			if (nl <= sl || nl - sl > ID_MAX ||
			    strcmp(e->d_name + nl - sl, suf[pass]))
				continue;
			memcpy(id, e->d_name, nl - sl);
			id[nl - sl] = '\0';
			/* Later passes: skip ids an earlier one already
			 * carried, so a session with more than one of these
			 * files is seen once. */
			if (pass >= 1) {
				pid_path(pp, sizeof(pp), id);
				if (access(pp, F_OK) == 0)
					continue;
			}
			if (pass == 2) {
				sock_path(pp, sizeof(pp), id);
				if (access(pp, F_OK) == 0)
					continue;
			}
			fn(id, arg);
		}
		closedir(d);
	}
}

static int gen_id(char *out)
{
	static const char hx[] = "0123456789abcdef";
	uint8_t rb[ID_LEN / 2];
	int i;

	if (random_bytes(rb, sizeof(rb)))
		return -1;
	for (i = 0; i < ID_LEN / 2; i++) {
		out[i * 2] = hx[rb[i] >> 4];
		out[i * 2 + 1] = hx[rb[i] & 0xf];
	}
	out[ID_LEN] = '\0';
	return 0;
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

/* Take the shared tmux, quietly: on the way out there may be no server left to
 * take, and tmux says so on stderr, over the operator's shell. */
static void kill_tmux(const char *sock)
{
	char *k[] = { "tmux", "-S", (char *)sock, "kill-server", NULL };
	int fd = open("/dev/null", O_WRONLY);
	int saved = -1;

	if (fd >= 0) {
		saved = dup(STDERR_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
	}
	run_wait(k);
	if (saved >= 0) {
		dup2(saved, STDERR_FILENO);
		close(saved);
	}
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

/* Drop every state file of one dead session. */
static void sweep_one(const char *id, void *arg)
{
	char p[512];

	(void)arg;
	if (session_live(id))
		return;			/* a live session: leave it */
	sock_path(p, sizeof(p), id);
	unlink(p);
	tok_path(p, sizeof(p), id);
	unlink(p);
	status_path(p, sizeof(p), id);
	unlink(p);
	json_path(p, sizeof(p), id);
	unlink(p);
	pid_path(p, sizeof(p), id);
	unlink(p);
	svc_path(p, sizeof(p), id);
	unlink(p);
}

/* Remove the state files of sessions whose tmux server or service pid is
 * gone, so stale state from an earlier run cannot linger or confuse a fresh
 * start. */
static void sweep_stale(void)
{
	each_session(sweep_one, NULL);
}

/*
 * An interactive session somebody is hosting right now: a live shared tmux with
 * a live service behind it.
 *
 * A tmux server standing with no service is not one of those. It is what a
 * service killed outright leaves -- the operator's foreground and the service
 * both gone, and nothing left that watches the tmux to take it. Nobody can
 * reach it (there is no service to serve it) and nobody would come back to it,
 * but it would keep answering `has-session` for as long as the machine is up
 * and stop every later `comrade` from starting. So it is collected here rather
 * than reported, and the operator gets the fresh session they asked for.
 */
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
		/* A headless session (it has a pidfile) belongs to its
		 * supervisor: the interactive `comrade` never adopts it. */
		pid_path(path, sizeof(path), cand);
		if (access(path, F_OK) == 0)
			continue;
		if (!svc_of(cand)) {
			kill_tmux(sock);
			sweep_one(cand, NULL);
			continue;
		}
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

/*
 * Exec tmux directly, taking over this process (no local status row).
 *
 * `keep` is the operator's end of the service's event pipe, held close-on-exec
 * so no tmux inherits it -- except this one, which becomes the operator: with
 * this process replaced there is nobody else left in front of the session, and
 * a pipe closing here would have the service read the operator as gone and end
 * a session somebody is sitting in. tmux holds it instead, for exactly as long
 * as the attach lasts.
 */
static int exec_tmux(char *const argv[], int keep)
{
	if (keep >= 0)
		fcntl(keep, F_SETFD, 0);
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
static int attach(const char *id, int keep)
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
		return exec_tmux(argv, keep);
	rows = ws.ws_row;
	cols = ws.ws_col;

	cws = ws;
	cws.ws_row = (unsigned short)(rows - 1);	/* tmux gets one row less */
	dbg_logf("host attach: terminal rows=%d cols=%d -> tmux gets %d rows",
		 rows, cols, rows - 1);
	child = forkpty(&master, NULL, &orig, &cws);
	if (child < 0)
		return exec_tmux(argv, keep);
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
			statusbar_render(rows, cols, &cur);
			prev = cur;
			last_paint = now;
		}
	}

	scroll_guard(rows, 1, 0);
	tcsetattr(STDIN_FILENO, TCSANOW, &orig);
	sigaction(SIGWINCH, &oldwinch, NULL);
	close(master);
	waitpid(child, NULL, 0);
	return tmux_alive(sock) ? 2 : 0;
}

/* Encode the current token (and its read-only twin), write both to the token
 * file so the foreground can print them and `comrade show` can read them, and
 * emit them to the foreground view. Called on every token state change, so an
 * unchanged token is not rewritten, and the file is replaced by a rename rather
 * than truncated in place: `comrade show` never reads a half-written one. A
 * token that did not reach the file is not remembered either, so the next state
 * change writes it again instead of deduplicating it away. */
static void svc_emit_token(struct svc *v)
{
	char tokbuf[TOKEN_STR_LEN + 1];
	char tokbuf_ro[TOKEN_STR_LEN + 1];
	char tmp[520];
	struct token ro;
	int fd, wrote = 0;

	if (token_encode(&v->tok, tokbuf, sizeof(tokbuf)))
		return;
	if (!strcmp(tokbuf, v->last_tok))
		return;
	ro = v->tok;
	ro.flags |= TOKEN_FLAG_RO;
	keys_derive_ro_auth(ro.auth, v->tok.auth);
	if (token_encode(&ro, tokbuf_ro, sizeof(tokbuf_ro)))
		return;
	snprintf(tmp, sizeof(tmp), "%s.tmp", v->tokfile);
	unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
	if (fd >= 0) {
		int n = dprintf(fd, "%s\n%s\n", tokbuf, tokbuf_ro);

		wrote = close(fd) == 0 &&
			n == (int)(strlen(tokbuf) + strlen(tokbuf_ro) + 2);
		if (!wrote || os_rename_replace(tmp, v->tokfile)) {
			unlink(tmp);
			wrote = 0;
		}
	}
	if (wrote)
		snprintf(v->last_tok, sizeof(v->last_tok), "%s", tokbuf);
	ui_emitter_token(&v->obs, tokbuf);	/* show it in the foreground */
	ui_emitter_token_ro(&v->obs, tokbuf_ro);
}

/* Called (in the service) whenever a family's token state changes: write it
 * into that family's slot and re-emit the token. */
static void on_token_state(void *arg, int family, int state,
			   const uint8_t *addr, uint16_t port)
{
	struct svc *v = arg;

	token_set_family(&v->tok, family, state, addr, port);
	svc_emit_token(v);
}

/*
 * End the session, from inside the service.
 *
 * The tmux server is what a session IS, so taking it is what ends one, and
 * everything that has to follow -- the serve loop stopping, each connected
 * client's sshd closing, the tombstone going out -- follows from the end
 * monitor seeing it go. Killed through the spawner where the service is not
 * allowed to exec. A forward-only session has no tmux to take, so its serve
 * flag stands in, with the turnstile's end socket shut to wake it at once.
 */
static void svc_end(struct svc *v)
{
	if (v->forward_only) {
		v->stop = 1;
		if (sock_isset(v->stop_wfd))
			sock_shutdown(v->stop_wfd, SHUT_RDWR);
	} else if (v->sp) {
		spawner_kill_server(v->sp);
	} else {
		char *k[] = { "tmux", "-S", v->sock, "kill-server", NULL };

		run_wait(k);
	}
}

/* Is the shared tmux session alive? Through the spawner when there is one; a
 * spawner that has itself died is read as the session ending, which ends the
 * serve loop without taking the tmux server (the operator or a sweep collects
 * it). */
static int svc_alive(struct svc *v)
{
	int r;

	if (!v->sp)
		return tmux_alive(v->sock);
	r = spawner_alive(v->sp);
	if (r == SPAWNER_GONE) {
		dbg_logf("host: spawner gone -- ending the service");
		return 0;
	}
	return r == SPAWNER_ALIVE;
}

/*
 * Fork the spawner and then confine this network-facing service. Called at a
 * single-threaded moment -- before the emitter thread and before the first
 * socket -- so the confinement covers every thread that follows and the spawner
 * inherits none of it. Where the platform will not deny exec there is no
 * spawner, and the service keeps running tmux directly.
 *
 * Returns the layers that engaged, which is a fact about this machine rather
 * than about the build and so is worth reporting rather than only logging.
 */
static int svc_confine(struct svc *v)
{
	struct sandbox_cfg sb;

	/* A forwarding-only host runs no tmux and execs nothing, so it needs no
	 * spawner; every other service hands its tmux to one where the platform
	 * can then deny the service's own exec. */
	if (!v->forward_only && sandbox_needs_spawner())
		v->sp = spawner_create(v->sock);
	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_SERVICE;
	sb.data_dir = appdir_data();
	sb.state_dir = state_dir();
	sb.no_exec = (v->sp != NULL) || v->forward_only;
	/* Forwarding-only serves no shell (see sshd.c), so it reaches no pty. */
	sb.no_pty = v->forward_only;
	/*
	 * A host is told which port to listen on when a client asks it to,
	 * which is long after this, so it cannot be given a list the way a
	 * client can -- it is all TCP or none. Declining to forward is what
	 * makes it none, and then the service keeps only the UDP it runs on.
	 */
	sb.tcp_any = !v->no_fwd;
	return sandbox_apply(&sb);
}

/*
 * Confine the operator's foreground: it drives a local tmux (so it keeps exec
 * and its terminal) and reads the service's state files, but never opens a
 * network socket, so its profile forbids exactly that. No filesystem
 * confinement -- it runs tmux, which needs a full view.
 */
static void foreground_confine(void)
{
	struct sandbox_cfg sb;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_FOREGROUND;
	sandbox_apply(&sb);
}

/* The serving core: sessions over the shared tmux, again after each client,
 * until the tmux server is gone. The observer in v->obs is already bound. */
static void svc_serve(struct svc *v, void *hostkey, int no_mcast, int no_dht)
{
	char cmd[600];
	char cmd_ro[600];
	struct session_cfg cfg;
	sock_t end_fd = INVALID_SOCK;
	pid_t end_pid = -1;
	int end_handle = -1;

	if (v->forward_only) {
		/* No tmux to anchor on, so a socketpair is the end signal: the
		 * turnstile polls end_fd and returns the moment stop shuts the
		 * write end, instead of waiting out its idle/deadline. */
		sock_t sp[2];

		if (!sock_pair(sp)) {
			end_fd = sp[0];
			v->stop_wfd = sp[1];
		}
	} else {
		snprintf(cmd, sizeof(cmd), "tmux -S %s attach -t comrade",
			 v->sock);
		snprintf(cmd_ro, sizeof(cmd_ro),
			 "tmux -S %s attach -r -t comrade", v->sock);
		if (v->sp)
			end_fd = spawner_endmon(v->sp, &end_handle);
		else
			end_fd = spawn_end_monitor(v->sock, &end_pid);
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.is_host = 1;
	cfg.tok = v->tok;
	cfg.host_serve_max = v->serve_max;
	cfg.host_admit_max = v->admit_max;
	cfg.sig_flags = (no_dht ? 0 : SIG_DHT) | (no_mcast ? 0 : SIG_MCAST);
	cfg.stun_port = 3478;
	cfg.stun_auto = 1;
	cfg.log_level = -1;
	cfg.connect_timeout_s = 60;
	cfg.hostkey = hostkey;
	cfg.no_fwd = v->no_fwd;
	cfg.forward_only = v->forward_only;
	cfg.ssh_end_fd = sock_isset(end_fd) ? end_fd : 0;
	if (!v->forward_only) {
		cfg.ssh_command = cmd;
		cfg.ssh_command_ro = cmd_ro;
		cfg.use_pty = 1;
	}
	cfg.status_path = v->statusfile;
	cfg.on_token_state = on_token_state;
	cfg.arg = v;
	cfg.obs = &v->obs;
	cfg.spawner = v->sp;

	/*
	 * Non-forward-only is anchored to tmux: the shared session is the
	 * durable state and the loop runs while it lives. Forward-only has no
	 * tmux, so it runs until stopped (v->stop, set by the supervisor's
	 * signal watcher or the operator) or the bounded grant is spent.
	 */
	while (v->forward_only ? !v->stop : svc_alive(v)) {
		cfg.tok = v->tok;	/* carry the located anchor forward, so the
					 * next idle attempt reinforces it rather
					 * than locating (and churning) a new one */
		session_run(&cfg);
		if (v->serve_max) {
			/* The bounded grant is spent: end for good, taking
			 * the shared tmux (if any) with us. */
			svc_end(v);
			break;
		}
	}
	if (v->sp && end_handle >= 0)
		spawner_close(v->sp, end_handle);
	if (sock_isset(end_fd))
		sock_close(end_fd);
	if (sock_isset(v->stop_wfd)) {
		sock_close(v->stop_wfd);
		v->stop_wfd = INVALID_SOCK;
	}
	if (end_pid > 0) {
		kill(end_pid, SIGTERM);
		waitpid(end_pid, NULL, 0);
	}
	unlink(v->tokfile);
	unlink(v->statusfile);
	if (v->svcfile[0])
		unlink(v->svcfile);
}

/*
 * The operator has gone.
 *
 * The event pipe is the one thing that is open for exactly as long as there is
 * an operator: the foreground holds the reading end while it draws the
 * dashboard, and hands it to tmux when it execs one, so it closes when -- and
 * only when -- there is nobody left in front of this session. Its closing is a
 * hangup, and the answer to a hangup is to end the session, not to carry on
 * serving a terminal nobody is watching.
 *
 * This is the backstop rather than the usual path: an operator who leaves the
 * dashboard ends the session itself and waits for the tombstone. What lands
 * here is everything that gives a foreground no chance to do so -- the terminal
 * closing, the connection to it dropping, the process being killed.
 *
 * Only errors are asked for: poll reports a hangup whatever the event mask
 * says, and asking to write would return ready every time and spin. Losing the
 * parent is watched alongside it, because how a poll on the writing end of a
 * broken pipe reports itself is the sort of thing that differs between kernels,
 * and this is the one place where being wrong means a session nobody is
 * watching stays up. The two answer the same question and either is enough.
 */
static void *hangup_watch(void *arg)
{
	struct svc *v = arg;
	pid_t parent = getppid();

	for (;;) {
		struct pollfd p;

		p.fd = v->obs_fd;
		p.events = 0;
		p.revents = 0;
		if (poll(&p, 1, 500) > 0 &&
		    (p.revents & (POLLERR | POLLHUP | POLLNVAL)))
			break;
		if (getppid() != parent)
			break;
	}
	dbg_logf("host: the operator's terminal is gone -- ending the session");
	svc_end(v);
	return NULL;
}

/* The connection service behind the interactive dashboard, forked off so the
 * operator's terminal is free to be the dashboard or the shared tmux. It is
 * detached from that terminal but not independent of it: see hangup_watch. */
static void run_service(struct svc *v, void *hostkey, int wfd, int no_mcast,
			int no_dht)
{
	pthread_t hw;
	FILE *svcf;
	int devnull;

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
	svc_confine(v);			/* spawner, then sandbox: before threads */
	ui_emitter(&v->obs, wfd);	/* progress -> the foreground view */
	v->obs_fd = wfd;
	/* So a later `comrade` can tell a session being hosted from a tmux
	 * server this service was killed and left standing (find_live). */
	svcf = fopen(v->svcfile, "w");
	if (svcf) {
		fprintf(svcf, "%ld\n", (long)getpid());
		fclose(svcf);
	}
	if (!pthread_create(&hw, NULL, hangup_watch, v))
		pthread_detach(hw);
	svc_serve(v, hostkey, no_mcast, no_dht);
	spawner_destroy(v->sp);
	_exit(0);
}

/*
 * Longest the operator's shell waits for the service to finish ending the
 * session: publishing the tombstone (session.c: SESSION_TOMB_MS) and releasing
 * whoever was connected, which run together rather than one after the other.
 * On any working network this returns in well under a second. The ceiling sits
 * above what those two can cost between them (SESSION_WIND_MS), so the SIGTERM
 * below is a backstop against a service that has genuinely wedged rather than
 * something a slow network reaches -- one killed while still publishing would
 * leave the invitation pointing at silence, which is the case this exists for.
 */
#define TEARDOWN_WAIT_MS 10000

/*
 * The operator is leaving, so the session ends: wait for the service to finish
 * ending it, and clear what it leaves behind.
 *
 * Waiting is the point. The service has things to say on the way out -- a
 * tombstone on the rendezvous, so nobody holding the invitation waits on a
 * session that is over -- and returning the prompt before it has said them
 * would leave exactly the unnoticed background comrade this lifecycle exists
 * to prevent. It is SIGTERMed only if it overruns, since a service killed
 * mid-publish leaves the invitation pointing at silence.
 */
static void teardown(pid_t svc, const char *sock, const char *tokfile)
{
	int i, reaped = 0;

	for (i = 0; i < TEARDOWN_WAIT_MS / 50; i++) {
		if (waitpid(svc, NULL, WNOHANG) == svc) {
			reaped = 1;
			break;
		}
		os_msleep(50);
	}
	if (!reaped) {
		kill(svc, SIGTERM);
		waitpid(svc, NULL, 0);
	}
	unlink(tokfile);
	unlink(sock);
}

/*
 * Start the shared tmux session. The lifecycle options are pinned against
 * whatever the operator's own tmux.conf says: guests' attaches are
 * disposable and the operator owns the session's lifetime, so a
 * destroy-unattached/exit-unattached carried over from their personal
 * config must not let the first guest's departure take the whole service
 * down (it did: one join-and-leave before the operator entered ended the
 * session).
 */
static int tmux_start(const char *sock)
{
	char *mk[] = { "tmux", "-S", (char *)sock, "new-session", "-d",
		       "-s", "comrade",
		       ";", "set", "-g", "status-position", "top",
		       ";", "set", "-g", "window-size", "smallest",
		       ";", "set", "-g", "destroy-unattached", "off",
		       ";", "set", "-s", "exit-unattached", "off",
		       NULL };
	char err[256];

	if (run_capture(mk, err, sizeof(err))) {
		if (err[0])
			fprintf(stderr, "comrade: could not start tmux: %s\n",
				err);
		else
			fprintf(stderr, "comrade: could not start tmux "
				"(is it installed?)\n");
		return -1;
	}
	return 0;
}

static int start_new(int ui_mode, int no_mcast, int no_dht, int no_fwd)
{
	struct svc v;
	char id[ID_LEN + 1];
	void *hostkey;
	struct ui *ui;
	pid_t pid;
	int pfd[2], enter, entered = 0, rc = 0;

	memset(&v, 0, sizeof(v));
	v.no_fwd = no_fwd;
	if (gen_id(id)) {
		fprintf(stderr, "comrade: random generation failed\n");
		return 1;
	}
	sock_path(v.sock, sizeof(v.sock), id);
	tok_path(v.tokfile, sizeof(v.tokfile), id);
	status_path(v.statusfile, sizeof(v.statusfile), id);
	svc_path(v.svcfile, sizeof(v.svcfile), id);

	v.tok.version = TOKEN_VERSION;
	hostkey = sshd_hostkey_new(v.tok.hostpub);
	if (!hostkey) {
		fprintf(stderr, "comrade: host key generation failed\n");
		return 1;
	}
	if (random_bytes(v.tok.rdv, TOKEN_RDV_LEN) ||
	    random_bytes(v.tok.auth, TOKEN_AUTH_LEN)) {
		fprintf(stderr, "comrade: random generation failed\n");
		return 1;
	}

	if (tmux_start(v.sock))
		return 1;

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
		/* never returns */
		run_service(&v, hostkey, pfd[1], no_mcast, no_dht);
	}
	close(pfd[1]);
	sshd_hostkey_free(hostkey);		/* the service has its own copy */
	foreground_confine();			/* no network from here on */

	/*
	 * The view renders the service's progress and blocks until the operator
	 * enters (1, playing the zap), leaves (-1), or the service exits because
	 * the session ended (0). Detaching tmux (attach() returns 2, the session
	 * still alive) comes back to the dashboard rather than to the shell:
	 * between the two there is always one of them on screen, and leaving is
	 * a thing the operator does deliberately, from here.
	 */
	ui = ui_create(UI_ROLE_HOST, ui_mode);
	for (;;) {
		enter = ui ? ui_host_wait(ui, pfd[0]) : 0;
		if (enter != 1)
			break;
		entered = 1;
		rc = attach(id, pfd[0]);
		if (rc != 2)
			break;
	}
	ui_destroy(ui);

	if (!enter) {			/* the service went first: nothing to wait */
		close(pfd[0]);
		kill_tmux(v.sock);	/* unless it left the tmux standing */
		fprintf(stderr, entered ?
			"comrade: the shared session ended.\n" :
			"comrade: session ended before you entered it.\n");
		return entered ? 0 : 1;
	}
	/*
	 * Every other way out of the loop above ends the session, and the shell
	 * waits for it to be ended: leaving the dashboard takes the tmux server
	 * first, while a session whose last shell exited has already lost it.
	 * What is waited on is the same either way -- the service publishing
	 * its tombstone and going -- because a prompt handed back before that
	 * is a comrade still running where nobody is looking.
	 */
	fprintf(stderr, "comrade: ending the session ...\n");
	if (enter < 0)
		kill_tmux(v.sock);
	teardown(pid, v.sock, v.tokfile);
	unlink(v.svcfile);
	close(pfd[0]);
	fprintf(stderr, "comrade: session ended.\n");
	return enter < 0 ? 0 : rc;
}

int host_run(int ui_mode, int no_mcast, int no_dht, int no_fwd)
{
	char id[ID_LEN + 1];

	sweep_stale();
	/*
	 * A live session is one somebody is sitting in front of, in the
	 * terminal it was started in -- the service ends with that foreground,
	 * so a session with nobody in front of it is a moment old at most. This
	 * is therefore not a session to adopt, and adopting it would be a way
	 * to resume one that was walked away from, which is the thing the
	 * lifecycle rules out. Say where it is instead.
	 */
	if (find_live(id)) {
		fprintf(stderr, "comrade: a session is already running in "
			"another terminal (its token: `comrade show`)\n"
			"comrade: end it there, or with `comrade stop`\n");
		return 1;
	}
	return start_new(ui_mode, no_mcast, no_dht, no_fwd);
}

/* Both token lines of a session's token file, newline-stripped; 0 when the
 * read-write line is there. */
static int read_tokens(const char *id, char *tok, size_t tn,
		       char *ro, size_t rn)
{
	char tf[512];
	FILE *f;
	char *nl;

	tok[0] = ro[0] = '\0';
	tok_path(tf, sizeof(tf), id);
	f = fopen(tf, "r");
	if (!f)
		return -1;
	if (fgets(tok, (int)tn, f) && (nl = strchr(tok, '\n')) != NULL)
		*nl = '\0';
	if (fgets(ro, (int)rn, f) && (nl = strchr(ro, '\n')) != NULL)
		*nl = '\0';
	fclose(f);
	return tok[0] ? 0 : -1;
}

/* A headless session's own state document, newline-stripped, or NULL. */
static char *read_statejson(const char *id, char *buf, size_t n)
{
	char path[512];
	FILE *f;
	size_t got;

	snprintf(path, sizeof(path), "%s/%s.json", state_dir(), id);
	f = fopen(path, "r");
	if (!f)
		return NULL;
	got = fread(buf, 1, n - 1, f);
	fclose(f);
	while (got && (buf[got - 1] == '\n' || buf[got - 1] == '\r'))
		got--;
	buf[got] = '\0';
	return got ? buf : NULL;
}

static void show_one(const char *id, void *arg)
{
	struct showfmt *f = arg;
	char sock[512], tok[TOKEN_STR_LEN + 8], ro[TOKEN_STR_LEN + 8];
	char state[4096];

	if (!session_live(id))
		return;
	sock_path(sock, sizeof(sock), id);
	if (read_tokens(id, tok, sizeof(tok), ro, sizeof(ro)))
		return;
	showfmt_session(f, id, sock, tok, ro,
			read_statejson(id, state, sizeof(state)));
}

int host_show(int what)
{
	struct showfmt f;

	showfmt_begin(&f, what, stdout);
	each_session(show_one, &f);
	return showfmt_end(&f);
}

struct only_ctx { char *only; size_t n; int count; };

static void live_one(const char *id, void *arg)
{
	struct only_ctx *c = arg;

	if (!session_live(id))
		return;
	if (c->only && !c->count)
		snprintf(c->only, c->n, "%s", id);
	c->count++;
}

/* Every live session; `only` picks the single one when the caller gave no
 * id. Returns the count. */
static int live_sessions(char *only, size_t n)
{
	struct only_ctx c;

	c.only = only;
	c.n = n;
	c.count = 0;
	each_session(live_one, &c);
	return c.count;
}

/* The one session an id-less machine verb may act on; -1 when ambiguous. */
static int resolve_id(const char *id_opt, char *id, size_t n)
{
	int count;

	if (id_opt) {
		if (!valid_id(id_opt)) {
			fprintf(stderr, "comrade: invalid --id\n");
			return -1;
		}
		snprintf(id, n, "%s", id_opt);
		return 0;
	}
	count = live_sessions(id, n);
	if (count > 1) {
		fprintf(stderr, "comrade: several sessions running -- name "
			"one with --id\n");
		return -1;
	}
	return count ? 0 : 1;
}

static volatile sig_atomic_t g_stop;

/*
 * The first signal asks for a wind-down, which the stop watch below carries
 * out. The second is taken at its word: the handler puts the default back and
 * re-raises, so a process that cannot reach its own exit -- because it is
 * wedged somewhere after the watch has been joined, or before it ever ran --
 * still answers the signal rather than needing to be killed outright. Both
 * calls are async-signal-safe.
 */
static void on_stop_sig(int sig)
{
	if (g_stop) {
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	g_stop = 1;
}

/*
 * SIGTERM/SIGINT end a headless session by killing its tmux server: the end
 * monitor sees that, every worker's sshd closes, the serve loop drains and
 * returns. A signal handler cannot run tmux, so this thread does.
 */
struct stop_watch {
	struct svc *v;			/* the service to end */
	uint64_t deadline;		/* --expire, as mono_ms; 0 = none */
	volatile int done;
};

/*
 * End the session on the supervisor's signal or the --expire deadline. A
 * signal handler cannot run tmux, so this thread does (svc_end).
 */
static void *stop_watch_thread(void *arg)
{
	struct stop_watch *w = arg;
	int fire = 0;

	while (!w->done) {
		if (g_stop || (w->deadline && mono_ms() >= w->deadline)) {
			fire = 1;
			break;
		}
		usleep(200 * 1000);
	}
	if (fire && !w->done)
		svc_end(w->v);
	return NULL;
}

int host_headless(const char *id_opt, int no_mcast, int no_dht, int no_fwd,
		  int forward_only, int expire_s, int max_clients)
{
	struct svc v;
	struct mview *m;
	struct stop_watch w;
	char id[ID_MAX + 1], jsonp[512], pidp[512];
	void *hostkey;
	pthread_t th;
	FILE *pf;
	int layers;

	memset(&v, 0, sizeof(v));
	v.no_fwd = no_fwd;
	v.forward_only = forward_only;
	v.serve_max = max_clients;
	v.admit_max = max_clients;
	sweep_stale();
	if (id_opt) {
		if (!valid_id(id_opt)) {
			fprintf(stderr, "comrade: invalid --id (a-z, 0-9, "
				"'-', '_', at most %d chars)\n", ID_MAX);
			return 2;
		}
		snprintf(id, sizeof(id), "%s", id_opt);
		sock_path(v.sock, sizeof(v.sock), id);
		if (tmux_alive(v.sock)) {
			fprintf(stderr, "comrade: session '%s' is already "
				"running (comrade stop --id %s)\n", id, id);
			return 2;
		}
	} else if (gen_id(id)) {
		fprintf(stderr, "comrade: random generation failed\n");
		return 1;
	}
	sock_path(v.sock, sizeof(v.sock), id);
	tok_path(v.tokfile, sizeof(v.tokfile), id);
	status_path(v.statusfile, sizeof(v.statusfile), id);
	json_path(jsonp, sizeof(jsonp), id);
	pid_path(pidp, sizeof(pidp), id);

	v.tok.version = TOKEN_VERSION;
	hostkey = sshd_hostkey_new(v.tok.hostpub);
	if (!hostkey) {
		fprintf(stderr, "comrade: host key generation failed\n");
		return 1;
	}
	if (random_bytes(v.tok.rdv, TOKEN_RDV_LEN) ||
	    random_bytes(v.tok.auth, TOKEN_AUTH_LEN)) {
		fprintf(stderr, "comrade: random generation failed\n");
		return 1;
	}
	m = mview_create(id, jsonp, v.sock);
	if (!m)
		return 1;
	/* Forward-only serves no shell, so it starts no tmux -- and needs
	 * none installed. The others anchor the session on the shared tmux. */
	if (!forward_only && tmux_start(v.sock)) {
		/* The error document stays for the supervisor's page; the
		 * next sweep collects it. */
		mview_error(m, "no_tmux");
		return 3;
	}
	pf = fopen(pidp, "w");
	if (pf) {
		fprintf(pf, "%ld\n", os_getpid());
		fclose(pf);
	}
	/* Fork the spawner and confine, while still single-threaded and before
	 * the first socket -- the stop-watch thread and the serving come after. */
	layers = svc_confine(&v);
	mview_sandbox(m, layers, sandbox_filter_insns());
	signal(SIGTERM, on_stop_sig);
	signal(SIGINT, on_stop_sig);
	signal(SIGPIPE, SIG_IGN);

	mview_limits(m, expire_s, max_clients);
	mview_bind(m, &v.obs);
	w.v = &v;
	w.deadline = expire_s > 0 ? mono_ms() + (uint64_t)expire_s * 1000 : 0;
	w.done = 0;
	if (pthread_create(&th, NULL, stop_watch_thread, &w)) {
		fprintf(stderr, "comrade: thread creation failed\n");
		unlink(pidp);
		mview_destroy(m);
		spawner_destroy(v.sp);
		return 1;
	}
	svc_serve(&v, hostkey, no_mcast, no_dht);
	w.done = 1;
	pthread_join(th, NULL);
	spawner_destroy(v.sp);
	unlink(pidp);
	mview_destroy(m);
	sshd_hostkey_free(hostkey);
	return 0;
}

int host_stop(const char *id_opt)
{
	char id[ID_MAX + 1], sock[512], path[512];
	FILE *pf;
	long pid = 0;
	int r, i;

	sweep_stale();
	r = resolve_id(id_opt, id, sizeof(id));
	if (r < 0)
		return 1;
	if (r > 0)
		return 0;		/* nothing running: stop is idempotent */
	sock_path(sock, sizeof(sock), id);
	pid_path(path, sizeof(path), id);
	pf = fopen(path, "r");
	if (pf) {
		if (fscanf(pf, "%ld", &pid) != 1)
			pid = 0;
		fclose(pf);
	}
	if (tmux_alive(sock)) {
		char *k[] = { "tmux", "-S", sock, "kill-server", NULL };

		run_wait(k);
	}
	if (pid > 0) {
		kill((pid_t)pid, SIGTERM);
		for (i = 0; i < 30 && !kill((pid_t)pid, 0); i++)
			usleep(100 * 1000);
	} else {
		/*
		 * An interactive session's service records no pid -- its
		 * lifetime belongs to the operator's foreground, not to a
		 * supervisor. Killing its tmux is the whole signal it needs;
		 * what is worth waiting for is the tombstone it publishes on
		 * the way out, and the token file going is the last thing it
		 * does. When this returns, the invitation says so too.
		 */
		char tf[512];

		tok_path(tf, sizeof(tf), id);
		for (i = 0; i < 120 && access(tf, F_OK) == 0; i++)
			usleep(50 * 1000);
	}
	sweep_stale();			/* collect whatever the exit left */
	return 0;
}

int host_capture(const char *id_opt, int ansi)
{
	char id[ID_MAX + 1], sock[512];
	char *cv[9];
	int n = 0, r;

	r = resolve_id(id_opt, id, sizeof(id));
	if (r < 0)
		return 1;
	if (r > 0) {
		fprintf(stderr, "comrade: no running session\n");
		return 1;
	}
	sock_path(sock, sizeof(sock), id);
	if (!tmux_alive(sock)) {
		/* A live forward-only session has no terminal to capture. */
		fprintf(stderr, session_live(id) ?
			"comrade: that session is forwarding-only "
			"(no terminal)\n" : "comrade: no running session\n");
		return 1;
	}
	cv[n++] = "tmux";
	cv[n++] = "-S";
	cv[n++] = sock;
	cv[n++] = "capture-pane";
	cv[n++] = "-p";
	if (ansi)
		cv[n++] = "-e";
	cv[n++] = "-t";
	cv[n++] = "comrade";
	cv[n] = NULL;
	r = run_wait(cv);
	return r < 0 ? 1 : r;
}

int host_attach(const char *id_opt, int read_only)
{
	char id[ID_MAX + 1], sock[512];
	char *cv[8];
	int n = 0, r;

	r = resolve_id(id_opt, id, sizeof(id));
	if (r < 0)
		return 1;
	if (r > 0) {
		fprintf(stderr, "comrade: no running session\n");
		return 1;
	}
	sock_path(sock, sizeof(sock), id);
	if (!tmux_alive(sock)) {
		fprintf(stderr, session_live(id) ?
			"comrade: that session is forwarding-only "
			"(no terminal)\n" : "comrade: no running session\n");
		return 1;
	}
	/* Exec tmux attach, taking over this process: a web front end spawns
	 * this on a PTY and wires its websocket to it, without knowing the
	 * socket path or the session name. -r is read-only. */
	cv[n++] = "tmux";
	cv[n++] = "-S";
	cv[n++] = sock;
	cv[n++] = "attach";
	if (read_only)
		cv[n++] = "-r";
	cv[n++] = "-t";
	cv[n++] = "comrade";
	execvp(cv[0], cv);
	fprintf(stderr, "comrade: could not exec tmux\n");
	return 1;
}

#endif
