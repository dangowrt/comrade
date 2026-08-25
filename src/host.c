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

#include "conn.h"
#include "mview.h"
#include "dbg.h"
#include "keys.h"
#include "oscompat.h"
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
	int no_fwd;			/* decline all client port forwarding */
	int forward_only;		/* serve no shell/tmux, forwarding only */
	volatile int stop;		/* forward-only: end the serve loop */
	sock_t stop_wfd;		/* shut to release the turnstile promptly */
	struct session_obs obs;		/* view-event emitter to the foreground */
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
		fprintf(stderr, "comrade: refusing unsafe state dir %s\n", dir);
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

/* The service pid a session's pidfile names, alive; 0 if none or dead. */
static long pid_of(const char *id)
{
	char pp[512];
	FILE *f;
	long pid = 0;

	pid_path(pp, sizeof(pp), id);
	f = fopen(pp, "r");
	if (!f)
		return 0;
	if (fscanf(f, "%ld", &pid) != 1)
		pid = 0;
	fclose(f);
	return (pid > 0 && kill((pid_t)pid, 0) == 0) ? pid : 0;
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
 * Visit every session id once (deduped): a tmux socket names one, and so does
 * a headless pidfile, and a tmux-headless session has both. Iterate pidfiles
 * first, then sockets whose id has no pidfile, so each id is seen once.
 */
static void each_session(void (*fn)(const char *id, void *arg), void *arg)
{
	const char *suf[2] = { ".pid", ".sock" };
	int pass;

	for (pass = 0; pass < 2; pass++) {
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
			/* Second pass (.sock): skip ids a pidfile already
			 * carried, so a tmux-headless session is not doubled. */
			if (pass == 1) {
				pid_path(pp, sizeof(pp), id);
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
}

/* Remove the state files of sessions whose tmux server or service pid is
 * gone, so stale state from an earlier run cannot linger or confuse a fresh
 * start. */
static void sweep_stale(void)
{
	each_session(sweep_one, NULL);
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
		/* A headless session (it has a pidfile) belongs to its
		 * supervisor: the interactive `comrade` never adopts it. */
		pid_path(path, sizeof(path), cand);
		if (access(path, F_OK) == 0)
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

/* The serving core: sessions over the shared tmux, again after each client,
 * until the tmux server is gone. The observer in v->obs is already bound. */
static void svc_serve(struct svc *v, void *hostkey, int no_mcast, int no_dht)
{
	char cmd[600];
	char cmd_ro[600];
	struct session_cfg cfg;
	sock_t end_fd = INVALID_SOCK;
	pid_t end_pid = -1;

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

	/*
	 * Non-forward-only is anchored to tmux: the shared session is the
	 * durable state and the loop runs while it lives. Forward-only has no
	 * tmux, so it runs until stopped (v->stop, set by the supervisor's
	 * signal watcher or the operator) or the bounded grant is spent.
	 */
	while (v->forward_only ? !v->stop : tmux_alive(v->sock)) {
		cfg.tok = v->tok;	/* carry the located anchor forward, so the
					 * next idle attempt reinforces it rather
					 * than locating (and churning) a new one */
		session_run(&cfg);
		if (v->serve_max) {
			/* The bounded grant is spent: end for good, taking
			 * the shared tmux (if any) with us. */
			if (!v->forward_only) {
				char *k[] = { "tmux", "-S", v->sock,
					      "kill-server", NULL };

				run_wait(k);
			}
			break;
		}
	}
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
}

/* The backgrounded connection service behind the interactive dashboard. */
static void run_service(struct svc *v, void *hostkey, int wfd, int no_mcast,
			int no_dht)
{
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
	ui_emitter(&v->obs, wfd);	/* progress -> the foreground view */
	svc_serve(v, hostkey, no_mcast, no_dht);
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

static int read_tokens(const char *id, char *tok, size_t tn,
		       char *ro, size_t rn);

static int start_new(int ui_mode, int no_mcast, int no_dht, int no_fwd)
{
	struct svc v;
	char id[ID_LEN + 1];
	void *hostkey;
	struct ui *ui;
	pid_t pid;
	int pfd[2], enter, rc = 0;

	memset(&v, 0, sizeof(v));
	v.no_fwd = no_fwd;
	if (gen_id(id)) {
		fprintf(stderr, "comrade: random generation failed\n");
		return 1;
	}
	sock_path(v.sock, sizeof(v.sock), id);
	tok_path(v.tokfile, sizeof(v.tokfile), id);
	status_path(v.statusfile, sizeof(v.statusfile), id);

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

	/* The view renders the service's progress and blocks until the operator
	 * enters (1, playing the zap), aborts (-1), or the service exits (0). A
	 * detach (attach() returns 2, session still alive) loops back to the
	 * dashboard instead of leaving it. */
	ui = ui_create(UI_ROLE_HOST, ui_mode);
	for (;;) {
		enter = ui ? ui_host_wait(ui, pfd[0]) : 0;
		if (enter != 1)
			break;
		rc = attach(id);
		if (rc != 2)
			break;
	}
	ui_destroy(ui);
	close(pfd[0]);

	if (enter == 1)
		return rc;
	if (enter < 0) {			/* operator aborted */
		teardown(pid, v.sock, v.tokfile);
		fprintf(stderr, "comrade: aborted.\n");
		return 0;
	}
	fprintf(stderr, "comrade: session ended before you entered "
		"(token: `comrade show`)\n");
	return 1;
}

/*
 * The foreground for a session this process did not start. It has no event
 * stream to render -- that pipe belongs to whoever forked the service -- so
 * the dashboard carries the invite from the state directory and waits on the
 * keyboard, with the connection status coming from attach()'s own status line
 * once inside.
 *
 * It exists because of the one rule this path must not break: a live session
 * is always either on screen as the shared terminal or as the dashboard, never
 * neither. Looping straight back into tmux left no way out of the session, and
 * exiting on a detach left it running with nothing to show it -- which is the
 * same as forgetting it. So a detach lands here, and the only way past the
 * dashboard is to end the session.
 */
static int reattach(const char *id, int ui_mode)
{
	char tok[TOKEN_STR_LEN + 1], ro[TOKEN_STR_LEN + 1];
	struct session_obs obs;
	struct ui *u;
	int quiet[2], enter, rc = 0;

	if (pipe(quiet))
		return 1;
	u = ui_create(UI_ROLE_HOST, ui_mode);
	if (!u) {
		close(quiet[0]);
		close(quiet[1]);
		return 1;
	}
	memset(&obs, 0, sizeof(obs));
	ui_bind(u, &obs);
	if (!read_tokens(id, tok, sizeof(tok), ro, sizeof(ro))) {
		if (obs.token)
			obs.token(obs.arg, tok);
		if (ro[0] && obs.token_ro)
			obs.token_ro(obs.arg, ro);
	}
	for (;;) {
		enter = ui_host_wait(u, quiet[0]);
		if (enter != 1)
			break;
		rc = attach(id);
		if (rc != 2)
			break;
	}
	ui_destroy(u);
	close(quiet[0]);
	close(quiet[1]);
	if (enter < 0) {		/* the dashboard is left by ending it */
		host_stop(id);
		fprintf(stderr, "comrade: session ended.\n");
		return 0;
	}
	return rc;
}

int host_run(int ui_mode, int no_mcast, int no_dht, int no_fwd)
{
	char id[ID_LEN + 1];

	sweep_stale();
	if (find_live(id)) {
		fprintf(stderr, "comrade: re-attaching to your running session"
			" (its token: `comrade show`)\n");
		if (no_mcast || no_dht || no_fwd)
			fprintf(stderr, "comrade: ignoring%s%s%s -- the "
				"running service keeps what it was started "
				"with\n",
				no_mcast ? " --no-multicast" : "",
				no_dht ? " --no-dht" : "",
				no_fwd ? " --no-forwarding" : "");
		return reattach(id, ui_mode);
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

static void on_stop_sig(int sig)
{
	(void)sig;
	g_stop = 1;
}

/*
 * SIGTERM/SIGINT end a headless session by killing its tmux server: the end
 * monitor sees that, every worker's sshd closes, the serve loop drains and
 * returns. A signal handler cannot run tmux, so this thread does.
 */
struct stop_watch {
	struct svc *v;			/* forward-only: set v->stop; else NULL */
	const char *sock;
	uint64_t deadline;		/* --expire, as mono_ms; 0 = none */
	volatile int done;
};

/*
 * End the session on the supervisor's signal or the --expire deadline. A
 * tmux-anchored session is ended by killing its server (the serve loop's
 * tmux_alive goes false); a forward-only one has no tmux, so its serve flag
 * is raised instead. A signal handler cannot run tmux, so this thread does.
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
	if (fire && !w->done) {
		if (w->v) {
			w->v->stop = 1;
			/* Wake the turnstile's end-fd so it returns at once. */
			if (sock_isset(w->v->stop_wfd))
				sock_shutdown(w->v->stop_wfd, SHUT_RDWR);
		} else {
			char *k[] = { "tmux", "-S", (char *)w->sock,
				      "kill-server", NULL };

			run_wait(k);
		}
	}
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
	signal(SIGTERM, on_stop_sig);
	signal(SIGINT, on_stop_sig);
	signal(SIGPIPE, SIG_IGN);

	mview_limits(m, expire_s, max_clients);
	mview_bind(m, &v.obs);
	w.v = forward_only ? &v : NULL;
	w.sock = v.sock;
	w.deadline = expire_s > 0 ? mono_ms() + (uint64_t)expire_s * 1000 : 0;
	w.done = 0;
	if (pthread_create(&th, NULL, stop_watch_thread, &w)) {
		fprintf(stderr, "comrade: thread creation failed\n");
		unlink(pidp);
		mview_destroy(m);
		return 1;
	}
	svc_serve(&v, hostkey, no_mcast, no_dht);
	w.done = 1;
	pthread_join(th, NULL);
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
