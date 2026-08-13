/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>

#include "host.h"

#ifndef COMRADE_HAVE_SESSION

int host_run(int ui_mode, int no_mcast)
{
	(void)ui_mode;
	(void)no_mcast;
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
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "keys.h"
#include "session.h"
#include "sig.h"
#include "sshd.h"
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

static int attach(const char *id)
{
	char sock[512];
	char *argv[] = { "tmux", "-S", sock, "attach", "-t", "comrade", NULL };

	sock_path(sock, sizeof(sock), id);
	execvp(argv[0], argv);
	fprintf(stderr, "comrade: could not run tmux\n");
	return 1;
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

static int start_new(int ui_mode, int no_mcast)
{
	struct svc v;
	char id[ID_LEN + 1];
	void *hostkey;
	struct ui *ui;
	pid_t pid;
	int pfd[2], enter;

	memset(&v, 0, sizeof(v));
	gen_id(id);
	sock_path(v.sock, sizeof(v.sock), id);
	tok_path(v.tokfile, sizeof(v.tokfile), id);

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
			       "-s", "comrade", NULL };

		if (run_wait(mk)) {
			fprintf(stderr,
				"comrade: could not start tmux (is it installed?)\n");
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

int host_run(int ui_mode, int no_mcast)
{
	char id[ID_LEN + 1];

	if (find_live(id)) {
		fprintf(stderr, "comrade: re-attaching to your running session"
			" (its token: `comrade show`)\n");
		return attach(id);
	}
	return start_new(ui_mode, no_mcast);
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
