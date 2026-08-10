/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>

#include "host.h"

#ifndef COMRADE_HAVE_SESSION

int host_run(void)
{
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

/*
 * The host is tmate-like. It runs a private, randomly-named tmux server so
 * concurrent comrade hosts never collide on a session, and so a remote client can
 * never reach the operator's own tmux. A backgrounded connection service
 * (setsid, so it outlives the foreground) serves that session over the punched
 * link and records the current token; the foreground prints the token and
 * attaches. Detaching leaves the service running; `comrade` again re-attaches a
 * live session, and a session ends when its tmux server dies.
 */

#define ID_LEN 12			/* hex chars of the per-session id */

struct svc {
	struct token tok;
	char sock[512];
	char tokfile[512];
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
}

/* The backgrounded connection service: serve the shared tmux over the punched
 * link, again after each client, until the tmux server is gone. */
static void run_service(struct svc *v, void *hostkey)
{
	char cmd[600];
	struct session_cfg cfg;
	int devnull;

	setsid();
	devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}
	snprintf(cmd, sizeof(cmd), "tmux -S %s attach -t comrade", v->sock);

	memset(&cfg, 0, sizeof(cfg));
	cfg.is_host = 1;
	cfg.tok = v->tok;
	cfg.sig_flags = SIG_DHT | SIG_MCAST;
	cfg.stun_port = 3478;
	cfg.stun_auto = 1;
	cfg.log_level = -1;
	cfg.connect_timeout_s = 60;
	cfg.hostkey = hostkey;
	cfg.ssh_command = cmd;
	cfg.use_pty = 1;
	cfg.on_rendezvous = on_rendezvous;
	cfg.arg = v;

	while (tmux_alive(v->sock))
		session_run(&cfg);
	unlink(v->tokfile);
	_exit(0);
}

static int start_new(void)
{
	struct svc v;
	char id[ID_LEN + 1];
	void *hostkey;
	pid_t pid;
	int waited;

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

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "comrade: fork failed\n");
		return 1;
	}
	if (pid == 0)
		run_service(&v, hostkey);	/* never returns */
	sshd_hostkey_free(hostkey);		/* the service has its own copy */

	/* Wait for the service to publish and record the token, then show it. */
	for (waited = 0; waited < 400; waited++) {
		char tok[TOKEN_STR_LEN + 8];
		FILE *f = fopen(v.tokfile, "r");

		if (f) {
			if (fgets(tok, sizeof(tok), f))
				printf("comrade session token (share out of band):\n\n"
				       "    %s\n", tok);
			fclose(f);
			fflush(stdout);
			break;
		}
		usleep(100000);
	}
	if (waited >= 400)
		fprintf(stderr, "comrade: warning: no token yet; run `comrade show`\n");

	return attach(id);			/* foreground; execs tmux */
}

int host_run(void)
{
	char id[ID_LEN + 1];

	if (find_live(id))
		return attach(id);
	return start_new();
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
