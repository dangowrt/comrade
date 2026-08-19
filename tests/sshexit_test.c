/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Session-end teardown. When the served session ends, the server must close
 * the channel toward the client so the client's read returns and it exits;
 * without that the client hangs -- the "[exited] then hang" symptom. Three
 * paths are exercised, each with the ctest timeout turning a hang into a fail:
 *
 *  - a command that exits on its own over a pipe (clean EOF), and
 *  - the same over a pty (the master reports EIO, not EOF, so the server relies
 *    on watching the child pid), and
 *  - a command that never exits, ended instead by the end-of-session fd going
 *    readable -- exactly how the host's liveness monitor releases the client
 *    the instant the shared tmux session dies.
 */

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "sshc.h"
#include "sshd.h"

struct srv_arg {
	int fd;
	void *hostkey;
	uint8_t auth[TOKEN_AUTH_LEN];
	int use_pty;
	const char *command;
	int end_fd;
};

static void *srv_thread(void *p)
{
	struct srv_arg *a = p;
	struct sshd_opts o;

	memset(&o, 0, sizeof(o));
	o.hostkey = a->hostkey;
	memcpy(o.auth, a->auth, sizeof(o.auth));
	o.command = a->command;
	o.use_pty = a->use_pty;
	o.end_fd = a->end_fd;
	sshd_serve_fd(a->fd, &o);
	return NULL;
}

struct cli_arg {
	int fd;
	uint8_t fp[32];
	uint8_t auth[TOKEN_AUTH_LEN];
	int rc;
	volatile int done;
};

static void *cli_thread(void *p)
{
	struct cli_arg *c = p;
	uint8_t got[64];
	size_t gl = 0;
	struct sshc_opts co;

	memset(&co, 0, sizeof(co));
	memcpy(co.host_fp, c->fp, 32);
	memcpy(co.auth, c->auth, sizeof(co.auth));
	co.interactive = 0;		/* interactive mode hijacks real stdio */
	co.send = (const uint8_t *)"x";
	co.send_len = 1;
	co.recv = got;
	co.recv_cap = sizeof(got);
	co.recv_len = &gl;
	c->rc = sshc_connect_fd(c->fd, &co);
	c->done = 1;
	return NULL;
}

/*
 * Serve one round. If close_after_ms >= 0, the write end of the end-of-session
 * fd is closed after that delay (standing in for the liveness monitor exiting);
 * the command then never exits on its own. Otherwise the command exits itself.
 * Returns 0 if the client returned in time, -1 if it hung.
 */
static int one_round(void *hostkey, const uint8_t fp[32],
		     const uint8_t auth[TOKEN_AUTH_LEN], int use_pty,
		     const char *command, int close_after_ms)
{
	struct srv_arg sa;
	struct cli_arg ca;
	pthread_t sth, cth;
	int sp[2], ep[2] = { -1, -1 }, i;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.fd = sp[1];
	sa.hostkey = hostkey;
	memcpy(sa.auth, auth, sizeof(sa.auth));
	sa.use_pty = use_pty;
	sa.command = command;
	if (close_after_ms >= 0) {
		assert(pipe(ep) == 0);
		sa.end_fd = ep[0];	/* read end handed to the server */
	}

	memset(&ca, 0, sizeof(ca));
	ca.fd = sp[0];
	memcpy(ca.fp, fp, 32);
	memcpy(ca.auth, auth, sizeof(ca.auth));

	assert(pthread_create(&sth, NULL, srv_thread, &sa) == 0);
	assert(pthread_create(&cth, NULL, cli_thread, &ca) == 0);

	if (close_after_ms >= 0) {
		usleep((useconds_t)close_after_ms * 1000);
		close(ep[1]);		/* EOF on the server's end_fd => end */
	}

	for (i = 0; i < 50 && !ca.done; i++)
		usleep(100000);
	if (!ca.done)
		return -1;		/* hung: let the ctest timeout catch it too */

	pthread_join(cth, NULL);
	pthread_join(sth, NULL);
	if (ep[0] >= 0)
		close(ep[0]);
	return 0;
}

int main(void)
{
	uint8_t fp[32], auth[TOKEN_AUTH_LEN];
	void *hostkey;
	size_t i;

	/* A peer closing first must not kill the test outright. */
	signal(SIGPIPE, SIG_IGN);

	for (i = 0; i < sizeof(auth); i++)
		auth[i] = (uint8_t)(i * 31 + 7);
	hostkey = sshd_hostkey_new(fp);
	assert(hostkey);

	/* Command exits on its own (a shell whose last command returns). */
	if (one_round(hostkey, fp, auth, 0, "sleep 0.3", -1)) {
		fprintf(stderr, "SSHEXIT FAIL: client hung, command exit (pipe)\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}
	if (one_round(hostkey, fp, auth, 1, "sleep 0.3", -1)) {
		fprintf(stderr, "SSHEXIT FAIL: client hung, command exit (pty)\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}

	/* Command lingers (as `tmux attach` does); the end fd ends the session. */
	if (one_round(hostkey, fp, auth, 1, "sleep 30", 500)) {
		fprintf(stderr, "SSHEXIT FAIL: client hung, end fd (pty)\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}

	sshd_hostkey_free(hostkey);
	printf("SSHEXIT PASS: client exits on command end and on end fd\n");
	return 0;
}
