/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Session-end teardown: the server's command exits on its own (a short sleep,
 * as a real tmux session does when its last shell exits). The server must then
 * close the channel toward the client so the client's read returns and it can
 * exit. A pty master reports the command's exit as EIO rather than a clean EOF,
 * which the connectors do not reliably surface, so the server watches the child
 * pid directly; without that the client would hang forever waiting for a close
 * that never comes -- the "[exited] then hang" symptom. The test's ctest
 * timeout turns any such hang into a failure. Both a pipe- and a pty-backed
 * command are exercised.
 */

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "sshc.h"
#include "sshd.h"

/* A liveness probe that reports the session gone after a few polls, standing in
 * for tmux's has-session going false while `tmux attach` itself lingers. */
static int g_alive_calls;
static int probe_dies(void *arg)
{
	(void)arg;
	return (++g_alive_calls < 8);	/* alive briefly, then gone */
}

struct srv_arg {
	int fd;
	void *hostkey;
	uint8_t auth[TOKEN_AUTH_LEN];
	int use_pty;
	const char *command;
	int (*alive)(void *arg);
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
	o.alive = a->alive;
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

/* Returns 0 if the client returned in time, -1 if it hung. The command either
 * exits on its own (alive == NULL) or lingers while the probe reports the end. */
static int one_round(void *hostkey, const uint8_t fp[32],
		     const uint8_t auth[TOKEN_AUTH_LEN], int use_pty,
		     const char *command, int (*alive)(void *))
{
	struct srv_arg sa;
	struct cli_arg ca;
	pthread_t sth, cth;
	int sp[2], i;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.fd = sp[1];
	sa.hostkey = hostkey;
	memcpy(sa.auth, auth, sizeof(sa.auth));
	sa.use_pty = use_pty;
	sa.command = command;
	sa.alive = alive;

	memset(&ca, 0, sizeof(ca));
	ca.fd = sp[0];
	memcpy(ca.fp, fp, 32);
	memcpy(ca.auth, auth, sizeof(ca.auth));

	assert(pthread_create(&sth, NULL, srv_thread, &sa) == 0);
	assert(pthread_create(&cth, NULL, cli_thread, &ca) == 0);

	for (i = 0; i < 50 && !ca.done; i++)
		usleep(100000);
	if (!ca.done)
		return -1;		/* hung: let the ctest timeout catch it too */

	pthread_join(cth, NULL);
	pthread_join(sth, NULL);
	return 0;
}

int main(void)
{
	uint8_t fp[32], auth[TOKEN_AUTH_LEN];
	void *hostkey;
	size_t i;

	for (i = 0; i < sizeof(auth); i++)
		auth[i] = (uint8_t)(i * 31 + 7);
	hostkey = sshd_hostkey_new(fp);
	assert(hostkey);

	/* Command exits on its own (a shell whose last command returns). */
	if (one_round(hostkey, fp, auth, 0, "sleep 0.3", NULL)) {
		fprintf(stderr, "SSHEXIT FAIL: client hung, command exit (pipe)\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}
	if (one_round(hostkey, fp, auth, 1, "sleep 0.3", NULL)) {
		fprintf(stderr, "SSHEXIT FAIL: client hung, command exit (pty)\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}

	/* Command lingers (as `tmux attach` does); the liveness probe ends it. */
	g_alive_calls = 0;
	if (one_round(hostkey, fp, auth, 1, "sleep 30", probe_dies)) {
		fprintf(stderr, "SSHEXIT FAIL: client hung, liveness probe (pty)\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}

	sshd_hostkey_free(hostkey);
	printf("SSHEXIT PASS: client exits on command end and on probe\n");
	return 0;
}
