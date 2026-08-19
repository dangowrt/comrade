/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Stage 1 of the SSH bring-up: run the real libssh server and client against
 * each other over a bare socketpair (no KCP yet), proving host-key pinning,
 * token-secret auth, channel setup and bidirectional data over the same fd
 * abstraction the punched KCP path will later present. The server runs `cat`,
 * so a correct round-trip echoes the request back byte for byte.
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

#define MSG_LEN 4096

struct srv_arg {
	int fd;
	void *hostkey;
	uint8_t auth[TOKEN_AUTH_LEN];
};

static void *srv_thread(void *p)
{
	struct srv_arg *a = p;
	struct sshd_opts o;

	memset(&o, 0, sizeof(o));
	o.hostkey = a->hostkey;
	memcpy(o.auth, a->auth, sizeof(o.auth));
	o.command = "cat";
	o.use_pty = 0;
	sshd_serve_fd(a->fd, &o);
	return NULL;
}

/* One session. corrupt_fp flips a fingerprint bit so the client must reject
 * the host key. Returns the client's rc; *echo_ok reports byte-exact echo. */
static int one_round(void *hostkey, const uint8_t fp[32],
		     const uint8_t auth[TOKEN_AUTH_LEN], int corrupt_fp,
		     int *echo_ok)
{
	uint8_t msg[MSG_LEN], got[MSG_LEN];
	struct sshc_opts co;
	struct srv_arg sa;
	pthread_t th;
	size_t gl = 0, i;
	int rc;

	int sp[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.fd = sp[1];
	sa.hostkey = hostkey;
	memcpy(sa.auth, auth, sizeof(sa.auth));
	assert(pthread_create(&th, NULL, srv_thread, &sa) == 0);

	for (i = 0; i < MSG_LEN; i++)
		msg[i] = (uint8_t)(i * 97 + 13);

	memset(&co, 0, sizeof(co));
	memcpy(co.host_fp, fp, 32);
	if (corrupt_fp)
		co.host_fp[0] ^= 0x01;
	memcpy(co.auth, auth, sizeof(co.auth));
	co.interactive = 0;
	co.send = msg;
	co.send_len = MSG_LEN;
	co.recv = got;
	co.recv_cap = MSG_LEN;
	co.recv_len = &gl;

	rc = sshc_connect_fd(sp[0], &co);
	pthread_join(th, NULL);

	*echo_ok = (rc == 0 && gl == MSG_LEN && memcmp(got, msg, MSG_LEN) == 0);
	return rc;
}

int main(void)
{
	uint8_t fp[32];
	uint8_t auth[TOKEN_AUTH_LEN];
	void *hostkey;
	int rc, echo_ok;
	size_t i;

	/* A peer closing first must not kill the test outright. */
	signal(SIGPIPE, SIG_IGN);

	for (i = 0; i < sizeof(auth); i++)
		auth[i] = (uint8_t)(i * 31 + 7);

	hostkey = sshd_hostkey_new(fp);
	assert(hostkey);

	/* Correct fingerprint and secret: full round-trip must succeed. */
	rc = one_round(hostkey, fp, auth, 0, &echo_ok);
	if (rc != 0 || !echo_ok) {
		fprintf(stderr, "SSH FAIL: rc=%d echo_ok=%d\n", rc, echo_ok);
		sshd_hostkey_free(hostkey);
		return 1;
	}

	/* Wrong fingerprint: the client must refuse (no TOFU). */
	rc = one_round(hostkey, fp, auth, 1, &echo_ok);
	if (rc == 0 || echo_ok) {
		fprintf(stderr, "SSH FAIL: MITM fingerprint was accepted\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}

	sshd_hostkey_free(hostkey);
	printf("SSH PASS: pinned auth + %d-byte echo over socketpair\n", MSG_LEN);
	return 0;
}
