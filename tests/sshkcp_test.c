/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Stage 2 of the SSH bring-up: run the real libssh server and client through
 * the sshbridge over a KCP stream, proving SSH survives KCP's framing and
 * flow control. The two KCP streams are cross-connected in-process (each
 * one's output is fed straight into the other's input), so this isolates the
 * SSH-over-KCP path from the network; the punched-path validation is done
 * separately by the e2e tool on real boxes.
 */

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#include "sshbridge.h"
#include "sshc.h"
#include "sshd.h"
#include "stream.h"

#define MSG_LEN 20000
#define CONV 0x70326b63

static struct stream *g_a, *g_b;

static uint32_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* Cross-connect: whatever one stream emits is the other's input. */
static int out_to_b(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	return stream_input(g_b, data, len);
}

static int out_to_a(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	return stream_input(g_a, data, len);
}

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

struct cli_arg {
	int fd;
	uint8_t fp[32];
	uint8_t auth[TOKEN_AUTH_LEN];
	const uint8_t *msg;
	uint8_t *got;
	size_t got_len;
	int rc;
};

static void *cli_thread(void *p)
{
	struct cli_arg *a = p;
	struct sshc_opts o;

	memset(&o, 0, sizeof(o));
	memcpy(o.host_fp, a->fp, 32);
	memcpy(o.auth, a->auth, sizeof(o.auth));
	o.interactive = 0;
	o.send = a->msg;
	o.send_len = MSG_LEN;
	o.recv = a->got;
	o.recv_cap = MSG_LEN;
	o.recv_len = &a->got_len;
	a->rc = sshc_connect_fd(a->fd, &o);
	return NULL;
}

int main(void)
{
	uint8_t fp[32], auth[TOKEN_AUTH_LEN];
	uint8_t msg[MSG_LEN], got[MSG_LEN];
	struct sshbridge *ba, *bb;
	struct srv_arg sa;
	struct cli_arg ca;
	pthread_t th_s, th_c;
	void *hostkey;
	int spa[2], spb[2];
	int done_a = 0, done_b = 0;
	uint32_t deadline;
	size_t i;

	for (i = 0; i < sizeof(auth); i++)
		auth[i] = (uint8_t)(i * 31 + 7);
	for (i = 0; i < MSG_LEN; i++)
		msg[i] = (uint8_t)(i * 97 + 13);

	hostkey = sshd_hostkey_new(fp);
	assert(hostkey);

	g_a = stream_create(CONV, out_to_b, NULL);   /* server side */
	g_b = stream_create(CONV, out_to_a, NULL);   /* client side */
	assert(g_a && g_b);

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, spa) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, spb) == 0);

	ba = sshbridge_create(spa[0], g_a, 1000);
	bb = sshbridge_create(spb[0], g_b, 1000);
	assert(ba && bb);

	memset(&sa, 0, sizeof(sa));
	sa.fd = spa[1];
	sa.hostkey = hostkey;
	memcpy(sa.auth, auth, sizeof(auth));
	assert(pthread_create(&th_s, NULL, srv_thread, &sa) == 0);

	memset(&ca, 0, sizeof(ca));
	ca.fd = spb[1];
	memcpy(ca.fp, fp, 32);
	memcpy(ca.auth, auth, sizeof(auth));
	ca.msg = msg;
	ca.got = got;
	assert(pthread_create(&th_c, NULL, cli_thread, &ca) == 0);

	deadline = now_ms() + 20000;
	while ((!done_a || !done_b) && now_ms() < deadline) {
		struct pollfd fds[2];
		uint32_t t = now_ms();

		fds[0].fd = sshbridge_fd(ba);
		fds[0].events = done_a ? 0 : sshbridge_events(ba);
		fds[0].revents = 0;
		fds[1].fd = sshbridge_fd(bb);
		fds[1].events = done_b ? 0 : sshbridge_events(bb);
		fds[1].revents = 0;

		poll(fds, 2, 5);

		if (!done_a && sshbridge_pump(ba, fds[0].revents, t) < 0)
			done_a = 1;
		if (!done_b && sshbridge_pump(bb, fds[1].revents, t) < 0)
			done_b = 1;
	}

	pthread_join(th_c, NULL);
	pthread_join(th_s, NULL);

	sshbridge_destroy(ba);
	sshbridge_destroy(bb);
	stream_destroy(g_a);
	stream_destroy(g_b);
	sshd_hostkey_free(hostkey);
	/* The SSH-end fds (spa[1]/spb[1]) are closed by the modules; we own the
	 * bridge ends. */
	close(spa[0]);
	close(spb[0]);

	if (!done_a || !done_b) {
		fprintf(stderr, "SSH/KCP FAIL: session did not close cleanly "
			"(done_a=%d done_b=%d)\n", done_a, done_b);
		return 1;
	}
	if (ca.rc != 0 || ca.got_len != MSG_LEN ||
	    memcmp(got, msg, MSG_LEN) != 0) {
		fprintf(stderr, "SSH/KCP FAIL: rc=%d got=%zu/%d\n",
			ca.rc, ca.got_len, MSG_LEN);
		return 1;
	}
	printf("SSH/KCP PASS: %d-byte echo over libssh through KCP bridge\n",
	       MSG_LEN);
	return 0;
}
