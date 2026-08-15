/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The comrade-ctl subsystem channel: alongside the interactive shell channel,
 * the client opens a second SSH channel (subsystem comrade-ctl) and the server
 * bridges it to a control fd. This drives real sshc + sshd over a cross-
 * connected KCP pair and checks that bytes written to the server's control fd
 * arrive on the client's, and vice versa -- i.e. the authenticated in-session
 * control plane works both ways, without touching the shell channel.
 */
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>

#include "sshbridge.h"
#include "sshc.h"
#include "sshd.h"
#include "stream.h"

#define CONV 0x70326b63
static struct stream *g_a, *g_b;

static uint32_t now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint32_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000);
}
static int out_to_b(void *a, const uint8_t *d, size_t n){(void)a; return stream_input(g_b, d, n);}
static int out_to_a(void *a, const uint8_t *d, size_t n){(void)a; return stream_input(g_a, d, n);}

struct srv_arg { int fd; void *hostkey; uint8_t auth[TOKEN_AUTH_LEN]; int ctl_fd; int end_fd; };
static void *srv_thread(void *p)
{
	struct srv_arg *a = p;
	struct sshd_opts o;

	memset(&o, 0, sizeof(o));
	o.hostkey = a->hostkey;
	memcpy(o.auth, a->auth, sizeof(o.auth));
	o.command = "sleep 30";
	o.use_pty = 0;
	o.ctl_fd = a->ctl_fd;
	o.end_fd = a->end_fd;
	sshd_serve_fd(a->fd, &o);
	return NULL;
}

struct cli_arg { int fd; uint8_t fp[32]; uint8_t auth[TOKEN_AUTH_LEN]; int ctl_fd; };
static void *cli_thread(void *p)
{
	struct cli_arg *a = p;
	struct sshc_opts o;

	memset(&o, 0, sizeof(o));
	memcpy(o.host_fp, a->fp, 32);
	memcpy(o.auth, a->auth, sizeof(o.auth));
	o.interactive = 1;
	o.ctl_fd = a->ctl_fd;
	sshc_connect_fd(a->fd, &o);
	return NULL;
}

int main(void)
{
	uint8_t fp[32], auth[TOKEN_AUTH_LEN];
	struct sshbridge *ba, *bb;
	struct srv_arg sa;
	struct cli_arg ca;
	pthread_t th_s, th_c;
	void *hostkey;
	int spa[2], spb[2], sctl[2], cctl[2], endp[2];
	int done_a = 0, done_b = 0, wrote = 0, got_s2c = 0, got_c2s = 0;
	uint32_t deadline, act;
	size_t i;

	for (i = 0; i < sizeof(auth); i++)
		auth[i] = (uint8_t)(i * 31 + 7);
	hostkey = sshd_hostkey_new(fp);
	assert(hostkey);

	g_a = stream_create(CONV, out_to_b, NULL);
	g_b = stream_create(CONV, out_to_a, NULL);
	assert(g_a && g_b);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, spa) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, spb) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sctl) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, cctl) == 0);
	assert(pipe(endp) == 0);
	/* Keep the exec'd shell command from inheriting the end-of-session
	 * write end, so closing it here actually gives endp[0] EOF. */
	fcntl(endp[1], F_SETFD, FD_CLOEXEC);
	fcntl(sctl[0], F_SETFL, O_NONBLOCK);
	fcntl(cctl[0], F_SETFL, O_NONBLOCK);

	ba = sshbridge_create(spa[0], g_a, 1000);
	bb = sshbridge_create(spb[0], g_b, 1000);
	assert(ba && bb);

	memset(&sa, 0, sizeof(sa));
	sa.fd = spa[1]; sa.hostkey = hostkey; sa.ctl_fd = sctl[1]; sa.end_fd = endp[0];
	memcpy(sa.auth, auth, sizeof(auth));
	assert(pthread_create(&th_s, NULL, srv_thread, &sa) == 0);

	memset(&ca, 0, sizeof(ca));
	ca.fd = spb[1]; ca.ctl_fd = cctl[1];
	memcpy(ca.fp, fp, 32);
	memcpy(ca.auth, auth, sizeof(auth));
	assert(pthread_create(&th_c, NULL, cli_thread, &ca) == 0);

	deadline = now_ms() + 15000;
	act = now_ms() + 800;		/* let the control channel come up first */
	while ((!done_a || !done_b) && now_ms() < deadline) {
		struct pollfd fds[2];
		char buf[64];
		ssize_t n;
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

		if (!wrote && now_ms() >= act) {
			assert(write(sctl[0], "S2C", 3) == 3);
			assert(write(cctl[0], "C2S", 3) == 3);
			wrote = 1;
		}
		if (wrote && !got_s2c) {
			n = read(cctl[0], buf, sizeof(buf));
			if (n == 3 && !memcmp(buf, "S2C", 3))
				got_s2c = 1;
		}
		if (wrote && !got_c2s) {
			n = read(sctl[0], buf, sizeof(buf));
			if (n == 3 && !memcmp(buf, "C2S", 3))
				got_c2s = 1;
		}
		if (got_s2c && got_c2s)
			break;			/* proven; let the session wind down */
	}

	close(endp[1]);		/* signal end-of-session; server closes the channel */
	deadline = now_ms() + 6000;
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
	close(spa[0]);
	close(spb[0]);

	if (!got_s2c || !got_c2s) {
		fprintf(stderr, "comrade-ctl FAIL: s2c=%d c2s=%d\n",
			got_s2c, got_c2s);
		return 1;
	}
	printf("comrade-ctl PASS: control plane echoes both ways over SSH\n");
	return 0;
}
