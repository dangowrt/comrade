/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * -L/-R TCP port forwarding through the real libssh server and client over
 * a socketpair (the same fd abstraction the punched path presents):
 *
 * - spec parsing (OpenSSH [bind:]port:host:hostport grammar);
 * - -L: TCP into the client's listener comes out of a host-side connect
 *   to a local echo server, byte-exact both ways;
 * - -R: TCP into the host-side listener comes out of a client-side
 *   connect to a local echo server, byte-exact both ways;
 * - -R bulk: several times the 2 MiB channel window one way, with the
 *   consumer stalled long enough for the window to close and reopen;
 * - --no-forwarding: the host refuses, the session itself stays healthy.
 */

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "fwdspec.h"
#include "sshc.h"
#include "sshd.h"

#define ECHO_LEN 256
#define HOLD_MS 4000
#define BULK_LEN (8u * 1024 * 1024)
#define BULK_STALL_MS 1200

static uint64_t now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)(t.tv_nsec / 1000000);
}

static void parse_checks(void)
{
	struct fwdspec sp;

	assert(!fwdspec_parse("8080:localhost:80", &sp));
	assert(!sp.bind[0] && sp.bind_port == 8080);
	assert(!strcmp(sp.host, "localhost") && sp.port == 80);

	assert(!fwdspec_parse("127.0.0.2:8080:example.net:443", &sp));
	assert(!strcmp(sp.bind, "127.0.0.2") && sp.bind_port == 8080);
	assert(!strcmp(sp.host, "example.net") && sp.port == 443);

	assert(!fwdspec_parse("*:0:h:1", &sp));
	assert(!strcmp(sp.bind, "*") && sp.bind_port == 0 && sp.port == 1);

	assert(!fwdspec_parse("[::1]:8080:[fe80::1]:22", &sp));
	assert(!strcmp(sp.bind, "::1") && !strcmp(sp.host, "fe80::1"));

	assert(fwdspec_parse("8080", &sp));		/* too few parts */
	assert(fwdspec_parse("a:b:c:d:e", &sp));	/* too many */
	/* Overlong in both directions: more fields than the token table holds,
	 * and a field longer than one token. Both used to run off the end. */
	assert(fwdspec_parse("a:b:c:d:e:f:g:h:i:j:k", &sp));
	{
		char big[1024];

		memset(big, 'x', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';
		assert(fwdspec_parse(big, &sp));
	}
	assert(fwdspec_parse("x:localhost:80", &sp));	/* bad port */
	assert(fwdspec_parse("8080::80", &sp));		/* empty host */
	assert(fwdspec_parse("8080:h:0", &sp));		/* zero target port */
	assert(fwdspec_parse("[::1:8080:h:1", &sp));	/* unclosed bracket */
}

/* A loopback TCP echo server bound at creation (no port race): serves one
 * connection, echoing until EOF, then exits. */
struct echo {
	int lfd;
	uint16_t port;
	pthread_t th;
};

static void *echo_thread(void *p)
{
	struct echo *e = p;
	char buf[4096];
	int fd = accept(e->lfd, NULL, NULL);
	ssize_t n;

	if (fd < 0)
		return NULL;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		ssize_t off = 0;

		while (off < n) {
			ssize_t w = write(fd, buf + off, (size_t)(n - off));

			if (w <= 0)
				goto out;
			off += w;
		}
	}
out:
	close(fd);
	return NULL;
}

static void serve_start(struct echo *e, void *(*fn)(void *))
{
	struct sockaddr_in a;
	socklen_t sl = sizeof(a);

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	e->lfd = socket(AF_INET, SOCK_STREAM, 0);
	assert(e->lfd >= 0);
	assert(!bind(e->lfd, (struct sockaddr *)&a, sizeof(a)));
	assert(!listen(e->lfd, 1));
	assert(!getsockname(e->lfd, (struct sockaddr *)&a, &sl));
	e->port = ntohs(a.sin_port);
	assert(!pthread_create(&e->th, NULL, fn, e));
}

static void echo_start(struct echo *e)
{
	serve_start(e, echo_thread);
}

static void echo_stop(struct echo *e)
{
	pthread_join(e->th, NULL);
	close(e->lfd);
}

/* A one-way source: serves one connection BULK_LEN bytes, then closes. */
static void *bulk_thread(void *p)
{
	struct echo *e = p;
	char buf[4096];
	int fd = accept(e->lfd, NULL, NULL);
	size_t left = BULK_LEN;

	if (fd < 0)
		return NULL;
	memset(buf, 'B', sizeof(buf));
	while (left) {
		size_t n = left < sizeof(buf) ? left : sizeof(buf);
		ssize_t w = write(fd, buf, n);

		if (w <= 0)
			break;
		left -= (size_t)w;
	}
	close(fd);
	return NULL;
}

/* Stall until the sender has filled the channel window, then drain it all:
 * BULK_LEN bytes and a clean EOF, through the closed-and-reopened window. */
static int bulk_check(int fd, uint64_t deadline)
{
	char buf[65536];
	size_t got = 0;

	usleep(BULK_STALL_MS * 1000);
	while (now_ms() < deadline) {
		struct pollfd p = { fd, POLLIN, 0 };
		ssize_t n;

		if (poll(&p, 1, 100) <= 0)
			continue;
		n = read(fd, buf, sizeof(buf));
		if (n < 0)
			return 0;
		if (n == 0)
			return got == BULK_LEN;
		got += (size_t)n;
	}
	return 0;
}

/* Reserve a loopback port for a listener the engine will bind later. */
static uint16_t pick_port(void)
{
	struct sockaddr_in a;
	socklen_t sl = sizeof(a);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	uint16_t p;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	assert(fd >= 0);
	assert(!bind(fd, (struct sockaddr *)&a, sizeof(a)));
	assert(!getsockname(fd, (struct sockaddr *)&a, &sl));
	p = ntohs(a.sin_port);
	close(fd);
	return p;
}

/* Connect to 127.0.0.1:port, retrying until deadline (the listener may not
 * be up yet). Returns the fd or -1. */
static int connect_retry(uint16_t port, uint64_t deadline)
{
	struct sockaddr_in a;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = htons(port);
	while (now_ms() < deadline) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);

		if (fd < 0)
			return -1;
		if (!connect(fd, (struct sockaddr *)&a, sizeof(a)))
			return fd;
		close(fd);
		usleep(50 * 1000);
	}
	return -1;
}

/* Write a pattern and expect it echoed back byte-exact within the deadline.
 * Returns 1 on success. */
static int echo_check(int fd, uint64_t deadline)
{
	uint8_t msg[ECHO_LEN], got[ECHO_LEN];
	size_t rd = 0, i;

	for (i = 0; i < sizeof(msg); i++)
		msg[i] = (uint8_t)(i * 41 + 5);
	if (write(fd, msg, sizeof(msg)) != (ssize_t)sizeof(msg))
		return 0;
	while (rd < sizeof(got) && now_ms() < deadline) {
		struct pollfd p = { fd, POLLIN, 0 };
		ssize_t n;

		if (poll(&p, 1, 100) <= 0)
			continue;
		n = read(fd, got + rd, sizeof(got) - rd);
		if (n <= 0)
			return 0;
		rd += (size_t)n;
	}
	return rd == sizeof(got) && !memcmp(got, msg, sizeof(got));
}

/* Expect the tunnel to deliver nothing: EOF (or silence to the deadline)
 * with no echoed data. Returns 1 when nothing came back. */
static int refuse_check(int fd, uint64_t deadline)
{
	uint8_t b;

	(void)!write(fd, "x", 1);
	while (now_ms() < deadline) {
		struct pollfd p = { fd, POLLIN, 0 };

		if (poll(&p, 1, 100) <= 0)
			continue;
		return read(fd, &b, 1) <= 0;
	}
	return 1;
}

struct srv_arg {
	int fd;
	void *hostkey;
	uint8_t auth[TOKEN_AUTH_LEN];
	int no_fwd;
	int forward_only;
	volatile int fwd_refused;
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
	o.no_fwd = a->no_fwd;
	o.forward_only = a->forward_only;
	o.fwd_refused_out = &a->fwd_refused;
	sshd_serve_fd(a->fd, &o);
	return NULL;
}

struct cli_arg {
	int fd;
	struct sshc_opts o;
	int rc;
};

static void *cli_thread(void *p)
{
	struct cli_arg *a = p;

	a->rc = sshc_connect_fd(a->fd, &a->o);
	return NULL;
}

/*
 * One session with the given forwarding setup. `check` probes connect_port
 * once the session runs and returns 1 on the expected outcome.
 */
static int one_round(void *hostkey, const uint8_t fp[32],
		     const uint8_t auth[TOKEN_AUTH_LEN], int no_fwd,
		     const struct fwdspec *l, const struct fwdspec *r,
		     uint16_t connect_port,
		     int (*check)(int fd, uint64_t deadline), int hold_ms)
{
	static const uint8_t ping[] = { 'p', 'i', 'n', 'g' };
	uint8_t echo[4];
	size_t echo_len = 0;
	struct srv_arg sa;
	struct cli_arg ca;
	pthread_t sth, cth;
	uint64_t deadline;
	int sp[2], fd, ok = 0;

	assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sp));

	memset(&sa, 0, sizeof(sa));
	sa.fd = sp[1];
	sa.hostkey = hostkey;
	memcpy(sa.auth, auth, sizeof(sa.auth));
	sa.no_fwd = no_fwd;
	assert(!pthread_create(&sth, NULL, srv_thread, &sa));

	memset(&ca, 0, sizeof(ca));
	ca.fd = sp[0];
	memcpy(ca.o.host_fp, fp, 32);
	memcpy(ca.o.auth, auth, sizeof(ca.o.auth));
	ca.o.send = ping;
	ca.o.send_len = sizeof(ping);
	ca.o.recv = echo;
	ca.o.recv_cap = sizeof(echo);
	ca.o.recv_len = &echo_len;
	ca.o.hold_ms = hold_ms;
	if (l) {
		ca.o.fwd_l = l;
		ca.o.nfwd_l = 1;
	}
	if (r) {
		ca.o.fwd_r = r;
		ca.o.nfwd_r = 1;
	}
	assert(!pthread_create(&cth, NULL, cli_thread, &ca));

	deadline = now_ms() + (uint64_t)hold_ms - 500;
	fd = connect_retry(connect_port, deadline);
	if (fd >= 0) {
		ok = check(fd, deadline);
		close(fd);
	}

	pthread_join(cth, NULL);
	pthread_join(sth, NULL);
	/* The shell echo must have worked in every scenario: forwarding never
	 * breaks the session, it only adds to it. */
	if (ca.rc || echo_len != sizeof(ping) || memcmp(echo, ping, 4))
		return 0;
	return ok;
}

/*
 * A forward-only session: the host serves no shell, the client requests none.
 * A -R forward still works end to end, and (when refuse is set) the host
 * declining forwarding is counted through fwd_refused_out. The client's
 * run_forward loops until the transport ends, so the harness closes both fds
 * to finish. Returns 1 on the expected outcome.
 */
static int forward_only_round(void *hostkey, const uint8_t fp[32],
			      const uint8_t auth[TOKEN_AUTH_LEN], int no_fwd,
			      const struct fwdspec *r, uint16_t connect_port,
			      int expect_forward)
{
	struct srv_arg sa;
	struct cli_arg ca;
	pthread_t sth, cth;
	uint64_t deadline;
	int sp[2], fd, ok;

	assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sp));

	memset(&sa, 0, sizeof(sa));
	sa.fd = sp[1];
	sa.hostkey = hostkey;
	memcpy(sa.auth, auth, sizeof(sa.auth));
	sa.no_fwd = no_fwd;
	sa.forward_only = 1;
	assert(!pthread_create(&sth, NULL, srv_thread, &sa));

	memset(&ca, 0, sizeof(ca));
	ca.fd = sp[0];
	memcpy(ca.o.host_fp, fp, 32);
	memcpy(ca.o.auth, auth, sizeof(ca.o.auth));
	ca.o.forward_only = 1;
	ca.o.fwd_r = r;
	ca.o.nfwd_r = 1;
	assert(!pthread_create(&cth, NULL, cli_thread, &ca));

	if (expect_forward) {
		deadline = now_ms() + HOLD_MS - 500;
		fd = connect_retry(connect_port, deadline);
		ok = fd >= 0 && echo_check(fd, deadline);
		if (fd >= 0)
			close(fd);
	} else {
		/* A refused -R binds no host listener, so there is nothing to
		 * connect to: the refusal shows only in the host's counter.
		 * Give the client a moment to attempt it and the host to
		 * decline. */
		usleep(500 * 1000);
		ok = 1;
	}

	/* End the forward-only client and server: no shell means no natural
	 * EOF, so drop the transport under them. */
	shutdown(sp[0], SHUT_RDWR);
	shutdown(sp[1], SHUT_RDWR);
	pthread_join(cth, NULL);
	pthread_join(sth, NULL);

	if (expect_forward)
		return ok;
	/* Refusal: the host counted the declined forward. */
	return sa.fwd_refused > 0;
}

int main(void)
{
	uint8_t fp[32], auth[TOKEN_AUTH_LEN];
	void *hostkey;
	struct fwdspec sp;
	struct echo e;
	uint16_t port;
	size_t i;

	signal(SIGPIPE, SIG_IGN);
	parse_checks();

	for (i = 0; i < sizeof(auth); i++)
		auth[i] = (uint8_t)(i * 31 + 7);
	hostkey = sshd_hostkey_new(fp);
	assert(hostkey);

	/* -L: local listener -> host-side connect to the echo server. */
	echo_start(&e);
	port = pick_port();
	memset(&sp, 0, sizeof(sp));
	sp.bind_port = port;
	snprintf(sp.host, sizeof(sp.host), "127.0.0.1");
	sp.port = e.port;
	if (!one_round(hostkey, fp, auth, 0, &sp, NULL, port, echo_check,
		       HOLD_MS)) {
		fprintf(stderr, "FWD FAIL: -L echo\n");
		return 1;
	}
	echo_stop(&e);

	/* -R: host-side listener -> client-side connect to the echo server. */
	echo_start(&e);
	port = pick_port();
	memset(&sp, 0, sizeof(sp));
	sp.bind_port = port;
	snprintf(sp.host, sizeof(sp.host), "127.0.0.1");
	sp.port = e.port;
	if (!one_round(hostkey, fp, auth, 0, NULL, &sp, port, echo_check,
		       HOLD_MS)) {
		fprintf(stderr, "FWD FAIL: -R echo\n");
		return 1;
	}
	echo_stop(&e);

	/* -R bulk: the transfer outgrows the channel window several times
	 * over, and the stalled consumer forces the window to close. */
	serve_start(&e, bulk_thread);
	port = pick_port();
	memset(&sp, 0, sizeof(sp));
	sp.bind_port = port;
	snprintf(sp.host, sizeof(sp.host), "127.0.0.1");
	sp.port = e.port;
	if (!one_round(hostkey, fp, auth, 0, NULL, &sp, port, bulk_check,
		       12000)) {
		fprintf(stderr, "FWD FAIL: -R bulk\n");
		return 1;
	}
	echo_stop(&e);

	/* --no-forwarding: the host refuses -L opens; the local listener still
	 * accepts, but the tunnel delivers nothing and closes. */
	echo_start(&e);
	port = pick_port();
	memset(&sp, 0, sizeof(sp));
	sp.bind_port = port;
	snprintf(sp.host, sizeof(sp.host), "127.0.0.1");
	sp.port = e.port;
	if (!one_round(hostkey, fp, auth, 1, &sp, NULL, port, refuse_check,
		       HOLD_MS)) {
		fprintf(stderr, "FWD FAIL: --no-forwarding still forwarded\n");
		return 1;
	}
	close(e.lfd);		/* never connected to: unblock and drop */
	pthread_cancel(e.th);
	pthread_join(e.th, NULL);

	/* Forward-only: the host serves no shell, yet -R still tunnels. */
	echo_start(&e);
	port = pick_port();
	memset(&sp, 0, sizeof(sp));
	sp.bind_port = port;
	snprintf(sp.host, sizeof(sp.host), "127.0.0.1");
	sp.port = e.port;
	if (!forward_only_round(hostkey, fp, auth, 0, &sp, port, 1)) {
		fprintf(stderr, "FWD FAIL: forward-only -R echo\n");
		return 1;
	}
	echo_stop(&e);

	/* Forward-only + declined: no tunnel, and the host counts the
	 * refusal so the operator can be shown it. */
	echo_start(&e);
	port = pick_port();
	memset(&sp, 0, sizeof(sp));
	sp.bind_port = port;
	snprintf(sp.host, sizeof(sp.host), "127.0.0.1");
	sp.port = e.port;
	if (!forward_only_round(hostkey, fp, auth, 1, &sp, port, 0)) {
		fprintf(stderr, "FWD FAIL: refusal not counted / still "
			"forwarded\n");
		return 1;
	}
	close(e.lfd);
	pthread_cancel(e.th);
	pthread_join(e.th, NULL);

	sshd_hostkey_free(hostkey);
	printf("FWD PASS: -L and -R echo, -R bulk past the window, "
	       "--no-forwarding refuses, forward-only serves no shell, "
	       "refusals counted\n");
	return 0;
}
