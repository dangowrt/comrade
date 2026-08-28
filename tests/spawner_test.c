/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The spawner's one hard property is that its single control channel stays
 * coherent under many concurrent callers: worker threads spawn and close
 * terminals while the serve loop asks whether the session is alive, and a reply
 * -- with the descriptors it carries -- must never reach the wrong caller. So
 * the test is a hammer: several threads each run a batch of spawn / close /
 * read-the-exit cycles while another thread spams the alive query, and every
 * spawn must come back with its own working exit-notify pipe. A missing lock or
 * a mis-ordered reply would surface here as a wrong descriptor count, a bad
 * read, a hang (which the ctest timeout catches) or a crash.
 *
 * tmux need not be installed: a spawned `tmux attach` on plain pipes exits at
 * once (no terminal, or no tmux), which is all the mechanism needs to exercise
 * fork, descriptor passing and reaping. Where tmux IS present a real session is
 * used to check the alive/kill answers too.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>
#include <sys/wait.h>

#include "spawner.h"
#include "wsock.h"

/* Enough concurrency to trip a missing lock or a mis-ordered reply -- a race on
 * the shared channel corrupts under any overlap. The spawned attaches exit at
 * once (their socket never had a server), so this stays quick. */
#define THREADS 8
#define ITERS 12

static struct spawner *g_sp;
static volatile int g_stop_alive;

/* One worker: spawn a pipe-backed attach, close it, and read its exit byte,
 * ITERS times. Returns a two-int array {spawns_ok, exits_ok}. */
static void *hammer(void *arg)
{
	int *res = calloc(2, sizeof(int));
	int i;

	(void)arg;
	for (i = 0; i < ITERS; i++) {
		sock_t in, out, ex;
		int h = -1;

		if (spawner_spawn(g_sp, i & 1, 0, 0, 0, "xterm-256color",
				  &in, &out, &ex, &h) != 0)
			continue;
		res[0]++;
		spawner_close(g_sp, h);
		for (;;) {
			unsigned char b;
			ssize_t r = read(ex, &b, 1);

			if (r == 1) {
				res[1]++;
				break;
			}
			if (r == 0)
				break;		/* closed without a byte */
			if (r < 0 && errno != EINTR)
				break;
		}
		sock_close(in);
		if (out != in)
			sock_close(out);
		sock_close(ex);
	}
	return res;
}

/* Spam the alive query alongside the hammer, to interleave a different opcode
 * on the shared channel. */
static void *alive_spam(void *arg)
{
	(void)arg;
	while (!g_stop_alive) {
		if (spawner_alive(g_sp) == SPAWNER_GONE)
			break;
		usleep(5 * 1000);	/* interleave, do not fork tmux flat out */
	}
	return NULL;
}

/* Start a detached tmux session on `sock`; return 1 if tmux ran, 0 otherwise. */
static int start_tmux(const char *sock)
{
	pid_t c = fork();
	int st;

	if (c < 0)
		return 0;
	if (c == 0) {
		int nul = open("/dev/null", O_RDWR);

		if (nul >= 0) {
			dup2(nul, 1);
			dup2(nul, 2);
		}
		execlp("tmux", "tmux", "-S", sock, "new-session", "-d",
		       "-s", "comrade", (char *)NULL);
		_exit(127);
	}
	if (waitpid(c, &st, 0) < 0)
		return 0;
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

/* The liveness answers, on a throwaway spawner over a real session that is then
 * ended -- kept apart from the hammer so the hammer's socket never had a server
 * and its attaches fail (and exit) at once. */
static void check_liveness(const char *sock)
{
	struct spawner *sp;

	if (!start_tmux(sock))
		return;			/* no tmux: nothing to check */
	sp = spawner_create(sock);
	assert(sp != NULL);
	assert(spawner_alive(sp) == SPAWNER_ALIVE);
	spawner_kill_server(sp);
	assert(spawner_alive(sp) == SPAWNER_NO_SESSION);
	spawner_destroy(sp);
	unlink(sock);
}

int main(void)
{
	char base[] = "/tmp/comrade-sptest-XXXXXX";
	char sock_a[128], sock_h[128];
	pthread_t th[THREADS], spam;
	int total_spawn = 0, total_exit = 0, i;

	if (!mkdtemp(base)) {
		fprintf(stderr, "spawner_test: no tmpdir, skipping\n");
		return 77;
	}
	snprintf(sock_a, sizeof(sock_a), "%s/alive", base);
	snprintf(sock_h, sizeof(sock_h), "%s/hammer", base);

	check_liveness(sock_a);

	/* sock_h never had a server, so each spawned attach exits immediately. */
	g_sp = spawner_create(sock_h);
	if (!g_sp) {
		fprintf(stderr, "spawner_test: spawner_create failed, "
			"skipping\n");
		rmdir(base);
		return 77;
	}

	g_stop_alive = 0;
	assert(pthread_create(&spam, NULL, alive_spam, NULL) == 0);
	for (i = 0; i < THREADS; i++)
		assert(pthread_create(&th[i], NULL, hammer, NULL) == 0);
	for (i = 0; i < THREADS; i++) {
		void *r = NULL;

		assert(pthread_join(th[i], &r) == 0);
		assert(r != NULL);
		total_spawn += ((int *)r)[0];
		total_exit += ((int *)r)[1];
		free(r);
	}
	g_stop_alive = 1;
	pthread_join(spam, NULL);

	/* Every spawn across every thread succeeded and delivered its own exit
	 * byte: the channel stayed coherent under the concurrent load. */
	assert(total_spawn == THREADS * ITERS);
	assert(total_exit == total_spawn);

	spawner_destroy(g_sp);
	unlink(sock_h);
	rmdir(base);
	printf("spawner_test: ok\n");
	return 0;
}
