/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The served terminal is read only while the transport underneath will take
 * what comes out of it. This is what makes tmux the thing that decides what a
 * guest sees after an outage: left unread, its output backs up in the terminal
 * and tmux drops the backlog and redraws the current screen. Read regardless,
 * it goes into the channel window and the send queue instead, and the guest is
 * served the seconds it missed frame by frame.
 *
 * So: a host whose tx_room says no must deliver essentially nothing, however
 * much the command produces, and must go on delivering the moment it says yes
 * again -- with the session intact throughout. The client here is raw libssh
 * rather than sshc, because when it reads is the whole question.
 */

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#include <libssh/libssh.h>

#include "base64.h"
#include "sshd.h"

/* Read for this long in each phase, then judge what arrived. */
#define PHASE_MS 1500

/*
 * What a gated host may still hand over: one slice in flight when the gate
 * shut, and nothing after it. An ungated one delivers megabytes in the same
 * window, so the two are never close.
 */
#define GATED_MAX 65536

/* And what an open one must beat, well under what `yes` can produce. */
#define OPEN_MIN 262144

/* What tx_room answers. It crosses the thread that sets it and the server
 * thread that asks, so it is not a plain int. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_room;

static void set_room(int room)
{
	pthread_mutex_lock(&g_lock);
	g_room = room;
	pthread_mutex_unlock(&g_lock);
}

static int room_cb(void *arg)
{
	int room;

	(void)arg;
	pthread_mutex_lock(&g_lock);
	room = g_room;
	pthread_mutex_unlock(&g_lock);
	return room;
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
	o.command = "yes";		/* more than any window can hold */
	o.use_pty = 1;
	o.tx_room = room_cb;
	sshd_serve_fd(a->fd, &o);
	return NULL;
}

static uint64_t mono_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)(t.tv_nsec / 1000000);
}

/* Read whatever the channel has for `ms`, and report how much that was. A
 * channel that ends under us is a failure of the case, not a result. */
static size_t drain_for(ssh_channel chan, int ms)
{
	char buf[16384];
	uint64_t end = mono_ms() + (uint64_t)ms;
	size_t got = 0;

	while (mono_ms() < end) {
		int n = ssh_channel_read_timeout(chan, buf, sizeof(buf), 0, 50);

		assert(n != SSH_ERROR);
		assert(!ssh_channel_is_eof(chan));
		assert(ssh_channel_is_open(chan));
		if (n > 0)
			got += (size_t)n;
	}
	return got;
}

int main(void)
{
	char password[64];
	uint8_t fp[32], auth[TOKEN_AUTH_LEN];
	unsigned char *hash = NULL;
	struct srv_arg sa;
	ssh_session s = NULL;
	ssh_channel chan = NULL;
	ssh_key srv_key = NULL;
	pthread_t th;
	socket_t sock;
	size_t hlen = 0, gated, open_got;
	void *hostkey;
	bool no_config = false;
	int sp[2];
	size_t i;

	/* The server closing first must not take the test down with it. */
	signal(SIGPIPE, SIG_IGN);

	for (i = 0; i < sizeof(auth); i++)
		auth[i] = (uint8_t)(i * 41 + 3);
	hostkey = sshd_hostkey_new(fp);
	assert(hostkey != NULL);
	assert(base64url_encode(auth, TOKEN_AUTH_LEN, password,
				sizeof(password)) > 0);

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	memset(&sa, 0, sizeof(sa));
	sa.fd = sp[1];
	sa.hostkey = hostkey;
	memcpy(sa.auth, auth, sizeof(sa.auth));

	/* Shut before the shell is ever asked for, so nothing the host may
	 * have read ahead of the gate can be mistaken for the gate leaking. */
	set_room(0);
	assert(pthread_create(&th, NULL, srv_thread, &sa) == 0);

	sock = sp[0];
	s = ssh_new();
	assert(s != NULL);
	ssh_options_set(s, SSH_OPTIONS_HOST, "comrade");
	ssh_options_set(s, SSH_OPTIONS_FD, &sock);
	ssh_options_set(s, SSH_OPTIONS_PROCESS_CONFIG, &no_config);
	assert(ssh_connect(s) == SSH_OK);
	assert(ssh_get_server_publickey(s, &srv_key) == SSH_OK);
	assert(ssh_get_publickey_hash(srv_key, SSH_PUBLICKEY_HASH_SHA256,
				      &hash, &hlen) == 0);
	assert(hlen == 32 && memcmp(hash, fp, 32) == 0);
	ssh_clean_pubkey_hash(&hash);
	ssh_key_free(srv_key);
	assert(ssh_userauth_password(s, NULL, password) == SSH_AUTH_SUCCESS);

	chan = ssh_channel_new(s);
	assert(chan != NULL);
	assert(ssh_channel_open_session(chan) == SSH_OK);
	assert(ssh_channel_request_pty_size(chan, "xterm-256color", 180, 47) ==
	       SSH_OK);
	assert(ssh_channel_request_shell(chan) == SSH_OK);

	gated = drain_for(chan, PHASE_MS);
	printf("gated: %zu bytes in %dms\n", gated, PHASE_MS);
	assert(gated <= GATED_MAX);

	set_room(1);
	open_got = drain_for(chan, PHASE_MS);
	printf("open:  %zu bytes in %dms\n", open_got, PHASE_MS);
	assert(open_got >= OPEN_MIN);

	/* And it shuts again, on a session that has been carrying bulk. */
	set_room(0);
	gated = drain_for(chan, PHASE_MS);
	printf("gated again: %zu bytes in %dms\n", gated, PHASE_MS);
	assert(gated <= GATED_MAX);

	ssh_channel_send_eof(chan);
	ssh_channel_close(chan);
	ssh_channel_free(chan);
	ssh_disconnect(s);
	ssh_free(s);
	close(sp[0]);
	pthread_join(th, NULL);
	sshd_hostkey_free(hostkey);

	printf("sshterm_test: OK\n");
	return 0;
}
