/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The read-only credential, end to end over the real libssh server. The host
 * offers two secrets: the read-write auth secret and its one-way derivation
 * (keys_derive_ro_auth). A client presenting the read-write secret is served
 * `command`; one presenting the derived secret is served `command_ro`; any
 * other password is refused. Each command prints its own two-byte marker down
 * the channel, so the bytes the client reads back prove which side ran --
 * exactly the mechanism that hands a read-only guest `tmux attach -r`.
 */

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "keys.h"
#include "sshc.h"
#include "sshd.h"

struct srv_arg {
	int fd;
	void *hostkey;
	uint8_t auth[TOKEN_AUTH_LEN];
	uint8_t auth_ro[TOKEN_AUTH_LEN];
};

static void *srv_thread(void *p)
{
	struct srv_arg *a = p;
	struct sshd_opts o;

	memset(&o, 0, sizeof(o));
	o.hostkey = a->hostkey;
	memcpy(o.auth, a->auth, sizeof(o.auth));
	memcpy(o.auth_ro, a->auth_ro, sizeof(o.auth_ro));
	o.have_ro = 1;
	o.command = "printf RW";
	o.command_ro = "printf RO";
	o.use_pty = 0;
	sshd_serve_fd(a->fd, &o);
	return NULL;
}

/* Connect once presenting `present`; the served command prints its marker,
 * which lands in got[0..1]. Returns the client rc. */
static int one_round(void *hostkey, const uint8_t fp[32],
		     const uint8_t rw[TOKEN_AUTH_LEN],
		     const uint8_t ro[TOKEN_AUTH_LEN],
		     const uint8_t present[TOKEN_AUTH_LEN], char got[2])
{
	uint8_t probe[2] = { 'z', 'z' };
	struct sshc_opts co;
	struct srv_arg sa;
	pthread_t th;
	size_t gl = 0;
	int rc;
	int sp[2];

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.fd = sp[1];
	sa.hostkey = hostkey;
	memcpy(sa.auth, rw, sizeof(sa.auth));
	memcpy(sa.auth_ro, ro, sizeof(sa.auth_ro));
	assert(pthread_create(&th, NULL, srv_thread, &sa) == 0);

	memset(&co, 0, sizeof(co));
	memcpy(co.host_fp, fp, 32);
	memcpy(co.auth, present, sizeof(co.auth));
	co.interactive = 0;
	co.send = probe;		/* content is ignored by printf */
	co.send_len = 2;
	co.recv = (uint8_t *)got;
	co.recv_cap = 2;
	co.recv_len = &gl;
	got[0] = got[1] = '\0';

	rc = sshc_connect_fd(sp[0], &co);
	pthread_join(th, NULL);
	return rc;
}

int main(void)
{
	uint8_t fp[32], rw[TOKEN_AUTH_LEN], ro[TOKEN_AUTH_LEN], bogus[TOKEN_AUTH_LEN];
	char got[2];
	void *hostkey;
	size_t i;
	int rc;

	signal(SIGPIPE, SIG_IGN);

	for (i = 0; i < sizeof(rw); i++)
		rw[i] = (uint8_t)(i * 31 + 7);
	keys_derive_ro_auth(ro, rw);
	for (i = 0; i < sizeof(bogus); i++)
		bogus[i] = (uint8_t)(i + 200);	/* neither rw nor ro */

	hostkey = sshd_hostkey_new(fp);
	assert(hostkey);

	/* Read-write secret -> read-write command. */
	rc = one_round(hostkey, fp, rw, ro, rw, got);
	assert(rc == 0);
	assert(got[0] == 'R' && got[1] == 'W');

	/* Derived read-only secret -> read-only command. */
	rc = one_round(hostkey, fp, rw, ro, ro, got);
	assert(rc == 0);
	assert(got[0] == 'R' && got[1] == 'O');

	/* A secret that is neither is refused. */
	rc = one_round(hostkey, fp, rw, ro, bogus, got);
	assert(rc != 0);

	sshd_hostkey_free(hostkey);
	printf("SSH PASS: read-only credential selects the read-only command\n");
	return 0;
}
