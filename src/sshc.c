/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libssh/libssh.h>

#include "base64.h"
#include "sshc.h"

/* Verify the server host key against the token-pinned fingerprint. A
 * mismatch is a hard failure: it means a MITM, so there is nothing to
 * prompt about. Returns 0 if it matches, -1 otherwise. */
static int pin_hostkey(ssh_session s, const uint8_t fp[32])
{
	unsigned char *hash = NULL;
	size_t hlen = 0;
	ssh_key srv = NULL;
	int rc = -1;

	if (ssh_get_server_publickey(s, &srv) != SSH_OK)
		return -1;
	if (ssh_get_publickey_hash(srv, SSH_PUBLICKEY_HASH_SHA256,
				   &hash, &hlen) == 0 &&
	    hlen == 32 && memcmp(hash, fp, 32) == 0)
		rc = 0;
	if (hash)
		ssh_clean_pubkey_hash(&hash);
	ssh_key_free(srv);
	return rc;
}

/* Test mode: write the whole request, then read echoed bytes until we have
 * as many as we sent (or the channel ends). */
static int run_test(ssh_channel chan, const struct sshc_opts *o)
{
	size_t got = 0;

	if (o->send_len &&
	    ssh_channel_write(chan, o->send, (uint32_t)o->send_len) !=
	    (int)o->send_len)
		return -1;

	while (got < o->send_len && got < o->recv_cap) {
		int n = ssh_channel_read(chan, o->recv + got,
					 (uint32_t)(o->recv_cap - got), 0);

		if (n < 0)
			return -1;
		if (n == 0)
			break;
		got += (size_t)n;
	}
	if (o->recv_len)
		*o->recv_len = got;
	return 0;
}

/* Interactive mode: bridge the local terminal to the channel. Deferred until
 * the terminal handling (raw mode, window-size, signals) lands with main.c. */
static int run_interactive(ssh_channel chan)
{
	(void)chan;
	fprintf(stderr, "comrade: interactive session not wired yet\n");
	return -1;
}

int sshc_connect_fd(int fd, const struct sshc_opts *o)
{
	char password[64];
	const char *host = "comrade";
	ssh_session s = NULL;
	ssh_channel chan = NULL;
	int sock = fd;
	int rc = -1;

	if (!o)
		return -1;
	if (!base64url_encode(o->auth, TOKEN_AUTH_LEN, password, sizeof(password)))
		return -1;

	s = ssh_new();
	if (!s)
		goto out;
	ssh_options_set(s, SSH_OPTIONS_HOST, host);
	ssh_options_set(s, SSH_OPTIONS_FD, &sock);
	if (ssh_connect(s) != SSH_OK) {
		fprintf(stderr, "comrade: ssh_connect: %s\n", ssh_get_error(s));
		goto out;
	}
	if (pin_hostkey(s, o->host_fp)) {
		fprintf(stderr, "comrade: host key mismatch, refusing to connect\n");
		goto out;
	}
	if (ssh_userauth_password(s, NULL, password) != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "comrade: authentication failed\n");
		goto out;
	}

	chan = ssh_channel_new(s);
	if (!chan || ssh_channel_open_session(chan) != SSH_OK)
		goto out;
	if (o->interactive) {
		if (ssh_channel_request_pty(chan) != SSH_OK)
			goto out;
		if (ssh_channel_request_shell(chan) != SSH_OK)
			goto out;
		rc = run_interactive(chan);
	} else {
		if (ssh_channel_request_shell(chan) != SSH_OK)
			goto out;
		rc = run_test(chan, o);
	}
out:
	if (chan) {
		if (ssh_channel_is_open(chan)) {
			ssh_channel_send_eof(chan);
			ssh_channel_close(chan);
		}
		ssh_channel_free(chan);
	}
	if (s) {
		ssh_disconnect(s);
		ssh_free(s);
	}
	/*
	 * libssh never closes an fd supplied via SSH_OPTIONS_FD; it is ours.
	 * Closing it is also what signals end-of-session to the bridge on the
	 * other end of the socketpair.
	 */
	if (sock >= 0)
		close(sock);
	return rc;
}
