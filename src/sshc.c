/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>

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

static volatile sig_atomic_t g_winch;

static void on_winch(int sig)
{
	(void)sig;
	g_winch = 1;
}

/*
 * Interactive mode: put the terminal in raw mode and bridge stdin/stdout/stderr
 * to the channel with libssh's connectors (the same mechanism the server uses),
 * relaying window-size changes to the remote pty. Runs until the channel ends
 * (the remote tmux detaches or exits).
 */
static int run_interactive(ssh_session s, ssh_channel chan)
{
	struct termios orig, raw;
	struct sigaction sa, old_winch;
	ssh_event event = ssh_event_new();
	ssh_connector c_in = ssh_connector_new(s);	/* stdin -> channel */
	ssh_connector c_out = ssh_connector_new(s);	/* channel -> stdout */
	ssh_connector c_err = ssh_connector_new(s);	/* channel stderr -> stderr */
	int have_tty = isatty(STDIN_FILENO);

	if (!event || !c_in || !c_out || !c_err)
		goto out;

	if (have_tty && !tcgetattr(STDIN_FILENO, &orig)) {
		raw = orig;
		cfmakeraw(&raw);
		tcsetattr(STDIN_FILENO, TCSANOW, &raw);
	} else {
		have_tty = 0;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_winch;
	sigaction(SIGWINCH, &sa, &old_winch);

	ssh_connector_set_in_fd(c_in, STDIN_FILENO);
	ssh_connector_set_out_channel(c_in, chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_in_channel(c_out, chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_out_fd(c_out, STDOUT_FILENO);
	ssh_connector_set_in_channel(c_err, chan, SSH_CONNECTOR_STDERR);
	ssh_connector_set_out_fd(c_err, STDERR_FILENO);
	ssh_event_add_connector(event, c_in);
	ssh_event_add_connector(event, c_out);
	ssh_event_add_connector(event, c_err);

	while (ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan)) {
		/*
		 * End only on the dedicated end-of-session signal: the host sends
		 * a channel exit-status and closes the channel when the shared
		 * session is over, which surfaces here as the channel reaching EOF
		 * / no longer open (the loop condition). A transport hiccup -- a
		 * slow or flaky link, or a roam that needs a fresh handshake -- must
		 * NOT be taken for the end of the session, so we deliberately do not
		 * exit on a poll error or a dropped connection. The SSH transport is
		 * a local socketpair bridged to KCP, so a broken path shows up here
		 * only as no data (dopoll idles), never as an error; a genuine end
		 * always arrives as the channel close. On the rare real poll error,
		 * pause briefly rather than spin, and keep waiting for the channel.
		 */
		if (ssh_event_dopoll(event, 200) == SSH_ERROR) {
			struct timespec ts = { 0, 100 * 1000 * 1000 };

			nanosleep(&ts, NULL);
		}
		if (g_winch) {
			struct winsize ws;

			g_winch = 0;
			if (have_tty && !ioctl(STDIN_FILENO, TIOCGWINSZ, &ws))
				ssh_channel_change_pty_size(chan, ws.ws_col,
							    ws.ws_row);
		}
	}

	ssh_event_remove_connector(event, c_in);
	ssh_event_remove_connector(event, c_out);
	ssh_event_remove_connector(event, c_err);
	sigaction(SIGWINCH, &old_winch, NULL);
	if (have_tty)
		tcsetattr(STDIN_FILENO, TCSANOW, &orig);
out:
	if (c_in)
		ssh_connector_free(c_in);
	if (c_out)
		ssh_connector_free(c_out);
	if (c_err)
		ssh_connector_free(c_err);
	if (event)
		ssh_event_free(event);
	return 0;
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
		struct winsize ws;
		const char *term = getenv("TERM");

		if (!term)
			term = "xterm-256color";
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws)) {
			ws.ws_col = 80;
			ws.ws_row = 24;
		}
		if (ssh_channel_request_pty_size(chan, term, ws.ws_col,
						 ws.ws_row) != SSH_OK)
			goto out;
		if (ssh_channel_request_shell(chan) != SSH_OK)
			goto out;
		rc = run_interactive(s, chan);
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
