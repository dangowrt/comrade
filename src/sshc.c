/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <poll.h>
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
#include "dbg.h"
#include "sshc.h"
#include "statusbar.h"
#include "termfilter.h"

/*
 * stdin -> channel, replacing libssh's plain connector so we can filter the
 * byte stream: tmux asks the terminal for its size and the terminal's answer
 * comes back this way, so termfilter rewrites it one row shorter to keep the
 * reserved status row (see termfilter.h). Keystrokes and everything else pass
 * through untouched.
 */
struct stdin_ctx {
	ssh_channel chan;
	struct termfilter *tf;
	int eof;
	const volatile int *interrupted;	/* link is down: keys go nowhere */
	volatile int *quit;			/* set to bail out of the session */
};

static int on_stdin(socket_t fd, int revents, void *userdata)
{
	struct stdin_ctx *c = userdata;
	char buf[4096], fb[4096 + 32];
	ssize_t n;
	size_t fn;

	if (!(revents & (POLLIN | POLLHUP | POLLERR)))
		return 0;
	n = read(fd, buf, sizeof(buf));
	if (n <= 0) {
		c->eof = 1;
		return 0;
	}
	/*
	 * While the link is down these keystrokes cannot reach the peer, so give
	 * the user a way out that does not need a second terminal: a lone Escape
	 * or a Ctrl-C quits instead of being swallowed. When the link is up they
	 * are ordinary input and pass straight through.
	 */
	if (c->interrupted && *c->interrupted) {
		int bail = (n == 1 && buf[0] == 0x1b);	/* lone ESC */
		ssize_t i;

		for (i = 0; i < n; i++)
			if (buf[i] == 0x03)		/* Ctrl-C */
				bail = 1;
		if (bail) {
			*c->quit = 1;
			return 0;
		}
	}
	fn = termfilter_run(c->tf, buf, (size_t)n, fb);
	if (fn)
		ssh_channel_write(c->chan, fb, (uint32_t)fn);
	return 0;
}

/* Confine the terminal's scroll region to the rows above our reserved status
 * row, so nothing scrolling in the tmux area can ever push into it; on == 0
 * restores the full-screen region. A no-op when we are not reserving. */
static void scroll_guard(int rows, int reserve, int on)
{
	char buf[32];
	int n;

	if (!reserve)
		return;
	if (on)
		n = snprintf(buf, sizeof(buf), "\033[1;%dr", rows - 1);
	else
		n = snprintf(buf, sizeof(buf), "\033[r");
	if (n > 0 && write(STDOUT_FILENO, buf, (size_t)n)) {
		/* best effort */
	}
}

static uint64_t mono_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)(t.tv_nsec / 1000000);
}

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
	/* Hold the session open (the session layer keeps the heartbeat alive on
	 * its own thread), so a test can keep one client connected while another
	 * joins -- the case that reveals slot hogging. */
	if (o->hold_ms > 0) {
		uint64_t end = mono_ms() + (uint64_t)o->hold_ms;

		while (mono_ms() < end && ssh_channel_is_open(chan) &&
		       !ssh_channel_is_eof(chan)) {
			struct timespec ts = { 0, 50 * 1000 * 1000 };

			nanosleep(&ts, NULL);
		}
	}
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
static int run_interactive(ssh_session s, ssh_channel chan,
			   const struct sshc_opts *o)
{
	struct termios orig, raw;
	struct sigaction sa, old_winch;
	int rows = 0, cols = 0, reserve = 0;
	volatile int interrupted = 0, quit = 0;
	int reconnect = 0;
	uint64_t last_status = 0;
	struct conn_status cur, prev;
	struct termfilter tf;
	struct stdin_ctx sctx;
	ssh_event event = ssh_event_new();
	ssh_connector c_out = ssh_connector_new(s);	/* channel -> stdout */
	ssh_connector c_err = ssh_connector_new(s);	/* channel stderr -> stderr */
	ssh_channel ctl = NULL;				/* comrade-ctl subsystem */
	ssh_connector c_ctl_in = NULL, c_ctl_out = NULL;
	int have_tty = isatty(STDIN_FILENO);

	if (!event || !c_out || !c_err)
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

	/* Reserve the bottom row for our local status line, if requested and there
	 * is room: the remote tmux was asked for a pty one row shorter, so it never
	 * touches this row. */
	memset(&prev, 0, sizeof(prev));
	if (have_tty && o && o->status) {
		struct winsize ws;

		if (!ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) && ws.ws_row > 1) {
			rows = ws.ws_row;
			cols = ws.ws_col;
			reserve = 1;
		}
	}
	dbg_logf("sshc run_interactive: have_tty=%d status=%d rows=%d cols=%d "
		 "reserve=%d (tmux gets %d rows)", have_tty, o && o->status,
		 rows, cols, reserve, reserve ? rows - 1 : rows);
	scroll_guard(rows, reserve, 1);

	/* stdin is pumped by us (with the terminal-answer filter); the channel's
	 * two output directions stay on libssh connectors. */
	termfilter_init(&tf, reserve);
	sctx.chan = chan;
	sctx.tf = &tf;
	sctx.eof = 0;
	sctx.interrupted = &interrupted;
	sctx.quit = &quit;
	ssh_connector_set_in_channel(c_out, chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_out_fd(c_out, STDOUT_FILENO);
	ssh_connector_set_in_channel(c_err, chan, SSH_CONNECTOR_STDERR);
	ssh_connector_set_out_fd(c_err, STDERR_FILENO);
	ssh_event_add_fd(event, STDIN_FILENO, POLLIN, on_stdin, &sctx);
	ssh_event_add_connector(event, c_out);
	ssh_event_add_connector(event, c_err);

	/* Open the authenticated control plane alongside the shell: a second SSH
	 * channel requesting the comrade-ctl subsystem, bridged to o->ctl_fd. The
	 * session layer runs its liveness/rendezvous protocol over that fd. */
	if (o && o->ctl_fd > 0) {
		ctl = ssh_channel_new(s);
		if (ctl && ssh_channel_open_session(ctl) == SSH_OK &&
		    ssh_channel_request_subsystem(ctl, "comrade-ctl") == SSH_OK) {
			c_ctl_in = ssh_connector_new(s);
			c_ctl_out = ssh_connector_new(s);
			if (c_ctl_in && c_ctl_out) {
				ssh_connector_set_in_fd(c_ctl_in, o->ctl_fd);
				ssh_connector_set_out_channel(c_ctl_in, ctl,
							SSH_CONNECTOR_STDOUT);
				ssh_connector_set_in_channel(c_ctl_out, ctl,
							SSH_CONNECTOR_STDOUT);
				ssh_connector_set_out_fd(c_ctl_out, o->ctl_fd);
				ssh_event_add_connector(event, c_ctl_in);
				ssh_event_add_connector(event, c_ctl_out);
			}
		}
	}

	while (ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan) &&
	       !quit && !reconnect) {
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
			if (have_tty && !ioctl(STDIN_FILENO, TIOCGWINSZ, &ws)) {
				rows = ws.ws_row;
				cols = ws.ws_col;
				ssh_channel_change_pty_size(chan, ws.ws_col,
							    ws.ws_row - reserve);
				dbg_logf("sshc resize: rows=%d cols=%d "
					 "(tmux gets %d rows)", rows, cols,
					 rows - reserve);
				scroll_guard(rows, reserve, 1);
				memset(&prev, 0, sizeof(prev));	/* repaint */
			}
		}
		if (o && o->status) {
			uint64_t now = mono_ms();

			memset(&cur, 0, sizeof(cur));
			o->status(o->status_arg, &cur);
			interrupted = (cur.state == CONN_LOST);
			/* Lost past the grace window: stop waiting and rejoin as
			 * a fresh client (the session lives on the host). A brief
			 * blip stays under the grace and rides out over KCP. */
			if (cur.state == CONN_LOST &&
			    cur.since_s >= SSHC_REJOIN_GRACE_S)
				reconnect = 1;
			if (reserve && (memcmp(&cur, &prev, sizeof(cur)) ||
			    now - last_status > 2000)) {
				statusbar_render(STDOUT_FILENO, rows, cols, &cur);
				prev = cur;
				last_status = now;
			}
		}
	}
	ssh_event_remove_fd(event, STDIN_FILENO);
	ssh_event_remove_connector(event, c_out);
	ssh_event_remove_connector(event, c_err);
	if (c_ctl_in) {
		ssh_event_remove_connector(event, c_ctl_in);
		ssh_event_remove_connector(event, c_ctl_out);
	}
	if (ctl && ssh_channel_is_open(ctl)) {
		ssh_channel_send_eof(ctl);
		ssh_channel_close(ctl);
	}
	scroll_guard(rows, reserve, 0);
	if (quit) {
		/* We force-quit while the remote tmux still owned the screen:
		 * leave its alternate screen and reset attributes so the shell
		 * comes back clean rather than on tmux's buffer. */
		const char *cl = "\033[?1049l\033[0m";
		ssize_t r = write(STDOUT_FILENO, cl, strlen(cl));

		(void)r;
	}
	sigaction(SIGWINCH, &old_winch, NULL);
	if (have_tty)
		tcsetattr(STDIN_FILENO, TCSANOW, &orig);
	if (quit)
		fprintf(stderr, "comrade: link lost -- disconnected.\n");
out:
	if (c_ctl_in)
		ssh_connector_free(c_ctl_in);
	if (c_ctl_out)
		ssh_connector_free(c_ctl_out);
	if (ctl)
		ssh_channel_free(ctl);
	if (c_out)
		ssh_connector_free(c_out);
	if (c_err)
		ssh_connector_free(c_err);
	if (event)
		ssh_event_free(event);
	return reconnect ? SSHC_RECONNECT : 0;
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
		int reserve, prows;

		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws)) {
			ws.ws_col = 80;
			ws.ws_row = 24;
		}
		/* Match run_interactive: a status line steals the bottom row. */
		reserve = (o->status && isatty(STDIN_FILENO) &&
			   ws.ws_row > 1) ? 1 : 0;
		prows = ws.ws_row - reserve;
		dbg_logf("sshc connect: term=%s rows=%d cols=%d reserve=%d "
			 "-> request pty %dx%d", term, ws.ws_row, ws.ws_col,
			 reserve, prows, ws.ws_col);
		if (ssh_channel_request_pty_size(chan, term, ws.ws_col,
						 prows) != SSH_OK)
			goto out;
		if (ssh_channel_request_shell(chan) != SSH_OK)
			goto out;
		rc = run_interactive(s, chan, o);
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
