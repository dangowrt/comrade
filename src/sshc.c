/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libssh/libssh.h>

#include "base64.h"
#include "dbg.h"
#include "oscompat.h"
#include "sshc.h"
#include "sshfwd.h"
#include "statusbar.h"
#include "termfilter.h"
#include "tty.h"

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
	int read_only;				/* view-only: intercept the leave keys */
	int prefix_pending;			/* saw the tmux prefix, awaiting its key */
	volatile int *left;			/* set when the user asked to leave */
};

/*
 * A view-only client's keystrokes never reach the host's tmux, so the usual
 * detach/exit keys are dead. Recognise the default tmux prefix (Ctrl-b)
 * followed by a detach (d) or kill (x, &) key locally and treat it as a
 * request to leave -- for comrade, detach, exit and leave all just tear the
 * client down. The prefix may straddle two reads, so the pending state lives
 * in the context. Ctrl-b is a C0 byte that never appears inside an escape
 * sequence, so watching for it cannot misfire mid-sequence.
 */
#define TMUX_PREFIX 0x02		/* Ctrl-b */

static int ro_wants_leave(struct stdin_ctx *c, const char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		unsigned char b = (unsigned char)buf[i];

		if (c->prefix_pending) {
			c->prefix_pending = 0;
			if (b == 'd' || b == 'x' || b == '&')
				return 1;
		} else if (b == TMUX_PREFIX) {
			c->prefix_pending = 1;
		}
	}
	return 0;
}

static int on_stdin(socket_t fd, int revents, void *userdata)
{
	struct stdin_ctx *c = userdata;
	char buf[4096], fb[4096 + 32];
	ssize_t n;
	size_t fn;

	if (!(revents & (POLLIN | POLLHUP | POLLERR)))
		return 0;
	n = sock_read(fd, buf, sizeof(buf));
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
	if (c->read_only && ro_wants_leave(c, buf, (size_t)n)) {
		*c->left = 1;
		*c->quit = 1;
		return 0;
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
	if (n > 0 && tty_write(buf, (size_t)n)) {
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

/* Create the forwarding engine and register the -L/-R specs, when any. */
static struct sshfwd *fwd_up(ssh_session s, ssh_event ev,
			     const struct sshc_opts *o)
{
	struct sshfwd *f;
	int i;

	if (!o || (!o->nfwd_l && !o->nfwd_r))
		return NULL;
	f = sshfwd_create(s, ev);
	if (!f)
		return NULL;
	sshfwd_set_tx_room(f, o->tx_room, o->tx_room_arg);
	for (i = 0; i < o->nfwd_l; i++)
		sshfwd_cli_local(f, &o->fwd_l[i]);
	for (i = 0; i < o->nfwd_r; i++)
		sshfwd_cli_remote(f, &o->fwd_r[i]);
	return f;
}

/*
 * Open the authenticated control plane alongside the session channel: a second
 * SSH channel requesting the comrade-ctl subsystem, bridged both ways to
 * o->ctl_fd. The session layer runs its liveness heartbeat, rendezvous exchange
 * and candidate advertisement over that fd. The caller owns everything handed
 * back and pumps `event`; a control plane that could not be opened leaves the
 * session running without one.
 */
static void ctl_open(ssh_session s, ssh_event event, const struct sshc_opts *o,
		     ssh_channel *chan, ssh_connector *in, ssh_connector *out)
{
	*chan = NULL;
	*in = NULL;
	*out = NULL;
	if (!event || !o || !sock_valid(o->ctl_fd))
		return;
	*chan = ssh_channel_new(s);
	if (!*chan)
		return;
	if (ssh_channel_open_session(*chan) != SSH_OK ||
	    ssh_channel_request_subsystem(*chan, "comrade-ctl") != SSH_OK)
		return;
	*in = ssh_connector_new(s);
	*out = ssh_connector_new(s);
	if (!*in || !*out)
		return;
	ssh_connector_set_in_fd(*in, o->ctl_fd);
	ssh_connector_set_out_channel(*in, *chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_in_channel(*out, *chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_out_fd(*out, o->ctl_fd);
	ssh_event_add_connector(event, *in);
	ssh_event_add_connector(event, *out);
}

/*
 * Told, or silent past the grace: either way stop waiting on this transport and
 * rejoin as a fresh client, the session being the host's and not this
 * connection's.
 *
 * Being told is the whole of it when it happens: a host that has reaped a
 * worker and answered the claim that came back with a new one says so on the
 * path it just punched, and there is nothing left to wait for. The grace below
 * is what is left for a host that says nothing -- an older one, or one whose
 * word did not arrive.
 *
 * Silence of the session, not of the path. The host reaps a worker for a
 * client that has gone quiet and keeps serving, so what the returning claim
 * gets is a fresh worker with a fresh sshd -- and every session shares one
 * conversation id and one sealing key, so that worker's frames arrive, open
 * and are taken by the transport while reaching nothing above it. A path can
 * therefore read as alive, and a resume can be picked up again and again,
 * with no session behind any of it. The heartbeat pong crosses the whole
 * session and nothing else does, so its silence is the one clock that keeps
 * running through all of that.
 *
 * Every loop asks: a client with no terminal is no less entitled to come back
 * than one with a dashboard.
 */
static int rejoin_due(const struct conn_status *cur)
{
	return cur->gone || cur->silent_s >= SSHC_REJOIN_GRACE_S;
}

static int rejoin_now(const struct sshc_opts *o)
{
	struct conn_status cur;

	if (!o || !o->status)
		return 0;
	memset(&cur, 0, sizeof(cur));
	o->status(o->status_arg, &cur);
	return rejoin_due(&cur);
}

/* Test mode: write the whole request, then read echoed bytes until we have
 * as many as we sent (or the channel ends). */
static int run_test(ssh_session s, ssh_channel chan, const struct sshc_opts *o)
{
	ssh_channel ctl = NULL;				/* comrade-ctl subsystem */
	ssh_connector c_ctl_in = NULL, c_ctl_out = NULL;
	ssh_event event = ssh_event_new();
	struct sshfwd *fwd = NULL;
	size_t got = 0;
	int rc = -1;

	if (event && (o->nfwd_l || o->nfwd_r))
		fwd = fwd_up(s, event, o);
	ctl_open(s, event, o, &ctl, &c_ctl_in, &c_ctl_out);

	if (o->send_len &&
	    ssh_channel_write(chan, o->send, (uint32_t)o->send_len) !=
	    (int)o->send_len)
		goto out;

	while (got < o->send_len && got < o->recv_cap) {
		int n = ssh_channel_read(chan, o->recv + got,
					 (uint32_t)(o->recv_cap - got), 0);

		if (n < 0)
			goto out;
		if (n == 0)
			break;
		got += (size_t)n;
	}
	if (o->recv_len)
		*o->recv_len = got;
	rc = 0;
	/* Hold the session open so a test can keep one client connected while
	 * another joins -- the case that reveals slot hogging -- and so the
	 * control plane, forwarding and path upkeep are all exercised over a
	 * live session rather than only over a bring-up. */
	if (o->hold_ms > 0) {
		uint64_t end = mono_ms() + (uint64_t)o->hold_ms;

		while (mono_ms() < end && ssh_channel_is_open(chan) &&
		       !ssh_channel_is_eof(chan) &&
		       !(o->stop && *o->stop)) {
			char sink[4096];

			if (rejoin_now(o)) {
				rc = SSHC_RECONNECT;
				break;
			}

			/* Drain what the command keeps producing, or the
			 * channel window would idle the very link the hold is
			 * meant to keep carrying. */
			while (ssh_channel_poll(chan, 0) > 0 &&
			       ssh_channel_read_nonblocking(chan, sink,
							    sizeof(sink),
							    0) > 0)
				;
			if (event) {
				ssh_event_dopoll(event, 50);
				sshfwd_tick(fwd);
			} else {
				os_msleep(50);
			}
		}
	}
out:
	sshfwd_destroy(fwd);
	if (c_ctl_in) {
		ssh_event_remove_connector(event, c_ctl_in);
		ssh_event_remove_connector(event, c_ctl_out);
	}
	if (ctl && ssh_channel_is_open(ctl)) {
		ssh_channel_send_eof(ctl);
		ssh_channel_close(ctl);
	}
	if (c_ctl_in)
		ssh_connector_free(c_ctl_in);
	if (c_ctl_out)
		ssh_connector_free(c_ctl_out);
	if (ctl)
		ssh_channel_free(ctl);
	if (event)
		ssh_event_free(event);
	return rc;
}

/*
 * Forward-only (-N): no shell was requested, so the primary channel is an
 * inert keepalive. Run the control plane, the -L/-R forwarding and path
 * upkeep until the channel ends or the transport drops. Returns 0 on a clean
 * end, -1 on failure.
 */
static int run_forward(ssh_session s, ssh_channel chan,
		       const struct sshc_opts *o)
{
	ssh_channel ctl = NULL;
	ssh_connector c_ctl_in = NULL, c_ctl_out = NULL;
	ssh_event event = ssh_event_new();
	struct sshfwd *fwd = NULL;
	int rc = 0;

	if (event)
		fwd = fwd_up(s, event, o);
	ctl_open(s, event, o, &ctl, &c_ctl_in, &c_ctl_out);
	/* With no shell connectors bridging the session, the event would not
	 * poll the session socket, so an incoming forwarded-tcpip channel (a
	 * -R connection) would never be seen. Add the session directly. */
	if (event)
		ssh_event_add_session(event, s);

	while (ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan)) {
		char sink[4096];

		if (rejoin_now(o)) {
			rc = SSHC_RECONNECT;
			break;
		}
		/* Nothing should arrive on the keepalive channel, but drain it
		 * so a stray byte never wedges the window. */
		while (ssh_channel_poll(chan, 0) > 0 &&
		       ssh_channel_read_nonblocking(chan, sink, sizeof(sink),
						    0) > 0)
			;
		if (event) {
			if (ssh_event_dopoll(event, 200) == SSH_ERROR) {
				rc = -1;
				break;
			}
			sshfwd_tick(fwd);
		} else {
			os_msleep(200);
		}
	}

	sshfwd_destroy(fwd);
	if (c_ctl_in) {
		ssh_event_remove_connector(event, c_ctl_in);
		ssh_event_remove_connector(event, c_ctl_out);
	}
	if (ctl && ssh_channel_is_open(ctl)) {
		ssh_channel_send_eof(ctl);
		ssh_channel_close(ctl);
	}
	if (c_ctl_in)
		ssh_connector_free(c_ctl_in);
	if (c_ctl_out)
		ssh_connector_free(c_ctl_out);
	if (ctl)
		ssh_channel_free(ctl);
	if (event) {
		ssh_event_remove_session(event, s);
		ssh_event_free(event);
	}
	return rc;
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
	struct tty_saved term;
	int rows = 0, cols = 0, reserve = 0;
	volatile int interrupted = 0, quit = 0, left = 0;
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
	struct sshfwd *fwd = NULL;			/* -L/-R forwarding */
	sock_t s_in = tty_sock_in(), s_out = tty_sock_out();
	sock_t s_err = tty_sock_err();
	int have_tty = tty_isatty_in();

	if (!event || !c_out || !c_err)
		goto out;
	if (!sock_valid(s_in) || !sock_valid(s_out) || !sock_valid(s_err))
		goto out;

	if (have_tty && tty_raw_on(&term, 1))
		have_tty = 0;
	tty_resize_watch(1);

	/* Reserve the bottom row for our local status line, if requested and there
	 * is room: the remote tmux was asked for a pty one row shorter, so it never
	 * touches this row. */
	memset(&prev, 0, sizeof(prev));
	if (have_tty && o && o->status) {
		int r, c;

		if (!tty_size(&r, &c) && r > 1) {
			rows = r;
			cols = c;
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
	sctx.read_only = o && o->read_only;
	sctx.prefix_pending = 0;
	sctx.left = &left;
	ssh_connector_set_in_channel(c_out, chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_out_fd(c_out, s_out);
	ssh_connector_set_in_channel(c_err, chan, SSH_CONNECTOR_STDERR);
	ssh_connector_set_out_fd(c_err, s_err);
	ssh_event_add_fd(event, s_in, POLLIN, on_stdin, &sctx);
	ssh_event_add_connector(event, c_out);
	ssh_event_add_connector(event, c_err);

	ctl_open(s, event, o, &ctl, &c_ctl_in, &c_ctl_out);

	/* -L/-R port forwarding rides the same session; served from this loop. */
	fwd = fwd_up(s, event, o);

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
			os_msleep(100);
		}
		sshfwd_tick(fwd);
		if (tty_resized()) {
			int r, c;

			if (have_tty && !tty_size(&r, &c)) {
				rows = r;
				cols = c;
				ssh_channel_change_pty_size(chan, c, r - reserve);
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
			if (rejoin_due(&cur))
				reconnect = 1;
			if (reserve && (memcmp(&cur, &prev, sizeof(cur)) ||
			    now - last_status > 2000)) {
				statusbar_render(rows, cols, &cur);
				prev = cur;
				last_status = now;
			}
		}
	}
	sshfwd_destroy(fwd);
	fwd = NULL;
	ssh_event_remove_fd(event, s_in);
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
		int r = tty_write(cl, strlen(cl));

		(void)r;
	}
	tty_resize_watch(0);
	if (have_tty)
		tty_raw_off(&term);
	if (left)
		fprintf(stderr, "comrade: detached.\n");
	else if (quit)
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
	/* Stops the console pump threads and closes their sockets; on POSIX the
	 * standard descriptors are handed back untouched. */
	tty_sock_release();
	return reconnect ? SSHC_RECONNECT : 0;
}

int sshc_connect_fd(sock_t fd, const struct sshc_opts *o)
{
	char password[64];
	const char *host = "comrade";
	ssh_session s = NULL;
	ssh_channel chan = NULL;
	socket_t sock = fd;
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
	if (o->connect_timeout_s > 0) {
		long tov = (long)o->connect_timeout_s;

		ssh_options_set(s, SSH_OPTIONS_TIMEOUT, &tov);
	}
	dbg_logf("sshc: ssh_connect starting");
	if (ssh_connect(s) != SSH_OK) {
		dbg_logf("sshc: ssh_connect failed: %s", ssh_get_error(s));
		fprintf(stderr, "comrade: ssh_connect: %s\n", ssh_get_error(s));
		goto out;
	}
	dbg_logf("sshc: ssh_connect ok, pin_hostkey");
	if (pin_hostkey(s, o->host_fp)) {
		dbg_logf("sshc: pin_hostkey mismatch");
		fprintf(stderr, "comrade: host key mismatch, refusing to connect\n");
		goto out;
	}
	dbg_logf("sshc: pin_hostkey ok, userauth");
	if (ssh_userauth_password(s, NULL, password) != SSH_AUTH_SUCCESS) {
		dbg_logf("sshc: userauth failed: %s", ssh_get_error(s));
		fprintf(stderr, "comrade: authentication failed\n");
		goto out;
	}
	dbg_logf("sshc: userauth ok, channel open");

	chan = ssh_channel_new(s);
	if (!chan || ssh_channel_open_session(chan) != SSH_OK) {
		dbg_logf("sshc: channel open failed: %s", ssh_get_error(s));
		goto out;
	}
	dbg_logf("sshc: channel open ok");
	if (o->forward_only) {
		/* No shell: hold the session channel open as a keepalive and
		 * run forwarding + the control plane only. */
		dbg_logf("sshc: forward-only, no shell requested");
		rc = run_forward(s, chan, o);
	} else if (o->interactive) {
		const char *term = getenv("TERM");
		int reserve, prows, rows, cols;

		if (!term)
			term = "xterm-256color";
		if (tty_size(&rows, &cols)) {
			rows = 24;
			cols = 80;
		}
		/* Match run_interactive: a status line steals the bottom row. */
		reserve = (o->status && tty_isatty_in() && rows > 1) ? 1 : 0;
		prows = rows - reserve;
		dbg_logf("sshc connect: term=%s rows=%d cols=%d reserve=%d "
			 "-> request pty %dx%d", term, rows, cols,
			 reserve, prows, cols);
		if (ssh_channel_request_pty_size(chan, term, cols,
						 prows) != SSH_OK)
			goto out;
		if (ssh_channel_request_shell(chan) != SSH_OK)
			goto out;
		rc = run_interactive(s, chan, o);
	} else {
		if (ssh_channel_request_shell(chan) != SSH_OK)
			goto out;
		rc = run_test(s, chan, o);
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
	if (sock_valid(sock))
		sock_close(sock);
	return rc;
}
