/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sshd.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "base64.h"
#include "cpty.h"
#include "dbg.h"
#include "sshfwd.h"

/*
 * This file is platform-neutral. Everything Unix-shaped it used to contain --
 * forkpty, TIOCSWINSZ, waitpid -- lives behind cpty.h, which is forkpty plus
 * /bin/sh on POSIX and a pseudoconsole plus CreateProcess on Windows, and
 * hands back the same pair of pollable ends either way (see cpty.h).
 */

/* Constant-time equality over a fixed-length buffer. */
static int ct_equal(const void *a, const void *b, size_t len)
{
	const volatile uint8_t *x = a, *y = b;
	uint8_t d = 0;
	size_t i;

	for (i = 0; i < len; i++)
		d |= (uint8_t)(x[i] ^ y[i]);
	return d == 0;
}

void *sshd_hostkey_new(uint8_t fp[32])
{
	unsigned char *hash = NULL;
	size_t hlen = 0;
	ssh_key key = NULL;
	ssh_key pub = NULL;

	/* ssh_pki_generate() is deprecated on new libssh and the only option on
	 * the older releases distributions still ship; the build probes for the
	 * replacement (see CMakeLists.txt). Ed25519 ignores the parameter. */
#ifdef COMRADE_HAVE_PKI_GENERATE_KEY
	if (ssh_pki_generate_key(SSH_KEYTYPE_ED25519, NULL, &key) != SSH_OK)
		return NULL;
#else
	if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &key) != SSH_OK)
		return NULL;
#endif
	if (ssh_pki_export_privkey_to_pubkey(key, &pub) != SSH_OK)
		goto fail;
	if (ssh_get_publickey_hash(pub, SSH_PUBLICKEY_HASH_SHA256,
				   &hash, &hlen) != 0)
		goto fail;
	if (hlen != 32)
		goto fail;
	memcpy(fp, hash, 32);
	ssh_clean_pubkey_hash(&hash);
	ssh_key_free(pub);
	return key;
fail:
	if (hash)
		ssh_clean_pubkey_hash(&hash);
	if (pub)
		ssh_key_free(pub);
	if (key)
		ssh_key_free(key);
	return NULL;
}

void sshd_hostkey_free(void *hostkey)
{
	if (hostkey)
		ssh_key_free((ssh_key)hostkey);
}

/* A terminal type is a short name; accept only a safe charset so it can be
 * pasted into the shell command that sets TERM (see spawn) without escaping. */
static int safe_term(const char *t)
{
	size_t i;

	if (!t || !*t)
		return 0;
	for (i = 0; t[i]; i++) {
		char c = t[i];

		if (i >= 63)
			return 0;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '-' ||
		      c == '_'))
			return 0;
	}
	return 1;
}

/* Authenticate: only password auth, only the token secret, constant-time. */
static int do_auth(ssh_session s, const char *password)
{
	for (;;) {
		ssh_message m = ssh_message_get(s);
		int type, subtype, ok = 0;

		if (!m)
			return -1;
		type = ssh_message_type(m);
		subtype = ssh_message_subtype(m);
		if (type == SSH_REQUEST_AUTH &&
		    subtype == SSH_AUTH_METHOD_PASSWORD) {
			const char *pw = ssh_message_auth_password(m);

			if (pw && strlen(pw) == strlen(password) &&
			    ct_equal(pw, password, strlen(password))) {
				ssh_message_auth_reply_success(m, 0);
				ssh_message_free(m);
				return 0;
			}
			ok = 0;
		}
		(void)ok;
		ssh_message_auth_set_methods(m, SSH_AUTH_METHOD_PASSWORD);
		ssh_message_reply_default(m);
		ssh_message_free(m);
	}
}

/* Accept a session channel. */
static ssh_channel do_channel(ssh_session s)
{
	for (;;) {
		ssh_message m = ssh_message_get(s);
		ssh_channel chan;

		if (!m)
			return NULL;
		if (ssh_message_type(m) == SSH_REQUEST_CHANNEL_OPEN &&
		    ssh_message_subtype(m) == SSH_CHANNEL_SESSION) {
			chan = ssh_message_channel_request_open_reply_accept(m);
			ssh_message_free(m);
			return chan;
		}
		ssh_message_reply_default(m);
		ssh_message_free(m);
	}
}

/* Wait for a shell/exec request; accept pty requests along the way. Reports
 * whether the client asked for a pty and, if so, the terminal size it asked
 * for so the child's pty can match it (see spawn). */
static int do_shell_request(ssh_session s, int *want_pty, int *rows, int *cols,
			    char *term, size_t termlen)
{
	*want_pty = 0;
	for (;;) {
		ssh_message m = ssh_message_get(s);
		int type, subtype;

		if (!m)
			return -1;
		type = ssh_message_type(m);
		subtype = ssh_message_subtype(m);
		if (type == SSH_REQUEST_CHANNEL) {
			if (subtype == SSH_CHANNEL_REQUEST_PTY) {
				const char *t =
					ssh_message_channel_request_pty_term(m);

				*want_pty = 1;
				*cols = ssh_message_channel_request_pty_width(m);
				*rows = ssh_message_channel_request_pty_height(m);
				if (safe_term(t))
					snprintf(term, termlen, "%s", t);
				ssh_message_channel_request_reply_success(m);
				ssh_message_free(m);
				continue;
			}
			if (subtype == SSH_CHANNEL_REQUEST_SHELL ||
			    subtype == SSH_CHANNEL_REQUEST_EXEC) {
				ssh_message_channel_request_reply_success(m);
				ssh_message_free(m);
				return 0;
			}
		}
		ssh_message_reply_default(m);
		ssh_message_free(m);
	}
}

/* Apply a client window-change to the child pty so tmux reflows. The client
 * has already subtracted its reserved status row, and its terminal-size answer
 * to tmux is corrected on the client side too, so tmux stays one row short. */
static void apply_winch(struct cpty *child, ssh_message m)
{
	int cols = ssh_message_channel_request_pty_width(m);
	int rows = ssh_message_channel_request_pty_height(m);

	dbg_logf("sshd window-change -> pty %dx%d", rows, cols);
	cpty_resize(child, rows, cols);
}

/*
 * State the pump loop carries so drain_messages() can accept and wire up extra
 * channels that arrive after the shell channel. Channels are dispatched by
 * subsystem name; today only "comrade-ctl" (an authenticated control plane
 * bridged to ctl_fd), leaving room for comrade-transfer / comrade-tunnel.
 */
struct pump_ctx {
	ssh_session s;
	ssh_event event;
	struct cpty *child;		/* the shell pty, for window-change */
	sock_t ctl_fd;			/* control-plane socket, 0 if none */
	ssh_channel ctl_chan;		/* the accepted control channel */
	ssh_connector ctl_in;		/* ctl_fd -> channel */
	ssh_connector ctl_out;		/* channel -> ctl_fd */
	struct sshfwd *fwd;		/* port forwarding; NULL = declined */
	int end_hit;
};

/* Bridge the accepted control channel to ctl_fd, both ways, once its subsystem
 * request has named it comrade-ctl. Returns 0 on success. */
static int ctl_bridge_up(struct pump_ctx *c)
{
	c->ctl_in = ssh_connector_new(c->s);
	c->ctl_out = ssh_connector_new(c->s);
	if (!c->ctl_in || !c->ctl_out)
		return -1;
	ssh_connector_set_in_fd(c->ctl_in, c->ctl_fd);
	ssh_connector_set_out_channel(c->ctl_in, c->ctl_chan,
				      SSH_CONNECTOR_STDOUT);
	ssh_connector_set_in_channel(c->ctl_out, c->ctl_chan,
				     SSH_CONNECTOR_STDOUT);
	ssh_connector_set_out_fd(c->ctl_out, c->ctl_fd);
	ssh_event_add_connector(c->event, c->ctl_in);
	ssh_event_add_connector(c->event, c->ctl_out);
	dbg_logf("sshd: comrade-ctl channel bridged");
	return 0;
}

/*
 * Drain pending session messages: apply window-change to the pty, accept a
 * second session channel and, if it requests the comrade-ctl subsystem, bridge
 * it to ctl_fd; reply to everything else so nothing stalls. Non-blocking (the
 * session is in non-blocking mode), so it returns once the queue is empty.
 */
static void drain_messages(struct pump_ctx *c)
{
	ssh_message m;

	while ((m = ssh_message_get(c->s)) != NULL) {
		int type = ssh_message_type(m);
		int sub = ssh_message_subtype(m);

		if (type == SSH_REQUEST_CHANNEL_OPEN &&
		    sub == SSH_CHANNEL_SESSION && sock_isset(c->ctl_fd) &&
		    !c->ctl_chan) {
			c->ctl_chan =
				ssh_message_channel_request_open_reply_accept(m);
			ssh_message_free(m);
			continue;
		}
		if (type == SSH_REQUEST_CHANNEL &&
		    sub == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
			apply_winch(c->child, m);
			ssh_message_reply_default(m);
			ssh_message_free(m);
			continue;
		}
		if (type == SSH_REQUEST_CHANNEL &&
		    sub == SSH_CHANNEL_REQUEST_SUBSYSTEM && c->ctl_chan &&
		    !c->ctl_in) {
			const char *name =
				ssh_message_channel_request_subsystem(m);

			if (name && !strcmp(name, "comrade-ctl") &&
			    !ctl_bridge_up(c)) {
				ssh_message_channel_request_reply_success(m);
				ssh_message_free(m);
				continue;
			}
		}
		/* Port forwarding (direct-tcpip, tcpip-forward): the engine
		 * consumes these when the host allows it; with no engine they
		 * fall through to the default reply, i.e. are refused. */
		if (c->fwd && sshfwd_srv_message(c->fwd, m))
			continue;
		ssh_message_reply_default(m);
		ssh_message_free(m);
	}
}

/* End-of-session fd became readable (a liveness monitor exited with the shared
 * session). Flag it; the pump breaks on the flag and closes toward the client. */
static int on_end_fd(socket_t fd, int revents, void *userdata)
{
	(void)fd;
	if (revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))
		*(int *)userdata = 1;
	return 0;
}

/*
 * Bridge the channel to the child's fds until either side ends. The child
 * exiting is one authoritative end of a session, but a pty master returns EIO
 * rather than a clean EOF when its slave goes away, so the connectors do not
 * reliably surface it. Worse, our command is `tmux attach`, which does not
 * reliably exit when the shared session it serves is gone. So we end the loop
 * on any of: the connectors erroring, the child exiting (watched directly;
 * WNOWAIT leaves it for the caller to reap), or the optional end-of-session fd
 * signalling (event-driven, so the client is released the moment the session
 * ends, not after a poll interval). A few extra polls flush the command's final
 * output first; then we return and the caller closes the channel to the client.
 */
static void pump(ssh_session s, ssh_channel chan, struct cpty *child,
		 const struct sshd_opts *o)
{
	sock_t end_fd = o->end_fd;
	struct pump_ctx c;
	ssh_connector c_in, c_out;	/* shell channel <-> child */
	int ending = 0, drain = 0;

	memset(&c, 0, sizeof(c));
	c.s = s;
	c.child = child;
	c.ctl_fd = o->ctl_fd;
	c.event = ssh_event_new();
	if (c.event && !o->no_fwd)
		c.fwd = sshfwd_create(s, c.event);
	c_in = ssh_connector_new(s);
	c_out = ssh_connector_new(s);
	if (!c.event || !c_in || !c_out)
		goto out;

	ssh_connector_set_out_fd(c_in, cpty_in(child));
	ssh_connector_set_in_channel(c_in, chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_in_fd(c_out, cpty_out(child));
	ssh_connector_set_out_channel(c_out, chan, SSH_CONNECTOR_STDOUT);

	ssh_event_add_connector(c.event, c_in);
	ssh_event_add_connector(c.event, c_out);
	if (sock_isset(end_fd))
		ssh_event_add_fd(c.event, end_fd,
				 POLLIN | POLLHUP | POLLERR | POLLNVAL,
				 on_end_fd, &c.end_hit);

	/* So drain_messages() can poll the request queue without blocking. */
	ssh_set_blocking(s, 0);

	while (ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan)) {
		if (ssh_event_dopoll(c.event, 200) == SSH_ERROR)
			break;
		drain_messages(&c);
		sshfwd_tick(c.fwd);
		if (!ending && c.end_hit)
			ending = 1;
		if (!ending && cpty_exited(child))
			ending = 1;
		if (ending && ++drain >= 3)
			break;
	}

	sshfwd_destroy(c.fwd);
	c.fwd = NULL;
	if (sock_isset(end_fd))
		ssh_event_remove_fd(c.event, end_fd);
	ssh_event_remove_connector(c.event, c_in);
	ssh_event_remove_connector(c.event, c_out);
	if (c.ctl_in) {
		ssh_event_remove_connector(c.event, c.ctl_in);
		ssh_event_remove_connector(c.event, c.ctl_out);
	}
	if (c.ctl_chan && ssh_channel_is_open(c.ctl_chan))
		ssh_channel_close(c.ctl_chan);
out:
	if (c_in)
		ssh_connector_free(c_in);
	if (c_out)
		ssh_connector_free(c_out);
	if (c.ctl_in)
		ssh_connector_free(c.ctl_in);
	if (c.ctl_out)
		ssh_connector_free(c.ctl_out);
	if (c.ctl_chan)
		ssh_channel_free(c.ctl_chan);
	if (c.event)
		ssh_event_free(c.event);
}

int sshd_serve_fd(sock_t fd, const struct sshd_opts *o)
{
	char password[64];
	ssh_bind bind = NULL;
	ssh_session s = NULL;
	ssh_channel chan = NULL;
	struct cpty *child = NULL;
	int want_pty = 0;
	int gave_fd = 0;
	int rc = -1;
	int exit_code = 0;
	int rows = 0, cols = 0;
	char term[64];

	if (!o || !o->hostkey)
		return -1;
	if (!base64url_encode(o->auth, TOKEN_AUTH_LEN, password, sizeof(password)))
		return -1;

	bind = ssh_bind_new();
	if (!bind)
		goto out;
	if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY,
				 ssh_key_dup((ssh_key)o->hostkey)) != SSH_OK)
		goto out;

	s = ssh_new();
	if (!s)
		goto out;
	if (ssh_bind_accept_fd(bind, s, fd) != SSH_OK)
		goto out;
	gave_fd = 1;
	if (ssh_handle_key_exchange(s) != SSH_OK)
		goto out;
	if (do_auth(s, password))
		goto out;
	chan = do_channel(s);
	if (!chan)
		goto out;
	term[0] = '\0';
	if (do_shell_request(s, &want_pty, &rows, &cols, term, sizeof(term)))
		goto out;

	/* Size the terminal from the client's request so the remote command
	 * (tmux) uses exactly the rows it asked for. The client reserves its own
	 * bottom status row by requesting one row fewer; honouring that here is
	 * what keeps tmux off that row. */
	child = cpty_spawn(o->command, o->use_pty || want_pty, rows, cols, term);
	if (!child)
		goto out;

	/* Live resizes arrive as window-change requests; the pump applies them
	 * to the pty. A second channel requesting the comrade-ctl subsystem is
	 * bridged to o->ctl_fd, and client port forwards are served unless
	 * o->no_fwd declines them (all in drain_messages). */
	pump(s, chan, child, o);
	rc = 0;
out:
	if (child)
		exit_code = cpty_close(child);
	if (chan) {
		if (ssh_channel_is_open(chan)) {
			/*
			 * The dedicated end-of-session signal: an SSH exit-status
			 * followed by EOF and close. This is how the peer learns the
			 * shared session is over -- distinct from a transport drop, so
			 * a flaky link or a roam is never mistaken for the end.
			 */
			ssh_channel_request_send_exit_status(chan, exit_code);
			ssh_channel_send_eof(chan);
			ssh_channel_close(chan);
		}
		ssh_channel_free(chan);
	}
	if (s) {
		ssh_disconnect(s);
		ssh_free(s);
	}
	if (bind)
		ssh_bind_free(bind);
	/*
	 * ssh_bind_accept_fd adopts the fd, so libssh closes it above; close it
	 * ourselves only if the session never got that far. Either way it ends
	 * up closed, which signals end-of-session to the bridge.
	 */
	if (!gave_fd)
		sock_close(fd);
	return rc;
}
