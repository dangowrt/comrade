/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "base64.h"
#include "sshd.h"

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

	if (ssh_pki_generate_key(SSH_KEYTYPE_ED25519, NULL, &key) != SSH_OK)
		return NULL;
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

/* Spawn /bin/sh -c command; return its pid, plus write- and read-side fds
 * toward the child's stdin and stdout. With a pty both are the master fd. */
static int spawn(const char *command, int use_pty, pid_t *pid,
		 int *to_child, int *from_child)
{
	const char *cmd = command ? command : "tmux new-session -A -s comrade";
	pid_t p;

	if (use_pty) {
		int master;

		p = forkpty(&master, NULL, NULL, NULL);
		if (p < 0)
			return -1;
		if (p == 0) {
			execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
			_exit(127);
		}
		*pid = p;
		*to_child = master;
		*from_child = master;
		return 0;
	} else {
		int in[2], out[2];

		if (pipe(in))
			return -1;
		if (pipe(out)) {
			close(in[0]);
			close(in[1]);
			return -1;
		}
		p = fork();
		if (p < 0) {
			close(in[0]); close(in[1]);
			close(out[0]); close(out[1]);
			return -1;
		}
		if (p == 0) {
			dup2(in[0], STDIN_FILENO);
			dup2(out[1], STDOUT_FILENO);
			dup2(out[1], STDERR_FILENO);
			close(in[0]); close(in[1]);
			close(out[0]); close(out[1]);
			execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
			_exit(127);
		}
		close(in[0]);
		close(out[1]);
		*pid = p;
		*to_child = in[1];
		*from_child = out[0];
		return 0;
	}
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
 * whether the client asked for a pty so we can match it on the child. */
static int do_shell_request(ssh_session s, int *want_pty)
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
				*want_pty = 1;
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
static void pump(ssh_session s, ssh_channel chan, int to_child, int from_child,
		 pid_t child, int end_fd)
{
	ssh_event event = ssh_event_new();
	ssh_connector c_in = ssh_connector_new(s);   /* channel -> child stdin */
	ssh_connector c_out = ssh_connector_new(s);  /* child stdout -> channel */
	int ending = 0, drain = 0, end_hit = 0;

	if (!event || !c_in || !c_out)
		goto out;

	ssh_connector_set_out_fd(c_in, to_child);
	ssh_connector_set_in_channel(c_in, chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_in_fd(c_out, from_child);
	ssh_connector_set_out_channel(c_out, chan, SSH_CONNECTOR_STDOUT);

	ssh_event_add_connector(event, c_in);
	ssh_event_add_connector(event, c_out);
	if (end_fd > 0)
		ssh_event_add_fd(event, end_fd,
				 POLLIN | POLLHUP | POLLERR | POLLNVAL,
				 on_end_fd, &end_hit);

	while (ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan)) {
		if (ssh_event_dopoll(event, 200) == SSH_ERROR)
			break;
		if (!ending && end_hit)
			ending = 1;
		if (!ending &&
		    waitpid(child, NULL, WNOHANG | WNOWAIT) == child)
			ending = 1;
		if (ending && ++drain >= 3)
			break;
	}

	if (end_fd > 0)
		ssh_event_remove_fd(event, end_fd);
	ssh_event_remove_connector(event, c_in);
	ssh_event_remove_connector(event, c_out);
out:
	if (c_in)
		ssh_connector_free(c_in);
	if (c_out)
		ssh_connector_free(c_out);
	if (event)
		ssh_event_free(event);
}

int sshd_serve_fd(int fd, const struct sshd_opts *o)
{
	char password[64];
	ssh_bind bind = NULL;
	ssh_session s = NULL;
	ssh_channel chan = NULL;
	pid_t child = -1;
	int to_child = -1, from_child = -1;
	int want_pty = 0;
	int gave_fd = 0;
	int rc = -1;

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
	if (do_shell_request(s, &want_pty))
		goto out;

	if (spawn(o->command, o->use_pty || want_pty, &child,
		  &to_child, &from_child))
		goto out;

	pump(s, chan, to_child, from_child, child, o->end_fd);
	rc = 0;
out:
	if (to_child >= 0)
		close(to_child);
	if (from_child >= 0 && from_child != to_child)
		close(from_child);
	if (child > 0) {
		int status;

		kill(child, SIGHUP);
		waitpid(child, &status, 0);
	}
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
	if (bind)
		ssh_bind_free(bind);
	/*
	 * ssh_bind_accept_fd adopts the fd, so libssh closes it above; close it
	 * ourselves only if the session never got that far. Either way it ends
	 * up closed, which signals end-of-session to the bridge.
	 */
	if (!gave_fd)
		close(fd);
	return rc;
}
