/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dbg.h"
#include "sshfwd.h"

#define FWD_MAX_BRIDGE 16		/* live forwarded connections */
#define FWD_MAX_LISTEN 8		/* listeners (-L local, -R host-side) */
#define FWD_MAX_PEND 8			/* in-flight connects / channel opens */
#define FWD_CONNECT_TIMEOUT_MS 5000

/* A live forwarded connection: fd <-> channel via two libssh connectors. */
struct fwd_bridge {
	int used;
	sock_t fd;
	ssh_channel chan;
	ssh_connector in;		/* fd -> channel */
	ssh_connector out;		/* channel -> fd */
};

/* A listening socket. On the client it carries the -L target spec; on the
 * host it is a -R listener whose accepts open reverse channels, reported
 * with the address string the client asked to bind. */
struct fwd_listener {
	int used;
	sock_t fd;
	int is_remote;			/* host side of -R */
	struct fwdspec sp;		/* client -L: connect target */
	char req_addr[64];		/* host -R: address to report */
	uint16_t port;			/* bound port (reported / matched) */
};

enum pend_kind {
	PEND_SRV_CONNECT,		/* host: direct-tcpip target connect;
					 * the open reply waits on the result */
	PEND_CLI_CONNECT,		/* client: -R local target connect */
	PEND_REV_OPEN			/* host: reverse channel open (SSH_AGAIN) */
};

struct fwd_pend {
	int used;
	enum pend_kind kind;
	sock_t fd;
	ssh_message msg;		/* PEND_SRV_CONNECT: deferred reply */
	ssh_channel chan;		/* PEND_CLI_CONNECT / PEND_REV_OPEN */
	uint64_t deadline;
	char addr[64];			/* PEND_REV_OPEN: reported bind address */
	uint16_t port;			/*   and port */
	char orig[64];			/* PEND_REV_OPEN: originator */
	uint16_t orig_port;
};

struct sshfwd {
	ssh_session s;
	ssh_event ev;
	int have_remote;		/* any -R registered: poll for accepts */
	struct fwd_bridge br[FWD_MAX_BRIDGE];
	struct fwd_listener ls[FWD_MAX_LISTEN];
	struct fwd_pend pd[FWD_MAX_PEND];
};

static uint64_t fwd_now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)(t.tv_nsec / 1000000);
}

/* The peer name of a connected fd, for channel-open originator fields. */
static void peer_name(sock_t fd, char *addr, size_t alen, uint16_t *port)
{
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);

	snprintf(addr, alen, "0.0.0.0");
	*port = 0;
	if (getpeername(fd, (struct sockaddr *)&ss, &sl))
		return;
	if (ss.ss_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)&ss;

		inet_ntop(AF_INET, &a->sin_addr, addr, (socklen_t)alen);
		*port = ntohs(a->sin_port);
	} else if (ss.ss_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)&ss;

		inet_ntop(AF_INET6, &a->sin6_addr, addr, (socklen_t)alen);
		*port = ntohs(a->sin6_port);
	}
}

/* Begin a non-blocking connect to host:port (first resolved address).
 * Returns the fd, or -1. getaddrinfo itself can block on real DNS; targets
 * here are typically loopback, numeric, or local names, and the punched
 * session tolerates a stall of that order (it rides KCP retransmission). */
static sock_t start_connect(const char *host, uint16_t port)
{
	struct addrinfo hints, *res = NULL;
	char portstr[8];
	sock_t fd = INVALID_SOCK;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	snprintf(portstr, sizeof(portstr), "%u", port);
	if (getaddrinfo(host, portstr, &hints, &res) || !res)
		return INVALID_SOCK;
	fd = socket(res->ai_family, SOCK_STREAM, 0);
	if (sock_valid(fd))
		sock_set_nonblock(fd);	/* SOCK_NONBLOCK is Linux-only */
	if (sock_valid(fd) && connect(fd, res->ai_addr, (int)res->ai_addrlen) &&
	    !sock_err_in_progress(sock_errno())) {
		sock_close(fd);
		fd = INVALID_SOCK;
	}
	freeaddrinfo(res);
	return fd;
}

/*
 * Poll a pending connect: 1 connected, 0 still going, -1 failed.
 *
 * WSAPoll does not report a *failed* connect at all -- neither POLLOUT nor
 * POLLERR -- so on Windows a refused target shows up as "still going" until
 * the caller's FWD_CONNECT_TIMEOUT_MS deadline expires, rather than as an
 * immediate refusal. The outcome is the same, just slower; SO_ERROR is still
 * consulted whenever the poll does report something.
 */
static int finish_connect(sock_t fd)
{
	struct pollfd p;
	int err = 0;
	socklen_t el = sizeof(err);

	p.fd = fd;
	p.events = POLLOUT;
	p.revents = 0;
	if (sock_poll(&p, 1, 0) <= 0)
		return 0;
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &el) || err)
		return -1;
	return 1;
}

/* Bind a listener for `addr` (fwdspec semantics: "" loopback, "*" any) on
 * `port` (0 = ephemeral). Returns the fd and stores the bound port. */
static sock_t listen_on(const char *addr, uint16_t port, uint16_t *bound)
{
	struct sockaddr_storage ss;
	struct sockaddr_in *a4 = (struct sockaddr_in *)&ss;
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
	socklen_t sl;
	sock_t fd;
	int one = 1;

	memset(&ss, 0, sizeof(ss));
	if (!addr[0] || !strcmp(addr, "localhost") ||
	    !strcmp(addr, "127.0.0.1")) {
		a4->sin_family = AF_INET;
		a4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else if (!strcmp(addr, "*") || !strcmp(addr, "0.0.0.0")) {
		a4->sin_family = AF_INET;
		a4->sin_addr.s_addr = htonl(INADDR_ANY);
	} else if (inet_pton(AF_INET, addr, &a4->sin_addr) == 1) {
		a4->sin_family = AF_INET;
	} else if (inet_pton(AF_INET6, addr, &a6->sin6_addr) == 1) {
		a6->sin6_family = AF_INET6;
	} else {
		return INVALID_SOCK;
	}
	if (ss.ss_family == AF_INET) {
		a4->sin_port = htons(port);
		sl = sizeof(*a4);
	} else {
		a6->sin6_port = htons(port);
		sl = sizeof(*a6);
	}
	fd = socket(ss.ss_family, SOCK_STREAM, 0);
	if (!sock_valid(fd))
		return INVALID_SOCK;
	sock_set_nonblock(fd);		/* SOCK_NONBLOCK is Linux-only */
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
	if (bind(fd, (struct sockaddr *)&ss, sl) || listen(fd, 8)) {
		sock_close(fd);
		return INVALID_SOCK;
	}
	sl = sizeof(ss);
	if (!getsockname(fd, (struct sockaddr *)&ss, &sl))
		*bound = ntohs(ss.ss_family == AF_INET ? a4->sin_port
							: a6->sin6_port);
	else
		*bound = port;
	return fd;
}

static struct fwd_bridge *bridge_slot(struct sshfwd *f)
{
	int i;

	for (i = 0; i < FWD_MAX_BRIDGE; i++)
		if (!f->br[i].used)
			return &f->br[i];
	return NULL;
}

static struct fwd_pend *pend_slot(struct sshfwd *f)
{
	int i;

	for (i = 0; i < FWD_MAX_PEND; i++)
		if (!f->pd[i].used)
			return &f->pd[i];
	return NULL;
}

/* Wire fd <-> chan with two connectors on the event. Takes ownership of
 * both; on failure closes and frees them. Returns 0 on success. */
static int bridge_up(struct sshfwd *f, sock_t fd, ssh_channel chan)
{
	struct fwd_bridge *b = bridge_slot(f);

	if (b) {
		b->in = ssh_connector_new(f->s);
		b->out = ssh_connector_new(f->s);
	}
	if (!b || !b->in || !b->out) {
		if (b && b->in)
			ssh_connector_free(b->in);
		if (b && b->out)
			ssh_connector_free(b->out);
		if (b)
			b->in = b->out = NULL;
		sock_close(fd);
		if (ssh_channel_is_open(chan))
			ssh_channel_close(chan);
		ssh_channel_free(chan);
		return -1;
	}
	sock_set_nonblock(fd);
	ssh_connector_set_in_fd(b->in, fd);
	ssh_connector_set_out_channel(b->in, chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_in_channel(b->out, chan, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_out_fd(b->out, fd);
	ssh_event_add_connector(f->ev, b->in);
	ssh_event_add_connector(f->ev, b->out);
	b->fd = fd;
	b->chan = chan;
	b->used = 1;
	return 0;
}

static void bridge_down(struct sshfwd *f, struct fwd_bridge *b)
{
	ssh_event_remove_connector(f->ev, b->in);
	ssh_event_remove_connector(f->ev, b->out);
	ssh_connector_free(b->in);
	ssh_connector_free(b->out);
	sock_close(b->fd);
	if (ssh_channel_is_open(b->chan))
		ssh_channel_close(b->chan);
	ssh_channel_free(b->chan);
	memset(b, 0, sizeof(*b));
}

struct sshfwd *sshfwd_create(ssh_session s, ssh_event ev)
{
	struct sshfwd *f = calloc(1, sizeof(*f));

	if (!f)
		return NULL;
	f->s = s;
	f->ev = ev;
	return f;
}

void sshfwd_destroy(struct sshfwd *f)
{
	int i;

	if (!f)
		return;
	for (i = 0; i < FWD_MAX_BRIDGE; i++)
		if (f->br[i].used)
			bridge_down(f, &f->br[i]);
	for (i = 0; i < FWD_MAX_LISTEN; i++)
		if (f->ls[i].used && sock_valid(f->ls[i].fd))
			sock_close(f->ls[i].fd);
	for (i = 0; i < FWD_MAX_PEND; i++) {
		struct fwd_pend *p = &f->pd[i];

		if (!p->used)
			continue;
		if (sock_valid(p->fd))
			sock_close(p->fd);
		if (p->msg) {
			ssh_message_reply_default(p->msg);
			ssh_message_free(p->msg);
		}
		if (p->chan)
			ssh_channel_free(p->chan);
	}
	free(f);
}

int sshfwd_cli_local(struct sshfwd *f, const struct fwdspec *sp)
{
	struct fwd_listener *l = NULL;
	int i;

	for (i = 0; i < FWD_MAX_LISTEN; i++)
		if (!f->ls[i].used) {
			l = &f->ls[i];
			break;
		}
	if (!l) {
		fprintf(stderr, "comrade: -L limit reached, ignoring %s:%u\n",
			sp->host, sp->port);
		return -1;
	}
	l->fd = listen_on(sp->bind, sp->bind_port, &l->port);
	if (!sock_valid(l->fd)) {
		fprintf(stderr, "comrade: -L could not listen on %s port %u\n",
			sp->bind[0] ? sp->bind : "localhost", sp->bind_port);
		return -1;
	}
	l->sp = *sp;
	l->is_remote = 0;
	l->used = 1;
	if (!sp->bind_port)
		fprintf(stderr, "comrade: -L listening on port %u\n", l->port);
	dbg_logf("sshfwd -L: port %u -> %s:%u", l->port, sp->host, sp->port);
	return 0;
}

int sshfwd_cli_remote(struct sshfwd *f, const struct fwdspec *sp)
{
	const char *addr = sp->bind[0] ? sp->bind : "localhost";
	int bound = 0, i;

	if (!strcmp(addr, "*"))
		addr = "";		/* RFC 4254: "" means every interface */
	if (ssh_channel_listen_forward(f->s, addr, sp->bind_port,
				       &bound) != SSH_OK) {
		fprintf(stderr, "comrade: -R refused by the host for %s port %u\n",
			sp->bind[0] ? sp->bind : "localhost", sp->bind_port);
		return -1;
	}
	if (!sp->bind_port)
		fprintf(stderr, "comrade: -R allocated port %d on the host\n",
			bound);
	/* Remember the target keyed by the host-side port, for accepts. */
	for (i = 0; i < FWD_MAX_LISTEN; i++)
		if (!f->ls[i].used) {
			f->ls[i].fd = INVALID_SOCK;
			f->ls[i].is_remote = 1;
			f->ls[i].sp = *sp;
			f->ls[i].port = (uint16_t)(bound ? bound : sp->bind_port);
			f->ls[i].used = 1;
			f->have_remote = 1;
			dbg_logf("sshfwd -R: host port %u -> %s:%u",
				 f->ls[i].port, sp->host, sp->port);
			return 0;
		}
	fprintf(stderr, "comrade: -R limit reached, ignoring %s:%u\n",
		sp->host, sp->port);
	return -1;
}

/* A connection accepted on a client -L listener: open the direct-tcpip
 * channel (blocks briefly for the host's reply) and bridge. */
static void cli_local_accept(struct sshfwd *f, struct fwd_listener *l)
{
	char orig[64];
	uint16_t oport;
	ssh_channel chan;
	sock_t fd = accept(l->fd, NULL, NULL);

	if (!sock_valid(fd))
		return;
	chan = ssh_channel_new(f->s);
	if (!chan) {
		sock_close(fd);
		return;
	}
	peer_name(fd, orig, sizeof(orig), &oport);
	if (ssh_channel_open_forward(chan, l->sp.host, l->sp.port,
				     orig, oport) != SSH_OK) {
		dbg_logf("sshfwd -L: host refused %s:%u",
			 l->sp.host, l->sp.port);
		sock_close(fd);
		ssh_channel_free(chan);
		return;
	}
	bridge_up(f, fd, chan);
}

/* A connection accepted on a host-side -R listener: open the reverse
 * (forwarded-tcpip) channel toward the client; completes in the tick loop
 * because the server session is non-blocking (SSH_AGAIN). */
static void srv_remote_accept(struct sshfwd *f, struct fwd_listener *l)
{
	struct fwd_pend *p;
	sock_t fd = accept(l->fd, NULL, NULL);

	if (!sock_valid(fd))
		return;
	p = pend_slot(f);
	if (!p) {
		sock_close(fd);
		return;
	}
	p->chan = ssh_channel_new(f->s);
	if (!p->chan) {
		sock_close(fd);
		return;
	}
	sock_set_nonblock(fd);
	p->kind = PEND_REV_OPEN;
	p->fd = fd;
	p->msg = NULL;
	snprintf(p->addr, sizeof(p->addr), "%s", l->req_addr);
	p->port = l->port;
	peer_name(fd, p->orig, sizeof(p->orig), &p->orig_port);
	p->deadline = fwd_now_ms() + FWD_CONNECT_TIMEOUT_MS;
	p->used = 1;
}

/* Progress one pending entry; returns 0 to keep it, non-zero when done. */
static int pend_step(struct sshfwd *f, struct fwd_pend *p)
{
	int rc;

	switch (p->kind) {
	case PEND_SRV_CONNECT:
		rc = finish_connect(p->fd);
		if (!rc && fwd_now_ms() < p->deadline)
			return 0;
		if (rc == 1) {
			ssh_channel chan =
				ssh_message_channel_request_open_reply_accept(p->msg);

			ssh_message_free(p->msg);
			p->msg = NULL;
			if (chan) {
				bridge_up(f, p->fd, chan);
				return 1;
			}
		} else {
			ssh_message_reply_default(p->msg);	/* open failure */
			ssh_message_free(p->msg);
			p->msg = NULL;
		}
		sock_close(p->fd);
		return 1;
	case PEND_CLI_CONNECT:
		rc = finish_connect(p->fd);
		if (!rc && fwd_now_ms() < p->deadline)
			return 0;
		if (rc == 1) {
			bridge_up(f, p->fd, p->chan);
			return 1;
		}
		dbg_logf("sshfwd -R: local target connect failed");
		sock_close(p->fd);
		if (ssh_channel_is_open(p->chan))
			ssh_channel_close(p->chan);
		ssh_channel_free(p->chan);
		return 1;
	case PEND_REV_OPEN:
		rc = ssh_channel_open_reverse_forward(p->chan, p->addr, p->port,
						      p->orig, p->orig_port);
		if (rc == SSH_AGAIN && fwd_now_ms() < p->deadline)
			return 0;
		if (rc == SSH_OK) {
			bridge_up(f, p->fd, p->chan);
			return 1;
		}
		sock_close(p->fd);
		ssh_channel_free(p->chan);
		return 1;
	}
	return 1;
}

void sshfwd_tick(struct sshfwd *f)
{
	int i;

	if (!f)
		return;

	/* Accept on local listeners (poll them ourselves, zero-timeout). */
	for (i = 0; i < FWD_MAX_LISTEN; i++) {
		struct fwd_listener *l = &f->ls[i];
		struct pollfd p;

		if (!l->used || !sock_valid(l->fd))
			continue;
		p.fd = l->fd;
		p.events = POLLIN;
		p.revents = 0;
		if (sock_poll(&p, 1, 0) > 0 &&
		    (p.revents & (POLLIN | POLLHUP | POLLERR))) {
			if (l->is_remote)
				srv_remote_accept(f, l);
			else
				cli_local_accept(f, l);
		}
	}

	/* Pick up host-accepted -R connections (client side). */
	if (f->have_remote) {
		for (;;) {
			int dport = 0, oport = 0;
			char *orig = NULL;
			ssh_channel chan = ssh_channel_open_forward_port(
						f->s, 0, &dport, &orig, &oport);
			struct fwd_pend *p;
			struct fwd_listener *l = NULL;

			if (!chan)
				break;
			if (orig)
				free(orig);
			for (i = 0; i < FWD_MAX_LISTEN; i++)
				if (f->ls[i].used && f->ls[i].is_remote &&
				    f->ls[i].port == (uint16_t)dport) {
					l = &f->ls[i];
					break;
				}
			p = l ? pend_slot(f) : NULL;
			if (p) {
				p->fd = start_connect(l->sp.host, l->sp.port);
				if (sock_valid(p->fd)) {
					p->kind = PEND_CLI_CONNECT;
					p->msg = NULL;
					p->chan = chan;
					p->deadline = fwd_now_ms() +
						      FWD_CONNECT_TIMEOUT_MS;
					p->used = 1;
					continue;
				}
			}
			if (ssh_channel_is_open(chan))
				ssh_channel_close(chan);
			ssh_channel_free(chan);
		}
	}

	/* Progress pending connects and reverse opens. */
	for (i = 0; i < FWD_MAX_PEND; i++)
		if (f->pd[i].used && pend_step(f, &f->pd[i]))
			memset(&f->pd[i], 0, sizeof(f->pd[i]));

	/* Reap bridges whose channel has ended and drained. */
	for (i = 0; i < FWD_MAX_BRIDGE; i++) {
		struct fwd_bridge *b = &f->br[i];

		if (b->used && (!ssh_channel_is_open(b->chan) ||
				(ssh_channel_is_eof(b->chan) &&
				 ssh_channel_poll(b->chan, 0) <= 0)))
			bridge_down(f, b);
	}
}

int sshfwd_srv_message(struct sshfwd *f, ssh_message m)
{
	int type, sub;

	if (!f)
		return 0;
	type = ssh_message_type(m);
	sub = ssh_message_subtype(m);

	/* direct-tcpip (-L): connect to the destination, replying once the
	 * connect resolves so a refused target is a refused channel open. */
	if (type == SSH_REQUEST_CHANNEL_OPEN && sub == SSH_CHANNEL_DIRECT_TCPIP) {
		const char *dest = ssh_message_channel_request_open_destination(m);
		int port = ssh_message_channel_request_open_destination_port(m);
		struct fwd_pend *p = pend_slot(f);

		if (!dest || port <= 0 || port > 65535 || !p) {
			ssh_message_reply_default(m);
			ssh_message_free(m);
			return 1;
		}
		p->fd = start_connect(dest, (uint16_t)port);
		if (!sock_valid(p->fd)) {
			ssh_message_reply_default(m);
			ssh_message_free(m);
			return 1;
		}
		dbg_logf("sshfwd srv: direct-tcpip to %s:%d", dest, port);
		p->kind = PEND_SRV_CONNECT;
		p->msg = m;
		p->chan = NULL;
		p->deadline = fwd_now_ms() + FWD_CONNECT_TIMEOUT_MS;
		p->used = 1;
		return 1;
	}

	/* tcpip-forward / cancel (-R): bind or drop a host-side listener. */
	if (type == SSH_REQUEST_GLOBAL &&
	    sub == SSH_GLOBAL_REQUEST_TCPIP_FORWARD) {
		const char *addr = ssh_message_global_request_address(m);
		int port = ssh_message_global_request_port(m);
		struct fwd_listener *l = NULL;
		int i;

		for (i = 0; i < FWD_MAX_LISTEN; i++)
			if (!f->ls[i].used) {
				l = &f->ls[i];
				break;
			}
		if (!l || !addr || port < 0 || port > 65535) {
			ssh_message_reply_default(m);
			ssh_message_free(m);
			return 1;
		}
		l->fd = listen_on(strcmp(addr, "localhost") ? addr : "",
				  (uint16_t)port, &l->port);
		if (!sock_valid(l->fd)) {
			ssh_message_reply_default(m);
			ssh_message_free(m);
			return 1;
		}
		snprintf(l->req_addr, sizeof(l->req_addr), "%s", addr);
		l->is_remote = 1;
		l->used = 1;
		dbg_logf("sshfwd srv: tcpip-forward %s port %u", addr, l->port);
		ssh_message_global_request_reply_success(m, l->port);
		ssh_message_free(m);
		return 1;
	}
	if (type == SSH_REQUEST_GLOBAL &&
	    sub == SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD) {
		int port = ssh_message_global_request_port(m);
		int i;

		for (i = 0; i < FWD_MAX_LISTEN; i++)
			if (f->ls[i].used && f->ls[i].is_remote &&
			    f->ls[i].port == port &&
			    sock_valid(f->ls[i].fd)) {
				sock_close(f->ls[i].fd);
				memset(&f->ls[i], 0, sizeof(f->ls[i]));
				ssh_message_global_request_reply_success(m, 0);
				ssh_message_free(m);
				return 1;
			}
		ssh_message_reply_default(m);
		ssh_message_free(m);
		return 1;
	}
	return 0;
}
