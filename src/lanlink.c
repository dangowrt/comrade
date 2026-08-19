/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#define _GNU_SOURCE
#include "wsock.h"
#include <stdlib.h>
#include <string.h>

#include "lanlink.h"

/*
 * A datagram we sent that bounced (an ICMP port-unreachable, reported by the
 * next receive) must not end the drain and strand the datagrams behind it, but
 * an error that never clears must not spin the loop that owns the session
 * either. Bound the run, and let the next poll pick up whatever is left.
 */
#define DRAIN_MAX_ERRS 16

struct lanlink {
	sock_t fd;			/* dual-stack v6 UDP socket, shared */
	uint16_t port;
	lanlink_recv_cb *on_recv;
	void *arg;
};

struct lanlink *lanlink_create(lanlink_recv_cb *on_recv, void *arg,
			       uint16_t port)
{
	struct lanlink *l = calloc(1, sizeof(*l));
	struct sockaddr_in6 a;
	socklen_t alen = sizeof(a);
	int off = 0;

	if (!l)
		return NULL;
	if (wsock_init()) {
		free(l);
		return NULL;
	}
	l->fd = INVALID_SOCK;		/* calloc's 0 is a legal SOCKET value */
	l->on_recv = on_recv;
	l->arg = arg;
	l->fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!sock_valid(l->fd))
		goto fail;
	if (sock_udp_disable_connreset(l->fd))
		goto fail;
	/* Dual stack: one socket carries both v6 (incl. link-local) and, as
	 * v4-mapped, v4. */
	setsockopt(l->fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off,
		   sizeof(off));
	memset(&a, 0, sizeof(a));
	a.sin6_family = AF_INET6;
	a.sin6_addr = in6addr_any;
	a.sin6_port = htons(port);
	if (bind(l->fd, (struct sockaddr *)&a, sizeof(a))) {
		/* The requested fixed port is taken: fall back to ephemeral and
		 * let the caller re-mint the token with the new port. */
		if (!port)
			goto fail;
		a.sin6_port = 0;
		if (bind(l->fd, (struct sockaddr *)&a, sizeof(a)))
			goto fail;
	}
	if (getsockname(l->fd, (struct sockaddr *)&a, &alen))
		goto fail;
	l->port = ntohs(a.sin6_port);
	sock_set_nonblock(l->fd);
	return l;
fail:
	lanlink_destroy(l);
	return NULL;
}

void lanlink_destroy(struct lanlink *l)
{
	if (!l)
		return;
	if (sock_valid(l->fd))
		sock_close(l->fd);
	free(l);
}

uint16_t lanlink_port(struct lanlink *l)
{
	return l->port;
}

int lanlink_map_peer(const struct sockaddr *sa, socklen_t len,
		     struct sockaddr_in6 *out)
{
	memset(out, 0, sizeof(*out));
	out->sin6_family = AF_INET6;
	if (sa->sa_family == AF_INET6) {
		if (len < (socklen_t)sizeof(struct sockaddr_in6))
			return -1;
		*out = *(const struct sockaddr_in6 *)sa;
	} else if (sa->sa_family == AF_INET) {
		/* Map a v4 peer into the dual-stack socket: ::ffff:a.b.c.d */
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;

		if (len < (socklen_t)sizeof(struct sockaddr_in))
			return -1;
		out->sin6_port = s4->sin_port;
		out->sin6_addr.s6_addr[10] = 0xff;
		out->sin6_addr.s6_addr[11] = 0xff;
		memcpy(&out->sin6_addr.s6_addr[12], &s4->sin_addr, 4);
	} else {
		return -1;
	}
	return 0;
}

int lanlink_prepare(struct lanlink *l, struct pollfd *fds, int maxfds,
		    int *timeout_ms)
{
	(void)timeout_ms;
	if (maxfds < 1)
		return 0;
	fds[0].fd = l->fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	return 1;
}

void lanlink_dispatch(struct lanlink *l, const struct pollfd *fds, int nfds)
{
	uint8_t buf[2048];
	int i, errs;

	for (i = 0; i < nfds; i++) {
		/* POLLHUP/POLLERR arrive without POLLIN under WSAPoll, so they
		 * are drained here rather than ignored (see wsock.h). */
		if (fds[i].fd != l->fd ||
		    !(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
			continue;
		for (errs = 0; errs < DRAIN_MAX_ERRS; ) {
			struct sockaddr_storage src;
			socklen_t srclen = sizeof(src);
			int rc = recvfrom(l->fd, (char *)buf, (int)sizeof(buf), 0,
					  (struct sockaddr *)&src, &srclen);

			if (rc < 0) {
				if (sock_err_would_block(sock_errno()))
					break;
				errs++;		/* a bounced datagram; keep draining */
				continue;
			}
			if (rc == 0)
				continue;
			if (l->on_recv)
				l->on_recv(l->arg, (struct sockaddr *)&src,
					   srclen, buf, (size_t)rc);
		}
	}
}

int lanlink_send(struct lanlink *l, const struct sockaddr_in6 *peer,
		 const uint8_t *data, size_t len)
{
	if (sendto(l->fd, (const char *)data, (int)len, 0,
		   (const struct sockaddr *)peer, sizeof(*peer)) < 0)
		return -1;
	return 0;
}
