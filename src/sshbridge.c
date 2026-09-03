/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdlib.h>

#include "sshbridge.h"

#define BRIDGE_BUF 65536

struct sshbridge {
	sock_t fd;
	struct stream *s;
	int fd_eof;		/* read side saw EOF or the fd is dead */
	int dead;		/* fatal fd error: stop */
	int linger_set;
	uint32_t linger_ms;	/* how long to flush after fd_eof (see header) */
	uint32_t linger_at;	/* monotonic ms when fd_eof was first seen */
	uint32_t linger_move;	/* and when the queue last got shorter */
	int linger_q;		/* how long it was then */
	size_t out_len;		/* bytes pulled from the stream, awaiting write */
	size_t out_pos;
	uint8_t out[BRIDGE_BUF];
};

struct sshbridge *sshbridge_create(sock_t fd, struct stream *s,
				   uint32_t linger_ms)
{
	struct sshbridge *b;

	if (!sock_valid(fd) || !s)
		return NULL;
	b = calloc(1, sizeof(*b));
	if (!b)
		return NULL;
	b->fd = fd;
	b->s = s;
	b->linger_ms = linger_ms;
	sock_set_nonblock(fd);
	return b;
}

void sshbridge_destroy(struct sshbridge *b)
{
	free(b);
}

sock_t sshbridge_fd(const struct sshbridge *b)
{
	return b->fd;
}

short sshbridge_events(const struct sshbridge *b)
{
	short ev = 0;

	if (!b->fd_eof && !b->dead)
		ev |= POLLIN;
	if (b->out_pos < b->out_len)
		ev |= POLLOUT;
	return ev;
}

/* Drain the fd into the stream. */
static void pump_in(struct sshbridge *b)
{
	uint8_t buf[BRIDGE_BUF];

	for (;;) {
		ssize_t n = sock_read(b->fd, buf, sizeof(buf));
		int e;

		if (n > 0) {
			stream_send(b->s, buf, (size_t)n);
			continue;
		}
		if (n == 0) {
			b->fd_eof = 1;
			return;
		}
		e = sock_errno();
		if (sock_err_would_block(e))
			return;
		if (sock_err_intr(e))
			continue;
		b->dead = 1;
		return;
	}
}

/* Move stream data out to the fd, buffering across would-blocks. */
static void pump_out(struct sshbridge *b)
{
	for (;;) {
		if (b->out_pos == b->out_len) {
			int n = stream_recv(b->s, b->out, sizeof(b->out));

			if (n <= 0)
				return;
			b->out_pos = 0;
			b->out_len = (size_t)n;
		}
		while (b->out_pos < b->out_len) {
			ssize_t n = sock_write(b->fd, b->out + b->out_pos,
					       b->out_len - b->out_pos);
			int e;

			if (n > 0) {
				b->out_pos += (size_t)n;
				continue;
			}
			e = sock_errno();
			if (n < 0 && sock_err_intr(e))
				continue;
			if (n < 0 && sock_err_would_block(e))
				return;
			/* EPIPE / WSAECONNRESET etc: the reader is gone. */
			b->dead = 1;
			return;
		}
	}
}

/*
 * How long to go on flushing with the queue not moving at all.
 *
 * The budget in linger_ms is for a peer that is THERE and slow -- a lossy link
 * that needs the trailing close repeating. A peer that has gone acks nothing
 * whatsoever, and spending the whole budget on it is dead time the other end
 * sees as a guest that has left still sitting in its list.
 *
 * A few round trips tells the two apart, since a peer that is there acks
 * something inside one. Where no round trip has been measured yet, a tenth of
 * a second stands in for it; the budget is still the ceiling either way.
 */
static uint32_t stall_ms(const struct sshbridge *b)
{
	int rtt = stream_rtt(b->s);
	uint32_t ms = (uint32_t)(rtt > 0 ? rtt : 100) * 4;

	return ms > b->linger_ms ? b->linger_ms : ms;
}

int sshbridge_pump(struct sshbridge *b, short revents, uint32_t now_ms)
{
	/*
	 * While our fd is live, move data both ways. Once it has closed there
	 * is nothing left to read from it and writing to it would fault, so we
	 * only keep the stream ticking to flush the send queue.
	 */
	if (!b->fd_eof) {
		if (revents & (POLLIN | POLLHUP | POLLERR))
			pump_in(b);
		pump_out(b);
	}
	stream_update(b->s, now_ms);

	if (b->dead)
		return -1;
	if (b->fd_eof) {
		int q = stream_waitsnd(b->s);

		if (!b->linger_set) {
			b->linger_set = 1;
			b->linger_at = now_ms;
			b->linger_move = now_ms;
			b->linger_q = q;
		}
		if (q < b->linger_q) {		/* acked: the peer is there */
			b->linger_q = q;
			b->linger_move = now_ms;
		}
		if (q == 0 ||
		    (uint32_t)(now_ms - b->linger_at) >= b->linger_ms ||
		    (uint32_t)(now_ms - b->linger_move) >= stall_ms(b))
			return -1;
	}
	return 0;
}
