/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "sshbridge.h"

#define BRIDGE_BUF 65536

/*
 * Once our fd closes we keep the stream running to deliver whatever is still
 * queued, but only for this long. Waiting for a full acknowledgement is not
 * safe: the peer may already be tearing down and no longer acking, which
 * would hang us forever on the trailing disconnect bytes. A live peer drains
 * the send queue well within this window, so real terminal output is not lost.
 */
#define BRIDGE_LINGER_MS 1000

struct sshbridge {
	int fd;
	struct stream *s;
	int fd_eof;		/* read side saw EOF or the fd is dead */
	int dead;		/* fatal fd error: stop */
	int linger_set;
	uint32_t linger_at;	/* monotonic ms when fd_eof was first seen */
	size_t out_len;		/* bytes pulled from the stream, awaiting write */
	size_t out_pos;
	uint8_t out[BRIDGE_BUF];
};

struct sshbridge *sshbridge_create(int fd, struct stream *s)
{
	struct sshbridge *b;
	int fl;

	if (fd < 0 || !s)
		return NULL;
	b = calloc(1, sizeof(*b));
	if (!b)
		return NULL;
	b->fd = fd;
	b->s = s;
	fl = fcntl(fd, F_GETFL, 0);
	if (fl >= 0)
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
	return b;
}

void sshbridge_destroy(struct sshbridge *b)
{
	free(b);
}

int sshbridge_fd(const struct sshbridge *b)
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
		ssize_t n = read(b->fd, buf, sizeof(buf));

		if (n > 0) {
			stream_send(b->s, buf, (size_t)n);
			continue;
		}
		if (n == 0) {
			b->fd_eof = 1;
			return;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		if (errno == EINTR)
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
			ssize_t n = write(b->fd, b->out + b->out_pos,
					  b->out_len - b->out_pos);

			if (n > 0) {
				b->out_pos += (size_t)n;
				continue;
			}
			if (n < 0 && errno == EINTR)
				continue;
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
				return;
			/* EPIPE etc: the reader is gone. */
			b->dead = 1;
			return;
		}
	}
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
		if (!b->linger_set) {
			b->linger_set = 1;
			b->linger_at = now_ms;
		}
		if (stream_waitsnd(b->s) == 0 ||
		    (uint32_t)(now_ms - b->linger_at) >= BRIDGE_LINGER_MS)
			return -1;
	}
	return 0;
}
