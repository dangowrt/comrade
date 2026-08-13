/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SSHBRIDGE_H
#define COMRADE_SSHBRIDGE_H

#include <poll.h>
#include <stdint.h>

#include "stream.h"

/*
 * Couple a KCP byte stream to a local fd. The fd is one end of a socketpair
 * whose other end libssh reads and writes with ordinary blocking I/O in its
 * own thread; this side moves bytes between that fd and the KCP stream inside
 * the caller's poll loop. It owns neither the fd nor the stream.
 *
 * The KCP-to-fd direction is buffered so a slow reader on the fd applies
 * backpressure (we stop draining the stream) instead of losing data.
 */

struct sshbridge;

/*
 * linger_ms bounds how long, after our fd closes, we keep flushing the send
 * queue to deliver the trailing SSH close. It returns early once the peer acks,
 * so this only matters when the peer has stopped acking. The host wants it
 * generous, to land the close on the client over a lossy link; the client wants
 * it short, since its own closing bytes are non-critical (the session always
 * ends host-first) and a long wait for acks a departed host will never send
 * just stalls the client's exit.
 */
struct sshbridge *sshbridge_create(int fd, struct stream *s, uint32_t linger_ms);
void sshbridge_destroy(struct sshbridge *b);

int sshbridge_fd(const struct sshbridge *b);

/* Events to request on the fd for the next poll(). */
short sshbridge_events(const struct sshbridge *b);

/*
 * One non-blocking pass. revents is the poll result for the fd (0 if it was
 * not polled). Moves data both ways and advances KCP timing with now_ms.
 * Returns 0 while the session is live, -1 once the fd has closed and all
 * pending bytes have drained in both directions (the session is over).
 */
int sshbridge_pump(struct sshbridge *b, short revents, uint32_t now_ms);

#endif
