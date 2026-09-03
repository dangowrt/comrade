/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * What the bridge does after its fd closes, with nobody listening.
 *
 * The flush that follows exists to land the trailing SSH close on a peer that
 * is there and slow. A peer that has GONE acks nothing at all, and waiting the
 * whole budget out for one was five seconds in which a host went on showing a
 * guest that had already left -- measured, on a real pair, as exactly the
 * host's linger.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "sshbridge.h"
#include "stream.h"

#define LINGER_MS 5000

/* A peer that has gone: what we send leaves and nothing ever comes back. */
static int sink(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	(void)data;
	return (int)len;
}

/* Drive the bridge on a hand-run clock until it says the session is over. */
static uint32_t flush_took(uint32_t linger_ms)
{
	uint8_t payload[4096];
	struct stream *s = stream_create(1, sink, NULL);
	struct sshbridge *b;
	int sp[2], eof_at = -1;
	uint32_t t;

	assert(s);
	assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	b = sshbridge_create(sp[0], s, linger_ms);
	assert(b);

	/* Something still to flush, and then our end goes -- which is a
	 * client's exit as the other end of the bridge sees it. */
	memset(payload, 'x', sizeof(payload));
	assert(write(sp[1], payload, sizeof(payload)) > 0);
	close(sp[1]);

	for (t = 0; t < 60000; t += 10) {
		if (sshbridge_pump(b, POLLIN, t) < 0) {
			eof_at = (int)t;
			break;
		}
	}
	sshbridge_destroy(b);
	stream_destroy(s);
	close(sp[0]);
	assert(eof_at >= 0);		/* it has to end */
	return (uint32_t)eof_at;
}

int main(void)
{
	uint32_t took = flush_took(LINGER_MS);

	/*
	 * Bounded by the queue standing still, not by the budget. The budget
	 * is the ceiling for a slow peer; nothing here is slow, it is absent.
	 */
	assert(took < LINGER_MS);
	assert(took <= LINGER_MS / 4);

	/* And the budget is still the ceiling: a shorter one ends sooner. */
	assert(flush_took(200) <= 200);

	printf("sshbridge: a flush to a peer that has gone ends in %ums, "
	       "not the %ums budget\n", (unsigned)took, (unsigned)LINGER_MS);
	return 0;
}
