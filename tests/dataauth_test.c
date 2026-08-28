/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Origin for stream datagrams (dataauth.c). SSH inside KCP means the bytes are
 * already unreadable on the path; the tag is what says the far end of this
 * connection sent them, so what matters here is that it refuses everything it
 * did not produce -- a changed byte anywhere, a changed counter, a tag from
 * another key, a truncation -- and that the counter survives the round trip,
 * since the replay window above it has nothing else to judge.
 */

#include <assert.h>
#include <string.h>

#include "dataauth.h"

int main(void)
{
	uint8_t key[32], other[32];
	uint8_t body[512], wire[512 + DATAAUTH_OVERHEAD], copy[sizeof(wire)];
	size_t n, got;
	uint64_t seq;
	size_t i;

	for (i = 0; i < sizeof(key); i++) {
		key[i] = (uint8_t)(i * 3 + 7);
		other[i] = (uint8_t)(i * 3 + 8);
	}
	for (i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)(i * 17);

	/* Round trip: the body comes back untouched and in place, and the
	 * counter with it. */
	n = dataauth_wrap(wire, sizeof(wire), key, body, sizeof(body),
			  0x0123456789abcdefULL);
	assert(n == sizeof(body) + DATAAUTH_OVERHEAD);
	assert(!dataauth_open(key, wire, n, &got, &seq));
	assert(got == sizeof(body));
	assert(seq == 0x0123456789abcdefULL);
	assert(!memcmp(wire, body, sizeof(body)));

	/* A tag from another key is not this connection's. */
	assert(dataauth_open(other, wire, n, &got, &seq) != 0);

	/* Any byte of the body, the counter or the tag itself. */
	for (i = 0; i < n; i += 37) {
		memcpy(copy, wire, n);
		copy[i] ^= 0x01;
		assert(dataauth_open(key, copy, n, &got, &seq) != 0);
	}
	memcpy(copy, wire, n);
	copy[n - 1] ^= 0x80;			/* the last byte of the tag */
	assert(dataauth_open(key, copy, n, &got, &seq) != 0);
	memcpy(copy, wire, n);
	copy[sizeof(body)] ^= 0x01;		/* the top byte of the counter */
	assert(dataauth_open(key, copy, n, &got, &seq) != 0);

	/* Truncation, down to nothing: never a body length that underflows. */
	for (i = 0; i < n; i++)
		assert(dataauth_open(key, wire, i, &got, &seq) != 0);

	/* An empty datagram is still framed and still checked. */
	n = dataauth_wrap(wire, sizeof(wire), key, body, 0, 1);
	assert(n == DATAAUTH_OVERHEAD);
	assert(!dataauth_open(key, wire, n, &got, &seq));
	assert(got == 0 && seq == 1);

	/* No room, no frame. */
	assert(dataauth_wrap(wire, DATAAUTH_OVERHEAD, key, body,
			     sizeof(body), 1) == 0);
	return 0;
}
