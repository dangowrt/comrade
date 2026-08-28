/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Sealing to a recipient (box_seal/box_open in keys.c). A claim in the mailbox
 * is read by every holder of the invitation, so what keeps a peer's addresses
 * private is that only the host holds the secret half. What must hold: the
 * host can open it, nobody else can, every byte is covered, and two boxes of
 * the same thing never look alike.
 */

#include <assert.h>
#include <string.h>

#include "ccrypto.h"
#include "keys.h"

int main(void)
{
	uint8_t hsk[32], hpk[32], osk[32], opk[32];
	uint8_t plain[256], box[256 + BOX_OVERHEAD], again[sizeof(box)];
	uint8_t out[sizeof(plain)], copy[sizeof(box)];
	size_t i;
	int n;

	assert(!random_bytes(hsk, sizeof(hsk)));
	assert(!random_bytes(osk, sizeof(osk)));
	assert(!cc_x25519_public(hpk, hsk));
	assert(!cc_x25519_public(opk, osk));
	for (i = 0; i < sizeof(plain); i++)
		plain[i] = (uint8_t)(i * 31 + 3);

	/* The host, and only the host, gets it back. */
	n = box_seal(box, sizeof(box), hpk, plain, sizeof(plain));
	assert(n == (int)(sizeof(plain) + BOX_OVERHEAD));
	assert(box_open(out, sizeof(out), hsk, box, (size_t)n) ==
	       (int)sizeof(plain));
	assert(!memcmp(out, plain, sizeof(plain)));

	/* Another guest holds an invitation, not the host's secret. */
	assert(box_open(out, sizeof(out), osk, box, (size_t)n) < 0);

	/* Every byte is covered: the ephemeral key, the tag, the ciphertext. */
	for (i = 0; i < (size_t)n; i += 13) {
		memcpy(copy, box, (size_t)n);
		copy[i] ^= 0x01;
		assert(box_open(out, sizeof(out), hsk, copy, (size_t)n) < 0);
	}

	/* Truncation, at every length. */
	for (i = 0; i < (size_t)n; i++)
		assert(box_open(out, sizeof(out), hsk, box, i) < 0);

	/*
	 * A fresh ephemeral every time, so two claims of the same description
	 * are not equal on the wire -- otherwise a watcher could tell a peer
	 * re-claiming from a new one arriving without opening anything.
	 */
	assert(box_seal(again, sizeof(again), hpk, plain, sizeof(plain)) == n);
	assert(memcmp(box, again, (size_t)n) != 0);
	assert(box_open(out, sizeof(out), hsk, again, (size_t)n) ==
	       (int)sizeof(plain));

	/* An empty payload is still a box, and still checked. */
	n = box_seal(box, sizeof(box), hpk, plain, 0);
	assert(n == BOX_OVERHEAD);
	assert(box_open(out, sizeof(out), hsk, box, (size_t)n) == 0);

	/* No room, no box. */
	assert(box_seal(box, BOX_OVERHEAD, hpk, plain, sizeof(plain)) < 0);
	return 0;
}
