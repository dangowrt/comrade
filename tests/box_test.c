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
#include <stdio.h>
#include <string.h>

#include "ccrypto.h"
#include "keys.h"

static void unhex(uint8_t *out, const char *hex, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		unsigned v;

		sscanf(hex + i * 2, "%2x", &v);
		out[i] = (uint8_t)v;
	}
}

/*
 * RFC 7748 section 6.1. Three backends implement this and two peers need not
 * share one, so agreement with the standard -- not merely with itself -- is
 * what makes a box sealed by one openable by another.
 */
static void rfc7748_check(void)
{
	uint8_t ask[32], apk[32], bsk[32], bpk[32], got[32], want[32];

	unhex(ask, "77076d0a7318a57d3c16c17251b26645"
		   "df4c2f87ebc0992ab177fba51db92c2a", 32);
	unhex(bsk, "5dab087e624a8a4b79e17f8b83800ee6"
		   "6f3bb1292618b6fd1c2f8b27ff88e0eb", 32);
	unhex(want, "4a5d9d5ba4ce2de1728e3bf480350f25"
		    "e07e21c947d19e3376f09b3c1e161742", 32);

	assert(!cc_x25519_public(apk, ask));
	assert(!cc_x25519_public(bpk, bsk));
	unhex(got, "8520f0098930a754748b7ddcb43ef75a"
		   "0dbf3a0d26381af4eba4a98eaa9b4e6a", 32);
	assert(!memcmp(apk, got, 32));
	unhex(got, "de9edb7d7b7dc1b4d35b61c2ece43537"
		   "3f8343c85b78674dadfc7e146f882b4f", 32);
	assert(!memcmp(bpk, got, 32));

	/* Both directions reach the same secret, which is the whole point. */
	assert(!cc_x25519(got, ask, bpk));
	assert(!memcmp(got, want, 32));
	assert(!cc_x25519(got, bsk, apk));
	assert(!memcmp(got, want, 32));
}

int main(void)
{
	uint8_t hsk[32], hpk[32], osk[32], opk[32];
	uint8_t plain[256], box[256 + BOX_OVERHEAD], again[sizeof(box)];
	uint8_t out[sizeof(plain)], copy[sizeof(box)];
	size_t i;
	int n;

	rfc7748_check();

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
