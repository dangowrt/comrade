/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The per-connection probe key (keys_conn_key). Both ends derive it from the
 * session key and a random half each, traded inside the SSH session, so it
 * must come out the same on both without either end deciding the order -- and
 * it must depend on every input, or a third holder of the invitation could
 * reach a connection it is not part of.
 */

#include <assert.h>
#include <string.h>

#include "keys.h"

static int popcount_diff(const uint8_t *a, const uint8_t *b, size_t n)
{
	size_t i;
	int bits = 0;

	for (i = 0; i < n; i++) {
		uint8_t x = (uint8_t)(a[i] ^ b[i]);

		while (x) {
			bits += x & 1;
			x = (uint8_t)(x >> 1);
		}
	}
	return bits;
}

int main(void)
{
	uint8_t sig[32], sig2[32];
	uint8_t a[KEYS_HALF_LEN], b[KEYS_HALF_LEN], c[KEYS_HALF_LEN];
	uint8_t k[32], k_again[32], k_swapped[32], k2[32];
	size_t i;

	for (i = 0; i < 32; i++) {
		sig[i] = (uint8_t)(i * 7 + 1);
		a[i] = (uint8_t)(i * 11 + 3);
		b[i] = (uint8_t)(i * 5 + 200);	/* sorts either side of a */
	}

	/* Deterministic. */
	keys_conn_key(k, sig, a, b);
	keys_conn_key(k_again, sig, a, b);
	assert(!memcmp(k, k_again, sizeof(k)));

	/*
	 * Order-free: the host and the client each hold "mine" and "theirs" in
	 * the opposite order, and neither is told which is which. Both must
	 * still arrive at one key.
	 */
	keys_conn_key(k_swapped, sig, b, a);
	assert(!memcmp(k, k_swapped, sizeof(k)));

	/* Not the session key, which every holder of the invitation has. */
	assert(memcmp(k, sig, sizeof(k)) != 0);

	/* A different session key gives a different connection key, so one
	 * invitation's traffic never opens under another's. */
	memcpy(sig2, sig, sizeof(sig));
	sig2[0] ^= 0x01;
	keys_conn_key(k2, sig2, a, b);
	assert(popcount_diff(k, k2, sizeof(k)) > (int)sizeof(k) * 8 / 5);

	/*
	 * And on each half: a guest who learns one half, or replays an old
	 * one, still does not have the key. Both halves are checked, since a
	 * derivation that ignored one would leave that end's contribution
	 * worthless.
	 */
	memcpy(c, a, sizeof(a));
	c[0] ^= 0x01;
	keys_conn_key(k2, sig, c, b);
	assert(popcount_diff(k, k2, sizeof(k)) > (int)sizeof(k) * 8 / 5);

	memcpy(c, b, sizeof(b));
	c[0] ^= 0x01;
	keys_conn_key(k2, sig, a, c);
	assert(popcount_diff(k, k2, sizeof(k)) > (int)sizeof(k) * 8 / 5);

	return 0;
}
