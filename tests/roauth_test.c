/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The read-only auth secret is a one-way keyed derivation of the read-write
 * one (keys_derive_ro_auth). The host holds only the read-write secret and
 * derives the read-only twin on demand -- to mint the read-only token and to
 * accept it at the door -- so this must be deterministic, distinct from its
 * input, and avalanche-sensitive (no bit of the read-write secret leaks
 * through unchanged, which is what stops a read-only guest walking it back).
 */

#include <assert.h>
#include <string.h>

#include "keys.h"
#include "token.h"

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
	uint8_t rw[TOKEN_AUTH_LEN], rw2[TOKEN_AUTH_LEN];
	uint8_t ro[TOKEN_AUTH_LEN], ro_again[TOKEN_AUTH_LEN], ro2[TOKEN_AUTH_LEN];
	size_t i;

	for (i = 0; i < TOKEN_AUTH_LEN; i++)
		rw[i] = (uint8_t)(i * 13 + 5);

	/* Deterministic: the host derives the same read-only secret every time
	 * it mints or checks, on both endpoints. */
	keys_derive_ro_auth(ro, rw);
	keys_derive_ro_auth(ro_again, rw);
	assert(!memcmp(ro, ro_again, TOKEN_AUTH_LEN));

	/* Distinct from the read-write secret: a read-only token never simply
	 * carries the read-write password. */
	assert(memcmp(ro, rw, TOKEN_AUTH_LEN) != 0);

	/* Avalanche: flipping one bit of the read-write secret changes roughly
	 * half of the read-only secret's bits, so nothing passes through
	 * untouched. A single flip changing under a fifth of the output bits
	 * would betray a weak (near-linear) relation; a real keyed hash sits
	 * near half. */
	memcpy(rw2, rw, TOKEN_AUTH_LEN);
	rw2[0] ^= 0x01;
	keys_derive_ro_auth(ro2, rw2);
	assert(memcmp(ro2, ro, TOKEN_AUTH_LEN) != 0);
	assert(popcount_diff(ro, ro2, TOKEN_AUTH_LEN) > TOKEN_AUTH_LEN * 8 / 5);

	return 0;
}
