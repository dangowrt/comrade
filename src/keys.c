/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>
#include <sys/random.h>

#include <monocypher.h>
#include <monocypher-ed25519.h>

#include "keys.h"

int random_bytes(void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len) {
		ssize_t n = getrandom(p, len, 0);

		if (n < 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

void keys_derive(struct session_keys *keys, const uint8_t rdv[TOKEN_RDV_LEN])
{
	static const char sig_info[] = "comrade1 sig key";
	static const char seed_info[] = "comrade1 bep44 seed";
	uint8_t seed[32];

	crypto_blake2b_keyed(keys->sig_key, sizeof(keys->sig_key),
			     rdv, TOKEN_RDV_LEN,
			     (const uint8_t *)sig_info, sizeof(sig_info) - 1);
	crypto_blake2b_keyed(seed, sizeof(seed), rdv, TOKEN_RDV_LEN,
			     (const uint8_t *)seed_info, sizeof(seed_info) - 1);
	crypto_ed25519_key_pair(keys->bep44_sk, keys->bep44_pk, seed);
}

int msg_seal(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *plain, size_t plain_len)
{
	if (dst_len < plain_len + SEAL_OVERHEAD)
		return -1;
	if (random_bytes(dst, 24))
		return -1;
	crypto_aead_lock(dst + 40, dst + 24, key, dst, NULL, 0,
			 plain, plain_len);
	return (int)(plain_len + SEAL_OVERHEAD);
}

int msg_open(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *sealed, size_t sealed_len)
{
	size_t plain_len;

	if (sealed_len < SEAL_OVERHEAD)
		return -1;
	plain_len = sealed_len - SEAL_OVERHEAD;
	if (dst_len < plain_len)
		return -1;
	if (crypto_aead_unlock(dst, sealed + 24, key, sealed, NULL, 0,
			       sealed + 40, plain_len))
		return -1;
	return (int)plain_len;
}
