/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <sys/random.h>
#endif

#include "ccrypto.h"
#include "keys.h"

/*
 * Randomness straight from the kernel, no library RNG in between. Linux
 * spells that getrandom(2); macOS has only getentropy(2), which is the same
 * syscall-direct guarantee but refuses more than 256 bytes at a time, hence
 * the chunking. Every caller here asks for far less than that.
 *
 * Windows' equivalent is BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG,
 * which draws from the same kernel CSPRNG without opening a provider handle or
 * linking a crypto library -- bcrypt.dll is a system DLL and libjuice already
 * imports it.
 */
int random_bytes(void *buf, size_t len)
{
	uint8_t *p = buf;

#ifdef _WIN32
	while (len) {
		ULONG n = len > 0x10000 ? 0x10000 : (ULONG)len;

		if (BCryptGenRandom(NULL, p, n,
				    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
			return -1;
		p += n;
		len -= n;
	}
	return 0;
#else
	while (len) {
#ifdef __APPLE__
		size_t n = len > 256 ? 256 : len;

		if (getentropy(p, n))
			return -1;
#else
		ssize_t rc = getrandom(p, len, 0);
		size_t n;

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n = (size_t)rc;
#endif
		p += n;
		len -= n;
	}
	return 0;
#endif
}

int keys_derive(struct session_keys *keys, const uint8_t rdv[TOKEN_RDV_LEN])
{
	static const char sig_info[] = "comrade1 sig key";
	static const char seed_info[] = "comrade1 bep44 seed";
	uint8_t seed[32];

	cc_blake2b_keyed(keys->sig_key, sizeof(keys->sig_key),
			 rdv, TOKEN_RDV_LEN,
			 (const uint8_t *)sig_info, sizeof(sig_info) - 1);
	cc_blake2b_keyed(seed, sizeof(seed), rdv, TOKEN_RDV_LEN,
			 (const uint8_t *)seed_info, sizeof(seed_info) - 1);
	return cc_ed25519_key_pair(keys->bep44_sk, keys->bep44_pk, seed);
}

int msg_seal(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *plain, size_t plain_len)
{
	if (dst_len < plain_len + SEAL_OVERHEAD)
		return -1;
	if (random_bytes(dst, 24))
		return -1;
	if (cc_aead_lock(dst + 40, dst + 24, key, dst, NULL, 0,
			 plain, plain_len))
		return -1;
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
	if (cc_aead_unlock(dst, sealed + 24, key, sealed, NULL, 0,
			   sealed + 40, plain_len))
		return -1;
	return (int)plain_len;
}
