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
/* The box key: the agreement, bound to both public keys so one ephemeral can
 * never produce the same key for two recipients. */
static void box_key(uint8_t key[32], const uint8_t shared[32],
		    const uint8_t epk[32], const uint8_t pk[32])
{
	static const char info[] = "comrade1 claim box";
	uint8_t buf[sizeof(info) - 1 + 64];

	memcpy(buf, info, sizeof(info) - 1);
	memcpy(buf + sizeof(info) - 1, epk, 32);
	memcpy(buf + sizeof(info) - 1 + 32, pk, 32);
	cc_blake2b_keyed(key, 32, shared, 32, buf, sizeof(buf));
}

int box_seal(uint8_t *dst, size_t dst_len, const uint8_t pk[32],
	     const uint8_t *plain, size_t plain_len)
{
	uint8_t esk[32], epk[32], shared[32], key[32];
	static const uint8_t nonce[24];		/* the key is used once */
	int rc = -1;

	if (dst_len < plain_len + BOX_OVERHEAD)
		return -1;
	if (random_bytes(esk, sizeof(esk)))
		return -1;
	if (cc_x25519_public(epk, esk) || cc_x25519(shared, esk, pk))
		goto out;
	box_key(key, shared, epk, pk);
	memcpy(dst, epk, 32);
	if (cc_aead_lock(dst + BOX_OVERHEAD, dst + 32, key, nonce, epk, 32,
			 plain, plain_len))
		goto out;
	rc = (int)(plain_len + BOX_OVERHEAD);
out:
	memset(esk, 0, sizeof(esk));
	memset(shared, 0, sizeof(shared));
	memset(key, 0, sizeof(key));
	return rc;
}

int box_open(uint8_t *dst, size_t dst_len, const uint8_t sk[32],
	     const uint8_t *sealed, size_t sealed_len)
{
	uint8_t pk[32], shared[32], key[32];
	static const uint8_t nonce[24];
	size_t n;
	int rc = -1;

	if (sealed_len < BOX_OVERHEAD)
		return -1;
	n = sealed_len - BOX_OVERHEAD;
	if (dst_len < n)
		return -1;
	if (cc_x25519_public(pk, sk) || cc_x25519(shared, sk, sealed))
		goto out;
	box_key(key, shared, sealed, pk);
	if (cc_aead_unlock(dst, sealed + 32, key, nonce, sealed, 32,
			   sealed + BOX_OVERHEAD, n))
		goto out;
	rc = (int)n;
out:
	memset(shared, 0, sizeof(shared));
	memset(key, 0, sizeof(key));
	return rc;
}

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
	static const char wire_info[] = "comrade1 wire tags";
	uint8_t seed[32];
	uint8_t tags[8];
	int i;

	cc_blake2b_keyed(keys->sig_key, sizeof(keys->sig_key),
			 rdv, TOKEN_RDV_LEN,
			 (const uint8_t *)sig_info, sizeof(sig_info) - 1);
	cc_blake2b_keyed(seed, sizeof(seed), rdv, TOKEN_RDV_LEN,
			 (const uint8_t *)seed_info, sizeof(seed_info) - 1);
	cc_blake2b_keyed(tags, sizeof(tags), rdv, TOKEN_RDV_LEN,
			 (const uint8_t *)wire_info, sizeof(wire_info) - 1);
	keys->probe_magic = 0;
	keys->conv = 0;
	for (i = 0; i < 4; i++) {
		keys->probe_magic = (keys->probe_magic << 8) | tags[i];
		keys->conv = (keys->conv << 8) | tags[4 + i];
	}
	/*
	 * The demux tells a probe from stream data by this one compare, so the
	 * two must differ; derived values agree only by chance, and chance is
	 * not a thing to leave in a parser.
	 */
	if (keys->probe_magic == keys->conv)
		keys->conv ^= 0x5f5f5f5fU;
	return cc_ed25519_key_pair(keys->bep44_sk, keys->bep44_pk, seed);
}

/* The read-only auth secret is a one-way derivation of the read-write one
 * (keyed BLAKE2b under the read-write secret). A host that holds only the
 * read-write secret can mint and accept the read-only credential, while a
 * read-only guest can never walk this back to the read-write secret it was
 * cut from, so handing it out grants observation without control. */
void keys_conn_key(uint8_t out[32], const uint8_t sig_key[32],
		   const uint8_t a[KEYS_HALF_LEN],
		   const uint8_t b[KEYS_HALF_LEN])
{
	static const char info[] = "comrade1 conn key";
	uint8_t buf[sizeof(info) - 1 + 2 * KEYS_HALF_LEN];
	const uint8_t *lo = memcmp(a, b, KEYS_HALF_LEN) <= 0 ? a : b;
	const uint8_t *hi = lo == a ? b : a;

	memcpy(buf, info, sizeof(info) - 1);
	memcpy(buf + sizeof(info) - 1, lo, KEYS_HALF_LEN);
	memcpy(buf + sizeof(info) - 1 + KEYS_HALF_LEN, hi, KEYS_HALF_LEN);
	cc_blake2b_keyed(out, 32, sig_key, 32, buf, sizeof(buf));
}

void keys_derive_ro_auth(uint8_t ro[TOKEN_AUTH_LEN],
			 const uint8_t rw[TOKEN_AUTH_LEN])
{
	static const char ro_info[] = "comrade1 ro token";
	uint8_t full[32];

	/* BLAKE2b exists only at whole standard digest sizes under gcrypt, so
	 * derive the 32-byte hash every backend agrees on and take its first
	 * TOKEN_AUTH_LEN bytes rather than asking for a 16-byte digest direct. */
	cc_blake2b_keyed(full, sizeof(full), rw, TOKEN_AUTH_LEN,
			 (const uint8_t *)ro_info, sizeof(ro_info) - 1);
	memcpy(ro, full, TOKEN_AUTH_LEN);
}

int msg_seal_ad(uint8_t *dst, size_t dst_len, const uint8_t key[32],
		const uint8_t *ad, size_t ad_len,
		const uint8_t *plain, size_t plain_len)
{
	if (dst_len < plain_len + SEAL_OVERHEAD)
		return -1;
	if (random_bytes(dst, 24))
		return -1;
	if (cc_aead_lock(dst + 40, dst + 24, key, dst, ad, ad_len,
			 plain, plain_len))
		return -1;
	return (int)(plain_len + SEAL_OVERHEAD);
}

int msg_seal(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *plain, size_t plain_len)
{
	return msg_seal_ad(dst, dst_len, key, NULL, 0, plain, plain_len);
}

int msg_open_ad(uint8_t *dst, size_t dst_len, const uint8_t key[32],
		const uint8_t *ad, size_t ad_len,
		const uint8_t *sealed, size_t sealed_len)
{
	size_t plain_len;

	if (sealed_len < SEAL_OVERHEAD)
		return -1;
	plain_len = sealed_len - SEAL_OVERHEAD;
	if (dst_len < plain_len)
		return -1;
	if (cc_aead_unlock(dst, sealed + 24, key, sealed, ad, ad_len,
			   sealed + 40, plain_len))
		return -1;
	return (int)plain_len;
}

int msg_open(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *sealed, size_t sealed_len)
{
	return msg_open_ad(dst, dst_len, key, NULL, 0, sealed, sealed_len);
}
