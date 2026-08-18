/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CCRYPTO_H
#define COMRADE_CCRYPTO_H

#include <stddef.h>
#include <stdint.h>

/*
 * comrade's crypto surface, one audited choke point over the backend
 * selected at configure time (-DCOMRADE_CRYPTO=openssl|monocypher).
 * Every output is byte-identical across backends except the unkeyed
 * 32-byte stream (see cc_blake2b_init), so a mixed pair of peers
 * interoperates.
 */

/* Unkeyed streaming BLAKE2b. hash_size is 32 or 64; the context is
 * backend-owned heap state, released by _final. With the OpenSSL
 * backend a 32-byte request is BLAKE2b-512 truncated to 32 bytes, NOT
 * native BLAKE2b-256 -- callers requesting 32 must be process-local
 * (netmon's fingerprint is; nothing on the wire may use it). */
struct cc_blake2b {
	void *impl;
	unsigned out_len;
};

int cc_blake2b_init(struct cc_blake2b *ctx, size_t hash_size);
void cc_blake2b_update(struct cc_blake2b *ctx, const void *msg, size_t len);
void cc_blake2b_final(struct cc_blake2b *ctx, uint8_t *out);

/* Keyed BLAKE2b (RFC 7693 keyed mode, digest length in the parameter
 * block): the KDF under K_sig and the BEP 44 seed. Interop-critical. */
void cc_blake2b_keyed(uint8_t *out, size_t out_len,
		      const uint8_t *key, size_t key_len,
		      const uint8_t *msg, size_t msg_len);

/* RFC 8032 Ed25519. sk is seed || public key (64 bytes); seed is wiped.
 * check returns 0 for a good signature, non-zero otherwise. */
int cc_ed25519_key_pair(uint8_t sk[64], uint8_t pk[32], uint8_t seed[32]);
int cc_ed25519_sign(uint8_t sig[64], const uint8_t sk[64],
		    const uint8_t *msg, size_t msg_len);
int cc_ed25519_check(const uint8_t sig[64], const uint8_t pk[32],
		     const uint8_t *msg, size_t msg_len);

/* XChaCha20-Poly1305 with a 24-byte nonce, Monocypher's crypto_aead_lock
 * layout and semantics. Returns 0 on success; unlock fails on a bad tag. */
int cc_aead_lock(uint8_t *ct, uint8_t mac[16], const uint8_t key[32],
		 const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		 const uint8_t *pt, size_t pt_len);
int cc_aead_unlock(uint8_t *pt, const uint8_t mac[16], const uint8_t key[32],
		   const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		   const uint8_t *ct, size_t ct_len);

#endif
