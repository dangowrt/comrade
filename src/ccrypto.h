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

/*
 * Keyed BLAKE2b (RFC 7693 keyed mode, digest length in the parameter
 * block): the KDF under K_sig and the BEP 44 seed. Interop-critical.
 *
 * Fills out, or does not return. Every key comrade holds comes from here --
 * the sealing key, the BEP 44 seed, the wire tags, the per-connection key,
 * the read-only secret, a path's id -- so a backend that cannot compute this
 * has no degraded mode to fall back to: an output left as zeros would be a
 * key every build without the primitive agreed on, and a mailbox target every
 * such session shared. There is nothing data-dependent about the failure
 * either, since it means the primitive is absent from this binary's backend
 * rather than that this call was wrong, so it is the same on every call and
 * belongs to the build. Configure proves the primitive is there (see the
 * backend probe in CMakeLists.txt); this is what happens if it lied.
 */
void cc_blake2b_keyed(uint8_t *out, size_t out_len,
		      const uint8_t *key, size_t key_len,
		      const uint8_t *msg, size_t msg_len);

/*
 * The backend cannot do something comrade's wire format requires. Names the
 * primitive on stderr and ends the process; never returns.
 */
void cc_fatal(const char *what);

/* RFC 8032 Ed25519. sk is seed || public key (64 bytes); seed is wiped.
 * check returns 0 for a good signature, non-zero otherwise. */
/*
 * X25519 (RFC 7748). A claim in the mailbox is sealed to the host, which is
 * the only holder of the secret half, so no other holder of the invitation can
 * read where a peer is. Interop-critical, like the rest of this header.
 */
int cc_x25519_public(uint8_t pk[32], const uint8_t sk[32]);
int cc_x25519(uint8_t out[32], const uint8_t sk[32], const uint8_t peer[32]);

int cc_ed25519_key_pair(uint8_t sk[64], uint8_t pk[32], uint8_t seed[32]);
int cc_ed25519_sign(uint8_t sig[64], const uint8_t sk[64],
		    const uint8_t *msg, size_t msg_len);
int cc_ed25519_check(const uint8_t sig[64], const uint8_t pk[32],
		     const uint8_t *msg, size_t msg_len);

/* XChaCha20-Poly1305 with a 24-byte nonce, Monocypher's crypto_aead_lock
 * layout and semantics. Returns 0 on success; unlock fails on a bad tag and
 * leaves no recoverable plaintext in pt. The caller must not read pt on a
 * non-zero return. */
int cc_aead_lock(uint8_t *ct, uint8_t mac[16], const uint8_t key[32],
		 const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		 const uint8_t *pt, size_t pt_len);
int cc_aead_unlock(uint8_t *pt, const uint8_t mac[16], const uint8_t key[32],
		   const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		   const uint8_t *ct, size_t ct_len);

#endif
