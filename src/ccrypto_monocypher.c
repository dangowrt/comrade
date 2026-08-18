/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * ccrypto backend on Monocypher: the original primitives, kept as a
 * fallback during the OpenSSL migration window (-DCOMRADE_CRYPTO=
 * monocypher) for bisects and size-constrained targets. Pass-throughs
 * except for heap-backing the streaming context, which mirrors the
 * OpenSSL arm so both meet the same contract.
 */

#include <stdlib.h>
#include <string.h>

#include <monocypher.h>
#include <monocypher-ed25519.h>

#include "ccrypto.h"

int cc_blake2b_init(struct cc_blake2b *ctx, size_t hash_size)
{
	crypto_blake2b_ctx *b = malloc(sizeof(*b));

	ctx->impl = b;
	ctx->out_len = (unsigned)hash_size;
	if (!b)
		return -1;
	crypto_blake2b_init(b, hash_size);
	return 0;
}

void cc_blake2b_update(struct cc_blake2b *ctx, const void *msg, size_t len)
{
	if (ctx->impl)
		crypto_blake2b_update(ctx->impl, msg, len);
}

void cc_blake2b_final(struct cc_blake2b *ctx, uint8_t *out)
{
	if (ctx->impl) {
		crypto_blake2b_final(ctx->impl, out);
		free(ctx->impl);
		ctx->impl = NULL;
	} else {
		memset(out, 0, ctx->out_len);
	}
}

void cc_blake2b_keyed(uint8_t *out, size_t out_len,
		      const uint8_t *key, size_t key_len,
		      const uint8_t *msg, size_t msg_len)
{
	crypto_blake2b_keyed(out, out_len, key, key_len, msg, msg_len);
}

int cc_ed25519_key_pair(uint8_t sk[64], uint8_t pk[32], uint8_t seed[32])
{
	crypto_ed25519_key_pair(sk, pk, seed);	/* wipes the seed */
	return 0;
}

int cc_ed25519_sign(uint8_t sig[64], const uint8_t sk[64],
		    const uint8_t *msg, size_t msg_len)
{
	crypto_ed25519_sign(sig, sk, msg, msg_len);
	return 0;
}

int cc_ed25519_check(const uint8_t sig[64], const uint8_t pk[32],
		     const uint8_t *msg, size_t msg_len)
{
	return crypto_ed25519_check(sig, pk, msg, msg_len);
}

int cc_aead_lock(uint8_t *ct, uint8_t mac[16], const uint8_t key[32],
		 const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		 const uint8_t *pt, size_t pt_len)
{
	crypto_aead_lock(ct, mac, key, nonce, ad, ad_len, pt, pt_len);
	return 0;
}

int cc_aead_unlock(uint8_t *pt, const uint8_t mac[16], const uint8_t key[32],
		   const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		   const uint8_t *ct, size_t ct_len)
{
	return crypto_aead_unlock(pt, mac, key, nonce, ad, ad_len, ct, ct_len);
}
