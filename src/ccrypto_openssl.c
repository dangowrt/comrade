/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * ccrypto backend on OpenSSL libcrypto. Byte-for-byte compatible with
 * the Monocypher backend on every interop-relevant primitive. The single piece of novel crypto plumbing
 * is cc_hchacha20 below -- everything else is a thin EVP wrapper with
 * the goto-out discipline OpenSSL's context lifecycle demands.
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "ccrypto.h"

static uint32_t ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void st32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

int cc_blake2b_init(struct cc_blake2b *ctx, size_t hash_size)
{
	EVP_MD_CTX *md = EVP_MD_CTX_new();

	ctx->impl = NULL;
	ctx->out_len = (unsigned)hash_size;
	if (!md)
		return -1;
	if (EVP_DigestInit_ex(md, EVP_blake2b512(), NULL) != 1) {
		EVP_MD_CTX_free(md);
		return -1;
	}
	ctx->impl = md;
	return 0;
}

void cc_blake2b_update(struct cc_blake2b *ctx, const void *msg, size_t len)
{
	if (ctx->impl)
		EVP_DigestUpdate(ctx->impl, msg, len);
}

void cc_blake2b_final(struct cc_blake2b *ctx, uint8_t *out)
{
	uint8_t full[64];
	unsigned n = 0;

	memset(full, 0, sizeof(full));
	if (ctx->impl) {
		EVP_DigestFinal_ex(ctx->impl, full, &n);
		EVP_MD_CTX_free(ctx->impl);
		ctx->impl = NULL;
	}
	memcpy(out, full, ctx->out_len <= 64 ? ctx->out_len : 64);
}

void cc_blake2b_keyed(uint8_t *out, size_t out_len,
		      const uint8_t *key, size_t key_len,
		      const uint8_t *msg, size_t msg_len)
{
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	size_t n = 0;

	memset(out, 0, out_len);
	mac = EVP_MAC_fetch(NULL, "BLAKE2BMAC", NULL);
	if (!mac)
		return;
	ctx = EVP_MAC_CTX_new(mac);
	if (!ctx)
		goto out;
	params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &out_len);
	params[1] = OSSL_PARAM_construct_end();
	if (EVP_MAC_init(ctx, key, key_len, params) != 1)
		goto out;
	if (EVP_MAC_update(ctx, msg, msg_len) != 1)
		goto out;
	EVP_MAC_final(ctx, out, &n, out_len);
out:
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);
}

/* RFC 7748 says a shared secret of all zeros means the peer sent a low-order
 * point, which agrees on nothing. Refuse rather than derive from it. */
static int x25519_degenerate(const uint8_t out[32])
{
	uint8_t d = 0;
	int i;

	for (i = 0; i < 32; i++)
		d = (uint8_t)(d | out[i]);
	return d == 0;
}

int cc_x25519_public(uint8_t pk[32], const uint8_t sk[32])
{
	EVP_PKEY *key;
	size_t plen = 32;
	int ok;

	key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
	if (!key)
		return -1;
	ok = EVP_PKEY_get_raw_public_key(key, pk, &plen) == 1 && plen == 32;
	EVP_PKEY_free(key);
	return ok ? 0 : -1;
}

int cc_x25519(uint8_t out[32], const uint8_t sk[32], const uint8_t peer[32])
{
	EVP_PKEY *mine = NULL, *theirs = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	size_t len = 32;
	int ok = 0;

	mine = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
	theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
	if (!mine || !theirs)
		goto out;
	ctx = EVP_PKEY_CTX_new(mine, NULL);
	if (!ctx || EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, theirs) != 1 ||
	    EVP_PKEY_derive(ctx, out, &len) != 1 || len != 32)
		goto out;
	ok = !x25519_degenerate(out);
out:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(theirs);
	EVP_PKEY_free(mine);
	if (!ok)
		OPENSSL_cleanse(out, 32);
	return ok ? 0 : -1;
}

int cc_ed25519_key_pair(uint8_t sk[64], uint8_t pk[32], uint8_t seed[32])
{
	EVP_PKEY *key;
	size_t plen = 32;
	int ok = 0;

	/* sk carries seed || pk, the layout the sign path re-imports. */
	key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
	if (!key)
		goto out;
	if (EVP_PKEY_get_raw_public_key(key, pk, &plen) != 1 || plen != 32)
		goto out;
	memcpy(sk, seed, 32);
	memcpy(sk + 32, pk, 32);
	ok = 1;
out:
	/* Monocypher's key_pair wipes the seed; keep that contract. */
	OPENSSL_cleanse(seed, 32);
	EVP_PKEY_free(key);
	return ok ? 0 : -1;
}

int cc_ed25519_sign(uint8_t sig[64], const uint8_t sk[64],
		    const uint8_t *msg, size_t msg_len)
{
	EVP_PKEY *key = NULL;
	EVP_MD_CTX *md = NULL;
	size_t slen = 64;
	int ok = 0;

	key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
	if (!key)
		goto out;
	md = EVP_MD_CTX_new();
	if (!md)
		goto out;
	if (EVP_DigestSignInit(md, NULL, NULL, NULL, key) != 1)
		goto out;
	/* Ed25519 mandates the one-shot form; there is no streaming sign. */
	if (EVP_DigestSign(md, sig, &slen, msg, msg_len) != 1 || slen != 64)
		goto out;
	ok = 1;
out:
	EVP_MD_CTX_free(md);
	EVP_PKEY_free(key);
	return ok ? 0 : -1;
}

int cc_ed25519_check(const uint8_t sig[64], const uint8_t pk[32],
		     const uint8_t *msg, size_t msg_len)
{
	EVP_PKEY *key = NULL;
	EVP_MD_CTX *md = NULL;
	int ok = 0;

	key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, 32);
	if (!key)
		goto out;
	md = EVP_MD_CTX_new();
	if (!md)
		goto out;
	if (EVP_DigestVerifyInit(md, NULL, NULL, NULL, key) != 1)
		goto out;
	ok = EVP_DigestVerify(md, sig, 64, msg, msg_len) == 1;
out:
	EVP_MD_CTX_free(md);
	EVP_PKEY_free(key);
	return ok ? 0 : -1;
}

/*
 * HChaCha20 on top of raw ChaCha20. OpenSSL has no XChaCha20; the
 * extended nonce needs HChaCha20(key, nonce[0..16]) as a subkey.
 * EVP_chacha20's first keystream block is Z = rounds(X) + X with the
 * 16 IV bytes sitting in state words 12-15, and HChaCha20 is words
 * {0..3,12..15} of rounds(X) alone -- so recover it by subtracting the
 * known initial state words from Z. Verified byte-identical to
 * Monocypher's crypto_chacha20_h.
 */
static int cc_hchacha20(uint8_t out[32], const uint8_t key[32],
			const uint8_t in[16])
{
	static const char sigma[] = "expand 32-byte k";	/* 16 bytes used */
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	uint8_t zero[64], ks[64];
	int outl, j, ok = 0;

	if (!c)
		return -1;
	memset(zero, 0, sizeof(zero));
	if (EVP_EncryptInit_ex(c, EVP_chacha20(), NULL, key, in) != 1)
		goto out;
	if (EVP_EncryptUpdate(c, ks, &outl, zero, 64) != 1 || outl != 64)
		goto out;
	for (j = 0; j < 4; j++)
		st32(out + j * 4,
		     ld32(ks + j * 4) - ld32((const uint8_t *)sigma + j * 4));
	for (j = 12; j < 16; j++)
		st32(out + 16 + (j - 12) * 4,
		     ld32(ks + j * 4) - ld32(in + (j - 12) * 4));
	ok = 1;
out:
	EVP_CIPHER_CTX_free(c);
	return ok ? 0 : -1;
}

/* The 24-byte nonce splits as HChaCha20 input || djb nonce; the djb
 * 8-byte nonce with counter 0 is the IETF 12-byte nonce 0^4 || nonce[16..24]
 * (RFC 8439's counter-high word is the IETF nonce's first four bytes). */
static void cc_aead_iv(uint8_t iv[12], const uint8_t nonce[24])
{
	memset(iv, 0, 4);
	memcpy(iv + 4, nonce + 16, 8);
}

int cc_aead_lock(uint8_t *ct, uint8_t mac[16], const uint8_t key[32],
		 const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		 const uint8_t *pt, size_t pt_len)
{
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	uint8_t subkey[32], iv[12], scratch[16];
	int outl, ok = 0;

	if (!c)
		return -1;
	if (cc_hchacha20(subkey, key, nonce))
		goto out;
	cc_aead_iv(iv, nonce);
	if (EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
		goto out;
	if (EVP_EncryptInit_ex(c, NULL, NULL, subkey, iv) != 1)
		goto out;
	if (ad_len && EVP_EncryptUpdate(c, NULL, &outl, ad, (int)ad_len) != 1)
		goto out;
	if (pt_len && EVP_EncryptUpdate(c, ct, &outl, pt, (int)pt_len) != 1)
		goto out;
	if (EVP_EncryptFinal_ex(c, scratch, &outl) != 1 || outl != 0)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, mac) != 1)
		goto out;
	ok = 1;
out:
	OPENSSL_cleanse(subkey, sizeof(subkey));
	EVP_CIPHER_CTX_free(c);
	return ok ? 0 : -1;
}

int cc_aead_unlock(uint8_t *pt, const uint8_t mac[16], const uint8_t key[32],
		   const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		   const uint8_t *ct, size_t ct_len)
{
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	uint8_t subkey[32], iv[12], tag[16], scratch[16];
	int outl, ok = 0;

	if (!c)
		return -1;
	if (cc_hchacha20(subkey, key, nonce))
		goto out;
	cc_aead_iv(iv, nonce);
	if (EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
		goto out;
	if (EVP_DecryptInit_ex(c, NULL, NULL, subkey, iv) != 1)
		goto out;
	memcpy(tag, mac, 16);	/* the ctrl wants a writable buffer */
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1)
		goto out;
	if (ad_len && EVP_DecryptUpdate(c, NULL, &outl, ad, (int)ad_len) != 1)
		goto out;
	if (ct_len && EVP_DecryptUpdate(c, pt, &outl, ct, (int)ct_len) != 1)
		goto out;
	if (EVP_DecryptFinal_ex(c, scratch, &outl) != 1 || outl != 0)
		goto out;	/* a tag mismatch fails the final */
	ok = 1;
out:
	if (!ok && ct_len)
		OPENSSL_cleanse(pt, ct_len);
	OPENSSL_cleanse(subkey, sizeof(subkey));
	EVP_CIPHER_CTX_free(c);
	return ok ? 0 : -1;
}
