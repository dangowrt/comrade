/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * ccrypto backend on libgcrypt, for hosts whose libssh is built against
 * it -- so comrade adds no second crypto library. Byte-for-byte
 * compatible with the other backends on every interop-relevant
 * primitive.
 *
 * gcrypt provides BLAKE2b (keyed and unkeyed, natively at both digest
 * lengths) and RFC 8032 Ed25519, so only XChaCha20-Poly1305 needs
 * rebuilding: HChaCha20 from a raw ChaCha20 block, then gcrypt's IETF
 * ChaCha20-Poly1305 under the derived subkey (identical to the OpenSSL
 * arm's reconstruction).
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#include "ccrypto.h"

/* gcrypt refuses to work until the version check has run. libssh does this
 * too when gcrypt is its backend, but ccrypto is also used by tools that
 * never open an SSH session, and comrade is threaded, so do it exactly once
 * ourselves; a second initialisation elsewhere is harmless. */
static pthread_once_t cc_once = PTHREAD_ONCE_INIT;

static void cc_init_once(void)
{
	if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
		gcry_check_version(NULL);
		gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
}

static void cc_init(void)
{
	pthread_once(&cc_once, cc_init_once);
}

/* Clear key material without the compiler optimising the store away
 * (libgcrypt's own wipememory is internal to it, not public API). */
static void cc_wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;

	while (n--)
		*v++ = 0;
}

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

/* comrade asks for 32- or 64-byte BLAKE2b; gcrypt has both natively. */
static int b2b_algo(size_t hash_size)
{
	if (hash_size == 32)
		return GCRY_MD_BLAKE2B_256;
	if (hash_size == 64)
		return GCRY_MD_BLAKE2B_512;
	return 0;
}

int cc_blake2b_init(struct cc_blake2b *ctx, size_t hash_size)
{
	gcry_md_hd_t h = NULL;
	int algo = b2b_algo(hash_size);

	cc_init();
	ctx->impl = NULL;
	ctx->out_len = (unsigned)hash_size;
	if (!algo || gcry_md_open(&h, algo, 0))
		return -1;
	ctx->impl = h;
	return 0;
}

void cc_blake2b_update(struct cc_blake2b *ctx, const void *msg, size_t len)
{
	if (ctx->impl)
		gcry_md_write((gcry_md_hd_t)ctx->impl, msg, len);
}

void cc_blake2b_final(struct cc_blake2b *ctx, uint8_t *out)
{
	gcry_md_hd_t h = ctx->impl;
	const unsigned char *d;

	if (!h) {
		memset(out, 0, ctx->out_len);
		return;
	}
	d = gcry_md_read(h, b2b_algo(ctx->out_len));
	if (d)
		memcpy(out, d, ctx->out_len);
	else
		memset(out, 0, ctx->out_len);
	gcry_md_close(h);
	ctx->impl = NULL;
}

void cc_blake2b_keyed(uint8_t *out, size_t out_len,
		      const uint8_t *key, size_t key_len,
		      const uint8_t *msg, size_t msg_len)
{
	gcry_md_hd_t h = NULL;
	int algo = b2b_algo(out_len);
	const unsigned char *d;

	cc_init();
	memset(out, 0, out_len);
	if (!algo || gcry_md_open(&h, algo, 0))
		return;
	/* RFC 7693 keyed mode, the digest length folded into the parameter
	 * block -- the same construction crypto_blake2b_keyed produces. */
	if (gcry_md_setkey(h, key, key_len)) {
		gcry_md_close(h);
		return;
	}
	gcry_md_write(h, msg, msg_len);
	d = gcry_md_read(h, algo);
	if (d)
		memcpy(out, d, out_len);
	gcry_md_close(h);
}

/* Copy a 32-byte EdDSA quantity out of an sexp/MPI. gcrypt carries these as
 * opaque MPIs, so the encoded bytes survive verbatim (leading zeros
 * included, verified over thousands of keys and signatures); anything other
 * than exactly 32 bytes is refused rather than padded, since guessing the
 * padding side would silently corrupt a key or signature. */
static int copy32(uint8_t out[32], gcry_mpi_t m)
{
	size_t wrote = 0;

	if (!m)
		return -1;
	if (gcry_mpi_get_flag(m, GCRYMPI_FLAG_OPAQUE)) {
		unsigned int nbits = 0;
		const void *p = gcry_mpi_get_opaque(m, &nbits);

		if (!p || (nbits + 7) / 8 != 32)
			return -1;
		memcpy(out, p, 32);
		return 0;
	}
	if (gcry_mpi_print(GCRYMPI_FMT_USG, out, 32, &wrote, m) || wrote != 32)
		return -1;
	return 0;
}

static int sexp_copy32(uint8_t out[32], gcry_sexp_t sig, const char *token)
{
	gcry_sexp_t t = gcry_sexp_find_token(sig, token, 0);
	const char *d;
	size_t len = 0;
	int rc = -1;

	if (!t)
		return -1;
	d = gcry_sexp_nth_data(t, 1, &len);
	if (d && len == 32) {
		memcpy(out, d, 32);
		rc = 0;
	}
	gcry_sexp_release(t);
	return rc;
}

int cc_ed25519_key_pair(uint8_t sk[64], uint8_t pk[32], uint8_t seed[32])
{
	gcry_sexp_t s_sk = NULL;
	gcry_ctx_t ctx = NULL;
	gcry_mpi_t q = NULL;
	int ok = 0;

	cc_init();
	/* gcrypt's EdDSA takes d as the RFC 8032 seed and does the SHA-512
	 * expansion and clamping itself, so q@eddsa is the standard public
	 * key in its compressed encoding. */
	if (gcry_sexp_build(&s_sk, NULL,
			    "(private-key(ecc(curve Ed25519)(flags eddsa)(d %b)))",
			    32, seed))
		goto out;
	if (gcry_mpi_ec_new(&ctx, s_sk, NULL))
		goto out;
	q = gcry_mpi_ec_get_mpi("q@eddsa", ctx, 1);
	if (copy32(pk, q))
		goto out;
	memcpy(sk, seed, 32);		/* sk is seed || pk, as elsewhere */
	memcpy(sk + 32, pk, 32);
	ok = 1;
out:
	if (q)
		gcry_mpi_release(q);
	if (ctx)
		gcry_ctx_release(ctx);
	if (s_sk)
		gcry_sexp_release(s_sk);
	/* Monocypher's key_pair wipes the seed; keep that contract. */
	cc_wipe(seed, 32);
	return ok ? 0 : -1;
}

int cc_ed25519_sign(uint8_t sig[64], const uint8_t sk[64],
		    const uint8_t *msg, size_t msg_len)
{
	gcry_sexp_t s_sk = NULL, s_data = NULL, s_sig = NULL;
	int ok = 0;

	cc_init();
	if (gcry_sexp_build(&s_sk, NULL,
			    "(private-key(ecc(curve Ed25519)(flags eddsa)(d %b)))",
			    32, sk))
		goto out;
	if (gcry_sexp_build(&s_data, NULL,
			    "(data(flags eddsa)(hash-algo sha512)(value %b))",
			    (int)msg_len, msg))
		goto out;
	if (gcry_pk_sign(&s_sig, s_data, s_sk))
		goto out;
	if (sexp_copy32(sig, s_sig, "r") || sexp_copy32(sig + 32, s_sig, "s"))
		goto out;
	ok = 1;
out:
	if (s_sig)
		gcry_sexp_release(s_sig);
	if (s_data)
		gcry_sexp_release(s_data);
	if (s_sk)
		gcry_sexp_release(s_sk);
	return ok ? 0 : -1;
}

int cc_ed25519_check(const uint8_t sig[64], const uint8_t pk[32],
		     const uint8_t *msg, size_t msg_len)
{
	gcry_sexp_t s_pk = NULL, s_data = NULL, s_sig = NULL;
	int ok = 0;

	cc_init();
	if (gcry_sexp_build(&s_pk, NULL,
			    "(public-key(ecc(curve Ed25519)(flags eddsa)(q %b)))",
			    32, pk))
		goto out;
	if (gcry_sexp_build(&s_data, NULL,
			    "(data(flags eddsa)(hash-algo sha512)(value %b))",
			    (int)msg_len, msg))
		goto out;
	if (gcry_sexp_build(&s_sig, NULL, "(sig-val(eddsa(r %b)(s %b)))",
			    32, sig, 32, sig + 32))
		goto out;
	ok = gcry_pk_verify(s_sig, s_data, s_pk) == 0;
out:
	if (s_sig)
		gcry_sexp_release(s_sig);
	if (s_data)
		gcry_sexp_release(s_data);
	if (s_pk)
		gcry_sexp_release(s_pk);
	return ok ? 0 : -1;
}

/*
 * HChaCha20 on top of raw ChaCha20, as in the OpenSSL arm: gcrypt's
 * 16-byte ChaCha20 IV lands in state words 12-15, so the first keystream
 * block is Z = rounds(X) + X, and subtracting the known initial state
 * recovers the HChaCha20 words. Verified byte-identical to Monocypher's
 * crypto_chacha20_h.
 */
static int cc_hchacha20(uint8_t out[32], const uint8_t key[32],
			const uint8_t in[16])
{
	static const char sigma[] = "expand 32-byte k";	/* 16 bytes used */
	gcry_cipher_hd_t h = NULL;
	uint8_t zero[64], ks[64];
	int j, ok = 0;

	memset(zero, 0, sizeof(zero));
	if (gcry_cipher_open(&h, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0))
		return -1;
	if (gcry_cipher_setkey(h, key, 32))
		goto out;
	if (gcry_cipher_setiv(h, in, 16))
		goto out;
	if (gcry_cipher_encrypt(h, ks, sizeof(ks), zero, sizeof(zero)))
		goto out;
	for (j = 0; j < 4; j++)
		st32(out + j * 4,
		     ld32(ks + j * 4) - ld32((const uint8_t *)sigma + j * 4));
	for (j = 12; j < 16; j++)
		st32(out + 16 + (j - 12) * 4,
		     ld32(ks + j * 4) - ld32(in + (j - 12) * 4));
	ok = 1;
out:
	gcry_cipher_close(h);
	return ok ? 0 : -1;
}

/* The 24-byte nonce splits as HChaCha20 input || djb nonce; the djb 8-byte
 * nonce with counter 0 is the IETF 12-byte nonce 0^4 || nonce[16..24]. */
static void cc_aead_iv(uint8_t iv[12], const uint8_t nonce[24])
{
	memset(iv, 0, 4);
	memcpy(iv + 4, nonce + 16, 8);
}

/* Shared set-up for lock/unlock: derive the subkey and open the AEAD. */
static int aead_open(gcry_cipher_hd_t *h, const uint8_t key[32],
		     const uint8_t nonce[24], const uint8_t *ad, size_t ad_len)
{
	uint8_t subkey[32], iv[12];
	int ok = 0;

	cc_init();
	*h = NULL;
	if (cc_hchacha20(subkey, key, nonce))
		return -1;
	cc_aead_iv(iv, nonce);
	if (gcry_cipher_open(h, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0))
		goto out;
	if (gcry_cipher_setkey(*h, subkey, 32))
		goto out;
	if (gcry_cipher_setiv(*h, iv, 12))
		goto out;
	if (ad_len && gcry_cipher_authenticate(*h, ad, ad_len))
		goto out;
	ok = 1;
out:
	cc_wipe(subkey, sizeof(subkey));
	if (!ok) {
		gcry_cipher_close(*h);
		*h = NULL;
	}
	return ok ? 0 : -1;
}

int cc_aead_lock(uint8_t *ct, uint8_t mac[16], const uint8_t key[32],
		 const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		 const uint8_t *pt, size_t pt_len)
{
	gcry_cipher_hd_t h;
	int ok = 0;

	if (aead_open(&h, key, nonce, ad, ad_len))
		return -1;
	if (pt_len && gcry_cipher_encrypt(h, ct, pt_len, pt, pt_len))
		goto out;
	if (gcry_cipher_gettag(h, mac, 16))
		goto out;
	ok = 1;
out:
	gcry_cipher_close(h);
	return ok ? 0 : -1;
}

int cc_aead_unlock(uint8_t *pt, const uint8_t mac[16], const uint8_t key[32],
		   const uint8_t nonce[24], const uint8_t *ad, size_t ad_len,
		   const uint8_t *ct, size_t ct_len)
{
	gcry_cipher_hd_t h;
	int ok = 0;

	if (aead_open(&h, key, nonce, ad, ad_len))
		return -1;
	if (ct_len && gcry_cipher_decrypt(h, pt, ct_len, ct, ct_len))
		goto out;
	if (gcry_cipher_checktag(h, mac, 16))	/* forgery fails here */
		goto out;
	ok = 1;
out:
	if (!ok && ct_len)
		memset(pt, 0, ct_len);
	gcry_cipher_close(h);
	return ok ? 0 : -1;
}
