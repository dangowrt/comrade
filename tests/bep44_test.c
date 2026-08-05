/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <monocypher-ed25519.h>

#include "bencode.h"
#include "bep44.h"
#include "sha1.h"

static void hex(uint8_t *out, const char *s)
{
	size_t i;

	for (i = 0; s[i * 2]; i++) {
		char b[3] = { s[i * 2], s[i * 2 + 1], 0 };

		out[i] = (uint8_t)strtol(b, NULL, 16);
	}
}

static void sha1_check(void)
{
	uint8_t d[20];
	static const uint8_t empty[20] = {
		0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
		0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
	};
	static const uint8_t abc[20] = {
		0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
		0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
	};

	sha1(d, "", 0);
	assert(!memcmp(d, empty, 20));
	sha1(d, "abc", 3);
	assert(!memcmp(d, abc, 20));
}

static void bencode_check(void)
{
	uint8_t buf[64];
	struct benc_buf b;
	const uint8_t *v;
	size_t vlen;
	int64_t n;
	const uint8_t *data;
	size_t dlen;

	benc_buf_init(&b, buf, sizeof(buf));
	benc_raw_add(&b, "d", 1);
	benc_key_add(&b, "seq");
	benc_int_add(&b, 42);
	benc_key_add(&b, "v");
	benc_str_add(&b, "hi", 2);
	benc_raw_add(&b, "e", 1);
	assert(!b.err);

	assert(!benc_dict_find(buf, b.len, "seq", &v, &vlen));
	assert(!benc_int_get(v, vlen, &n) && n == 42);
	assert(!benc_dict_find(buf, b.len, "v", &v, &vlen));
	assert(!benc_str_get(v, vlen, &data, &dlen));
	assert(dlen == 2 && !memcmp(data, "hi", 2));
	assert(benc_dict_find(buf, b.len, "x", &v, &vlen));
}

static void bencode_reject_check(void)
{
	const uint8_t *v;
	size_t vlen;

	assert(benc_dict_find((const uint8_t *)"d3:foo", 6, "foo", &v, &vlen));
	assert(benc_dict_find((const uint8_t *)"x", 1, "a", &v, &vlen));
}

static void bencode_depth_check(void)
{
	uint8_t deep[256];
	const uint8_t *p, *end;
	size_t i;

	for (i = 0; i < sizeof(deep); i++)
		deep[i] = 'l';
	p = deep;
	end = deep + sizeof(deep);
	assert(benc_skip(&p, end) < 0);
}

static void sig_buffer_check(void)
{
	uint8_t buf[128];
	size_t len;
	static const char want1[] = "3:seqi1e1:v12:Hello World!";
	static const char want2[] = "4:salt6:foobar3:seqi1e1:v12:Hello World!";

	len = bep44_sig_buffer(buf, sizeof(buf), "", 1,
			       (const uint8_t *)"12:Hello World!", 15);
	assert(len == sizeof(want1) - 1 && !memcmp(buf, want1, len));

	len = bep44_sig_buffer(buf, sizeof(buf), "foobar", 1,
			       (const uint8_t *)"12:Hello World!", 15);
	assert(len == sizeof(want2) - 1 && !memcmp(buf, want2, len));
}

static void vector_check(const char *pk_hex, const char *salt,
			 const char *target_hex, const char *sig_hex)
{
	uint8_t pk[32], target[20], want_sig[64], want_target[20];
	uint8_t sigbuf[128];
	size_t len;

	hex(pk, pk_hex);
	hex(want_target, target_hex);
	hex(want_sig, sig_hex);

	bep44_target(target, pk, salt);
	assert(!memcmp(target, want_target, 20));

	len = bep44_sig_buffer(sigbuf, sizeof(sigbuf), salt, 1,
			       (const uint8_t *)"12:Hello World!", 15);
	assert(!crypto_ed25519_check(want_sig, pk, sigbuf, len));
}

static void sign_roundtrip_check(void)
{
	uint8_t seed[32], pk[32], sk[64], sig[64], sigbuf[128];
	size_t len, i;

	for (i = 0; i < 32; i++)
		seed[i] = (uint8_t)(i * 3 + 1);
	crypto_ed25519_key_pair(sk, pk, seed);

	len = bep44_sig_buffer(sigbuf, sizeof(sigbuf), "comrade", 7,
			       (const uint8_t *)"3:abc", 5);
	crypto_ed25519_sign(sig, sk, sigbuf, len);
	assert(!crypto_ed25519_check(sig, pk, sigbuf, len));
	sig[0] ^= 1;
	assert(crypto_ed25519_check(sig, pk, sigbuf, len));
}

static void vectors_check(void)
{
	static const char pk[] =
		"77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548";

	vector_check(pk, "",
		     "4a533d47ec9c7d95b1ad75f576cffc641853b750",
		     "305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff"
		     "1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01");
	vector_check(pk, "foobar",
		     "411eba73b6f087ca51a3795d9c8c938d365e32c1",
		     "6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17d"
		     "df9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08");
}

int main(void)
{
	sha1_check();
	bencode_check();
	bencode_reject_check();
	bencode_depth_check();
	sig_buffer_check();
	vectors_check();
	sign_roundtrip_check();
	return 0;
}
