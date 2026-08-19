/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "sha1.h"

static uint32_t rotl(uint32_t x, int n)
{
	return x << n | x >> (32 - n);
}

static void cc_sha1_block(struct cc_sha1_ctx *ctx, const uint8_t *p)
{
	uint32_t w[80];
	uint32_t a, b, c, d, e, f, k, t;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
		       (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
	for (i = 16; i < 80; i++)
		w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];

	for (i = 0; i < 80; i++) {
		if (i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5a827999;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ed9eba1;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8f1bbcdc;
		} else {
			f = b ^ c ^ d;
			k = 0xca62c1d6;
		}
		t = rotl(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rotl(b, 30);
		b = a;
		a = t;
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
}

void cc_sha1_init(struct cc_sha1_ctx *ctx)
{
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xc3d2e1f0;
	ctx->len = 0;
}

void cc_sha1_update(struct cc_sha1_ctx *ctx, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t fill = ctx->len % 64;

	ctx->len += len;

	if (fill) {
		size_t n = 64 - fill;

		if (n > len)
			n = len;
		memcpy(ctx->buf + fill, p, n);
		p += n;
		len -= n;
		if (fill + n < 64)
			return;
		cc_sha1_block(ctx, ctx->buf);
	}
	for (; len >= 64; p += 64, len -= 64)
		cc_sha1_block(ctx, p);
	if (len)
		memcpy(ctx->buf, p, len);
}

void cc_sha1_final(struct cc_sha1_ctx *ctx, uint8_t digest[SHA1_LEN])
{
	uint64_t bits = ctx->len * 8;
	uint8_t pad[72];
	size_t fill = ctx->len % 64;
	size_t padlen = (fill < 56 ? 56 : 120) - fill;
	int i;

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;
	for (i = 0; i < 8; i++)
		pad[padlen + i] = (uint8_t)(bits >> (56 - 8 * i));
	cc_sha1_update(ctx, pad, padlen + 8);

	for (i = 0; i < 5; i++) {
		digest[i * 4] = (uint8_t)(ctx->h[i] >> 24);
		digest[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
		digest[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
		digest[i * 4 + 3] = (uint8_t)ctx->h[i];
	}
}

void cc_sha1(uint8_t digest[SHA1_LEN], const void *data, size_t len)
{
	struct cc_sha1_ctx ctx;

	cc_sha1_init(&ctx);
	cc_sha1_update(&ctx, data, len);
	cc_sha1_final(&ctx, digest);
}
