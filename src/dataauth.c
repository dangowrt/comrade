/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "ccrypto.h"
#include "dataauth.h"

static void put_u64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t get_u64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;

	for (i = 0; i < 8; i++)
		v = (v << 8) | p[i];
	return v;
}

/* BLAKE2b is available at whole digest sizes on every backend, so take the
 * 32-byte one and keep the first half rather than asking for 16 direct. */
static void tag_of(const uint8_t key[32], const uint8_t *body, size_t n,
		   uint8_t out[DATAAUTH_TAG_LEN])
{
	uint8_t full[32];

	cc_blake2b_keyed(full, sizeof(full), key, 32, body, n);
	memcpy(out, full, DATAAUTH_TAG_LEN);
}

/* Equal, without saying where they differ. */
static int tag_eq(const uint8_t *a, const uint8_t *b)
{
	uint8_t d = 0;
	size_t i;

	for (i = 0; i < DATAAUTH_TAG_LEN; i++)
		d = (uint8_t)(d | (a[i] ^ b[i]));
	return d == 0;
}

size_t dataauth_wrap(uint8_t *out, size_t out_max, const uint8_t key[32],
		     const uint8_t *data, size_t len, uint64_t seq)
{
	size_t n;

	if (len + DATAAUTH_OVERHEAD > out_max)
		return 0;
	memcpy(out, data, len);
	put_u64(out + len, seq);
	n = len + DATAAUTH_CTR_LEN;
	tag_of(key, out, n, out + n);
	return n + DATAAUTH_TAG_LEN;
}

int dataauth_open(const uint8_t key[32], const uint8_t *in, size_t len,
		  size_t *body, uint64_t *seq)
{
	uint8_t tag[DATAAUTH_TAG_LEN];
	size_t n;

	if (len < DATAAUTH_OVERHEAD)
		return -1;
	n = len - DATAAUTH_TAG_LEN;
	tag_of(key, in, n, tag);
	if (!tag_eq(tag, in + n))
		return -1;
	*seq = get_u64(in + n - DATAAUTH_CTR_LEN);
	*body = n - DATAAUTH_CTR_LEN;
	return 0;
}
