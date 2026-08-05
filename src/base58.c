/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "base58.h"

#define B58_BUF (BASE58_MAX_IN * 138 / 100 + 2)
#define B256_BUF (BASE58_MAX_STR * 733 / 1000 + 2)

static const char alphabet[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int b58_value(int c)
{
	const char *p;

	if (c == '\0')
		return -1;
	p = strchr(alphabet, c);
	return p ? (int)(p - alphabet) : -1;
}

size_t base58_encode(const uint8_t *src, size_t src_len, char *dst, size_t dst_len)
{
	uint8_t b58[B58_BUF];
	size_t zeros = 0, start, need, i, o = 0;

	if (src_len > BASE58_MAX_IN)
		return 0;
	while (zeros < src_len && src[zeros] == 0)
		zeros++;

	memset(b58, 0, sizeof(b58));
	for (i = zeros; i < src_len; i++) {
		int carry = src[i];
		size_t j = sizeof(b58);

		while (j-- > 0) {
			carry += 256 * b58[j];
			b58[j] = (uint8_t)(carry % 58);
			carry /= 58;
		}
	}

	start = 0;
	while (start < sizeof(b58) && b58[start] == 0)
		start++;
	need = zeros + (sizeof(b58) - start);
	if (dst_len < need + 1)
		return 0;

	for (i = 0; i < zeros; i++)
		dst[o++] = '1';
	for (i = start; i < sizeof(b58); i++)
		dst[o++] = alphabet[b58[i]];
	dst[o] = '\0';
	return o;
}

int base58_decode(const char *src, size_t src_len, uint8_t *dst, size_t dst_len)
{
	uint8_t b256[B256_BUF];
	size_t zeros = 0, start, need, i, o = 0;

	if (src_len > BASE58_MAX_STR)
		return -1;
	while (zeros < src_len && src[zeros] == '1')
		zeros++;

	memset(b256, 0, sizeof(b256));
	for (i = zeros; i < src_len; i++) {
		int v = b58_value((unsigned char)src[i]);
		size_t j = sizeof(b256);

		if (v < 0)
			return -1;
		while (j-- > 0) {
			v += 58 * b256[j];
			b256[j] = (uint8_t)(v % 256);
			v /= 256;
		}
	}

	start = 0;
	while (start < sizeof(b256) && b256[start] == 0)
		start++;
	need = zeros + (sizeof(b256) - start);
	if (need > dst_len)
		return -1;

	for (i = 0; i < zeros; i++)
		dst[o++] = 0;
	for (i = start; i < sizeof(b256); i++)
		dst[o++] = b256[i];
	return (int)o;
}
