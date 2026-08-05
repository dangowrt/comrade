/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_BASE58_H
#define COMRADE_BASE58_H

#include <stddef.h>
#include <stdint.h>

/*
 * base58 (Bitcoin alphabet): case-sensitive, free of the visually ambiguous
 * glyphs 0 O I l, letters and digits only. Encode is minimal-length; decode
 * fills a fixed number of bytes (right-aligned big integer) so a token can
 * be left-padded to a constant width with the zero digit '1'.
 */

#define BASE58_MAX_IN 160
#define BASE58_MAX_STR 200

size_t base58_encode(const uint8_t *src, size_t src_len, char *dst, size_t dst_len);

/* Decode into exactly dst_len bytes (leading zeros as needed). Returns
 * dst_len, or -1 on a bad character or a value too large to fit. */
int base58_decode(const char *src, size_t src_len, uint8_t *dst, size_t dst_len);

#endif
