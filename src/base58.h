/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_BASE58_H
#define COMRADE_BASE58_H

#include <stddef.h>
#include <stdint.h>

/*
 * base58 (Bitcoin alphabet): compact, case-sensitive, and free of the
 * visually ambiguous glyphs 0 O I l, so a token transcribed from a photo
 * of a screen stays unambiguous. Letters and digits only (keymap-safe).
 */

#define BASE58_MAX_IN 160
#define BASE58_MAX_STR 256

size_t base58_encode(const uint8_t *src, size_t src_len, char *dst, size_t dst_len);
int base58_decode(const char *src, size_t src_len, uint8_t *dst, size_t dst_len);

#endif
