/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_BASE64_H
#define COMRADE_BASE64_H

#include <stddef.h>
#include <stdint.h>

size_t base64url_encode(const uint8_t *src, size_t src_len, char *dest, size_t dest_len);
/* Standard alphabet, '=' padded (RFC 4648 section 4): what OSC 52 carries. */
size_t base64_encode(const uint8_t *src, size_t src_len, char *dest, size_t dest_len);
int base64url_decode(const char *src, size_t src_len, uint8_t *dest, size_t dest_len);

#endif
