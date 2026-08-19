/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SHA1_H
#define COMRADE_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_LEN 20

struct cc_sha1_ctx {
	uint32_t h[5];
	uint64_t len;
	uint8_t buf[64];
};

void cc_sha1_init(struct cc_sha1_ctx *ctx);
void cc_sha1_update(struct cc_sha1_ctx *ctx, const void *data, size_t len);
void cc_sha1_final(struct cc_sha1_ctx *ctx, uint8_t digest[SHA1_LEN]);
void cc_sha1(uint8_t digest[SHA1_LEN], const void *data, size_t len);

#endif
