/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_KEYS_H
#define COMRADE_KEYS_H

#include <stddef.h>
#include <stdint.h>

#include "token.h"

#define SEAL_OVERHEAD (24 + 16)

struct session_keys {
	uint8_t sig_key[32];
	uint8_t bep44_pk[32];
	uint8_t bep44_sk[64];
};

void keys_derive(struct session_keys *keys, const uint8_t rdv[TOKEN_RDV_LEN]);
int msg_seal(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *plain, size_t plain_len);
int msg_open(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *sealed, size_t sealed_len);
int random_bytes(void *buf, size_t len);

#endif
