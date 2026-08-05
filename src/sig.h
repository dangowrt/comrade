/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SIG_H
#define COMRADE_SIG_H

#include <stddef.h>
#include <stdint.h>

#include "token.h"

struct sig_backend;

struct sig_ops {
	int (*open)(struct sig_backend *sb, const uint8_t rdv[TOKEN_RDV_LEN]);
	int (*put)(struct sig_backend *sb, const char *salt,
		   const uint8_t *val, size_t val_len);
	int (*get)(struct sig_backend *sb, const char *salt,
		   uint8_t *val, size_t *val_len);
	void (*close)(struct sig_backend *sb);
};

struct sig_backend {
	const struct sig_ops *ops;
};

struct sig_backend *sig_bep44_create(void);

#endif
