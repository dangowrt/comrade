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
	/*
	 * What this session's datagrams open with. A constant here would be the
	 * same four bytes in every build, so every comrade datagram anywhere
	 * would announce itself at offset 0 and one stateless rule would drop
	 * all of them at line rate, with no flow state and no false positives.
	 * For a tool whose whole purpose is reaching your own machine from
	 * wherever you are, that is the cheapest possible thing to take away.
	 *
	 * Derived from the same secret the sealing key comes from, so both ends
	 * agree without another exchange, and forced apart from each other so
	 * the demux that tells a probe from stream data still works.
	 */
	uint32_t probe_magic;
	uint32_t conv;
};

int keys_derive(struct session_keys *keys, const uint8_t rdv[TOKEN_RDV_LEN]);
void keys_derive_ro_auth(uint8_t ro[TOKEN_AUTH_LEN],
			 const uint8_t rw[TOKEN_AUTH_LEN]);
int msg_seal(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *plain, size_t plain_len);
int msg_open(uint8_t *dst, size_t dst_len, const uint8_t key[32],
	     const uint8_t *sealed, size_t sealed_len);

/*
 * The same, with a header the sender wants bound to the ciphertext without
 * hiding it: the AEAD covers `ad` even though it stays in the clear, so a
 * frame relabelled in transit no longer opens. Used where framing outside the
 * seal decides what the plaintext means -- the multicast slot a value belongs
 * to, for one, which decides whether a description is read as an offer or an
 * answer.
 */
int msg_seal_ad(uint8_t *dst, size_t dst_len, const uint8_t key[32],
		const uint8_t *ad, size_t ad_len,
		const uint8_t *plain, size_t plain_len);
int msg_open_ad(uint8_t *dst, size_t dst_len, const uint8_t key[32],
		const uint8_t *ad, size_t ad_len,
		const uint8_t *sealed, size_t sealed_len);
int random_bytes(void *buf, size_t len);

#endif
