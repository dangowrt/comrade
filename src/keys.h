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
	/*
	 * The port this session's link-local announcements meet on. A fixed one
	 * puts every comrade session on a segment into the same conversation:
	 * each hears every other's announcements, opens none of them, and pays
	 * for all of them -- and a busy segment is exactly where a lab runs
	 * several at once. Derived, so two sessions share a port only by the
	 * same accident that would have them share a key.
	 */
	uint16_t mcast_port;
};

#define KEYS_HALF_LEN 32

int keys_derive(struct session_keys *keys, const uint8_t rdv[TOKEN_RDV_LEN]);
/*
 * The key one connection's probes are sealed under: the session key, which
 * says a token holder is speaking, and a random half from each end, which says
 * which two. The halves travel inside the SSH session, so a third token holder
 * never sees them and cannot reach a connection it is not part of -- what the
 * token alone buys is the right to start one.
 *
 * The halves are ordered by value rather than by role, so both ends compute
 * the same key with neither being the one that decides.
 */
void keys_conn_key(uint8_t out[32], const uint8_t sig_key[32],
		   const uint8_t a[KEYS_HALF_LEN],
		   const uint8_t b[KEYS_HALF_LEN]);
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
/*
 * Seal to a recipient rather than to a shared secret.
 *
 * A claim in the mailbox names where a peer is, and the mailbox is read by
 * every holder of the invitation -- which, for a read-only link handed to a
 * room, is a crowd with no reason to trust each other. So a claim is boxed to
 * a key the host publishes in its own slot and whose secret half it alone
 * holds: the outer seal still says a token holder wrote the slot, and this
 * says only the host may read it.
 *
 *   box = [ephemeral public key 32][tag 16][ciphertext]
 *
 * The key is derived from the agreement and both public keys, so it is fresh
 * for every box and belongs to exactly one recipient; the nonce is therefore
 * fixed and costs nothing to carry.
 */
#define BOX_OVERHEAD (32 + 16)

int box_seal(uint8_t *dst, size_t dst_len, const uint8_t pk[32],
	     const uint8_t *plain, size_t plain_len);
int box_open(uint8_t *dst, size_t dst_len, const uint8_t sk[32],
	     const uint8_t *sealed, size_t sealed_len);

int random_bytes(void *buf, size_t len);

#endif
