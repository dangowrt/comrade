/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_TOKEN_H
#define COMRADE_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#define TOKEN_VERSION		2

#define TOKEN_RDV_LEN		16
#define TOKEN_AUTH_LEN		16
#define TOKEN_HOSTPUB_LEN	32
#define TOKEN_EP6_LEN		16
#define TOKEN_EP4_LEN		4

/*
 * Fixed 90-byte payload:
 *
 *   ver(1) flags(1) R(16) A(16) hostpub(32)
 *   ep6_addr(16) ep6_port(2) ep4_addr(4) ep4_port(2)
 *
 * R is the rendezvous secret, A the session auth secret, hostpub the SHA-256
 * fingerprint of the host's ephemeral SSH key (the client pins it, so there
 * is no trust-on-first-use).
 *
 * The two endpoint slots (v6, v4) are per-family, and a slot together with
 * that family's EPx_RDV and EPx_SETTLED bits carries one of four states:
 *   - PENDING (slot all-zero, SETTLED clear): the host has not finished
 *     working this family out.
 *   - NONE (slot all-zero, SETTLED set): this family has no path to the DHT,
 *     so it is reachable over link-local discovery alone.
 *   - RENDEZVOUS (slot set, RDV set): a DHT node holding the host's mailbox
 *     for that family, like a tracker address in a magnet URI. The client
 *     queries it directly for a fast lookup-free rendezvous while the host's
 *     own address stays out of the token, which is the right posture for a
 *     NATed host (it cannot be reached directly from a one-way token; the
 *     client's address must reach it through the two-way DHT/mcast mailbox).
 *   - DIRECT (slot set, RDV clear): the host's own endpoint, proven reachable
 *     from outside, which lets the client connect server-model with no punch
 *     and the DHT untouched.
 * The families are wholly independent, because a host is commonly reachable
 * over one and not the other. The state is advisory: R alone always suffices,
 * so the host re-mints as its situation changes and an already-copied token
 * is a snapshot that is never wrong, only sometimes slower.
 *
 * A CRC-32 over the payload is appended (wire form) so any transcription
 * typo is caught instantly on decode, before any network use. The wire form
 * is base58 encoded and left-padded with the zero digit '1' to a constant
 * width, so every token string is exactly TOKEN_STR_LEN characters: a human
 * and a parser can both see at a glance when a token is complete.
 */
#define TOKEN_RAW_LEN		(2 + TOKEN_RDV_LEN + TOKEN_AUTH_LEN + \
				 TOKEN_HOSTPUB_LEN + \
				 (TOKEN_EP6_LEN + 2) + (TOKEN_EP4_LEN + 2))
#define TOKEN_SUM_LEN		4
#define TOKEN_WIRE_LEN		(TOKEN_RAW_LEN + TOKEN_SUM_LEN)
/* base58 expands by at most log(256)/log(58) < 1.38, plus a pad char. */
#define TOKEN_STR_LEN		(TOKEN_WIRE_LEN * 138 / 100 + 1)

#define TOKEN_FLAG_RO		0x01	/* read-only credential */
#define TOKEN_FLAG_NODHT	0x02	/* reserved, never set: no token state tells a peer to drop a transport */
#define TOKEN_FLAG_EP6_RDV	0x04	/* ep6 slot is a rendezvous DHT node, not a direct endpoint */
#define TOKEN_FLAG_EP4_RDV	0x08	/* ep4 slot is a rendezvous DHT node, not a direct endpoint */
#define TOKEN_FLAG_EP6_SETTLED	0x10	/* the v6 family's state is determined, not still being worked out */
#define TOKEN_FLAG_EP4_SETTLED	0x20	/* likewise for v4 */

enum token_state {
	TOKEN_STATE_PENDING,
	TOKEN_STATE_NONE,
	TOKEN_STATE_RENDEZVOUS,
	TOKEN_STATE_DIRECT
};

struct token {
	uint8_t version;
	uint8_t flags;
	uint8_t rdv[TOKEN_RDV_LEN];
	uint8_t auth[TOKEN_AUTH_LEN];
	uint8_t hostpub[TOKEN_HOSTPUB_LEN];
	uint8_t ep6_addr[TOKEN_EP6_LEN];
	uint16_t ep6_port;
	uint8_t ep4_addr[TOKEN_EP4_LEN];
	uint16_t ep4_port;
};

int token_encode(const struct token *tok, char *dest, size_t dest_len);
/*
 * Returns 0, or TOKEN_ERR_VERSION for a well-formed token of a version this
 * build does not speak, or -1 for anything else. The version is worth telling
 * apart because everything else a decode rejects is a typo, and this one is
 * not: the string is intact and the other end simply derives different keys
 * from it, which without a word here shows up much later as a punch that
 * never completes.
 */
#define TOKEN_ERR_VERSION (-2)
int token_decode(struct token *tok, const char *src);

/*
 * The TOKEN_STATE_* one family (4 or 6) carries. A set slot with SETTLED clear
 * does not occur, and is read as settled, so a token minted before the SETTLED
 * bits existed still reads as the DIRECT or RENDEZVOUS it was.
 */
int token_family_state(const struct token *tok, int family);

/*
 * Write one family's state into its slot. `addr` is that family's address
 * bytes (TOKEN_EP4_LEN or TOKEN_EP6_LEN) and `port` is in host byte order;
 * both are read only for the two states that carry an address, so a caller
 * with none to give may pass anything.
 */
void token_set_family(struct token *tok, int family, int state,
		      const uint8_t *addr, uint16_t port);

#endif
