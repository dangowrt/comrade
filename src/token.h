/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_TOKEN_H
#define COMRADE_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#define TOKEN_VERSION		1

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
 * The two endpoint slots (v6, v4) are per-family hints whose meaning is set
 * independently by the flags:
 *   - all-zero address: absent, nothing known for that family.
 *   - direct (EPx_RDV clear): the host's own reachable endpoint. A directly
 *     reachable host (public IP, permissive-firewall v6, or LAN) lets the
 *     client connect server-model with no punch and the DHT untouched.
 *   - rendezvous (EPx_RDV set): a DHT node holding the host's mailbox for
 *     that family, like a tracker address in a magnet URI. The client
 *     queries it directly for a fast lookup-free rendezvous while the host's
 *     own address stays out of the token, which is the right posture for a
 *     NATed host (it cannot be reached directly from a one-way token; the
 *     client's address must reach it through the two-way DHT/mcast mailbox).
 * The direct/rendezvous choice is one bit per family because a host is
 * commonly v6-direct and v4-rendezvous (or v4-absent) at the same time.
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
int token_decode(struct token *tok, const char *src);

#endif
