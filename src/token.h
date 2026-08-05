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
 * The endpoints are the host's own self-discovered reachable addresses (all
 * zero when a family is unavailable), letting a joiner connect without the
 * DHT by default. The token is one-way (host generates, client uses), so it
 * only ever carries the host's addresses; the host learns the client's from
 * the incoming connection.
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
#define TOKEN_FLAG_NODHT	0x02	/* host is not on the DHT; do not query it */

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
