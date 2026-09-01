/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "base58.h"
#include "token.h"

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static uint16_t get16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* CRC-32 (IEEE), just to catch transcription typos, not for security. */
static uint32_t crc32(const uint8_t *data, size_t len)
{
	uint32_t c = 0xffffffffu;
	size_t i;
	int k;

	for (i = 0; i < len; i++) {
		c ^= data[i];
		for (k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320u & (uint32_t)(-(int32_t)(c & 1)));
	}
	return ~c;
}

static void payload_pack(const struct token *tok, uint8_t *raw)
{
	size_t o = 0;

	raw[o++] = tok->version;
	raw[o++] = tok->flags;
	memcpy(&raw[o], tok->rdv, TOKEN_RDV_LEN);
	o += TOKEN_RDV_LEN;
	memcpy(&raw[o], tok->auth, TOKEN_AUTH_LEN);
	o += TOKEN_AUTH_LEN;
	memcpy(&raw[o], tok->hostpub, TOKEN_HOSTPUB_LEN);
	o += TOKEN_HOSTPUB_LEN;
	memcpy(&raw[o], tok->ep6_addr, TOKEN_EP6_LEN);
	o += TOKEN_EP6_LEN;
	put16(&raw[o], tok->ep6_port);
	o += 2;
	memcpy(&raw[o], tok->ep4_addr, TOKEN_EP4_LEN);
	o += TOKEN_EP4_LEN;
	put16(&raw[o], tok->ep4_port);
}

static void payload_unpack(struct token *tok, const uint8_t *raw)
{
	size_t o = 0;

	tok->version = raw[o++];
	tok->flags = raw[o++];
	memcpy(tok->rdv, &raw[o], TOKEN_RDV_LEN);
	o += TOKEN_RDV_LEN;
	memcpy(tok->auth, &raw[o], TOKEN_AUTH_LEN);
	o += TOKEN_AUTH_LEN;
	memcpy(tok->hostpub, &raw[o], TOKEN_HOSTPUB_LEN);
	o += TOKEN_HOSTPUB_LEN;
	memcpy(tok->ep6_addr, &raw[o], TOKEN_EP6_LEN);
	o += TOKEN_EP6_LEN;
	tok->ep6_port = get16(&raw[o]);
	o += 2;
	memcpy(tok->ep4_addr, &raw[o], TOKEN_EP4_LEN);
	o += TOKEN_EP4_LEN;
	tok->ep4_port = get16(&raw[o]);
}

int token_encode(const struct token *tok, char *dest, size_t dest_len)
{
	uint8_t wire[TOKEN_WIRE_LEN];
	char tmp[TOKEN_STR_LEN + 1];
	uint32_t sum;
	size_t n, pad;

	payload_pack(tok, wire);
	sum = crc32(wire, TOKEN_RAW_LEN);
	put16(&wire[TOKEN_RAW_LEN], (uint16_t)(sum >> 16));
	put16(&wire[TOKEN_RAW_LEN + 2], (uint16_t)sum);

	n = base58_encode(wire, sizeof(wire), tmp, sizeof(tmp));
	if (!n || n > TOKEN_STR_LEN || dest_len < TOKEN_STR_LEN + 1)
		return -1;

	pad = TOKEN_STR_LEN - n;
	memset(dest, '1', pad);
	memcpy(dest + pad, tmp, n);
	dest[TOKEN_STR_LEN] = '\0';
	return 0;
}

int token_decode(struct token *tok, const char *src)
{
	uint8_t wire[TOKEN_WIRE_LEN];
	uint32_t sum, want;

	/* Fixed length: a truncated or padded-wrong token is rejected here. */
	if (strlen(src) != TOKEN_STR_LEN)
		return -1;
	if (base58_decode(src, TOKEN_STR_LEN, wire, sizeof(wire)) != (int)TOKEN_WIRE_LEN)
		return -1;

	sum = crc32(wire, TOKEN_RAW_LEN);
	want = (uint32_t)get16(&wire[TOKEN_RAW_LEN]) << 16 | get16(&wire[TOKEN_RAW_LEN + 2]);
	if (sum != want)
		return -1;
	if (wire[0] != TOKEN_VERSION)
		return TOKEN_ERR_VERSION;

	payload_unpack(tok, wire);
	return 0;
}

/*
 * The per-family state lives in the family's slot plus its two flag bits, and
 * is read and written here alone so the encoding has exactly one home.
 */
int token_family_state(const struct token *tok, int family)
{
	const uint8_t *a = family == 6 ? tok->ep6_addr : tok->ep4_addr;
	size_t n = family == 6 ? TOKEN_EP6_LEN : TOKEN_EP4_LEN;
	uint8_t rdv = family == 6 ? TOKEN_FLAG_EP6_RDV : TOKEN_FLAG_EP4_RDV;
	uint8_t set = family == 6 ? TOKEN_FLAG_EP6_SETTLED :
				    TOKEN_FLAG_EP4_SETTLED;
	size_t i;

	for (i = 0; i < n; i++)
		if (a[i])
			return (tok->flags & rdv) ? TOKEN_STATE_RENDEZVOUS :
						    TOKEN_STATE_DIRECT;
	return (tok->flags & set) ? TOKEN_STATE_NONE : TOKEN_STATE_PENDING;
}

void token_set_family(struct token *tok, int family, int state,
		      const uint8_t *addr, uint16_t port)
{
	uint8_t *a = family == 6 ? tok->ep6_addr : tok->ep4_addr;
	uint16_t *p = family == 6 ? &tok->ep6_port : &tok->ep4_port;
	size_t n = family == 6 ? TOKEN_EP6_LEN : TOKEN_EP4_LEN;
	uint8_t rdv = family == 6 ? TOKEN_FLAG_EP6_RDV : TOKEN_FLAG_EP4_RDV;
	uint8_t set = family == 6 ? TOKEN_FLAG_EP6_SETTLED :
				    TOKEN_FLAG_EP4_SETTLED;

	tok->flags &= (uint8_t)~(rdv | set);
	if (state == TOKEN_STATE_RENDEZVOUS || state == TOKEN_STATE_DIRECT) {
		memcpy(a, addr, n);
		*p = port;
		tok->flags |= set;
		if (state == TOKEN_STATE_RENDEZVOUS)
			tok->flags |= rdv;
	} else {
		memset(a, 0, n);
		*p = 0;
		if (state == TOKEN_STATE_NONE)
			tok->flags |= set;
	}
}
