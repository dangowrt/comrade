/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <string.h>

#include "base58.h"
#include "token.h"

static void base58_fixed_roundtrip_check(void)
{
	uint8_t in[TOKEN_WIRE_LEN], out[TOKEN_WIRE_LEN];
	char enc[TOKEN_STR_LEN + 1];
	size_t i, elen, pad;

	/* Max value must still fit inside the fixed width. */
	memset(in, 0xff, sizeof(in));
	elen = base58_encode(in, sizeof(in), enc, sizeof(enc));
	assert(elen > 0 && elen <= TOKEN_STR_LEN);

	for (i = 0; i < sizeof(in); i++)
		in[i] = (uint8_t)(i * 37 + 11);
	elen = base58_encode(in, sizeof(in), enc, sizeof(enc));
	assert(elen > 0 && elen <= TOKEN_STR_LEN);

	/* Left-pad with the zero digit '1' and decode back to the fixed width. */
	pad = TOKEN_STR_LEN - elen;
	memmove(enc + pad, enc, elen + 1);
	memset(enc, '1', pad);
	assert(base58_decode(enc, TOKEN_STR_LEN, out, sizeof(out)) == (int)sizeof(out));
	assert(!memcmp(in, out, sizeof(in)));
}

static void base58_reject_check(void)
{
	uint8_t out[16];

	assert(base58_decode("0", 1, out, sizeof(out)) < 0);   /* 0 not in set */
	assert(base58_decode("O", 1, out, sizeof(out)) < 0);
	assert(base58_decode("I", 1, out, sizeof(out)) < 0);
	assert(base58_decode("l", 1, out, sizeof(out)) < 0);
	assert(base58_decode("A B", 3, out, sizeof(out)) < 0); /* space */
}

static void token_fill(struct token *tok)
{
	size_t i;

	tok->version = TOKEN_VERSION;
	tok->flags = TOKEN_FLAG_RO | TOKEN_FLAG_NODHT;
	for (i = 0; i < TOKEN_RDV_LEN; i++)
		tok->rdv[i] = (uint8_t)(i * 7 + 1);
	for (i = 0; i < TOKEN_AUTH_LEN; i++)
		tok->auth[i] = (uint8_t)(i * 13 + 5);
	for (i = 0; i < TOKEN_HOSTPUB_LEN; i++)
		tok->hostpub[i] = (uint8_t)(255 - i);
	for (i = 0; i < TOKEN_EP6_LEN; i++)
		tok->ep6_addr[i] = (uint8_t)(0x20 + i);
	tok->ep6_port = 45678;
	for (i = 0; i < TOKEN_EP4_LEN; i++)
		tok->ep4_addr[i] = (uint8_t)(192 - i);
	tok->ep4_port = 51820;
}

static void token_roundtrip_check(void)
{
	struct token in, out;
	char str[TOKEN_STR_LEN + 1];
	size_t i;

	token_fill(&in);
	assert(token_encode(&in, str, sizeof(str)) == 0);
	/* Always exactly TOKEN_STR_LEN, and no ambiguous glyphs. */
	assert(strlen(str) == TOKEN_STR_LEN);
	for (i = 0; str[i]; i++)
		assert(str[i] != '0' && str[i] != 'O' &&
		       str[i] != 'I' && str[i] != 'l');
	assert(token_decode(&out, str) == 0);
	assert(out.version == in.version && out.flags == in.flags);
	assert(!memcmp(out.rdv, in.rdv, TOKEN_RDV_LEN));
	assert(!memcmp(out.auth, in.auth, TOKEN_AUTH_LEN));
	assert(!memcmp(out.hostpub, in.hostpub, TOKEN_HOSTPUB_LEN));
	assert(!memcmp(out.ep6_addr, in.ep6_addr, TOKEN_EP6_LEN));
	assert(out.ep6_port == in.ep6_port);
	assert(!memcmp(out.ep4_addr, in.ep4_addr, TOKEN_EP4_LEN));
	assert(out.ep4_port == in.ep4_port);
}

static void token_typo_check(void)
{
	struct token in, out;
	char str[TOKEN_STR_LEN + 1];
	size_t i, caught = 0;

	token_fill(&in);
	assert(token_encode(&in, str, sizeof(str)) == 0);

	/* Every single-character substitution is caught by the checksum
	 * (or is an invalid character); none decodes to a valid token. */
	for (i = 0; i < TOKEN_STR_LEN; i++) {
		char orig = str[i];
		char sub = orig == 'z' ? 'y' : 'z';

		str[i] = sub;
		if (token_decode(&out, str) < 0)
			caught++;
		str[i] = orig;
	}
	assert(caught == TOKEN_STR_LEN);
}

/* Every kind of token: all flag combinations (ro, nodht, per-family
 * direct/rendezvous) crossed with endpoint presence (none, v6-only, v4-only,
 * dual). Each must round-trip exactly, stay the fixed width, avoid ambiguous
 * glyphs, and keep its checksum live. */
static void token_kinds_check(void)
{
	struct token in, out;
	char str[TOKEN_STR_LEN + 1];
	unsigned flags;
	int ep6p, ep4p;
	size_t i;

	for (flags = 0; flags < 16; flags++)
		for (ep6p = 0; ep6p <= 1; ep6p++)
			for (ep4p = 0; ep4p <= 1; ep4p++) {
				memset(&in, 0, sizeof(in));
				in.version = TOKEN_VERSION;
				in.flags = (uint8_t)flags;
				for (i = 0; i < TOKEN_RDV_LEN; i++)
					in.rdv[i] = (uint8_t)(i + flags);
				for (i = 0; i < TOKEN_AUTH_LEN; i++)
					in.auth[i] = (uint8_t)(i * 3 + ep6p);
				for (i = 0; i < TOKEN_HOSTPUB_LEN; i++)
					in.hostpub[i] = (uint8_t)(i * 5 + ep4p);
				if (ep6p) {
					for (i = 0; i < TOKEN_EP6_LEN; i++)
						in.ep6_addr[i] = (uint8_t)(0x20 + i);
					in.ep6_port = 45678;
				}
				if (ep4p) {
					for (i = 0; i < TOKEN_EP4_LEN; i++)
						in.ep4_addr[i] = (uint8_t)(192 - i);
					in.ep4_port = 51820;
				}

				assert(token_encode(&in, str, sizeof(str)) == 0);
				assert(strlen(str) == TOKEN_STR_LEN);
				for (i = 0; str[i]; i++)
					assert(str[i] != '0' && str[i] != 'O' &&
					       str[i] != 'I' && str[i] != 'l');

				assert(token_decode(&out, str) == 0);
				assert(out.version == in.version);
				assert(out.flags == in.flags);
				assert(!memcmp(out.rdv, in.rdv, TOKEN_RDV_LEN));
				assert(!memcmp(out.auth, in.auth, TOKEN_AUTH_LEN));
				assert(!memcmp(out.hostpub, in.hostpub,
					       TOKEN_HOSTPUB_LEN));
				assert(!memcmp(out.ep6_addr, in.ep6_addr,
					       TOKEN_EP6_LEN));
				assert(out.ep6_port == in.ep6_port);
				assert(!memcmp(out.ep4_addr, in.ep4_addr,
					       TOKEN_EP4_LEN));
				assert(out.ep4_port == in.ep4_port);

				/* the checksum is live for this kind too */
				str[TOKEN_STR_LEN - 1] =
					str[TOKEN_STR_LEN - 1] == 'z' ? 'y' : 'z';
				assert(token_decode(&out, str) < 0);
			}
}

static void token_reject_check(void)
{
	struct token in, out;
	char str[TOKEN_STR_LEN + 1];
	char small[TOKEN_STR_LEN];

	token_fill(&in);
	assert(token_encode(&in, small, sizeof(small)) < 0);   /* buffer too small */
	assert(token_encode(&in, str, sizeof(str)) == 0);
	assert(token_decode(&out, "") < 0);                    /* empty */
	assert(token_decode(&out, str + 1) < 0);               /* short by one */
}

int main(void)
{
	base58_fixed_roundtrip_check();
	base58_reject_check();
	token_roundtrip_check();
	token_kinds_check();
	token_typo_check();
	token_reject_check();
	return 0;
}
