/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <string.h>

#include "base58.h"
#include "token.h"

static void base58_roundtrip_check(void)
{
	uint8_t in[80], out[80];
	char enc[128];
	size_t i, len, elen;
	int dlen;

	for (len = 1; len <= sizeof(in); len++) {
		for (i = 0; i < len; i++)
			in[i] = (uint8_t)(i * 37 + 11);
		elen = base58_encode(in, len, enc, sizeof(enc));
		assert(elen > 0);
		dlen = base58_decode(enc, elen, out, sizeof(out));
		assert(dlen == (int)len && !memcmp(in, out, len));
	}
}

static void base58_alphabet_check(void)
{
	uint8_t in[66], out[66];
	char enc[128];
	size_t i, elen;

	for (i = 0; i < sizeof(in); i++)
		in[i] = (uint8_t)(i * 53 + 7);
	elen = base58_encode(in, sizeof(in), enc, sizeof(enc));
	assert(elen > 0);
	/* No ambiguous glyphs and no punctuation, ever. */
	for (i = 0; i < elen; i++) {
		char c = enc[i];

		assert(c != '0' && c != 'O' && c != 'I' && c != 'l');
		assert((c >= '1' && c <= '9') || (c >= 'A' && c <= 'Z') ||
		       (c >= 'a' && c <= 'z'));
	}
	assert(base58_decode(enc, elen, out, sizeof(out)) == (int)sizeof(in));
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
	assert(base58_decode("zzzz", 4, out, 1) < 0);          /* dst too small */
}

static void token_fill(struct token *tok)
{
	size_t i;

	tok->version = TOKEN_VERSION;
	tok->flags = TOKEN_FLAG_RO;
	for (i = 0; i < TOKEN_RDV_LEN; i++)
		tok->rdv[i] = (uint8_t)(i * 7 + 1);
	for (i = 0; i < TOKEN_AUTH_LEN; i++)
		tok->auth[i] = (uint8_t)(i * 13 + 5);
	for (i = 0; i < TOKEN_HOSTPUB_LEN; i++)
		tok->hostpub[i] = (uint8_t)(255 - i);
}

static void token_roundtrip_check(void)
{
	struct token in, out;
	char str[TOKEN_STR_MAX + 1];

	token_fill(&in);
	assert(token_encode(&in, str, sizeof(str)) == 0);
	assert(strlen(str) <= TOKEN_STR_MAX);
	assert(token_decode(&out, str) == 0);
	assert(out.version == in.version);
	assert(out.flags == in.flags);
	assert(!memcmp(out.rdv, in.rdv, TOKEN_RDV_LEN));
	assert(!memcmp(out.auth, in.auth, TOKEN_AUTH_LEN));
	assert(!memcmp(out.hostpub, in.hostpub, TOKEN_HOSTPUB_LEN));
}

static void token_reject_check(void)
{
	struct token in, out;
	char str[TOKEN_STR_MAX + 1];
	char tiny[4];

	token_fill(&in);
	assert(token_encode(&in, tiny, sizeof(tiny)) < 0);
	assert(token_encode(&in, str, sizeof(str)) == 0);
	assert(token_decode(&out, "") < 0);
	assert(token_decode(&out, str + 1) < 0);
	str[0] = str[0] == 'z' ? 'y' : 'z';
	assert(token_decode(&out, str) < 0);
}

int main(void)
{
	base58_roundtrip_check();
	base58_alphabet_check();
	base58_reject_check();
	token_roundtrip_check();
	token_reject_check();
	return 0;
}
