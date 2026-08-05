/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <string.h>

#include "base64.h"
#include "token.h"

static const struct {
	const char *raw;
	const char *encoded;
} b64_vectors[] = {
	{ "", "" },
	{ "f", "Zg" },
	{ "fo", "Zm8" },
	{ "foo", "Zm9v" },
	{ "foob", "Zm9vYg" },
	{ "fooba", "Zm9vYmE" },
	{ "foobar", "Zm9vYmFy" },
};

static void b64_vectors_check(void)
{
	char enc[16];
	uint8_t dec[16];
	size_t i, raw_len;

	for (i = 0; i < sizeof(b64_vectors) / sizeof(b64_vectors[0]); i++) {
		raw_len = strlen(b64_vectors[i].raw);
		assert(base64url_encode((const uint8_t *)b64_vectors[i].raw, raw_len,
					enc, sizeof(enc)) == strlen(b64_vectors[i].encoded));
		assert(!strcmp(enc, b64_vectors[i].encoded));
		assert(base64url_decode(b64_vectors[i].encoded,
					strlen(b64_vectors[i].encoded),
					dec, sizeof(dec)) == (int)raw_len);
		assert(!memcmp(dec, b64_vectors[i].raw, raw_len));
	}
}

static void b64_reject_check(void)
{
	uint8_t dec[8];
	char enc[8];

	assert(base64url_decode("A", 1, dec, sizeof(dec)) < 0);
	assert(base64url_decode("Zg!", 3, dec, sizeof(dec)) < 0);
	assert(base64url_decode("Zh", 2, dec, sizeof(dec)) < 0);
	assert(base64url_decode("Zm9v", 4, dec, 2) < 0);
	assert(base64url_encode((const uint8_t *)"foobar", 6, enc, sizeof(enc)) == 0);
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
	char str[TOKEN_STR_LEN + 1];

	token_fill(&in);
	assert(token_encode(&in, str, sizeof(str)) == 0);
	assert(strlen(str) == TOKEN_STR_LEN);
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
	char str[TOKEN_STR_LEN + 1];
	char small[TOKEN_STR_LEN];

	token_fill(&in);
	assert(token_encode(&in, small, sizeof(small)) < 0);
	assert(token_encode(&in, str, sizeof(str)) == 0);
	assert(token_decode(&out, "") < 0);
	assert(token_decode(&out, str + 1) < 0);
	str[0] = 'C';
	assert(token_decode(&out, str) < 0);
}

int main(void)
{
	b64_vectors_check();
	b64_reject_check();
	token_roundtrip_check();
	token_reject_check();
	return 0;
}
