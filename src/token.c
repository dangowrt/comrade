#include <string.h>

#include "base64.h"
#include "token.h"

int token_encode(const struct token *tok, char *dest, size_t dest_len)
{
	uint8_t raw[TOKEN_RAW_LEN];

	raw[0] = tok->version;
	raw[1] = tok->flags;
	memcpy(&raw[2], tok->rdv, TOKEN_RDV_LEN);
	memcpy(&raw[2 + TOKEN_RDV_LEN], tok->auth, TOKEN_AUTH_LEN);
	memcpy(&raw[2 + TOKEN_RDV_LEN + TOKEN_AUTH_LEN], tok->hostpub, TOKEN_HOSTPUB_LEN);

	if (base64url_encode(raw, sizeof(raw), dest, dest_len) != TOKEN_STR_LEN)
		return -1;

	return 0;
}

int token_decode(struct token *tok, const char *src)
{
	uint8_t raw[TOKEN_RAW_LEN];
	size_t len = strlen(src);

	if (len != TOKEN_STR_LEN)
		return -1;
	if (base64url_decode(src, len, raw, sizeof(raw)) != TOKEN_RAW_LEN)
		return -1;
	if (raw[0] != TOKEN_VERSION)
		return -1;

	tok->version = raw[0];
	tok->flags = raw[1];
	memcpy(tok->rdv, &raw[2], TOKEN_RDV_LEN);
	memcpy(tok->auth, &raw[2 + TOKEN_RDV_LEN], TOKEN_AUTH_LEN);
	memcpy(tok->hostpub, &raw[2 + TOKEN_RDV_LEN + TOKEN_AUTH_LEN], TOKEN_HOSTPUB_LEN);

	return 0;
}
