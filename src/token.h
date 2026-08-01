#ifndef COMRADE_TOKEN_H
#define COMRADE_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#define TOKEN_VERSION		1

#define TOKEN_RDV_LEN		16
#define TOKEN_AUTH_LEN		16
#define TOKEN_HOSTPUB_LEN	32
#define TOKEN_RAW_LEN		(2 + TOKEN_RDV_LEN + TOKEN_AUTH_LEN + TOKEN_HOSTPUB_LEN)
#define TOKEN_STR_LEN		(TOKEN_RAW_LEN / 3 * 4)

#define TOKEN_FLAG_RO		0x01

struct token {
	uint8_t version;
	uint8_t flags;
	uint8_t rdv[TOKEN_RDV_LEN];
	uint8_t auth[TOKEN_AUTH_LEN];
	uint8_t hostpub[TOKEN_HOSTPUB_LEN];
};

int token_encode(const struct token *tok, char *dest, size_t dest_len);
int token_decode(struct token *tok, const char *src);

#endif
