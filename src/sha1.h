#ifndef COMRADE_SHA1_H
#define COMRADE_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_LEN 20

struct sha1_ctx {
	uint32_t h[5];
	uint64_t len;
	uint8_t buf[64];
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const void *data, size_t len);
void sha1_final(struct sha1_ctx *ctx, uint8_t digest[SHA1_LEN]);
void sha1(uint8_t digest[SHA1_LEN], const void *data, size_t len);

#endif
