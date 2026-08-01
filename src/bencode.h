#ifndef COMRADE_BENCODE_H
#define COMRADE_BENCODE_H

#include <stddef.h>
#include <stdint.h>

#define BENC_MAX_DEPTH 16

struct benc_buf {
	uint8_t *buf;
	size_t len;
	size_t cap;
	int err;
};

void benc_buf_init(struct benc_buf *b, uint8_t *buf, size_t cap);
void benc_raw_add(struct benc_buf *b, const void *data, size_t len);
void benc_str_add(struct benc_buf *b, const void *data, size_t len);
void benc_int_add(struct benc_buf *b, int64_t val);
void benc_key_add(struct benc_buf *b, const char *key);

int benc_skip(const uint8_t **p, const uint8_t *end);
int benc_dict_find(const uint8_t *dict, size_t dict_len, const char *key,
		   const uint8_t **val, size_t *val_len);
int benc_str_get(const uint8_t *val, size_t val_len,
		 const uint8_t **data, size_t *data_len);
int benc_int_get(const uint8_t *val, size_t val_len, int64_t *out);

#endif
