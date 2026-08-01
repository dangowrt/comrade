#include <stdio.h>
#include <string.h>

#include "bencode.h"

void benc_buf_init(struct benc_buf *b, uint8_t *buf, size_t cap)
{
	b->buf = buf;
	b->len = 0;
	b->cap = cap;
	b->err = 0;
}

void benc_raw_add(struct benc_buf *b, const void *data, size_t len)
{
	if (b->err || b->cap - b->len < len) {
		b->err = 1;
		return;
	}
	memcpy(b->buf + b->len, data, len);
	b->len += len;
}

void benc_str_add(struct benc_buf *b, const void *data, size_t len)
{
	char hdr[24];
	int n = snprintf(hdr, sizeof(hdr), "%zu:", len);

	benc_raw_add(b, hdr, (size_t)n);
	benc_raw_add(b, data, len);
}

void benc_int_add(struct benc_buf *b, int64_t val)
{
	char num[32];
	int n = snprintf(num, sizeof(num), "i%llde", (long long)val);

	benc_raw_add(b, num, (size_t)n);
}

void benc_key_add(struct benc_buf *b, const char *key)
{
	benc_str_add(b, key, strlen(key));
}

static int benc_digits(const uint8_t **p, const uint8_t *end, int64_t *out)
{
	int64_t val = 0;
	int digits = 0;

	while (*p < end && **p >= '0' && **p <= '9') {
		if (val > (INT64_MAX - 9) / 10)
			return -1;
		val = val * 10 + (**p - '0');
		(*p)++;
		digits++;
	}
	if (!digits)
		return -1;
	*out = val;
	return 0;
}

static int benc_skip_depth(const uint8_t **p, const uint8_t *end, int depth)
{
	int64_t num;

	if (depth > BENC_MAX_DEPTH)
		return -1;
	if (*p >= end)
		return -1;

	switch (**p) {
	case 'i':
		(*p)++;
		if (*p < end && **p == '-')
			(*p)++;
		if (benc_digits(p, end, &num))
			return -1;
		if (*p >= end || **p != 'e')
			return -1;
		(*p)++;
		return 0;
	case 'l':
	case 'd':
		(*p)++;
		while (*p < end && **p != 'e') {
			if (benc_skip_depth(p, end, depth + 1))
				return -1;
		}
		if (*p >= end)
			return -1;
		(*p)++;
		return 0;
	default:
		if (benc_digits(p, end, &num))
			return -1;
		if (*p >= end || **p != ':' || end - *p - 1 < num)
			return -1;
		*p += 1 + num;
		return 0;
	}
}

int benc_skip(const uint8_t **p, const uint8_t *end)
{
	return benc_skip_depth(p, end, 0);
}

int benc_dict_find(const uint8_t *dict, size_t dict_len, const char *key,
		   const uint8_t **val, size_t *val_len)
{
	const uint8_t *p = dict, *end = dict + dict_len;
	size_t key_len = strlen(key);

	if (p >= end || *p != 'd')
		return -1;
	p++;

	while (p < end && *p != 'e') {
		const uint8_t *k, *v;
		size_t k_len;
		const uint8_t *kstart = p;

		if (benc_skip(&p, end))
			return -1;
		if (benc_str_get(kstart, (size_t)(p - kstart), &k, &k_len))
			return -1;
		v = p;
		if (benc_skip(&p, end))
			return -1;
		if (k_len == key_len && !memcmp(k, key, key_len)) {
			*val = v;
			*val_len = (size_t)(p - v);
			return 0;
		}
	}
	return -1;
}

int benc_str_get(const uint8_t *val, size_t val_len,
		 const uint8_t **data, size_t *data_len)
{
	const uint8_t *p = val, *end = val + val_len;
	int64_t num;

	if (benc_digits(&p, end, &num))
		return -1;
	if (p >= end || *p != ':' || end - p - 1 < num)
		return -1;
	*data = p + 1;
	*data_len = (size_t)num;
	return 0;
}

int benc_int_get(const uint8_t *val, size_t val_len, int64_t *out)
{
	const uint8_t *p = val, *end = val + val_len;
	int neg = 0;
	int64_t num;

	if (p >= end || *p != 'i')
		return -1;
	p++;
	if (p < end && *p == '-') {
		neg = 1;
		p++;
	}
	if (benc_digits(&p, end, &num))
		return -1;
	if (p >= end || *p != 'e')
		return -1;
	*out = neg ? -num : num;
	return 0;
}
