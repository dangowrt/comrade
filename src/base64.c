#include "base64.h"

static const char b64url_alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t base64url_encode(const uint8_t *src, size_t src_len, char *dest, size_t dest_len)
{
	size_t rem = src_len % 3;
	size_t need = src_len / 3 * 4 + (rem ? rem + 1 : 0) + 1;
	size_t i, o = 0;
	uint32_t v;

	if (dest_len < need)
		return 0;

	for (i = 0; i + 3 <= src_len; i += 3) {
		v = (uint32_t)src[i] << 16 | (uint32_t)src[i + 1] << 8 | src[i + 2];
		dest[o++] = b64url_alphabet[v >> 18];
		dest[o++] = b64url_alphabet[v >> 12 & 63];
		dest[o++] = b64url_alphabet[v >> 6 & 63];
		dest[o++] = b64url_alphabet[v & 63];
	}
	if (rem) {
		v = (uint32_t)src[i] << 16;
		if (rem == 2)
			v |= (uint32_t)src[i + 1] << 8;
		dest[o++] = b64url_alphabet[v >> 18];
		dest[o++] = b64url_alphabet[v >> 12 & 63];
		if (rem == 2)
			dest[o++] = b64url_alphabet[v >> 6 & 63];
	}
	dest[o] = '\0';
	return o;
}

static int b64url_value(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '-')
		return 62;
	if (c == '_')
		return 63;
	return -1;
}

int base64url_decode(const char *src, size_t src_len, uint8_t *dest, size_t dest_len)
{
	size_t i, o = 0;
	uint32_t v = 0;
	int bits = 0, d;

	if (src_len % 4 == 1)
		return -1;

	for (i = 0; i < src_len; i++) {
		d = b64url_value((unsigned char)src[i]);
		if (d < 0)
			return -1;
		v = v << 6 | (uint32_t)d;
		bits += 6;
		if (bits < 8)
			continue;
		bits -= 8;
		if (o >= dest_len)
			return -1;
		dest[o++] = (uint8_t)(v >> bits);
	}
	if (v & ((1u << bits) - 1))
		return -1;
	return (int)o;
}
