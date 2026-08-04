#define _GNU_SOURCE
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>

#include "candpolicy.h"

void cand_policy_default(struct cand_policy *p)
{
	p->allow_private_v4 = 1;
	p->allow_ula = 0;
	p->allow_overlay = 0;
	p->allow_eui64 = 0;
	p->allow_linklocal = 0;
}

static int v6_keep(const uint8_t b[16], const struct cand_policy *p)
{
	static const uint8_t loopback[16] = { [15] = 1 };

	if (!memcmp(b, loopback, 16))
		return 0;
	if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
		return p->allow_linklocal;
	if ((b[0] & 0xfe) == 0xfc)
		return p->allow_ula;
	if ((b[0] & 0xfe) == 0x02)
		return p->allow_overlay;
	if ((b[0] & 0xe0) == 0x20) {
		if (b[11] == 0xff && b[12] == 0xfe && !p->allow_eui64)
			return 0;
		return 1;
	}
	return 0;
}

static int v4_keep(const uint8_t b[4], const struct cand_policy *p)
{
	if (b[0] == 127)
		return 0;
	if (b[0] == 169 && b[1] == 254)
		return p->allow_linklocal;
	if (b[0] == 10)
		return p->allow_private_v4;
	if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
		return p->allow_private_v4;
	if (b[0] == 192 && b[1] == 168)
		return p->allow_private_v4;
	return 1;
}

int cand_addr_keep(const char *addr, int family_filter,
		   const struct cand_policy *p, int *family_out)
{
	uint8_t b[16];
	int fam = 0;
	int keep;

	if (inet_pton(AF_INET6, addr, b) == 1) {
		fam = 6;
		keep = v6_keep(b, p);
	} else if (inet_pton(AF_INET, addr, b) == 1) {
		fam = 4;
		keep = v4_keep(b, p);
	} else {
		if (family_out)
			*family_out = 0;
		return 0;
	}

	if (family_out)
		*family_out = fam;
	if (family_filter && fam != family_filter)
		return 0;
	return keep;
}

static int line_addr(const char *line, size_t len, char *buf, size_t buflen)
{
	const char *p = memmem(line, len, "candidate:", 10);
	const char *end = line + len;
	const char *start;
	int spaces = 0;
	size_t n = 0;

	if (!p)
		return -1;
	for (p += 10; p < end && *p != '\r' && *p != '\n'; p++) {
		if (*p != ' ')
			continue;
		if (++spaces == 4) {
			start = p + 1;
			while (start < end && *start != ' ' &&
			       *start != '\r' && *start != '\n') {
				if (n >= buflen - 1)
					return -1;
				buf[n++] = *start++;
			}
			buf[n] = '\0';
			return n ? 0 : -1;
		}
	}
	return -1;
}

void cand_sdp_filter(const char *in, int family_filter,
		     const struct cand_policy *p, char *out, size_t outlen)
{
	const char *line = in;
	size_t o = 0;

	while (*line) {
		const char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line + 1) : strlen(line);
		int keep = 1;
		char addr[64];

		if (memmem(line, len, "candidate:", 10)) {
			if (line_addr(line, len, addr, sizeof(addr)) ||
			    !cand_addr_keep(addr, family_filter, p, NULL))
				keep = 0;
		}
		if (keep && o + len < outlen) {
			memcpy(out + o, line, len);
			o += len;
		}
		if (!nl)
			break;
		line = nl + 1;
	}
	out[o] = '\0';
}
