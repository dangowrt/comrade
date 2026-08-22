/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <string.h>

#include "stunprobe.h"

static const uint8_t seed[STUN_PROBE_TXID_LEN] =
	{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0 };

static void build_check(void)
{
	uint8_t req[STUN_PROBE_REQ_LEN];

	stun_probe_build(req, seed);
	assert(req[0] == 0x00 && req[1] == 0x01);	/* binding request */
	assert(req[2] == 0x00 && req[3] == 0x00);	/* no attributes */
	assert(req[4] == 0x21 && req[5] == 0x12 &&
	       req[6] == 0xa4 && req[7] == 0x42);	/* magic cookie */
	assert(!memcmp(req + 8, seed, STUN_PROBE_TXID_LEN));
}

/* A binding success response for 203.0.113.9:54321, txid seed[0..10]||7. */
static size_t mkresp(uint8_t *out, int xored, int family)
{
	static const uint8_t ip[4] = { 203, 0, 113, 9 };
	size_t o = 0;
	int i;

	out[o++] = 0x01; out[o++] = 0x01;		/* success */
	out[o++] = 0x00; out[o++] = 0x0c;		/* one attribute */
	out[o++] = 0x21; out[o++] = 0x12; out[o++] = 0xa4; out[o++] = 0x42;
	memcpy(out + o, seed, STUN_PROBE_TXID_LEN - 1);
	o += STUN_PROBE_TXID_LEN - 1;
	out[o++] = 7;					/* per-server byte */
	out[o++] = (uint8_t)((xored ? 0x0020 : 0x0001) >> 8);
	out[o++] = (uint8_t)(xored ? 0x20 : 0x01);
	out[o++] = 0x00; out[o++] = 0x08;
	out[o++] = 0x00;
	out[o++] = (uint8_t)family;
	if (xored) {
		out[o++] = (0x54321 >> 8 & 0xff) ^ 0x21;
		out[o++] = (0x54321 & 0xff) ^ 0x12;
		for (i = 0; i < 4; i++) {
			static const uint8_t m[4] = { 0x21, 0x12, 0xa4, 0x42 };

			out[o++] = ip[i] ^ m[i];
		}
	} else {
		out[o++] = 0x54321 >> 8 & 0xff;
		out[o++] = 0x54321 & 0xff;
		for (i = 0; i < 4; i++)
			out[o++] = ip[i];
	}
	return o;
}

static void parse_check(void)
{
	uint8_t resp[64], addr[4];
	uint16_t port;
	size_t n;

	n = mkresp(resp, 1, 0x01);
	assert(stun_probe_mapped4(resp, n, seed, addr, &port) == 0);
	assert(addr[0] == 203 && addr[1] == 0 && addr[2] == 113 && addr[3] == 9);
	assert(port == (0x54321 & 0xffff));

	n = mkresp(resp, 0, 0x01);
	assert(stun_probe_mapped4(resp, n, seed, addr, &port) == 0);
	assert(addr[0] == 203 && addr[3] == 9);

	/* A v6 mapping is not a pool member here. */
	n = mkresp(resp, 1, 0x02);
	assert(stun_probe_mapped4(resp, n, seed, addr, &port) != 0);

	/* Foreign transaction id: refused. */
	n = mkresp(resp, 1, 0x01);
	resp[9] ^= 0xff;
	assert(stun_probe_mapped4(resp, n, seed, addr, &port) != 0);

	/* Truncation anywhere: refused, never read past. */
	n = mkresp(resp, 1, 0x01);
	assert(stun_probe_mapped4(resp, 19, seed, addr, &port) != 0);
	assert(stun_probe_mapped4(resp, n - 1, seed, addr, &port) != 0);

	/* A request is not a response. */
	stun_probe_build(resp, seed);
	assert(stun_probe_mapped4(resp, STUN_PROBE_REQ_LEN, seed, addr,
				  &port) != 0);
}

int main(void)
{
	build_check();
	parse_check();
	return 0;
}
