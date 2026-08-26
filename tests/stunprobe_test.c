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

static void mapping_check(void)
{
	struct stun_mapping m;
	static const uint8_t a1[4] = { 203, 0, 113, 9 };
	static const uint8_t a2[4] = { 198, 51, 100, 7 };

	/* Fewer than two samples: unknown either way. */
	stun_mapping_reset(&m);
	assert(stun_mapping_result(&m) == STUN_MAPPING_UNKNOWN);
	stun_mapping_add(&m, a1, 40000);
	assert(stun_mapping_result(&m) == STUN_MAPPING_UNKNOWN);

	/* Every server sees the same (address, port): independent. */
	stun_mapping_reset(&m);
	stun_mapping_add(&m, a1, 40000);
	stun_mapping_add(&m, a1, 40000);
	assert(stun_mapping_result(&m) == STUN_MAPPING_INDEPENDENT);

	/* Same address, a different port: dependent. */
	stun_mapping_reset(&m);
	stun_mapping_add(&m, a1, 40000);
	stun_mapping_add(&m, a1, 40001);
	assert(stun_mapping_result(&m) == STUN_MAPPING_DEPENDENT);

	/* A different address entirely (a carrier pool): dependent. */
	stun_mapping_reset(&m);
	stun_mapping_add(&m, a1, 40000);
	stun_mapping_add(&m, a2, 40000);
	assert(stun_mapping_result(&m) == STUN_MAPPING_DEPENDENT);

	/* Once disagreement is seen, a later agreeing sample does not undo
	 * it -- the verdict is sticky. */
	stun_mapping_reset(&m);
	stun_mapping_add(&m, a1, 40000);
	stun_mapping_add(&m, a1, 40000);
	stun_mapping_add(&m, a2, 40000);
	assert(stun_mapping_result(&m) == STUN_MAPPING_DEPENDENT);

	/* A reset drops all of that and starts over. */
	stun_mapping_reset(&m);
	assert(stun_mapping_result(&m) == STUN_MAPPING_UNKNOWN);

	/*
	 * Which half moved is a separate question, and the one that decides
	 * whether a peer can still be told where to aim. A carrier pool hands
	 * out an address per destination and keeps the port: every address is
	 * worth naming, against the port this socket was mapped to. Answering
	 * the coarser question instead turns the fan off in exactly the case
	 * it exists for.
	 */
	stun_mapping_reset(&m);
	assert(stun_mapping_port_stable(&m));		/* nothing has moved yet */
	stun_mapping_add(&m, a1, 40000);
	stun_mapping_add(&m, a2, 40000);
	assert(stun_mapping_result(&m) == STUN_MAPPING_DEPENDENT);
	assert(stun_mapping_port_stable(&m));

	/* A port that moves with the destination leaves nothing to name: it is
	 * not the port ICE listens on and cannot be guessed. */
	stun_mapping_reset(&m);
	stun_mapping_add(&m, a1, 40000);
	stun_mapping_add(&m, a2, 40001);
	assert(stun_mapping_result(&m) == STUN_MAPPING_DEPENDENT);
	assert(!stun_mapping_port_stable(&m));

	/* Sticky, the same way the verdict is. */
	stun_mapping_reset(&m);
	stun_mapping_add(&m, a1, 40000);
	stun_mapping_add(&m, a1, 40001);
	stun_mapping_add(&m, a1, 40000);
	assert(!stun_mapping_port_stable(&m));
}


/*
 * A v6 binding success response for 2001:db8::1234:5678, txid seed[0..10]||7.
 * RFC 5389 15.2 masks a v6 address with the magic cookie followed by the
 * transaction id, so the second half is unmaskable without the reply itself --
 * which is the part easiest to get wrong, hence this.
 */
static size_t mkresp6(uint8_t *out, int xored)
{
	static const uint8_t ip6[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78
	};
	static const uint8_t magic[4] = { 0x21, 0x12, 0xa4, 0x42 };
	uint8_t txid[STUN_PROBE_TXID_LEN];
	size_t o = 0;
	int i;

	memcpy(txid, seed, STUN_PROBE_TXID_LEN - 1);
	txid[STUN_PROBE_TXID_LEN - 1] = 7;

	out[o++] = 0x01; out[o++] = 0x01;		/* success */
	out[o++] = 0x00; out[o++] = 0x18;		/* one attribute, 24 bytes */
	memcpy(out + o, magic, 4);
	o += 4;
	memcpy(out + o, txid, STUN_PROBE_TXID_LEN);
	o += STUN_PROBE_TXID_LEN;
	out[o++] = (uint8_t)((xored ? 0x0020 : 0x0001) >> 8);
	out[o++] = (uint8_t)(xored ? 0x20 : 0x01);
	out[o++] = 0x00; out[o++] = 0x14;		/* 20 bytes of value */
	out[o++] = 0x00;
	out[o++] = 0x02;				/* family v6 */
	if (xored) {
		out[o++] = (0x54321 >> 8 & 0xff) ^ 0x21;
		out[o++] = (0x54321 & 0xff) ^ 0x12;
		for (i = 0; i < 4; i++)
			out[o++] = ip6[i] ^ magic[i];
		for (i = 4; i < 16; i++)
			out[o++] = ip6[i] ^ txid[i - 4];
	} else {
		out[o++] = 0x54321 >> 8 & 0xff;
		out[o++] = 0x54321 & 0xff;
		for (i = 0; i < 16; i++)
			out[o++] = ip6[i];
	}
	return o;
}

/* The v6 half of the same decoder: what the dedicated v6 probe reports, and
 * often the only v6 address anything sees -- ICE gathers no v6 srflx when a
 * global host candidate already exists. */
static void parse6_check(void)
{
	static const uint8_t want[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78
	};
	uint8_t resp[96], addr[16];
	uint16_t port;
	size_t n;

	n = mkresp6(resp, 1);
	assert(stun_probe_mapped_fam(resp, n, seed, 0x02, addr, &port) == 0);
	assert(!memcmp(addr, want, 16));
	assert(port == (0x54321 & 0xffff));

	n = mkresp6(resp, 0);
	assert(stun_probe_mapped_fam(resp, n, seed, 0x02, addr, &port) == 0);
	assert(!memcmp(addr, want, 16));

	/* asking for the wrong family finds nothing */
	n = mkresp6(resp, 1);
	assert(stun_probe_mapped_fam(resp, n, seed, 0x01, addr, &port) != 0);
}

int main(void)
{
	build_check();
	parse_check();
	parse6_check();
	mapping_check();
	return 0;
}
