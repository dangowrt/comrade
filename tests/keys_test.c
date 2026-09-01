/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The session key schedule (keys_derive), and specifically the two wire tags
 * it draws.
 *
 * A probe and a stream datagram are told apart by their first four bytes, and
 * so are a comrade datagram and a WireGuard one wherever the two share a port.
 * That makes three properties of the pair rather than one: probe_magic and
 * conv must differ, and neither may be a WireGuard message type as it reaches
 * the wire -- which is a different number in each, because a probe writes
 * probe_magic big-endian and kcp writes conv little-endian.
 *
 * Both tags are the first bytes of a 32-byte digest rather than a digest of
 * their own length, because BLAKE2b folds the digest length into its parameter
 * block and a library offering only the standard sizes cannot be asked for a
 * short one. The vector below is therefore also a statement about backends:
 * these are the numbers every backend produces, and a build whose backend
 * quietly produced others would meet no other build on the wire.
 */

#include <assert.h>
#include <string.h>

#include "keys.h"
#include "token.h"

static uint32_t wire_le(uint32_t v)	/* the four bytes, read little-endian */
{
	return (v >> 24) | ((v >> 8) & 0xff00U) |
	       ((v << 8) & 0xff0000U) | (v << 24);
}

static int is_wg(uint32_t first_four_le)
{
	return first_four_le >= 1 && first_four_le <= 4;
}

int main(void)
{
	struct session_keys k, again;
	uint8_t rdv[TOKEN_RDV_LEN];
	int i, t;

	for (i = 0; i < TOKEN_RDV_LEN; i++)
		rdv[i] = (uint8_t)(i * 11 + 5);
	memset(&k, 0, sizeof(k));
	assert(keys_derive(&k, rdv) == 0);

	/* The numbers every backend agrees on, checked against the value and
	 * not against another run of the same code. */
	assert(k.probe_magic == 0x30d38fb9U);
	assert(k.conv == 0x45450c76U);
	assert(k.mcast_port == 44915);

	/* Deterministic: both ends derive from the same invitation alone. */
	memset(&again, 0, sizeof(again));
	assert(keys_derive(&again, rdv) == 0);
	assert(again.probe_magic == k.probe_magic);
	assert(again.conv == k.conv);
	assert(again.mcast_port == k.mcast_port);
	assert(!memcmp(again.sig_key, k.sig_key, sizeof(k.sig_key)));
	assert(!memcmp(again.bep44_pk, k.bep44_pk, sizeof(k.bep44_pk)));

	/*
	 * The three properties, over enough invitations that a construction
	 * which merely made a collision unlikely would still be right here.
	 * This cannot reach the rejection branch -- that wants a draw in a
	 * 2^-30 set -- so it stands for the ordinary case only, which is the
	 * case where a mistake would be silent.
	 */
	for (t = 0; t < 20000; t++) {
		for (i = 0; i < TOKEN_RDV_LEN; i++)
			rdv[i] = (uint8_t)(t * 7 + i * 31 + (t >> 8));
		memset(&k, 0, sizeof(k));
		assert(keys_derive(&k, rdv) == 0);
		assert(k.probe_magic != k.conv);
		assert(!is_wg(wire_le(k.probe_magic)));
		assert(!is_wg(k.conv));
		/* Above the registered range, inside the derived window. */
		assert(k.mcast_port >= 32768 && k.mcast_port < 32768 + 16384);
	}
	return 0;
}
