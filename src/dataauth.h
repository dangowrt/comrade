/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_DATAAUTH_H
#define COMRADE_DATAAUTH_H

#include <stddef.h>
#include <stdint.h>

/*
 * Who sent a stream datagram. The stream is SSH inside KCP, so its bytes are
 * already unreadable to anyone on the path; what they lack is any statement of
 * origin, and a forged segment costs more here than a dropped one -- dropping
 * is what the path layer survives by moving, while corruption ends the SSH
 * session above every path at once.
 *
 * So each datagram carries a counter and a tag over itself and that counter:
 *
 *   [kcp datagram][8 counter BE][16 tag]
 *
 * It authenticates and does not encrypt. Sealing instead would hide the KCP
 * header, whose segment sizes and timing are on the wire regardless, and cost
 * 40 bytes a datagram rather than 24; on x86 with OpenSSL the two are within a
 * tenth of each other either way, so the overhead is what decides it. Both
 * live behind this interface, so the choice can be revisited on a target where
 * the measurement comes out differently.
 *
 * The tag goes last so the datagram still opens with KCP's conversation id,
 * which is what tells a stream datagram from a probe.
 */
#define DATAAUTH_CTR_LEN 8
#define DATAAUTH_TAG_LEN 16
#define DATAAUTH_OVERHEAD (DATAAUTH_CTR_LEN + DATAAUTH_TAG_LEN)

/*
 * Write data, its counter and the tag into out. Returns the total length, or 0
 * when out cannot hold it.
 */
size_t dataauth_wrap(uint8_t *out, size_t out_max, const uint8_t key[32],
		     const uint8_t *data, size_t len, uint64_t seq);

/*
 * Check the tag on a wrapped datagram. On success *body is the length of the
 * datagram without the counter and tag, *seq the counter it carried; the body
 * is at the front of `in`, so nothing is copied. Returns 0 when the tag is
 * this key's, -1 otherwise. Comparison does not say where a tag differs.
 */
int dataauth_open(const uint8_t key[32], const uint8_t *in, size_t len,
		  size_t *body, uint64_t *seq);

#endif /* COMRADE_DATAAUTH_H */
