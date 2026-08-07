/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CANDPACK_H
#define COMRADE_CANDPACK_H

#include <stddef.h>
#include <stdint.h>

/*
 * Compact binary codec for the ICE parameters exchanged through signalling.
 *
 * libjuice hands us a text description (ice-ufrag, ice-pwd and a=candidate
 * lines); a DHT mutable item is only ~1000 bytes and holds two of these, so
 * the verbose text does not fit. This packs the credentials and the candidate
 * tuples (type, family, priority, port, address) into a few bytes each and
 * rebuilds a description libjuice accepts.
 *
 * With routable_only set, non-routed candidate addresses (RFC1918, ULA,
 * link-local, loopback, overlay) are dropped: they never help a peer across
 * the public internet, and same-domain peers rendezvous over multicast
 * instead, so publishing them to the DHT only wastes the slot.
 */

/* Pack an SDP description into out (up to max). Returns bytes written, -1 on
 * error, 0 if nothing packable (no ufrag/pwd). */
int candpack_encode(const char *sdp, int routable_only, uint8_t *out,
		    size_t max);

/* Rebuild an SDP description from packed bytes into out (NUL-terminated, up to
 * max). Returns string length, or -1 on error. */
int candpack_decode(const uint8_t *in, size_t in_len, char *out, size_t max);

#endif
