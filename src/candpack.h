/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CANDPACK_H
#define COMRADE_CANDPACK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/*
 * Compact binary codec for the ICE parameters exchanged through signalling.
 *
 * libjuice hands us a text description (ice-ufrag, ice-pwd and a=candidate
 * lines); a DHT mutable item is only ~1000 bytes and holds two of these, so
 * the verbose text does not fit. This packs the credentials and the candidate
 * tuples (type, family, priority, port, address) into a few bytes each and
 * rebuilds a description libjuice accepts.
 *
 * With for_dht set, addresses that cannot help a peer off our own L2 segment
 * (link-local, ULA, overlay, EUI-64, loopback) are dropped, since multicast
 * covers same-segment peers. Private v4 (RFC1918/CGNAT) is kept: it lets the
 * inner peer of a nested NAT punch to the outer peer's private address, which
 * multicast cannot reach. The mailbox is sealed, so none of this is exposed to
 * the public DHT. Without for_dht every gathered address is packed.
 */

/* Pack an SDP description into out (up to max). Returns bytes written, -1 on
 * error, 0 if nothing packable (no ufrag/pwd). */
int candpack_encode(const char *sdp, int for_dht, uint8_t *out, size_t max);

/* Rebuild an SDP description from packed bytes into out (NUL-terminated, up to
 * max). Returns string length, or -1 on error. */
int candpack_decode(const uint8_t *in, size_t in_len, char *out, size_t max);

/*
 * Multicast announcement codec. On a shared segment a peer's address is the
 * packet source, so the announcement carries only the ICE credentials and
 * port, never an address. encode packs ufrag/pwd + the (identity-pinned) port
 * from the local description; decode rebuilds a description with one host
 * candidate at (src address, announced port), keeping the zone id link-local
 * needs. Returns bytes/length written, -1 on error, 0 if nothing to announce.
 */
int candpack_announce_encode(const char *sdp, uint8_t *out, size_t max);
int candpack_announce_decode(const uint8_t *in, size_t in_len,
			     const struct sockaddr *src, socklen_t srclen,
			     char *out, size_t max);

#endif
