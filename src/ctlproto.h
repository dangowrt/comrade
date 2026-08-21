/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CTLPROTO_H
#define COMRADE_CTLPROTO_H

#include <stddef.h>
#include <stdint.h>
#include "wsock.h"

/*
 * Wire framing for the comrade-ctl control channel (see session.c). The channel
 * is a reliable, ordered byte stream inside the authenticated SSH session, so a
 * message carries no magic and no checksum of its own -- the SSH channel
 * already authenticates and frames the transport. Only a message boundary is
 * needed: frame = [type:1][len:1][payload:len], len being the payload length.
 */
#define CTLM_PING 0		/* payload: timestamp(8), big-endian */
#define CTLM_PONG 1		/* payload: echoed timestamp(8) */
#define CTLM_RDV 2		/* payload: family(1) port(2) addr(16) */
#define CTLM_CAND 3		/* payload: family(1) port(2) addr(16) */
#define CTL_HDR 2
#define CTL_TS_LEN 8
#define CTL_RDV_PLEN 19
#define CTL_FRAME_MAX (CTL_HDR + CTL_RDV_PLEN)

/* Big-endian 64-bit helpers, used for the heartbeat timestamps. */
void ctl_put_u64(uint8_t *p, uint64_t v);
uint64_t ctl_get_u64(const uint8_t *p);

/* Encode one frame into buf (which must hold CTL_FRAME_MAX). Returns the total
 * frame length, or 0 if plen exceeds the maximum payload. */
size_t ctl_frame(uint8_t *buf, int type, const uint8_t *payload, size_t plen);

/*
 * Reframer: accumulates raw stream bytes and emits whole messages. Sized to
 * hold one partial frame plus a full read chunk; input that cannot be a valid
 * frame is dropped and the accumulator resynced rather than growing unbounded.
 */
struct ctl_reframer {
	uint8_t buf[128];
	size_t len;
};

/* Feed n bytes; invoke cb(arg, type, payload, plen) for each complete frame. */
void ctl_reframer_feed(struct ctl_reframer *r, const uint8_t *in, size_t n,
		       void (*cb)(void *, int, const uint8_t *, size_t),
		       void *arg);

/* An endpoint <-> a CTL_RDV_PLEN payload: a rendezvous node for CTLM_RDV, one
 * of the sender's own local candidate endpoints for CTLM_CAND. The two share
 * the payload shape and so the codec. Decode returns the family (4 or 6), or 0
 * if the payload names neither. */
void ctl_rdv_encode(uint8_t *pl, int family, const struct sockaddr *sa);
int ctl_rdv_decode(const uint8_t *pl, size_t plen, struct sockaddr_storage *out,
		   socklen_t *len);

#endif
