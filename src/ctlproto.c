/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <string.h>

#include "ctlproto.h"

void ctl_put_u64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (56 - 8 * i));
}

uint64_t ctl_get_u64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;

	for (i = 0; i < 8; i++)
		v = (v << 8) | p[i];
	return v;
}

size_t ctl_frame(uint8_t *buf, int type, const uint8_t *payload, size_t plen)
{
	if (plen > CTL_FRAME_MAX - CTL_HDR)
		return 0;
	buf[0] = (uint8_t)type;
	buf[1] = (uint8_t)plen;
	if (plen)
		memcpy(buf + CTL_HDR, payload, plen);
	return CTL_HDR + plen;
}

void ctl_reframer_feed(struct ctl_reframer *r, const uint8_t *in, size_t n,
		       void (*cb)(void *, int, const uint8_t *, size_t),
		       void *arg)
{
	size_t off = 0;

	/* A single feed larger than the buffer cannot be our framing (frames are
	 * tiny), so drop it and keep what is held; a feed that would only overflow
	 * the held partial drops that partial and resyncs on the fresh bytes. */
	if (n > sizeof(r->buf))
		return;
	if (r->len + n > sizeof(r->buf))
		r->len = 0;
	memcpy(r->buf + r->len, in, n);
	r->len += n;

	while (r->len - off >= CTL_HDR) {
		size_t plen = r->buf[off + 1];

		/* A payload larger than the protocol's declared maximum
		 * (CTL_FRAME_MAX) can never be one of our frames -- the writer
		 * caps it there -- so the stream is unrecoverable (impossible on
		 * the authenticated channel): drop everything and resync rather
		 * than emit an oversized frame. An unknown future type within the
		 * bound is skipped by its length in the callback. */
		if (CTL_HDR + plen > CTL_FRAME_MAX) {
			off = r->len;
			break;
		}
		if (r->len - off < CTL_HDR + plen)
			break;
		cb(arg, r->buf[off], r->buf + off + CTL_HDR, plen);
		off += CTL_HDR + plen;
	}
	if (off) {
		memmove(r->buf, r->buf + off, r->len - off);
		r->len -= off;
	}
}

void ctl_rdv_encode(uint8_t *pl, int family, const struct sockaddr *sa)
{
	uint16_t port;

	pl[0] = (uint8_t)(family == 6 ? 6 : 4);
	memset(pl + 3, 0, 16);
	if (family == 6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		port = ntohs(a->sin6_port);
		memcpy(pl + 3, &a->sin6_addr, 16);
	} else {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		port = ntohs(a->sin_port);
		memcpy(pl + 3, &a->sin_addr, 4);
	}
	pl[1] = (uint8_t)(port >> 8);
	pl[2] = (uint8_t)port;
}

void ctl_reach_encode(uint8_t *pl, int slot, int state, int flags)
{
	if (slot != 0 && slot != 1)
		return;
	pl[slot * 2] = (uint8_t)state;
	pl[slot * 2 + 1] = (uint8_t)flags;
}

int ctl_reach_decode(const uint8_t *pl, size_t plen, int slot, int *state,
		     int *flags)
{
	uint8_t st;

	*state = CTL_REACH_DOWN;
	*flags = 0;
	if (plen < CTL_REACH_PLEN || (slot != 0 && slot != 1))
		return 0;
	st = pl[slot * 2];
	/* Anything this build has no meaning for is not reachability. */
	if (st == CTL_REACH_PENDING || st == CTL_REACH_UP)
		*state = st;
	*flags = pl[slot * 2 + 1];
	return 1;
}

int ctl_rdv_decode(const uint8_t *pl, size_t plen, struct sockaddr_storage *out,
		   socklen_t *len)
{
	uint16_t port;

	*len = 0;
	if (plen < CTL_RDV_PLEN)
		return 0;
	port = (uint16_t)((pl[1] << 8) | pl[2]);
	memset(out, 0, sizeof(*out));
	if (pl[0] == 6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;

		a->sin6_family = AF_INET6;
		a->sin6_port = htons(port);
		memcpy(&a->sin6_addr, pl + 3, 16);
		*len = sizeof(*a);
		return 6;
	}
	if (pl[0] == 4) {
		struct sockaddr_in *a = (struct sockaddr_in *)out;

		a->sin_family = AF_INET;
		a->sin_port = htons(port);
		memcpy(&a->sin_addr, pl + 3, 4);
		*len = sizeof(*a);
		return 4;
	}
	return 0;
}
