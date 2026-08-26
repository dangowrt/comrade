/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Unit tests for the comrade-ctl wire framing: frame encode, the reframer's
 * handling of split and coalesced reads and of garbage resync, the big-endian
 * timestamp helpers, and the rendezvous payload round-trip for both families.
 */
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ctlproto.h"

struct got {
	int type;
	uint8_t pl[CTL_FRAME_MAX];
	size_t plen;
};

static struct got seen[16];
static int nseen;

static void collect(void *arg, int type, const uint8_t *pl, size_t plen)
{
	(void)arg;
	assert(nseen < 16);
	assert(plen <= CTL_FRAME_MAX);
	seen[nseen].type = type;
	seen[nseen].plen = plen;
	if (plen)
		memcpy(seen[nseen].pl, pl, plen);
	nseen++;
}

static void reset(struct ctl_reframer *r)
{
	memset(r, 0, sizeof(*r));
	nseen = 0;
}

int main(void)
{
	struct ctl_reframer r;
	uint8_t f1[CTL_FRAME_MAX], f2[CTL_FRAME_MAX], ts[CTL_TS_LEN];
	uint8_t rdv[CTL_RDV_PLEN], junk[8];
	size_t n1, n2;

	/* u64 helpers round-trip, big-endian. */
	ctl_put_u64(ts, 0x0102030405060708ULL);
	assert(ts[0] == 0x01 && ts[7] == 0x08);
	assert(ctl_get_u64(ts) == 0x0102030405060708ULL);

	/* Frame with a max payload, and reject an over-long one. */
	n1 = ctl_frame(f1, CTLM_PING, ts, CTL_TS_LEN);
	assert(n1 == CTL_HDR + CTL_TS_LEN);
	assert(f1[0] == CTLM_PING && f1[1] == CTL_TS_LEN);
	{
		uint8_t big[64], out[64];

		assert(ctl_frame(out, CTLM_RDV, big, sizeof(big)) == 0);
	}

	/* One whole frame in one feed -> one message, payload intact. */
	reset(&r);
	ctl_reframer_feed(&r, f1, n1, collect, NULL);
	assert(nseen == 1);
	assert(seen[0].type == CTLM_PING && seen[0].plen == CTL_TS_LEN);
	assert(ctl_get_u64(seen[0].pl) == 0x0102030405060708ULL);
	assert(r.len == 0);

	/* Split across two reads: nothing until the frame completes. */
	reset(&r);
	ctl_reframer_feed(&r, f1, 3, collect, NULL);
	assert(nseen == 0);
	ctl_reframer_feed(&r, f1 + 3, n1 - 3, collect, NULL);
	assert(nseen == 1 && seen[0].plen == CTL_TS_LEN);

	/* Two frames coalesced into one read -> two messages, in order. */
	n2 = ctl_frame(f2, CTLM_PONG, ts, CTL_TS_LEN);
	reset(&r);
	{
		uint8_t both[CTL_FRAME_MAX * 2];

		memcpy(both, f1, n1);
		memcpy(both + n1, f2, n2);
		ctl_reframer_feed(&r, both, n1 + n2, collect, NULL);
	}
	assert(nseen == 2);
	assert(seen[0].type == CTLM_PING && seen[1].type == CTLM_PONG);

	/* A byte with an impossible length is skipped; a valid frame that
	 * follows still lands (resync, not deadlock). */
	reset(&r);
	junk[0] = 0x7f;			/* type */
	junk[1] = 0x7f;			/* len far past the max payload */
	ctl_reframer_feed(&r, junk, 2, collect, NULL);
	assert(nseen == 0);
	ctl_reframer_feed(&r, f1, n1, collect, NULL);
	assert(nseen == 1 && seen[0].type == CTLM_PING);

	/* Rendezvous payload round-trips for IPv4. */
	{
		struct sockaddr_in a;
		struct sockaddr_storage out;
		socklen_t ol = 0;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_port = htons(4711);
		assert(inet_pton(AF_INET, "203.0.113.7", &a.sin_addr) == 1);
		ctl_rdv_encode(rdv, 4, (struct sockaddr *)&a);
		assert(ctl_rdv_decode(rdv, CTL_RDV_PLEN, &out, &ol) == 4);
		{
			struct sockaddr_in *b = (struct sockaddr_in *)&out;

			assert(b->sin_family == AF_INET);
			assert(ntohs(b->sin_port) == 4711);
			assert(memcmp(&b->sin_addr, &a.sin_addr, 4) == 0);
		}
	}

	/* A short RDV payload is rejected and leaves *len zeroed. */
	{
		struct sockaddr_storage out;
		socklen_t ol = 7;

		assert(ctl_rdv_decode(rdv, CTL_RDV_PLEN - 1, &out, &ol) == 0);
		assert(ol == 0);
	}

	/* And for IPv6. */
	{
		struct sockaddr_in6 a;
		struct sockaddr_storage out;
		socklen_t ol = 0;

		memset(&a, 0, sizeof(a));
		a.sin6_family = AF_INET6;
		a.sin6_port = htons(50505);
		assert(inet_pton(AF_INET6, "2001:db8::dead:beef",
				 &a.sin6_addr) == 1);
		ctl_rdv_encode(rdv, 6, (struct sockaddr *)&a);
		assert(ctl_rdv_decode(rdv, CTL_RDV_PLEN, &out, &ol) == 6);
		{
			struct sockaddr_in6 *b = (struct sockaddr_in6 *)&out;

			assert(b->sin6_family == AF_INET6);
			assert(ntohs(b->sin6_port) == 50505);
			assert(memcmp(&b->sin6_addr, &a.sin6_addr, 16) == 0);
		}
	}

	/* A payload naming neither family decodes to 0. */
	{
		struct sockaddr_storage out;
		socklen_t ol = 0;

		memset(rdv, 0, sizeof(rdv));
		rdv[0] = 9;
		assert(ctl_rdv_decode(rdv, CTL_RDV_PLEN, &out, &ol) == 0);
	}

	/*
	 * A candidate advertisement is one endpoint in the same 19-byte shape,
	 * so it frames to exactly CTL_FRAME_MAX and needs no more room than the
	 * rendezvous message the framing was sized for.
	 */
	{
		struct sockaddr_in a;
		struct sockaddr_storage out;
		socklen_t ol = 0;
		uint8_t f[CTL_FRAME_MAX];
		size_t n;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_port = htons(51820);
		assert(inet_pton(AF_INET, "198.51.100.9", &a.sin_addr) == 1);
		ctl_rdv_encode(rdv, 4, (struct sockaddr *)&a);
		n = ctl_frame(f, CTLM_CAND, rdv, CTL_RDV_PLEN);
		assert(n == CTL_FRAME_MAX);
		reset(&r);
		ctl_reframer_feed(&r, f, n, collect, NULL);
		assert(nseen == 1 && seen[0].type == CTLM_CAND);
		assert(seen[0].plen == CTL_RDV_PLEN);
		assert(ctl_rdv_decode(seen[0].pl, seen[0].plen, &out, &ol) == 4);
		{
			struct sockaddr_in *b = (struct sockaddr_in *)&out;

			assert(ntohs(b->sin_port) == 51820);
			assert(memcmp(&b->sin_addr, &a.sin_addr, 4) == 0);
		}
	}

	/*
	 * Reachability: both families in one message, so a peer learns the
	 * whole situation at once instead of a family at a time.
	 */
	{
		uint8_t pl[CTL_REACH_PLEN];
		uint8_t f[CTL_FRAME_MAX];
		int st = -1, fl = -1;
		size_t n;

		memset(pl, 0, sizeof(pl));
		ctl_reach_encode(pl, 0, CTL_REACH_UP, CTL_REACHF_DHT);
		ctl_reach_encode(pl, 1, CTL_REACH_PENDING, 0);
		n = ctl_frame(f, CTLM_REACH, pl, CTL_REACH_PLEN);
		assert(n == CTL_HDR + CTL_REACH_PLEN);
		reset(&r);
		ctl_reframer_feed(&r, f, n, collect, NULL);
		assert(nseen == 1 && seen[0].type == CTLM_REACH);
		assert(seen[0].plen == CTL_REACH_PLEN);
		assert(ctl_reach_decode(seen[0].pl, seen[0].plen, 0, &st, &fl));
		assert(st == CTL_REACH_UP && (fl & CTL_REACHF_DHT));
		assert(ctl_reach_decode(seen[0].pl, seen[0].plen, 1, &st, &fl));
		assert(st == CTL_REACH_PENDING && !(fl & CTL_REACHF_DHT));

		/* One family says nothing about the other. */
		memset(pl, 0, sizeof(pl));
		ctl_reach_encode(pl, 1, CTL_REACH_UP, CTL_REACHF_DHT);
		assert(ctl_reach_decode(pl, sizeof(pl), 0, &st, &fl));
		assert(st == CTL_REACH_DOWN && fl == 0);

		/*
		 * A state this build has no meaning for is not reachability: a
		 * peer on a later build must never have a value it invented
		 * read here as "you can rely on me".
		 */
		memset(pl, 0, sizeof(pl));
		pl[0] = 99;
		pl[1] = CTL_REACHF_DHT;
		assert(ctl_reach_decode(pl, sizeof(pl), 0, &st, &fl));
		assert(st == CTL_REACH_DOWN);

		/* Short payloads decode to nothing rather than to whatever is
		 * past the end. */
		st = CTL_REACH_UP;
		assert(ctl_reach_decode(pl, CTL_REACH_PLEN - 1, 0, &st, &fl) == 0);
		assert(st == CTL_REACH_DOWN && fl == 0);
	}

	printf("ctlproto: all framing, rendezvous, candidate and reach cases pass\n");
	return 0;
}
