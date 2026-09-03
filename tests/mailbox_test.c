/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Unit tests for the rendezvous mailbox: the
 * container build/parse/merge, the turnstile claim decision (the
 * answer slot as a mutex), the host rotate that releases the answer slot
 * until it is observed gone, the tombstone that says the session is over --
 * including a live host erasing a forged one -- and the CAS/seq contract
 * modelled with an in-test store so that two
 * claimants against one empty slot resolve to exactly one winner. The slot
 * payloads are arbitrary byte blobs -- the container layer never inspects the
 * sealed contents -- so no crypto or DHT is involved.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "bep44.h"		/* BEP44_MAX_VALUE, the modelled store's value size */
#include "mailbox.h"

/*
 * A minimal model of the BEP44 mutable-item store: a stored value with a seq.
 * A put carries the value's new seq and the cas (the seq the writer read); the
 * node accepts it only if cas matches the currently stored seq, mirroring
 * bep44.c update_store (seq = prev+1, cas = prev). This is the sole modelled
 * piece; the bytes it stores are always produced by the REAL mailbox_merge.
 */
struct store {
	uint8_t v[BEP44_MAX_VALUE];
	size_t len;
	int64_t seq;
	int have;
};

static void store_seed(struct store *st, const uint8_t *v, size_t len,
		       int64_t seq)
{
	memcpy(st->v, v, len);
	st->len = len;
	st->seq = seq;
	st->have = 1;
}

/* Attempt a CAS put; returns 0 on success, -1 if the CAS is lost. */
static int store_put(struct store *st, const uint8_t *v, size_t len,
		     int64_t seq, int64_t cas)
{
	if (st->have && cas != st->seq)
		return -1;		/* stale writer: CAS lost */
	memcpy(st->v, v, len);
	st->len = len;
	st->seq = seq;
	st->have = 1;
	return 0;
}

/* Build an offer-only container (the free turnstile state a host publishes). */
static size_t offer_only(uint8_t *out, size_t max, const uint8_t *offer,
			 size_t olen)
{
	struct mailbox h;

	mailbox_init(&h, 1);
	mailbox_set_mine(&h, offer, olen);
	return mailbox_build(&h, out, max);
}

/* One client's claim attempt against the value it read at read_seq: write only
 * when the mutex is free, with CAS against read_seq. Returns 0 lands, -1 CAS
 * lost, 1 declined (slot busy). The merged bytes come from mailbox_merge. */
static int client_claim(struct store *st, struct mailbox *m,
			const uint8_t *read_v, size_t read_len, int64_t read_seq)
{
	uint8_t out[BEP44_MAX_VALUE];
	size_t olen;

	if (!mailbox_client_should_claim(m))
		return 1;
	if (mailbox_merge(m, read_v, read_len, out, &olen, sizeof(out)))
		return -2;
	return store_put(st, out, olen, read_seq + 1, read_seq);
}

/*
 * ARMING A RELEASE MAKES THE WRITE DUE AT ONCE.
 *
 * The answer slot is a mutex, so every round it is held for is a round in
 * which no claimant may write. The rule that a releasing host owes a write
 * lives in the need-write computation, and that ran only when a container was
 * parsed -- so arming a release marked nothing, and the turnstile stayed held
 * until some unrelated reason to write came along. On a host with nothing else
 * to say, that is for ever.
 */
static void arming_a_release_makes_the_write_due(void)
{
	static const char offer[] = "OFFER-BYTES";
	static const char dead[] = "CLAIM-NOBODY-CAN-OPEN";
	uint8_t held[512];
	size_t hlen;
	struct mailbox m, g;

	/* A container carrying the host's offer and somebody's claim. */
	mailbox_init(&g, 0);
	mailbox_set_mine(&g, (const uint8_t *)dead, sizeof(dead) - 1);
	hlen = offer_only(held, sizeof(held), (const uint8_t *)offer,
			  sizeof(offer) - 1);
	assert(!mailbox_merge(&g, held, hlen, held, &hlen, sizeof(held)));

	mailbox_init(&m, 1);
	mailbox_set_mine(&m, (const uint8_t *)offer, sizeof(offer) - 1);
	mailbox_parse(&m, held, hlen);

	/* Its own slot is already what it would write, so nothing is owed. */
	assert(!m.need_write);

	/* Until it releases the claim it cannot open. */
	mailbox_arm_release(&m);
	assert(m.need_write);
}

int main(void)
{
	static const uint8_t OFFER_E[] = { 0xEE, 0x01, 0x02 };
	static const uint8_t OFFER_E1[] = { 0xEE, 0x11, 0x22, 0x33 };
	static const uint8_t ANS1[] = { 0xA1, 0xA1, 0xA1 };
	static const uint8_t ANS2[] = { 0xB2, 0xB2 };
	static const uint8_t ANS3[] = { 0xC3, 0xC3, 0xC3, 0xC3 };
	uint8_t out[BEP44_MAX_VALUE];
	uint8_t offv[64];
	size_t offlen;
	size_t n;

	/* An offer-only container reused across the claim-status cases. */
	offlen = offer_only(offv, sizeof(offv), OFFER_E, sizeof(OFFER_E));

	/* ---- 1. Container build/parse, all slot combinations ---- */

	/* Host, offer only, no peer answer: exact bencode framing. */
	{
		struct mailbox h;
		uint8_t off[2];

		off[0] = 'X';
		off[1] = 'Y';
		mailbox_init(&h, 1);
		mailbox_set_mine(&h, off, 2);
		n = mailbox_build(&h, out, sizeof(out));
		assert(n == 9 && !memcmp(out, "d1:o2:XYe", 9));
	}

	/* Client, answer and known offer: 'a' then 'o', deterministic order. */
	{
		struct mailbox c;
		uint8_t a1[1];

		a1[0] = 'A';
		mailbox_init(&c, 0);
		mailbox_set_mine(&c, a1, 1);
		mailbox_parse(&c, (const uint8_t *)"d1:o1:Be", 8);	/* learn offer */
		n = mailbox_build(&c, out, sizeof(out));
		assert(n == 14 && !memcmp(out, "d1:a1:A1:o1:Be", 14));
	}

	/* Empty container: no mine, no peer -> "de"; parse yields both absent. */
	{
		struct mailbox h;

		mailbox_init(&h, 1);
		n = mailbox_build(&h, out, sizeof(out));
		assert(n == 2 && !memcmp(out, "de", 2));
		mailbox_parse(&h, out, n);
		assert(h.slot_o_len == 0 && h.slot_a_len == 0);
	}

	/* Round-trip: build a two-slot container, parse it back, slots intact. */
	{
		struct mailbox c, probe;
		const uint8_t *po, *pa;

		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		mailbox_parse(&c, offv, offlen);		/* learn the offer */
		n = mailbox_build(&c, out, sizeof(out));

		mailbox_init(&probe, 1);
		mailbox_parse(&probe, out, n);
		assert(probe.slot_a_len == sizeof(ANS1));
		assert(!memcmp(probe.slot_a, ANS1, sizeof(ANS1)));
		assert(probe.slot_o_len == sizeof(OFFER_E));
		assert(!memcmp(probe.slot_o, OFFER_E, sizeof(OFFER_E)));
		/* peer_slot for a host is the answer, for a client the offer */
		assert(mailbox_peer_slot(&probe, &pa) == sizeof(ANS1));
		assert(!memcmp(pa, ANS1, sizeof(ANS1)));
		assert(mailbox_peer_slot(&c, &po) == sizeof(OFFER_E));
		assert(!memcmp(po, OFFER_E, sizeof(OFFER_E)));
	}

	/* Merge preserves the peer's slot: a host writing its offer keeps the
	 * client's answer that is already in the container. */
	{
		struct mailbox h, probe;
		uint8_t cur[64];
		size_t clen, olen;

		/* current container holds a client answer in 'a' only */
		mailbox_init(&h, 0);
		mailbox_set_mine(&h, ANS1, sizeof(ANS1));
		clen = mailbox_build(&h, cur, sizeof(cur));

		mailbox_init(&h, 1);
		mailbox_set_mine(&h, OFFER_E, sizeof(OFFER_E));
		assert(mailbox_merge(&h, cur, clen, out, &olen, sizeof(out)) == 0);
		mailbox_init(&probe, 1);
		mailbox_parse(&probe, out, olen);
		assert(probe.slot_a_len == sizeof(ANS1));	/* peer answer kept */
		assert(!memcmp(probe.slot_a, ANS1, sizeof(ANS1)));
		assert(probe.slot_o_len == sizeof(OFFER_E));	/* our offer written */
	}

	/* Host rotate releases the answer slot until it is OBSERVED gone: every
	 * build omits the released claim -- a write that loses the store race
	 * and is remerged still releases it -- and a read showing the slot
	 * empty (or replaced) ends the release. */
	{
		struct mailbox h, probe;
		uint8_t cur[64], cur3[64];
		size_t clen, c3len, b1, b2;

		mailbox_init(&h, 0);
		mailbox_set_mine(&h, ANS1, sizeof(ANS1));
		clen = mailbox_build(&h, cur, sizeof(cur));

		mailbox_init(&h, 1);
		mailbox_set_mine(&h, OFFER_E, sizeof(OFFER_E));
		mailbox_parse(&h, cur, clen);		/* host reads answer into slot_a */
		assert(h.slot_a_len == sizeof(ANS1));

		mailbox_arm_release(&h);
		b1 = mailbox_build(&h, out, sizeof(out));	/* clears 'a' */
		mailbox_init(&probe, 1);
		mailbox_parse(&probe, out, b1);
		assert(probe.slot_a_len == 0);
		assert(probe.slot_o_len == sizeof(OFFER_E));

		/* The write was lost and the store still holds ANS1: the retried
		 * merge must STILL release it, not resurrect it. */
		assert(mailbox_merge(&h, cur, clen, out, &b2, sizeof(out)) == 0);
		mailbox_parse(&probe, out, b2);
		assert(probe.slot_a_len == 0);

		/* A NEW claim in the store meanwhile ends the release: the merge
		 * keeps it, so releasing one claim never eats the next. */
		mailbox_init(&probe, 0);
		mailbox_set_mine(&probe, ANS3, sizeof(ANS3));
		c3len = mailbox_build(&probe, cur3, sizeof(cur3));
		assert(mailbox_merge(&h, cur3, c3len, out, &b2, sizeof(out)) == 0);
		mailbox_init(&probe, 1);
		mailbox_parse(&probe, out, b2);
		assert(probe.slot_a_len == sizeof(ANS3));
		assert(!memcmp(probe.slot_a, ANS3, sizeof(ANS3)));

		/* Observed empty: the release ends; a later claim is kept. */
		mailbox_parse(&h, out, b1);		/* the offer-only value */
		mailbox_parse(&h, cur, clen);		/* ANS1 claims again */
		b2 = mailbox_build(&h, out, sizeof(out));
		mailbox_init(&probe, 1);
		mailbox_parse(&probe, out, b2);
		assert(probe.slot_a_len == sizeof(ANS1));
	}

	/* A client behind its OWN superseded claim: the slot bytes differ from
	 * its current answer, so alone they read as a foreign claim -- but once
	 * the owner recognises the claimant as itself (mailbox_note_own_answer)
	 * the slot is HELD, the overwrite is allowed, and the turnstile cannot
	 * be wedged by a stale claim the host failed to release. The note is
	 * observation-bound: any fresh parse clears it. */
	{
		struct mailbox c, old;
		uint8_t cur[64];
		size_t clen;

		mailbox_init(&old, 0);
		mailbox_set_mine(&old, ANS1, sizeof(ANS1));	/* the old attempt */
		mailbox_parse(&old, offv, offlen);
		clen = mailbox_build(&old, cur, sizeof(cur));

		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS2, sizeof(ANS2));	/* the new attempt */
		mailbox_parse(&c, cur, clen);
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_BUSY);
		assert(!mailbox_client_should_claim(&c));

		mailbox_note_own_answer(&c, 1);
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_HELD);
		assert(mailbox_client_should_claim(&c));

		mailbox_parse(&c, cur, clen);			/* fresh read */
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_BUSY);
		assert(!mailbox_client_should_claim(&c));
	}

	/* ---- 2. Turnstile claim / mutex logic ---- */

	/* A host mailbox is never a claimant: status is always UNKNOWN. */
	{
		struct mailbox h;

		mailbox_init(&h, 1);
		assert(mailbox_claim_status(&h) == MAILBOX_CLAIM_UNKNOWN);
		mailbox_set_mine(&h, OFFER_E, sizeof(OFFER_E));
		mailbox_parse(&h, offv, offlen);
		assert(mailbox_claim_status(&h) == MAILBOX_CLAIM_UNKNOWN);
	}

	/* A fresh client that has not read the mailbox: UNKNOWN, no claim. */
	{
		struct mailbox c;

		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_UNKNOWN);
		assert(!mailbox_client_should_claim(&c));
	}

	/* Empty answer slot -> FREE and claimable. */
	{
		struct mailbox c;

		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		mailbox_parse(&c, offv, offlen);
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_FREE);
		assert(mailbox_client_should_claim(&c));
	}

	/* Our own answer in the slot -> HELD, and nothing left to write. */
	{
		struct mailbox c;
		uint8_t cur[64];
		size_t clen;

		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		mailbox_parse(&c, offv, offlen);
		clen = mailbox_build(&c, cur, sizeof(cur));	/* our a + the offer */
		mailbox_parse(&c, cur, clen);			/* read it back */
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_HELD);
		assert(!c.need_write);
		assert(!mailbox_client_should_claim(&c));
	}

	/* A foreign answer in the slot -> BUSY; we leave it alone and do NOT
	 * claim, even though our own slot is stale (need_write set). */
	{
		struct mailbox c, other;
		uint8_t cur[64];
		size_t clen;

		mailbox_init(&other, 0);
		mailbox_set_mine(&other, ANS2, sizeof(ANS2));
		mailbox_parse(&other, offv, offlen);
		clen = mailbox_build(&other, cur, sizeof(cur));	/* foreign a + offer */

		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		mailbox_parse(&c, cur, clen);
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_BUSY);
		assert(c.need_write);				/* our answer is not there */
		assert(!mailbox_client_should_claim(&c));	/* but we back off */
	}

	/* ---- 3. CAS/seq contract: two claimants, one empty slot ---- */
	{
		struct store st;
		struct mailbox host, c1, c2, probe;
		uint8_t free_v[64];
		size_t free_len;
		const uint8_t *picked;
		size_t plen;
		int r1, r2, rh;
		int64_t read_seq;

		/* Host publishes offer E, answer slot empty: the free state at seq 5. */
		mailbox_init(&host, 1);
		mailbox_set_mine(&host, OFFER_E, sizeof(OFFER_E));
		free_len = offer_only(free_v, sizeof(free_v), OFFER_E,
				      sizeof(OFFER_E));
		store_seed(&st, free_v, free_len, 5);

		/* Two clients GET the same free state (both observe FREE at seq 5). */
		mailbox_init(&c1, 0);
		mailbox_set_mine(&c1, ANS1, sizeof(ANS1));
		mailbox_parse(&c1, st.v, st.len);
		mailbox_init(&c2, 0);
		mailbox_set_mine(&c2, ANS2, sizeof(ANS2));
		mailbox_parse(&c2, st.v, st.len);
		read_seq = st.seq;
		assert(mailbox_claim_status(&c1) == MAILBOX_CLAIM_FREE);
		assert(mailbox_claim_status(&c2) == MAILBOX_CLAIM_FREE);

		/* Both write with cas = 5. Exactly one lands; the other loses CAS. */
		r1 = client_claim(&st, &c1, free_v, free_len, read_seq);
		r2 = client_claim(&st, &c2, free_v, free_len, read_seq);
		assert(r1 == 0);		/* first write lands */
		assert(r2 == -1);		/* second write bounced by CAS */
		assert(st.seq == 6);

		/* The slot holds client 1's answer, never a mix or the loser's. */
		mailbox_init(&probe, 1);
		mailbox_parse(&probe, st.v, st.len);
		assert(probe.slot_a_len == sizeof(ANS1));
		assert(!memcmp(probe.slot_a, ANS1, sizeof(ANS1)));

		/* ---- Host pickup + release-on-rotate ---- */

		/* Host reads the answer it just picked up. */
		mailbox_parse(&host, st.v, st.len);
		plen = mailbox_peer_slot(&host, &picked);
		assert(plen == sizeof(ANS1) && !memcmp(picked, ANS1, sizeof(ANS1)));

		/* Rotate: fresh offer E+1 into 'o', clear 'a', CAS against seq 6. */
		read_seq = st.seq;
		mailbox_set_mine(&host, OFFER_E1, sizeof(OFFER_E1));
		mailbox_arm_release(&host);
		{
			uint8_t hw[BEP44_MAX_VALUE];
			size_t hlen;

			assert(mailbox_merge(&host, st.v, st.len, hw, &hlen,
					     sizeof(hw)) == 0);
			rh = store_put(&st, hw, hlen, read_seq + 1, read_seq);
		}
		assert(rh == 0 && st.seq == 7);

		/* The turnstile is free again: answer cleared, fresh offer present. */
		mailbox_parse(&probe, st.v, st.len);
		assert(probe.slot_a_len == 0);
		assert(probe.slot_o_len == sizeof(OFFER_E1));
		assert(!memcmp(probe.slot_o, OFFER_E1, sizeof(OFFER_E1)));

		/* A stale writer holding the old seq 6 is still bounced. */
		assert(store_put(&st, free_v, free_len, 7, 6) == -1);

		/* The next client sees the fresh free state and claims it. */
		mailbox_init(&probe, 0);
		mailbox_set_mine(&probe, ANS3, sizeof(ANS3));
		mailbox_parse(&probe, st.v, st.len);
		assert(mailbox_claim_status(&probe) == MAILBOX_CLAIM_FREE);
		assert(mailbox_client_should_claim(&probe));
	}

	/* ---- 4. Withdraw, three-way race, reconnect re-claim ---- */

	/* Withdraw: a client that stops advertising declines an otherwise free
	 * slot, so a slot the host frees is not auto-reclaimed; a later set_mine
	 * re-arms the claim. */
	{
		struct mailbox c;

		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		mailbox_parse(&c, offv, offlen);
		assert(mailbox_client_should_claim(&c));	/* armed: would claim */
		mailbox_withdraw(&c);
		assert(!mailbox_client_should_claim(&c));	/* withdrawn: stands down */
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_FREE);	/* slot free */
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));	/* re-arm */
		assert(mailbox_client_should_claim(&c));
	}

	/* Three claimants, one empty slot: exactly one write lands, the other two
	 * lose the CAS and, on re-read, see BUSY and back off. The host then
	 * releases and the two remaining race the freed slot; again exactly one
	 * lands. Admit-one-per-cycle holds for N > 2. */
	{
		struct store st;
		struct mailbox c1, c2, c3, hst, probe;
		uint8_t free_v[64], hw[BEP44_MAX_VALUE], snap[BEP44_MAX_VALUE];
		size_t free_len, hlen, snaplen;
		int r1, r2, r3, wins, losers;
		int64_t read_seq;

		mailbox_init(&hst, 1);
		mailbox_set_mine(&hst, OFFER_E, sizeof(OFFER_E));
		free_len = offer_only(free_v, sizeof(free_v), OFFER_E,
				      sizeof(OFFER_E));
		store_seed(&st, free_v, free_len, 10);

		/* All three GET the same free state at seq 10. */
		mailbox_init(&c1, 0);
		mailbox_set_mine(&c1, ANS1, sizeof(ANS1));
		mailbox_parse(&c1, st.v, st.len);
		mailbox_init(&c2, 0);
		mailbox_set_mine(&c2, ANS2, sizeof(ANS2));
		mailbox_parse(&c2, st.v, st.len);
		mailbox_init(&c3, 0);
		mailbox_set_mine(&c3, ANS3, sizeof(ANS3));
		mailbox_parse(&c3, st.v, st.len);
		read_seq = st.seq;
		assert(mailbox_claim_status(&c1) == MAILBOX_CLAIM_FREE);
		assert(mailbox_claim_status(&c2) == MAILBOX_CLAIM_FREE);
		assert(mailbox_claim_status(&c3) == MAILBOX_CLAIM_FREE);

		r1 = client_claim(&st, &c1, free_v, free_len, read_seq);
		r2 = client_claim(&st, &c2, free_v, free_len, read_seq);
		r3 = client_claim(&st, &c3, free_v, free_len, read_seq);
		wins = (r1 == 0) + (r2 == 0) + (r3 == 0);
		losers = (r1 == -1) + (r2 == -1) + (r3 == -1);
		assert(wins == 1 && losers == 2);	/* exactly one admitted */
		assert(st.seq == 11);

		/* The two losers re-GET the now-busy state and stand down. */
		mailbox_parse(&c2, st.v, st.len);
		mailbox_parse(&c3, st.v, st.len);
		assert(mailbox_claim_status(&c2) == MAILBOX_CLAIM_BUSY);
		assert(mailbox_claim_status(&c3) == MAILBOX_CLAIM_BUSY);
		assert(!mailbox_client_should_claim(&c2));
		assert(!mailbox_client_should_claim(&c3));

		/* Host picks up the winner (the read that delivered the claim)
		 * and releases: fresh offer, 'a' cleared. */
		read_seq = st.seq;
		mailbox_parse(&hst, st.v, st.len);
		mailbox_set_mine(&hst, OFFER_E1, sizeof(OFFER_E1));
		mailbox_arm_release(&hst);
		assert(mailbox_merge(&hst, st.v, st.len, hw, &hlen, sizeof(hw)) == 0);
		assert(store_put(&st, hw, hlen, read_seq + 1, read_seq) == 0);
		mailbox_init(&probe, 1);
		mailbox_parse(&probe, st.v, st.len);
		assert(probe.slot_a_len == 0);

		/* The two remaining race the freed slot from one snapshot: one lands. */
		mailbox_parse(&c2, st.v, st.len);
		mailbox_parse(&c3, st.v, st.len);
		assert(mailbox_claim_status(&c2) == MAILBOX_CLAIM_FREE);
		assert(mailbox_claim_status(&c3) == MAILBOX_CLAIM_FREE);
		read_seq = st.seq;
		memcpy(snap, st.v, st.len);
		snaplen = st.len;
		r2 = client_claim(&st, &c2, snap, snaplen, read_seq);
		r3 = client_claim(&st, &c3, snap, snaplen, read_seq);
		assert((r2 == 0) + (r3 == 0) == 1);
		assert((r2 == -1) + (r3 == -1) == 1);
	}

	/* Reconnect: a client whose answer was picked up and cleared re-enters the
	 * claim loop against the current offer, exactly as a new joiner would
	 *. */
	{
		struct mailbox c;
		uint8_t held[64], freed[64];
		size_t heldlen, freedlen;

		/* The client holds the slot (its answer plus the offer it read). */
		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		mailbox_parse(&c, offv, offlen);
		heldlen = mailbox_build(&c, held, sizeof(held));
		mailbox_parse(&c, held, heldlen);
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_HELD);
		assert(!mailbox_client_should_claim(&c));

		/* Host releases: the offer stands, 'a' is gone. The same client now
		 * sees FREE and re-claims without any special reconnect path. */
		freedlen = offer_only(freed, sizeof(freed), OFFER_E, sizeof(OFFER_E));
		mailbox_parse(&c, freed, freedlen);
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_FREE);
		assert(mailbox_client_should_claim(&c));
	}

	/*
	 * Relaying: a client asked to place the container on a family its host
	 * cannot reach. It is publishing for somebody else, so it must put back
	 * exactly what is there -- taking the answer slot would seize the
	 * turnstile for the session, and dropping it would discard a claim in
	 * flight.
	 */
	{
		struct mailbox c, other, blank;
		uint8_t cur[BEP44_MAX_VALUE], relayed[BEP44_MAX_VALUE];
		uint8_t held[BEP44_MAX_VALUE];
		size_t curlen, outlen = 0, heldlen;

		/* The container as it stands: another client's claim in the
		 * answer slot, the host's offer in the other. */
		mailbox_init(&other, 0);
		mailbox_set_mine(&other, ANS2, sizeof(ANS2));
		mailbox_parse(&other, offv, offlen);
		curlen = mailbox_build(&other, cur, sizeof(cur));
		assert(curlen);

		/* The relayer has an answer of its own, which is exactly what
		 * must not go out. */
		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		mailbox_parse(&c, cur, curlen);

		assert(!mailbox_relay(&c, cur, curlen, relayed, &outlen,
				      sizeof(relayed)));
		/* Byte for byte what was read: not our answer, and not a
		 * container with the other client's claim missing. */
		assert(outlen == curlen && !memcmp(relayed, cur, curlen));

		/* The ordinary merge on the same input is what the relay must
		 * NOT do: it writes our own answer in. */
		heldlen = mailbox_build(&c, held, sizeof(held));
		assert(heldlen != curlen || memcmp(held, cur, curlen));

		/*
		 * The nodes being stored to are the ones that do not hold the
		 * value yet, so the read comes back empty. What we last read is
		 * placed instead -- otherwise the store would put an empty
		 * container where the mailbox belongs.
		 */
		outlen = 0;
		assert(!mailbox_relay(&c, NULL, 0, relayed, &outlen,
				      sizeof(relayed)));
		assert(outlen == curlen && !memcmp(relayed, cur, curlen));

		/* An end that has never read the container has nothing to
		 * place, and must not place emptiness over a good value. */
		mailbox_init(&blank, 0);
		mailbox_set_mine(&blank, ANS1, sizeof(ANS1));
		outlen = 0;
		assert(mailbox_relay(&blank, NULL, 0, relayed, &outlen,
				     sizeof(relayed)) == -1);

		/* Relaying leaves the relayer's own turnstile state alone: it
		 * still holds what it held and still owes what it owed. */
		assert(mailbox_claim_status(&c) == MAILBOX_CLAIM_BUSY);
		assert(!mailbox_client_should_claim(&c));
	}

	/* ---- 6. The tombstone: the session is over ---- */
	{
		static const uint8_t TOMB[] = { 0x7B, 0x7B };
		struct mailbox h, c;
		const uint8_t *slot;
		uint8_t ended[BEP44_MAX_VALUE], claimed[BEP44_MAX_VALUE];
		uint8_t live[BEP44_MAX_VALUE];
		size_t endlen, livelen, outlen;

		/* A host that is serving: an offer, and a claim in the mutex. */
		mailbox_init(&h, 1);
		mailbox_set_mine(&h, OFFER_E, sizeof(OFFER_E));
		mailbox_parse(&h, offv, offlen);
		mailbox_init(&c, 0);
		mailbox_set_mine(&c, ANS1, sizeof(ANS1));
		assert(!mailbox_merge(&c, offv, offlen, claimed, &outlen,
				      sizeof(claimed)));
		mailbox_parse(&h, claimed, outlen);
		assert(mailbox_peer_slot(&h, &slot) == sizeof(ANS1));
		assert(!mailbox_tombstoned(&h));

		/* Ending replaces the lot: no offer to answer, no claim to
		 * serve, one tombstone where the invitation points. */
		mailbox_entomb(&h, TOMB, sizeof(TOMB));
		endlen = mailbox_build(&h, ended, sizeof(ended));
		assert(endlen == 6 + sizeof(TOMB) + 1);
		assert(!memcmp(ended, "d1:x2:", 6));
		assert(!memcmp(ended + 6, TOMB, sizeof(TOMB)));
		assert(ended[endlen - 1] == 'e');

		/* And it is placed until it is the only thing there: a claim
		 * landing over it is another round, not the end of it. */
		mailbox_parse(&h, ended, endlen);
		assert(!h.need_write);
		mailbox_parse(&h, claimed, outlen);
		assert(h.need_write);

		/* A client reads it. The container layer only reports it; when
		 * it is believed is sig's judgement, not the container's. */
		mailbox_init(&c, 0);
		mailbox_parse(&c, ended, endlen);
		assert(mailbox_tombstoned(&c));
		assert(!mailbox_peer_slot(&c, &slot));

		/* A client does not claim an ended mailbox: there is nobody
		 * left to answer it, and every claim the host loses the CAS to
		 * is another round before the end is where the next joiner
		 * looks. Should it write for another reason, the tombstone goes
		 * through rather than being erased. */
		mailbox_set_mine(&c, ANS2, sizeof(ANS2));
		assert(!mailbox_client_should_claim(&c));
		assert(!mailbox_merge(&c, ended, endlen, claimed, &outlen,
				      sizeof(claimed)));
		mailbox_init(&h, 0);
		mailbox_parse(&h, claimed, outlen);
		assert(mailbox_tombstoned(&h));

		/* A live host does the opposite with a tombstone somebody else
		 * wrote: everyone holding the invitation can write this
		 * container, so the one end that knows takes the slot back. */
		mailbox_init(&h, 1);
		mailbox_set_mine(&h, OFFER_E, sizeof(OFFER_E));
		mailbox_parse(&h, ended, endlen);
		assert(mailbox_tombstoned(&h) && h.need_write);
		livelen = mailbox_build(&h, live, sizeof(live));
		mailbox_init(&c, 0);
		mailbox_parse(&c, live, livelen);
		assert(!mailbox_tombstoned(&c));
		assert(mailbox_peer_slot(&c, &slot) == sizeof(OFFER_E));

		/*
		 * And a tombstone standing beside an offer stalls nobody: that
		 * is a live host about to erase it, so a claimant carries on
		 * claiming rather than handing every holder of the invitation a
		 * way to freeze the turnstile. No writer here builds that
		 * pairing, so the container is assembled by hand -- which is
		 * what a holder writing a forged tombstone would do.
		 */
		{
			uint8_t both[64];
			size_t bl = 0;

			memcpy(both, "d1:o", 4); bl = 4;
			bl += (size_t)sprintf((char *)both + bl, "%u:",
					      (unsigned)sizeof(OFFER_E));
			memcpy(both + bl, OFFER_E, sizeof(OFFER_E));
			bl += sizeof(OFFER_E);
			memcpy(both + bl, "1:x", 3); bl += 3;
			bl += (size_t)sprintf((char *)both + bl, "%u:",
					      (unsigned)sizeof(TOMB));
			memcpy(both + bl, TOMB, sizeof(TOMB));
			bl += sizeof(TOMB);
			both[bl++] = 'e';

			mailbox_init(&c, 0);
			mailbox_set_mine(&c, ANS1, sizeof(ANS1));
			mailbox_parse(&c, both, bl);
			assert(mailbox_tombstoned(&c));
			assert(mailbox_peer_slot(&c, &slot) == sizeof(OFFER_E));
			assert(mailbox_client_should_claim(&c));

			/* The claim it then writes drops the contradicted
			 * tombstone, so the container never carries three
			 * sealed slots at once. */
			assert(!mailbox_merge(&c, both, bl, claimed, &outlen,
					      sizeof(claimed)));
			mailbox_init(&h, 0);
			mailbox_parse(&h, claimed, outlen);
			assert(!mailbox_tombstoned(&h));
			assert(mailbox_peer_slot(&h, &slot) == sizeof(OFFER_E));
		}

		/* Relaying on somebody else's behalf preserves a tombstone the
		 * same way, so a client rendezvousing for a host it cannot see
		 * does not quietly revive a session that has ended. */
		mailbox_init(&c, 0);
		mailbox_parse(&c, ended, endlen);
		assert(!mailbox_relay(&c, ended, endlen, claimed, &outlen,
				      sizeof(claimed)));
		assert(outlen == endlen && !memcmp(claimed, ended, endlen));
	}

	arming_a_release_makes_the_write_due();

	printf("mailbox: all container, turnstile, tombstone, CAS and relay "
	       "cases pass\n");
	return 0;
}
