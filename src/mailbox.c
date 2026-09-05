/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "bencode.h"
#include "mailbox.h"

void mailbox_init(struct mailbox *m, int is_host)
{
	memset(m, 0, sizeof(*m));
	m->is_host = is_host;
}

void mailbox_set_mine(struct mailbox *m, const uint8_t *data, size_t len)
{
	if (len > sizeof(m->mine))
		return;
	memcpy(m->mine, data, len);
	m->mine_len = len;
	m->have_mine = 1;
	m->need_write = 1;
}

void mailbox_withdraw(struct mailbox *m)
{
	m->have_mine = 0;
	m->need_write = 0;
}

/* The claim under release: gone or replaced means the release is done. */
static int releasing(const struct mailbox *m)
{
	return m->released_len && m->slot_a_len == m->released_len &&
	       !memcmp(m->slot_a, m->released, m->released_len);
}

/*
 * The claim in the slot is one that did not open. Unlike a release this is
 * never completed by observing the slot empty: those bytes are held against
 * for as long as they keep coming back, which is what a copy still serving
 * them does. It ends when somebody writes something else, because whatever
 * that is, it is not the claim nobody can open.
 */
static int refusing(const struct mailbox *m)
{
	return m->refused_len && m->slot_a_len == m->refused_len &&
	       !memcmp(m->slot_a, m->refused, m->refused_len);
}

/* We must (re)write when our slot in the container does not match ours. */
static void recompute_need_write(struct mailbox *m)
{
	const uint8_t *cur = m->is_host ? m->slot_o : m->slot_a;
	size_t cur_len = m->is_host ? m->slot_o_len : m->slot_a_len;

	if (m->ending)
		/* Placed once the container is the tombstone and nothing but,
		 * so a write that lost a race -- or a holder writing a claim
		 * over it -- is followed by another. */
		m->need_write = (m->slot_x_len != m->tomb_len ||
				 memcmp(m->slot_x, m->tomb, m->tomb_len) ||
				 m->slot_o_len || m->slot_a_len) ? 1 : 0;
	else if (m->is_host && m->slot_x_len)
		/*
		 * A tombstone under a host that is still serving. Nobody who
		 * can write this container has anything true to say about
		 * whether the session behind it is over, so the one end that
		 * does takes the slot back on its next write.
		 */
		m->need_write = 1;
	else if (!m->have_mine)
		m->need_write = 0;
	else if (m->is_host && (releasing(m) || refusing(m)))
		/*
		 * The claim being let go is still in the container, so what is
		 * stored is not what we would write, whatever our own slot
		 * says. Without this a release armed without a fresh offer
		 * beside it never reaches the DHT, and the answer slot -- the
		 * turnstile mutex -- stays held by a claim nobody will serve.
		 */
		m->need_write = 1;
	else
		m->need_write = (cur_len != m->mine_len ||
				 memcmp(cur, m->mine, m->mine_len)) ? 1 : 0;
}


void mailbox_arm_release(struct mailbox *m)
{
	memcpy(m->released, m->slot_a, m->slot_a_len);
	m->released_len = m->slot_a_len;
	/*
	 * Scheduled here rather than left to the next read of the container.
	 * The rule that a releasing host must write is in
	 * recompute_need_write, and recompute ran only on a parse -- so arming
	 * a release marked nothing, and the turnstile stayed held until some
	 * other reason to write came along. The slot is a mutex: every round
	 * it is held for is a round in which no claimant may write, so the
	 * release has to be due at once.
	 */
	recompute_need_write(m);
}

void mailbox_refuse(struct mailbox *m, const uint8_t *data, size_t len)
{
	if (!m->is_host || !len || len > sizeof(m->refused))
		return;
	memcpy(m->refused, data, len);
	m->refused_len = len;
	recompute_need_write(m);
}

void mailbox_entomb(struct mailbox *m, const uint8_t *data, size_t len)
{
	if (!m->is_host || len > sizeof(m->tomb) || !len)
		return;
	memcpy(m->tomb, data, len);
	m->tomb_len = len;
	m->ending = 1;
	m->released_len = 0;		/* nothing left to release a turnstile for */
	m->need_write = 1;
}

int mailbox_tombstoned(const struct mailbox *m)
{
	return m->have_cur && m->slot_x_len != 0;
}

void mailbox_note_own_answer(struct mailbox *m, int own)
{
	m->slot_a_own = own;
}



/* Pull one slot's sealed string out of the container into dst. */
static size_t slot_extract(const uint8_t *v, size_t v_len, const char *key,
			   uint8_t *dst, size_t dst_max)
{
	const uint8_t *val, *str;
	size_t val_len, str_len;

	if (benc_dict_find(v, v_len, key, &val, &val_len) ||
	    benc_str_get(val, val_len, &str, &str_len) || str_len > dst_max)
		return 0;
	memcpy(dst, str, str_len);
	return str_len;
}

/* Raw slot extraction; a fresh read invalidates the own-claim note and
 * completes a release whose claim is observed gone or replaced. */
static void parse_slots(struct mailbox *m, const uint8_t *v, size_t v_len)
{
	m->slot_o_len = slot_extract(v, v_len, "o", m->slot_o, sizeof(m->slot_o));
	m->slot_a_len = slot_extract(v, v_len, "a", m->slot_a, sizeof(m->slot_a));
	m->slot_x_len = slot_extract(v, v_len, "x", m->slot_x, sizeof(m->slot_x));
	m->slot_a_own = 0;
	if (m->released_len && (m->slot_a_len != m->released_len ||
				memcmp(m->slot_a, m->released, m->released_len)))
		m->released_len = 0;
}


void mailbox_parse(struct mailbox *m, const uint8_t *v, size_t v_len)
{
	parse_slots(m, v, v_len);
	m->have_cur = 1;
	recompute_need_write(m);
}

/* The container itself: the answer slot, the offer slot and the tombstone in
 * bencode's key order, each omitted when empty. Every writer goes through
 * here, so there is one definition of what the value on the wire looks like. */
static size_t build_slots(const uint8_t *pa, size_t la, const uint8_t *po,
			  size_t lo, const uint8_t *px, size_t lx,
			  uint8_t *out, size_t outlen)
{
	struct benc_buf b;

	benc_buf_init(&b, out, outlen);
	benc_raw_add(&b, "d", 1);
	if (la) {
		benc_key_add(&b, "a");
		benc_str_add(&b, pa, la);
	}
	if (lo) {
		benc_key_add(&b, "o");
		benc_str_add(&b, po, lo);
	}
	if (lx) {
		benc_key_add(&b, "x");
		benc_str_add(&b, px, lx);
	}
	benc_raw_add(&b, "e", 1);
	return b.err ? 0 : b.len;
}

size_t mailbox_build(struct mailbox *m, uint8_t *out, size_t outlen)
{
	const uint8_t *pa = NULL, *po = NULL, *px = NULL;
	size_t la = 0, lo = 0, lx = 0;

	if (m->ending)
		/* An offer beside it would say the session is both live and
		 * over, and a claim would be one nobody is left to serve. */
		return build_slots(NULL, 0, NULL, 0, m->tomb, m->tomb_len,
				   out, outlen);

	if (m->is_host) {
		po = m->mine;
		lo = m->mine_len;
		pa = m->slot_a;
		la = m->slot_a_len;
		if (releasing(m) || refusing(m))
			la = 0;			/* release the answer slot */
		/* A live host's write is what erases a tombstone it reads: lx
		 * stays 0 whatever the container carried. */
	} else {
		pa = m->mine;
		la = m->mine_len;
		po = m->slot_o;
		lo = m->slot_o_len;
		/*
		 * A client passes a tombstone through: it is not the client's to
		 * judge, and dropping it while claiming would erase the one
		 * thing telling the next joiner not to wait. Not beside an
		 * offer, though -- that pairing says the session is both live
		 * and over, the host is about to erase it anyway, and carrying
		 * all three slots is what would take the container past what one
		 * mutable item holds.
		 */
		if (!lo) {
			px = m->slot_x;
			lx = m->slot_x_len;
		}
	}

	return build_slots(pa, la, po, lo, px, lx, out, outlen);
}

void mailbox_note_seq(struct mailbox *m, int64_t seq)
{
	if (seq > m->seq_high)
		m->seq_high = seq;
}

/* Whether a delivered copy may be written from: see mailbox_merge. */
static int stale(const struct mailbox *m, const uint8_t *cur, int64_t seq)
{
	return cur && seq >= 0 && m->seq_high && seq < m->seq_high;
}

int mailbox_merge(struct mailbox *m, const uint8_t *cur, size_t cur_len,
		  int64_t seq, uint8_t *out, size_t *out_len, size_t max)
{
	size_t n;

	if (!cur)
		/*
		 * Nothing stored where we asked, so the sequence we are holding
		 * describes a container that is not there any more and whatever
		 * we write starts a new run. Noticing it here is what keeps a
		 * clock out of this: an item that ages out everywhere is found
		 * by our own next write rather than waited out.
		 */
		m->seq_high = 0;
	else if (stale(m, cur, seq))
		cur = NULL;		/* merged over, not from */
	if (cur)
		parse_slots(m, cur, cur_len);
	n = mailbox_build(m, out, max);
	if (!n)
		return -1;
	*out_len = n;
	return 0;
}

int mailbox_relay(const struct mailbox *m, const uint8_t *cur, size_t cur_len,
		  int64_t seq, uint8_t *out, size_t *out_len, size_t max)
{
	uint8_t a[MAILBOX_SLOT_MAX], o[MAILBOX_SLOT_MAX], x[MAILBOX_SLOT_MAX];
	size_t la = 0, lo = 0, lx = 0, n;

	if (stale(m, cur, seq))
		cur = NULL;
	if (cur && cur_len) {
		la = slot_extract(cur, cur_len, "a", a, sizeof(a));
		lo = slot_extract(cur, cur_len, "o", o, sizeof(o));
		lx = slot_extract(cur, cur_len, "x", x, sizeof(x));
	}
	if (!la && !lo && !lx) {
		if (!m->have_cur)
			return -1;
		memcpy(a, m->slot_a, m->slot_a_len);
		la = m->slot_a_len;
		memcpy(o, m->slot_o, m->slot_o_len);
		lo = m->slot_o_len;
		memcpy(x, m->slot_x, m->slot_x_len);
		lx = m->slot_x_len;
	}
	if (!la && !lo && !lx)		/* nothing worth placing anywhere */
		return -1;
	if (lo)
		lx = 0;			/* see mailbox_build: never both */
	n = build_slots(a, la, o, lo, x, lx, out, max);
	if (!n)
		return -1;
	*out_len = n;
	return 0;
}

enum mailbox_claim mailbox_claim_status(const struct mailbox *m)
{
	if (m->is_host || !m->have_cur)
		return MAILBOX_CLAIM_UNKNOWN;
	if (!m->slot_a_len)
		return MAILBOX_CLAIM_FREE;
	if (m->slot_a_own)
		return MAILBOX_CLAIM_HELD;
	if (m->have_mine && m->slot_a_len == m->mine_len &&
	    !memcmp(m->slot_a, m->mine, m->mine_len))
		return MAILBOX_CLAIM_HELD;
	return MAILBOX_CLAIM_BUSY;
}

int mailbox_client_should_claim(const struct mailbox *m)
{
	/*
	 * A container that carries a tombstone and no offer has no host left to
	 * answer, so a claim written into it is a write nobody will read -- and
	 * it costs more than nothing: the host is entombing the same item, and
	 * every claim it loses the compare-and-swap to is another round before
	 * the end of the session is where the next joiner will look. A
	 * tombstone standing beside an offer is not this: that is a live host
	 * about to erase it, and stopping there would let any holder of the
	 * invitation stall every claimant by writing one.
	 */
	if (m->slot_x_len && !m->slot_o_len)
		return 0;
	return !m->is_host && m->have_mine && m->need_write && m->have_cur &&
	       (m->slot_a_len == 0 || m->slot_a_own);
}

size_t mailbox_peer_slot_in(const struct mailbox *m, const uint8_t *v,
			    size_t v_len, uint8_t *out, size_t max)
{
	if (!v || !v_len || max < MAILBOX_SLOT_MAX)
		return 0;
	return slot_extract(v, v_len, m->is_host ? "a" : "o", out, max);
}

size_t mailbox_peer_slot(const struct mailbox *m, const uint8_t **out)
{
	if (m->is_host) {
		*out = m->slot_a;
		return m->slot_a_len;
	}
	*out = m->slot_o;
	return m->slot_o_len;
}
