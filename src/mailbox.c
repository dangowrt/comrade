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

void mailbox_arm_release(struct mailbox *m)
{
	m->clear_peer = 1;
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

/* Raw slot extraction only; no bookkeeping (the merge path uses this). */
static void parse_slots(struct mailbox *m, const uint8_t *v, size_t v_len)
{
	m->slot_o_len = slot_extract(v, v_len, "o", m->slot_o, sizeof(m->slot_o));
	m->slot_a_len = slot_extract(v, v_len, "a", m->slot_a, sizeof(m->slot_a));
}

/* We must (re)write when our slot in the container does not match ours. */
static void recompute_need_write(struct mailbox *m)
{
	const uint8_t *cur = m->is_host ? m->slot_o : m->slot_a;
	size_t cur_len = m->is_host ? m->slot_o_len : m->slot_a_len;

	if (!m->have_mine)
		m->need_write = 0;
	else
		m->need_write = (cur_len != m->mine_len ||
				 memcmp(cur, m->mine, m->mine_len)) ? 1 : 0;
}

void mailbox_parse(struct mailbox *m, const uint8_t *v, size_t v_len)
{
	parse_slots(m, v, v_len);
	m->have_cur = 1;
	recompute_need_write(m);
}

size_t mailbox_build(struct mailbox *m, uint8_t *out, size_t outlen)
{
	struct benc_buf b;
	const uint8_t *pa = NULL, *po = NULL;
	size_t la = 0, lo = 0;

	if (m->is_host) {
		po = m->mine;
		lo = m->mine_len;
		pa = m->slot_a;
		la = m->slot_a_len;
		if (m->clear_peer) {
			la = 0;			/* release the answer slot */
			m->clear_peer = 0;	/* one-shot per rotate */
		}
	} else {
		pa = m->mine;
		la = m->mine_len;
		po = m->slot_o;
		lo = m->slot_o_len;
	}

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
	benc_raw_add(&b, "e", 1);
	return b.err ? 0 : b.len;
}

int mailbox_merge(struct mailbox *m, const uint8_t *cur, size_t cur_len,
		  uint8_t *out, size_t *out_len, size_t max)
{
	size_t n;

	if (cur)
		parse_slots(m, cur, cur_len);
	n = mailbox_build(m, out, max);
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
	if (m->have_mine && m->slot_a_len == m->mine_len &&
	    !memcmp(m->slot_a, m->mine, m->mine_len))
		return MAILBOX_CLAIM_HELD;
	return MAILBOX_CLAIM_BUSY;
}

int mailbox_client_should_claim(const struct mailbox *m)
{
	return !m->is_host && m->have_mine && m->need_write && m->have_cur &&
	       m->slot_a_len == 0;
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
