/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_MAILBOX_H
#define COMRADE_MAILBOX_H

#include <stddef.h>
#include <stdint.h>

/*
 * The rendezvous mailbox: the two-slot container at the heart of the turnstile
 * factored out of sig.c so its build, parse,
 * merge and claim logic can be exercised without a DHT or any crypto.
 *
 * The container is a bencoded dict of two optional slots, the host's offer in
 * 'o' and the client's answer in 'a':
 *
 *     d 1:a <sealed answer> 1:o <sealed offer> e
 *
 * Each slot holds an opaque, already-sealed byte blob; this layer never looks
 * inside it. The host owns 'o' and the client owns 'a'. A writer preserves the
 * peer's slot on every read-modify-write, except that the host clears 'a' once
 * per rotate to release the turnstile.
 */

#define MAILBOX_SLOT_MAX 512	/* one sealed slot; holds SIG_SEALED_MAX */

/* The observed state of the answer slot, from the client's point of view. */
enum mailbox_claim {
	MAILBOX_CLAIM_UNKNOWN = 0,	/* host, or the mailbox not yet read */
	MAILBOX_CLAIM_FREE,		/* answer slot empty -- claimable */
	MAILBOX_CLAIM_HELD,		/* our own answer occupies the slot */
	MAILBOX_CLAIM_BUSY		/* another client's answer holds it */
};

struct mailbox {
	int is_host;			/* our slot: 'o' (host) or 'a' (client) */

	uint8_t mine[MAILBOX_SLOT_MAX];	/* our slot's sealed bytes */
	size_t mine_len;
	int have_mine;

	uint8_t slot_o[MAILBOX_SLOT_MAX];	/* last-seen container slots, */
	size_t slot_o_len;			/* a zero length means absent */
	uint8_t slot_a[MAILBOX_SLOT_MAX];
	size_t slot_a_len;
	int have_cur;			/* the container has been read at least once */
	int need_write;			/* our slot in the container is stale */
	int clear_peer;			/* host one-shot: drop 'a' on the next build */
};

void mailbox_init(struct mailbox *m, int is_host);

/* Set our slot value (the sealed offer or answer); marks it as needing a write. */
void mailbox_set_mine(struct mailbox *m, const uint8_t *data, size_t len);

/* Client: stop advertising our answer, so a slot the host frees is not
 * re-claimed automatically. A later mailbox_set_mine re-arms it. */
void mailbox_withdraw(struct mailbox *m);

/* Host: arm the one-shot that drops the answer slot on the next build, the
 * turnstile release paired with a fresh offer in mailbox_set_mine. */
void mailbox_arm_release(struct mailbox *m);

/* Parse a container into the two slots; marks it read and recomputes need_write. */
void mailbox_parse(struct mailbox *m, const uint8_t *v, size_t v_len);

/* Build the merged container (our slot plus the peer's, if known) into out;
 * returns its length, or 0 on error. Consumes a pending host release, dropping
 * the answer slot exactly once. */
size_t mailbox_build(struct mailbox *m, uint8_t *out, size_t outlen);

/*
 * Read-modify-write in one call, matching the bep44 merge-callback contract:
 * parse cur (the value currently stored, NULL if none) then build our merged
 * value into out. Returns 0 on success, -1 on error.
 */
int mailbox_merge(struct mailbox *m, const uint8_t *cur, size_t cur_len,
		  uint8_t *out, size_t *out_len, size_t max);

/* The client's view of the answer slot in the last-read container. */
enum mailbox_claim mailbox_claim_status(const struct mailbox *m);

/*
 * Whether a client should write its answer now: it has an answer to place, its
 * slot in the container is stale, the container has been read, and the answer
 * slot is empty (the turnstile mutex is free). The empty-slot precondition is
 * the claim rule -- a slot already holding an answer belongs to another client.
 */
int mailbox_client_should_claim(const struct mailbox *m);

/*
 * The peer's slot in the last-read container (the offer for a client, the
 * answer for a host): points *out at it and returns its length, 0 if absent.
 */
size_t mailbox_peer_slot(const struct mailbox *m, const uint8_t **out);

#endif
