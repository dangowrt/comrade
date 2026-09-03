/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_MAILBOX_H
#define COMRADE_MAILBOX_H

#include <stddef.h>
#include <stdint.h>

/*
 * The rendezvous mailbox: the container at the heart of the turnstile
 * factored out of sig.c so its build, parse,
 * merge and claim logic can be exercised without a DHT or any crypto.
 *
 * The container is a bencoded dict of three optional slots, the host's offer
 * in 'o', the client's answer in 'a', and the host's tombstone in 'x':
 *
 *     d 1:a <sealed answer> 1:o <sealed offer> 1:x <sealed tombstone> e
 *
 * Each slot holds an opaque, already-sealed byte blob; this layer never looks
 * inside it. The host owns 'o' and 'x', the client owns 'a'. A writer preserves
 * the peer's slot on every read-modify-write, except that the host, once per
 * rotate, drops the claim it picked up from 'a' -- from every write until a
 * read shows it gone -- to release the turnstile.
 *
 * The tombstone says the session behind this invitation has ended, so a client
 * joining it gets an answer instead of waiting for an offer that will never
 * come again. It belongs to this container rather than to the signalling
 * because this is the part that outlives the host: it is stored, and read by
 * somebody who arrives long afterwards. A host writes it as it goes and never
 * beside an offer, the two together saying a session is both live and over. A
 * LIVE host does the opposite and erases any 'x' it reads, which is what makes
 * the slot self-healing -- every holder of the invitation can write the
 * container, so a forged tombstone must not outlive the next write of the host
 * it lies about.
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
	uint8_t slot_x[MAILBOX_SLOT_MAX];
	size_t slot_x_len;
	int have_cur;			/* the container has been read at least once */
	int need_write;			/* our slot in the container is stale */
	int slot_a_own;			/* the answer slot holds OUR claimant's
					 * claim (possibly a superseded one); set
					 * by the owner via mailbox_note_own_answer,
					 * cleared on every parse */
	uint8_t released[MAILBOX_SLOT_MAX];	/* host: the claim being released;
						 * omitted from builds until a read
						 * shows it gone or superseded */
	size_t released_len;
	uint8_t refused[MAILBOX_SLOT_MAX];	/* host: a claim that did not open;
						 * omitted from every build for as
						 * long as the slot holds it */
	size_t refused_len;
	uint8_t tomb[MAILBOX_SLOT_MAX];	/* host: the tombstone we are placing */
	size_t tomb_len;
	int ending;			/* host: the container is a tombstone now */
};

void mailbox_init(struct mailbox *m, int is_host);

/* Set our slot value (the sealed offer or answer); marks it as needing a write. */
void mailbox_set_mine(struct mailbox *m, const uint8_t *data, size_t len);

/* Client: stop advertising our answer, so a slot the host frees is not
 * re-claimed automatically. A later mailbox_set_mine re-arms it. */
void mailbox_withdraw(struct mailbox *m);

/* Host: release the turnstile, paired with a fresh offer in mailbox_set_mine.
 * The answer slot's current claim is omitted from every build until a read
 * shows it gone or replaced, so a write that loses a store race and is
 * retried still releases it -- a new claim arriving meanwhile is kept. */
void mailbox_arm_release(struct mailbox *m);

/*
 * Host: this exact claim did not open, so nothing can ever be served for it.
 * It is omitted from every build for as long as it is what the answer slot
 * holds -- however many copies of the container carrying it are still being
 * served, and whichever of them a write happens to merge against.
 *
 * NOT THE SAME THING AS A RELEASE, AND THE DIFFERENCE IS THE WHOLE OF IT. A
 * release is about a claimant that is HERE: the host will not serve it this
 * round -- its punch is already running, it holds a worker, the admission
 * budget is spent -- so the mutex goes back and the claimant asks again. It
 * re-puts the claim it already has, unchanged, because nothing about it
 * changed. A host that held those bytes against it would erase every retry,
 * and the two would sit there for ever, one posting and the other waiting.
 *
 * A refusal is about a claimant that is GONE, or was never there: the box does
 * not open, so there is nobody to serve and no later reading of those bytes
 * that could become useful. Only that case may be held against the bytes --
 * and it must be, because it is the one a lagging copy would otherwise put
 * back in front of the turnstile for the life of the item.
 */
void mailbox_refuse(struct mailbox *m, const uint8_t *data, size_t len);

/*
 * Host: the session is over. Every later build is the tombstone alone -- both
 * slots dropped, 'x' holding `data` -- so what is left where the invitation
 * points says the session ended rather than that the host is merely slow. One
 * way: nothing puts a mailbox back to serving after this.
 */
void mailbox_entomb(struct mailbox *m, const uint8_t *data, size_t len);

/* The last-read container carried a tombstone. */
int mailbox_tombstoned(const struct mailbox *m);

/* Client: the owner has looked inside the answer slot and recognised (or not)
 * its own claimant's claim. An own claim -- typically a superseded one from an
 * earlier attempt -- may be overwritten; without this, a client could wedge
 * itself out of the turnstile behind its own stale claim. Cleared on parse. */
void mailbox_note_own_answer(struct mailbox *m, int own);

/* Parse a container into its slots; marks it read and recomputes need_write. */
void mailbox_parse(struct mailbox *m, const uint8_t *v, size_t v_len);

/* Build the merged container (our slot plus the peer's, if known) into out;
 * returns its length, or 0 on error. A pending host release omits the
 * released claim from the answer slot, and an ended host builds its tombstone
 * and nothing else. */
size_t mailbox_build(struct mailbox *m, uint8_t *out, size_t outlen);

/*
 * Read-modify-write in one call, matching the bep44 merge-callback contract:
 * parse cur (the value currently stored, NULL if none) then build our merged
 * value into out. Returns 0 on success, -1 on error.
 */
int mailbox_merge(struct mailbox *m, const uint8_t *cur, size_t cur_len,
		  uint8_t *out, size_t *out_len, size_t max);

/*
 * Re-store the container as it stands, for an end publishing on somebody
 * else's behalf: a client asked by a host to establish a rendezvous on a
 * family the host cannot reach itself.
 *
 * Neither slot is the relayer's to write. The offer is the host's, and the
 * answer is whichever client holds the turnstile -- writing our own slot here
 * would claim that mutex and lock every other client out for the session, and
 * dropping the slot would throw away a claim in flight. So both go back
 * exactly as found.
 *
 * What the read found wins, since it is the newer of the two views; where it
 * found nothing -- which is the whole point, these being nodes that do not
 * hold the value yet -- what we last read is what gets placed. An end that has
 * never read the container has nothing to relay and this returns -1, rather
 * than storing an empty one over a good one.
 *
 * Reads m and does not touch it: the relayer's own turnstile state is not this
 * operation's business. Matches the bep44 merge-callback contract otherwise.
 */
int mailbox_relay(const struct mailbox *m, const uint8_t *cur, size_t cur_len,
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
