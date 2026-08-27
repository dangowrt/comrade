/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CLAIMLOG_H
#define COMRADE_CLAIMLOG_H

/*
 * The claims already spent, so the mailbox cannot sell one of them twice.
 *
 * A BEP 44 item is eventually consistent: a replica that missed the release
 * keeps answering reads with the container that still holds a claim, so a
 * claim outlives the client that wrote it by minutes. Punching one of those
 * spends a whole punch budget on a peer that is gone, and rotates the offer
 * out from under whoever is claiming for real.
 *
 * The password separates the two cases. It is minted per attempt, so a claim
 * matching in both ufrag and password is the same attempt coming back, while
 * a claimant genuinely trying again brings a new one and is admitted as ever.
 *
 * A ring: several claimants can leave one behind, and the newest is the one
 * most likely to still be circulating. A claim pushed out of it is punched
 * again, which is where this started and no worse.
 */

#define CLAIMLOG_MAX 8
#define CLAIMLOG_ID 40

struct claimlog_entry {
	char ufrag[CLAIMLOG_ID];
	char pwd[CLAIMLOG_ID];
};

struct claimlog {
	struct claimlog_entry e[CLAIMLOG_MAX];
	int next;
};

/* Remember a claim that has been punched and came to nothing. */
void claimlog_note(struct claimlog *l, const char *ufrag, const char *pwd);

/* Whether this exact claim has already been spent. */
int claimlog_seen(const struct claimlog *l, const char *ufrag,
		  const char *pwd);

/*
 * Whether a claim is the very attempt a connection was punched from, given
 * that connection's remote password. The mailbox hands a claim back for a
 * while after it has been served, and read as a fresh ask it starts a second
 * punch against a session that is one second old.
 */
int claim_made(const char *conn_pwd, const char *claim_pwd);

#endif /* COMRADE_CLAIMLOG_H */
