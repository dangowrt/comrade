/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CLAIMLOG_H
#define COMRADE_CLAIMLOG_H

/*
 * Telling a claim the mailbox is repeating from a claimant asking again.
 *
 * A BEP 44 item is eventually consistent, so a replica that missed the
 * release keeps answering reads with the container that still holds a claim,
 * and one arrives again seconds after it has been served. Read as a fresh
 * ask, it starts a second punch against a session that is a second old.
 *
 * The password decides it. It is minted per attempt -- conn_fresh_pwd on a
 * resumption, conn_gen_ice on a regather -- so the password a connection was
 * punched from names that same attempt, and a claimant that really is trying
 * again brings one of its own.
 */

/* Whether a claim is the very attempt a connection was punched from, given
 * that connection's remote password. */
int claim_made(const char *conn_pwd, const char *claim_pwd);

#endif /* COMRADE_CLAIMLOG_H */
