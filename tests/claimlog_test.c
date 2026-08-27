/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "claimlog.h"

/* The case it exists for: the same attempt handed back by a stale replica. */
static void the_same_attempt_is_recognised(void)
{
	struct claimlog l;

	memset(&l, 0, sizeof(l));
	assert(!claimlog_seen(&l, "1f78cab7", "92d421"));
	claimlog_note(&l, "1f78cab7", "92d421");
	assert(claimlog_seen(&l, "1f78cab7", "92d421"));
}

/* And the case it must not catch: the claimant asking again, which brings a
 * fresh password under the identity it keeps across a resumption. */
static void a_new_attempt_is_not(void)
{
	struct claimlog l;

	memset(&l, 0, sizeof(l));
	claimlog_note(&l, "1f78cab7", "92d421");
	assert(!claimlog_seen(&l, "1f78cab7", "5b0e77"));
	assert(!claimlog_seen(&l, "dad971d7", "92d421"));
}

/* Several claimants can leave one behind at once. */
static void more_than_one_is_remembered(void)
{
	struct claimlog l;
	char pwd[16];
	int i;

	memset(&l, 0, sizeof(l));
	for (i = 0; i < CLAIMLOG_MAX; i++) {
		sprintf(pwd, "pwd%d", i);
		claimlog_note(&l, "ufrag", pwd);
	}
	for (i = 0; i < CLAIMLOG_MAX; i++) {
		sprintf(pwd, "pwd%d", i);
		assert(claimlog_seen(&l, "ufrag", pwd));
	}
	/* One past the ring pushes the oldest out, and nothing else. */
	claimlog_note(&l, "ufrag", "overflow");
	assert(claimlog_seen(&l, "ufrag", "overflow"));
	assert(!claimlog_seen(&l, "ufrag", "pwd0"));
	assert(claimlog_seen(&l, "ufrag", "pwd1"));
}

/* Noting the same claim twice must not cost the ring an entry. */
static void a_repeat_does_not_evict(void)
{
	struct claimlog l;
	int i;

	memset(&l, 0, sizeof(l));
	claimlog_note(&l, "first", "pwd");
	for (i = 0; i < CLAIMLOG_MAX * 2; i++)
		claimlog_note(&l, "again", "pwd");
	assert(claimlog_seen(&l, "first", "pwd"));
	assert(claimlog_seen(&l, "again", "pwd"));
}

/* An empty half names nobody, so it is never a match. */
static void an_empty_claim_matches_nothing(void)
{
	struct claimlog l;

	memset(&l, 0, sizeof(l));
	claimlog_note(&l, "", "");
	assert(!claimlog_seen(&l, "", ""));
	claimlog_note(&l, "ufrag", "");
	assert(!claimlog_seen(&l, "ufrag", ""));
}

/*
 * A worker one second old, and the claim that made it coming round again: the
 * password says it is the same attempt, and a resumption would have minted a
 * new one.
 */
static void the_attempt_behind_a_worker_is_known(void)
{
	assert(claim_made("92d421", "92d421"));
	assert(!claim_made("92d421", "5b0e77"));
	assert(!claim_made("", "92d421"));
	assert(!claim_made("92d421", ""));
	/* Two blanks are not a match, they are two things unknown. */
	assert(!claim_made("", ""));
}

int main(void)
{
	the_attempt_behind_a_worker_is_known();
	the_same_attempt_is_recognised();
	a_new_attempt_is_not();
	more_than_one_is_remembered();
	a_repeat_does_not_evict();
	an_empty_claim_matches_nothing();
	printf("claimlog_test: ok\n");
	return 0;
}
