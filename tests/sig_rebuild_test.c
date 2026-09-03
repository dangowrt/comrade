/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Signalling churn: the two calls a roam makes.
 *
 * session.c:sig_rebuild discards the signaller and arms a fresh one from the
 * top of the loop that pumps every live connection, so both halves have to
 * return promptly. The dangerous one is the DHT node: its bootstrap routers are
 * resolved on a side thread, and a teardown that waits for that thread waits on
 * getaddrinfo -- for a network that has just gone away, and with every worker
 * the same thread drains stalled behind it. getaddrinfo cannot be cancelled, so
 * the wait cannot be bounded at the call site; the node has to be freed without
 * it.
 *
 * The stall is manufactured here rather than waited for. src/dhtnode.c holds
 * the only getaddrinfo call in anything comrade_sig links, so dhtnode.o binds
 * to this translation unit's own definition at static link time: no LD_PRELOAD
 * and no test-only branch in shipped code. Keep the link line to comrade_sig alone,
 * or a library that resolves hostnames for real would be handed the stall too.
 * BUILD_TESTING is off on Windows, so ELF and Mach-O are the whole surface.
 *
 * A round that waits on the resolver costs one stall per bootstrap router; a
 * round that does not costs about a millisecond.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sig.h"
#include "wsock.h"

#define STALL_MS 1000		/* per bootstrap router, as a slow uplink would */
#define ROUNDS 10
#define ROUND_MAX_MS 250	/* generous: a clean round is ~1 ms, a waiting
				 * one is STALL_MS x the router count */

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **res)
{
	struct timespec ts;

	(void)node;
	(void)service;
	(void)hints;
	ts.tv_sec = STALL_MS / 1000;
	ts.tv_nsec = (long)(STALL_MS % 1000) * 1000000L;
	nanosleep(&ts, NULL);
	*res = NULL;
	return EAI_NONAME;
}

void freeaddrinfo(struct addrinfo *res)
{
	(void)res;
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

int main(void)
{
	uint8_t rdv[TOKEN_RDV_LEN];
	struct pollfd fds[8];
	struct sig *s;
	uint64_t t0;
	int i, nfds, timeout_ms;

	for (i = 0; i < TOKEN_RDV_LEN; i++)
		rdv[i] = (uint8_t)(i * 11 + 3);

	/* NULL means only that the caller asked for no transport at all; a
	 * transport that cannot be brought up now is retried from dispatch. */
	assert(sig_create(rdv, 0, 1) == NULL);

	/* A DHT node needs a UDP socket on one family or the other. */
	s = sig_create(rdv, SIG_DHT, 1);
	assert(s);
	nfds = sig_prepare(s, fds, 8, &timeout_ms);
	sig_discard(s);
	if (nfds <= 0) {
		printf("skipped: no DHT node could be created on this host\n");
		return 77;
	}

	/*
	 * The roam's own sequence. Each round also pins the jech/dht singleton
	 * invariant sig_rebuild leans on: dht_init and dht_uninit must pair, or
	 * the next node is never created and prepare offers no descriptor.
	 *
	 * AND THE CLAIM KEY SURVIVES IT. A claimant boxes its claim to the key
	 * it read in the host's offer, so a rebuild that minted a fresh one
	 * left the host unable to open a claim already in flight -- and a host
	 * that cannot open a claim releases the slot, erasing one that was
	 * perfectly good. Every round here is a roam, and the key a session
	 * carries across them must be the one it started with.
	 */
	{
		uint8_t k0[32], k[32];

		s = sig_create(rdv, SIG_DHT, 1);
		assert(s && !sig_claim_key(s, k0));
		sig_discard(s);

		for (i = 0; i < ROUNDS; i++) {
			t0 = now_ms();
			s = sig_create(rdv, SIG_DHT, 1);
			assert(s);
			/* What the session does across its own rebuild. */
			sig_use_claim_key(s, k0);
			assert(!sig_claim_key(s, k) && !memcmp(k, k0, 32));
			assert(sig_prepare(s, fds, 8, &timeout_ms) > 0);
			sig_discard(s);
			assert(now_ms() - t0 < ROUND_MAX_MS);
		}
	}

	/* The session's own teardown, which persists the node cache. */
	t0 = now_ms();
	s = sig_create(rdv, SIG_DHT, 1);
	assert(s);
	assert(sig_prepare(s, fds, 8, &timeout_ms) > 0);
	sig_destroy(s);
	assert(now_ms() - t0 < ROUND_MAX_MS);

	return 0;
}
