/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/* A set that resolved nothing is asked for again, since a node built where
 * nothing resolves would otherwise have nothing to ping for the whole run. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dhtnode.h"
#include "sig.h"
#include "wsock.h"

#define FIRST_MAX_MS 5000
#define RETRY_MAX_MS (DHTNODE_BOOTSTRAP_FIRST_MS * 2)
#define SPIN_WINDOW_MS 2000
#define PUMP_NAP_MS 5

static int asked;

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **res)
{
	(void)node;
	(void)service;
	(void)hints;
	__atomic_add_fetch(&asked, 1, __ATOMIC_RELAXED);
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

/* When the `want`th pass went out, or 0 if the bound ran out first. */
static uint64_t pump_until(struct sig *s, int want, uint64_t bound_ms)
{
	uint64_t t0 = now_ms();
	struct pollfd fds[8];
	int nfds, timeout_ms;
	struct timespec nap;

	nap.tv_sec = 0;
	nap.tv_nsec = PUMP_NAP_MS * 1000000L;
	for (;;) {
		nfds = sig_prepare(s, fds, 8, &timeout_ms);
		sig_dispatch(s, fds, nfds);
		if (__atomic_load_n(&asked, __ATOMIC_RELAXED) >= want)
			return now_ms();
		if (now_ms() - t0 > bound_ms)
			return 0;
		nanosleep(&nap, NULL);
	}
}

int main(void)
{
	uint8_t rdv[TOKEN_RDV_LEN];
	uint64_t first, second;
	struct pollfd fds[8];
	int i, timeout_ms;
	struct sig *s;

	for (i = 0; i < TOKEN_RDV_LEN; i++)
		rdv[i] = (uint8_t)(i * 7 + 1);
	setenv("COMRADE_DHT_BOOTSTRAP", "nowhere.invalid:6881", 1);

	s = sig_create(rdv, SIG_DHT, 1);
	if (!s || sig_prepare(s, fds, 8, &timeout_ms) <= 0) {
		printf("skipped: no DHT node could be created on this host\n");
		return 77;
	}

	first = pump_until(s, 1, FIRST_MAX_MS);
	assert(first);

	/* On the bootstrap cadence: a round of its own would ask a name
	 * server five times a second, for a year. */
	assert(!pump_until(s, 3, SPIN_WINDOW_MS));

	second = pump_until(s, 2, RETRY_MAX_MS);
	assert(second);
	assert(second > first);

	sig_destroy(s);
	return 0;
}
