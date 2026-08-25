/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * One node of a private DHT, for the tests.
 *
 * A handful of these on loopback, each told where the previous ones are, is a
 * swarm that behaves like the mainline one and belongs entirely to the run
 * that started it. The tests point comrade at it with COMRADE_DHT_BOOTSTRAP,
 * so what they measure is comrade rather than how busy the internet was.
 *
 * jech/dht keeps its state in globals, so a process holds exactly one node and
 * a swarm is that many processes. The port is ephemeral and printed on stdout
 * as "port <n>" before anything else, because the next member has to be told
 * where this one is.
 *
 * usage: comrade-dhtseed [host:port ...]
 */

#include "wsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhtnode.h"

static int seed_peer(struct dhtnode *n, const char *spec)
{
	struct sockaddr_in a;
	char host[128];
	const char *colon = strrchr(spec, ':');
	size_t hl = colon ? (size_t)(colon - spec) : strlen(spec);

	if (!colon || hl >= sizeof(host))
		return -1;
	memcpy(host, spec, hl);
	host[hl] = '\0';
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)atoi(colon + 1));
	if (inet_pton(AF_INET, host, &a.sin_addr) != 1)
		return -1;
	return dhtnode_seed(n, (struct sockaddr *)&a, sizeof(a));
}

int main(int argc, char **argv)
{
	struct dhtnode *n;
	int i;

	/* Seeded: this swarm is the whole world, so the public routers have no
	 * part in it and must not be contacted. */
	n = dhtnode_create_seeded();
	if (!n) {
		fprintf(stderr, "dhtseed: could not create a node\n");
		return 1;
	}
	for (i = 1; i < argc; i++)
		if (seed_peer(n, argv[i]))
			fprintf(stderr, "dhtseed: bad peer '%s'\n", argv[i]);

	printf("port %u\n", dhtnode_port(n, 4));
	fflush(stdout);

	for (;;) {
		struct pollfd fds[4];
		int timeout = 1000;
		int nfds = dhtnode_prepare(n, fds, 4, &timeout);

		sock_poll(fds, (nfds_t)nfds, timeout);
		dhtnode_dispatch(n, fds, nfds);
	}
}
