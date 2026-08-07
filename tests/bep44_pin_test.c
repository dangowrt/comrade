/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * Proves the pinned-node guarantee: a node pinned via bep44_pin_add is
 * injected into every op and queried even after the seed ring has been
 * cycled far past its capacity (which evicts ordinary seeds). A loopback
 * "victim" socket stands in for the rendezvous node; the test asserts the
 * engine actually sends it a query.
 */

#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "bep44.h"

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void on_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq,
		   const struct sockaddr *node, socklen_t node_len)
{
	(void)arg; (void)v; (void)v_len; (void)seq; (void)node; (void)node_len;
}

static int udp_loopback(int *port)
{
	struct sockaddr_in a;
	socklen_t al = sizeof(a);
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	assert(s >= 0);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	assert(bind(s, (struct sockaddr *)&a, sizeof(a)) == 0);
	assert(getsockname(s, (struct sockaddr *)&a, &al) == 0);
	*port = ntohs(a.sin_port);
	return s;
}

int main(void)
{
	uint8_t myid[20], pk[32];
	struct bep44_engine *e;
	struct sockaddr_in pin, junk;
	uint64_t deadline;
	int vport = 0, eport = 0;
	int vsock, esock, fl, i, got = 0;

	memset(myid, 0x11, sizeof(myid));
	memset(pk, 0x22, sizeof(pk));

	vsock = udp_loopback(&vport);
	esock = udp_loopback(&eport);
	fl = fcntl(vsock, F_GETFL, 0);
	fcntl(vsock, F_SETFL, fl | O_NONBLOCK);

	e = bep44_create(myid, esock, -1);
	assert(e);

	/* Pin the victim as a rendezvous node (address only, no id). */
	memset(&pin, 0, sizeof(pin));
	pin.sin_family = AF_INET;
	pin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	pin.sin_port = htons((uint16_t)vport);
	assert(bep44_pin_add(e, NULL, (struct sockaddr *)&pin, sizeof(pin)) == 0);

	/* Cycle the seed ring far past B44_SEEDS_MAX, which would evict any
	 * ordinary seed. The pin must survive this. */
	for (i = 0; i < 40; i++) {
		memset(&junk, 0, sizeof(junk));
		junk.sin_family = AF_INET;
		junk.sin_addr.s_addr = htonl(0x0a000000u | (unsigned)i);
		junk.sin_port = htons((uint16_t)(1000 + i));
		bep44_seed_add(e, NULL, (struct sockaddr *)&junk, sizeof(junk));
	}

	/* Start a query and confirm the pinned node is actually contacted. */
	bep44_get(e, pk, "offer", on_get, NULL);

	deadline = now_ms() + 3000;
	while (now_ms() < deadline && !got) {
		struct pollfd pfd;
		uint8_t buf[1500];
		int to = 100;

		bep44_periodic(e, &to);
		pfd.fd = vsock;
		pfd.events = POLLIN;
		pfd.revents = 0;
		poll(&pfd, 1, 50);
		if (recv(vsock, buf, sizeof(buf), 0) > 0)
			got = 1;
	}

	assert(got);	/* pinned node queried despite the cycled ring */

	bep44_free(e);
	close(vsock);
	close(esock);
	return 0;
}
