/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "nat.h"
#include "stream.h"

struct peer {
	struct nat_agent *nat;
	struct stream *stream;
	struct peer *other;
	char sdp[NAT_SDP_MAX];
	int have_sdp;
};

static uint32_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void ms_sleep(int ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

static void on_local_sdp(void *arg, const char *sdp)
{
	struct peer *p = arg;

	strncpy(p->sdp, sdp, sizeof(p->sdp) - 1);
	p->have_sdp = 1;
}

static int on_stream_output(void *arg, const uint8_t *data, size_t len)
{
	struct peer *p = arg;

	return nat_send(p->nat, data, len);
}

static void on_nat_recv(void *arg, const uint8_t *data, size_t len)
{
	struct peer *p = arg;

	stream_input(p->stream, data, len);
}

static struct peer a, b;

static void peer_init(struct peer *p, struct peer *other, uint32_t conv)
{
	struct nat_config cfg;

	memset(p, 0, sizeof(*p));
	p->other = other;
	memset(&cfg, 0, sizeof(cfg));
	cfg.stun_host = NULL;
	cfg.on_local_sdp = on_local_sdp;
	cfg.on_recv = on_nat_recv;
	cfg.arg = p;
	p->nat = nat_create(&cfg);
	assert(p->nat);
	p->stream = stream_create(conv, on_stream_output, p);
	assert(p->stream);
}

static int wait_for(int (*pred)(void), int timeout_ms)
{
	uint32_t deadline = now_ms() + (uint32_t)timeout_ms;

	while (now_ms() < deadline) {
		if (pred())
			return 1;
		ms_sleep(20);
	}
	return pred();
}

static int both_gathered(void)
{
	return a.have_sdp && b.have_sdp;
}

static int both_connected(void)
{
	return nat_connected(a.nat) && nat_connected(b.nat);
}

int main(void)
{
	static const size_t total = 100 * 1024;
	uint8_t *sent, *recvd;
	size_t got = 0, i;
	uint32_t deadline;

	a.other = &b;
	b.other = &a;
	peer_init(&a, &b, 0x70323031);
	peer_init(&b, &a, 0x70323031);

	assert(!nat_gather(a.nat));
	assert(!nat_gather(b.nat));

	if (!wait_for(both_gathered, 5000)) {
		fprintf(stderr, "gathering timed out\n");
		return 1;
	}

	assert(!nat_set_remote_description(a.nat, b.sdp));
	assert(!nat_set_remote_description(b.nat, a.sdp));

	if (!wait_for(both_connected, 15000)) {
		fprintf(stderr, "ICE did not connect (a=%d b=%d)\n",
			nat_connected(a.nat), nat_connected(b.nat));
		return 1;
	}
	fprintf(stderr, "ICE connected\n");

	sent = malloc(total);
	recvd = malloc(total);
	assert(sent && recvd);
	for (i = 0; i < total; i++)
		sent[i] = (uint8_t)(i * 131 + 7);

	assert(stream_send(a.stream, sent, total) >= 0);

	deadline = now_ms() + 20000;
	while (got < total && now_ms() < deadline) {
		int n;

		stream_update(a.stream, now_ms());
		stream_update(b.stream, now_ms());
		n = stream_recv(b.stream, recvd + got, (int)(total - got));
		if (n > 0)
			got += (size_t)n;
		else
			ms_sleep(5);
	}

	if (got != total) {
		fprintf(stderr, "stream transfer incomplete: %zu/%zu\n", got, total);
		return 1;
	}
	assert(!memcmp(sent, recvd, total));
	fprintf(stderr, "stream transfer OK: %zu bytes verified\n", total);

	free(sent);
	free(recvd);
	stream_destroy(a.stream);
	stream_destroy(b.stream);
	nat_destroy(a.nat);
	nat_destroy(b.nat);
	return 0;
}
