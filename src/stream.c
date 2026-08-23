/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <pthread.h>
#include <stdlib.h>

#include <ikcp.h>

#include "stream.h"

#define STREAM_MTU 1200
#define STREAM_WND 256
#define STREAM_DEAD_LINK 1000

#define STREAM_RATE_MS 100		/* delivery-rate sample period */
#define STREAM_TXQ_MS 300		/* unsent-queue bound, in transmit time */
#define STREAM_TXQ_MIN 16		/* segments; startup / idle-restart floor */

struct stream {
	ikcpcb *kcp;
	stream_output_fn *out;
	void *out_arg;
	pthread_mutex_t lock;
	uint32_t rate_t;		/* last delivery-rate sample time */
	uint32_t rate_una;		/* snd_una at that sample */
	uint32_t rate_sps;		/* EWMA delivered segments per second */
};

/* Called from ikcp_input/ikcp_update with s->lock held (non-recursive), so the
 * output callback must not re-enter stream_* on the same stream; the only
 * callback writes to a socket, which does not. */
static int kcp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	struct stream *s = user;

	(void)kcp;
	if (!s->out || len <= 0)
		return 0;
	return s->out(s->out_arg, (const uint8_t *)buf, (size_t)len);
}

struct stream *stream_create(uint32_t conv, stream_output_fn *out, void *arg)
{
	struct stream *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	if (pthread_mutex_init(&s->lock, NULL)) {
		free(s);
		return NULL;
	}
	s->out = out;
	s->out_arg = arg;
	s->kcp = ikcp_create(conv, s);
	if (!s->kcp) {
		pthread_mutex_destroy(&s->lock);
		free(s);
		return NULL;
	}
	s->kcp->output = kcp_output;
	s->kcp->stream = 1;
	s->kcp->dead_link = STREAM_DEAD_LINK;
	ikcp_setmtu(s->kcp, STREAM_MTU);
	ikcp_wndsize(s->kcp, STREAM_WND, STREAM_WND);
	ikcp_nodelay(s->kcp, 1, 10, 2, 0);
	return s;
}

void stream_destroy(struct stream *s)
{
	if (!s)
		return;
	if (s->kcp)
		ikcp_release(s->kcp);
	pthread_mutex_destroy(&s->lock);
	free(s);
}

int stream_send(struct stream *s, const uint8_t *data, size_t len)
{
	int rc;

	pthread_mutex_lock(&s->lock);
	rc = ikcp_send(s->kcp, (const char *)data, (int)len);
	pthread_mutex_unlock(&s->lock);
	return rc;
}

int stream_recv(struct stream *s, uint8_t *data, size_t len)
{
	int rc;

	pthread_mutex_lock(&s->lock);
	rc = ikcp_recv(s->kcp, (char *)data, (int)len);
	pthread_mutex_unlock(&s->lock);
	return rc;
}

int stream_input(struct stream *s, const uint8_t *data, size_t len)
{
	int rc;

	pthread_mutex_lock(&s->lock);
	rc = ikcp_input(s->kcp, (const char *)data, (long)len);
	pthread_mutex_unlock(&s->lock);
	return rc;
}

uint32_t stream_update(struct stream *s, uint32_t now_ms)
{
	uint32_t next, dt;

	pthread_mutex_lock(&s->lock);
	ikcp_update(s->kcp, now_ms);
	next = ikcp_check(s->kcp, now_ms);
	if (!s->rate_t) {
		s->rate_t = now_ms ? now_ms : 1;
		s->rate_una = s->kcp->snd_una;
	}
	dt = now_ms - s->rate_t;
	if (dt >= STREAM_RATE_MS) {
		uint32_t d = s->kcp->snd_una - s->rate_una;

		s->rate_sps -= s->rate_sps / 4;
		s->rate_sps += d * 1000 / dt / 4;
		s->rate_t = now_ms ? now_ms : 1;
		s->rate_una = s->kcp->snd_una;
	}
	pthread_mutex_unlock(&s->lock);
	return next;
}

int stream_waitsnd(struct stream *s)
{
	int rc;

	pthread_mutex_lock(&s->lock);
	rc = ikcp_waitsnd(s->kcp);
	pthread_mutex_unlock(&s->lock);
	return rc;
}

int stream_tx_room(struct stream *s)
{
	uint32_t target;
	int room;

	pthread_mutex_lock(&s->lock);
	target = s->rate_sps * STREAM_TXQ_MS / 1000;
	if (target < STREAM_TXQ_MIN)
		target = STREAM_TXQ_MIN;
	room = s->kcp->nsnd_que < target;
	pthread_mutex_unlock(&s->lock);
	return room;
}

int stream_rtt(struct stream *s)
{
	int rtt;

	pthread_mutex_lock(&s->lock);
	rtt = s->kcp ? (int)s->kcp->rx_srtt : 0;
	pthread_mutex_unlock(&s->lock);
	return rtt;
}

void stream_set_output(struct stream *s, stream_output_fn *out, void *arg)
{
	pthread_mutex_lock(&s->lock);
	s->out = out;
	s->out_arg = arg;
	pthread_mutex_unlock(&s->lock);
}
