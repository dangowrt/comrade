/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <pthread.h>
#include <stdlib.h>

#include <ikcp.h>

#include "stream.h"

#define STREAM_MTU 1200
#define STREAM_WND 1024
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

#ifdef COMRADE_HAVE_KCP_CC

/*
 * Rate-based congestion control (BBR-style), replacing kcp's builtin
 * Tahoe, which resets cwnd to 1 on any retransmission timeout and pins a
 * path with steady random loss to a fraction of its capacity. Loss is not
 * a control signal here: the pace follows the measured delivery rate, so
 * what the path does not carry is simply not offered again faster.
 * All hooks run under the stream lock (called from ikcp_update/input).
 */
#define CC_BW_ROUNDS 10			/* delivery-rate max-filter length */
#define CC_RTPROP_MS 10000		/* min-RTT filter window */
#define CC_GAIN_STARTUP 2.77		/* pacing gain while the pipe grows */
#define CC_GAIN_DRAIN 0.36		/* one phase to drain startup's queue */
#define CC_CWND_MIN 16			/* segments */
#define CC_BW_FLOOR 2.0			/* bytes/ms; keeps restart possible */

struct stream_cc {
	double btlbw;			/* delivered bytes/ms, max over bw[] */
	double bw[CC_BW_ROUNDS];
	int bwi;
	double rtprop;			/* least RTT seen, ms */
	IUINT32 rtprop_t;
	IUINT32 round_t;		/* current sample round */
	double acked_round;
	int app_limited;		/* round had no backlog to measure */
	int startup;
	int drain;
	IUINT32 drain_t;
	double growth_ref;
	int plateau;
	int cycle;			/* ProbeBW pacing-gain phase */
	IUINT32 cycle_t;
	double carry;			/* pacing token bucket, bytes */
	IUINT32 carry_t;
};

static int cc_init(ikcpcb *kcp)
{
	struct stream_cc *c = calloc(1, sizeof(*c));

	if (!c)
		return -1;		/* setcc fails; builtin CC remains */
	c->rtprop = 100.0;
	c->btlbw = (double)kcp->mss / kcp->interval;
	c->growth_ref = c->btlbw;
	c->startup = 1;
	kcp->congest = c;
	kcp->cwnd = CC_CWND_MIN;
	return 0;
}

static void cc_release(ikcpcb *kcp)
{
	free(kcp->congest);
	kcp->congest = NULL;
}

static void cc_on_rtt(ikcpcb *kcp, IINT32 rtt)
{
	struct stream_cc *c = kcp->congest;

	if (rtt <= 0)
		return;
	if ((double)rtt < c->rtprop ||
	    (IUINT32)(kcp->current - c->rtprop_t) > CC_RTPROP_MS) {
		c->rtprop = (double)rtt;
		c->rtprop_t = kcp->current;
	}
}

static void cc_on_ack(ikcpcb *kcp, IUINT32 acked_segs, IUINT32 acked_bytes,
		      IUINT32 prior_in_flight)
{
	struct stream_cc *c = kcp->congest;

	(void)acked_segs;
	(void)prior_in_flight;
	c->acked_round += (double)acked_bytes;
}

static void cc_on_app_limited(ikcpcb *kcp, IUINT32 inflight)
{
	struct stream_cc *c = kcp->congest;

	(void)inflight;
	c->app_limited = 1;
}

/* Present so kcp's builtin Tahoe reset never runs; loss shows up in the
 * delivery rate, which is where this controller reads it. */
static void cc_on_fast_retransmit(ikcpcb *kcp, IUINT32 n, IUINT32 inflight,
				  IUINT32 prior_cwnd)
{
	(void)kcp;
	(void)n;
	(void)inflight;
	(void)prior_cwnd;
}

static void cc_on_timeout(ikcpcb *kcp, IUINT32 prior_cwnd)
{
	(void)kcp;
	(void)prior_cwnd;
}

static void cc_on_pkt_sent(ikcpcb *kcp, IUINT32 sn, IUINT32 ts, IUINT32 len,
			   IUINT32 inflight, IUINT32 xmit)
{
	struct stream_cc *c = kcp->congest;

	(void)sn;
	(void)ts;
	(void)inflight;
	(void)xmit;
	c->carry -= (double)len;
}

static void cc_on_tick(ikcpcb *kcp)
{
	struct stream_cc *c = kcp->congest;
	IUINT32 dt = kcp->current - c->round_t;
	double round = c->rtprop > kcp->interval ? c->rtprop : kcp->interval;
	double bdp, cw;
	int i;

	if (!c->round_t) {
		c->round_t = kcp->current ? kcp->current : 1;
		return;
	}
	if ((double)dt >= round) {
		double sample = c->acked_round / (double)dt;

		/* An app-limited round measures the app, not the path: it
		 * may only raise the estimate, never age real samples out. */
		if (!c->app_limited || sample > c->btlbw) {
			c->bwi = (c->bwi + 1) % CC_BW_ROUNDS;
			c->bw[c->bwi] = sample;
			c->btlbw = CC_BW_FLOOR;
			for (i = 0; i < CC_BW_ROUNDS; i++)
				if (c->bw[i] > c->btlbw)
					c->btlbw = c->bw[i];
		}
		if (c->startup && sample > 0) {
			if (c->btlbw < c->growth_ref * 1.25) {
				if (++c->plateau >= 3) {
					c->startup = 0;
					c->drain = 1;
					c->drain_t = kcp->current;
				}
			} else {
				c->plateau = 0;
				c->growth_ref = c->btlbw;
			}
		}
		c->acked_round = 0;
		c->app_limited = 0;
		c->round_t = kcp->current;
	}
	bdp = c->btlbw * (c->rtprop + kcp->interval);
	if (c->drain &&
	    ((double)kcp->nsnd_buf * kcp->mss <= bdp ||
	     (double)(IUINT32)(kcp->current - c->drain_t) > 2.0 * c->rtprop))
		c->drain = 0;
	if ((double)(IUINT32)(kcp->current - c->cycle_t) > c->rtprop) {
		c->cycle = (c->cycle + 1) % 8;
		c->cycle_t = kcp->current;
	}
	/* In-flight must cover the flush quantum on top of the path RTT,
	 * or cwnd caps delivery, delivery caps btlbw, and the loop wedges. */
	cw = (c->startup ? 2.89 : 2.0) * bdp / kcp->mss;
	if (cw < CC_CWND_MIN)
		cw = CC_CWND_MIN;
	if (cw > kcp->snd_wnd)
		cw = kcp->snd_wnd;
	kcp->cwnd = (IUINT32)cw;
}

static IUINT32 cc_pacing_rate(ikcpcb *kcp)
{
	static const double gains[8] = { 1.25, 0.75, 1, 1, 1, 1, 1, 1 };
	struct stream_cc *c = kcp->congest;
	double gain = gains[c->cycle];
	IUINT32 dt = kcp->current - c->carry_t;
	double cap;

	if (c->startup)
		gain = CC_GAIN_STARTUP;
	else if (c->drain)
		gain = CC_GAIN_DRAIN;
	if (!c->carry_t || dt > 1000)
		dt = kcp->interval;
	c->carry_t = kcp->current;
	c->carry += gain * c->btlbw * (double)dt;
	cap = gain * c->btlbw * 4.0 * kcp->interval;
	if (cap < 2.0 * kcp->mss)
		cap = 2.0 * kcp->mss;
	if (c->carry > cap)
		c->carry = cap;
	/* Never below one segment: a smaller budget makes kcp's flush
	 * mutate a segment's retransmit state and then not send it, which
	 * wedges the head of the queue. cwnd limits slower links. */
	if (c->carry < (double)kcp->mss)
		return (IUINT32)kcp->mss;
	return (IUINT32)c->carry;
}

static const struct IKCPOPS cc_ops = {
	"comrade-rate",
	cc_init,
	cc_release,
	cc_on_ack,
	cc_on_fast_retransmit,
	cc_on_timeout,
	cc_on_tick,
	cc_on_app_limited,
	cc_on_rtt,
	cc_on_pkt_sent,
	NULL,				/* on_pkt_acked */
	NULL,				/* get_info */
	cc_pacing_rate,
};

#endif /* COMRADE_HAVE_KCP_CC */

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
#ifdef COMRADE_HAVE_KCP_CC
	ikcp_setcc(s->kcp, &cc_ops);	/* on failure the builtin CC remains */
#endif
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
