/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_STREAM_H
#define COMRADE_STREAM_H

#include <stddef.h>
#include <stdint.h>

struct stream;

typedef int stream_output_fn(void *arg, const uint8_t *data, size_t len);

struct stream *stream_create(uint32_t conv, stream_output_fn *out, void *arg);
void stream_destroy(struct stream *s);

int stream_send(struct stream *s, const uint8_t *data, size_t len);
int stream_recv(struct stream *s, uint8_t *data, size_t len);
int stream_input(struct stream *s, const uint8_t *data, size_t len);

uint32_t stream_update(struct stream *s, uint32_t now_ms);
int stream_waitsnd(struct stream *s);
void stream_set_output(struct stream *s, stream_output_fn *out, void *arg);

/* Smoothed round-trip time in ms (KCP's rx_srtt); 0 before the first sample. */
int stream_rtt(struct stream *s);

/*
 * Nonzero while the unsent queue has room for more bulk payload. The queue is
 * bounded to ~STREAM_TXQ_MS of transmission at the measured delivery rate, so
 * anything written behind bulk (a keystroke, a heartbeat) waits a bounded
 * moment, not the whole backlog. Bulk senders ask before writing; everything
 * else writes regardless.
 */
int stream_tx_room(struct stream *s);

#endif
