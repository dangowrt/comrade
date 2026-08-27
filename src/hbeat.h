/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_HBEAT_H
#define COMRADE_HBEAT_H

/*
 * The liveness heartbeat over the comrade-ctl control channel (framing in
 * ctlproto.h): a ping every HB_INTERVAL_MS, and the link is treated as lost
 * once nothing at all has arrived from the peer -- no pong, and no other
 * traffic -- for as long as hb_lost_ms() allows.
 *
 * The pong alone must not carry the verdict: it rides the same stream as bulk
 * data through several queues, so on a saturated slow link it arrives seconds
 * late while the transfer is demonstrably moving. Arriving datagrams are the
 * liveness; the pong's own job is the round-trip figure.
 */
#define HB_INTERVAL_MS 700

/*
 * Pings that may go unanswered before the link is given up on. A count, not a
 * span: what it says is that one lost datagram is not an outage and three in a
 * row is.
 */
#define HB_SILENT_TRIES 3

/*
 * The peer's own round-trip is added, because a link that answers in 400ms
 * cannot be judged on the patience of one that answers in 4. Past this the
 * figure stops being useful -- a path that slow is unusable rather than slow,
 * and waiting on it only delays the resume that would replace it.
 */
#define HB_RTT_CAP_MS 1000

/* How long silence may last, given the last round-trip measured (0 or less
 * where none has been). */
unsigned hb_lost_ms(int rtt_ms);

#endif /* COMRADE_HBEAT_H */
