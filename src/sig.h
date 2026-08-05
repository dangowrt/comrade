/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SIG_H
#define COMRADE_SIG_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "token.h"

/*
 * Signalling over the DHT: a sealed publish/subscribe mailbox keyed by a
 * channel name (the BEP 44 salt). Multiple channels run concurrently, which
 * is what racing several connection paths in parallel needs. Values are
 * sealed under K_sig derived from the rendezvous secret, so only token
 * holders can read or write them; the DHT sees opaque blobs.
 */

#define SIG_MAX_VALUE 900

/* Transports; combine with OR. */
#define SIG_DHT		0x1	/* BitTorrent mainline DHT (internet-wide) */
#define SIG_MCAST	0x2	/* link-local multicast (isolated LANs) */

struct sig;

typedef void sig_recv_cb(void *arg, const uint8_t *data, size_t len);

/*
 * With both transports, multicast runs first and the DHT is not even
 * engaged until a short grace elapses without a peer being discovered on
 * the link, so a successful LAN discovery never touches the DHT.
 */
struct sig *sig_create(const uint8_t rdv[TOKEN_RDV_LEN], unsigned flags);
void sig_destroy(struct sig *s);

int sig_prepare(struct sig *s, struct pollfd *fds, int maxfds, int *timeout_ms);
void sig_dispatch(struct sig *s, const struct pollfd *fds, int nfds);
int sig_ready(struct sig *s);

/* Publish (and keep alive) a value on a channel; call again to update it. */
int sig_publish(struct sig *s, const char *channel, const uint8_t *data, size_t len);

/* Subscribe to a channel; cb fires each time the peer's value changes. */
int sig_subscribe(struct sig *s, const char *channel, sig_recv_cb *cb, void *arg);

#endif
