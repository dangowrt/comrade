/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SIG_H
#define COMRADE_SIG_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "sig_mcast.h"		/* struct sig_mcast_if */
#include "token.h"

/*
 * Signalling over a single shared rendezvous mailbox.
 *
 * The two peers meet at ONE DHT mutable item: a small container with two
 * slots, the host's offer and the client's answer. Because a DHT stores a key
 * on the nodes closest to it, two different keys live on different nodes, so a
 * single shared key is the only way one rendezvous node can serve BOTH
 * directions. Each peer writes its own slot with compare-and-swap so neither
 * clobbers the other; a stale write loses the CAS and is retried after the
 * next read. On a LAN, multicast carries the two slots directly instead, with
 * no shared item.
 */

#define SIG_MAX_VALUE 440		/* plaintext per slot; two sealed slots
					 * plus framing fit one BEP44 value */

/* Transports; combine with OR. */
#define SIG_DHT		0x1	/* BitTorrent mainline DHT (internet-wide) */
#define SIG_MCAST	0x2	/* link-local multicast (isolated LANs) */

struct sig;

typedef void sig_recv_cb(void *arg, const uint8_t *data, size_t len);

/*
 * is_host selects which slot is ours: the host writes the offer and reads the
 * answer, the client the reverse. With both transports, multicast runs first
 * and the DHT is engaged only after a grace elapses without a peer on the link.
 */
struct sig *sig_create(const uint8_t rdv[TOKEN_RDV_LEN], unsigned flags,
		       int is_host);
void sig_destroy(struct sig *s);

int sig_prepare(struct sig *s, struct pollfd *fds, int maxfds, int *timeout_ms);
void sig_dispatch(struct sig *s, const struct pollfd *fds, int nfds);
int sig_ready(struct sig *s);

/* Post our endpoints into our mailbox slot; kept alive and merged via CAS. */
int sig_post(struct sig *s, const uint8_t *data, size_t len);

/* cb fires when the peer's slot appears or changes. */
int sig_subscribe(struct sig *s, sig_recv_cb *cb, void *arg);

/*
 * Link-local direct bypass (multicast only). Our own direct-transport port is
 * carried in the announcement; when the peer's announcement arrives from a
 * link-local source -- proving a clear layer-2 path that needs no ICE -- cb
 * fires with the peer's endpoint (that source address, keeping its zone id,
 * and the announced direct port). ICE still runs on the routable candidates in
 * the same announcement; the two race and whichever carries KCP first wins.
 */
typedef void sig_direct_cb(void *arg, const struct sockaddr *peer,
			   socklen_t len);
void sig_set_direct_port(struct sig *s, uint16_t port);
int sig_subscribe_direct(struct sig *s, sig_direct_cb *cb, void *arg);

/*
 * Rendezvous acceleration.
 *
 * sig_seed_node (client): plant a token's rendezvous node as a sticky DHT
 * hint, queried first, with the global DHT bootstrapping alongside as fallback.
 *
 * sig_locate (host): start capturing the fastest node that serves the mailbox
 * back (the node to embed in the token). The candidates are the nodes that
 * stored our value; the get validates and ranks them, and sig_located returns
 * the fastest once known.
 */
int sig_seed_node(struct sig *s, const struct sockaddr *sa, socklen_t len);
int sig_locate(struct sig *s);
/* The located rendezvous node for `family` (4 or 6), if one has been captured. */
int sig_located(struct sig *s, int family, struct sockaddr *out,
		socklen_t *out_len);

/* The up, multicast-capable interfaces this signaller services (view only). */
int sig_link_ifaces(struct sig *s, struct sig_mcast_if *out, int max);

#endif
