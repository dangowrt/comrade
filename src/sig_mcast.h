/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SIG_MCAST_H
#define COMRADE_SIG_MCAST_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/*
 * Link-local multicast signalling transport for isolated LANs with no DHT
 * reachability. Plain L3 UDP multicast (IPv4 224.0.0.0/24 link scope and
 * IPv6 ff02:: link scope) on every up, multicast-capable interface. No
 * netadmin capability, no promiscuous mode. Carries the same sealed blobs
 * the DHT transport does; the front-end handles sealing and matching.
 */

struct sig_mcast;

/* An up, multicast-capable interface being serviced, and the families it has. */
struct sig_mcast_if {
	char name[32];
	int has4;
	int has6;
};

typedef void sig_mcast_recv_cb(void *arg, const char *salt,
			       const uint8_t *data, size_t len,
			       const struct sockaddr *src, socklen_t srclen);

struct sig_mcast *sig_mcast_open(void);
void sig_mcast_close(struct sig_mcast *m);

/* Copy up to max serviced interfaces into out; returns how many. */
int sig_mcast_ifaces(struct sig_mcast *m, struct sig_mcast_if *out, int max);

int sig_mcast_prepare(struct sig_mcast *m, struct pollfd *fds, int maxfds);
void sig_mcast_dispatch(struct sig_mcast *m, const struct pollfd *fds, int nfds,
			sig_mcast_recv_cb *cb, void *arg);
int sig_mcast_send(struct sig_mcast *m, const char *salt,
		   const uint8_t *data, size_t len);

#endif
