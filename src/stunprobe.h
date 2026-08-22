/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_STUNPROBE_H
#define COMRADE_STUNPROBE_H

#include <stddef.h>
#include <stdint.h>

#define STUN_PROBE_REQ_LEN 20
#define STUN_PROBE_TXID_LEN 12

/* A binding request with the given transaction id; always STUN_PROBE_REQ_LEN
 * bytes. */
void stun_probe_build(uint8_t out[STUN_PROBE_REQ_LEN],
		      const uint8_t txid[STUN_PROBE_TXID_LEN]);

/*
 * The mapped v4 address out of a binding success response whose transaction id
 * begins with the STUN_PROBE_TXID_LEN-1 seed bytes (the last byte numbers the
 * server the request went to, so one seed validates a whole probe run).
 * XOR-MAPPED-ADDRESS is preferred, MAPPED-ADDRESS accepted. 0 if found.
 */
int stun_probe_mapped4(const uint8_t *pkt, size_t len,
		       const uint8_t seed[STUN_PROBE_TXID_LEN],
		       uint8_t addr[4], uint16_t *port);

typedef void stun_probe_hit(void *arg, const uint8_t addr[4]);

/*
 * Ask up to `nservers` "host:port" STUN servers for this network's mapping of
 * one socket, calling `hit` for each response's mapped v4 address as it
 * arrives; run for at most `total_ms`, or until *stop goes nonzero. Blocking
 * (resolution included) -- meant for a thread of its own. The seed's last
 * byte is overwritten per server.
 */
void stun_probe_run(char *const *servers, int nservers, int total_ms,
		    uint8_t seed[STUN_PROBE_TXID_LEN], volatile int *stop,
		    stun_probe_hit *hit, void *arg);

#endif
