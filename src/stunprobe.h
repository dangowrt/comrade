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

typedef void stun_probe_hit(void *arg, const uint8_t addr[4], uint16_t port);

/*
 * Ask up to `nservers` "host:port" STUN servers for this network's mapping of
 * one socket, calling `hit` for each response's mapped v4 address and port as
 * it arrives; run for at most `total_ms`, or until *stop goes nonzero.
 * Blocking (resolution included) -- meant for a thread of its own. The seed's
 * last byte is overwritten per server.
 */
void stun_probe_run(char *const *servers, int nservers, int total_ms,
		    uint8_t seed[STUN_PROBE_TXID_LEN], volatile int *stop,
		    stun_probe_hit *hit, void *arg);

/*
 * The mapped address a validated reply carries for the wire-format family byte
 * `want_fam` (0x01 v4, 0x02 v6) -- four bytes of `addr` for v4, sixteen for v6.
 * stun_probe_mapped4 is this for v4 alone. 0 if found.
 */
int stun_probe_mapped_fam(const uint8_t *pkt, size_t len,
			  const uint8_t seed[STUN_PROBE_TXID_LEN], int want_fam,
			  uint8_t addr[16], uint16_t *port);

/*
 * addr[0..3] for a v4 reply, addr[0..15] for a v6 one -- the caller already
 * knows which, having asked stun_probe_check for that family.
 */
typedef void stun_probe_check_hit(void *arg, const uint8_t addr[16],
				  uint16_t port);

/*
 * Ask up to `nservers` "host:port" STUN servers of `family` (AF_INET or
 * AF_INET6) for a binding response, calling `hit` once real proof arrives --
 * a validated reply to this exact request -- with the address it says we are
 * seen as. No pool and no NAT classification: stun_probe_run is still where
 * those come from for v4. Runs for at most `total_ms`, or until *stop goes
 * nonzero, calling `hit` at most once. Blocking (resolution included) -- meant
 * for a thread of its own.
 */
void stun_probe_check(char *const *servers, int nservers, int family,
		      int total_ms, uint8_t seed[STUN_PROBE_TXID_LEN],
		      volatile int *stop, stun_probe_check_hit *hit, void *arg);

/*
 * RFC 4787 mapping-behaviour classification, built incrementally from the
 * (address, port) pairs a probe run's `hit` callback sees: every server
 * agreeing means an endpoint-independent (cone-family) mapping; any
 * disagreement means an address/port-dependent (symmetric-family) one. Pure
 * and socket-free -- a probe run's samples all come from one socket, so
 * mixing in mappings observed on a different socket would invalidate the
 * comparison.
 */
enum {
	STUN_MAPPING_UNKNOWN = 0,	/* fewer than two samples yet */
	STUN_MAPPING_INDEPENDENT,	/* every server saw the same mapping */
	STUN_MAPPING_DEPENDENT		/* two servers disagreed */
};

struct stun_mapping {
	uint8_t addr[4];
	uint16_t port;
	int nsamples;
	int agree;
};

void stun_mapping_reset(struct stun_mapping *m);
void stun_mapping_add(struct stun_mapping *m, const uint8_t addr[4],
		      uint16_t port);
int stun_mapping_result(const struct stun_mapping *m);

#endif
