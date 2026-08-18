/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_FWDSPEC_H
#define COMRADE_FWDSPEC_H

#include <stdint.h>

/*
 * One parsed -L/-R forwarding specification, OpenSSH grammar:
 *
 *     [bind_address:]port:host:hostport
 *
 * with IPv6 literals in square brackets. bind_address "" means loopback
 * (ssh's default without GatewayPorts) and "*" means every interface.
 * port may be 0 for "any" (-R lets the peer pick and report it back).
 */

struct fwdspec {
	char bind[64];		/* listen address; "" = loopback, "*" = any */
	uint16_t bind_port;
	char host[256];		/* connect target for accepted connections */
	uint16_t port;
};

/* Parse arg into sp. Returns 0 on success, -1 on a malformed spec. */
int fwdspec_parse(const char *arg, struct fwdspec *sp);

#endif
