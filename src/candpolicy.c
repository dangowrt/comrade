/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#define _GNU_SOURCE
#include "wsock.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "candpolicy.h"
#include "oscompat.h"

void cand_policy_default(struct cand_policy *p)
{
	p->allow_private_v4 = 1;
	p->allow_ula = 0;
	p->allow_overlay = 0;
	p->allow_eui64 = 0;
	p->allow_linklocal = 0;
}

static int v6_keep(const uint8_t b[16], const struct cand_policy *p)
{
	static const uint8_t loopback[16] = { [15] = 1 };

	if (!memcmp(b, loopback, 16))
		return 0;
	if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
		return p->allow_linklocal;
	if ((b[0] & 0xfe) == 0xfc)
		return p->allow_ula;
	if ((b[0] & 0xfe) == 0x02)
		return p->allow_overlay;
	if ((b[0] & 0xe0) == 0x20) {
		if (b[11] == 0xff && b[12] == 0xfe && !p->allow_eui64)
			return 0;
		return 1;
	}
	return 0;
}

static int v4_keep(const uint8_t b[4], const struct cand_policy *p)
{
	if (b[0] == 127)
		return 0;
	if (b[0] == 169 && b[1] == 254)
		return p->allow_linklocal;
	if (b[0] == 10)
		return p->allow_private_v4;
	if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
		return p->allow_private_v4;
	if (b[0] == 192 && b[1] == 168)
		return p->allow_private_v4;
	return 1;
}

int cand_addr_keep(const char *addr, int family_filter,
		   const struct cand_policy *p, int *family_out)
{
	uint8_t b[16];
	int fam = 0;
	int keep;

	if (inet_pton(AF_INET6, addr, b) == 1) {
		fam = 6;
		keep = v6_keep(b, p);
	} else if (inet_pton(AF_INET, addr, b) == 1) {
		fam = 4;
		keep = v4_keep(b, p);
	} else {
		if (family_out)
			*family_out = 0;
		return 0;
	}

	if (family_out)
		*family_out = fam;
	if (family_filter && fam != family_filter)
		return 0;
	return keep;
}

static int line_addr(const char *line, size_t len, char *buf, size_t buflen)
{
	const char *p = os_memmem(line, len, "candidate:", 10);
	const char *end = line + len;
	const char *start;
	int spaces = 0;
	size_t n = 0;

	if (!p)
		return -1;
	for (p += 10; p < end && *p != '\r' && *p != '\n'; p++) {
		if (*p != ' ')
			continue;
		if (++spaces == 4) {
			start = p + 1;
			while (start < end && *start != ' ' &&
			       *start != '\r' && *start != '\n') {
				if (n >= buflen - 1)
					return -1;
				buf[n++] = *start++;
			}
			buf[n] = '\0';
			return n ? 0 : -1;
		}
	}
	return -1;
}

int cand_addr_is_local(const char *addr, const struct netmon_addr *local,
		       size_t nlocal)
{
	uint8_t b[16];
	int alen;
	size_t i;

	if (inet_pton(AF_INET6, addr, b) == 1)
		alen = 16;
	else if (inet_pton(AF_INET, addr, b) == 1)
		alen = 4;
	else
		return 0;
	for (i = 0; i < nlocal; i++)
		if (local[i].addrlen == alen && !memcmp(local[i].addr, b, (size_t)alen))
			return 1;
	return 0;
}

void cand_sdp_filter(const char *in, int family_filter,
		     const struct cand_policy *p, char *out, size_t outlen)
{
	const char *line = in;
	size_t o = 0;

	while (*line) {
		const char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line + 1) : strlen(line);
		int keep = 1;
		char addr[64];

		if (os_memmem(line, len, "candidate:", 10)) {
			if (line_addr(line, len, addr, sizeof(addr)) ||
			    !cand_addr_keep(addr, family_filter, p, NULL))
				keep = 0;
		}
		if (keep && o + len < outlen) {
			memcpy(out + o, line, len);
			o += len;
		}
		if (!nl)
			break;
		line = nl + 1;
	}
	out[o] = '\0';
}

void cand_sdp_fan_v4(char *sdp, size_t cap, const uint8_t (*pool)[4],
		     size_t npool, int mapping_dependent)
{
	uint8_t seen[8][4];
	const char *line = sdp;
	size_t nseen = 0, o, i, k;
	unsigned prio = 0;
	int port = -1;

	if (mapping_dependent)
		return;
	while (*line) {
		const char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line + 1) : strlen(line);
		const char *p = os_memmem(line, len, "candidate:", 10);
		char addr[64], typ[16];
		uint8_t b[4];
		unsigned pr;
		int pt;

		if (p && sscanf(p, "candidate:%*s %*d %*s %u %63s %d typ %15s",
				&pr, addr, &pt, typ) == 4 &&
		    !strcmp(typ, "srflx") && inet_pton(AF_INET, addr, b) == 1) {
			if (port >= 0 && pt != port)
				return;
			port = pt;
			if (!prio || pr < prio)
				prio = pr;
			if (nseen < sizeof(seen) / sizeof(seen[0])) {
				memcpy(seen[nseen], b, 4);
				nseen++;
			}
		}
		if (!nl)
			break;
		line = nl + 1;
	}
	if (port <= 0)
		return;

	o = strlen(sdp);
	if (o && sdp[o - 1] != '\n') {
		if (o + 1 >= cap)
			return;
		sdp[o++] = '\n';
		sdp[o] = '\0';
	}
	for (i = 0; i < npool; i++) {
		char abuf[64], cand[96];
		int n, dup = 0;

		for (k = 0; k < nseen; k++)
			if (!memcmp(seen[k], pool[i], 4))
				dup = 1;
		if (dup || !inet_ntop(AF_INET, pool[i], abuf, sizeof(abuf)))
			continue;
		n = snprintf(cand, sizeof(cand),
			     "a=candidate:pool%u 1 UDP %u %s %d typ srflx "
			     "raddr 0.0.0.0 rport 0\n", (unsigned)i,
			     prio > (unsigned)i + 1 ? prio - (unsigned)i - 1 : 1,
			     abuf, port);
		if (n < 0 || o + (size_t)n >= cap)
			return;
		memcpy(sdp + o, cand, (size_t)n + 1);
		o += (size_t)n;
	}
}

int cand_ep_is_local(const uint8_t addr[16], const struct netmon_addr *local,
		     size_t nlocal)
{
	static const uint8_t v4_prefix[12] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
	};
	static const uint8_t v6_loop[16] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
	};
	const uint8_t *a = addr;
	int alen = 16;
	size_t i;

	if (!memcmp(addr, v4_prefix, sizeof(v4_prefix))) {
		a = addr + 12;
		alen = 4;
	}
	/*
	 * Loopback is ours by definition and is not in the interface snapshot,
	 * which leaves it out as naming this machine to nobody else. A peer
	 * offering it is offering us ourselves.
	 */
	if (alen == 4 ? a[0] == 127 : !memcmp(a, v6_loop, 16))
		return 1;
	for (i = 0; i < nlocal; i++)
		if (local[i].addrlen == alen &&
		    !memcmp(local[i].addr, a, (size_t)alen))
			return 1;
	return 0;
}

/*
 * A description is an offer to somewhere only if something in it can be aimed
 * at from there. Anything the peer's checks reach through a NAT -- reflexive,
 * peer-reflexive, relayed -- says yes on its own; a host candidate says yes
 * only when its address is globally routable, which is how IPv6 usually
 * arrives, since no reflexive candidate is gathered beside a global host one.
 */
int cand_sdp_reaches_off_segment(const char *sdp)
{
	struct cand_policy global;
	const char *line = sdp;

	memset(&global, 0, sizeof(global));
	global.allow_eui64 = 1;		/* however formed, a global address reaches */
	while (*line) {
		const char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line + 1) : strlen(line);
		const char *p = os_memmem(line, len, "candidate:", 10);
		char addr[64], typ[16];

		if (p && sscanf(p, "candidate:%*s %*d %*s %*u %63s %*d typ %15s",
				addr, typ) == 2) {
			if (strcmp(typ, "host"))
				return 1;
			if (cand_addr_keep(addr, 0, &global, NULL))
				return 1;
		}
		if (!nl)
			break;
		line = nl + 1;
	}
	return 0;
}

void cand_sdp_ufrag(const char *sdp, char *out, size_t max)
{
	const char *p;
	size_t i = 0;

	if (!out || !max)
		return;
	out[0] = '\0';
	if (!sdp)
		return;
	p = strstr(sdp, "a=ice-ufrag:");
	if (!p)
		return;
	p += 12;
	while (*p && *p != '\r' && *p != '\n' && *p != ' ' && i + 1 < max)
		out[i++] = *p++;
	out[i] = '\0';
}
