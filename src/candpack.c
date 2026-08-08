/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include "candpack.h"
#include "candpolicy.h"

#define CANDPACK_VERSION 1

#define CT_HOST 0
#define CT_SRFLX 1
#define CT_PRFLX 2
#define CT_RELAY 3

static int type_code(const char *t)
{
	if (!strcmp(t, "host"))
		return CT_HOST;
	if (!strcmp(t, "srflx"))
		return CT_SRFLX;
	if (!strcmp(t, "prflx"))
		return CT_PRFLX;
	if (!strcmp(t, "relay"))
		return CT_RELAY;
	return -1;
}

static const char *type_name(int c)
{
	if (c == CT_HOST)
		return "host";
	if (c == CT_SRFLX)
		return "srflx";
	if (c == CT_PRFLX)
		return "prflx";
	if (c == CT_RELAY)
		return "relay";
	return NULL;
}

/* Copy one '\n'-delimited line (CR stripped) into buf; advance *p. */
static int next_line(const char **p, char *buf, size_t bufsz)
{
	const char *s = *p;
	size_t n = 0;

	if (!*s)
		return 0;
	while (*s && *s != '\n') {
		if (*s != '\r' && n + 1 < bufsz)
			buf[n++] = *s;
		s++;
	}
	if (*s == '\n')
		s++;
	buf[n] = '\0';
	*p = s;
	return 1;
}

static int cred_value(const char *line, const char *key, char *out, size_t max)
{
	size_t klen = strlen(key);

	if (strncmp(line, key, klen))
		return 0;
	if (sscanf(line + klen, "%256s", out) != 1)
		return 0;
	if (strlen(out) >= max)
		return 0;
	return 1;
}

int candpack_encode(const char *sdp, int for_dht, uint8_t *out, size_t max)
{
	struct cand_policy pol;
	char ufrag[257], pwd[257];
	char line[512];
	const char *p;
	size_t o = 0;
	size_t ncand_off;
	int ncand = 0;
	int ul, pl;

	ufrag[0] = '\0';
	pwd[0] = '\0';

	/*
	 * A private v4 address (RFC1918/CGNAT) is kept for the DHT even though
	 * it is useless across the open internet: when the two peers share a
	 * private network through nested NAT -- one on the inner, one on the
	 * outer side -- multicast cannot reach across the L3 boundary, but the
	 * inner peer can still punch to the outer peer's private address, and
	 * the outer peer learns the inner peer's source address from that
	 * incoming check (libjuice peer-reflexive). What cannot help off our own
	 * L2 segment (link-local, ULA, overlay, EUI-64) is dropped; multicast
	 * covers same-segment peers. The mailbox is sealed, so nothing here is
	 * exposed to the public DHT.
	 */
	if (for_dht) {
		cand_policy_default(&pol);
	} else {
		pol.allow_private_v4 = 1;
		pol.allow_ula = 1;
		pol.allow_overlay = 1;
		pol.allow_eui64 = 1;
		pol.allow_linklocal = 1;
	}

	p = sdp;
	while (next_line(&p, line, sizeof(line))) {
		cred_value(line, "a=ice-ufrag:", ufrag, sizeof(ufrag));
		cred_value(line, "a=ice-pwd:", pwd, sizeof(pwd));
	}
	if (!ufrag[0] || !pwd[0])
		return 0;

	ul = (int)strlen(ufrag);
	pl = (int)strlen(pwd);
	if (max < (size_t)(1 + 1 + ul + 1 + pl + 1))
		return -1;
	out[o++] = CANDPACK_VERSION;
	out[o++] = (uint8_t)ul;
	memcpy(out + o, ufrag, (size_t)ul);
	o += (size_t)ul;
	out[o++] = (uint8_t)pl;
	memcpy(out + o, pwd, (size_t)pl);
	o += (size_t)pl;
	ncand_off = o++;		/* backfilled once counted */

	p = sdp;
	while (next_line(&p, line, sizeof(line))) {
		char found[33], transport[8], addr[64], type[16];
		uint8_t ab[16];
		uint32_t prio;
		int comp, port, fam, tc;
		size_t need;

		if (strncmp(line, "a=candidate:", 12))
			continue;
		if (sscanf(line + 12, "%32s %d %7s %u %63s %d typ %15s",
			   found, &comp, transport, &prio, addr, &port,
			   type) < 7)
			continue;
		if (comp != 1 || strcasecmp(transport, "UDP"))
			continue;
		if (port < 0 || port > 65535)
			continue;
		tc = type_code(type);
		if (tc < 0)
			continue;
		if (!cand_addr_keep(addr, 0, &pol, NULL))
			continue;
		if (inet_pton(AF_INET6, addr, ab) == 1)
			fam = 6;
		else if (inet_pton(AF_INET, addr, ab) == 1)
			fam = 4;
		else
			continue;
		if (ncand == 255)
			break;

		need = 1 + 1 + 4 + 2 + (fam == 6 ? 16 : 4);
		if (o + need > max)
			return -1;
		out[o++] = (uint8_t)tc;
		out[o++] = (uint8_t)fam;
		out[o++] = (uint8_t)(prio >> 24);
		out[o++] = (uint8_t)(prio >> 16);
		out[o++] = (uint8_t)(prio >> 8);
		out[o++] = (uint8_t)prio;
		out[o++] = (uint8_t)(port >> 8);
		out[o++] = (uint8_t)port;
		memcpy(out + o, ab, fam == 6 ? 16 : 4);
		o += (fam == 6 ? 16 : 4);
		ncand++;
	}

	out[ncand_off] = (uint8_t)ncand;
	return (int)o;
}

int candpack_announce_encode(const char *sdp, uint8_t *out, size_t max)
{
	char ufrag[257], pwd[257], line[512];
	const char *p = sdp;
	int port = -1, ul, pl;
	size_t o = 0;

	ufrag[0] = '\0';
	pwd[0] = '\0';
	while (next_line(&p, line, sizeof(line))) {
		char f[33], tr[8], addr[64], ty[16];
		int comp, pt;
		unsigned prio;

		cred_value(line, "a=ice-ufrag:", ufrag, sizeof(ufrag));
		cred_value(line, "a=ice-pwd:", pwd, sizeof(pwd));
		if (port < 0 && !strncmp(line, "a=candidate:", 12) &&
		    sscanf(line + 12, "%32s %d %7s %u %63s %d typ %15s", f,
			   &comp, tr, &prio, addr, &pt, ty) >= 7 &&
		    pt > 0 && pt <= 65535)
			port = pt;
	}
	if (!ufrag[0] || !pwd[0] || port < 0)
		return 0;
	ul = (int)strlen(ufrag);
	pl = (int)strlen(pwd);
	if (max < (size_t)(1 + 1 + ul + 1 + pl + 2))
		return -1;
	out[o++] = CANDPACK_VERSION;
	out[o++] = (uint8_t)ul;
	memcpy(out + o, ufrag, (size_t)ul);
	o += (size_t)ul;
	out[o++] = (uint8_t)pl;
	memcpy(out + o, pwd, (size_t)pl);
	o += (size_t)pl;
	out[o++] = (uint8_t)((port >> 8) & 0xff);
	out[o++] = (uint8_t)(port & 0xff);
	return (int)o;
}

int candpack_announce_decode(const uint8_t *in, size_t in_len,
			     const struct sockaddr *src, socklen_t srclen,
			     char *out, size_t max)
{
	char ufrag[257], pwd[257], host[128];
	size_t i = 0;
	int ul, pl, port, r;

	if (in_len < 1 || in[i++] != CANDPACK_VERSION)
		return -1;
	if (i >= in_len)
		return -1;
	ul = in[i++];
	if (i + (size_t)ul >= in_len)
		return -1;
	memcpy(ufrag, in + i, (size_t)ul);
	ufrag[ul] = '\0';
	i += (size_t)ul;
	pl = in[i++];
	if (i + (size_t)pl + 2 > in_len)
		return -1;
	memcpy(pwd, in + i, (size_t)pl);
	pwd[pl] = '\0';
	i += (size_t)pl;
	port = (in[i] << 8) | in[i + 1];

	/* The address is the packet source; getnameinfo keeps the zone id a
	 * link-local address needs, and libjuice resolves it with getaddrinfo. */
	if (getnameinfo(src, srclen, host, sizeof(host), NULL, 0, NI_NUMERICHOST))
		return -1;

	r = snprintf(out, max,
		     "a=ice-ufrag:%s\na=ice-pwd:%s\n"
		     "a=candidate:0 1 UDP 2130706431 %s %d typ host\n",
		     ufrag, pwd, host, port);
	if (r < 0 || (size_t)r >= max)
		return -1;
	return r;
}

int candpack_decode(const uint8_t *in, size_t in_len, char *out, size_t max)
{
	size_t i = 0;
	int o = 0, r;
	int ul, pl, ncand, k;
	char ufrag[257], pwd[257];

	if (in_len < 1 || in[i++] != CANDPACK_VERSION)
		return -1;
	if (i >= in_len)
		return -1;
	ul = in[i++];
	if (i + (size_t)ul >= in_len)
		return -1;
	memcpy(ufrag, in + i, (size_t)ul);
	ufrag[ul] = '\0';
	i += (size_t)ul;
	pl = in[i++];
	if (i + (size_t)pl > in_len)
		return -1;
	memcpy(pwd, in + i, (size_t)pl);
	pwd[pl] = '\0';
	i += (size_t)pl;
	if (i >= in_len)
		return -1;
	ncand = in[i++];

	r = snprintf(out + o, max - (size_t)o,
		     "a=ice-ufrag:%s\na=ice-pwd:%s\n", ufrag, pwd);
	if (r < 0 || (size_t)o + (size_t)r >= max)
		return -1;
	o += r;

	for (k = 0; k < ncand; k++) {
		char abuf[64];
		const char *tn;
		uint32_t prio;
		int fam, tc, port, alen;

		if (i + 8 > in_len)
			return -1;
		tc = in[i++];
		fam = in[i++];
		prio = ((uint32_t)in[i] << 24) | ((uint32_t)in[i + 1] << 16) |
		       ((uint32_t)in[i + 2] << 8) | (uint32_t)in[i + 3];
		i += 4;
		port = (in[i] << 8) | in[i + 1];
		i += 2;
		alen = (fam == 6) ? 16 : 4;
		if (i + (size_t)alen > in_len)
			return -1;
		if (!inet_ntop(fam == 6 ? AF_INET6 : AF_INET, in + i, abuf,
			       sizeof(abuf)))
			return -1;
		i += (size_t)alen;
		tn = type_name(tc);
		if (!tn)
			return -1;

		r = snprintf(out + o, max - (size_t)o,
			     "a=candidate:%d 1 UDP %u %s %d typ %s%s\n", k,
			     (unsigned)prio, abuf, port, tn,
			     tc == CT_HOST ? "" : " raddr 0.0.0.0 rport 0");
		if (r < 0 || (size_t)o + (size_t)r >= max)
			return -1;
		o += r;
	}

	return o;
}
