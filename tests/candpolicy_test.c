/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "candpolicy.h"
#include "path.h"
#include "wsock.h"

static void default_policy_check(void)
{
	struct cand_policy p;
	int fam;

	cand_policy_default(&p);

	/* Global non-EUI-64 IPv6: keep. */
	assert(cand_addr_keep("2001:db8::279", 0, &p, &fam) == 1);
	assert(fam == 6);

	/* Global EUI-64 IPv6 (ff:fe in the IID, embeds MAC): drop. */
	assert(cand_addr_keep("2001:db8::211:22ff:fe33:4455", 0, &p, &fam) == 0);

	/* Link-local, ULA, Yggdrasil overlay, loopback: drop. */
	assert(cand_addr_keep("fe80::1", 0, &p, NULL) == 0);
	assert(cand_addr_keep("fc00::1", 0, &p, NULL) == 0);
	assert(cand_addr_keep("fd12:3456::1", 0, &p, NULL) == 0);
	assert(cand_addr_keep("0200::1", 0, &p, NULL) == 0);
	assert(cand_addr_keep("0300::abcd", 0, &p, NULL) == 0);
	assert(cand_addr_keep("::1", 0, &p, NULL) == 0);

	/* IPv4: private kept by default, loopback and link-local dropped. */
	assert(cand_addr_keep("192.168.1.5", 0, &p, &fam) == 1 && fam == 4);
	assert(cand_addr_keep("10.0.0.7", 0, &p, NULL) == 1);
	assert(cand_addr_keep("172.16.9.9", 0, &p, NULL) == 1);
	assert(cand_addr_keep("203.0.113.5", 0, &p, NULL) == 1);
	assert(cand_addr_keep("127.0.0.1", 0, &p, NULL) == 0);
	assert(cand_addr_keep("169.254.1.1", 0, &p, NULL) == 0);

	/* Family filter. */
	assert(cand_addr_keep("2001:db8::279", 4, &p, NULL) == 0);
	assert(cand_addr_keep("203.0.113.5", 6, &p, NULL) == 0);

	/* Garbage: drop. */
	assert(cand_addr_keep("host.local", 0, &p, NULL) == 0);
}

static void opt_in_check(void)
{
	struct cand_policy p;

	cand_policy_default(&p);
	p.allow_ula = 1;
	p.allow_overlay = 1;
	p.allow_eui64 = 1;
	assert(cand_addr_keep("fc00::1", 0, &p, NULL) == 1);
	assert(cand_addr_keep("0200::1", 0, &p, NULL) == 1);
	assert(cand_addr_keep("2001:db8::211:22ff:fe33:4455", 0, &p, NULL) == 1);

	cand_policy_default(&p);
	p.allow_private_v4 = 0;
	assert(cand_addr_keep("192.168.1.5", 0, &p, NULL) == 0);
}

static void sdp_filter_check(void)
{
	struct cand_policy p;
	char out[1024];
	static const char sdp[] =
		"a=ice-ufrag:abcd\r\n"
		"a=ice-pwd:secretpwd\r\n"
		"a=candidate:1 1 UDP 2 2001:db8::279 40000 typ host\r\n"
		"a=candidate:2 1 UDP 2 fe80::1 40001 typ host\r\n"
		"a=candidate:3 1 UDP 2 fc00::1 40002 typ host\r\n"
		"a=candidate:4 1 UDP 2 2001:db8::211:22ff:fe33:4455 40003 typ host\r\n"
		"a=candidate:5 1 UDP 2 192.168.1.5 40004 typ host\r\n";

	cand_policy_default(&p);
	cand_sdp_filter(sdp, 0, &p, out, sizeof(out));

	assert(strstr(out, "ice-ufrag"));
	assert(strstr(out, "2001:db8::279"));
	assert(strstr(out, "192.168.1.5"));
	assert(!strstr(out, "fe80::1"));
	assert(!strstr(out, "fc00::1"));
	assert(!strstr(out, "fe33:4455"));

	cand_sdp_filter(sdp, 6, &p, out, sizeof(out));
	assert(strstr(out, "2001:db8::279"));
	assert(!strstr(out, "192.168.1.5"));
}

/*
 * An endpoint the peer advertised over the segment is probed with nothing
 * having arrived from it, so one of our own addresses is not the peer -- and
 * a v4 address arrives here in the mapped form paths hold.
 */
static void own_endpoint_check(void)
{
	struct netmon_addr local[2];
	struct path_ep ep;
	struct sockaddr_in sa4;

	memset(local, 0, sizeof(local));
	local[0].family = AF_INET;
	local[0].addrlen = 4;
	assert(inet_pton(AF_INET, "192.168.5.164", local[0].addr) == 1);
	local[1].family = AF_INET6;
	local[1].addrlen = 16;
	assert(inet_pton(AF_INET6, "2a01:db8::1", local[1].addr) == 1);

	memset(&sa4, 0, sizeof(sa4));
	sa4.sin_family = AF_INET;
	sa4.sin_port = htons(40000);
	assert(inet_pton(AF_INET, "192.168.5.164", &sa4.sin_addr) == 1);
	assert(!path_ep_from_sockaddr(&ep, (struct sockaddr *)&sa4,
				      sizeof(sa4)));
	assert(cand_ep_is_local(ep.addr, local, 2));

	assert(inet_pton(AF_INET, "192.168.5.170", &sa4.sin_addr) == 1);
	assert(!path_ep_from_sockaddr(&ep, (struct sockaddr *)&sa4,
				      sizeof(sa4)));
	assert(!cand_ep_is_local(ep.addr, local, 2));

	/* The v6 half, and a machine that knows of no address of its own. */
	memset(&ep, 0, sizeof(ep));
	assert(inet_pton(AF_INET6, "2a01:db8::1", ep.addr) == 1);
	assert(cand_ep_is_local(ep.addr, local, 2));
	assert(!cand_ep_is_local(ep.addr, NULL, 0));
}

static void fan_check(void)
{
	uint8_t pool[3][4];
	char sdp[1024];
	char *at;
	unsigned pr;
	static const char base[] =
		"a=ice-ufrag:abcd\r\n"
		"a=ice-pwd:secretpwd\r\n"
		"a=candidate:1 1 UDP 2130706431 192.168.5.164 40000 typ host\r\n"
		"a=candidate:2 1 UDP 1678769919 203.0.113.9 40002 typ srflx raddr 0.0.0.0 rport 0\r\n";

	assert(inet_pton(AF_INET, "203.0.113.9", pool[0]) == 1);
	assert(inet_pton(AF_INET, "198.51.100.7", pool[1]) == 1);
	assert(inet_pton(AF_INET, "192.0.2.33", pool[2]) == 1);

	/* Every pool member is advertised once, at the reflexive port, ranked
	 * below the observed candidate; the observed one is not repeated. */
	strcpy(sdp, base);
	cand_sdp_fan_v4(sdp, sizeof(sdp), pool, 3, 0);
	assert(strstr(sdp, "198.51.100.7 40002 typ srflx"));
	assert(strstr(sdp, "192.0.2.33 40002 typ srflx"));
	at = strstr(sdp, "203.0.113.9");
	assert(at && !strstr(at + 1, "203.0.113.9"));
	at = strstr(sdp, "a=candidate:pool");
	assert(at && sscanf(at, "a=candidate:%*s %*d %*s %u", &pr) == 1 &&
	       pr < 1678769919);

	/* The host candidate is never a fan source. */
	assert(!strstr(sdp, "192.168.5.164 40000 typ srflx"));

	/* No reflexive candidate: nothing to fan from. */
	strcpy(sdp,
	       "a=ice-ufrag:abcd\r\n"
	       "a=candidate:1 1 UDP 2 192.168.5.164 40000 typ host\r\n");
	cand_sdp_fan_v4(sdp, sizeof(sdp), pool, 3, 0);
	assert(!strstr(sdp, "198.51.100.7"));

	/* Reflexive ports disagree: the mapping is per-destination in the
	 * port too, and no variant can be named. */
	strcpy(sdp,
	       "a=candidate:1 1 UDP 9 203.0.113.9 40002 typ srflx raddr 0.0.0.0 rport 0\r\n"
	       "a=candidate:2 1 UDP 8 192.0.2.33 40007 typ srflx raddr 0.0.0.0 rport 0\r\n");
	cand_sdp_fan_v4(sdp, sizeof(sdp), pool, 3, 0);
	assert(!strstr(sdp, "198.51.100.7"));

	/* Two observed members at one port (a multi-homed STUN name): only
	 * the missing third is added. */
	strcpy(sdp,
	       "a=candidate:1 1 UDP 9 203.0.113.9 40002 typ srflx raddr 0.0.0.0 rport 0\r\n"
	       "a=candidate:2 1 UDP 8 192.0.2.33 40002 typ srflx raddr 0.0.0.0 rport 0\r\n");
	cand_sdp_fan_v4(sdp, sizeof(sdp), pool, 3, 0);
	assert(strstr(sdp, "198.51.100.7 40002 typ srflx"));
	at = strstr(sdp, "192.0.2.33");
	assert(at && !strstr(at + 1, "192.0.2.33"));

	/* A description without a trailing newline still parses whole. */
	strcpy(sdp,
	       "a=candidate:1 1 UDP 9 203.0.113.9 40002 typ srflx raddr 0.0.0.0 rport 0");
	cand_sdp_fan_v4(sdp, sizeof(sdp), pool, 3, 0);
	assert(strstr(sdp, "198.51.100.7 40002 typ srflx"));
	assert(strstr(sdp, "192.0.2.33 40002 typ srflx"));

	/* A buffer with no room for a whole variant line stays as it was. */
	strcpy(sdp, base);
	cand_sdp_fan_v4(sdp, strlen(base) + 40, pool, 3, 0);
	assert(!strcmp(sdp, base));
}

/*
 * A probe-proven dependent mapping bails before any candidate is even
 * scanned -- unlike the reactive port-disagreement check, this also covers
 * the single-candidate case, where nothing has an existing port to disagree
 * with.
 */
static void mapping_dependent_check(void)
{
	uint8_t pool[3][4];
	char sdp[1024];
	static const char one[] =
		"a=ice-ufrag:abcd\r\n"
		"a=candidate:2 1 UDP 1678769919 203.0.113.9 40002 typ srflx raddr 0.0.0.0 rport 0\r\n";
	static const char agree[] =
		"a=candidate:1 1 UDP 9 203.0.113.9 40002 typ srflx raddr 0.0.0.0 rport 0\r\n"
		"a=candidate:2 1 UDP 8 192.0.2.33 40002 typ srflx raddr 0.0.0.0 rport 0\r\n";

	assert(inet_pton(AF_INET, "203.0.113.9", pool[0]) == 1);
	assert(inet_pton(AF_INET, "198.51.100.7", pool[1]) == 1);
	assert(inet_pton(AF_INET, "192.0.2.33", pool[2]) == 1);

	/* One candidate can never reactively disagree with itself, so today
	 * this would be fanned; the probe's own verdict must stop it. */
	strcpy(sdp, one);
	cand_sdp_fan_v4(sdp, sizeof(sdp), pool, 3, 1);
	assert(!strcmp(sdp, one));

	/* Two candidates that happen to agree would be fanned reactively
	 * (see fan_check); the probe's verdict overrides that optimism. */
	strcpy(sdp, agree);
	cand_sdp_fan_v4(sdp, sizeof(sdp), pool, 3, 1);
	assert(!strcmp(sdp, agree));
}

/* A description is an offer to somewhere only if something in it can be aimed
 * at from there. */
static void off_segment_check(void)
{
	static const char lan_only[] =
		"a=candidate:1 1 UDP 2130706431 192.168.1.5 40000 typ host\n"
		"a=candidate:2 1 UDP 2130706430 10.0.0.7 40000 typ host\n";
	static const char with_srflx[] =
		"a=candidate:1 1 UDP 2130706431 192.168.1.5 40000 typ host\n"
		"a=candidate:2 1 UDP 1678769663 203.0.113.9 40000 typ srflx "
		"raddr 0.0.0.0 rport 0\n";
	static const char v6_host[] =
		"a=candidate:1 1 UDP 2130706431 192.168.1.5 40000 typ host\n"
		"a=candidate:2 1 UDP 2130706430 2001:db8::279 40000 typ host\n";
	static const char v6_ula[] =
		"a=candidate:1 1 UDP 2130706430 fd12:3456::1 40000 typ host\n"
		"a=candidate:2 1 UDP 2130706429 fe80::1 40000 typ host\n";
	static const char relayed[] =
		"a=candidate:1 1 UDP 16777215 203.0.113.1 3478 typ relay "
		"raddr 0.0.0.0 rport 0\n";

	assert(cand_sdp_reaches_off_segment(lan_only) == 0);
	assert(cand_sdp_reaches_off_segment(with_srflx) == 1);
	assert(cand_sdp_reaches_off_segment(v6_host) == 1);
	assert(cand_sdp_reaches_off_segment(v6_ula) == 0);
	assert(cand_sdp_reaches_off_segment(relayed) == 1);
	assert(cand_sdp_reaches_off_segment("") == 0);
	assert(cand_sdp_reaches_off_segment("v=0\r\na=ice-ufrag:abcd\r\n") == 0);
}

int main(void)
{
	off_segment_check();
	default_policy_check();
	opt_in_check();
	sdp_filter_check();
	own_endpoint_check();
	fan_check();
	mapping_dependent_check();
	return 0;
}
