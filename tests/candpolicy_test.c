/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <string.h>

#include "candpolicy.h"

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

int main(void)
{
	default_policy_check();
	opt_in_check();
	sdp_filter_check();
	return 0;
}
