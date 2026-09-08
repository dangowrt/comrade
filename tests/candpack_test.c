/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "candpack.h"

static const char *sdp =
	"a=ice-ufrag:abcdef01\n"
	"a=ice-pwd:0123456789abcdef0123456789abcdef\n"
	"a=candidate:4 1 UDP 2116025599 2001:db8::279 51790 typ host\n"
	"a=candidate:1 1 UDP 2114977791 192.168.0.2 51790 typ host\n"
	"a=candidate:2 1 UDP 2114977535 10.1.2.3 51790 typ host\n"
	"a=candidate:5 1 UDP 1678769151 203.0.113.233 51790 typ srflx raddr 0.0.0.0 rport 0\n"
	"a=candidate:6 1 UDP 1679817727 fe80::1234:5678 51790 typ host\n";

/* Count "a=candidate:" occurrences in a description. */
static int count_cands(const char *s)
{
	int n = 0;
	const char *p = s;

	while ((p = strstr(p, "a=candidate:")) != NULL) {
		n++;
		p += 12;
	}
	return n;
}

static void for_dht_check(void)
{
	uint8_t buf[512];
	char out[2048];
	int n, r;

	n = candpack_encode(sdp, 1, 0, NULL, buf, sizeof(buf));
	assert(n > 0);

	r = candpack_decode(buf, (size_t)n, NULL, NULL, 0, out, sizeof(out));
	assert(r > 0);

	/* ufrag/pwd preserved (libjuice rejects a description lacking them). */
	assert(strstr(out, "a=ice-ufrag:abcdef01\n"));
	assert(strstr(out, "a=ice-pwd:0123456789abcdef0123456789abcdef\n"));

	/* Global v6 host, public v4 srflx, AND the private v4 (RFC1918) that a
	 * nested-NAT inner peer can punch to -- all four survive. Only the
	 * link-local v6, useless off-segment, is dropped. */
	assert(count_cands(out) == 4);
	assert(strstr(out, "2001:db8::279"));
	assert(strstr(out, "203.0.113.233"));
	assert(strstr(out, "192.168.0.2"));
	assert(strstr(out, "10.1.2.3"));
	assert(!strstr(out, "fe80::"));

	/* srflx carries raddr/rport; host does not. */
	assert(strstr(out, "203.0.113.233 51790 typ srflx raddr 0.0.0.0 rport 0"));
	assert(strstr(out, "2001:db8::279 51790 typ host\n"));
}

static void full_set_check(void)
{
	uint8_t buf[512];
	char out[2048];
	int n, r;

	/* Permissive keeps every on-link address, including private v4 and the
	 * link-local v6 that same-segment peers use. All five survive. */
	n = candpack_encode(sdp, 0, 0, NULL, buf, sizeof(buf));
	assert(n > 0);
	r = candpack_decode(buf, (size_t)n, NULL, NULL, 0, out, sizeof(out));
	assert(r > 0);
	assert(strstr(out, "192.168.0.2"));
	assert(strstr(out, "10.1.2.3"));
	assert(strstr(out, "fe80::1234:5678"));
	assert(count_cands(out) == 5);
}

static void no_creds_check(void)
{
	uint8_t buf[512];
	int n;

	/* Nothing packable without credentials. */
	n = candpack_encode("a=candidate:1 1 UDP 100 203.0.113.5 9 typ host\n", 1,
			    0, NULL, buf, sizeof(buf));
	assert(n == 0);
}

/* The offer's network generation rides the packed slot and comes back whole. */
static void gen_check(void)
{
	uint8_t buf[512];
	char out[2048];
	uint32_t g = 0;
	int n, r;

	n = candpack_encode(sdp, 1, 0xdeadbeef, NULL, buf, sizeof(buf));
	assert(n > 0);
	r = candpack_decode(buf, (size_t)n, &g, NULL, 0, out, sizeof(out));
	assert(r > 0);
	assert(g == 0xdeadbeef);
	n = candpack_encode(sdp, 1, 0, NULL, buf, sizeof(buf));
	assert(n > 0);
	r = candpack_decode(buf, (size_t)n, &g, NULL, 0, out, sizeof(out));
	assert(r > 0 && g == 0);
}

/* The offer ufrag a claim answers rides the packed slot and comes back whole;
 * a packing that names none decodes to the empty string. */
static void offer_check(void)
{
	char co[64], out[2048];
	uint8_t buf[512];
	int n, r;

	n = candpack_encode(sdp, 1, 0, "9f3c2a1b", buf, sizeof(buf));
	assert(n > 0);
	co[0] = 'x';
	r = candpack_decode(buf, (size_t)n, NULL, co, sizeof(co), out,
			    sizeof(out));
	assert(r > 0);
	assert(!strcmp(co, "9f3c2a1b"));
	/* the candidates and creds are unaffected by the named offer */
	assert(strstr(out, "a=ice-ufrag:abcdef01\n"));
	assert(count_cands(out) == 4);

	n = candpack_encode(sdp, 1, 0, NULL, buf, sizeof(buf));
	assert(n > 0);
	co[0] = 'x';
	r = candpack_decode(buf, (size_t)n, NULL, co, sizeof(co), out,
			    sizeof(out));
	assert(r > 0);
	assert(co[0] == '\0');
}

/* A version-2 buffer predates the offer-ufrag field and still decodes. */
static void v2_compat_check(void)
{
	static const uint8_t v2[] = {
		2, 0, 0, 0, 0,
		4, 'a', 'b', 'c', 'd',
		4, '1', '2', '3', '4',
		0
	};
	char co[64], out[2048];
	uint32_t g = 1;
	int r;

	co[0] = 'x';
	r = candpack_decode(v2, sizeof(v2), &g, co, sizeof(co), out,
			    sizeof(out));
	assert(r > 0);
	assert(g == 0);
	assert(co[0] == '\0');
	assert(strstr(out, "a=ice-ufrag:abcd\n"));
	assert(strstr(out, "a=ice-pwd:1234\n"));
}

int main(void)
{
	for_dht_check();
	full_set_check();
	no_creds_check();
	gen_check();
	offer_check();
	v2_compat_check();
	printf("candpack_test: all checks passed\n");
	return 0;
}
