/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The storing side of bep44.c, driven the way the network drives it: crafted
 * datagrams into bep44_input(), replies read back off a real socket. Nothing
 * here reaches into the engine's internals, so the test asserts the behaviour
 * a peer sees rather than the shape of the implementation.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wsock.h"

#include "bencode.h"
#include "bep44.h"
#include "ccrypto.h"
#include "sha1.h"

#define V_RAW "12:Hello World!"
#define V_LEN 15

static struct bep44_engine *e;
static uint8_t g_myid[20];
static sock_t s_node, s_peer;
static struct sockaddr_in peer_addr;
static uint8_t pk[32], sk[64];
static uint8_t last[2048];
static size_t last_len;

/*
 * The serving path drops martian sources (loopback among them), so this test
 * has to speak from a routable address; discover one the way a node would,
 * without sending anything, and SKIP (exit 77) if the host has only loopback.
 */
static uint32_t routable_addr(void)
{
	struct sockaddr_in probe, self;
	socklen_t len = sizeof(self);
	sock_t s = socket(AF_INET, SOCK_DGRAM, 0);
	uint32_t addr = 0;

	if (!sock_valid(s))
		return 0;
	memset(&probe, 0, sizeof(probe));
	probe.sin_family = AF_INET;
	probe.sin_port = htons(53);
	probe.sin_addr.s_addr = htonl(0xc0000201);	/* 192.0.2.1 */
	if (!connect(s, (struct sockaddr *)&probe, sizeof(probe)) &&
	    !getsockname(s, (struct sockaddr *)&self, &len))
		addr = self.sin_addr.s_addr;
	sock_close(s);
	if ((ntohl(addr) >> 24) == 127 || addr == 0)
		return 0;
	return addr;
}

static sock_t bind_addr(struct sockaddr_in *out, uint32_t addr)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	sock_t s = socket(AF_INET, SOCK_DGRAM, 0);

	assert(sock_valid(s));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	assert(!bind(s, (struct sockaddr *)&sin, sizeof(sin)));
	assert(!getsockname(s, (struct sockaddr *)&sin, &len));
	if (out)
		*out = sin;
	return s;
}

/* Feed one datagram and collect whatever the node sends back. */
static int deliver(const uint8_t *msg, size_t len)
{
	struct pollfd fd;
	int consumed;

	last_len = 0;
	consumed = bep44_input(e, msg, len, (struct sockaddr *)&peer_addr,
			       sizeof(peer_addr));
	fd.fd = s_peer;
	fd.events = POLLIN;
	if (sock_poll(&fd, 1, 50) > 0) {
		ssize_t n = recv(s_peer, (char *)last, sizeof(last), 0);

		if (n > 0)
			last_len = (size_t)n;
	}
	return consumed;
}

static int feed_str(const char *msg)
{
	return deliver((const uint8_t *)msg, strlen(msg));
}

static int reply_is(const char *kind)
{
	const uint8_t *v, *d;
	size_t vlen, dlen;

	if (!last_len || benc_dict_find(last, last_len, "y", &v, &vlen) ||
	    benc_str_get(v, vlen, &d, &dlen) || dlen != 1)
		return 0;
	return d[0] == kind[0];
}

static int64_t reply_error_code(void)
{
	const uint8_t *v, *p, *end;
	size_t vlen;
	int64_t code = 0;

	if (!reply_is("e") || benc_dict_find(last, last_len, "e", &v, &vlen))
		return 0;
	p = v;
	end = v + vlen;
	assert(p < end && *p == 'l');
	p++;
	if (benc_int_get(p, (size_t)(end - p), &code))
		return 0;
	return code;
}

/* r-dict accessors */
static int reply_field(const char *key, const uint8_t **data, size_t *len)
{
	const uint8_t *r, *v;
	size_t rlen, vlen;

	if (!reply_is("r") || benc_dict_find(last, last_len, "r", &r, &rlen))
		return -1;
	if (benc_dict_find(r, rlen, key, &v, &vlen))
		return -1;
	*data = v;
	*len = vlen;
	return 0;
}

static int reply_str(const char *key, const uint8_t **data, size_t *len)
{
	const uint8_t *v;
	size_t vlen;

	if (reply_field(key, &v, &vlen))
		return -1;
	return benc_str_get(v, vlen, data, len);
}

static int reply_int(const char *key, int64_t *out)
{
	const uint8_t *v;
	size_t vlen;

	if (reply_field(key, &v, &vlen))
		return -1;
	return benc_int_get(v, vlen, out);
}

/* v is raw: compare the bencoded span byte for byte. */
static int reply_v_is(const char *want, size_t want_len)
{
	const uint8_t *v;
	size_t vlen;

	if (reply_field("v", &v, &vlen))
		return 0;
	return vlen == want_len && !memcmp(v, want, want_len);
}

static size_t q_get(uint8_t *buf, size_t cap, const uint8_t target[20],
		    const int64_t *seq, int want)
{
	struct benc_buf b;

	benc_buf_init(&b, buf, cap);
	benc_raw_add(&b, "d1:ad", 5);
	benc_key_add(&b, "id");
	benc_str_add(&b, "aaaaaaaaaaaaaaaaaaaa", 20);
	if (seq) {
		benc_key_add(&b, "seq");
		benc_int_add(&b, *seq);
	}
	benc_key_add(&b, "target");
	benc_str_add(&b, target, 20);
	if (want)
		benc_raw_add(&b, "4:wantl2:n42:n6e", 16);
	benc_raw_add(&b, "e1:q3:get1:t2:zz1:y1:qe", 23);
	assert(!b.err);
	return b.len;
}

/* A token is only good for the target it was issued for, so fetch one per
 * target the way a real client does: with a get. */
static void token_for(const uint8_t target[20], uint8_t tok[64],
		      size_t *tok_len)
{
	uint8_t buf[512];
	const uint8_t *t;
	size_t n = q_get(buf, sizeof(buf), target, NULL, 0), tlen;

	assert(deliver(buf, n) == 1);
	assert(!reply_str("token", &t, &tlen) && tlen && tlen <= 64);
	memcpy(tok, t, tlen);
	*tok_len = tlen;
}

/* The canonical signing buffer, with the salt carried by length so a NUL
 * inside it is just another byte: (4:salt S)3:seqiNe1:v V. */
static size_t sig_buffer(uint8_t *dst, size_t cap, const uint8_t *salt,
			 size_t salt_len, int64_t seq, const uint8_t *v,
			 size_t v_len)
{
	struct benc_buf b;

	benc_buf_init(&b, dst, cap);
	if (salt_len) {
		benc_raw_add(&b, "4:salt", 6);
		benc_str_add(&b, salt, salt_len);
	}
	benc_raw_add(&b, "3:seq", 5);
	benc_int_add(&b, seq);
	benc_raw_add(&b, "1:v", 3);
	benc_raw_add(&b, v, v_len);
	return b.err ? 0 : b.len;
}

struct put_spec {
	int mutable_put;
	const uint8_t *salt;
	size_t salt_len;
	int64_t seq;
	const int64_t *cas;
	const char *v;
	size_t v_len;
	int break_sig;
	const uint8_t *token;
	size_t token_len;
};

static size_t q_put(uint8_t *buf, size_t cap, const struct put_spec *s)
{
	uint8_t sigbuf[BEP44_MAX_VALUE + 128], sig[64];
	struct benc_buf b;
	size_t n;

	benc_buf_init(&b, buf, cap);
	benc_raw_add(&b, "d1:ad", 5);
	if (s->cas) {
		benc_key_add(&b, "cas");
		benc_int_add(&b, *s->cas);
	}
	benc_key_add(&b, "id");
	benc_str_add(&b, "aaaaaaaaaaaaaaaaaaaa", 20);
	if (s->mutable_put) {
		benc_key_add(&b, "k");
		benc_str_add(&b, pk, 32);
	}
	if (s->mutable_put && s->salt_len) {
		benc_key_add(&b, "salt");
		benc_str_add(&b, s->salt, s->salt_len);
	}
	if (s->mutable_put) {
		benc_key_add(&b, "seq");
		benc_int_add(&b, s->seq);
		n = sig_buffer(sigbuf, sizeof(sigbuf), s->salt, s->salt_len,
			       s->seq, (const uint8_t *)s->v, s->v_len);
		assert(n);
		assert(!cc_ed25519_sign(sig, sk, sigbuf, n));
		if (s->break_sig)
			sig[0] ^= 0xaa;
		benc_key_add(&b, "sig");
		benc_str_add(&b, sig, 64);
	}
	benc_key_add(&b, "token");
	benc_str_add(&b, s->token, s->token_len);
	benc_key_add(&b, "v");
	benc_raw_add(&b, s->v, s->v_len);
	benc_raw_add(&b, "e1:q3:put1:t2:zz1:y1:qe", 23);
	assert(!b.err);
	return b.len;
}

static void target_of(uint8_t target[20], const uint8_t *salt, size_t salt_len)
{
	struct cc_sha1_ctx ctx;

	cc_sha1_init(&ctx);
	cc_sha1_update(&ctx, pk, 32);
	if (salt_len)
		cc_sha1_update(&ctx, salt, salt_len);
	cc_sha1_final(&ctx, target);
}

static int put(const struct put_spec *spec)
{
	uint8_t buf[2048];

	return deliver(buf, q_put(buf, sizeof(buf), spec));
}

static void put_and_expect(const struct put_spec *in, int want_code)
{
	struct put_spec s = *in;
	uint8_t tok[64], target[20];
	size_t tok_len;

	if (s.mutable_put)
		target_of(target, s.salt, s.salt_len);
	else
		bep44_immutable_target(target, (const uint8_t *)s.v, s.v_len);
	if (!s.token) {
		token_for(target, tok, &tok_len);
		s.token = tok;
		s.token_len = tok_len;
	}
	assert(put(&s) == 1);
	if (want_code) {
		assert(reply_error_code() == want_code);
	} else {
		assert(reply_is("r"));
	}
}

static void serves(const uint8_t target[20], const char *v, size_t v_len)
{
	uint8_t buf[512];

	assert(deliver(buf, q_get(buf, sizeof(buf), target, NULL, 0)) == 1);
	assert(reply_v_is(v, v_len));
}

static int stored_value_present(const uint8_t target[20])
{
	uint8_t buf[512];
	const uint8_t *v;
	size_t vlen;

	if (deliver(buf, q_get(buf, sizeof(buf), target, NULL, 0)) != 1)
		return 0;
	return reply_field("v", &v, &vlen) == 0;
}

static void serves_nothing(const uint8_t target[20])
{
	uint8_t buf[512];
	const uint8_t *v;
	size_t vlen;

	assert(deliver(buf, q_get(buf, sizeof(buf), target, NULL, 0)) == 1);
	assert(reply_field("v", &v, &vlen));
}

static void immutable_check(void)
{
	struct put_spec s = { 0 };
	uint8_t target[20];
	const uint8_t *d;
	size_t dlen;

	s.v = V_RAW;
	s.v_len = V_LEN;
	bep44_immutable_target(target, (const uint8_t *)V_RAW, V_LEN);
	put_and_expect(&s, 0);
	serves(target, V_RAW, V_LEN);
	/* an immutable item carries no key or signature */
	assert(reply_str("k", &d, &dlen));
	assert(reply_str("sig", &d, &dlen));
	/* and stays visible to a get that carries seq, unlike libtorrent's */
	{
		uint8_t buf[512];
		int64_t seq = 0;

		assert(deliver(buf, q_get(buf, sizeof(buf), target, &seq, 0))
		       == 1);
		assert(reply_v_is(V_RAW, V_LEN));
	}
}

static void mutable_check(void)
{
	struct put_spec s = { 0 };
	uint8_t target[20];
	const uint8_t *d;
	size_t dlen;
	int64_t seq;

	s.mutable_put = 1;
	s.salt = (const uint8_t *)"foobar";
	s.salt_len = 6;
	s.seq = 1;
	s.v = V_RAW;
	s.v_len = V_LEN;
	target_of(target, s.salt, s.salt_len);
	put_and_expect(&s, 0);

	serves(target, V_RAW, V_LEN);
	assert(!reply_str("k", &d, &dlen) && dlen == 32 && !memcmp(d, pk, 32));
	assert(!reply_str("sig", &d, &dlen) && dlen == 64);
	assert(!reply_int("seq", &seq) && seq == 1);

	/* a broken signature is refused and changes nothing */
	s.seq = 2;
	s.v = "3:new";
	s.v_len = 5;
	s.break_sig = 1;
	put_and_expect(&s, 206);
	serves(target, V_RAW, V_LEN);
	s.break_sig = 0;

	/* a lower seq is refused */
	s.seq = 0;
	put_and_expect(&s, 302);
	serves(target, V_RAW, V_LEN);

	/* an equal seq with a different value is refused too */
	s.seq = 1;
	put_and_expect(&s, 302);
	serves(target, V_RAW, V_LEN);

	/* an equal seq with the SAME value is a republish, not a conflict */
	s.v = V_RAW;
	s.v_len = V_LEN;
	put_and_expect(&s, 0);
	serves(target, V_RAW, V_LEN);

	/* a higher seq replaces */
	s.seq = 2;
	s.v = "3:new";
	s.v_len = 5;
	put_and_expect(&s, 0);
	serves(target, "3:new", 5);
}

static void cas_check(void)
{
	struct put_spec s = { 0 };
	uint8_t target[20];
	int64_t cas;

	s.mutable_put = 1;
	s.salt = (const uint8_t *)"cas";
	s.salt_len = 3;
	s.seq = 5;
	s.v = "2:v1";
	s.v_len = 4;
	target_of(target, s.salt, s.salt_len);
	put_and_expect(&s, 0);

	/* the wrong expected seq is refused */
	s.seq = 6;
	s.v = "2:v2";
	cas = 4;
	s.cas = &cas;
	put_and_expect(&s, 301);
	serves(target, "2:v1", 4);

	/* a cas above 2^32 must not alias the stored seq by truncation */
	cas = (int64_t)1 << 32 | 5;
	put_and_expect(&s, 301);
	serves(target, "2:v1", 4);

	/* the right one goes through */
	cas = 5;
	put_and_expect(&s, 0);
	serves(target, "2:v2", 4);
}

static void limits_check(void)
{
	struct put_spec s = { 0 };
	static char big_v[1200];
	static uint8_t big_salt[65];
	uint8_t target[20], tok[64];
	size_t tok_len;

	memset(big_salt, 's', sizeof(big_salt));
	snprintf(big_v, sizeof(big_v), "1010:");
	memset(big_v + 5, 'x', 1010);

	s.mutable_put = 1;
	s.salt = (const uint8_t *)"lim";
	s.salt_len = 3;
	s.seq = 1;
	s.v = big_v;
	s.v_len = 1015;
	put_and_expect(&s, 205);

	s.v = V_RAW;
	s.v_len = V_LEN;
	s.salt = big_salt;
	s.salt_len = sizeof(big_salt);
	put_and_expect(&s, 207);

	/* a value of exactly 1000 bencoded bytes is inside the ceiling */
	{
		static char v1000[1001];

		snprintf(v1000, sizeof(v1000), "996:");
		memset(v1000 + 4, 'y', 996);
		s.salt = (const uint8_t *)"exact";
		s.salt_len = 5;
		s.v = v1000;
		s.v_len = 1000;
		target_of(target, s.salt, s.salt_len);
		put_and_expect(&s, 0);
		serves(target, v1000, 1000);
	}

	/* a forged token stores nothing */
	s.salt = (const uint8_t *)"forged";
	s.salt_len = 6;
	s.v = V_RAW;
	s.v_len = V_LEN;
	memset(tok, 0x11, sizeof(tok));
	tok_len = 8;
	s.token = tok;
	s.token_len = tok_len;
	target_of(target, s.salt, s.salt_len);
	put_and_expect(&s, 203);
	serves_nothing(target);
}

/* A salt is bytes, not text: NUL inside it must survive the round trip. */
static void binary_salt_check(void)
{
	struct put_spec s = { 0 };
	static const uint8_t salt[8] = { 'a', 0, 'b', 0xff, 0, 1, 2, 3 };
	uint8_t target[20];

	s.mutable_put = 1;
	s.salt = salt;
	s.salt_len = sizeof(salt);
	s.seq = 1;
	s.v = "3:bin";
	s.v_len = 5;
	target_of(target, salt, sizeof(salt));
	put_and_expect(&s, 0);
	serves(target, "3:bin", 5);
}

static void conditional_get_check(void)
{
	struct put_spec s = { 0 };
	uint8_t target[20], buf[512];
	const uint8_t *d;
	size_t dlen;
	int64_t seq, got;

	s.mutable_put = 1;
	s.salt = (const uint8_t *)"cond";
	s.salt_len = 4;
	s.seq = 7;
	s.v = "4:cond";
	s.v_len = 6;
	target_of(target, s.salt, s.salt_len);
	put_and_expect(&s, 0);

	/* asker already has seq 7: value withheld, seq still reported */
	seq = 7;
	assert(deliver(buf, q_get(buf, sizeof(buf), target, &seq, 0)) == 1);
	assert(reply_str("v", &d, &dlen));
	assert(reply_str("k", &d, &dlen));
	assert(reply_str("sig", &d, &dlen));
	assert(!reply_int("seq", &got) && got == 7);

	/* asker is behind: value due */
	seq = 6;
	assert(deliver(buf, q_get(buf, sizeof(buf), target, &seq, 0)) == 1);
	assert(reply_v_is("4:cond", 6));

	/* a negative seq is below every stored seq, so the value is due */
	seq = -1;
	assert(deliver(buf, q_get(buf, sizeof(buf), target, &seq, 0)) == 1);
	assert(reply_v_is("4:cond", 6));
}

static uint8_t *find_bytes(uint8_t *hay, size_t hay_len, const char *needle,
			   size_t needle_len)
{
	size_t i;

	for (i = 0; i + needle_len <= hay_len; i++) {
		if (!memcmp(hay + i, needle, needle_len))
			return hay + i;
	}
	return NULL;
}

static void malformed_check(void)
{
	uint8_t buf[2048];
	struct benc_buf b;
	uint8_t tok[64], target[20];
	size_t tok_len;

	/* a get with no target */
	assert(feed_str("d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q3:get1:t2:zz1:y1:qe")
	       == 1);
	assert(reply_error_code() == 203);

	/* a put with no arguments at all */
	assert(feed_str("d1:q3:put1:t2:aa1:y1:qe") == 1);
	assert(reply_error_code() == 203);

	/* a query we do not serve is left for the BEP 5 engine */
	assert(feed_str("d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:zz1:y1:qe")
	       == 0);

	/* k present but the wrong length: refused, and NOT demoted to an
	 * immutable store at sha1(v) behind the sender's back */
	target_of(target, (const uint8_t *)"bad", 3);
	token_for(target, tok, &tok_len);
	benc_buf_init(&b, buf, sizeof(buf));
	benc_raw_add(&b, "d1:ad", 5);
	benc_key_add(&b, "id");
	benc_str_add(&b, "aaaaaaaaaaaaaaaaaaaa", 20);
	benc_key_add(&b, "k");
	benc_str_add(&b, pk, 31);
	benc_key_add(&b, "salt");
	benc_str_add(&b, "bad", 3);
	benc_key_add(&b, "seq");
	benc_int_add(&b, 1);
	benc_key_add(&b, "sig");
	benc_str_add(&b, "0123456789012345678901234567890123456789"
			 "012345678901234567890123", 64);
	benc_key_add(&b, "token");
	benc_str_add(&b, tok, tok_len);
	benc_key_add(&b, "v");
	benc_raw_add(&b, V_RAW, V_LEN);
	benc_raw_add(&b, "e1:q3:put1:t2:zz1:y1:qe", 23);
	assert(!b.err);
	assert(deliver(buf, b.len) == 1);
	assert(reply_error_code() == 203);
	serves_nothing(target);
	bep44_immutable_target(target, (const uint8_t *)V_RAW, V_LEN);
	/* immutable_check stored exactly this value already, so the check is
	 * that it is unchanged rather than that nothing is there */
	serves(target, V_RAW, V_LEN);

	/* a non-canonical integer in a put: the signature covers exact bytes,
	 * so it must not be stored */
	{
		struct put_spec s = { 0 };
		size_t n;
		uint8_t *at;

		s.mutable_put = 1;
		s.salt = (const uint8_t *)"nc";
		s.salt_len = 2;
		s.seq = 1;
		s.v = V_RAW;
		s.v_len = V_LEN;
		target_of(target, s.salt, s.salt_len);
		token_for(target, tok, &tok_len);
		s.token = tok;
		s.token_len = tok_len;
		n = q_put(buf, sizeof(buf), &s);
		at = find_bytes(buf, n, "3:seqi1e", 8);
		assert(at);
		memmove(at + 8, at + 7, n - (size_t)(at + 7 - buf));
		memcpy(at, "3:seqi01e", 9);
		n++;
		assert(deliver(buf, n) == 1);
		assert(reply_error_code() == 203);
		serves_nothing(target);
	}
}

/* A get miss on a node that has learned no nodes hands back id and token but no
 * stale or invented referral. The referral cache is fed only from this node's
 * own lookups (a put's claimed id is never trusted), and this test does none,
 * so the cache is honestly empty. */
static void referral_empty_check(void)
{
	uint8_t buf[512], target[20];
	const uint8_t *d;
	size_t dlen;

	memset(target, 0x42, sizeof(target));
	assert(deliver(buf, q_get(buf, sizeof(buf), target, NULL, 1)) == 1);
	assert(reply_is("r"));
	assert(!reply_str("token", &d, &dlen));
	assert(reply_str("nodes", &d, &dlen));	/* no nodes learned -> none served */
}

/* A martian source (loopback here) is dropped, not served: the datagram is
 * consumed so it never reaches the BEP 5 engine, and no reply is emitted. */
static void martian_check(void)
{
	struct sockaddr_in loop;
	uint8_t buf[512], target[20];

	memset(&loop, 0, sizeof(loop));
	loop.sin_family = AF_INET;
	loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	loop.sin_port = htons(9999);
	memset(target, 0x24, sizeof(target));
	last_len = 0;
	assert(bep44_input(e, buf, q_get(buf, sizeof(buf), target, NULL, 0),
			   (struct sockaddr *)&loop, sizeof(loop)) == 1);
	{
		struct pollfd fd = { .fd = s_peer, .events = POLLIN };

		assert(sock_poll(&fd, 1, 100) == 0);	/* nothing sent back */
	}
}

/*
 * A distant flood must not evict a nearby item. Plant one item whose target is
 * genuinely close to our id (grind an immutable value until sha1(v) shares our
 * id's top bits), flood the store past full with items at random distance, and
 * confirm the near item is still served: eviction takes the furthest, so the
 * nearest never goes.
 */
static void admission_check(void)
{
	struct put_spec s = { 0 };
	uint8_t near_target[20], tok[64], near_v[40], buf[600];
	size_t tok_len, near_len = 0;
	char salt[24];
	uint32_t n;
	int i;

	/* find v with sha1(v) matching our id in the top 16 bits */
	for (n = 0; n < 1000000; n++) {
		char body[16];
		int bl = snprintf(body, sizeof(body), "near%u", n);
		struct benc_buf vb;

		benc_buf_init(&vb, near_v, sizeof(near_v));
		benc_str_add(&vb, body, (size_t)bl);
		assert(!vb.err);
		bep44_immutable_target(near_target, near_v, vb.len);
		if (near_target[0] == g_myid[0] && near_target[1] == g_myid[1]) {
			near_len = vb.len;
			break;
		}
	}
	assert(near_len);
	token_for(near_target, tok, &tok_len);
	{
		struct benc_buf b;

		benc_buf_init(&b, buf, sizeof(buf));
		benc_raw_add(&b, "d1:ad", 5);
		benc_key_add(&b, "id");
		benc_str_add(&b, "aaaaaaaaaaaaaaaaaaaa", 20);
		benc_key_add(&b, "token");
		benc_str_add(&b, tok, tok_len);
		benc_key_add(&b, "v");
		benc_raw_add(&b, near_v, near_len);
		benc_raw_add(&b, "e1:q3:put1:t2:zz1:y1:qe", 23);
		assert(!b.err);
		assert(deliver(buf, b.len) == 1 && reply_is("r"));
	}
	assert(stored_value_present(near_target));

	/* flood well past the 256-item store with distinct far-ish items */
	s.mutable_put = 1;
	s.seq = 1;
	s.v = V_RAW;
	s.v_len = V_LEN;
	for (i = 0; i < 400; i++) {
		snprintf(salt, sizeof(salt), "fill-%d", i);
		s.salt = (const uint8_t *)salt;
		s.salt_len = strlen(salt);
		put_and_expect(&s, 0);		/* always acked */
		if (i % 100 == 99)
			sleep(1);		/* let the token bucket refill */
	}
	/* the near item, closest of all, is untouched */
	assert(stored_value_present(near_target));
}

/* The token-bucket limiter drops served queries past the burst, and refills
 * over time; a genuine node under the limit is unaffected. */
static void rate_limit_check(void)
{
	uint8_t buf[512], target[20];
	int replies = 0, i;

	memset(target, 0x77, sizeof(target));
	/* Fire well past the burst in a tight loop (no time passes, so no
	 * refill): some are answered, then the bucket empties and the rest are
	 * dropped. */
	for (i = 0; i < 4000; i++) {
		last_len = 0;
		bep44_input(e, buf, q_get(buf, sizeof(buf), target, NULL, 0),
			    (struct sockaddr *)&peer_addr, sizeof(peer_addr));
		{
			struct pollfd fd = { .fd = s_peer, .events = POLLIN };

			while (sock_poll(&fd, 1, 0) > 0) {
				char junk[2048];

				if (recv(s_peer, junk, sizeof(junk), 0) > 0)
					replies++;
			}
		}
	}
	/* far below 4000: the bucket bounded it */
	assert(replies > 0 && replies < 2000);
}

/*
 * A put carrying a degenerate public key (here the Ed25519 identity point) must
 * be rejected, not verified into a crash. On the gcrypt backend libgcrypt's
 * verifier aborts on such a key unless it is screened first; on every backend
 * a signature that is not the trivial low-order forgery fails to verify.
 */
static void low_order_key_check(void)
{
	uint8_t buf[600], target[20], tok[64], idk[32];
	struct cc_sha1_ctx ctx;
	struct benc_buf b;
	size_t tok_len;

	memset(idk, 0, 32);
	idk[0] = 1;				/* identity point */
	cc_sha1_init(&ctx);
	cc_sha1_update(&ctx, idk, 32);
	cc_sha1_update(&ctx, "lo", 2);
	cc_sha1_final(&ctx, target);
	token_for(target, tok, &tok_len);

	benc_buf_init(&b, buf, sizeof(buf));
	benc_raw_add(&b, "d1:ad", 5);
	benc_key_add(&b, "id");
	benc_str_add(&b, "aaaaaaaaaaaaaaaaaaaa", 20);
	benc_key_add(&b, "k");
	benc_str_add(&b, idk, 32);
	benc_key_add(&b, "salt");
	benc_str_add(&b, "lo", 2);
	benc_key_add(&b, "seq");
	benc_int_add(&b, 1);
	benc_key_add(&b, "sig");
	{
		uint8_t sig[64];

		memset(sig, 0xab, 64);		/* not the trivial forgery */
		benc_str_add(&b, sig, 64);
	}
	benc_key_add(&b, "token");
	benc_str_add(&b, tok, tok_len);
	benc_key_add(&b, "v");
	benc_raw_add(&b, V_RAW, V_LEN);
	benc_raw_add(&b, "e1:q3:put1:t2:zz1:y1:qe", 23);
	assert(!b.err);
	assert(deliver(buf, b.len) == 1);
	assert(reply_error_code() == 206);	/* rejected, no abort */
	serves_nothing(target);
}

static void serving_off_check(void)
{
	uint8_t buf[512], target[20];

	memset(target, 0x11, sizeof(target));
	assert(!bep44_serve(e, 0));
	/* with serving off nothing is claimed, so the caller can hand every
	 * packet to its BEP 5 engine as before */
	assert(deliver(buf, q_get(buf, sizeof(buf), target, NULL, 0)) == 0);
	assert(!last_len);
	assert(!bep44_serve(e, 1));
}

int main(void)
{
	uint8_t myid[20], seed[32];
	size_t i;

	for (i = 0; i < sizeof(myid); i++)
		myid[i] = (uint8_t)(i * 5 + 3);
	memcpy(g_myid, myid, sizeof(myid));
	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)(i + 1);
	assert(!cc_ed25519_key_pair(sk, pk, seed));

	{
		uint32_t addr = routable_addr();

		if (!addr) {
			fprintf(stderr, "no routable address; skipping\n");
			return 77;	/* CMake SKIP_RETURN_CODE */
		}
		s_node = bind_addr(NULL, addr);
		s_peer = bind_addr(&peer_addr, addr);
	}

	e = bep44_create(myid, s_node, INVALID_SOCK);
	assert(e);
	assert(!bep44_serve(e, 1));

	immutable_check();
	mutable_check();
	cas_check();
	limits_check();
	binary_salt_check();
	conditional_get_check();
	malformed_check();
	referral_empty_check();
	martian_check();
	admission_check();
	low_order_key_check();
	rate_limit_check();
	serving_off_check();

	bep44_free(e);
	return 0;
}
