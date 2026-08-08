/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bencode.h"
#include "bep44.h"
#include "candpack.h"
#include "dhtnode.h"
#include "keys.h"
#include "sig.h"
#include "sig_mcast.h"

#define SIG_SALT "m"			/* the one shared mailbox */
#define SIG_SEALED_MAX (SIG_MAX_VALUE + SEAL_OVERHEAD)
#define SIG_SDP_MAX 4096		/* raw ICE description in/out of candpack */
#define SIG_DHT_GET_MS 1000
#define SIG_DHT_PUT_MS 1500
#define SIG_DHT_RESTORE_MS 8000		/* re-store backoff while a store's
					 * k-close nodes are being validated */
#define SIG_MCAST_ANN_MS 1000
#define SIG_DHT_GRACE_MS 2000

struct sig {
	unsigned flags;
	struct session_keys keys;
	uint64_t start_ms;
	int is_host;			/* our slot: 'o' (host) or 'a' (client) */

	int dht_engaged;
	struct dhtnode *node;
	struct bep44_engine *engine;

	struct sig_mcast *mc;
	int mcast_delivered;

	uint8_t mine[SIG_SEALED_MAX];	/* our slot value, sealed (DHT) */
	size_t mine_len;
	uint8_t mcast_mine[SIG_SEALED_MAX];	/* our announcement, sealed (mcast) */
	size_t mcast_mine_len;
	int have_mine;

	/* Last-seen container: each slot's sealed bytes (len 0 = absent). */
	uint8_t slot_o[SIG_SEALED_MAX];
	size_t slot_o_len;
	uint8_t slot_a[SIG_SEALED_MAX];
	size_t slot_a_len;
	int64_t cur_seq;
	int have_cur;
	int need_write;

	sig_recv_cb *cb;
	void *arg;
	uint8_t last_peer[SIG_MAX_VALUE];
	size_t last_peer_len;
	int have_last;

	int locate;
	int put_inflight;		/* a convergent host store is running */
	struct sockaddr_storage rnode;
	socklen_t rnode_len;

	uint64_t next_get_ms;
	uint64_t next_put_ms;
	uint64_t next_mcast_ms;
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static char my_slot(const struct sig *s)
{
	return s->is_host ? 'o' : 'a';
}

static char peer_slot(const struct sig *s)
{
	return s->is_host ? 'a' : 'o';
}

static int engage_dht(struct sig *s)
{
	s->node = dhtnode_create();
	if (!s->node)
		return -1;
	s->engine = dhtnode_engine(s->node);
	s->dht_engaged = 1;
	return 0;
}

struct sig *sig_create(const uint8_t rdv[TOKEN_RDV_LEN], unsigned flags,
		       int is_host)
{
	struct sig *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	keys_derive(&s->keys, rdv);
	s->flags = flags;
	s->is_host = is_host;
	s->start_ms = now_ms();

	if (flags & SIG_MCAST) {
		s->mc = sig_mcast_open();
		if (!s->mc)
			s->flags &= ~SIG_MCAST;
	}
	if ((s->flags & SIG_DHT) && !(s->flags & SIG_MCAST)) {
		if (engage_dht(s)) {
			sig_destroy(s);
			return NULL;
		}
	}
	if (!(s->flags & (SIG_DHT | SIG_MCAST))) {
		sig_destroy(s);
		return NULL;
	}
	return s;
}

void sig_destroy(struct sig *s)
{
	if (!s)
		return;
	if (s->node)
		dhtnode_free(s->node);
	if (s->mc)
		sig_mcast_close(s->mc);
	free(s);
}

int sig_prepare(struct sig *s, struct pollfd *fds, int maxfds, int *timeout_ms)
{
	int nfds = 0, t;

	if (s->dht_engaged)
		nfds += dhtnode_prepare(s->node, fds + nfds, maxfds - nfds, &t);
	if (s->mc)
		nfds += sig_mcast_prepare(s->mc, fds + nfds, maxfds - nfds);
	*timeout_ms = 100;
	return nfds;
}

int sig_ready(struct sig *s)
{
	if (s->mc)
		return 1;
	return s->dht_engaged && dhtnode_ready(s->node);
}

int sig_post(struct sig *s, const uint8_t *data, size_t len)
{
	char sdp[SIG_SDP_MAX];
	uint8_t packed[SIG_MAX_VALUE];
	int plen, slen;

	/* Pack for the DHT slot: global and shared-private (nested-NAT) reachable
	 * candidates, dropping only what cannot help off our own L2 segment. */
	if (len >= sizeof(sdp))
		return -1;
	memcpy(sdp, data, len);
	sdp[len] = '\0';
	plen = candpack_encode(sdp, 1, packed, sizeof(packed));
	if (plen <= 0)
		return -1;
	slen = msg_seal(s->mine, sizeof(s->mine), s->keys.sig_key, packed,
			(size_t)plen);
	if (slen < 0)
		return -1;
	s->mine_len = (size_t)slen;

	/* The multicast announcement carries only our credentials and port; the
	 * peer reads our address from the packet source on the shared segment. */
	plen = candpack_announce_encode(sdp, packed, sizeof(packed));
	if (plen > 0) {
		slen = msg_seal(s->mcast_mine, sizeof(s->mcast_mine),
				s->keys.sig_key, packed, (size_t)plen);
		if (slen > 0)
			s->mcast_mine_len = (size_t)slen;
	}

	s->have_mine = 1;
	s->need_write = 1;
	s->next_put_ms = 0;
	s->next_mcast_ms = 0;
	return 0;
}

int sig_subscribe(struct sig *s, sig_recv_cb *cb, void *arg)
{
	s->cb = cb;
	s->arg = arg;
	return 0;
}

int sig_seed_node(struct sig *s, const struct sockaddr *sa, socklen_t len)
{
	if (!s->dht_engaged && engage_dht(s))
		return -1;
	return bep44_pin_add(s->engine, NULL, sa, len);
}

int sig_locate(struct sig *s)
{
	if (!s->dht_engaged && engage_dht(s))
		return -1;
	s->locate = 1;
	return 0;
}

int sig_located(struct sig *s, struct sockaddr *out, socklen_t *out_len)
{
	if (!s->locate || !s->rnode_len || *out_len < s->rnode_len)
		return 0;
	memcpy(out, &s->rnode, s->rnode_len);
	*out_len = s->rnode_len;
	return 1;
}

/* Open the peer's sealed slot and deliver it once, de-duplicated. */
static void deliver_peer(struct sig *s, const uint8_t *sealed, size_t len)
{
	uint8_t plain[SIG_MAX_VALUE];
	char sdp[SIG_SDP_MAX];
	int n = msg_open(plain, sizeof(plain), s->keys.sig_key, sealed, len);
	int slen;

	if (n < 0)
		return;
	if (s->have_last && s->last_peer_len == (size_t)n &&
	    !memcmp(s->last_peer, plain, (size_t)n))
		return;
	memcpy(s->last_peer, plain, (size_t)n);
	s->last_peer_len = (size_t)n;
	s->have_last = 1;
	slen = candpack_decode(plain, (size_t)n, sdp, sizeof(sdp));
	if (slen < 0)
		return;
	if (s->cb)
		s->cb(s->arg, (const uint8_t *)sdp, (size_t)slen);
}

static size_t peer_sealed(struct sig *s, const uint8_t **out)
{
	if (s->is_host) {
		*out = s->slot_a;
		return s->slot_a_len;
	}
	*out = s->slot_o;
	return s->slot_o_len;
}

/* Pull one slot's sealed string out of the container into dst. */
static size_t slot_extract(const uint8_t *v, size_t v_len, const char *key,
			   uint8_t *dst, size_t dst_max)
{
	const uint8_t *val, *str;
	size_t val_len, str_len;

	if (benc_dict_find(v, v_len, key, &val, &val_len) ||
	    benc_str_get(val, val_len, &str, &str_len) || str_len > dst_max)
		return 0;
	memcpy(dst, str, str_len);
	return str_len;
}

static void container_parse(struct sig *s, const uint8_t *v, size_t v_len)
{
	s->slot_o_len = slot_extract(v, v_len, "o", s->slot_o, sizeof(s->slot_o));
	s->slot_a_len = slot_extract(v, v_len, "a", s->slot_a, sizeof(s->slot_a));
}

/* We must (re)write when our slot in the container does not match ours. */
static void recompute_need_write(struct sig *s)
{
	const uint8_t *cur = s->is_host ? s->slot_o : s->slot_a;
	size_t cur_len = s->is_host ? s->slot_o_len : s->slot_a_len;

	if (!s->have_mine)
		s->need_write = 0;
	else
		s->need_write = (cur_len != s->mine_len ||
				 memcmp(cur, s->mine, s->mine_len)) ? 1 : 0;
}

/* Build the merged container: our slot plus the peer's, if known. */
static size_t container_build(struct sig *s, uint8_t *out, size_t outlen)
{
	struct benc_buf b;
	const uint8_t *pa = NULL, *po = NULL;
	size_t la = 0, lo = 0;

	if (s->is_host) {
		po = s->mine;
		lo = s->mine_len;
		pa = s->slot_a;
		la = s->slot_a_len;
	} else {
		pa = s->mine;
		la = s->mine_len;
		po = s->slot_o;
		lo = s->slot_o_len;
	}

	benc_buf_init(&b, out, outlen);
	benc_raw_add(&b, "d", 1);
	if (la) {
		benc_key_add(&b, "a");
		benc_str_add(&b, pa, la);
	}
	if (lo) {
		benc_key_add(&b, "o");
		benc_str_add(&b, po, lo);
	}
	benc_raw_add(&b, "e", 1);
	return b.err ? 0 : b.len;
}

static void on_dht_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq,
		       const struct sockaddr *node, socklen_t node_len)
{
	struct sig *s = arg;
	const uint8_t *peer;
	size_t peer_len;

	if (!v)
		return;
	container_parse(s, v, v_len);
	s->cur_seq = seq;
	s->have_cur = 1;
	recompute_need_write(s);

	peer_len = peer_sealed(s, &peer);
	if (peer_len)
		deliver_peer(s, peer, peer_len);

	/*
	 * The value is signature-checked as ours, so the node that served it is
	 * a validated, responsive, k-close rendezvous point. Keep the first
	 * (fastest) and pin it: it goes in the token, and from now the host
	 * reads the client's reply straight from it, no convergence.
	 */
	if (s->locate && !s->rnode_len && node && node_len &&
	    (size_t)node_len <= sizeof(s->rnode)) {
		memcpy(&s->rnode, node, node_len);
		s->rnode_len = node_len;
		bep44_pin_add(s->engine, NULL, node, node_len);
	}
}

/*
 * Open a multicast announcement and deliver the peer's description, its one
 * host candidate reconstructed from the packet source. Re-announcements repeat
 * the same candidate; libjuice de-duplicates it, so no dedup is needed here.
 */
static void deliver_peer_mcast(struct sig *s, const uint8_t *sealed, size_t len,
			       const struct sockaddr *src, socklen_t srclen)
{
	uint8_t plain[SIG_MAX_VALUE];
	char sdp[SIG_SDP_MAX];
	int n = msg_open(plain, sizeof(plain), s->keys.sig_key, sealed, len);
	int slen;

	if (n < 0)
		return;
	slen = candpack_announce_decode(plain, (size_t)n, src, srclen, sdp,
					sizeof(sdp));
	if (slen < 0)
		return;
	if (s->cb)
		s->cb(s->arg, (const uint8_t *)sdp, (size_t)slen);
}

static void on_mcast_recv(void *arg, const char *salt, const uint8_t *data,
			  size_t len, const struct sockaddr *src,
			  socklen_t srclen)
{
	struct sig *s = arg;
	char ps[2];

	ps[0] = peer_slot(s);
	ps[1] = '\0';
	if (!strcmp(salt, ps)) {
		deliver_peer_mcast(s, data, len, src, srclen);
		s->mcast_delivered = 1;
	}
}

/* Merge our slot into the value just read, preserving the peer's slot. */
static int mailbox_merge(void *arg, const uint8_t *cur, size_t cur_len,
			 uint8_t *out, size_t *out_len, size_t max)
{
	struct sig *s = arg;
	size_t n;

	if (cur)
		container_parse(s, cur, cur_len);
	n = container_build(s, out, max);
	if (!n)
		return -1;
	*out_len = n;
	return 0;
}

/*
 * The convergent store finished (on the k-closest nodes). It does not pick the
 * rendezvous node: a store acknowledgement does not prove a node will serve the
 * value back, and the closest-stored node need not be closest to the key. The
 * rendezvous node is chosen by the validating GET that follows (on_dht_get),
 * which proves a k-close node both holds the value and answers.
 */
static void on_host_put(void *arg, int stored, const struct sockaddr *node,
			socklen_t node_len)
{
	struct sig *s = arg;

	(void)node;
	(void)node_len;
	s->put_inflight = 0;
	/* Only a store that found a home earns the wide window for the
	 * validating gets to pick the rendezvous node; one that stored nowhere
	 * retries at the normal cadence. */
	if (stored > 0)
		s->next_put_ms = now_ms() + SIG_DHT_RESTORE_MS;
}

static void dht_pump(struct sig *s, uint64_t now)
{
	if (!dhtnode_ready(s->node))
		return;
	if (now >= s->next_get_ms) {
		/*
		 * Read directly from the shared rendezvous node: the host from
		 * the nodes it stored to, the client from the token's pinned
		 * node. No convergence -- the host paid that once, up front.
		 */
		bep44_get_direct(s->engine, s->keys.bep44_pk, SIG_SALT,
				 on_dht_get, s);
		s->next_get_ms = now + SIG_DHT_GET_MS;
	}
	if (now < s->next_put_ms)
		return;
	if (s->is_host) {
		/*
		 * One convergent store places the mailbox on the k-closest
		 * nodes (idiomatic and discoverable) and yields the rendezvous
		 * node for the token. It runs once, until that node is captured.
		 */
		if (s->have_mine && !s->rnode_len && !s->put_inflight) {
			s->put_inflight = 1;
			bep44_update(s->engine, s->keys.bep44_sk,
				     s->keys.bep44_pk, SIG_SALT, mailbox_merge,
				     s, on_host_put, s);
			s->next_put_ms = now + SIG_DHT_PUT_MS;
		}
	} else if (s->have_mine && s->need_write && s->have_cur) {
		/*
		 * The client has read the host's offer; it writes its answer
		 * straight to the pinned rendezvous node -- a round-trip, not a
		 * lookup -- so it never clobbers the offer and never converges.
		 */
		bep44_update_direct(s->engine, s->keys.bep44_sk,
				    s->keys.bep44_pk, SIG_SALT, mailbox_merge,
				    s, NULL, NULL);
		s->next_put_ms = now + SIG_DHT_PUT_MS;
	}
}

static void mcast_pump(struct sig *s, uint64_t now)
{
	char ms[2];

	if (!s->have_mine || !s->mcast_mine_len || now < s->next_mcast_ms)
		return;
	ms[0] = my_slot(s);
	ms[1] = '\0';
	sig_mcast_send(s->mc, ms, s->mcast_mine, s->mcast_mine_len);
	s->next_mcast_ms = now + SIG_MCAST_ANN_MS;
}

void sig_dispatch(struct sig *s, const struct pollfd *fds, int nfds)
{
	uint64_t now = now_ms();

	if (s->mc) {
		sig_mcast_dispatch(s->mc, fds, nfds, on_mcast_recv, s);
		mcast_pump(s, now);
	}

	/*
	 * With no multicast in play there is nothing on the link to wait for,
	 * so engage the DHT at once; only a combined session gives the link a
	 * brief grace to answer before falling back to the DHT.
	 */
	if ((s->flags & SIG_DHT) && !s->dht_engaged && !s->mcast_delivered &&
	    (!(s->flags & SIG_MCAST) || now - s->start_ms > SIG_DHT_GRACE_MS))
		engage_dht(s);

	if (s->dht_engaged) {
		dhtnode_dispatch(s->node, fds, nfds);
		dht_pump(s, now);
	}
}
