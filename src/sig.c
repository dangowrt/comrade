/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bep44.h"
#include "dbg.h"
#include "candpack.h"
#include "ccrypto.h"
#include "dhtnode.h"
#include "keys.h"
#include "mailbox.h"
#include "sig.h"
#include "sig_mcast.h"

#define SIG_SALT "m"			/* the one shared mailbox */
#define SIG_SEALED_MAX (SIG_MAX_VALUE + SEAL_OVERHEAD)
/* the mcast value prepends a 2-byte direct-transport port to the candpack */
#define SIG_MCAST_SEALED_MAX (2 + SIG_MAX_VALUE + SEAL_OVERHEAD)
#define SIG_SDP_MAX 4096		/* raw ICE description in/out of candpack */
#define SIG_DHT_GET_MS 1000
#define SIG_DHT_PUT_MS 1000		/* re-run the convergent store/gather this
					 * often while locating, so the slower v6
					 * DHT gets more attempts inside the window */
#define SIG_DHT_RESTORE_MS 8000		/* re-store backoff while a store's
					 * k-close nodes are being validated */
#define SIG_MCAST_ANN_MS 1000
#define SIG_MCAST_OPEN_MS 1000		/* retry the link-local half this often
					 * while no interface can carry it */
#define SIG_DHT_GRACE_MS 2000
#define SIG_DHT_OPEN_MS 1000		/* retry the DHT half this often while a
					 * node cannot be created */
/*
 * The convergent fallback, on both ends.
 *
 * A rendezvous node in a token is an accelerator, not the only way in: it
 * turns meeting into one round trip instead of a lookup. A token that names
 * none of them -- minted before the host had found any -- or names one that
 * has since gone must still work, or the invite someone copied an hour ago is
 * worthless. So the mailbox is also reached the ordinary way, by converging on
 * the key, whenever the direct route has not produced the peer.
 *
 * Both ends need it. A client that finds the value this way writes its answer
 * to the nodes that served it, and those are only read back if the host also
 * looks past the handful it pinned.
 */
/* Reads older than the one we hold, before we believe the item restarted. */
#define SIG_SEQ_REGRESS_MAX 3

#define SIG_DHT_WIDE_GET_MS 4000	/* while the peer's slot is still unseen */
#define SIG_DHT_WIDE_IDLE_MS 20000	/* once it has been, as a safety net */
#define SIG_DHT_WIDE_PUT_MS 45000	/* keep the value on whoever is closest
					 * now, not only where it first landed */

#define SIG_DHT_PUT_SLOW_MS 20000	/* a still-missing family with no proven
					 * connectivity yet is retried at this
					 * slower pace instead of not at all --
					 * see sig_set_family_up. */

struct sig {
	unsigned flags;
	struct session_keys keys;
	uint64_t start_ms;
	int is_host;			/* our slot: 'o' (host) or 'a' (client) */

	int dht_engaged;
	struct dhtnode *node;
	struct bep44_engine *engine;

	struct sig_mcast *mc;
	int mcast_claims;		/* host demultiplexes lanlink itself, so a
					 * mcast claimant is a direct claim, not an
					 * ICE offer for the turnstile */

	struct mailbox mb;		/* the two-slot rendezvous container */
	uint8_t mcast_mine[SIG_MCAST_SEALED_MAX];	/* our announcement, sealed (mcast) */
	size_t mcast_mine_len;
	int64_t cur_seq;

	sig_recv_cb *cb;
	void *arg;
	uint16_t direct_port;		/* our direct-transport port, announced */
	sig_direct_cb *direct_cb;	/* fires on a link-local announcement */
	void *direct_arg;
	uint8_t last_peer[SIG_MAX_VALUE];
	size_t last_peer_len;
	int have_last;
	/*
	 * A claim names where a peer is, and every holder of the invitation can
	 * read the mailbox -- a read-only link handed to a room is a crowd with
	 * no reason to trust each other. So the host publishes a key in its own
	 * slot and holds the secret half alone, and a claim is boxed to it
	 * inside the seal the slot already carries: the seal still says a token
	 * holder wrote it, the box says only the host may read it.
	 *
	 * The claimant's ufrag rides in the clear beside the box, because the
	 * turnstile rule that lets a client overwrite its own superseded claim
	 * is about identity, not about where that claimant is.
	 */
	uint8_t claim_sk[32];		/* host: the half nobody else has */
	uint8_t claim_pk[32];
	uint8_t peer_claim_pk[32];	/* client: taken from the host's slot */
	int have_peer_claim_pk;
	uint8_t my_packed[SIG_MAX_VALUE];	/* staged before it can be boxed */
	size_t my_packed_len;
	char my_ufrag[64];		/* our claim's ICE ufrag: recognises our
					 * own (possibly superseded) answer in
					 * the slot, see mailbox_note_own_answer */

	int locate;
	int put_inflight;		/* a convergent host store is running */
	struct sockaddr_storage rnode4;	/* rendezvous node per family: captured */
	socklen_t rnode4_len;		/* independently as each family's DHT */
	struct sockaddr_storage rnode6;	/* serves the value back */
	socklen_t rnode6_len;
	int acked4, acked6;		/* a validated get had a node of this
					 * family serve our own value back */
	/*
	 * The node that served the last validated get, per family, waiting to be
	 * read. Who answered is what says whether the rendezvous we hold is
	 * still the rendezvous, so it is reported rather than acted on here:
	 * keeping or replacing an anchor is a decision about the network we are
	 * on, and that is not this module's to make.
	 */
	struct sockaddr_storage ack_node4, ack_node6;
	socklen_t ack_node4_len, ack_node6_len;
	int ack_new4, ack_new6;
	int relocate4, relocate6;	/* search for a replacement, while still
					 * serving the one we hold */
	int relay4, relay6;		/* client: asked to establish a
					 * rendezvous the peer cannot reach */
	int up4, up6;			/* proven connectivity, see sig_set_family_up */
	int seq_regress;		/* consecutive reads older than what we hold */
	int gets_ok;			/* validated reads of the container */
	int puts_ok;			/* stores that found a home */
	uint64_t last_get_ms;		/* when either last happened, 0 = never */
	uint64_t last_put_ms;
	uint64_t next_wide_get_ms;
	uint64_t next_wide_put_ms;
	int anchor_seen4, anchor_seen6;	/* the node we hold answered a get since
					 * this was last taken; sticky, because
					 * another holder answering after it must
					 * not erase that it did */
	uint64_t first_locate_ms;	/* when the first family was captured */
	int rdv_stage;			/* engine-wide progress: cold/warmup/store/get */

	uint64_t next_get_ms;
	uint64_t next_put_ms;
	uint64_t next_mcast_ms;
	uint64_t next_mcast_open_ms;
	uint64_t next_dht_open_ms;
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static int sig_stage(struct sig *s);

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
	if (keys_derive(&s->keys, rdv)) {
		free(s);
		return NULL;
	}
	/*
	 * The key claims are boxed to. Minted once per signaller rather than
	 * per offer: a rotation that changed it would strand a claim already in
	 * flight against the old one, and a rebuild -- which is what a move or
	 * a new network produces -- mints a fresh one anyway.
	 */
	if (is_host &&
	    (random_bytes(s->claim_sk, sizeof(s->claim_sk)) ||
	     cc_x25519_public(s->claim_pk, s->claim_sk))) {
		free(s);
		return NULL;
	}
	s->flags = flags;
	s->is_host = is_host;
	mailbox_init(&s->mb, is_host);
	s->start_ms = now_ms();

	/*
	 * A link-local half that will not open now leaves SIG_MCAST set: a moment
	 * with no multicast-capable interface up -- a laptop between two access
	 * points, a link being renumbered -- is what signalling exists to survive,
	 * so sig_dispatch keeps trying until one appears. With none up there is
	 * nothing on the link to wait for, so the DHT is engaged at once, exactly
	 * as for a session that asked for no multicast at all; a failure there is
	 * retried from sig_dispatch too.
	 */
	if (flags & SIG_MCAST)
		s->mc = sig_mcast_open(s->keys.mcast_port);
	if ((s->flags & SIG_DHT) && !s->mc)
		engage_dht(s);
	if (!(s->flags & (SIG_DHT | SIG_MCAST))) {
		sig_discard(s);
		return NULL;
	}
	return s;
}

static void sig_free(struct sig *s, int persist)
{
	if (!s)
		return;
	if (s->node) {
		if (persist)
			dhtnode_free(s->node);
		else
			dhtnode_discard(s->node);
	}
	if (s->mc)
		sig_mcast_close(s->mc);
	free(s);
}

void sig_destroy(struct sig *s)
{
	sig_free(s, 1);
}

void sig_discard(struct sig *s)
{
	sig_free(s, 0);
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

/* The ICE ufrag an sdp names, "" when absent. */
static void sdp_ufrag_of(const char *sdp, char *out, size_t outlen)
{
	const char *p = strstr(sdp, "ice-ufrag:");
	size_t i = 0;

	out[0] = '\0';
	if (!p)
		return;
	p += 10;
	while (*p && *p != '\r' && *p != '\n' && i + 1 < outlen)
		out[i++] = *p++;
	out[i] = '\0';
}

int sig_post(struct sig *s, const uint8_t *data, size_t len)
{
	char sdp[SIG_SDP_MAX];
	int plen;

	/* Pack for the DHT slot: global and shared-private (nested-NAT) reachable
	 * candidates, dropping only what cannot help off our own L2 segment. */
	if (len >= sizeof(sdp))
		return -1;
	memcpy(sdp, data, len);
	sdp[len] = '\0';
	sdp_ufrag_of(sdp, s->my_ufrag, sizeof(s->my_ufrag));
	plen = candpack_encode(sdp, 1, s->my_packed, sizeof(s->my_packed));
	if (plen <= 0)
		return -1;
	s->my_packed_len = (size_t)plen;
	sig_stage(s);


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

enum sig_claim sig_claim_status(struct sig *s)
{
	switch (mailbox_claim_status(&s->mb)) {
	case MAILBOX_CLAIM_FREE:
		return SIG_CLAIM_FREE;
	case MAILBOX_CLAIM_HELD:
		return SIG_CLAIM_HELD;
	case MAILBOX_CLAIM_BUSY:
		return SIG_CLAIM_BUSY;
	default:
		return SIG_CLAIM_UNKNOWN;
	}
}

void sig_withdraw(struct sig *s)
{
	mailbox_withdraw(&s->mb);
}

int sig_rotate(struct sig *s, const uint8_t *offer, size_t len)
{
	int rc = sig_post(s, offer, len);

	if (rc)
		return rc;
	mailbox_arm_release(&s->mb);	/* omit the answer slot on the next write */
	s->have_last = 0;	/* re-deliver the next answer even if identical */
	return 0;
}

void sig_release(struct sig *s)
{
	mailbox_arm_release(&s->mb);
	/*
	 * Emptying the slot means the next answer is new business even if it is
	 * the same bytes, exactly as after a rotate. A client whose claim was
	 * let go re-puts the one it already has -- nothing about it changed --
	 * so a delivery de-duplicated against the copy we just released is one
	 * the host never sees, and the claimant goes on writing into a mailbox
	 * that is answering nobody.
	 */
	s->have_last = 0;
}

void sig_redeliver(struct sig *s)
{
	s->have_last = 0;
}

void sig_set_direct_port(struct sig *s, uint16_t port)
{
	s->direct_port = port;
}

int sig_subscribe_direct(struct sig *s, sig_direct_cb *cb, void *arg)
{
	s->direct_cb = cb;
	s->direct_arg = arg;
	return 0;
}

void sig_set_mcast_claims(struct sig *s, int on)
{
	s->mcast_claims = on;
}

int sig_seed_node(struct sig *s, const struct sockaddr *sa, socklen_t len)
{
	if (!(s->flags & SIG_DHT))
		return -1;
	if (!s->dht_engaged && engage_dht(s))
		return -1;
	return bep44_pin_add(s->engine, NULL, sa, len);
}

void sig_set_family_up(struct sig *s, int family, int up)
{
	if (family == 6)
		s->up6 = up;
	else
		s->up4 = up;
}

int sig_locate(struct sig *s)
{
	if (!(s->flags & SIG_DHT))
		return -1;
	if (!s->dht_engaged && engage_dht(s))
		return -1;
	s->locate = 1;
	return 0;
}

int sig_located(struct sig *s, int family, struct sockaddr *out,
		socklen_t *out_len)
{
	const struct sockaddr_storage *r = family == 6 ? &s->rnode6 : &s->rnode4;
	socklen_t rl = family == 6 ? s->rnode6_len : s->rnode4_len;

	if (!s->locate || !rl || *out_len < rl)
		return 0;
	memcpy(out, r, rl);
	*out_len = rl;
	return 1;
}

int sig_dht_acked(struct sig *s, int family)
{
	return family == 6 ? s->acked6 : s->acked4;
}

int sig_dht_ready(struct sig *s)
{
	return s->dht_engaged && dhtnode_ready(s->node);
}

int sig_take_ack(struct sig *s, int family, struct sockaddr *out,
		 socklen_t *out_len)
{
	int *have = family == 6 ? &s->ack_new6 : &s->ack_new4;
	const struct sockaddr_storage *n = family == 6 ? &s->ack_node6 :
							&s->ack_node4;
	socklen_t nl = family == 6 ? s->ack_node6_len : s->ack_node4_len;

	if (!*have || !nl || *out_len < nl)
		return 0;
	memcpy(out, n, nl);
	*out_len = nl;
	*have = 0;
	return 1;
}

int sig_take_anchor_seen(struct sig *s, int family)
{
	int *seen = family == 6 ? &s->anchor_seen6 : &s->anchor_seen4;
	int was = *seen;

	*seen = 0;
	return was;
}

void sig_relay(struct sig *s, int family, int on)
{
	if (family == 6)
		s->relay6 = on;
	else
		s->relay4 = on;
	if (on)
		s->locate = 1;		/* the get that follows is what captures */
}

void sig_search_again(struct sig *s, int family)
{
	/* The node we hold keeps being served while this runs: a rendezvous
	 * that vanishes is worse than a stale one, and the caller swaps it only
	 * once a different node has actually answered. */
	if (family == 6)
		s->relocate6 = 1;
	else
		s->relocate4 = 1;
}

void sig_forget(struct sig *s, int family)
{
	struct sockaddr_storage *r = family == 6 ? &s->rnode6 : &s->rnode4;
	socklen_t *rl = family == 6 ? &s->rnode6_len : &s->rnode4_len;

	if (!*rl)
		return;
	if (s->dht_engaged)
		bep44_pin_del(s->engine, (const struct sockaddr *)r, *rl);
	memset(r, 0, sizeof(*r));
	*rl = 0;
	if (family == 6) {
		s->relocate6 = 0;
		s->acked6 = 0;
		s->anchor_seen6 = 0;
		s->ack_new6 = 0;
	} else {
		s->relocate4 = 0;
		s->acked4 = 0;
		s->anchor_seen4 = 0;
		s->ack_new4 = 0;
	}
	s->next_put_ms = 0;
}

int sig_locating(struct sig *s, int family)
{
	socklen_t rl = family == 6 ? s->rnode6_len : s->rnode4_len;

	if (!(s->flags & SIG_DHT) || !s->is_host || !s->locate || rl)
		return 0;
	/* Still actively pursued once the other family has proven the DHT
	 * reachable at all: there is no fixed point past which a family that
	 * has not answered yet is known to never will, so this stays true
	 * (still PENDING, not settled to NONE) until it is captured or the
	 * session ends. */
	return s->first_locate_ms != 0;
}

int sig_reinforce(struct sig *s, int family, const struct sockaddr *sa,
		  socklen_t len)
{
	struct sockaddr_storage *r = family == 6 ? &s->rnode6 : &s->rnode4;
	socklen_t *rl = family == 6 ? &s->rnode6_len : &s->rnode4_len;

	if ((size_t)len > sizeof(*r))
		return -1;
	if (!(s->flags & SIG_DHT))
		return -1;
	if (!s->dht_engaged && engage_dht(s))
		return -1;
	if (bep44_pin_add(s->engine, NULL, sa, len))
		return -1;
	if (*rl != len || memcmp(r, sa, len)) {
		if (family == 6)
			s->anchor_seen6 = 0;
		else
			s->anchor_seen4 = 0;
	}
	memcpy(r, sa, len);		/* adopt it as the located rendezvous, ... */
	*rl = len;
	if (family == 6)
		s->relocate6 = 0;
	else
		s->relocate4 = 0;
	s->locate = 1;			/* ... so sig_located returns it and the get
					 * never re-captures a different one. A
					 * still-missing family is located as usual;
					 * once none is missing, dht_pump reinforces. */
	if (!s->first_locate_ms)	/* paces any locate of a missing family */
		s->first_locate_ms = now_ms();
	return 0;
}

int sig_link_ifaces(struct sig *s, struct sig_mcast_if *out, int max)
{
	if (!s->mc)
		return 0;
	return sig_mcast_ifaces(s->mc, out, max);
}

/*
 * A handful of read intervals: long enough that a table thinning out between
 * refreshes is not read as an empty one, short enough that a signaller nothing
 * can answer is replaced before a peer gives up on finding us.
 */
#define SIG_QUIET_GONE_MS (SIG_DHT_GET_MS * 8)
/* A table that looks healthy but answers nothing: only time tells. */
#define SIG_QUIET_MS 60000
#if SIG_QUIET_GONE_MS >= SIG_QUIET_MS
#error "an unasking node is the quicker verdict of the two"
#endif

int sig_quiet_due(int node_ready, uint64_t idle_ms)
{
	if (!node_ready)
		return idle_ms > SIG_QUIET_GONE_MS;
	return idle_ms > SIG_QUIET_MS;
}

int sig_quiet(struct sig *s)
{
	if (!s || !s->dht_engaged || !s->last_get_ms)
		return 0;
	return sig_quiet_due(dhtnode_ready(s->node),
			     now_ms() - s->last_get_ms);
}

void sig_mailbox_state(struct sig *s, struct sig_mailbox *out)
{
	memset(out, 0, sizeof(*out));
	if (!s)
		return;
	out->engaged = s->dht_engaged;
	out->stage = s->rdv_stage;
	out->have_mine = s->mb.have_mine;
	/* need_write is set while what is stored is not what we want stored,
	 * so its absence is the only honest way to say "ours is up there". */
	out->mine_stored = s->mb.have_mine && s->mb.have_cur && !s->mb.need_write;
	out->peer_seen = s->mb.is_host ? s->mb.slot_a_len != 0 :
					 s->mb.slot_o_len != 0;
	out->seq = s->mb.have_cur ? s->cur_seq : -1;
	out->gets = s->gets_ok;
	out->puts = s->puts_ok;
	out->claim = (int)sig_claim_status(s);
	out->last_get_ms = s->last_get_ms;
	out->last_put_ms = s->last_put_ms;
}

int sig_rdv_stage(struct sig *s, int family)
{
	socklen_t rl = family == 6 ? s->rnode6_len : s->rnode4_len;

	if (rl)
		return 4;			/* RDV_READY, per family */
	return s->rdv_stage;			/* 0 cold .. 3 get, engine-wide */
}

/*
 * Build what goes in our slot from the packed description we hold, and stage
 * it. The host prefixes the key claims are boxed to; a client boxes to that
 * key and puts its ufrag in the clear beside it. A client that has not seen
 * the host's slot yet cannot box anything, so it stages nothing and is called
 * again when the slot arrives -- which is before it could have written, since
 * a write is only decided against a container that has been read.
 */
static int sig_stage(struct sig *s)
{
	uint8_t val[SIG_MAX_VALUE];
	uint8_t sealed[SIG_SEALED_MAX];
	uint8_t mc[2 + SIG_MAX_VALUE];
	char ms[2];
	size_t ulen, n;
	int slen;

	if (!s->my_packed_len)
		return -1;
	if (s->is_host) {
		if (32 + s->my_packed_len > sizeof(val))
			return -1;
		memcpy(val, s->claim_pk, 32);
		memcpy(val + 32, s->my_packed, s->my_packed_len);
		n = 32 + s->my_packed_len;
	} else {
		if (!s->have_peer_claim_pk)
			return -1;
		ulen = strlen(s->my_ufrag);
		if (ulen > 255 ||
		    1 + ulen + s->my_packed_len + BOX_OVERHEAD > sizeof(val))
			return -1;
		val[0] = (uint8_t)ulen;
		memcpy(val + 1, s->my_ufrag, ulen);
		slen = box_seal(val + 1 + ulen, sizeof(val) - 1 - ulen,
				s->peer_claim_pk, s->my_packed,
				s->my_packed_len);
		if (slen < 0)
			return -1;
		n = 1 + ulen + (size_t)slen;
	}
	slen = msg_seal(sealed, sizeof(sealed), s->keys.sig_key, val, n);
	if (slen < 0)
		return -1;
	mailbox_set_mine(&s->mb, sealed, (size_t)slen);

	/*
	 * The multicast announcement carries the same value with our
	 * direct-transport port prepended, bound to the slot letter it goes out
	 * under: that letter frames the value outside the seal and is what says
	 * whether a description is an offer or an answer, so without binding it
	 * a frame captured from one slot opens in the other.
	 */
	mc[0] = (uint8_t)(s->direct_port >> 8);
	mc[1] = (uint8_t)s->direct_port;
	memcpy(mc + 2, val, n);
	ms[0] = my_slot(s);
	ms[1] = '\0';
	slen = msg_seal_ad(s->mcast_mine, sizeof(s->mcast_mine),
			   s->keys.sig_key, (const uint8_t *)ms, 1, mc, n + 2);
	if (slen > 0)
		s->mcast_mine_len = (size_t)slen;
	return 0;
}

/*
 * The peer's slot value -> its packed description. A client reads the host's
 * slot, which carries the key claims are boxed to ahead of the description; a
 * host reads a claim, which is its claimant's ufrag in the clear and then a box
 * only the host can open. Returns the packed length, or -1.
 *
 * `uf`, when asked for, receives the claimant's ufrag -- empty on the host's
 * slot, which has none.
 */
static int slot_unwrap(struct sig *s, const uint8_t *val, size_t n,
		       uint8_t *out, size_t out_max, char *uf, size_t uf_max)
{
	size_t ulen;

	if (uf && uf_max)
		uf[0] = '\0';
	if (!s->is_host) {
		if (n < 32)
			return -1;
		if (memcmp(s->peer_claim_pk, val, 32)) {
			memcpy(s->peer_claim_pk, val, 32);
			s->have_peer_claim_pk = 1;
			sig_stage(s);	/* now it can be boxed */
		}
		n -= 32;
		if (n > out_max)
			return -1;
		memcpy(out, val + 32, n);
		return (int)n;
	}
	if (!n)
		return -1;
	ulen = val[0];
	if (1 + ulen > n)
		return -1;
	if (uf && uf_max) {
		if (ulen >= uf_max)
			return -1;
		memcpy(uf, val + 1, ulen);
		uf[ulen] = '\0';
	}
	return box_open(out, out_max, s->claim_sk, val + 1 + ulen,
			n - 1 - ulen);
}

/* Open the peer's sealed slot and deliver it once, de-duplicated. */
static void deliver_peer(struct sig *s, const uint8_t *sealed, size_t len)
{
	uint8_t plain[SIG_MAX_VALUE], packed[SIG_MAX_VALUE];
	char sdp[SIG_SDP_MAX];
	int n = msg_open(plain, sizeof(plain), s->keys.sig_key, sealed, len);
	int slen;

	if (n < 0)
		return;
	if (s->have_last && s->last_peer_len == (size_t)n &&
	    !memcmp(s->last_peer, plain, (size_t)n))
		return;
	dbg_logf("sig: peer slot delivered (%d bytes)", n);
	memcpy(s->last_peer, plain, (size_t)n);
	s->last_peer_len = (size_t)n;
	s->have_last = 1;
	n = slot_unwrap(s, plain, (size_t)n, packed, sizeof(packed), NULL, 0);
	if (n < 0)
		return;
	slen = candpack_decode(packed, (size_t)n, sdp, sizeof(sdp));
	if (slen < 0)
		return;
	if (s->cb)
		s->cb(s->arg, (const uint8_t *)sdp, (size_t)slen);
}

static void on_dht_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq,
		       const struct sockaddr *node, socklen_t node_len)
{
	struct sig *s = arg;
	const uint8_t *peer;
	size_t peer_len;

	if (!v)
		return;
	/*
	 * Two reads are in flight at once -- the direct one and the convergent
	 * one -- and they answer from different nodes, so an older container can
	 * land after a newer one. Taking it would put a superseded claim back in
	 * front of the turnstile and walk cur_seq backwards, which the next
	 * compare-and-swap then loses on.
	 *
	 * A lower seq that keeps coming back is not a straggler though: if the
	 * item aged out everywhere our own next store begins again at one. So
	 * hold out for a few, then believe it.
	 */
	if (s->cur_seq && seq < s->cur_seq &&
	    ++s->seq_regress < SIG_SEQ_REGRESS_MAX)
		return;
	s->seq_regress = 0;
	s->gets_ok++;
	s->last_get_ms = now_ms();
	mailbox_parse(&s->mb, v, v_len);
	s->cur_seq = seq;

	/* A client recognises its own claimant's claim in the answer slot --
	 * typically a superseded attempt the host never released -- so the
	 * turnstile rule lets it overwrite that one rather than wedge itself
	 * out behind it. */
	if (!s->mb.is_host && s->mb.slot_a_len && s->my_ufrag[0]) {
		uint8_t plain[SIG_MAX_VALUE];
		char uf[64];
		int n = msg_open(plain, sizeof(plain), s->keys.sig_key,
				 s->mb.slot_a, s->mb.slot_a_len);
		size_t ulen;

		/*
		 * A claim is boxed to the host, so a client cannot read one --
		 * not even its own, whose ephemeral secret is long gone. The
		 * ufrag beside the box is what this rule was ever about: it
		 * says which claimant holds the slot, and nothing about where.
		 */
		if (n > 0) {
			ulen = plain[0];
			if (1 + ulen <= (size_t)n && ulen < sizeof(uf)) {
				memcpy(uf, plain + 1, ulen);
				uf[ulen] = '\0';
				mailbox_note_own_answer(&s->mb,
							uf[0] &&
							!strcmp(uf,
								s->my_ufrag));
			}
		}
	}

	peer_len = mailbox_peer_slot(&s->mb, &peer);
	if (peer_len)
		deliver_peer(s, peer, peer_len);

	/*
	 * The value is signature-checked as ours, so the node that served it is
	 * a validated, responsive, k-close rendezvous point, and its family has
	 * acknowledged our publish. Keep the first (fastest) of EACH family and
	 * pin it: a dual-stack client may live behind only one family, so both
	 * go in the token. The v4 and v6 DHTs converge independently, so
	 * capturing per family here -- rather than the first node of any family
	 * -- lets both be found within one session.
	 */
	if (node && node_len && (size_t)node_len <= sizeof(s->rnode4)) {
		int captured = 0;
		socklen_t rl = node->sa_family == AF_INET6 ? s->rnode6_len :
							     s->rnode4_len;
		const void *r = node->sa_family == AF_INET6 ?
				(const void *)&s->rnode6 :
				(const void *)&s->rnode4;

		/* It answered for itself. Nothing here is said about any other
		 * node: the convergent store puts the value on every k-close
		 * node, so several hold it and whichever is quickest replies. */
		if (rl == node_len && !memcmp(r, node, node_len)) {
			if (node->sa_family == AF_INET6)
				s->anchor_seen6 = 1;
			else
				s->anchor_seen4 = 1;
		}

		if (node->sa_family == AF_INET6) {
			s->acked6 = 1;
			memcpy(&s->ack_node6, node, node_len);
			s->ack_node6_len = node_len;
			s->ack_new6 = 1;
			if (s->locate && !s->rnode6_len) {
				memcpy(&s->rnode6, node, node_len);
				s->rnode6_len = node_len;
				captured = 1;
			}
		} else if (node->sa_family == AF_INET) {
			s->acked4 = 1;
			memcpy(&s->ack_node4, node, node_len);
			s->ack_node4_len = node_len;
			s->ack_new4 = 1;
			if (s->locate && !s->rnode4_len) {
				memcpy(&s->rnode4, node, node_len);
				s->rnode4_len = node_len;
				captured = 1;
			}
		}
		if (captured) {
			bep44_pin_add(s->engine, NULL, node, node_len);
			if (!s->first_locate_ms)
				s->first_locate_ms = now_ms();
		}
	}
}

/*
 * LAN scope: a source on our own layer-2 segment. Multicast is link-scoped
 * (TTL/hops 1), so a claimant we hear is on our segment and reachable over the
 * direct transport without ICE. Link-local, RFC1918 and ULA all qualify. This
 * is not the trust boundary -- the seal is; it only decides which peers get the
 * ICE-free bypass.
 */
static int addr_is_lan_scope(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
		const uint8_t *b = s6->sin6_addr.s6_addr;

		if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr) ||
		    IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr))	/* ::1 same-host */
			return 1;
		return (b[0] & 0xfe) == 0xfc;			/* fc00::/7 ULA */
	}
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
		const uint8_t *b = (const uint8_t *)&s4->sin_addr;

		if (b[0] == 127)				/* 127/8 same-host */
			return 1;
		if (b[0] == 10)					/* 10.0.0.0/8 */
			return 1;
		if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)	/* 172.16.0.0/12 */
			return 1;
		if (b[0] == 192 && b[1] == 168)			/* 192.168.0.0/16 */
			return 1;
		if (b[0] == 169 && b[1] == 254)			/* 169.254.0.0/16 */
			return 1;
	}
	return 0;
}

/*
 * Open a multicast announcement: the peer's direct port (2 bytes) followed by
 * the routable candpack. Split by role. A client feeds the candidates to ICE and
 * learns the host's direct endpoint for the bypass. A host that demultiplexes
 * the shared lanlink socket (mcast_claims) does NOT feed the candpack to its ICE
 * turnstile -- it can serve a same-segment claimant directly over lanlink, so
 * punching it too would serve the client twice; instead the claimant's endpoint
 * becomes a direct claim. Either way the endpoint is (that source, zone id kept,
 * at the announced port), adopted only from a LAN-scope source of a sealed blob.
 */
static void deliver_peer_mcast(struct sig *s, const uint8_t *sealed, size_t len,
			       const struct sockaddr *src, socklen_t srclen)
{
	uint8_t plain[2 + SIG_MAX_VALUE], packed[SIG_MAX_VALUE];
	char sdp[SIG_SDP_MAX];
	struct sockaddr_storage ep;
	char ps[2];
	int n, slen;
	uint16_t dport;

	ps[0] = peer_slot(s);
	ps[1] = '\0';
	n = msg_open_ad(plain, sizeof(plain), s->keys.sig_key,
			(const uint8_t *)ps, 1, sealed, len);
	if (n < 3)
		return;
	dport = (uint16_t)((plain[0] << 8) | plain[1]);
	n = slot_unwrap(s, plain + 2, (size_t)n - 2, packed, sizeof(packed),
			NULL, 0);
	if (n < 0)
		return;
	slen = candpack_decode(packed, (size_t)n, sdp, sizeof(sdp));
	if (slen >= 0 && s->cb && !(s->is_host && s->mcast_claims))
		s->cb(s->arg, (const uint8_t *)sdp, (size_t)slen);

	if (slen >= 0 && s->direct_cb && dport && addr_is_lan_scope(src) &&
	    (size_t)srclen <= sizeof(ep)) {
		memcpy(&ep, src, srclen);
		if (ep.ss_family == AF_INET6)
			((struct sockaddr_in6 *)&ep)->sin6_port = htons(dport);
		else
			((struct sockaddr_in *)&ep)->sin_port = htons(dport);
		s->direct_cb(s->direct_arg, (struct sockaddr *)&ep, srclen,
			     (const uint8_t *)sdp, (size_t)slen);
	}
}

static void on_mcast_recv(void *arg, const char *salt, const uint8_t *data,
			  size_t len, const struct sockaddr *src,
			  socklen_t srclen)
{
	struct sig *s = arg;
	char ps[2];

	ps[0] = peer_slot(s);
	ps[1] = '\0';
	if (!strcmp(salt, ps))
		deliver_peer_mcast(s, data, len, src, srclen);
}

/* Merge our slot into the value just read, preserving the peer's slot. */
static int sig_merge(void *arg, const uint8_t *cur, size_t cur_len,
		     uint8_t *out, size_t *out_len, size_t max)
{
	struct sig *s = arg;

	return mailbox_merge(&s->mb, cur, cur_len, out, out_len, max);
}

/* Place the container unchanged, for a store made on the peer's behalf: see
 * mailbox_relay for why neither slot may be written here. */
static int sig_relay_merge(void *arg, const uint8_t *cur, size_t cur_len,
			   uint8_t *out, size_t *out_len, size_t max)
{
	struct sig *s = arg;

	return mailbox_relay(&s->mb, cur, cur_len, out, out_len, max);
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
	if (stored > 0) {
		s->next_put_ms = now_ms() + SIG_DHT_RESTORE_MS;
		if (s->rdv_stage < 3)
			s->rdv_stage = 3;	/* stored: now reading it back */
	}
}

/* A store has gone out. Counted where it is issued rather than where it is
 * acknowledged, because only the convergent one reports back at all -- and a
 * store nobody answered is exactly what the operator needs to see. Whether it
 * took is the separate question mine_stored answers. */
static void sig_note_put(struct sig *s)
{
	s->puts_ok++;
	s->last_put_ms = now_ms();
}

/* Asked to establish a rendezvous for a family we have not captured one on
 * yet. A family we already hold needs no store: what we hold is what the peer
 * is told. */
static int relaying(const struct sig *s)
{
	return (s->relay4 && !s->rnode4_len) || (s->relay6 && !s->rnode6_len);
}

/*
 * A family this end has, that the DHT has not answered on yet.
 *
 * A client has no reason of its own to exercise a family it is not currently
 * meeting over, and would settle into a trickle on whichever one its token
 * happened to name -- so the other stays cold, and the first thing that needs
 * it (a host that moved, or one that never had it) waits for a warm-up that
 * could have happened long before. Every family this end has is kept engaged
 * until it has answered, whether or not anything wants it yet.
 *
 * A family that never answers keeps this true, and that is the same judgement
 * the host's own locating makes: there is no point past which a family that
 * has not answered is known never to.
 */
static int warming(const struct sig *s)
{
	return (s->up4 && !s->acked4) || (s->up6 && !s->acked6);
}

static void dht_pump(struct sig *s, uint64_t now)
{
	if (!dhtnode_ready(s->node))
		return;
	if (s->rdv_stage < 1)
		s->rdv_stage = 1;		/* DHT warm: nodes found near key */
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
	/*
	 * And the same read the ordinary way. Eagerly until the peer's slot has
	 * been seen -- which is the case a token with no rendezvous node, or a
	 * dead one, leaves us in -- then rarely, so a peer that wrote its answer
	 * to a node we never pinned is still found. The nodes that answer are
	 * retained, so the direct route takes over as soon as there is one.
	 */
	if (now >= s->next_wide_get_ms) {
		const uint8_t *slot;

		bep44_get(s->engine, s->keys.bep44_pk, SIG_SALT, on_dht_get, s);
		/*
		 * Relaying keeps it eager: this read is not looking for the
		 * peer's slot, it is what turns the store just made into a node
		 * that has answered here. So does a family still to answer at
		 * all, which is how both of them get warm rather than only the
		 * one in use.
		 */
		s->next_wide_get_ms = now +
			((mailbox_peer_slot(&s->mb, &slot) && !relaying(s) &&
			  !warming(s)) ?
			 SIG_DHT_WIDE_IDLE_MS : SIG_DHT_WIDE_GET_MS);
	}
	if (now < s->next_put_ms)
		return;
	if (s->is_host) {
		/*
		 * A reachable family with no anchor yet is still being located:
		 * the convergent store places the mailbox on its k-closest nodes
		 * (idiomatic and discoverable) and the validating get captures
		 * one as the anchor. It repeats until that family is captured --
		 * the v6 DHT converges later than v4, so an early store misses
		 * its k-closest. It keeps retrying for as long as it takes rather
		 * than giving up on a timing guess: eager for as long as a still-
		 * missing family's own connectivity is proven up (sig_set_family_up),
		 * slower otherwise, never stopping outright. An already-anchored
		 * family is never re-located.
		 */
		int missing = !s->rnode4_len || !s->rnode6_len ||
			      s->relocate4 || s->relocate6;

		if (s->mb.have_mine && missing && !s->put_inflight) {
			int eager = ((!s->rnode4_len || s->relocate4) && s->up4) ||
				    ((!s->rnode6_len || s->relocate6) && s->up6);

			s->put_inflight = 1;
			if (s->rdv_stage < 2)
				s->rdv_stage = 2;	/* placing the mailbox */
			bep44_update(s->engine, s->keys.bep44_sk,
				     s->keys.bep44_pk, SIG_SALT, sig_merge,
				     s, on_host_put, s);
			s->next_put_ms = now +
				(eager ? SIG_DHT_PUT_MS : SIG_DHT_PUT_SLOW_MS);
		} else if (s->mb.have_mine && now >= s->next_wide_put_ms) {
			/*
			 * The value where the key says it belongs, not only
			 * where it first landed. Which nodes are closest drifts
			 * as the DHT churns, and a client that has to converge
			 * -- an old token, or one that never named a node --
			 * finds whoever is closest now, so the value has to be
			 * there and not merely on the handful we pinned once.
			 */
			sig_note_put(s);
			bep44_update(s->engine, s->keys.bep44_sk,
				     s->keys.bep44_pk, SIG_SALT, sig_merge,
				     s, NULL, NULL);
			s->next_wide_put_ms = now + SIG_DHT_WIDE_PUT_MS;
			s->next_put_ms = now + SIG_DHT_PUT_MS;
		} else if (s->mb.have_mine && (s->rnode4_len || s->rnode6_len) &&
			   s->mb.need_write) {
			/*
			 * Locating done: keep the anchor warm with a direct
			 * store -- a round-trip to the pinned node, no
			 * convergence -- but only when it no longer carries our
			 * offer (need_write is the GET-driven forget signal), so
			 * the token never churns and the mailbox never expires.
			 */
			sig_note_put(s);
			bep44_update_direct(s->engine, s->keys.bep44_sk,
					    s->keys.bep44_pk, SIG_SALT,
					    sig_merge, s, NULL, NULL);
			s->next_put_ms = now + SIG_DHT_PUT_MS;
		}
	} else if (mailbox_client_should_claim(&s->mb)) {
		dbg_logf("sig: writing claim to the rendezvous");
		sig_note_put(s);
		/*
		 * The client claims by writing its answer straight to the pinned
		 * rendezvous node once it has read the offer -- a round-trip, not
		 * a lookup, so it never clobbers the offer and never converges.
		 * Only an EMPTY answer slot is claimed (the turnstile mutex): a
		 * slot already holding an answer belongs to another client, so we
		 * leave it and back off until the host frees it.
		 */
		bep44_update_direct(s->engine, s->keys.bep44_sk,
				    s->keys.bep44_pk, SIG_SALT, sig_merge,
				    s, NULL, NULL);
		s->next_put_ms = now + SIG_DHT_PUT_MS;
	} else if (relaying(s) && !s->put_inflight) {
		/*
		 * Rendezvous on the peer's behalf: a host that cannot reach a
		 * family has asked us to establish one there. The sequence is
		 * the host's own -- the convergent store places the container
		 * on the nodes the key belongs to, and the validating get that
		 * follows picks whichever of them answers -- because a node
		 * established any other way would carry a weaker promise while
		 * being indistinguishable afterwards.
		 *
		 * What differs is only what is written: the container as it
		 * stands, neither slot ours (mailbox_relay). Claiming the
		 * answer slot here would take the turnstile and hold it for the
		 * session, locking out every other client, for a store that was
		 * never about claiming anything.
		 */
		sig_note_put(s);
		bep44_update(s->engine, s->keys.bep44_sk, s->keys.bep44_pk,
			     SIG_SALT, sig_relay_merge, s, NULL, NULL);
		s->next_put_ms = now + SIG_DHT_PUT_MS;
	}
}

static void mcast_pump(struct sig *s, uint64_t now)
{
	char ms[2];

	/*
	 * Gate on the sealed announcement, not on have_mine. A same-segment client
	 * withdraws its DHT mailbox answer (clearing have_mine) the instant it
	 * learns the peer over lanlink, to stop a double-serve -- but the host
	 * learns that client from exactly this multicast announcement, so stopping
	 * it on withdraw would race the host's admission (which may not have
	 * processed the announcement yet). Keep announcing; a host deduplicates a
	 * claimant it has already admitted.
	 */
	if (!s->mcast_mine_len || now < s->next_mcast_ms)
		return;
	ms[0] = my_slot(s);
	ms[1] = '\0';
	sig_mcast_send(s->mc, ms, s->mcast_mine, s->mcast_mine_len);
	s->next_mcast_ms = now + SIG_MCAST_ANN_MS;
}

void sig_dispatch(struct sig *s, const struct pollfd *fds, int nfds)
{
	uint64_t now = now_ms();

	if ((s->flags & SIG_MCAST) && !s->mc && now >= s->next_mcast_open_ms) {
		s->mc = sig_mcast_open(s->keys.mcast_port);
		s->next_mcast_open_ms = now + SIG_MCAST_OPEN_MS;
	}
	if (s->mc) {
		sig_mcast_dispatch(s->mc, fds, nfds, on_mcast_recv, s);
		mcast_pump(s, now);
	}

	/*
	 * With no multicast in play there is nothing on the link to wait for,
	 * so engage the DHT at once; a combined session gives the link a brief
	 * grace first and then engages whether or not it answered -- the DHT is
	 * the only rendezvous that survives a change of network, so it has to be
	 * running before the change rather than started after it.
	 */
	if ((s->flags & SIG_DHT) && !s->dht_engaged &&
	    (!s->mc || now - s->start_ms > SIG_DHT_GRACE_MS) &&
	    now >= s->next_dht_open_ms) {
		engage_dht(s);
		s->next_dht_open_ms = now + SIG_DHT_OPEN_MS;
	}

	if (s->dht_engaged) {
		dhtnode_dispatch(s->node, fds, nfds);
		dht_pump(s, now);
	}
}
