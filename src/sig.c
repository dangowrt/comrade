/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bencode.h"
#include "bep44.h"
#include "dbg.h"
#include "candpack.h"
#include "candpolicy.h"
#include "ctlproto.h"
#include "dhtnode.h"
#include "keys.h"
#include "rdv.h"
#include "sig.h"
#include "sig_mcast.h"

#define SIG_VALUE_MAX (RDV_MAX_MSG + SEAL_OVERHEAD)
#define SIG_WIRE_MAX BEP44_MAX_VALUE	/* the sealed value as a bencoded string */
#define SIG_SDP_MAX 4096		/* raw ICE description in/out of candpack */
#define SIG_OPS_MAX 64
#define SIG_MCAST_MAX (RDV_CID_LEN + 2 + SIG_VALUE_MAX)

#define SIG_DHT_GET_MS 1000
#define SIG_DHT_PUT_MS 1000		/* re-run the convergent store/gather this
					 * often while locating, so the slower v6
					 * DHT gets more attempts inside the window */
#define SIG_DHT_RESTORE_MS 8000		/* re-store backoff while a store's
					 * k-close nodes are being validated */
#define SIG_MCAST_ANN_MS 1000
#define SIG_DHT_TOMB_MS 300		/* the tombstone's own store cadence: the
					 * session is over and the operator's
					 * shell is waiting on it, so it is
					 * retried faster than a live mailbox */
/*
 * How long a tombstone must stand unanswered before a client believes it.
 *
 * Every holder of the invitation can write the cell, so the cell alone is
 * not proof: a live host takes it back on its next write, roughly once a
 * second while it is serving. Waiting a few of those rounds is what separates
 * a session that ended from one somebody is lying about.
 */
#define SIG_TOMB_SETTLE_MS 4000
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
 * worthless. So the cell is also reached the ordinary way, by converging on
 * its key, whenever the direct route has not produced it. A client that finds
 * it this way retains the nodes that served it, which are the host's own, and
 * writes its offer there.
 */

#define SIG_DHT_WIDE_GET_MS 4000	/* while the cell is still unseen */
#define SIG_DHT_WIDE_IDLE_MS 20000	/* once it has been, as a safety net */
#define SIG_DHT_RELAY_MS 4000		/* operating a rendezvous the peer cannot
					 * reach: often enough that a change to
					 * the cell reaches the family within a
					 * round of being made */
#define SIG_DHT_WIDE_PUT_MS 45000	/* keep the value on whoever is closest
					 * now, not only where it first landed */

#define SIG_DHT_PUT_SLOW_MS 20000	/* a still-missing family with no proven
					 * connectivity yet is retried at this
					 * slower pace instead of not at all --
					 * see sig_set_family_up. */

#define SIG_GRADE_RW 1
#define SIG_GRADE_RO 2

struct sig_fam {
	struct sockaddr_storage rnode;
	struct sockaddr_storage ack_node;
	socklen_t rnode_len;
	socklen_t ack_node_len;
	uint32_t epoch;
	int ack_new;
	int anchor_seen;
	int relocate;
	int relay;
	int up;
};

/* One operation in flight: the slot it reads or writes, and for a read the
 * network each family was on when it was asked. */
struct sig_op {
	struct sig *s;
	uint8_t val[SIG_WIRE_MAX];
	size_t val_len;
	uint8_t cid[RDV_CID_LEN];
	uint32_t qep[2];
	int64_t seq_seen;
	char kind;
	uint8_t busy, done, wide, is_put;
	uint8_t free_turn;		/* the host's statement hands the turn back */
};

struct sig {
	unsigned flags;
	struct session_keys keys;
	uint8_t rdv[TOKEN_RDV_LEN];
	uint8_t auth[TOKEN_AUTH_LEN];
	uint8_t auth_ro[TOKEN_AUTH_LEN];
	int have_rw;
	uint64_t start_ms;
	int is_host;

	struct dhtnode *node;
	struct bep44_engine *engine;
	struct sig_op ops[SIG_OPS_MAX];

	struct sig_mcast *mc;
	int mcast_claims;		/* host demultiplexes lanlink itself, so a
					 * mcast claimant is a direct claim, not an
					 * ICE offer for the turnstile */

	struct rdv_host *rh;
	struct rdv_client *rc;
	uint8_t hval[SIG_WIRE_MAX];
	size_t hval_len;
	int h_stale;
	uint8_t hcopy[SIG_WIRE_MAX];
	size_t hcopy_len;
	int64_t hcopy_seq;
	int64_t h_seq;
	int end_placed_direct;
	int end_placed_wide;
	uint64_t tomb_seen_ms;
	uint64_t info_seen_ms;

	sig_recv_cb *cb;
	void *arg;
	uint16_t direct_port;		/* our direct-transport port, announced */
	sig_direct_cb *direct_cb;	/* fires on a link-local announcement */
	void *direct_arg;
	uint8_t my_packed[RDV_MAX_PAYLOAD];
	size_t my_packed_len;
	char my_ufrag[40];		/* the identity the last offer carried */
	uint32_t my_gen;

	int locate;
	int located_any;
	int mine_stored;
	struct sig_fam fam[2];
	int gets_ok;
	int puts_ok;
	uint64_t last_get_ms;
	uint64_t last_put_ms;
	uint64_t engaged_ms;
	int rdv_stage;			/* engine-wide progress: cold/warmup/store/get */
	int routeless;			/* the last pump had nowhere to ask */
	unsigned read_turn;
	int claim_cursor;

	uint64_t next_get_ms;
	uint64_t next_put_ms;
	uint64_t next_hput_ms;		/* the host statement's store schedule */
	uint64_t next_wide_get_ms;
	uint64_t next_wide_put_ms;
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

static int fam_of(int family)
{
	return family == 6 ? 1 : 0;
}

static int fam_of_af(int af)
{
	return af == AF_INET6 ? 1 : 0;
}

static int engage_dht(struct sig *s)
{
	s->node = dhtnode_create();
	if (!s->node)
		return -1;
	s->engine = dhtnode_engine(s->node);
	s->engaged_ms = now_ms();
	return 0;
}

const uint8_t *sig_instance_id(void)
{
	static uint8_t cid[RDV_CID_LEN];
	static int set;

	if (!set) {
		if (random_bytes(cid, sizeof(cid)))
			return NULL;
		set = 1;
	}
	return cid;
}

struct sig *sig_create(const uint8_t rdv[TOKEN_RDV_LEN],
		       const uint8_t auth[TOKEN_AUTH_LEN], int auth_ro,
		       unsigned flags, int is_host)
{
	struct sig *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	if (keys_derive(&s->keys, rdv)) {
		free(s);
		return NULL;
	}
	memcpy(s->rdv, rdv, TOKEN_RDV_LEN);
	if (auth_ro) {
		memcpy(s->auth_ro, auth, TOKEN_AUTH_LEN);
	} else {
		memcpy(s->auth, auth, TOKEN_AUTH_LEN);
		keys_derive_ro_auth(s->auth_ro, auth);
		s->have_rw = 1;
	}
	s->flags = flags;
	s->is_host = is_host;
	s->h_seq = -1;
	s->hcopy_seq = -1;
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

void sig_rdv_host(struct sig *s, struct rdv_host *h)
{
	s->rh = h;
	s->next_put_ms = 0;
	s->next_hput_ms = 0;
}

void sig_rdv_client(struct sig *s, struct rdv_client *c)
{
	s->rc = c;
	s->next_put_ms = 0;
}

unsigned sig_routes_open(int node_ready, int rdv_held)
{
	if (node_ready)
		return SIG_ROUTE_DIRECT | SIG_ROUTE_WIDE;
	return rdv_held ? SIG_ROUTE_DIRECT : 0u;
}

/* The same against this signaller; only valid once the DHT is engaged. */
static unsigned routes_now(struct sig *s)
{
	return sig_routes_open(dhtnode_ready(s->node),
			       bep44_direct_nodes(s->engine) > 0);
}

int sig_prepare(struct sig *s, struct pollfd *fds, int maxfds, int *timeout_ms)
{
	int nfds = 0, t;

	if (s->node)
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
	return s->node && routes_now(s) != 0;
}

static void slot_key(const struct sig *s, int grade, uint8_t out[32])
{
	keys_slot_key(out, grade == SIG_GRADE_RO ? s->auth_ro : s->auth);
}

static int my_grade(const struct sig *s)
{
	return s->have_rw ? SIG_GRADE_RW : SIG_GRADE_RO;
}

static void slot_salt(const struct sig *s, char out[KEYS_SALT_LEN])
{
	keys_slot_salt(out, s->rdv);
}

static void sig_mb_note(const char *tag, const uint8_t *cid, const char *sdp)
{
	char flat[SIG_SDP_MAX];
	size_t i;

	if (!dbg_mailbox_on())
		return;
	for (i = 0; sdp[i] && i < sizeof(flat) - 1; i++)
		flat[i] = (sdp[i] == '\n' || sdp[i] == '\r') ? '|' : sdp[i];
	flat[i] = '\0';
	dbg_logf("mailbox %s %02x%02x%02x%02x sdp=[%s]", tag, cid[0], cid[1],
		 cid[2], cid[3], flat);
}

void sig_ident_changed(struct sig *s)
{
	if (!s || s->is_host || !s->rc)
		return;
	rdv_client_ident_changed(s->rc);
	s->my_ufrag[0] = '\0';
}

/* Say the ask again as one the host has not read: an unchanged description is
 * written once, and the host reads what stands as a replay. */
void sig_reask(struct sig *s)
{
	if (s->is_host || !s->rc)
		return;
	rdv_client_reask(s->rc);
	s->next_put_ms = 0;
}

int sig_post(struct sig *s, const uint8_t *data, size_t len)
{
	uint8_t packed[RDV_MAX_PAYLOAD];
	char sdp[SIG_SDP_MAX];
	int plen, changed;
	char ufrag[40];

	if (s->is_host || !s->rc || len >= sizeof(sdp))
		return -1;
	memcpy(sdp, data, len);
	sdp[len] = '\0';
	plen = candpack_encode(sdp, 1, s->my_gen, NULL, sig_instance_id(),
			       packed, sizeof(packed));
	if (plen <= 0)
		return -1;
	changed = s->my_packed_len != (size_t)plen ||
		  memcmp(s->my_packed, packed, (size_t)plen);
	cand_sdp_ufrag(sdp, ufrag, sizeof(ufrag));
	if (s->my_ufrag[0] && strcmp(s->my_ufrag, ufrag))
		rdv_client_ident_changed(s->rc);
	snprintf(s->my_ufrag, sizeof(s->my_ufrag), "%s", ufrag);
	memcpy(s->my_packed, packed, (size_t)plen);
	s->my_packed_len = (size_t)plen;
	rdv_client_set_live(s->rc, 0);
	if (changed) {
		sig_mb_note("PUT offer", s->rc->cid, sdp);
		s->next_put_ms = 0;
	}
	s->next_mcast_ms = 0;
	return 0;
}

int sig_subscribe(struct sig *s, sig_recv_cb *cb, void *arg)
{
	s->cb = cb;
	s->arg = arg;
	return 0;
}

int sig_answer(struct sig *s, const uint8_t *cid, const uint8_t *data,
	       size_t len)
{
	uint8_t packed[RDV_MAX_PAYLOAD];
	char sdp[SIG_SDP_MAX];
	int plen;

	if (!s->is_host || !s->rh || len >= sizeof(sdp))
		return -1;
	memcpy(sdp, data, len);
	sdp[len] = '\0';
	plen = candpack_encode(sdp, 1, s->my_gen, NULL, sig_instance_id(),
			       packed, sizeof(packed));
	if (plen <= 0)
		return -1;
	sig_mb_note("PUT answer", cid, sdp);
	rdv_host_answer(s->rh, cid, packed, (size_t)plen);
	s->next_put_ms = 0;
	return 0;
}

void sig_refuse(struct sig *s, const uint8_t *cid)
{
	if (!s->is_host || !s->rh)
		return;
	rdv_host_refuse(s->rh, cid, RDV_REFUSE_FULL);
	s->next_put_ms = 0;
}

void sig_claimant_gone(struct sig *s, const uint8_t *cid)
{
	if (s->rh)
		rdv_host_forget(s->rh, cid);
}

int sig_refusal(struct sig *s)
{
	return s->rc ? s->rc->refusal : 0;
}

void sig_withdraw(struct sig *s)
{
	if (s->rc)
		rdv_client_set_live(s->rc, 1);
}

void sig_end(struct sig *s)
{
	if (!s->is_host || !s->rh || s->rh->gone)
		return;
	rdv_host_entomb(s->rh);
	s->next_hput_ms = 0;		/* place it now, not on the next round */
	dbg_logf("sig: publishing the tombstone");
}

static int ending(const struct sig *s)
{
	return s->rh && s->rh->gone;
}

int sig_end_placed(struct sig *s)
{
	int placed = 1;

	if (!ending(s))
		return 0;
	/*
	 * Only a DHT that is actually up is waited on. One that was never there
	 * -- an isolated LAN, or a network that has just gone -- has no store to
	 * make, and holding the operator's shell for one that was never going to
	 * happen would tax every quit for a case that cannot succeed.
	 */
	if ((s->flags & SIG_DHT) && s->node && dhtnode_ready(s->node)) {
		placed = s->end_placed_wide;
		if ((s->fam[0].rnode_len || s->fam[1].rnode_len) &&
		    !s->end_placed_direct)
			placed = 0;
	}
	return placed;
}

int sig_tomb_settled(uint64_t tomb_ms, uint64_t info_ms, uint64_t now)
{
	if (!tomb_ms)
		return 0;
	/* Host info since the tombstone is a host still serving, whatever the
	 * slot says -- so the clock only runs while nothing has answered. */
	if (info_ms >= tomb_ms)
		return 0;
	return now - tomb_ms >= SIG_TOMB_SETTLE_MS;
}

int sig_peer_ended(struct sig *s)
{
	if (s->is_host)
		return 0;
	return sig_tomb_settled(s->tomb_seen_ms, s->info_seen_ms, now_ms());
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
	if (!s->node && engage_dht(s))
		return -1;
	return bep44_pin_add(s->engine, NULL, sa, len);
}

void sig_set_family_up(struct sig *s, int family, int up)
{
	s->fam[fam_of(family)].up = up;
}

void sig_set_gen(struct sig *s, uint32_t gen)
{
	s->my_gen = gen;
	if (s->rh) {
		rdv_host_set_gen(s->rh, gen);
		s->next_hput_ms = 0;
	}
}

void sig_set_family_epoch(struct sig *s, int family, uint32_t epoch)
{
	struct sig_fam *f = &s->fam[fam_of(family)];

	if (f->epoch == epoch)
		return;
	f->epoch = epoch;
	/* Held evidence was asked for on the network being left. */
	f->anchor_seen = 0;
	f->ack_new = 0;
}

uint32_t sig_peer_gen(const struct sig *s)
{
	return s->rc ? s->rc->host_gen : 0;
}

const uint8_t *sig_peer_cid(const struct sig *s)
{
	return s->rc && s->rc->have_host ? s->rc->host_cid : NULL;
}

int sig_locate(struct sig *s)
{
	if (!(s->flags & SIG_DHT))
		return -1;
	if (!s->node && engage_dht(s))
		return -1;
	s->locate = 1;
	return 0;
}

int sig_located(struct sig *s, int family, struct sockaddr *out,
		socklen_t *out_len)
{
	const struct sig_fam *f = &s->fam[fam_of(family)];

	if (!s->locate || !f->rnode_len || *out_len < f->rnode_len)
		return 0;
	memcpy(out, &f->rnode, f->rnode_len);
	*out_len = f->rnode_len;
	return 1;
}

int sig_dht_ready(struct sig *s)
{
	return s->node && dhtnode_ready(s->node);
}

int sig_take_ack(struct sig *s, int family, struct sockaddr *out,
		 socklen_t *out_len)
{
	struct sig_fam *f = &s->fam[fam_of(family)];

	if (!f->ack_new || !f->ack_node_len || *out_len < f->ack_node_len)
		return 0;
	memcpy(out, &f->ack_node, f->ack_node_len);
	*out_len = f->ack_node_len;
	f->ack_new = 0;
	return 1;
}

int sig_take_anchor_seen(struct sig *s, int family)
{
	struct sig_fam *f = &s->fam[fam_of(family)];
	int was = f->anchor_seen;

	f->anchor_seen = 0;
	return was;
}

void sig_relay(struct sig *s, int family, int on)
{
	s->fam[fam_of(family)].relay = on;
	if (on)
		s->locate = 1;		/* the get that follows is what captures */
}

void sig_search_again(struct sig *s, int family)
{
	/* The node we hold keeps being served while this runs: a rendezvous
	 * that vanishes is worse than a stale one, and the caller swaps it only
	 * once a different node has actually answered. */
	s->fam[fam_of(family)].relocate = 1;
}

void sig_forget(struct sig *s, int family)
{
	struct sig_fam *f = &s->fam[fam_of(family)];

	if (!f->rnode_len)
		return;
	if (s->node)
		bep44_pin_del(s->engine, (const struct sockaddr *)&f->rnode,
			      f->rnode_len);
	memset(&f->rnode, 0, sizeof(f->rnode));
	f->rnode_len = 0;
	f->ack_node_len = 0;
	f->relocate = 0;
	f->anchor_seen = 0;
	f->ack_new = 0;
	s->next_hput_ms = 0;
}

int sig_locating(struct sig *s, int family)
{
	if (!(s->flags & SIG_DHT) || !s->is_host || !s->locate ||
	    s->fam[fam_of(family)].rnode_len)
		return 0;
	/* Still actively pursued once the other family has proven the DHT
	 * reachable at all: there is no fixed point past which a family that
	 * has not answered yet is known to never will, so this stays true
	 * (still PENDING, not settled to NONE) until it is captured or the
	 * session ends. */
	return s->located_any;
}

int sig_reinforce(struct sig *s, int family, const struct sockaddr *sa,
		  socklen_t len)
{
	struct sig_fam *f = &s->fam[fam_of(family)];

	if ((size_t)len > sizeof(f->rnode))
		return -1;
	if (!(s->flags & SIG_DHT))
		return -1;
	if (!s->node && engage_dht(s))
		return -1;
	if (bep44_pin_add(s->engine, NULL, sa, len))
		return -1;
	if (f->rnode_len != len || memcmp(&f->rnode, sa, len)) {
		f->anchor_seen = 0;
		if (s->is_host && s->rh)
			s->rh->info_pending = 1;
	}
	memcpy(&f->rnode, sa, len);		/* adopt it as the located rendezvous, ... */
	f->rnode_len = len;
	f->relocate = 0;
	s->locate = 1;			/* ... so sig_located returns it and the get
					 * never re-captures a different one. A
					 * still-missing family is located as usual;
					 * once none is missing, dht_pump reinforces. */
	s->located_any = 1;
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
/* And one that has answered nothing at all, counted from engaging rather than
 * from a read there has never been. */
#define SIG_QUIET_COLD_MS 45000
#if SIG_QUIET_GONE_MS >= SIG_QUIET_MS
#error "an unasking node is the quicker verdict of the two"
#endif
#if SIG_QUIET_COLD_MS <= 3 * DHTNODE_BOOTSTRAP_FIRST_MS
#error "a cold signaller must outlast the opening bootstrap rounds"
#endif

int sig_quiet_due(int asking, int answered, uint64_t idle_ms)
{
	if (!answered)
		return idle_ms > SIG_QUIET_COLD_MS;
	if (!asking)
		return idle_ms > SIG_QUIET_GONE_MS;
	return idle_ms > SIG_QUIET_MS;
}

int sig_quiet(struct sig *s)
{
	if (!s || !s->node)
		return 0;
	/* Never answered is a verdict only where a family is proven to carry
	 * something: on an isolated LAN the DHT is meant to answer nothing, and
	 * that is not a signaller to throw away. */
	if (!s->last_get_ms && !s->fam[0].up && !s->fam[1].up)
		return 0;
	return sig_quiet_due(routes_now(s) != 0, s->last_get_ms != 0,
			     now_ms() - (s->last_get_ms ? s->last_get_ms :
							 s->engaged_ms));
}

static int claim_standing(const struct sig *s)
{
	if (!s->rc || !s->rc->have_host)
		return SIG_CLAIM_UNKNOWN;
	switch (s->rc->state) {
	case RDV_CL_OFFERED:
		return SIG_CLAIM_HELD;
	case RDV_CL_ANSWERED:
		return SIG_CLAIM_ANSWERED;
	case RDV_CL_REFUSED:
		return SIG_CLAIM_REFUSED;
	default:
		return SIG_CLAIM_FREE;
	}
}

static int claimants_seen(const struct sig *s)
{
	int i;

	if (!s->rh)
		return 0;
	for (i = 0; i < RDV_HOST_MAX; i++)
		if (s->rh->c[i].state != RDV_C_FREE)
			return 1;
	return 0;
}

void sig_mailbox_state(struct sig *s, struct sig_mailbox *out)
{
	memset(out, 0, sizeof(*out));
	if (!s)
		return;
	out->engaged = s->node != NULL;
	out->stage = s->rdv_stage;
	out->have_mine = s->is_host ? s->hval_len != 0 : s->my_packed_len != 0;
	out->mine_stored = s->mine_stored;
	out->peer_seen = s->is_host ? claimants_seen(s) :
				      (s->rc && s->rc->have_host);
	out->seq = s->h_seq;
	out->gets = s->gets_ok;
	out->puts = s->puts_ok;
	out->claim = claim_standing(s);
	out->last_get_ms = s->last_get_ms;
	out->last_put_ms = s->last_put_ms;
	out->engaged_ms = s->engaged_ms;
}

int sig_rdv_stage(struct sig *s, int family)
{
	if (s->fam[fam_of(family)].rnode_len)
		return 4;			/* RDV_READY, per family */
	return s->rdv_stage;			/* 0 cold .. 3 get, engine-wide */
}

static struct sig_op *op_alloc(struct sig *s, char kind, const uint8_t *cid,
			       int wide, int is_put)
{
	struct sig_op *op;
	int i;

	for (i = 0; i < SIG_OPS_MAX; i++) {
		op = &s->ops[i];
		if (op->busy)
			continue;
		memset(op, 0, sizeof(*op));
		op->s = s;
		op->kind = kind;
		if (cid)
			memcpy(op->cid, cid, RDV_CID_LEN);
		op->qep[0] = s->fam[0].epoch;
		op->qep[1] = s->fam[1].epoch;
		op->wide = (uint8_t)wide;
		op->is_put = (uint8_t)is_put;
		op->busy = 1;
		return op;
	}
	return NULL;
}

/* A read's callback fires once per family that served it, so a context is
 * released only after the dispatch that finished the operation. */
static void op_sweep(struct sig *s)
{
	int i;

	for (i = 0; i < SIG_OPS_MAX; i++)
		if (s->ops[i].busy && s->ops[i].done)
			s->ops[i].busy = 0;
}

static int rdv_open(const uint8_t key[32], const uint8_t *sealed, size_t slen,
		    struct rdv_msg *m)
{
	uint8_t plain[RDV_MAX_MSG];
	int n, rc;

	n = msg_open(plain, sizeof(plain), key, sealed, slen);
	if (n < 0)
		return -1;
	rc = rdv_decode(m, plain, (size_t)n);
	if (rc == RDV_ERR_VERSION)
		dbg_logf("sig: slot message is rdv v%u, this build reads v%u "
			 "-- ignored", (unsigned)plain[0], (unsigned)RDV_VERSION);
	return rc;
}

/* The cell carries two places: the host's own statement, which every holder
 * opens and which is how a client finds the host at all, and the one turn a
 * claimant exchange takes. A writer keeps the place it did not author. */
#define CELL_HOST "h"
#define CELL_TURN "c"

static int cell_part(const uint8_t *v, size_t v_len, const char *place,
		     const uint8_t **p, size_t *len)
{
	const uint8_t *val;
	size_t val_len;

	*p = NULL;
	*len = 0;
	if (!v || !v_len)
		return -1;
	if (benc_dict_find(v, v_len, place, &val, &val_len))
		return -1;
	return benc_str_get(val, val_len, p, len);
}

static int cell_pack(uint8_t *out, size_t max, const uint8_t *host,
		     size_t host_len, const uint8_t *turn, size_t turn_len)
{
	struct benc_buf b;

	benc_buf_init(&b, out, max);
	benc_raw_add(&b, "d", 1);
	if (turn && turn_len) {
		benc_key_add(&b, CELL_TURN);
		benc_str_add(&b, turn, turn_len);
	}
	if (host && host_len) {
		benc_key_add(&b, CELL_HOST);
		benc_str_add(&b, host, host_len);
	}
	benc_raw_add(&b, "e", 1);
	return b.err ? -1 : (int)b.len;
}

/* No instance id enters a class key, so a claimant the host has never met is
 * opened by trying each class and reading its cid from inside the seal. */
static int claimant_open(const struct sig *s, const uint8_t *v, size_t v_len,
			 struct rdv_msg *m, int *grade)
{
	uint8_t key[32];

	if (s->have_rw) {
		slot_key(s, SIG_GRADE_RW, key);
		if (!rdv_open(key, v, v_len, m)) {
			*grade = SIG_GRADE_RW;
			return 0;
		}
	}
	slot_key(s, SIG_GRADE_RO, key);
	if (!rdv_open(key, v, v_len, m)) {
		*grade = SIG_GRADE_RO;
		return 0;
	}
	return -1;
}

static int sdp_of(const struct rdv_msg *m, char *sdp, size_t max)
{
	int slen;

	slen = candpack_decode(m->payload, m->payload_len, NULL, NULL, 0, NULL,
			       sdp, max);
	if (slen == CANDPACK_ERR_VERSION)
		dbg_logf("sig: peer slot packs candpack v%u, this build reads "
			 "up to v%u -- ignored", (unsigned)m->payload[0],
			 (unsigned)CANDPACK_VERSION);
	else if (slen < 0)
		dbg_logf("sig: peer slot did not decode -- ignored");
	return slen;
}

/* Whether an answer from this family speaks for the network it is on now: a
 * reply to a query sent before a move says nothing about the one after it. */
static int ack_on_net(const struct sig *s, const struct sig_op *op, int af)
{
	return op->qep[fam_of_af(af)] == s->fam[fam_of_af(af)].epoch;
}

static void node_note(struct sig *s, const struct sig_op *op,
		      const struct sockaddr *node, socklen_t node_len)
{
	struct sig_fam *f;
	int captured = 0;

	if (!node || !node_len || (size_t)node_len > sizeof(f->rnode))
		return;
	if (node->sa_family != AF_INET && node->sa_family != AF_INET6)
		return;
	f = &s->fam[fam_of_af(node->sa_family)];
	/* It answered for itself. Nothing here is said about any other
	 * node: the convergent store puts the value on every k-close
	 * node, so several hold it and whichever is quickest replies. */
	if (ack_on_net(s, op, node->sa_family) && f->rnode_len == node_len &&
	    !memcmp(&f->rnode, node, node_len))
		f->anchor_seen = 1;
	if (ack_on_net(s, op, node->sa_family)) {
		memcpy(&f->ack_node, node, node_len);
		f->ack_node_len = node_len;
		f->ack_new = 1;
	}
	if (s->locate && !f->rnode_len) {
		memcpy(&f->rnode, node, node_len);
		f->rnode_len = node_len;
		captured = 1;
	}
	if (captured) {
		bep44_pin_add(s->engine, NULL, node, node_len);
		s->located_any = 1;
		/* A statement sealed before this one carries no node for a
		 * claimant to work the cell through, so it is said again. */
		if (s->is_host && s->rh)
			s->rh->info_pending = 1;
	}
}

/* The nodes the host says it is operating: pin them, so the next statement
 * goes to the node it reads rather than through a lookup of our own. */
static void host_nodes_seed(struct sig *s, const uint8_t *pl, size_t plen)
{
	struct sockaddr_storage ss;
	socklen_t len;
	size_t o;

	for (o = 0; o + CTL_RDV_PLEN <= plen; o += CTL_RDV_PLEN) {
		if (!ctl_rdv_decode(pl + o, CTL_RDV_PLEN, &ss, &len) || !len)
			continue;
		sig_seed_node(s, (const struct sockaddr *)&ss, len);
	}
}

/* The host place of the cell: the statement a client meets the host by. */
static int host_slot_read(struct sig *s, const uint8_t *v, size_t v_len,
			  int64_t seq)
{
	struct rdv_msg m;
	int moved;

	if (!v || !v_len)
		return 1;
	if (rdv_open(s->keys.sig_key, v, v_len, &m))
		return 1;
	if (m.kind != RDV_HOSTINFO && m.kind != RDV_TOMB)
		return 1;
	s->gets_ok++;
	s->last_get_ms = now_ms();
	if (s->is_host) {
		if (v_len != s->hval_len || memcmp(v, s->hval, v_len))
			s->h_stale = 1;
		else
			s->mine_stored = 1;
		if (seq > s->h_seq)
			s->h_seq = seq;
		return 0;
	}
	if (!s->rc)
		return 0;
	if (seq >= s->hcopy_seq) {
		memcpy(s->hcopy, v, v_len);
		s->hcopy_len = v_len;
		s->hcopy_seq = seq;
	}
	moved = rdv_client_host_slot(s->rc, &m, seq);
	if (moved < 0)
		return 0;
	if (seq > s->h_seq)
		s->h_seq = seq;
	if (m.kind == RDV_TOMB) {
		if (!s->tomb_seen_ms)
			s->tomb_seen_ms = s->last_get_ms;
		return 0;
	}
	s->info_seen_ms = s->last_get_ms;
	s->tomb_seen_ms = 0;
	host_nodes_seed(s, m.payload, m.payload_len);
	if (moved) {
		dbg_logf("sig: host instance %02x%02x%02x%02x gen %u",
			 m.from[0], m.from[1], m.from[2], m.from[3],
			 (unsigned)m.gen);
		s->next_put_ms = 0;
	}
	return 0;
}

static void claimant_read(struct sig *s, const uint8_t *v, size_t v_len,
			  int wide)
{
	struct rdv_claimant *c;
	char sdp[SIG_SDP_MAX];
	struct rdv_msg m;
	int grade, slen;

	if (!s->rh || claimant_open(s, v, v_len, &m, &grade))
		return;
	s->gets_ok++;
	s->last_get_ms = now_ms();
	if (m.kind != RDV_OFFER)
		return;
	if (!rdv_host_slot(s->rh, &m))
		return;
	c = rdv_host_find(s->rh, m.from);
	if (c) {
		c->grade = (uint8_t)grade;
		/* It is reachable the way its ask arrived, and a claimant on a
		 * token naming no node is reachable no other way. */
		c->wide_ask = (uint8_t)(wide != 0);
	}
	slen = sdp_of(&m, sdp, sizeof(sdp));
	if (slen < 0)
		return;
	sig_mb_note("GET offer", m.from, sdp);
	if (s->cb)
		s->cb(s->arg, m.from, (const uint8_t *)sdp, (size_t)slen);
}

static void answer_read(struct sig *s, const uint8_t *v, size_t v_len,
			int64_t seq)
{
	char sdp[SIG_SDP_MAX];
	struct rdv_msg m;
	uint8_t key[32];
	int slen;

	if (!s->rc)
		return;
	slot_key(s, my_grade(s), key);
	/* Whatever the turn carries, it is not the ask we left there. */
	if (rdv_open(key, v, v_len, &m)) {
		rdv_client_ask_gone(s->rc, seq);
		return;
	}
	s->gets_ok++;
	s->last_get_ms = now_ms();
	if (!memcmp(m.from, s->rc->cid, RDV_CID_LEN))
		return;
	if (!rdv_client_would_take(s->rc, &m)) {
		if (m.kind == RDV_ANSWER || m.kind == RDV_REFUSE)
			dbg_logf("sig: not ours to take -- %s (re=%u ours=%u "
				 "prev=%u taken=%u)",
				 rdv_client_refusal_name(
					 rdv_client_refusal(s->rc, &m)),
				 (unsigned)m.re, (unsigned)s->rc->offer_seq,
				 (unsigned)s->rc->prev_offer_seq,
				 (unsigned)s->rc->answer_seq);
		rdv_client_ask_gone(s->rc, seq);
		return;
	}
	/* Decoded before it is taken: an answer we cannot read must leave us
	 * asking, not holding a sequence nothing will ever come of. */
	slen = m.kind == RDV_REFUSE ? 0 : sdp_of(&m, sdp, sizeof(sdp));
	if (slen < 0) {
		rdv_client_answer_unusable(s->rc, &m);
		return;
	}
	if (!rdv_client_own_slot(s->rc, &m))
		return;
	if (m.kind == RDV_REFUSE) {
		dbg_logf("sig: the host refused us (%u)",
			 (unsigned)s->rc->refusal);
		return;
	}
	sig_mb_note("GET answer", m.from, sdp);
	if (s->cb)
		s->cb(s->arg, m.from, (const uint8_t *)sdp, (size_t)slen);
}

static void on_slot_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq,
			const struct sockaddr *node, socklen_t node_len)
{
	struct sig_op *op = arg;
	int first = !op->done;
	struct sig *s = op->s;
	const uint8_t *part;
	size_t part_len;

	op->done = 1;
	if (!v)
		return;
	node_note(s, op, node, node_len);
	if (!first)
		return;
	if (!cell_part(v, v_len, CELL_HOST, &part, &part_len))
		host_slot_read(s, part, part_len, seq);
	if (cell_part(v, v_len, CELL_TURN, &part, &part_len)) {
		if (!s->is_host && s->rc)
			rdv_client_ask_gone(s->rc, seq);
		return;
	}
	/* Whose turn it is is discovered, not asked for: one that opens under
	 * neither of our keys is another claimant's. */
	if (s->is_host)
		claimant_read(s, part, part_len, op->wide);
	else
		answer_read(s, part, part_len, seq);
}

static void on_slot_put(void *arg, int stored, const struct sockaddr *node,
			socklen_t node_len)
{
	struct sig_op *op = arg;
	struct sig *s = op->s;

	(void)node;
	(void)node_len;
	op->done = 1;
	switch (op->kind) {
	case RDV_TOMB:
		dbg_logf("sig: tombstone stored %s -> %d node(s)",
			 op->wide ? "where the key belongs" :
				    "on the rendezvous node", stored);
		if (stored > 0 && op->wide)
			s->end_placed_wide = 1;
		else if (stored > 0)
			s->end_placed_direct = 1;
		break;
	case RDV_HOSTINFO:
		if (!s->is_host)
			break;
		if (stored > 0) {
			s->mine_stored = 1;
			s->h_stale = 0;
			if (op->free_turn && s->rh)
				rdv_host_turn_kept(s->rh);
		}
		if (stored > 0 && op->wide) {
			s->next_hput_ms = now_ms() + SIG_DHT_RESTORE_MS;
			if (s->rdv_stage < 3)
				s->rdv_stage = 3;	/* stored: now reading it back */
		}
		break;
	case RDV_ANSWER:
		if (stored > 0 || !s->rh)
			break;
		rdv_host_unsent(s->rh, op->cid);
		break;
	case RDV_OFFER:
		if (stored > 0)
			s->mine_stored = 1;
		break;
	default:
		break;
	}
}

/*
 * A claimant takes the turn when it is free, to replace an ask of its own
 * under a different number, over an answer the host addressed to somebody else,
 * and over one addressed to it that it has already taken -- a client coming
 * back from a move has to get its new ask in without waiting on the host to
 * hand the turn back. An answer it has not read, it reads: written over before
 * that, it leaves both ends waiting on each other. A rival's ask standing
 * there is its turn, and waiting is the queue.
 */
static int turn_is_ours(const struct sig *s, const uint8_t *turn,
			size_t turn_len)
{
	struct rdv_msg m;
	int opened;
	int grade;

	if (!turn || !turn_len || !s->rc)
		return 1;
	opened = !claimant_open(s, turn, turn_len, &m, &grade);

	return rdv_client_may_replace(s->rc, &m, opened);
}

static int writes_host_place(char kind)
{
	return kind == RDV_HOSTINFO || kind == RDV_TOMB;
}

static int merge_mine(void *arg, const uint8_t *cur, size_t cur_len,
		      int64_t seq, uint8_t *out, size_t *out_len, size_t max)
{
	const uint8_t *host, *turn;
	size_t host_len, turn_len;
	struct sig_op *op = arg;
	int n;

	if (op->seq_seen >= 0 && cur && seq > op->seq_seen)
		return -1;
	cell_part(cur, cur_len, CELL_HOST, &host, &host_len);
	cell_part(cur, cur_len, CELL_TURN, &turn, &turn_len);
	if (writes_host_place(op->kind)) {
		host = op->val;
		host_len = op->val_len;
		/* A tombstone ends the session, and a host with nobody engaged
		 * hands the turn back to whoever asks next. */
		if (op->kind == RDV_TOMB || op->free_turn) {
			turn = NULL;
			turn_len = 0;
		}
	} else {
		if (op->kind == RDV_OFFER && !turn_is_ours(op->s, turn, turn_len))
			return -1;
		turn = op->val;
		turn_len = op->val_len;
	}
	n = cell_pack(out, max, host, host_len, turn, turn_len);
	if (n <= 0)
		return -1;
	*out_len = (size_t)n;
	return 0;
}

static int slot_get(struct sig *s, int wide)
{
	char salt[KEYS_SALT_LEN];
	struct sig_op *op;
	int rc;

	op = op_alloc(s, 0, NULL, wide, 0);
	if (!op)
		return -1;
	slot_salt(s, salt);
	if (wide)
		rc = bep44_get(s->engine, s->keys.bep44_pk, salt, on_slot_get,
			       op);
	else
		rc = bep44_get_direct(s->engine, s->keys.bep44_pk, salt,
				      on_slot_get, op);
	if (rc)
		op->busy = 0;
	return rc;
}

/* `kind` is the statement written, for what the store's outcome means. */
static int slot_put(struct sig *s, char kind, const uint8_t *cid, int wide,
		    const uint8_t *val, size_t val_len, int64_t seq_seen)
{
	char salt[KEYS_SALT_LEN];
	struct sig_op *op;
	int rc;

	if (val_len > SIG_WIRE_MAX)
		return -1;
	op = op_alloc(s, kind, cid, wide, 1);
	if (!op)
		return -1;
	if (s->is_host && s->rh && writes_host_place(kind))
		op->free_turn = rdv_host_turn_spent(s->rh);
	memcpy(op->val, val, val_len);
	op->val_len = val_len;
	op->seq_seen = seq_seen;
	slot_salt(s, salt);
	if (wide)
		rc = bep44_update(s->engine, s->keys.bep44_sk,
				  s->keys.bep44_pk, salt, merge_mine, op,
				  on_slot_put, op);
	else
		rc = bep44_update_direct(s->engine, s->keys.bep44_sk,
					 s->keys.bep44_pk, salt, merge_mine,
					 op, on_slot_put, op);
	if (rc) {
		op->busy = 0;
		return rc;
	}
	s->puts_ok++;
	s->last_put_ms = now_ms();
	return 0;
}

/* Two stores in flight read the same sequence and write the same next one, so
 * every node refuses the second. One cell, so any store excludes any other. */
static int slot_inflight(const struct sig *s)
{
	const struct sig_op *op;
	int i;

	for (i = 0; i < SIG_OPS_MAX; i++) {
		op = &s->ops[i];
		if (op->busy && !op->done && op->is_put)
			return 1;
	}
	return 0;
}

static int seal_to(const uint8_t key[32], const struct rdv_out *o,
		   uint8_t *out, size_t max)
{
	return msg_seal(out, max, key, o->msg, o->len);
}

/* The nodes the host is operating, for a claimant that converged on the key to
 * go direct with instead of paying a lookup for every statement. */
static size_t host_info_nodes(const struct sig *s, uint8_t *out, size_t max)
{
	static const int famv[2] = { 4, 6 };
	size_t n = 0;
	int i;

	for (i = 0; i < 2; i++) {
		if (!s->fam[i].rnode_len || n + CTL_RDV_PLEN > max)
			continue;
		ctl_rdv_encode(out + n, famv[i],
			       (const struct sockaddr *)&s->fam[i].rnode);
		n += CTL_RDV_PLEN;
	}
	return n;
}

/* The host's next statement, sealed and due. */
static void host_info_seal(struct sig *s)
{
	uint8_t info[RDV_HOST_PAYLOAD];
	struct rdv_out o;
	size_t ilen;
	int n;

	ilen = host_info_nodes(s, info, sizeof(info));
	if (!rdv_host_next(s->rh, info, ilen, &o) || o.seal != RDV_SEAL_INFO)
		return;
	n = seal_to(s->keys.sig_key, &o, s->hval, sizeof(s->hval));
	if (n <= 0)
		return;
	s->hval_len = (size_t)n;
	s->h_stale = 1;
	s->mine_stored = 0;
	s->next_hput_ms = 0;
}

/* Each answer or refusal due takes the cell in turn; one that finds a store in
 * flight, or no route yet, waits a tick. */
static void host_answers(struct sig *s, unsigned routes)
{
	struct rdv_claimant *held[RDV_HOST_MAX];
	uint8_t val[SIG_WIRE_MAX];
	struct rdv_claimant *c;
	int nheld = 0, i, n;
	struct rdv_msg m;
	struct rdv_out o;
	uint8_t key[32];

	while (nheld < RDV_HOST_MAX && rdv_host_next(s->rh, NULL, 0, &o)) {
		if (o.seal != RDV_SEAL_CLASS || rdv_decode(&m, o.msg, o.len))
			continue;
		c = rdv_host_find(s->rh, m.to);
		if (!c)
			continue;
		if (!routes || slot_inflight(s)) {
			held[nheld++] = c;
			continue;
		}
		slot_key(s, c->grade == SIG_GRADE_RO ? SIG_GRADE_RO :
						       SIG_GRADE_RW, key);
		n = seal_to(key, &o, val, sizeof(val));
		if (n < 0 ||
		    slot_put(s, RDV_ANSWER, m.to, c->wide_ask, val, (size_t)n,
			     -1))
			held[nheld++] = c;
	}
	for (i = 0; i < nheld; i++)
		rdv_host_unsent(s->rh, held[i]->cid);
}

static void host_tomb_put(struct sig *s, unsigned routes, uint64_t now)
{
	int held = s->fam[0].rnode_len || s->fam[1].rnode_len;

	/*
	 * The rendezvous node answers a client holding this invitation first,
	 * and the k-closest are where a token naming no node leads one, so a
	 * tombstone only one of them can see leaves the other waiting.
	 */
	if (!s->end_placed_direct && held)
		slot_put(s, RDV_TOMB, NULL, 0, s->hval, s->hval_len, -1);
	else if ((routes & SIG_ROUTE_WIDE) && !s->end_placed_wide)
		slot_put(s, RDV_TOMB, NULL, 1, s->hval, s->hval_len, -1);
	s->next_hput_ms = now + SIG_DHT_TOMB_MS;
}

static void host_slot_put(struct sig *s, unsigned routes, uint64_t now)
{
	int missing, eager;

	/* The cheap path: the rendezvous node already holds this key, so a
	 * re-store to it costs a round trip and no lookup. */
	if (s->h_stale && (routes & SIG_ROUTE_DIRECT) &&
	    (s->fam[0].rnode_len || s->fam[1].rnode_len)) {
		slot_put(s, RDV_HOSTINFO, NULL, 0, s->hval, s->hval_len, -1);
		s->next_hput_ms = now + SIG_DHT_PUT_MS;
		return;
	}
	/*
	 * A reachable family with no anchor yet is still being located:
	 * the convergent store places the cell on its k-closest nodes
	 * (idiomatic and discoverable) and the validating get captures
	 * one as the anchor. It repeats until that family is captured --
	 * the v6 DHT converges later than v4, so an early store misses
	 * its k-closest. It keeps retrying for as long as it takes rather
	 * than giving up on a timing guess: eager for as long as a still-
	 * missing family's own connectivity is proven up (sig_set_family_up),
	 * slower otherwise, never stopping outright. An already-anchored
	 * family is never re-located.
	 */
	missing = !s->fam[0].rnode_len || !s->fam[1].rnode_len ||
		  s->fam[0].relocate || s->fam[1].relocate;
	if (missing && (routes & SIG_ROUTE_WIDE)) {
		eager = ((!s->fam[0].rnode_len || s->fam[0].relocate) &&
			 s->fam[0].up) ||
			((!s->fam[1].rnode_len || s->fam[1].relocate) &&
			 s->fam[1].up);
		if (s->rdv_stage < 2)
			s->rdv_stage = 2;	/* placing the cell */
		slot_put(s, RDV_HOSTINFO, NULL, 1, s->hval, s->hval_len, -1);
		s->next_hput_ms = now + (eager ? SIG_DHT_PUT_MS :
						 SIG_DHT_PUT_SLOW_MS);
		return;
	}
	if ((routes & SIG_ROUTE_WIDE) && now >= s->next_wide_put_ms) {
		/*
		 * The value where the key says it belongs, not only
		 * where it first landed. Which nodes are closest drifts
		 * as the DHT churns, and a client that has to converge
		 * -- an old token, or one that never named a node --
		 * finds whoever is closest now, so the value has to be
		 * there and not merely on the handful we pinned once.
		 */
		slot_put(s, RDV_HOSTINFO, NULL, 1, s->hval, s->hval_len, -1);
		s->next_wide_put_ms = now + SIG_DHT_WIDE_PUT_MS;
		s->next_hput_ms = now + SIG_DHT_PUT_MS;
	}
}

static void host_pump_puts(struct sig *s, unsigned routes, uint64_t now)
{
	if (!s->rh)
		return;
	if (s->rh->info_pending)
		host_info_seal(s);
	if (!ending(s) && now >= s->next_put_ms) {
		host_answers(s, routes);
		s->next_put_ms = now + SIG_DHT_PUT_MS;
	}
	if (!s->hval_len || now < s->next_hput_ms ||
	    slot_inflight(s))
		return;
	if (ending(s))
		host_tomb_put(s, routes, now);
	else
		host_slot_put(s, routes, now);
}

static int relaying(const struct sig *s)
{
	return s->fam[0].relay || s->fam[1].relay;
}

/* Still looking for the node, as opposed to operating one we have. Only the
 * search is urgent: the peer is waiting on it and has nothing meanwhile. */
static int relay_locating(const struct sig *s)
{
	return (s->fam[0].relay && !s->fam[0].rnode_len) ||
	       (s->fam[1].relay && !s->fam[1].rnode_len);
}

static void client_pump_puts(struct sig *s, unsigned routes, uint64_t now)
{
	uint8_t val[SIG_WIRE_MAX];
	struct rdv_out o;
	uint8_t key[32];
	int n;

	if (!s->rc || now < s->next_put_ms)
		return;
	if ((routes & SIG_ROUTE_DIRECT) && !slot_inflight(s) &&
	    rdv_client_next(s->rc, s->my_packed, s->my_packed_len, &o)) {
		slot_key(s, my_grade(s), key);
		n = seal_to(key, &o, val, sizeof(val));
		if (n > 0)
			slot_put(s, RDV_OFFER, s->rc->cid, 0, val, (size_t)n,
				 -1);
		s->next_put_ms = now + SIG_DHT_PUT_MS;
		return;
	}
	if (!relaying(s) || !s->hcopy_len || slot_inflight(s))
		return;
	if (relay_locating(s) && (routes & SIG_ROUTE_WIDE)) {
		slot_put(s, RDV_HOSTINFO, NULL, 1, s->hcopy, s->hcopy_len,
			 s->hcopy_seq);
		s->next_put_ms = now + SIG_DHT_PUT_MS;
	} else if (routes & SIG_ROUTE_DIRECT) {
		slot_put(s, RDV_HOSTINFO, NULL, 0, s->hcopy, s->hcopy_len,
			 s->hcopy_seq);
		s->next_put_ms = now + SIG_DHT_RELAY_MS;
	}
}

/* One cell, so one read tells the host everything: its own statement still
 * standing, or whichever claimant has taken the turn. */
static void host_read(struct sig *s)
{
	s->read_turn++;
	slot_get(s, 0);
}

static void client_read(struct sig *s)
{
	s->read_turn++;
	slot_get(s, 0);
}

static int warming(const struct sig *s)
{
	return (s->fam[0].up && !s->fam[0].ack_node_len) ||
	       (s->fam[1].up && !s->fam[1].ack_node_len);
}

static void dht_pump(struct sig *s, uint64_t now)
{
	unsigned routes = routes_now(s);
	int seen;

	if (s->routeless != !routes) {
		s->routeless = !routes;
		dbg_logf("sig: %s to work the mailbox through",
			 routes ? "a route" : "no route");
	}
	if (!routes)
		return;
	if ((routes & SIG_ROUTE_WIDE) && s->rdv_stage < 1)
		s->rdv_stage = 1;		/* DHT warm: nodes found near key */
	if (now >= s->next_get_ms) {
		if (s->is_host)
			host_read(s);
		else
			client_read(s);
		s->next_get_ms = now + SIG_DHT_GET_MS;
	}
	if ((routes & SIG_ROUTE_WIDE) && now >= s->next_wide_get_ms) {
		slot_get(s, 1);
		seen = s->is_host ? s->mine_stored : (s->rc && s->rc->have_host);
		s->next_wide_get_ms = now +
			((seen && !relay_locating(s) && !warming(s)) ?
			 SIG_DHT_WIDE_IDLE_MS : SIG_DHT_WIDE_GET_MS);
	}
	if (s->is_host)
		host_pump_puts(s, routes, now);
	else
		client_pump_puts(s, routes, now);
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

static void direct_fire(struct sig *s, const struct sockaddr *src,
			socklen_t srclen, uint16_t dport, const char *sdp,
			size_t slen)
{
	struct sockaddr_storage ep;

	if (!s->direct_cb || !dport || !addr_is_lan_scope(src) ||
	    (size_t)srclen > sizeof(ep))
		return;
	memcpy(&ep, src, srclen);
	if (ep.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&ep)->sin6_port = htons(dport);
	else
		((struct sockaddr_in *)&ep)->sin_port = htons(dport);
	s->direct_cb(s->direct_arg, (struct sockaddr *)&ep, srclen,
		     (const uint8_t *)sdp, slen);
}

static int mcast_open(const uint8_t key[32], const char *salt,
		      const uint8_t *data, size_t len, uint16_t *dport,
		      struct rdv_msg *m)
{
	uint8_t plain[2 + RDV_MAX_MSG];
	int n;

	n = msg_open_ad(plain, sizeof(plain), key, (const uint8_t *)salt, 1,
			data, len);
	if (n < 3)
		return -1;
	*dport = (uint16_t)((plain[0] << 8) | plain[1]);
	return rdv_decode(m, plain + 2, (size_t)n - 2);
}

static void deliver_host_mcast(struct sig *s, const uint8_t *data, size_t len,
			       const struct sockaddr *src, socklen_t srclen)
{
	struct rdv_msg m;
	uint16_t dport;

	if (mcast_open(s->keys.sig_key, "h", data, len, &dport, &m))
		return;
	if (m.kind != RDV_HOSTINFO)
		return;
	direct_fire(s, src, srclen, dport, "", 0);
}

static void deliver_claim_mcast(struct sig *s, const uint8_t *data, size_t len,
				const struct sockaddr *src, socklen_t srclen)
{
	struct rdv_claimant *c;
	char sdp[SIG_SDP_MAX];
	const uint8_t *cid;
	int n, slen, grade;
	struct rdv_msg m;
	uint8_t key[32];
	uint16_t dport;

	if (len <= RDV_CID_LEN)
		return;
	cid = data;
	data += RDV_CID_LEN;
	len -= RDV_CID_LEN;
	grade = SIG_GRADE_RW;
	slot_key(s, grade, key);
	n = mcast_open(key, "c", data, len, &dport, &m);
	if (n) {
		grade = SIG_GRADE_RO;
		slot_key(s, grade, key);
		n = mcast_open(key, "c", data, len, &dport, &m);
	}
	if (n || m.kind != RDV_OFFER || memcmp(m.from, cid, RDV_CID_LEN))
		return;
	slen = sdp_of(&m, sdp, sizeof(sdp));
	if (slen < 0)
		return;
	if (!s->mcast_claims && s->rh && rdv_host_slot(s->rh, &m)) {
		c = rdv_host_find(s->rh, cid);
		if (c)
			c->grade = (uint8_t)grade;
		if (s->cb)
			s->cb(s->arg, cid, (const uint8_t *)sdp, (size_t)slen);
	}
	direct_fire(s, src, srclen, dport, sdp, (size_t)slen);
}

static void on_mcast_recv(void *arg, const char *salt, const uint8_t *data,
			  size_t len, const struct sockaddr *src,
			  socklen_t srclen)
{
	struct sig *s = arg;

	if (s->is_host && !strcmp(salt, "c"))
		deliver_claim_mcast(s, data, len, src, srclen);
	else if (!s->is_host && !strcmp(salt, "h"))
		deliver_host_mcast(s, data, len, src, srclen);
}

static int mcast_frame(struct sig *s, uint8_t *out, size_t max,
		       const char **salt)
{
	uint8_t plain[2 + RDV_MAX_MSG];
	struct rdv_msg m;
	uint8_t key[32];
	size_t o;
	int n;

	memset(&m, 0, sizeof(m));
	plain[0] = (uint8_t)(s->direct_port >> 8);
	plain[1] = (uint8_t)s->direct_port;
	if (s->is_host) {
		if (!s->rh)
			return -1;
		m.kind = RDV_HOSTINFO;
		m.gen = s->rh->gen;
		memcpy(m.from, s->rh->cid, RDV_CID_LEN);
		n = rdv_encode(&m, plain + 2, sizeof(plain) - 2);
		if (n < 0)
			return -1;
		*salt = "h";
		return msg_seal_ad(out, max, s->keys.sig_key,
				   (const uint8_t *)"h", 1, plain,
				   (size_t)n + 2);
	}
	if (!s->rc || !s->my_packed_len || max < RDV_CID_LEN)
		return -1;
	m.kind = RDV_OFFER;
	m.gen = s->rc->host_gen;
	memcpy(m.from, s->rc->cid, RDV_CID_LEN);
	if (s->rc->have_host)
		memcpy(m.to, s->rc->host_cid, RDV_CID_LEN);
	memcpy(m.payload, s->my_packed, s->my_packed_len);
	m.payload_len = (uint16_t)s->my_packed_len;
	n = rdv_encode(&m, plain + 2, sizeof(plain) - 2);
	if (n < 0)
		return -1;
	memcpy(out, s->rc->cid, RDV_CID_LEN);
	o = RDV_CID_LEN;
	slot_key(s, my_grade(s), key);
	n = msg_seal_ad(out + o, max - o, key, (const uint8_t *)"c", 1, plain,
			(size_t)n + 2);
	if (n < 0)
		return -1;
	*salt = "c";
	return (int)o + n;
}

static void mcast_pump(struct sig *s, uint64_t now)
{
	uint8_t frame[SIG_MCAST_MAX];
	const char *salt;
	int n;

	/* Nothing is announced once the session is over: what a peer needs to
	 * hear on a segment is that the offer has stopped. */
	if (ending(s) || now < s->next_mcast_ms)
		return;
	n = mcast_frame(s, frame, sizeof(frame), &salt);
	if (n > 0)
		sig_mcast_send(s->mc, salt, frame, (size_t)n);
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
	if ((s->flags & SIG_DHT) && !s->node &&
	    (!s->mc || now - s->start_ms > SIG_DHT_GRACE_MS) &&
	    now >= s->next_dht_open_ms) {
		engage_dht(s);
		s->next_dht_open_ms = now + SIG_DHT_OPEN_MS;
	}

	if (s->node) {
		dhtnode_dispatch(s->node, fds, nfds);
		dht_pump(s, now);
		op_sweep(s);
	}
}
