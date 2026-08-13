/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

static int b44_debug = -1;

static int debug_on(void)
{
	if (b44_debug < 0)
		b44_debug = getenv("COMRADE_BEP44_DEBUG") ? 1 : 0;
	return b44_debug;
}

#include <monocypher-ed25519.h>

#include "bencode.h"
#include "bep44.h"
#include "sha1.h"

/*
 * Query concurrency is budgeted per family (see op_step): the v4 DHT is dense,
 * so a shared cap lets v4 crowd out the sparse v6 branch. Give v6 the larger
 * ALPHA so its lookups fan out wide enough to converge quickly; the request
 * table holds both families at once. A tighter per-request timeout drops slow
 * or dead nodes sooner and moves on, and the deeper node list keeps v6 nodes
 * -- which sort further from the target than the plentiful v4 ones -- from
 * being evicted before they are queried.
 */
#define B44_ALPHA_V4 16
#define B44_ALPHA_V6 32
#define B44_K 8
#define B44_NODES_MAX 192
#define B44_BOOTSTRAP_MAX 8
#define B44_REQS_MAX (B44_ALPHA_V4 + B44_ALPHA_V6)
#define B44_REQ_TIMEOUT_MS 1000
#define B44_OP_TIMEOUT_MS 30000
#define B44_TOKEN_MAX 40
#define B44_MSG_MAX 1400
#define B44_SEEDS_MAX 16
#define B44_PINNED_MAX 8
#define B44_RETAINED_MAX 8

enum b44_node_state {
	B44_NODE_FRESH,
	B44_NODE_INFLIGHT,
	B44_NODE_REPLIED,
	B44_NODE_FAILED,
	B44_NODE_STORE_INFLIGHT,
	B44_NODE_STORED,
};

enum b44_phase {
	B44_PHASE_LOOKUP,
	B44_PHASE_STORE,
};

struct b44_node {
	uint8_t id[20];
	uint8_t dist[20];
	struct sockaddr_storage ss;
	socklen_t sslen;
	uint8_t state;
	uint8_t token[B44_TOKEN_MAX];
	uint8_t token_len;
};

struct b44_req {
	uint8_t in_use;
	uint8_t node;
	uint16_t tid;
	uint64_t sent_ms;
};

struct b44_op {
	struct b44_op *next;
	struct bep44_engine *e;
	uint8_t is_put;
	uint8_t is_update;		/* get, then merge, then put on same nodes */
	uint8_t direct;			/* rendezvous mode: talk only to the seeded
					 * and pinned nodes, never converge toward
					 * the target (no find_node expansion) */
	bep44_merge_fn *merge;
	void *merge_arg;
	uint8_t phase;
	uint8_t target[20];
	uint8_t pk[32];
	uint8_t sk[64];
	char salt[BEP44_MAX_SALT + 1];
	uint8_t value[BEP44_MAX_VALUE];
	uint16_t value_len;
	int64_t seq;
	int64_t cas;		/* compare-and-swap expected seq, -1 = none */
	uint8_t best[BEP44_MAX_VALUE];
	uint16_t best_len;
	int64_t best_seq;
	uint8_t have_best;
	struct sockaddr_storage best_node;	/* who first served the value */
	socklen_t best_node_len;
	struct b44_node nodes[B44_NODES_MAX];
	uint8_t nnodes;
	struct b44_req reqs[B44_REQS_MAX];
	uint64_t start_ms;
	int stored;
	bep44_put_cb *put_cb;
	bep44_get_cb *get_cb;
	void *cb_arg;
};

struct b44_seed {
	uint8_t id[20];
	struct sockaddr_storage ss;
	socklen_t sslen;
	uint8_t in_use;
	uint8_t has_id;
};

struct bep44_engine {
	uint8_t myid[20];
	int s4;
	int s6;
	uint16_t tid_seq;
	struct sockaddr_storage bootstrap[B44_BOOTSTRAP_MAX];
	socklen_t bootstrap_len[B44_BOOTSTRAP_MAX];
	int nbootstrap;
	struct b44_seed seeds[B44_SEEDS_MAX];
	int seed_next;
	/*
	 * Pinned nodes (rendezvous hints from a token). Unlike seeds, which are
	 * a cycling ring the routing-table cache overwrites, pinned nodes are
	 * never overwritten and never aged: they are injected into the initial
	 * node set of EVERY op, so a token-supplied node is tried on every
	 * query for the life of the engine, with the global DHT as fallback.
	 */
	struct b44_seed pinned[B44_PINNED_MAX];
	int npinned;
	/*
	 * Closest nodes retained from finished lookups, in a ring the routing
	 * cache does not touch (unlike seeds), so a get right after a put stays
	 * converged instead of being cold.
	 */
	struct b44_seed retained[B44_RETAINED_MAX];
	int retain_next;
	struct b44_op *ops;
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

size_t bep44_sig_buffer(uint8_t *dst, size_t dst_len, const char *salt,
			int64_t seq, const uint8_t *v, size_t v_len)
{
	struct benc_buf b;
	size_t salt_len = salt ? strlen(salt) : 0;

	benc_buf_init(&b, dst, dst_len);
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

void bep44_target(uint8_t target[20], const uint8_t pk[32], const char *salt)
{
	struct sha1_ctx ctx;

	sha1_init(&ctx);
	sha1_update(&ctx, pk, 32);
	if (salt)
		sha1_update(&ctx, salt, strlen(salt));
	sha1_final(&ctx, target);
}

struct bep44_engine *bep44_create(const uint8_t myid[20], int s4, int s6)
{
	struct bep44_engine *e = calloc(1, sizeof(*e));

	if (!e)
		return NULL;
	memcpy(e->myid, myid, 20);
	e->s4 = s4;
	e->s6 = s6;
	return e;
}

static void op_free(struct bep44_engine *e, struct b44_op *op)
{
	struct b44_op **p = &e->ops;

	while (*p && *p != op)
		p = &(*p)->next;
	if (*p)
		*p = op->next;
	free(op);
}

void bep44_free(struct bep44_engine *e)
{
	while (e->ops)
		op_free(e, e->ops);
	free(e);
}

int bep44_bootstrap_add(struct bep44_engine *e, const struct sockaddr *sa,
			socklen_t salen)
{
	if (e->nbootstrap >= B44_BOOTSTRAP_MAX || salen > sizeof(e->bootstrap[0]))
		return -1;
	memcpy(&e->bootstrap[e->nbootstrap], sa, salen);
	e->bootstrap_len[e->nbootstrap] = salen;
	e->nbootstrap++;
	return 0;
}

static int msg_send(struct bep44_engine *e, const struct sockaddr_storage *ss,
		    socklen_t sslen, const uint8_t *buf, size_t len)
{
	int s = ss->ss_family == AF_INET6 ? e->s6 : e->s4;

	if (s < 0)
		return -1;
	return (int)sendto(s, buf, len, 0, (const struct sockaddr *)ss, sslen);
}

static void dist_calc(uint8_t dist[20], const uint8_t id[20],
		      const uint8_t target[20])
{
	int i;

	for (i = 0; i < 20; i++)
		dist[i] = id[i] ^ target[i];
}

static int node_insert(struct b44_op *op, const uint8_t *id,
		       const struct sockaddr *sa, socklen_t salen, int pinned)
{
	uint8_t dist[20];
	int i, pos;

	/*
	 * Once a node's id is known it ranks by true XOR distance, pinned or
	 * not (a rendezvous node is close to its target, so it sorts near the
	 * front naturally). A pinned node whose id we have not learned yet is
	 * ranked at distance zero so it is queried first and reveals its id;
	 * an ordinary id-less node (routing cache) ranks last instead.
	 */
	if (id)
		dist_calc(dist, id, op->target);
	else if (pinned)
		memset(dist, 0, sizeof(dist));
	else
		memset(dist, 0xff, sizeof(dist));

	for (i = 0; i < op->nnodes; i++) {
		if (op->nodes[i].sslen == salen &&
		    !memcmp(&op->nodes[i].ss, sa, salen))
			return 0;
		if (id && !memcmp(op->nodes[i].id, id, 20))
			return 0;
	}

	for (pos = 0; pos < op->nnodes; pos++) {
		if (memcmp(dist, op->nodes[pos].dist, 20) < 0)
			break;
	}
	if (pos >= B44_NODES_MAX)
		return 0;
	if (op->nnodes >= B44_NODES_MAX) {
		uint8_t tail = op->nodes[B44_NODES_MAX - 1].state;

		if (tail == B44_NODE_INFLIGHT || tail == B44_NODE_STORE_INFLIGHT)
			return 0;
		op->nnodes = B44_NODES_MAX - 1;
	}
	memmove(&op->nodes[pos + 1], &op->nodes[pos],
		(size_t)(op->nnodes - pos) * sizeof(op->nodes[0]));
	memset(&op->nodes[pos], 0, sizeof(op->nodes[0]));
	if (id)
		memcpy(op->nodes[pos].id, id, 20);
	memcpy(op->nodes[pos].dist, dist, 20);
	memcpy(&op->nodes[pos].ss, sa, salen);
	op->nodes[pos].sslen = salen;
	op->nodes[pos].state = B44_NODE_FRESH;
	op->nnodes++;

	for (i = 0; i < B44_REQS_MAX; i++) {
		if (op->reqs[i].in_use && op->reqs[i].node >= pos)
			op->reqs[i].node++;
	}
	return 1;
}

static void nodes_compact_add(struct b44_op *op, const uint8_t *data,
			      size_t len, int af)
{
	size_t entry = af == AF_INET ? 26 : 38;
	size_t i;

	for (i = 0; i + entry <= len; i += entry) {
		const uint8_t *p = data + i;

		if (af == AF_INET) {
			struct sockaddr_in sin;

			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			memcpy(&sin.sin_addr, p + 20, 4);
			memcpy(&sin.sin_port, p + 24, 2);
			node_insert(op, p, (struct sockaddr *)&sin, sizeof(sin), 0);
		} else {
			struct sockaddr_in6 sin6;

			memset(&sin6, 0, sizeof(sin6));
			sin6.sin6_family = AF_INET6;
			memcpy(&sin6.sin6_addr, p + 20, 16);
			memcpy(&sin6.sin6_port, p + 36, 2);
			node_insert(op, p, (struct sockaddr *)&sin6, sizeof(sin6), 0);
		}
	}
}

static struct b44_req *req_alloc(struct b44_op *op, int node)
{
	int i;

	for (i = 0; i < B44_REQS_MAX; i++) {
		if (op->reqs[i].in_use)
			continue;
		op->reqs[i].in_use = 1;
		op->reqs[i].node = (uint8_t)node;
		op->reqs[i].tid = op->e->tid_seq++;
		op->reqs[i].sent_ms = now_ms();
		return &op->reqs[i];
	}
	return NULL;
}

static void tid_bytes(uint8_t tid[4], uint16_t seq)
{
	tid[0] = 'p';
	tid[1] = 'm';
	tid[2] = (uint8_t)seq;
	tid[3] = (uint8_t)(seq >> 8);
}

static int get_send(struct b44_op *op, int node)
{
	struct b44_req *req = req_alloc(op, node);
	uint8_t msg[B44_MSG_MAX];
	uint8_t tid[4];
	struct benc_buf b;

	if (!req)
		return -1;
	tid_bytes(tid, req->tid);

	benc_buf_init(&b, msg, sizeof(msg));
	benc_raw_add(&b, "d1:ad", 5);
	benc_key_add(&b, "id");
	benc_str_add(&b, op->e->myid, 20);
	benc_key_add(&b, "target");
	benc_str_add(&b, op->target, 20);
	benc_key_add(&b, "want");
	benc_raw_add(&b, "l2:n42:n6e", 10);	/* BEP 32: want both v4 and v6 nodes,
						 * else a v4-sent query returns only
						 * v4 and the v6 DHT is never found */
	benc_raw_add(&b, "e1:q3:get1:t", 12);
	benc_str_add(&b, tid, 4);
	benc_raw_add(&b, "1:y1:qe", 7);
	if (b.err) {
		req->in_use = 0;
		return -1;
	}
	op->nodes[node].state = op->phase == B44_PHASE_STORE ?
		B44_NODE_STORE_INFLIGHT : B44_NODE_INFLIGHT;
	msg_send(op->e, &op->nodes[node].ss, op->nodes[node].sslen, msg, b.len);
	return 0;
}

static int put_send(struct b44_op *op, int node)
{
	struct b44_req *req = req_alloc(op, node);
	uint8_t msg[B44_MSG_MAX];
	uint8_t sigbuf[BEP44_MAX_VALUE + 128];
	uint8_t sig[64];
	size_t sigbuf_len, salt_len = strlen(op->salt);
	uint8_t tid[4];
	struct benc_buf b;

	if (!req)
		return -1;
	tid_bytes(tid, req->tid);

	sigbuf_len = bep44_sig_buffer(sigbuf, sizeof(sigbuf), op->salt,
				      op->seq, op->value, op->value_len);
	if (!sigbuf_len) {
		req->in_use = 0;
		return -1;
	}
	crypto_ed25519_sign(sig, op->sk, sigbuf, sigbuf_len);

	benc_buf_init(&b, msg, sizeof(msg));
	benc_raw_add(&b, "d1:ad", 5);
	if (op->cas >= 0) {
		benc_key_add(&b, "cas");	/* sorts before "id" */
		benc_int_add(&b, op->cas);
	}
	benc_key_add(&b, "id");
	benc_str_add(&b, op->e->myid, 20);
	benc_key_add(&b, "k");
	benc_str_add(&b, op->pk, 32);
	if (salt_len) {
		benc_key_add(&b, "salt");
		benc_str_add(&b, op->salt, salt_len);
	}
	benc_key_add(&b, "seq");
	benc_int_add(&b, op->seq);
	benc_key_add(&b, "sig");
	benc_str_add(&b, sig, 64);
	benc_key_add(&b, "token");
	benc_str_add(&b, op->nodes[node].token, op->nodes[node].token_len);
	benc_key_add(&b, "v");
	benc_raw_add(&b, op->value, op->value_len);
	benc_raw_add(&b, "e1:q3:put1:t", 12);
	benc_str_add(&b, tid, 4);
	benc_raw_add(&b, "1:y1:qe", 7);
	if (b.err) {
		req->in_use = 0;
		return -1;
	}
	op->nodes[node].state = B44_NODE_STORE_INFLIGHT;
	msg_send(op->e, &op->nodes[node].ss, op->nodes[node].sslen, msg, b.len);
	return 0;
}

static int node_addr_usable(const struct sockaddr *sa, socklen_t len);

static int id_nonzero(const uint8_t id[20])
{
	int i;

	for (i = 0; i < 20; i++)
		if (id[i])
			return 1;
	return 0;
}

static void retain_add(struct bep44_engine *e, const uint8_t id[20],
		       const struct sockaddr *sa, socklen_t salen)
{
	struct b44_seed *r;
	int i;

	if ((size_t)salen > sizeof(r->ss))
		return;
	for (i = 0; i < B44_RETAINED_MAX; i++) {
		r = &e->retained[i];
		if (r->in_use && r->sslen == salen && !memcmp(&r->ss, sa, salen))
			return;
	}
	r = &e->retained[e->retain_next];
	e->retain_next = (e->retain_next + 1) % B44_RETAINED_MAX;
	memset(r, 0, sizeof(*r));
	if (id) {
		memcpy(r->id, id, 20);
		r->has_id = 1;
	}
	memcpy(&r->ss, sa, salen);
	r->sslen = salen;
	r->in_use = 1;
}

/*
 * Keep the closest nodes that answered this op, so the next op to the same or
 * a nearby target (a get right after a put, or the repeated gets a
 * subscription makes) starts already converged instead of cold. They carry
 * ids, so they rank by true distance and actually accelerate the next lookup.
 */
static void op_retain_nodes(struct bep44_engine *e, struct b44_op *op)
{
	int k, kept4 = 0, kept6 = 0;

	/* Retain the closest answering nodes of EACH family, so the direct get
	 * that follows a put has v6 nodes to read the value back from -- not just
	 * the v4 ones that dominate a distance-sorted list. */
	for (k = 0; k < op->nnodes && (kept4 < 4 || kept6 < 4); k++) {
		struct b44_node *nd = &op->nodes[k];
		int v6;

		if (nd->state != B44_NODE_REPLIED && nd->state != B44_NODE_STORED)
			continue;
		v6 = nd->ss.ss_family == AF_INET6;
		if ((v6 ? kept6 : kept4) >= 4)
			continue;
		retain_add(e, id_nonzero(nd->id) ? nd->id : NULL,
			   (struct sockaddr *)&nd->ss, nd->sslen);
		if (v6)
			kept6++;
		else
			kept4++;
	}
}

static void op_finish(struct b44_op *op)
{
	struct bep44_engine *e = op->e;

	if (debug_on()) {
		int i, replied = 0, tokened = 0, n6 = 0, r6 = 0, st6 = 0;

		for (i = 0; i < op->nnodes; i++) {
			int v6 = op->nodes[i].ss.ss_family == AF_INET6;
			int up = op->nodes[i].state == B44_NODE_REPLIED ||
				 op->nodes[i].state == B44_NODE_STORED ||
				 op->nodes[i].state == B44_NODE_STORE_INFLIGHT;

			if (v6)
				n6++;
			if (up) {
				replied++;
				if (v6)
					r6++;
			}
			if (op->nodes[i].state == B44_NODE_STORED && v6)
				st6++;
			if (op->nodes[i].token_len)
				tokened++;
		}
		fprintf(stderr,
			"[bep44] %s finish: nodes=%d(v6=%d) replied=%d(v6=%d) tokened=%d stored=%d(v6=%d) best=%d\n",
			op->is_put ? "put" : "get", op->nnodes, n6, replied, r6,
			tokened, op->stored, st6, op->have_best);
		fprintf(stderr, "[bep44]   target %02x%02x%02x%02x  closest dists:",
			op->target[0], op->target[1], op->target[2], op->target[3]);
		for (i = 0; i < op->nnodes && i < 4; i++)
			fprintf(stderr, " %02x%02x%02x%02x",
				op->nodes[i].dist[0], op->nodes[i].dist[1],
				op->nodes[i].dist[2], op->nodes[i].dist[3]);
		fprintf(stderr, "\n");
	}

	bep44_put_cb *put_cb = op->put_cb;
	bep44_get_cb *get_cb = op->get_cb;
	void *arg = op->cb_arg;
	int stored = op->stored;

	/*
	 * For a put, the rendezvous node is the closest node that acknowledged
	 * storing the value: known here, at store time, from the store itself,
	 * so the host never needs a separate (cold) get to discover it.
	 */
	if (op->is_put && !op->best_node_len) {
		int k;

		for (k = 0; k < op->nnodes; k++) {
			if (op->nodes[k].state != B44_NODE_STORED ||
			    !node_addr_usable((struct sockaddr *)&op->nodes[k].ss,
					      op->nodes[k].sslen))
				continue;
			memcpy(&op->best_node, &op->nodes[k].ss, op->nodes[k].sslen);
			op->best_node_len = op->nodes[k].sslen;
			break;
		}
	}
	uint8_t best[BEP44_MAX_VALUE];
	uint16_t best_len = op->best_len;
	int64_t best_seq = op->best_seq;
	uint8_t have_best = op->have_best;
	struct sockaddr_storage best_node = op->best_node;
	socklen_t best_node_len = op->best_node_len;

	memcpy(best, op->best, best_len);
	op_retain_nodes(e, op);
	op_free(e, op);
	if (put_cb)
		put_cb(arg, stored,
		       best_node_len ? (struct sockaddr *)&best_node : NULL,
		       best_node_len);
	else if (get_cb)
		get_cb(arg, have_best ? best : NULL, best_len, best_seq,
		       best_node_len ? (struct sockaddr *)&best_node : NULL,
		       best_node_len);
}

static int store_start(struct b44_op *op)
{
	int i, sent = 0, s4 = 0, s6 = 0;

	/* Store on the closest token-bearing nodes of EACH family, so the value
	 * lands on the v6 k-closest too and a v6-only client can read it. */
	op->phase = B44_PHASE_STORE;
	for (i = 0; i < op->nnodes; i++) {
		int v6;

		if (op->nodes[i].state != B44_NODE_REPLIED ||
		    !op->nodes[i].token_len)
			continue;
		v6 = op->nodes[i].ss.ss_family == AF_INET6;
		if ((v6 ? s6 : s4) >= B44_K)
			continue;
		if (put_send(op, i))
			break;
		if (v6)
			s6++;
		else
			s4++;
		sent++;
	}
	return sent;
}

/* Lookup done: let the caller merge its slot into the value we read, then
 * store it back on those same token-bearing nodes -- standard get-then-put. */
static void update_store(struct b44_op *op)
{
	uint8_t nv[BEP44_MAX_VALUE];
	size_t nvlen = 0;

	if (op->merge(op->merge_arg, op->have_best ? op->best : NULL,
		      op->best_len, nv, &nvlen, sizeof(nv)) ||
	    !nvlen || nvlen > BEP44_MAX_VALUE) {
		op_finish(op);
		return;
	}
	memcpy(op->value, nv, nvlen);
	op->value_len = (uint16_t)nvlen;
	op->seq = op->have_best ? op->best_seq + 1 : 1;
	op->cas = op->have_best ? op->best_seq : -1;
	op->is_put = 1;
	if (!store_start(op))
		op_finish(op);
}

static void op_step(struct b44_op *op)
{
	uint64_t now = now_ms();
	int i, inflight = 0, if4 = 0, if6 = 0;

	if (now - op->start_ms > B44_OP_TIMEOUT_MS) {
		op_finish(op);
		return;
	}

	for (i = 0; i < B44_REQS_MAX; i++) {
		struct b44_req *req = &op->reqs[i];

		if (!req->in_use)
			continue;
		if (now - req->sent_ms > B44_REQ_TIMEOUT_MS) {
			op->nodes[req->node].state = B44_NODE_FAILED;
			req->in_use = 0;
			continue;
		}
		inflight++;
		if (op->nodes[req->node].ss.ss_family == AF_INET6)
			if6++;
		else
			if4++;
	}

	if (op->phase == B44_PHASE_LOOKUP) {
		/*
		 * Budget the query concurrency per family. The nodes are one list
		 * sorted by distance, but the v4 DHT is far denser, so the closest
		 * fresh nodes are almost all v4 -- a single ALPHA cap over both
		 * lets v4 crowd v6 out entirely, and v6 rendezvous then takes
		 * minutes. Give each family its own ALPHA so the sparse v6 branch
		 * converges as fast as it would alone (REQS_MAX holds both).
		 */
		for (i = 0; i < op->nnodes; i++) {
			int v6;

			if (op->nodes[i].state != B44_NODE_FRESH)
				continue;
			v6 = op->nodes[i].ss.ss_family == AF_INET6;
			if ((v6 ? if6 : if4) >= (v6 ? B44_ALPHA_V6 : B44_ALPHA_V4))
				continue;
			if (get_send(op, i))
				break;
			inflight++;
			if (v6)
				if6++;
			else
				if4++;
		}
		if (inflight)
			return;
		if (op->is_update) {
			update_store(op);
			return;
		}
		if (!op->is_put) {
			op_finish(op);
			return;
		}
		if (!store_start(op))
			op_finish(op);
		return;
	}

	if (!inflight)
		op_finish(op);
}

/* A node address worth handing on as a rendezvous hint: real family, and
 * neither the address nor the port all-zero (bogus compact entries appear). */
static int node_addr_usable(const struct sockaddr *sa, socklen_t len)
{
	if (sa->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *s = (const struct sockaddr_in *)sa;

		return s->sin_port != 0 && s->sin_addr.s_addr != 0;
	}
	if (sa->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
		static const uint8_t zero[16] = { 0 };

		return s->sin6_port != 0 &&
		       memcmp(&s->sin6_addr, zero, 16) != 0;
	}
	return 0;
}

static void record_best_node(struct b44_op *op, const struct sockaddr *sa,
			     socklen_t salen)
{
	if (op->best_node_len || !sa || !node_addr_usable(sa, salen))
		return;
	memcpy(&op->best_node, sa, salen);
	op->best_node_len = salen;
}

static void value_check(struct b44_op *op, const struct sockaddr *from,
			socklen_t fromlen, const uint8_t *rdict, size_t rlen)
{
	const uint8_t *val;
	size_t val_len;
	const uint8_t *k, *sig, *v;
	size_t k_len, sig_len, v_len;
	uint8_t sigbuf[BEP44_MAX_VALUE + 128];
	size_t sigbuf_len;
	int64_t seq;

	if (benc_dict_find(rdict, rlen, "v", &v, &v_len) || v_len > BEP44_MAX_VALUE)
		return;
	if (benc_dict_find(rdict, rlen, "k", &val, &val_len) ||
	    benc_str_get(val, val_len, &k, &k_len) || k_len != 32)
		return;
	if (memcmp(k, op->pk, 32))
		return;
	if (benc_dict_find(rdict, rlen, "sig", &val, &val_len) ||
	    benc_str_get(val, val_len, &sig, &sig_len) || sig_len != 64)
		return;
	if (benc_dict_find(rdict, rlen, "seq", &val, &val_len) ||
	    benc_int_get(val, val_len, &seq) || seq < 0)
		return;

	sigbuf_len = bep44_sig_buffer(sigbuf, sizeof(sigbuf), op->salt, seq,
				      v, v_len);
	if (!sigbuf_len || crypto_ed25519_check(sig, op->pk, sigbuf, sigbuf_len))
		return;

	if (op->have_best && seq <= op->best_seq) {
		/* Same value already held; still adopt a usable node if the
		 * first replier's address was bogus, so we end up with the
		 * fastest *working* node. */
		record_best_node(op, from, fromlen);
		return;
	}
	memcpy(op->best, v, v_len);
	op->best_len = (uint16_t)v_len;
	op->best_seq = seq;
	op->have_best = 1;
	op->best_node_len = 0;
	record_best_node(op, from, fromlen);
}

/*
 * Learn and store the id of a pinned node that just answered. A token only
 * carries ip:port, so a rendezvous node starts id-less (front-ranked); once
 * it replies we record its real id, and thereafter it ranks by true distance
 * like any Kademlia node.
 */
static void pin_learn_id(struct bep44_engine *e, const struct sockaddr *from,
			 socklen_t fromlen, const uint8_t *rdict, size_t rlen)
{
	const uint8_t *val, *id;
	size_t val_len, id_len;
	int i;

	if (!from || benc_dict_find(rdict, rlen, "id", &val, &val_len) ||
	    benc_str_get(val, val_len, &id, &id_len) || id_len != 20)
		return;
	for (i = 0; i < e->npinned; i++) {
		struct b44_seed *p = &e->pinned[i];

		if (p->has_id || p->sslen != fromlen ||
		    memcmp(&p->ss, from, fromlen))
			continue;
		memcpy(p->id, id, 20);
		p->has_id = 1;
	}
}

static void reply_handle(struct b44_op *op, struct b44_req *req,
			 const uint8_t *buf, size_t len, int is_error,
			 const struct sockaddr *from, socklen_t fromlen)
{
	struct b44_node *node = &op->nodes[req->node];
	const uint8_t *rdict, *val;
	size_t rlen, val_len;

	req->in_use = 0;

	if (node->state == B44_NODE_STORE_INFLIGHT) {
		if (is_error) {
			node->state = B44_NODE_FAILED;
		} else {
			node->state = B44_NODE_STORED;
			op->stored++;
		}
		op_step(op);
		return;
	}

	if (is_error) {
		node->state = B44_NODE_FAILED;
		op_step(op);
		return;
	}
	node->state = B44_NODE_REPLIED;

	if (benc_dict_find(buf, len, "r", &rdict, &rlen)) {
		op_step(op);
		return;
	}

	pin_learn_id(op->e, from, fromlen, rdict, rlen);

	if (!benc_dict_find(rdict, rlen, "token", &val, &val_len)) {
		const uint8_t *tok;
		size_t tok_len;

		if (!benc_str_get(val, val_len, &tok, &tok_len) &&
		    tok_len <= B44_TOKEN_MAX) {
			memcpy(node->token, tok, tok_len);
			node->token_len = (uint8_t)tok_len;
		}
	}

	/* A rendezvous op talks only to the nodes it was seeded/pinned with, so
	 * it never grows toward the target: skip the returned closer nodes. */
	if (!op->direct &&
	    !benc_dict_find(rdict, rlen, "nodes", &val, &val_len)) {
		const uint8_t *data;
		size_t data_len;

		if (!benc_str_get(val, val_len, &data, &data_len))
			nodes_compact_add(op, data, data_len, AF_INET);
	}
	if (!op->direct &&
	    !benc_dict_find(rdict, rlen, "nodes6", &val, &val_len)) {
		const uint8_t *data;
		size_t data_len;

		if (!benc_str_get(val, val_len, &data, &data_len))
			nodes_compact_add(op, data, data_len, AF_INET6);
	}

	if (!op->is_put)
		value_check(op, from, fromlen, rdict, rlen);

	op_step(op);
}

int bep44_input(struct bep44_engine *e, const uint8_t *buf, size_t len,
		const struct sockaddr *from, socklen_t fromlen)
{
	const uint8_t *val, *t, *y;
	size_t val_len, t_len, y_len;
	uint16_t tid;
	int is_error;
	struct b44_op *op;

	if (benc_dict_find(buf, len, "t", &val, &val_len) ||
	    benc_str_get(val, val_len, &t, &t_len))
		return 0;
	if (t_len != 4 || t[0] != 'p' || t[1] != 'm')
		return 0;
	tid = (uint16_t)(t[2] | t[3] << 8);

	if (benc_dict_find(buf, len, "y", &val, &val_len) ||
	    benc_str_get(val, val_len, &y, &y_len) || y_len != 1)
		return 1;
	if (y[0] == 'e')
		is_error = 1;
	else if (y[0] == 'r')
		is_error = 0;
	else
		return 1;

	for (op = e->ops; op; op = op->next) {
		int i;

		for (i = 0; i < B44_REQS_MAX; i++) {
			struct b44_node *node;

			if (!op->reqs[i].in_use || op->reqs[i].tid != tid)
				continue;
			/* A reply counts only if it comes from the node the
			 * request went to. Without this an off-path source that
			 * guessed the linear tid could inject forged GET replies
			 * and poison the op node set (mailbox values stay
			 * Ed25519-verified regardless). */
			node = &op->nodes[op->reqs[i].node];
			if (fromlen != node->sslen ||
			    memcmp(from, &node->ss, (size_t)node->sslen))
				continue;
			reply_handle(op, &op->reqs[i], buf, len, is_error,
				     from, fromlen);
			return 1;
		}
	}
	return 1;
}

int bep44_periodic(struct bep44_engine *e, int *timeout_ms)
{
	struct b44_op *op = e->ops;

	while (op) {
		struct b44_op *next = op->next;

		op_step(op);
		op = next;
	}

	if (e->ops && *timeout_ms > 300)
		*timeout_ms = 300;
	return e->ops != NULL;
}

static struct b44_op *op_create(struct bep44_engine *e, const uint8_t pk[32],
				const char *salt, int direct)
{
	struct b44_op *op;
	int i;

	if (strlen(salt) > BEP44_MAX_SALT)
		return NULL;
	op = calloc(1, sizeof(*op));
	if (!op)
		return NULL;
	op->e = e;
	op->direct = (uint8_t)(direct != 0);
	memcpy(op->pk, pk, 32);
	strcpy(op->salt, salt);
	bep44_target(op->target, pk, salt);
	op->start_ms = now_ms();
	op->phase = B44_PHASE_LOOKUP;

	/* Pinned (rendezvous) nodes go into every op first, so they are always
	 * in the initial set and queried in the first round of every lookup. */
	for (i = 0; i < e->npinned; i++)
		node_insert(op, e->pinned[i].has_id ? e->pinned[i].id : NULL,
			    (struct sockaddr *)&e->pinned[i].ss,
			    e->pinned[i].sslen, 1);

	for (i = 0; i < B44_RETAINED_MAX; i++) {
		if (e->retained[i].in_use)
			node_insert(op,
				    e->retained[i].has_id ? e->retained[i].id : NULL,
				    (struct sockaddr *)&e->retained[i].ss,
				    e->retained[i].sslen, 0);
	}

	/* A direct op addresses only the shared rendezvous (pinned/retained)
	 * nodes and never converges, so it skips the wider seed/bootstrap set. */
	if (!direct) {
		for (i = 0; i < B44_SEEDS_MAX; i++) {
			if (e->seeds[i].in_use)
				node_insert(op,
					    e->seeds[i].has_id ? e->seeds[i].id : NULL,
					    (struct sockaddr *)&e->seeds[i].ss,
					    e->seeds[i].sslen, 0);
		}
		for (i = 0; i < e->nbootstrap; i++)
			node_insert(op, NULL, (struct sockaddr *)&e->bootstrap[i],
				    e->bootstrap_len[i], 0);
	}

	op->next = e->ops;
	e->ops = op;
	return op;
}

int bep44_seed_add(struct bep44_engine *e, const uint8_t id[20],
		   const struct sockaddr *sa, socklen_t salen)
{
	struct b44_seed *seed;
	int i;

	if (salen > sizeof(seed->ss))
		return -1;
	for (i = 0; i < B44_SEEDS_MAX; i++) {
		seed = &e->seeds[i];
		if (seed->in_use && seed->sslen == salen &&
		    !memcmp(&seed->ss, sa, salen))
			return 0;
	}
	seed = &e->seeds[e->seed_next];
	e->seed_next = (e->seed_next + 1) % B44_SEEDS_MAX;
	if (id) {
		memcpy(seed->id, id, 20);
		seed->has_id = 1;
	} else {
		seed->has_id = 0;
	}
	memcpy(&seed->ss, sa, salen);
	seed->sslen = salen;
	seed->in_use = 1;
	return 0;
}

int bep44_pin_add(struct bep44_engine *e, const uint8_t id[20],
		  const struct sockaddr *sa, socklen_t salen)
{
	struct b44_seed *p;
	int i;

	if ((size_t)salen > sizeof(p->ss))
		return -1;
	for (i = 0; i < e->npinned; i++) {
		p = &e->pinned[i];
		if (p->sslen == salen && !memcmp(&p->ss, sa, salen))
			return 0;		/* already pinned */
	}
	if (e->npinned >= B44_PINNED_MAX)
		return -1;			/* never evict an existing pin */
	p = &e->pinned[e->npinned++];
	memset(p, 0, sizeof(*p));
	if (id) {
		memcpy(p->id, id, 20);
		p->has_id = 1;
	}
	memcpy(&p->ss, sa, salen);
	p->sslen = salen;
	p->in_use = 1;
	return 0;
}

int bep44_put(struct bep44_engine *e, const uint8_t sk[64], const uint8_t pk[32],
	      const char *salt, const uint8_t *v, size_t v_len, int64_t seq,
	      int64_t cas, bep44_put_cb *cb, void *arg)
{
	struct b44_op *op;

	if (v_len > BEP44_MAX_VALUE)
		return -1;
	op = op_create(e, pk, salt, 0);
	if (!op)
		return -1;
	op->is_put = 1;
	memcpy(op->sk, sk, 64);
	memcpy(op->value, v, v_len);
	op->value_len = (uint16_t)v_len;
	op->seq = seq;
	op->cas = cas;
	op->put_cb = cb;
	op->cb_arg = arg;
	op_step(op);
	return 0;
}

static int update_impl(struct bep44_engine *e, const uint8_t sk[64],
		       const uint8_t pk[32], const char *salt,
		       bep44_merge_fn *merge, void *merge_arg, int direct,
		       bep44_put_cb *cb, void *arg)
{
	struct b44_op *op = op_create(e, pk, salt, direct);

	if (!op)
		return -1;
	/* Starts as a get (is_put stays 0 so the value is collected); at
	 * lookup settle op_step merges and stores on the same nodes. */
	op->is_update = 1;
	memcpy(op->sk, sk, 64);
	op->merge = merge;
	op->merge_arg = merge_arg;
	op->put_cb = cb;
	op->cb_arg = arg;
	op_step(op);
	return 0;
}

int bep44_update(struct bep44_engine *e, const uint8_t sk[64],
		 const uint8_t pk[32], const char *salt, bep44_merge_fn *merge,
		 void *merge_arg, bep44_put_cb *cb, void *arg)
{
	return update_impl(e, sk, pk, salt, merge, merge_arg, 0, cb, arg);
}

int bep44_update_direct(struct bep44_engine *e, const uint8_t sk[64],
			const uint8_t pk[32], const char *salt,
			bep44_merge_fn *merge, void *merge_arg,
			bep44_put_cb *cb, void *arg)
{
	return update_impl(e, sk, pk, salt, merge, merge_arg, 1, cb, arg);
}

static int get_impl(struct bep44_engine *e, const uint8_t pk[32],
		    const char *salt, int direct, bep44_get_cb *cb, void *arg)
{
	struct b44_op *op = op_create(e, pk, salt, direct);

	if (!op)
		return -1;
	op->get_cb = cb;
	op->cb_arg = arg;
	op_step(op);
	return 0;
}

int bep44_get(struct bep44_engine *e, const uint8_t pk[32], const char *salt,
	      bep44_get_cb *cb, void *arg)
{
	return get_impl(e, pk, salt, 0, cb, arg);
}

int bep44_get_direct(struct bep44_engine *e, const uint8_t pk[32],
		     const char *salt, bep44_get_cb *cb, void *arg)
{
	return get_impl(e, pk, salt, 1, cb, arg);
}
