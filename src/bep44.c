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

#define B44_ALPHA 4
#define B44_K 8
#define B44_NODES_MAX 64
#define B44_BOOTSTRAP_MAX 8
#define B44_REQS_MAX (B44_ALPHA * 2)
#define B44_REQ_TIMEOUT_MS 1500
#define B44_OP_TIMEOUT_MS 30000
#define B44_TOKEN_MAX 40
#define B44_MSG_MAX 1400
#define B44_SEEDS_MAX 16

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
	uint8_t phase;
	uint8_t target[20];
	uint8_t pk[32];
	uint8_t sk[64];
	char salt[BEP44_MAX_SALT + 1];
	uint8_t value[BEP44_MAX_VALUE];
	uint16_t value_len;
	int64_t seq;
	uint8_t best[BEP44_MAX_VALUE];
	uint16_t best_len;
	int64_t best_seq;
	uint8_t have_best;
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
		       const struct sockaddr *sa, socklen_t salen)
{
	uint8_t dist[20];
	int i, pos;

	if (id)
		dist_calc(dist, id, op->target);
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
			node_insert(op, p, (struct sockaddr *)&sin, sizeof(sin));
		} else {
			struct sockaddr_in6 sin6;

			memset(&sin6, 0, sizeof(sin6));
			sin6.sin6_family = AF_INET6;
			memcpy(&sin6.sin6_addr, p + 20, 16);
			memcpy(&sin6.sin6_port, p + 36, 2);
			node_insert(op, p, (struct sockaddr *)&sin6, sizeof(sin6));
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

static void op_finish(struct b44_op *op)
{
	struct bep44_engine *e = op->e;

	if (debug_on()) {
		int i, replied = 0, tokened = 0;

		for (i = 0; i < op->nnodes; i++) {
			if (op->nodes[i].state == B44_NODE_REPLIED ||
			    op->nodes[i].state == B44_NODE_STORED ||
			    op->nodes[i].state == B44_NODE_STORE_INFLIGHT)
				replied++;
			if (op->nodes[i].token_len)
				tokened++;
		}
		fprintf(stderr,
			"[bep44] %s finish: nodes=%d replied=%d tokened=%d stored=%d best=%d\n",
			op->is_put ? "put" : "get", op->nnodes, replied,
			tokened, op->stored, op->have_best);
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
	uint8_t best[BEP44_MAX_VALUE];
	uint16_t best_len = op->best_len;
	int64_t best_seq = op->best_seq;
	uint8_t have_best = op->have_best;

	memcpy(best, op->best, best_len);
	op_free(e, op);
	if (put_cb)
		put_cb(arg, stored);
	else if (get_cb)
		get_cb(arg, have_best ? best : NULL, best_len, best_seq);
}

static int store_start(struct b44_op *op)
{
	int i, sent = 0;

	op->phase = B44_PHASE_STORE;
	for (i = 0; i < op->nnodes && sent < B44_K; i++) {
		if (op->nodes[i].state != B44_NODE_REPLIED ||
		    !op->nodes[i].token_len)
			continue;
		if (put_send(op, i))
			break;
		sent++;
	}
	return sent;
}

static void op_step(struct b44_op *op)
{
	uint64_t now = now_ms();
	int i, inflight = 0;

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
	}

	if (op->phase == B44_PHASE_LOOKUP) {
		for (i = 0; i < op->nnodes && inflight < B44_ALPHA; i++) {
			if (op->nodes[i].state != B44_NODE_FRESH)
				continue;
			if (get_send(op, i))
				break;
			inflight++;
		}
		if (inflight)
			return;
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

static void value_check(struct b44_op *op, const uint8_t *rdict, size_t rlen)
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

	if (op->have_best && seq <= op->best_seq)
		return;
	memcpy(op->best, v, v_len);
	op->best_len = (uint16_t)v_len;
	op->best_seq = seq;
	op->have_best = 1;
}

static void reply_handle(struct b44_op *op, struct b44_req *req,
			 const uint8_t *buf, size_t len, int is_error)
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

	if (!benc_dict_find(rdict, rlen, "token", &val, &val_len)) {
		const uint8_t *tok;
		size_t tok_len;

		if (!benc_str_get(val, val_len, &tok, &tok_len) &&
		    tok_len <= B44_TOKEN_MAX) {
			memcpy(node->token, tok, tok_len);
			node->token_len = (uint8_t)tok_len;
		}
	}

	if (!benc_dict_find(rdict, rlen, "nodes", &val, &val_len)) {
		const uint8_t *data;
		size_t data_len;

		if (!benc_str_get(val, val_len, &data, &data_len))
			nodes_compact_add(op, data, data_len, AF_INET);
	}
	if (!benc_dict_find(rdict, rlen, "nodes6", &val, &val_len)) {
		const uint8_t *data;
		size_t data_len;

		if (!benc_str_get(val, val_len, &data, &data_len))
			nodes_compact_add(op, data, data_len, AF_INET6);
	}

	if (!op->is_put)
		value_check(op, rdict, rlen);

	op_step(op);
}

int bep44_input(struct bep44_engine *e, const uint8_t *buf, size_t len)
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
			if (!op->reqs[i].in_use || op->reqs[i].tid != tid)
				continue;
			reply_handle(op, &op->reqs[i], buf, len, is_error);
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
				const char *salt)
{
	struct b44_op *op;
	int i;

	if (strlen(salt) > BEP44_MAX_SALT)
		return NULL;
	op = calloc(1, sizeof(*op));
	if (!op)
		return NULL;
	op->e = e;
	memcpy(op->pk, pk, 32);
	strcpy(op->salt, salt);
	bep44_target(op->target, pk, salt);
	op->start_ms = now_ms();
	op->phase = B44_PHASE_LOOKUP;

	for (i = 0; i < B44_SEEDS_MAX; i++) {
		if (e->seeds[i].in_use)
			node_insert(op, e->seeds[i].has_id ? e->seeds[i].id : NULL,
				    (struct sockaddr *)&e->seeds[i].ss,
				    e->seeds[i].sslen);
	}
	for (i = 0; i < e->nbootstrap; i++)
		node_insert(op, NULL, (struct sockaddr *)&e->bootstrap[i],
			    e->bootstrap_len[i]);

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

int bep44_put(struct bep44_engine *e, const uint8_t sk[64], const uint8_t pk[32],
	      const char *salt, const uint8_t *v, size_t v_len, int64_t seq,
	      bep44_put_cb *cb, void *arg)
{
	struct b44_op *op;

	if (v_len > BEP44_MAX_VALUE)
		return -1;
	op = op_create(e, pk, salt);
	if (!op)
		return -1;
	op->is_put = 1;
	memcpy(op->sk, sk, 64);
	memcpy(op->value, v, v_len);
	op->value_len = (uint16_t)v_len;
	op->seq = seq;
	op->put_cb = cb;
	op->cb_arg = arg;
	op_step(op);
	return 0;
}

int bep44_get(struct bep44_engine *e, const uint8_t pk[32], const char *salt,
	      bep44_get_cb *cb, void *arg)
{
	struct b44_op *op = op_create(e, pk, salt);

	if (!op)
		return -1;
	op->get_cb = cb;
	op->cb_arg = arg;
	op_step(op);
	return 0;
}
