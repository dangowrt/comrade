/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "wsock.h"

/*
 * Platform headers for the installed-memory query that sizes the item store.
 * wsock.h has already pulled in windows.h on Win32 (GlobalMemoryStatusEx);
 * the BSDs and macOS answer through sysctl, everyone else through sysconf.
 */
#ifndef _WIN32
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#endif

static int b44_debug = -1;

static int debug_on(void)
{
	if (b44_debug < 0)
		b44_debug = getenv("COMRADE_BEP44_DEBUG") ? 1 : 0;
	return b44_debug;
}

#include "bencode.h"
#include "bep44.h"
#include "ccrypto.h"
#include "keys.h"
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

/*
 * Storing-node side. The item store is the whole of what this node holds for
 * other peers: entries are allocated on demand, so a client-only embedder that
 * never calls bep44_serve() pays nothing for it. Items live two hours unless a
 * republish refreshes them, the interval BEP 44 assumes and mldht uses.
 *
 * The write-token secret rotates on a timer with the previous one still
 * accepted, so a token stays usable across a rotation without ever being valid
 * for long -- BEP 5's rule, and what libtorrent and libbtdht both do.
 */
_Static_assert(BEP44_MAX_VALUE <= UINT16_MAX, "v_len is stored in a uint16_t");
_Static_assert(BEP44_MAX_SALT <= UINT8_MAX, "salt_len is stored in a uint8_t");

/*
 * The item store is sized to the machine, not fixed: hold at most 0.5% of
 * installed memory worth of items, budgeting a full ~1.25 KiB for each, so a
 * 64 MB box lands near 256 and a large host scales up. Total installed memory
 * is the portable choice (available memory needs per-OS vm stats); the clamp
 * keeps a tiny box usable and a huge one from reserving gigabytes, and the
 * default covers a host whose memory we cannot read.
 */
#define B44_STORE_MIN 64
#define B44_STORE_MAX 32768
#define B44_STORE_DEFAULT 256
#define B44_ITEM_BUDGET 1280			/* bytes charged per stored item */
#define B44_ITEM_TTL_MS (2 * 60 * 60 * 1000)
#define B44_TOKEN_ROTATE_MS (5 * 60 * 1000)
#define B44_TOKEN_LEN 8
#define B44_SECRET_LEN 16
#define B44_TID_MAX 64
#define B44_CACHE_MAX 128
#define B44_REPLY_NODES 8
#define B44_CACHE_TTL_MS (60 * 60 * 1000)	/* drop a referral unseen for an hour */
/*
 * Per-source rate limiting, the way a real libtorrent/uTorrent node does it
 * (its dht dos_blocker): count a source's messages over a fixed window and, if
 * it exceeds the limit, ban it for a while (here 50 in 10 s -> a 5-minute ban).
 * On top of that plain per-address ban is prefix consolidation. Tracking
 * starts at the individual address; when offenders appear in distinct siblings
 * of a wider prefix the ban widens to it, each step needing one more offender:
 * v6 /128 -> /64 (2) -> /56 (3) -> /48 (4) -> /40 (5) -> /32 (6), v4 in fine
 * steps that stop at /24, /32 -> /30 (2) -> /28 (3) -> /26 (4) -> /24 (5), since
 * a whole ISP can sit behind a /24. A banned prefix swallows its interior --
 * offenders inside it are dropped, not re-counted -- so lone offenders that
 * merely share a wide prefix never widen the ban; only spread across it does.
 * If the table of bans fills, the node fails closed, dropping all unsolicited
 * queries until it drains.
 */
#define B44_BAN_MAX 128				/* blocklist / tracker entries */
#define B44_BAN_WINDOW_MS 10000			/* the counting window (libtorrent's 10s) */
#define B44_BAN_RATE 5				/* messages/sec over the window before a ban */
#define B44_BAN_TIME_MS (5 * 60 * 1000)		/* ban duration (libtorrent's 5 min) */
#define B44_FAILCLOSED_MS 30000			/* block-all window when the table saturates */
#define B44_COMPACT_CACHE_MAX 4			/* cache entries taken from one reply */

/*
 * One stored item. v is the value's bencoded bytes exactly as they arrived: the
 * signature covers those bytes, so anything that re-encodes them destroys the
 * item even though it still decodes to the same value.
 */
struct b44_item {
	uint8_t target[20];
	uint8_t k[32];
	uint8_t sig[64];
	uint8_t salt[BEP44_MAX_SALT];
	uint8_t salt_len;
	uint8_t is_mutable;
	int64_t seq;
	uint64_t expires_ms;
	uint16_t v_len;
	uint8_t v[];
};

/*
 * One entry in the ban list: a network prefix that is either being rate-tracked
 * (banned_until == 0) or currently banned. libtorrent (dos_blocker) and mldht
 * (SpamThrottle) both rate-limit per source; this keeps the global bucket
 * underneath as a total-load backstop and adds the prefix escalation above.
 */
struct b44_ban {
	uint8_t net[16];		/* network prefix, masked to `bits` */
	uint8_t family;			/* AF_INET / AF_INET6; 0 = free slot */
	uint8_t bits;			/* prefix length */
	uint16_t weight;		/* offenders this ban stands for (for widening) */
	int32_t count;			/* messages seen in the current window */
	uint64_t window_ms;		/* end of the current counting window */
	uint64_t banned_until;		/* 0 = tracking, else banned through this time */
};

/*
 * A node we have seen with its id, kept so a get we answer can name closer
 * nodes and the querier's lookup keeps converging instead of dead-ending here.
 */
struct b44_cnode {
	uint8_t id[20];
	struct sockaddr_storage ss;
	socklen_t sslen;
	uint64_t seen_ms;
};

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
	uint8_t is_immutable;		/* item named by sha1(v), no key or seq */
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
	sock_t s4;
	sock_t s6;
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
	/* Storing side; all of it stays zero until bep44_serve() enables it. */
	uint8_t serving;
	uint8_t token_secret[2][B44_SECRET_LEN];
	uint64_t token_rotate_ms;
	struct b44_item **store;
	int store_cap;
	struct b44_cnode cache[B44_CACHE_MAX];
	int cache_next;
	/*
	 * A global token bucket over served queries, the same defence jech/dht
	 * applies at its own ingress (dht.c token_bucket): the BEP 44 engine now
	 * answers get/put before jech sees them, so it must carry its own cap or
	 * an unauthenticated get becomes an unmetered reflector.
	 */
	struct b44_ban ban[B44_BAN_MAX];
	uint64_t block_all_until;	/* fail-closed window when the ban table saturates */
	int rl_rate;			/* per-source messages/sec threshold (0 disables) */
	uint64_t rl_ban_ms;		/* ban duration; 0 disables rate limiting */
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Total installed physical memory in bytes, or 0 if the platform will not say. */
static uint64_t plat_total_memory(void)
{
#if defined(_WIN32)
	MEMORYSTATUSEX st;

	st.dwLength = sizeof(st);
	if (GlobalMemoryStatusEx(&st))
		return st.ullTotalPhys;
	return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
	defined(__OpenBSD__) || defined(__DragonFly__)
	int mib[2] = { CTL_HW,
#if defined(HW_MEMSIZE)
		HW_MEMSIZE		/* macOS: 64-bit total */
#elif defined(HW_PHYSMEM64)
		HW_PHYSMEM64		/* NetBSD/OpenBSD */
#else
		HW_PHYSMEM		/* older BSD: may saturate at 4 GiB */
#endif
	};
	uint64_t mem = 0;
	size_t len = sizeof(mem);

	if (sysctl(mib, 2, &mem, &len, NULL, 0) == 0 && len == sizeof(mem))
		return mem;
	return 0;
#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
	long pages = sysconf(_SC_PHYS_PAGES);
	long psz = sysconf(_SC_PAGESIZE);

	if (pages > 0 && psz > 0)
		return (uint64_t)pages * (uint64_t)psz;
	return 0;
#else
	return 0;
#endif
}

/* How many items to hold: 0.5% of installed memory, one B44_ITEM_BUDGET each. */
static int store_cap_for_memory(void)
{
	uint64_t total = plat_total_memory();
	uint64_t records;

	if (!total)
		return B44_STORE_DEFAULT;
	records = (total / 200) / B44_ITEM_BUDGET;	/* 0.5% */
	if (records < B44_STORE_MIN)
		return B44_STORE_MIN;
	if (records > B44_STORE_MAX)
		return B44_STORE_MAX;
	return (int)records;
}

/*
 * The salt is a byte string, not text: it may hold NUL and is only bound by its
 * length. The public entry points take the C string pmate itself uses; the
 * storing side, which relays whatever a peer sent, needs the explicit length.
 */
static size_t sig_buffer_n(uint8_t *dst, size_t dst_len, const uint8_t *salt,
			   size_t salt_len, int64_t seq, const uint8_t *v,
			   size_t v_len)
{
	struct benc_buf b;

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

static void target_n(uint8_t target[20], const uint8_t pk[32],
		     const uint8_t *salt, size_t salt_len)
{
	struct cc_sha1_ctx ctx;

	cc_sha1_init(&ctx);
	cc_sha1_update(&ctx, pk, 32);
	if (salt_len)
		cc_sha1_update(&ctx, salt, salt_len);
	cc_sha1_final(&ctx, target);
}

size_t bep44_sig_buffer(uint8_t *dst, size_t dst_len, const char *salt,
			int64_t seq, const uint8_t *v, size_t v_len)
{
	return sig_buffer_n(dst, dst_len, (const uint8_t *)salt,
			    salt ? strlen(salt) : 0, seq, v, v_len);
}

void bep44_target(uint8_t target[20], const uint8_t pk[32], const char *salt)
{
	target_n(target, pk, (const uint8_t *)salt, salt ? strlen(salt) : 0);
}

void bep44_immutable_target(uint8_t target[20], const uint8_t *v, size_t v_len)
{
	cc_sha1(target, v, v_len);
}

struct bep44_engine *bep44_create(const uint8_t myid[20], sock_t s4, sock_t s6)
{
	struct bep44_engine *e = calloc(1, sizeof(*e));

	if (!e)
		return NULL;
	e->store_cap = store_cap_for_memory();
	e->store = calloc((size_t)e->store_cap, sizeof(*e->store));
	if (!e->store) {
		free(e);
		return NULL;
	}
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
	int i;

	while (e->ops)
		op_free(e, e->ops);
	for (i = 0; i < e->store_cap; i++)
		free(e->store[i]);
	free(e->store);
	free(e);
}

int bep44_bootstrap_add(struct bep44_engine *e, const struct sockaddr *sa,
			socklen_t salen)
{
	if (e->nbootstrap >= B44_BOOTSTRAP_MAX ||
	    (size_t)salen > sizeof(e->bootstrap[0]))
		return -1;
	memcpy(&e->bootstrap[e->nbootstrap], sa, salen);
	e->bootstrap_len[e->nbootstrap] = salen;
	e->nbootstrap++;
	return 0;
}

static int msg_send(struct bep44_engine *e, const struct sockaddr_storage *ss,
		    socklen_t sslen, const uint8_t *buf, size_t len)
{
	sock_t s = ss->ss_family == AF_INET6 ? e->s6 : e->s4;

	if (!sock_valid(s))
		return -1;
	return (int)sendto(s, (const char *)buf, (int)len, 0,
			 (const struct sockaddr *)ss, sslen);
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

static void cache_add(struct bep44_engine *e, const uint8_t id[20],
		      const struct sockaddr *sa, socklen_t salen);

/*
 * A source we must not serve, refer a peer to, or cache: the unroutable and
 * unspoofable-target ranges jech/dht filters at its own ingress (dht.c
 * is_martian). Since the BEP 44 engine now answers before jech, it repeats the
 * check, so a get/put spoofed from loopback, 0/8, multicast or a link-local
 * address is neither answered (a reflector aimed at that address) nor turned
 * into a referral this node hands out.
 */
static int addr_martian(const struct sockaddr *sa, socklen_t salen)
{
	if (sa && sa->sa_family == AF_INET &&
	    salen >= (socklen_t)sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
		const uint8_t *a = (const uint8_t *)&s->sin_addr;

		return s->sin_port == 0 || a[0] == 0 || a[0] == 127 ||
		       (a[0] & 0xe0) == 0xe0;
	}
	if (sa && sa->sa_family == AF_INET6 &&
	    salen >= (socklen_t)sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
		const uint8_t *a = (const uint8_t *)&s->sin6_addr;
		static const uint8_t v4map[12] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
		static const uint8_t zero[15] = { 0 };

		return s->sin6_port == 0 || a[0] == 0xff ||
		       (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) ||
		       !memcmp(a, v4map, 12) ||
		       (!memcmp(a, zero, 15) && (a[15] == 0 || a[15] == 1));
	}
	return 1;
}

/* Same host, ignoring the port: an address behind a NAT keeps one cache slot
 * however many source ports it speaks from, so a single host cannot crowd the
 * referral cache with an entry per port. */
static int addr_same_host(const struct sockaddr *a, socklen_t alen,
			  const struct sockaddr_storage *b, socklen_t blen)
{
	if (alen != blen || a->sa_family != b->ss_family)
		return 0;
	if (a->sa_family == AF_INET)
		return !memcmp(&((const struct sockaddr_in *)a)->sin_addr,
			       &((const struct sockaddr_in *)b)->sin_addr, 4);
	if (a->sa_family == AF_INET6)
		return !memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
			       &((const struct sockaddr_in6 *)b)->sin6_addr, 16);
	return 0;
}

static void nodes_compact_add(struct b44_op *op, const uint8_t *data,
			      size_t len, int af)
{
	size_t entry = af == AF_INET ? 26 : 38;
	size_t i;
	int cached = 0;

	for (i = 0; i + entry <= len; i += entry) {
		const uint8_t *p = data + i;
		struct sockaddr_storage ss;
		socklen_t sslen;

		memset(&ss, 0, sizeof(ss));
		if (af == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&ss;

			sin->sin_family = AF_INET;
			memcpy(&sin->sin_addr, p + 20, 4);
			memcpy(&sin->sin_port, p + 24, 2);
			sslen = sizeof(*sin);
		} else {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;

			sin6->sin6_family = AF_INET6;
			memcpy(&sin6->sin6_addr, p + 20, 16);
			memcpy(&sin6->sin6_port, p + 36, 2);
			sslen = sizeof(*sin6);
		}
		node_insert(op, p, (struct sockaddr *)&ss, sslen, 0);
		/* Cap what one reply contributes to the referral cache, so a
		 * single node answering our lookup cannot fill the ring. */
		if (cached < B44_COMPACT_CACHE_MAX) {
			cache_add(op->e, p, (struct sockaddr *)&ss, sslen);
			cached++;
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

	if (op->is_immutable) {
		/* An immutable item is named by its own bytes: no key, no salt,
		 * no seq, nothing to sign. */
		benc_buf_init(&b, msg, sizeof(msg));
		benc_raw_add(&b, "d1:ad", 5);
		benc_key_add(&b, "id");
		benc_str_add(&b, op->e->myid, 20);
		benc_key_add(&b, "token");
		benc_str_add(&b, op->nodes[node].token,
			     op->nodes[node].token_len);
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
		msg_send(op->e, &op->nodes[node].ss, op->nodes[node].sslen,
			 msg, b.len);
		return 0;
	}

	sigbuf_len = bep44_sig_buffer(sigbuf, sizeof(sigbuf), op->salt,
				      op->seq, op->value, op->value_len);
	if (!sigbuf_len) {
		req->in_use = 0;
		return -1;
	}
	if (cc_ed25519_sign(sig, op->sk, sigbuf, sigbuf_len)) {
		req->in_use = 0;
		return -1;
	}

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
	if (op->best_node_len || !sa || (size_t)salen > sizeof(op->best_node) ||
	    !node_addr_usable(sa, salen))
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
	if (op->is_immutable) {
		uint8_t got[20];

		/* The name IS the hash of the value, so a served value either
		 * hashes to what we asked for or is somebody else's. */
		cc_sha1(got, v, v_len);
		if (memcmp(got, op->target, 20))
			return;
		if (op->have_best) {
			record_best_node(op, from, fromlen);
			return;
		}
		memcpy(op->best, v, v_len);
		op->best_len = (uint16_t)v_len;
		op->best_seq = -1;
		op->have_best = 1;
		op->best_node_len = 0;
		record_best_node(op, from, fromlen);
		return;
	}
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
	if (!sigbuf_len || cc_ed25519_check(sig, op->pk, sigbuf, sigbuf_len))
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

/*
 * ---------------------------------------------------------------------------
 * Storing side: answer other peers' get and put, and hold what they store.
 *
 * bep44_input() offers every datagram here first and falls back to the BEP 5
 * engine for anything this does not claim, so get and put are answered once,
 * by whichever layer understands them, and never twice.
 * ---------------------------------------------------------------------------
 */

static size_t addr_bytes(const struct sockaddr *sa, socklen_t salen,
			 const uint8_t **out)
{
	*out = NULL;
	if (!sa)
		return 0;
	if (sa->sa_family == AF_INET &&
	    salen >= (socklen_t)sizeof(struct sockaddr_in)) {
		*out = (const uint8_t *)
			&((const struct sockaddr_in *)sa)->sin_addr;
		return 4;
	}
	if (sa->sa_family == AF_INET6 &&
	    salen >= (socklen_t)sizeof(struct sockaddr_in6)) {
		*out = (const uint8_t *)
			&((const struct sockaddr_in6 *)sa)->sin6_addr;
		return 16;
	}
	return 0;
}

/*
 * A write token proves the peer receives at the address it claims. It covers
 * the address but not the port, so a peer behind a NAT that reassigns ports
 * mid-lookup keeps its token, and it covers the target, so a token earned for
 * one item cannot be spent on another.
 */
static void token_make(uint8_t out[B44_TOKEN_LEN],
		       const uint8_t secret[B44_SECRET_LEN],
		       const struct sockaddr *sa, socklen_t salen,
		       const uint8_t target[20])
{
	struct cc_sha1_ctx ctx;
	const uint8_t *ab;
	size_t ablen = addr_bytes(sa, salen, &ab);
	uint8_t d[SHA1_LEN];

	cc_sha1_init(&ctx);
	cc_sha1_update(&ctx, secret, B44_SECRET_LEN);
	if (ablen)
		cc_sha1_update(&ctx, ab, ablen);
	cc_sha1_update(&ctx, target, 20);
	cc_sha1_final(&ctx, d);
	memcpy(out, d, B44_TOKEN_LEN);
}

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t diff = 0;
	size_t i;

	for (i = 0; i < len; i++)
		diff |= (uint8_t)(a[i] ^ b[i]);
	return diff == 0;
}

static int token_valid(struct bep44_engine *e, const uint8_t *tok,
		       size_t tok_len, const struct sockaddr *sa,
		       socklen_t salen, const uint8_t target[20])
{
	uint8_t want[B44_TOKEN_LEN];
	int i;

	if (tok_len != B44_TOKEN_LEN)
		return 0;
	for (i = 0; i < 2; i++) {
		token_make(want, e->token_secret[i], sa, salen, target);
		if (ct_eq(want, tok, B44_TOKEN_LEN))
			return 1;
	}
	return 0;
}

/*
 * Rotate the secret on a timer, keeping the previous one valid: a token handed
 * out just before a rotation still works, and none stays usable for long. Both
 * secrets are random from the start -- shifting an all-zero initial secret into
 * the "previous" slot would leave a window where anyone could mint a token.
 */
static void token_rotate(struct bep44_engine *e, uint64_t now)
{
	uint8_t fresh[B44_SECRET_LEN];

	if (now < e->token_rotate_ms)
		return;
	if (random_bytes(fresh, sizeof(fresh)))
		return;
	memcpy(e->token_secret[1], e->token_secret[0], sizeof(fresh));
	memcpy(e->token_secret[0], fresh, sizeof(fresh));
	e->token_rotate_ms = now + B44_TOKEN_ROTATE_MS;
}

/* -- the item store ------------------------------------------------------ */

static void store_expire(struct bep44_engine *e, uint64_t now)
{
	int i;

	for (i = 0; i < e->store_cap; i++) {
		if (e->store[i] && now >= e->store[i]->expires_ms) {
			free(e->store[i]);
			e->store[i] = NULL;
		}
	}
}

static struct b44_item **store_slot_of(struct bep44_engine *e,
				       const uint8_t target[20])
{
	int i;

	for (i = 0; i < e->store_cap; i++) {
		if (e->store[i] && !memcmp(e->store[i]->target, target, 20))
			return &e->store[i];
	}
	return NULL;
}

/*
 * A free slot for an item at new_target, evicting if need be. The victim is the
 * stored item furthest from our own id: the one we are least responsible for
 * holding, and so the one its owner is most likely to also have stored on
 * better-placed nodes. When the store is full, the incoming item is admitted
 * only if it is closer to our id than that furthest item -- so a flood of
 * distant items cannot evict a nearby one we are the right node to hold. -1
 * means "full, and this item is the least important of all": decline it.
 */
static int store_free_slot(struct bep44_engine *e, const uint8_t new_target[20])
{
	uint8_t vdist[20], ndist[20];
	int i, victim = -1;

	for (i = 0; i < e->store_cap; i++) {
		if (!e->store[i])
			return i;
	}
	for (i = 0; i < e->store_cap; i++) {
		uint8_t d[20];

		dist_calc(d, e->store[i]->target, e->myid);
		if (victim < 0 || memcmp(d, vdist, 20) > 0) {
			victim = i;
			memcpy(vdist, d, 20);
		}
	}
	dist_calc(ndist, new_target, e->myid);
	if (memcmp(ndist, vdist, 20) >= 0)
		return -1;			/* no closer than what we hold */
	free(e->store[victim]);
	e->store[victim] = NULL;
	return victim;
}

static struct b44_item *item_new(const uint8_t target[20], const uint8_t *v,
				 size_t v_len, uint64_t now)
{
	struct b44_item *it = calloc(1, sizeof(*it) + v_len);

	if (!it)
		return NULL;
	memcpy(it->target, target, 20);
	memcpy(it->v, v, v_len);
	it->v_len = (uint16_t)v_len;
	it->expires_ms = now + B44_ITEM_TTL_MS;
	return it;
}

/* -- the node cache ------------------------------------------------------ */

/*
 * Nodes we have seen with their ids, so a get we answer can name closer ones
 * and the asker's lookup keeps converging. Fed from the compact node lists our
 * own lookups collect and from peers whose write token proved their address.
 */
static void cache_add(struct bep44_engine *e, const uint8_t id[20],
		      const struct sockaddr *sa, socklen_t salen)
{
	struct b44_cnode *c;
	int i;

	/*
	 * The id is only ever claimed, never proven (a write token proves the
	 * address, not the id it travels with), so a poisoned referral can at
	 * worst mislead a lookup -- values stay Ed25519-verified regardless.
	 * What is enforced here is that the address is real and routable and
	 * that one host holds at most one slot.
	 */
	if (!e->serving || !id || !id_nonzero(id) || !sa ||
	    (size_t)salen > sizeof(c->ss) || !node_addr_usable(sa, salen) ||
	    addr_martian(sa, salen) || !memcmp(id, e->myid, 20))
		return;
	for (i = 0; i < B44_CACHE_MAX; i++) {
		c = &e->cache[i];
		if (c->sslen && addr_same_host(sa, salen, &c->ss, c->sslen)) {
			memcpy(c->id, id, 20);
			memcpy(&c->ss, sa, salen);
			c->sslen = salen;
			c->seen_ms = now_ms();
			return;
		}
	}
	c = &e->cache[e->cache_next];
	e->cache_next = (e->cache_next + 1) % B44_CACHE_MAX;
	memset(c, 0, sizeof(*c));
	memcpy(c->id, id, 20);
	memcpy(&c->ss, sa, salen);
	c->sslen = salen;
	c->seen_ms = now_ms();
}

static size_t cache_nodes(struct bep44_engine *e, const uint8_t target[20],
			  int af, uint8_t *out, size_t out_cap)
{
	uint8_t pdist[B44_REPLY_NODES][20];
	int pick[B44_REPLY_NODES];
	size_t entry = af == AF_INET ? 26 : 38;
	uint64_t now = now_ms();
	int i, j, n = 0;
	size_t len = 0;

	if (out_cap < entry)
		return 0;
	for (i = 0; i < B44_CACHE_MAX; i++) {
		struct b44_cnode *c = &e->cache[i];
		uint8_t d[20];

		if (!c->sslen || c->ss.ss_family != af ||
		    now - c->seen_ms > B44_CACHE_TTL_MS)
			continue;
		dist_calc(d, c->id, target);
		for (j = 0; j < n; j++) {
			if (memcmp(d, pdist[j], 20) < 0)
				break;
		}
		if (j >= B44_REPLY_NODES)
			continue;
		if (n < B44_REPLY_NODES)
			n++;
		for (int m = n - 1; m > j; m--) {
			pick[m] = pick[m - 1];
			memcpy(pdist[m], pdist[m - 1], 20);
		}
		pick[j] = i;
		memcpy(pdist[j], d, 20);
	}
	for (i = 0; i < n && len + entry <= out_cap; i++) {
		struct b44_cnode *c = &e->cache[pick[i]];

		memcpy(out + len, c->id, 20);
		if (af == AF_INET) {
			const struct sockaddr_in *s =
				(const struct sockaddr_in *)&c->ss;

			memcpy(out + len + 20, &s->sin_addr, 4);
			memcpy(out + len + 24, &s->sin_port, 2);
		} else {
			const struct sockaddr_in6 *s =
				(const struct sockaddr_in6 *)&c->ss;

			memcpy(out + len + 20, &s->sin6_addr, 16);
			memcpy(out + len + 36, &s->sin6_port, 2);
		}
		len += entry;
	}
	return len;
}

/* -- incoming queries ---------------------------------------------------- */

struct b44_query {
	struct bep44_engine *e;
	const uint8_t *tid;
	size_t tid_len;
	const uint8_t *id;
	const struct sockaddr *from;
	socklen_t fromlen;
	const uint8_t *args;
	size_t args_len;
	uint8_t want4;
	uint8_t want6;
};

static void query_send(struct b44_query *q, const uint8_t *msg, size_t len)
{
	struct sockaddr_storage ss;

	if (!q->from || !q->fromlen || (size_t)q->fromlen > sizeof(ss))
		return;
	memset(&ss, 0, sizeof(ss));
	memcpy(&ss, q->from, q->fromlen);
	msg_send(q->e, &ss, q->fromlen, msg, len);
}

/* A KRPC error is y="e" with e=[code, message] and no r dict at all. */
static void send_error(struct b44_query *q, int code, const char *msg)
{
	uint8_t buf[256];
	struct benc_buf b;

	benc_buf_init(&b, buf, sizeof(buf));
	benc_raw_add(&b, "d1:el", 5);
	benc_int_add(&b, code);
	benc_str_add(&b, msg, strlen(msg));
	benc_raw_add(&b, "e1:t", 4);
	benc_str_add(&b, q->tid, q->tid_len);
	benc_raw_add(&b, "1:y1:ee", 7);
	if (!b.err)
		query_send(q, buf, b.len);
}

static void send_ack(struct b44_query *q)
{
	uint8_t buf[128];
	struct benc_buf b;

	benc_buf_init(&b, buf, sizeof(buf));
	benc_raw_add(&b, "d1:rd", 5);
	benc_key_add(&b, "id");
	benc_str_add(&b, q->e->myid, 20);
	benc_raw_add(&b, "e1:t", 4);
	benc_str_add(&b, q->tid, q->tid_len);
	benc_raw_add(&b, "1:y1:re", 7);
	if (!b.err)
		query_send(q, buf, b.len);
}

/*
 * Argument accessors with three outcomes, because a field that is present but
 * malformed must never be mistaken for one that is absent: reading a mangled
 * cas as "no cas given" is exactly how a compare-and-swap gets bypassed.
 * 0 = present and of the wanted type, 1 = absent, -1 = present but malformed.
 * These distinguish a field's own type; a put runs benc_canonical over the
 * whole args dict first, so a dict that stops parsing before the field cannot
 * masquerade as the field being absent. A get carries nothing signed, so the
 * worst such a malformed get can do is hide the asker's own conditional seq.
 */
static int arg_raw(struct b44_query *q, const char *key, const uint8_t **data,
		   size_t *len)
{
	if (!q->args || benc_dict_find(q->args, q->args_len, key, data, len))
		return 1;
	return 0;
}

static int arg_str(struct b44_query *q, const char *key, const uint8_t **data,
		   size_t *len)
{
	const uint8_t *val;
	size_t val_len;

	if (!q->args ||
	    benc_dict_find(q->args, q->args_len, key, &val, &val_len))
		return 1;
	return benc_str_get(val, val_len, data, len) ? -1 : 0;
}

static int arg_int(struct b44_query *q, const char *key, int64_t *out)
{
	const uint8_t *val;
	size_t val_len;

	if (!q->args ||
	    benc_dict_find(q->args, q->args_len, key, &val, &val_len))
		return 1;
	return benc_int_get(val, val_len, out) ? -1 : 0;
}

static void handle_get(struct b44_query *q)
{
	struct bep44_engine *e = q->e;
	const uint8_t *target;
	size_t tlen, nlen;
	int64_t want_seq = 0;
	int rc, have_seq, serve_value = 1;
	struct b44_item **slot, *it = NULL;
	uint8_t msg[B44_MSG_MAX];
	uint8_t nodes[B44_REPLY_NODES * 38];
	uint8_t token[B44_TOKEN_LEN];
	struct benc_buf b;

	if (arg_str(q, "target", &target, &tlen) || tlen != 20) {
		send_error(q, 203, "get requires a 20-byte target");
		return;
	}
	rc = arg_int(q, "seq", &want_seq);
	if (rc < 0) {
		send_error(q, 203, "seq must be an integer");
		return;
	}
	have_seq = rc == 0;

	store_expire(e, now_ms());
	slot = store_slot_of(e, target);
	if (slot)
		it = *slot;
	/*
	 * A conditional get withholds the value only from an asker that already
	 * has this seq or a better one. There is no floor on the asker's seq: a
	 * negative one is below every stored seq, so the value is still due. An
	 * immutable item has no seq to compare and is always served.
	 */
	if (it && it->is_mutable && have_seq && it->seq <= want_seq)
		serve_value = 0;

	token_make(token, e->token_secret[0], q->from, q->fromlen, target);

	benc_buf_init(&b, msg, sizeof(msg));
	benc_raw_add(&b, "d1:rd", 5);
	benc_key_add(&b, "id");
	benc_str_add(&b, e->myid, 20);
	if (it && it->is_mutable && serve_value) {
		benc_key_add(&b, "k");
		benc_str_add(&b, it->k, 32);
	}
	/*
	 * Referrals and a value are alternatives, not a pair: once the value is
	 * in the reply the asker's lookup is over, so leaving the node lists out
	 * keeps the reply inside one datagram. A get is unauthenticated, so a
	 * value reply is still larger than the query -- the rate limiter, not
	 * this, is what bounds that reflection.
	 */
	if (!(it && serve_value)) {
		if (q->want4) {
			nlen = cache_nodes(e, target, AF_INET, nodes,
					   sizeof(nodes));
			if (nlen) {
				benc_key_add(&b, "nodes");
				benc_str_add(&b, nodes, nlen);
			}
		}
		if (q->want6) {
			nlen = cache_nodes(e, target, AF_INET6, nodes,
					   sizeof(nodes));
			if (nlen) {
				benc_key_add(&b, "nodes6");
				benc_str_add(&b, nodes, nlen);
			}
		}
	}
	if (it && it->is_mutable) {
		benc_key_add(&b, "seq");
		benc_int_add(&b, it->seq);
	}
	if (it && it->is_mutable && serve_value) {
		benc_key_add(&b, "sig");
		benc_str_add(&b, it->sig, 64);
	}
	benc_key_add(&b, "token");
	benc_str_add(&b, token, B44_TOKEN_LEN);
	if (it && serve_value) {
		benc_key_add(&b, "v");
		benc_raw_add(&b, it->v, it->v_len);
	}
	benc_raw_add(&b, "e1:t", 4);
	benc_str_add(&b, q->tid, q->tid_len);
	benc_raw_add(&b, "1:y1:re", 7);
	if (!b.err)
		query_send(q, msg, b.len);
}

static void handle_put(struct b44_query *q)
{
	struct bep44_engine *e = q->e;
	const uint8_t *v, *tok, *k = NULL, *sig = NULL, *salt = NULL;
	size_t v_len, tok_len, k_len = 0, sig_len = 0, salt_len = 0;
	int64_t seq = 0, cas = 0;
	int have_k, have_sig, have_salt, have_seq, have_cas, is_mutable, rc;
	uint8_t target[20];
	uint8_t sigbuf[BEP44_MAX_VALUE + 128];
	uint64_t now = now_ms();
	struct b44_item **slot, *it, *fresh;

	/*
	 * The signature covers the value's exact bytes, so an item encoded
	 * non-canonically cannot survive a hop that re-encodes it. Refuse the
	 * put rather than store something nobody downstream can verify.
	 */
	if (benc_canonical(q->args, q->args_len)) {
		send_error(q, 203, "put arguments are not canonical bencode");
		return;
	}
	if (arg_raw(q, "v", &v, &v_len)) {
		send_error(q, 203, "put requires v");
		return;
	}

	rc = arg_str(q, "k", &k, &k_len);
	if (rc < 0) {
		send_error(q, 203, "k must be a string");
		return;
	}
	have_k = rc == 0;
	rc = arg_str(q, "sig", &sig, &sig_len);
	if (rc < 0) {
		send_error(q, 203, "sig must be a string");
		return;
	}
	have_sig = rc == 0;
	rc = arg_str(q, "salt", &salt, &salt_len);
	if (rc < 0) {
		send_error(q, 203, "salt must be a string");
		return;
	}
	have_salt = rc == 0;
	rc = arg_int(q, "seq", &seq);
	if (rc < 0) {
		send_error(q, 203, "seq must be an integer");
		return;
	}
	have_seq = rc == 0;
	rc = arg_int(q, "cas", &cas);
	if (rc < 0) {
		send_error(q, 203, "cas must be an integer");
		return;
	}
	have_cas = rc == 0;

	/*
	 * Any one mutable field commits the put to being mutable, and then all
	 * of k, sig and seq must be there and well formed. A malformed mutable
	 * put is refused outright, never quietly demoted to an immutable store
	 * at sha1(v): that turns a write the sender never authorised into one
	 * that lands under a name they cannot predict.
	 */
	is_mutable = have_k || have_sig || have_seq || have_cas;
	if (is_mutable &&
	    (!have_k || !have_sig || !have_seq || k_len != 32 ||
	     sig_len != 64 || seq < 0)) {
		send_error(q, 203, "incomplete or malformed mutable put");
		return;
	}
	if (!have_salt)
		salt_len = 0;

	/* The target is derived here and nowhere else; a target sent in the
	 * put is not consulted, or any signed value could squat any id. */
	if (is_mutable)
		target_n(target, k, salt, salt_len);
	else
		cc_sha1(target, v, v_len);

	if (arg_str(q, "token", &tok, &tok_len) ||
	    !token_valid(e, tok, tok_len, q->from, q->fromlen, target)) {
		send_error(q, 203, "bad write token");
		return;
	}
	if (v_len > BEP44_MAX_VALUE) {
		send_error(q, 205, "message (v field) too big");
		return;
	}
	if (salt_len > BEP44_MAX_SALT) {
		send_error(q, 207, "salt (salt field) too big");
		return;
	}
	if (is_mutable) {
		size_t n = sig_buffer_n(sigbuf, sizeof(sigbuf), salt, salt_len,
					seq, v, v_len);

		if (!n || cc_ed25519_check(sig, k, sigbuf, n)) {
			send_error(q, 206, "invalid signature");
			return;
		}
	}

	store_expire(e, now);
	slot = store_slot_of(e, target);
	it = slot ? *slot : NULL;
	if (it) {
		if (it->is_mutable != (is_mutable ? 1 : 0)) {
			send_error(q, 203,
				   "cannot replace an item with the other kind");
			return;
		}
		if (!it->is_mutable) {
			/* Immutable: the value is its own name, so a repeat put
			 * carries the same bytes. Keep it alive. */
			it->expires_ms = now + B44_ITEM_TTL_MS;
			send_ack(q);
			return;
		}
		if (have_cas && cas != it->seq) {
			send_error(q, 301,
				   "CAS mismatched, re-read value and try again");
			return;
		}
		if (seq == it->seq && v_len == it->v_len &&
		    !memcmp(v, it->v, v_len)) {
			it->expires_ms = now + B44_ITEM_TTL_MS;
			send_ack(q);
			return;
		}
		if (seq <= it->seq) {
			send_error(q, 302, "sequence number less than current");
			return;
		}
	}

	fresh = item_new(target, v, v_len, now);
	if (!fresh) {
		send_error(q, 202, "server error");
		return;
	}
	if (is_mutable) {
		fresh->is_mutable = 1;
		fresh->seq = seq;
		memcpy(fresh->k, k, 32);
		memcpy(fresh->sig, sig, 64);
		if (salt_len)
			memcpy(fresh->salt, salt, salt_len);
		fresh->salt_len = (uint8_t)salt_len;
	}
	if (slot) {
		free(*slot);
		*slot = fresh;
	} else {
		int at = store_free_slot(e, target);

		if (at < 0) {
			/* The store is full of items we are a closer node for.
			 * Acknowledge -- the value lives on the nodes that are
			 * its proper home -- but do not evict a nearer item. */
			free(fresh);
			send_ack(q);
			return;
		}
		e->store[at] = fresh;
	}
	send_ack(q);
}

/* BEP 32: which address families the asker wants back. Absent means the one it
 * reached us on, which is all a v4-only or v6-only peer can use anyway. */
static void want_parse(struct b44_query *q)
{
	const uint8_t *want;
	size_t want_len, i;

	if (arg_raw(q, "want", &want, &want_len)) {
		q->want4 = q->from && q->from->sa_family == AF_INET;
		q->want6 = q->from && q->from->sa_family == AF_INET6;
		return;
	}
	for (i = 0; i + 4 <= want_len; i++) {
		if (!memcmp(want + i, "2:n4", 4))
			q->want4 = 1;
		else if (!memcmp(want + i, "2:n6", 4))
			q->want6 = 1;
	}
}

/*
 * Prefix ladders the ban list widens along. v6 is coarse-stepped: a customer
 * holds a /64 at least, often a /56 or /48, so a lone /128 is pointless to
 * block and the useful units start at /64. v4 is fine-stepped and stops at
 * /24: an attacker's contiguous block is small, and a whole ISP can sit behind
 * a /24, so widening past it would punish bystanders for one bad host.
 */
static const uint8_t b44_ladder6[] = { 128, 64, 56, 48, 40, 32 };
static const uint8_t b44_ladder4[] = { 32, 30, 28, 26, 24 };

static size_t fam_len(int family)
{
	return family == AF_INET6 ? 16 : 4;
}

static int ban_base_bits(int family)
{
	return family == AF_INET6 ? 128 : 32;
}

/* Copy addr into out, clearing every bit past the prefix length. */
static void net_mask(uint8_t out[16], const uint8_t *addr, size_t alen, int bits)
{
	size_t i;

	for (i = 0; i < alen; i++) {
		int keep = bits - (int)i * 8;

		if (keep >= 8)
			out[i] = addr[i];
		else if (keep <= 0)
			out[i] = 0;
		else
			out[i] = addr[i] & (uint8_t)(0xff << (8 - keep));
	}
}

/* Does addr fall inside this ban's prefix? (family is checked by the caller.) */
static int net_contains(const struct b44_ban *b, const uint8_t *addr, size_t alen)
{
	uint8_t m[16];

	net_mask(m, addr, alen, b->bits);
	return !memcmp(m, b->net, alen);
}

/*
 * A prefix has just been banned: walk up its family's ladder and, at each
 * wider prefix, sum the offender weight of the bans within it; when that
 * reaches the level's threshold (one more per step -- 2 for the first widening,
 * 3 for the next, and so on) replace those bans with a single ban of the wider
 * prefix carrying their combined weight, then keep climbing. Because a banned
 * prefix already swallows its interior, the weight in a wider prefix can only
 * grow through offenders in distinct un-banned siblings, so widening tracks
 * spread, not a single busy corner.
 */
static void ban_escalate(struct bep44_engine *e, const uint8_t seed_net[16],
			 int family, uint64_t now)
{
	const uint8_t *ladder = family == AF_INET6 ? b44_ladder6 : b44_ladder4;
	size_t n = family == AF_INET6 ? sizeof(b44_ladder6) : sizeof(b44_ladder4);
	size_t alen = fam_len(family);
	size_t i;

	for (i = 1; i < n; i++) {		/* index 0 is the base; parents follow */
		int pbits = ladder[i];
		uint8_t pnet[16], bm[16];
		int j, weight = 0, first = -1;

		net_mask(pnet, seed_net, alen, pbits);
		for (j = 0; j < B44_BAN_MAX; j++) {
			struct b44_ban *b = &e->ban[j];

			if (b->family != family || b->banned_until <= now ||
			    b->bits < pbits)
				continue;
			net_mask(bm, b->net, alen, pbits);
			if (memcmp(bm, pnet, alen))
				continue;
			weight += b->weight;
			if (first < 0)
				first = j;
		}
		if (weight < (int)(i + 1))	/* one more offender per level */
			continue;
		for (j = 0; j < B44_BAN_MAX; j++) {
			struct b44_ban *b = &e->ban[j];

			if (b->family != family || b->banned_until <= now ||
			    b->bits < pbits)
				continue;
			net_mask(bm, b->net, alen, pbits);
			if (!memcmp(bm, pnet, alen))
				memset(b, 0, sizeof(*b));
		}
		memset(&e->ban[first], 0, sizeof(e->ban[first]));
		memcpy(e->ban[first].net, pnet, alen);
		e->ban[first].family = (uint8_t)family;
		e->ban[first].bits = (uint8_t)pbits;
		e->ban[first].weight = (uint16_t)weight;
		e->ban[first].banned_until = now + e->rl_ban_ms;
		if (debug_on())
			fprintf(stderr,
				"[bep44] widen ban to %s /%d (%d offenders)\n",
				family == AF_INET6 ? "v6" : "v4", pbits, weight);
	}
}

/*
 * The per-source half of the limit. A source is dropped if it falls inside a
 * banned prefix; otherwise it is rate-tracked at its family's base prefix
 * (/64 for v6, /32 for v4). Exceeding the bucket only throttles; sustained
 * abuse past the empty bucket bans the prefix and tries to widen the ban. When
 * every slot is an active ban the table is saturated, so the node fails closed,
 * dropping all unsolicited queries for a cool-off. A caller with no usable
 * address is left to the global bucket.
 */
static int ban_ok(struct bep44_engine *e, const struct sockaddr *from,
		  socklen_t fromlen)
{
	const uint8_t *ab;
	size_t alen = addr_bytes(from, fromlen, &ab);
	int family = from ? from->sa_family : 0;
	uint64_t now = now_ms();
	struct b44_ban *track = NULL, *slot = NULL, *lru = NULL;
	uint8_t base[16];
	int i, base_bits;

	if (!e->rl_ban_ms)		/* rate limiting disabled (a test driver) */
		return 1;
	if (e->block_all_until > now)
		return 0;
	if (!alen)
		return 1;

	base_bits = ban_base_bits(family);
	net_mask(base, ab, alen, base_bits);

	for (i = 0; i < B44_BAN_MAX; i++) {
		struct b44_ban *b = &e->ban[i];

		if (!b->family) {
			if (!slot)
				slot = b;
			continue;
		}
		if (b->banned_until && b->banned_until <= now) {
			memset(b, 0, sizeof(*b));	/* expired: reclaim */
			if (!slot)
				slot = b;
			continue;
		}
		if (b->family != family)
			continue;
		if (b->banned_until > now && net_contains(b, ab, alen))
			return 0;			/* inside a banned prefix */
		if (!b->banned_until) {
			if (b->bits == base_bits && !memcmp(b->net, base, alen))
				track = b;
			if (!lru || b->count < lru->count)
				lru = b;
		}
	}

	if (track) {
		if (now >= track->window_ms) {	/* window elapsed: start a fresh one */
			track->count = 0;
			track->window_ms = now + B44_BAN_WINDOW_MS;
		}
		if (++track->count < e->rl_rate * 10)
			return 1;		/* under the window's limit: served */
		/* too many in one window: ban the address and try to widen it */
		track->banned_until = now + e->rl_ban_ms;
		track->weight = 1;
		track->count = 0;
		if (debug_on())
			fprintf(stderr, "[bep44] ban %s /%u %02x%02x%02x%02x\n",
				family == AF_INET6 ? "v6" : "v4", track->bits,
				track->net[0], track->net[1], track->net[2],
				track->net[3]);
		ban_escalate(e, track->net, family, now);
		return 0;
	}

	if (!slot)
		slot = lru;			/* reuse the least active tracker */
	if (!slot) {
		e->block_all_until = now + B44_FAILCLOSED_MS;	/* saturated */
		if (debug_on())
			fprintf(stderr, "[bep44] ban table full, failing closed\n");
		return 0;
	}
	memset(slot, 0, sizeof(*slot));
	memcpy(slot->net, base, alen);
	slot->family = (uint8_t)family;
	slot->bits = (uint8_t)base_bits;
	slot->count = 1;
	slot->window_ms = now + B44_BAN_WINDOW_MS;
	return 1;
}

static int query_handle(struct bep44_engine *e, const uint8_t *buf, size_t len,
			const struct sockaddr *from, socklen_t fromlen)
{
	struct b44_query q;
	const uint8_t *val, *meth;
	size_t val_len, meth_len, id_len;
	int is_put;

	if (!e->serving)
		return 0;
	if (benc_dict_find(buf, len, "q", &val, &val_len) ||
	    benc_str_get(val, val_len, &meth, &meth_len) || meth_len != 3)
		return 0;
	if (!memcmp(meth, "get", 3))
		is_put = 0;
	else if (!memcmp(meth, "put", 3))
		is_put = 1;
	else
		return 0;

	/*
	 * A martian source is dropped, not served: it is either spoofed (so a
	 * reply is a reflection aimed at that address) or unroutable. It is
	 * consumed here rather than handed on, since jech/dht would only drop it
	 * too. Over the rate limit, likewise drop it silently.
	 */
	if (addr_martian(from, fromlen) || !ban_ok(e, from, fromlen))
		return 1;

	/* From here the query is ours to answer, well formed or not: falling
	 * through would let the BEP 5 engine reply to it as well. */
	memset(&q, 0, sizeof(q));
	q.e = e;
	q.from = from;
	q.fromlen = fromlen;
	if (benc_dict_find(buf, len, "t", &val, &val_len) ||
	    benc_str_get(val, val_len, &q.tid, &q.tid_len) ||
	    q.tid_len > B44_TID_MAX)
		return 1;		/* nothing to address a reply to */

	if (benc_dict_find(buf, len, "a", &val, &val_len) || val_len < 2 ||
	    val[0] != 'd') {
		send_error(&q, 203, "missing arguments dict");
		return 1;
	}
	q.args = val;
	q.args_len = val_len;
	if (arg_str(&q, "id", &q.id, &id_len) || id_len != 20) {
		send_error(&q, 203, "bad node id");
		return 1;
	}
	if (is_put) {
		handle_put(&q);
	} else {
		want_parse(&q);
		handle_get(&q);
	}
	return 1;
}

/*
 * Tune or disable the per-source rate limiter, the way libtorrent exposes
 * dht_block_ratelimit / dht_block_timeout. A real node keeps the default (a
 * source is banned for ban_seconds once it exceeds per_source_rate messages a
 * second over a 10s window); a conformance harness passes ban_seconds 0 to turn
 * it off, since a black-box suite drives one source far faster than any peer --
 * exactly what drivers/libtorrent does to run the same tests.
 */
void bep44_ratelimit(struct bep44_engine *e, int per_source_rate,
		     int ban_seconds)
{
	e->rl_rate = per_source_rate;
	e->rl_ban_ms = (uint64_t)(ban_seconds > 0 ? ban_seconds : 0) * 1000;
}

int bep44_serve(struct bep44_engine *e, int enable)
{
	if (!enable) {
		e->serving = 0;
		return 0;
	}
	if (!e->serving) {
		if (random_bytes(e->token_secret[0], B44_SECRET_LEN) ||
		    random_bytes(e->token_secret[1], B44_SECRET_LEN))
			return -1;
		e->token_rotate_ms = now_ms() + B44_TOKEN_ROTATE_MS;
		e->rl_rate = B44_BAN_RATE;
		e->rl_ban_ms = B44_BAN_TIME_MS;
		e->serving = 1;
	}
	return 0;
}

/*
 * Returns 1 when the datagram was consumed here -- one of our replies, or a
 * get/put we answered or deliberately dropped (martian, rate-limited, or
 * unanswerable) -- and 0 when the caller should hand it to its BEP 5 engine
 * instead. Nothing is ever answered by both.
 */
int bep44_input(struct bep44_engine *e, const uint8_t *buf, size_t len,
		const struct sockaddr *from, socklen_t fromlen)
{
	const uint8_t *val, *t, *y;
	size_t val_len, t_len, y_len;
	uint16_t tid;
	int is_error;
	struct b44_op *op;

	if (benc_dict_find(buf, len, "y", &val, &val_len) ||
	    benc_str_get(val, val_len, &y, &y_len) || y_len != 1)
		return 0;
	if (y[0] == 'q')
		return query_handle(e, buf, len, from, fromlen);
	if (y[0] == 'e')
		is_error = 1;
	else if (y[0] == 'r')
		is_error = 0;
	else
		return 0;

	if (benc_dict_find(buf, len, "t", &val, &val_len) ||
	    benc_str_get(val, val_len, &t, &t_len))
		return 0;
	if (t_len != 4 || t[0] != 'p' || t[1] != 'm')
		return 0;
	tid = (uint16_t)(t[2] | t[3] << 8);

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

	if (e->serving) {
		uint64_t now = now_ms();

		token_rotate(e, now);
		store_expire(e, now);
	}

	while (op) {
		struct b44_op *next = op->next;

		op_step(op);
		op = next;
	}

	if (e->ops && *timeout_ms > 300)
		*timeout_ms = 300;
	return e->ops != NULL;
}

static struct b44_op *op_new(struct bep44_engine *e, const uint8_t target[20],
			    int direct)
{
	struct b44_op *op = calloc(1, sizeof(*op));
	int i;

	if (!op)
		return NULL;
	op->e = e;
	op->direct = (uint8_t)(direct != 0);
	memcpy(op->target, target, 20);
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

static struct b44_op *op_create(struct bep44_engine *e, const uint8_t pk[32],
				const char *salt, int direct)
{
	struct b44_op *op;
	uint8_t target[20];

	if (strlen(salt) > BEP44_MAX_SALT)
		return NULL;
	bep44_target(target, pk, salt);
	op = op_new(e, target, direct);
	if (!op)
		return NULL;
	memcpy(op->pk, pk, 32);
	strcpy(op->salt, salt);
	return op;
}

int bep44_seed_add(struct bep44_engine *e, const uint8_t id[20],
		   const struct sockaddr *sa, socklen_t salen)
{
	struct b44_seed *seed;
	int i;

	if ((size_t)salen > sizeof(seed->ss))
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

	if (!v_len || v_len > BEP44_MAX_VALUE)
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

int bep44_put_immutable(struct bep44_engine *e, const uint8_t *v, size_t v_len,
			bep44_put_cb *cb, void *arg)
{
	struct b44_op *op;
	uint8_t target[20];

	if (!v_len || v_len > BEP44_MAX_VALUE)
		return -1;
	cc_sha1(target, v, v_len);
	op = op_new(e, target, 0);
	if (!op)
		return -1;
	op->is_put = 1;
	op->is_immutable = 1;
	op->cas = -1;
	memcpy(op->value, v, v_len);
	op->value_len = (uint16_t)v_len;
	op->put_cb = cb;
	op->cb_arg = arg;
	op_step(op);
	return 0;
}

int bep44_get_immutable(struct bep44_engine *e, const uint8_t target[20],
			bep44_get_cb *cb, void *arg)
{
	struct b44_op *op = op_new(e, target, 0);

	if (!op)
		return -1;
	op->is_immutable = 1;
	op->get_cb = cb;
	op->cb_arg = arg;
	op_step(op);
	return 0;
}
