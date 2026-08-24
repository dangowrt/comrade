/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "candpolicy.h"
#include "conn.h"
#include "ctlproto.h"
#include "dbg.h"
#include "keys.h"
#include "lanlink.h"
#include "nat.h"
#include "netmon.h"
#include "path.h"
#include "session.h"
#include "sig.h"
#include "sshbridge.h"
#include "sshc.h"
#include "sshd.h"
#include "stream.h"
#include "stunlist.h"
#include "stunprobe.h"
#include "tokgen.h"

#define SESSION_CONV 0x70326531

/*
 * Liveness heartbeat cadence over the comrade-ctl control channel (framing in
 * ctlproto.h): a ping every HB_INTERVAL_MS, and the link is declared lost when
 * nothing at all -- no pong, and no other traffic -- has arrived from the peer
 * for HB_LOST_MS. The pong alone must not carry the verdict: it rides the
 * same stream as bulk data through several queues, so on a saturated slow
 * link it arrives seconds late while the transfer is demonstrably moving
 * (measured at carrier fair-use rates: the link declared lost, and the worker
 * reaped, mid-download). Arriving datagrams are the liveness; the pong's own
 * job is the round-trip figure.
 */
#define HB_INTERVAL_MS 700
#define HB_LOST_MS 2500
/*
 * A host worker whose client has been silent this long is presumed gone and the
 * worker reaps itself: with no clean disconnect the SSH bridge never ends on its
 * own (KCP buffers a dead path indefinitely), so the heartbeat is what frees the
 * worker (and its tmux client). Well above HB_LOST_MS so a brief outage, during
 * which the client may still be reconnecting, does not tear a live worker down,
 * and well above PATH_DEAD_MS so a client moving between paths is never
 * reaped mid-switch.
 */
#define HOST_REAP_MS 12000
/*
 * Rendezvous keep-warm cadence. Re-validating a rendezvous node touches the
 * DHT, so do it rarely: a node dying AND a roam needing it inside the same
 * window is unlikely, and a full DHT lookup is always the fallback. Poll faster
 * only until the first node is captured after locate starts. The peer
 * announcement rides the transport (not the DHT), so it can refresh more often.
 */
#define RDV_WARM_MS 180000		/* 3 min: re-validate/keep warm */
#define RDV_POLL_MS 5000		/* until the first node is captured */
#define RDV_TELL_MS 30000		/* announce our nodes to the peer */
/*
 * Candidate advertisement cadence. Each end names its own local endpoints on
 * the shared lanlink socket over CTLM_CAND, so both explore the full set rather
 * than only the pair admission produced, and a multi-homed end has its
 * alternatives warm before anything fails. Repeated on a period rather than
 * sent once: an interface brought up mid-session is then advertised within one,
 * and a frame is 21 bytes.
 */
#define CAND_TELL_MS 5000

/* Rendezvous node kept for reconnection (ours when we can reach the family, or
 * the peer's for a family we cannot yet reach but might roam to). */
struct rdv_node {
	struct sockaddr_storage sa;
	socklen_t len;
	int have;
};

/* [0] is IPv4, [1] is IPv6. */
static int fam_idx(int family)
{
	return family == 6 ? 1 : 0;
}
/*
 * Backstop only, well above real-internet connect time: libjuice reaches its
 * own FAILED verdict after a full ICE negotiation, which drives retry; this
 * catches an agent that neither connects nor fails.
 */
#define ICE_ATTEMPT_MS 90000

/*
 * If, this long after start, we still hold only a private/CGNAT IPv4 and STUN
 * has not returned a public one, the STUN pool is probably stale or unreachable
 * -- warn once and point at `comrade stun-update`.
 */
#define STUN_WARN_MS 8000

/*
 * If a gather has held a private/CGNAT IPv4 this long with no reflexive one,
 * the pool server this attempt drew is written off and the next one is tried
 * -- but only while no peer has answered yet: from then on the ICE retry path
 * owns rotation. Bounded, so a network that filters all STUN settles for the
 * STUN_WARN_MS escalation instead of churning offers forever.
 */
#define STUN_ROTATE_MS 3000
#define STUN_ROTATE_MAX 3

/*
 * A path is qualified when an authenticated probe has round-tripped on it; the
 * probe cadences, the measurements and the choice between paths are the model
 * in path.h. This bounds only the wait: how long a client keeps probing after
 * its claim has left the answer slot before concluding it was not the pickup.
 * Only ever measured from that moment, never from the start of the attempt: a
 * claim still sitting in the slot is queued, however long the queue, and a
 * timeout that cannot tell those two apart livelocks one case or the other
 * (measured, both ways).
 *
 * Two bounds, because the slot's exit says how it left. A claim the host
 * consumed is in all likelihood being punched right now, and a punch through
 * carrier-grade NAT takes several seconds of checks before the first one
 * lands, so it gets the long wait. One overwritten by a rival claimant is
 * settled -- the host will punch the rival, never this agent -- and waits only
 * long enough to absorb a stale read of the slot.
 */
#define PATH_PROBE_MS 12000
#define PATH_LOST_MS 2500

/*
 * Public v4 addresses remembered per network for the reflexive fan-out. A
 * subscriber's flows spread only as wide as the NAT group behind its session
 * anchor, never the operator's whole pool: paired pooling is the deployed
 * default (RFC 6888 REQ-2) and per-subscriber traceability pushes the same
 * way, so the measured three-member spray is already the pathology and eight
 * bounds it with headroom. The cap prices only observations -- the wire
 * carries observed members alone, 12 bytes each against SIG_MAX_VALUE, which
 * candpack_encode answers with a failed post rather than a truncated one.
 */
#define POOL4_MAX 8

/*
 * The active probe that fills the pool set: this many servers asked, over one
 * socket, the moment the session starts -- so the members are on the table
 * when the first description posts, rather than trickling in one gather at a
 * time (measured: one member per STUN name per agent, far too slow for a
 * punch on the first attempt). A handful of packets, once per network.
 */
#define STUN_PROBE_SERVERS 6
#define STUN_PROBE_MS 3000

/*
 * Post-teardown linger for the bridge. The host keeps flushing generously, to
 * land the dedicated end-of-session signal (the channel exit-status and close)
 * on the client even over a lossy link -- it returns as soon as the client
 * acks, so this bound only bites when the client is genuinely gone. The client
 * exits as soon as it has that signal, so its own closing bytes are
 * non-critical and it lingers only briefly rather than waiting on acks a
 * departed host will never send.
 */
#define LINGER_HOST_MS 5000
#define LINGER_CLIENT_MS 200

/* The host serves at most this many clients at once (ICE and LAN workers share
 * the budget). Defined here so the LAN admission registry can size to it. */
#define HOST_MAX_WORKERS 16

enum state {
	ST_WAIT_DHT,
	ST_GATHER,
	ST_SIGNAL,
	ST_WAIT_ICE,
	ST_RUN,
	ST_DONE,
	ST_FAIL,
};

struct sess;			/* forward: a conn carries a back-pointer to it */

/*
 * One client connection's running state: the transport (nat/stream), the SSH
 * session and its comrade-ctl channel, the liveness heartbeat, the peer's
 * rendezvous announcement, and this connection's status. A host serves several
 * of these at once over the shared tmux; today there is
 * one, embedded in the session. Callbacks reach the session through `sess`.
 */
struct conn {
	struct sess *sess;		/* the session this connection belongs to */

	/* This connection's ICE identity. A fresh one per host offer (single-use
	 * per join, so two clients never share credentials); the client keeps its
	 * one identity for the session. */
	uint16_t bind_port;
	char ice_ufrag[16];
	char ice_pwd[40];
	/* The peer ICE identity that primed this agent. Candidate trickles from
	 * a rotated offer must not be sent to an agent for an older offer. */
	char remote_ufrag[40];

	struct nat_agent *nat;
	struct stream *stream;
	pthread_mutex_t stream_lock;	/* guards c->stream: a transport receive
					 * thread (libjuice) or the host's main
					 * demux may touch it during teardown */

	/*
	 * Every path this connection holds, and the choice between them (the
	 * model is path.h). A transport reporting a pair says only that packets
	 * move; it does not say the far end is serving *us* -- a host answers a
	 * losing claimant's ICE checks with credentials every reader of its
	 * offer holds. So a path carries the session only once a probe has
	 * round-tripped on it bearing our own claimant identity.
	 *
	 * path_lock covers the table and nothing else: libjuice's receive
	 * thread, the host's main demux and this connection's own loop all
	 * reach it. It is never held across a lanlink_send, a nat_send, a seal
	 * or an agent call, and never nested with stream_lock in either order.
	 * The computations under it are the ranking, a handful of integer
	 * compares over at most PATH_TABLE_MAX entries, and the path id, a keyed
	 * digest over 36 bytes taken when an endpoint of the pair is learnt or
	 * changes.
	 */
	struct path_table paths;
	pthread_mutex_t path_lock;
	uint64_t next_ice_ep_ms;	/* when to ask the agent which pair it
					 * has nominated (see conn_ice_ep) */
	/*
	 * The turnstile's answer slot is the mutex, so it -- not a clock -- says
	 * whether this client is still in the running. held_seen records that our
	 * claim reached the slot; released_ms is when it left again, which is the
	 * host picking somebody up. If that somebody was us a worker now exists and
	 * a probe answers within a round trip; if it was not, nothing ever will.
	 * claim_lost records that the slot left HELD by being overwritten (BUSY):
	 * a rival queued over us, so no pickup of our claim is coming.
	 */
	int claim_held_seen;
	int claim_lost;
	uint64_t claim_released_ms;
	int pongs_sent;			/* answered pings (test_drop_pong's count) */

	/*
	 * In-place transport resume. On the client, a lost link re-claims
	 * through the turnstile under this connection's own session-stable ICE
	 * identity, so the host recognises the claimant and grafts the fresh
	 * punch into the worker it already runs -- the SSH session, the
	 * forwards and their carried TCP streams ride through on KCP
	 * retransmission (rs_state: 0 idle, 1 gathering, 2 claimed). On the
	 * host, the turnstile parks the punched agent in resume_agent for the
	 * worker's own thread to adopt -- c->nat belongs to that thread -- and
	 * resume_pending holds the reap off while the punch is in flight.
	 */
	int rs_state;
	uint64_t rs_deadline;
	struct nat_agent *volatile resume_agent;
	volatile int resume_pending;
	uint64_t resume_last_ms;	/* host: when a resume punch last began,
					 * so a redelivered claim in the window
					 * between graft and first probe does
					 * not punch the same worker twice */
	/* The claimant's ICE ufrag, carried for the worker's whole lifetime so the
	 * host recognises the same client arriving over the other transport. */
	char claim_ufrag[40];
	/* The path deliberately made to die (test_blackhole_ms); bh_kind is -1
	 * while none is, bh_done once one has been (so a lift does not re-arm
	 * it). */
	int bh_kind;
	int bh_done;
	volatile int bh_mute;		/* test_blackhole_all: drop receives too,
					 * read on the receive threads */
	struct path_ep bh_ep;

	sock_t ssh_fd;			/* the ssh thread's socketpair end */
	sock_t ssh_ctl_fd;		/* the ssh thread's comrade-ctl end */
	sock_t ctl_fd;			/* our end of the comrade-ctl socketpair */
	struct ctl_reframer ctl_rf;	/* reassembles ctl messages across reads */
	int ssh_cli_rc;

	/* Liveness heartbeat: a tiny ping/pong over the comrade-ctl channel, so a
	 * dead link is noticed even when nobody is typing. Riding the reliable
	 * SSH/KCP stream, it measures end-to-end liveness -- a pong stops arriving
	 * once the link has truly stalled, which is exactly the signal we want. */
	pthread_mutex_t hb_lock;
	uint64_t hb_last_pong;		/* when a pong last came back */
	uint64_t hb_last_heard;		/* when anything last arrived from the
					 * peer (fed by the receive threads) */
	int hb_rtt;			/* round trip from the last pong, ms */
	int hb_pong_seen;		/* a pong has ever come back on this conn */
	uint64_t lost_since_ms;		/* when the link was first seen lost, 0 if live */

	/* The peer's rendezvous announcement, handed from the ctl reader to the
	 * loop; [0]=v4 [1]=v6. */
	struct rdv_node rdv_in[2];
	pthread_mutex_t rdv_lock;
	int rdv_in_dirty;
	uint64_t next_rdv_tell_ms;
	uint64_t next_cand_ms;		/* when to advertise our own endpoints */

	/* This connection's status (data only; the view renders it). */
	pthread_mutex_t status_lock;
	struct conn_status status;
	char status_peer[80];		/* address of the chosen pair, once live */
	int dash_id;			/* this connection's dashboard peer-row id */
	uint64_t next_status_ms;

	/* Read-only grade (host): the ssh thread sets it once the client has
	 * authenticated (which secret it used), the main loop reports it to the
	 * dashboard once. Written from the ssh thread, so volatile like done. */
	volatile int read_only;
	int ro_reported;		/* main-thread only: sent to the view yet */
	volatile int fwd_refused;	/* forwards the ssh thread refused */
	int fwd_reported;		/* main-thread only: refusal surfaced yet */
};

struct sess {
	const struct session_cfg *cfg;

	uint8_t auth[TOKEN_AUTH_LEN];

	struct sig *sig;
	struct lanlink *lan;
	struct session_keys keys;	/* sig_key, for sealing transport probes */

	struct netmon netmon;		/* detect a roam while still waiting */
	uint64_t next_roam_ms;		/* next synthetic change (test_roam_ms) */
	int roams;			/* synthetic changes reported so far */

	char local_sdp[NAT_SDP_MAX];
	volatile int have_local_sdp;
	/*
	 * Candidates as they trickle in (libjuice's gather thread appends here
	 * under trickle_lock; the main loop drains and reports them), so the local
	 * addresses show at once instead of waiting for gathering -- which can
	 * stall behind a slow STUN server -- to finish.
	 */
	char trickle_sdp[NAT_SDP_MAX];
	pthread_mutex_t trickle_lock;
	volatile int trickle_dirty;
	char src6[64];			/* address we source outbound global v6 from */
	char peer_sdp[NAT_SDP_MAX];
	volatile int have_peer_sdp;
	int remote_set;
	/*
	 * The ufrag of the newest offer seen in the peer slot, recorded even when
	 * the agent declines to adopt it. Release-on-pickup rotates a fresh ICE
	 * identity every time the host serves somebody, and it punches a claim with
	 * whatever listener is current when it *reads* it -- so a client still
	 * queued against an older offer would be punched by an agent whose
	 * credentials it does not hold, and could never pair.
	 */
	char cur_offer_ufrag[40];
	/*
	 * The offer we last re-gathered because of. Every pickup rotates, so N
	 * queued clients all go stale at the same instant; without this they
	 * re-gather in lockstep, collide on the answer slot and make no progress
	 * (measured: 10 re-claims for 4 pickups, 2 of 4 served).
	 */
	char regathered_for[40];
	struct conn *offer_conn;		/* live conn the peer-offer callback feeds */

	uint64_t ice_attempt_start;
	int ice_attempt;
	int expect4, expect6;		/* host has DHT reach on this family */
	int tok_state[2];		/* per family [0]=v4 [1]=v6, TOKEN_STATE_* */
	int tok_told[2];		/* the state has been reported at least once */
	int noconn_warned;		/* operator told no family can be advertised */
	uint64_t next_tok_ms;		/* throttle the per-family advert decision */
	uint64_t dht_since_ms;		/* this DHT attempt started (armed with sig) */

	uint64_t start_ms;		/* observer: session start, for escalation */
	int escalated;			/* observer: client warned of DHT warm */
	int peer_state;			/* observer: highest SESSION_PEER_* sent */
	int established_fired;		/* observer: established sent once */
	volatile int have_priv4;	/* a private/CGNAT v4 host candidate (needs
					 * STUN); set from the gather thread */
	volatile int have_srflx4;	/* STUN gave us a public v4 (reflexive) */
	int stun_warned;		/* warned once that STUN produced nothing */
	uint64_t stun_since_ms;		/* current agent started gathering */
	int stun_rotations;		/* pool servers written off this network */

	char status_rdv[80];		/* located rendezvous endpoint (host side) */

	/*
	 * Rendezvous nodes we have located and keep warm for a fast reconnect:
	 * [0]=v4 [1]=v6, our own located node per family (or the peer's, adopted
	 * for one we cannot yet reach but might roam to).
	 */
	struct rdv_node rdv[2];
	uint64_t next_rdv_warm_ms;

	char **stun_servers;		/* rotated across ICE retries (host:port) */
	int stun_count;
	char stun_host[128];		/* the current attempt's host, split out */
	/*
	 * Distinct public v4 addresses this network's NAT has been seen mapping
	 * our sockets to. One entry is the ordinary case; more mean a carrier
	 * pool that picks its member per destination, which is what the posted
	 * description must fan across (see fan_local_sdp). Grown from the
	 * gather thread and read at post time, both under trickle_lock; a roam
	 * empties it with the other per-network facts.
	 */
	uint8_t pool4[POOL4_MAX][4];
	int npool4;
	int pool_reported;		/* members the dashboard has been shown */
	int pool_posted;		/* members the posted description fans */
	pthread_t probe_th;		/* the active pool probe (stunprobe) */
	int probe_running;
	volatile int probe_stop;
	/*
	 * RFC 4787 mapping classification built from the same probe's
	 * responses (see stun_mapping_add) -- read and grown under
	 * trickle_lock alongside pool4.
	 */
	struct stun_mapping map4;
	int mapping_reported;		/* 0 not yet, 1 sent independent, 2 sent dependent */

	/*
	 * Host admission registry, all touched only on the host main thread (no
	 * lock): the active direct workers (for source-demux and dedup), a small
	 * bounded queue of newly-claimed endpoints awaiting a worker, and the
	 * claimant identities in flight -- one ufrag per punch slot, plus the most
	 * recently served one -- which both transports consult so a client is
	 * admitted once however it reached us.
	 */
	struct conn *lan_conns[HOST_MAX_WORKERS];
	struct {
		struct sockaddr_storage sa;
		socklen_t len;
		char ufrag[40];
	} lan_pending[HOST_MAX_WORKERS];
	int lan_pending_n;
	/*
	 * Every connection this host serves, whichever transport admitted it, so
	 * a probe from a source no path names can be matched to the claimant it
	 * names -- and the budget that bounds what a stranger can make us open
	 * (adopt_allow). Both belong to the thread that dispatches the shared
	 * lanlink socket, which is this one.
	 */
	struct conn *conns[HOST_MAX_WORKERS];
	int adopt_tokens;			/* thousandths of a token */
	uint64_t adopt_ms;
	char punch_ufrag[HOST_MAX_WORKERS][40];	/* each punch's claimant id */
	char last_served_ufrag[40];
	int admitted_n;			/* claimants admitted this run (the
					 * host_admit_max budget) */		/* the most recently served one */
	int have_served;

	struct conn c;			/* the (single, for now) connection */
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* "addr:port" of a sockaddr into out. */
static void addr_str(const struct sockaddr *sa, char *out, size_t n)
{
	char host[64];

	out[0] = '\0';
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		if (inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof(host)))
			snprintf(out, n, "%s:%u", host, ntohs(a->sin6_port));
	} else if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		if (inet_ntop(AF_INET, &a->sin_addr, host, sizeof(host)))
			snprintf(out, n, "%s:%u", host, ntohs(a->sin_port));
	}
}

/* First candidate address in an SDP into out; 1 if found. */
static int sdp_first_addr(const char *sdp, char *out, size_t n)
{
	const char *p = strstr(sdp, "a=candidate:");
	char addr[64];

	if (!p)
		return 0;
	if (sscanf(p, "a=candidate:%*s %*d %*s %*u %63s", addr) != 1)
		return 0;
	snprintf(out, n, "%s", addr);
	return 1;
}

/* "addr:port" from an ICE candidate line (as juice reports the selected pair);
 * handles both the "candidate:" and "a=candidate:" spellings. 1 if found. */
static int cand_addr(const char *cand, char *out, size_t n)
{
	const char *p = strstr(cand, "candidate:");
	char addr[64];
	unsigned port = 0;

	if (!p)
		return 0;
	if (sscanf(p, "candidate:%*s %*d %*s %*u %63s %u", addr, &port) < 1)
		return 0;
	if (port)
		snprintf(out, n, "%s:%u", addr, port);
	else
		snprintf(out, n, "%s", addr);
	return 1;
}

/*
 * The endpoint of an ICE candidate line, canonicalised. libjuice reports the
 * selected pair as two such lines, which is the only source of a remote
 * endpoint for PATH_ICE -- its receive callback carries no source address at
 * all. Right except between a re-nomination and the next report. 0 if found.
 */
static int cand_ep(const char *cand, struct path_ep *ep)
{
	const char *p = strstr(cand, "candidate:");
	struct sockaddr_in6 a6;
	struct sockaddr_in a4;
	char addr[64];
	unsigned port = 0;

	if (!p || sscanf(p, "candidate:%*s %*d %*s %*u %63s %u",
			 addr, &port) != 2 || !port)
		return -1;
	if (strchr(addr, ':')) {
		memset(&a6, 0, sizeof(a6));
		a6.sin6_family = AF_INET6;
		a6.sin6_port = htons((uint16_t)port);
		if (inet_pton(AF_INET6, addr, &a6.sin6_addr) != 1)
			return -1;
		return path_ep_from_sockaddr(ep, (struct sockaddr *)&a6,
					     sizeof(a6));
	}
	memset(&a4, 0, sizeof(a4));
	a4.sin_family = AF_INET;
	a4.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, addr, &a4.sin_addr) != 1)
		return -1;
	return path_ep_from_sockaddr(ep, (struct sockaddr *)&a4, sizeof(a4));
}

/* Printable "addr:port" ("[v6]:port") for a sockaddr; empty on failure. */
static void fmt_sockaddr(const struct sockaddr *sa, socklen_t len,
			 char *out, size_t n)
{
	char host[64], serv[8];		/* serv is NI_NUMERICSERV: 5 digits max */

	out[0] = '\0';
	if (getnameinfo(sa, len, host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV))
		return;
	if (strchr(host, ':'))
		snprintf(out, n, "[%s]:%s", host, serv);
	else
		snprintf(out, n, "%s:%s", host, serv);
}

/* Enter one endpoint on the shared lanlink socket as a path, or find the path
 * already naming it; its printable form goes to label when one is asked for.
 * Returns 0 when the connection holds the path afterwards. */
static int conn_add_lan_path(struct conn *c, enum path_kind kind,
			     const struct sockaddr_in6 *remote,
			     char *label, size_t label_len)
{
	struct path *p;

	pthread_mutex_lock(&c->path_lock);
	p = path_table_add(&c->paths, kind, remote, NULL, now_ms());
	if (p && label)
		snprintf(label, label_len, "%s", p->label);
	pthread_mutex_unlock(&c->path_lock);
	return p ? 0 : -1;
}

static void conn_add_ice_path(struct conn *c)
{
	pthread_mutex_lock(&c->path_lock);
	path_table_add(&c->paths, PATH_ICE, NULL, c->nat, now_ms());
	pthread_mutex_unlock(&c->path_lock);
}

/* Retire the ICE path before its agent goes: the path borrows the agent, it
 * does not own it. */
static void conn_drop_ice_path(struct conn *c)
{
	pthread_mutex_lock(&c->path_lock);
	path_table_drop_kind(&c->paths, PATH_ICE);
	pthread_mutex_unlock(&c->path_lock);
}

/* How many lanlink paths this connection holds; routable_only leaves out the
 * link-local endpoints a lanlink send cannot reliably reach. */
static int conn_lan_paths(struct conn *c, int routable_only)
{
	int i, n = 0;

	pthread_mutex_lock(&c->path_lock);
	for (i = 0; i < PATH_TABLE_MAX; i++) {
		struct path *p = &c->paths.p[i];

		if (!p->used || p->kind == PATH_ICE)
			continue;
		if (routable_only &&
		    IN6_IS_ADDR_LINKLOCAL(&p->remote.sin6_addr))
			continue;
		n++;
	}
	pthread_mutex_unlock(&c->path_lock);
	return n;
}

/* Does this connection hold a lanlink path naming this endpoint? exact asks for
 * the whole endpoint; otherwise the lanlink port alone identifies the peer. */
static int conn_holds_ep(struct conn *c, const struct path_ep *ep, int exact)
{
	int hit;

	pthread_mutex_lock(&c->path_lock);
	hit = exact ? path_table_find_ep(&c->paths, ep) != NULL :
		      path_table_find_port(&c->paths, ep->port) != NULL;
	pthread_mutex_unlock(&c->path_lock);
	return hit;
}

/* What a caller needs of the path carrying the session, copied out under the
 * lock so nothing reaches into the table without it. */
struct path_pick {
	int kind;			/* -1 when no path can carry one */
	int blackholed;			/* the test hook has taken this one away */
	int qualified;			/* something has actually answered on it */
	struct sockaddr_in6 remote;
	struct nat_agent *agent;
	char label[PATH_LABEL_MAX];
};

/*
 * Is this the path the test hook has taken away (test_blackhole_ms)? A path
 * cannot be removed for real on a machine without CAP_NET_ADMIN, so the hook
 * simply stops this end sending on the one that was carrying the session: the
 * probes that keep a path warm are ours, so it falls silent at both ends.
 * Called with path_lock held, which is what the hook is written under too.
 */
static int path_blackholed(const struct conn *c, int kind,
			   const struct sockaddr_in6 *to)
{
	struct path_ep ep;

	if (c->bh_mute)
		return 1;
	if (c->bh_kind < 0 || kind != c->bh_kind)
		return 0;
	if (kind == PATH_ICE)
		return 1;
	if (!to || path_ep_from_sockaddr(&ep, (const struct sockaddr *)to,
					 sizeof(*to)))
		return 0;
	return path_ep_eq(&ep, &c->bh_ep);
}

/* One path's measurements, both ends' views of them, as the selection log
 * shows them. */
static void path_desc(const struct path *p, char *out, size_t n)
{
	snprintf(out, n, "%s bucket=%d srtt=%d/%d loss=%d/%d",
		 p->label[0] ? p->label : "ICE", path_bucket(p),
		 path_srtt_ms(p), p->peer_srtt_ms,
		 path_loss_ppt(p), p->peer_loss_ppt);
}

/*
 * The path carrying the session, chosen purely by measurement (path_select):
 * the lowest cost in the best occupied warmth tier, ties to the lowest id, both
 * ends computing that from the same pair of published views. Kind plays no
 * part -- a segment path wins because it measures lower, and where it does not
 * measure lower the measurement is right.
 *
 * An ICE agent that has nominated no pair carries nothing at all, so it is
 * marked unusable rather than ranked; the agent is asked before the lock, which
 * is never held across a call into one.
 *
 * Returns 0 when a path was chosen. A change of path is logged with both ends'
 * numbers, the one triage surface when a switch looks wrong.
 */
static int conn_pick(struct conn *c, struct path_pick *out)
{
	char from[PATH_LABEL_MAX + 64], to[PATH_LABEL_MAX + 64];
	int ice_ok = c->nat && nat_connected(c->nat);
	int i, prev, sel;

	memset(out, 0, sizeof(*out));
	out->kind = -1;
	from[0] = '\0';
	to[0] = '\0';
	pthread_mutex_lock(&c->path_lock);
	for (i = 0; i < PATH_TABLE_MAX; i++)
		c->paths.p[i].usable = c->paths.p[i].kind != PATH_ICE || ice_ok;
	prev = c->paths.sel;
	sel = path_select(&c->paths, now_ms());
	if (sel >= 0) {
		struct path *p = &c->paths.p[sel];

		out->kind = (int)p->kind;
		out->remote = p->remote;
		out->agent = p->agent;
		out->qualified = p->qualified;
		out->blackholed = path_blackholed(c, out->kind, &p->remote);
		snprintf(out->label, sizeof(out->label), "%s", p->label);
		if (sel != prev) {
			path_desc(p, to, sizeof(to));
			if (prev >= 0 && c->paths.p[prev].used)
				path_desc(&c->paths.p[prev], from, sizeof(from));
		}
	}
	pthread_mutex_unlock(&c->path_lock);
	if (to[0])
		dbg_logf("path: carrying %s (was %s)", to,
			 from[0] ? from : "none");
	return out->kind < 0 ? -1 : 0;
}

/* The endpoint the session is on right now, printable (view). Empty for an ICE
 * path whose agent has not yet reported the pair it nominated, or for any
 * path -- an advertised candidate included -- nothing has actually answered
 * on yet: a claim is not evidence. */
static void conn_path_label(struct conn *c, char *out, size_t n)
{
	struct path_pick pick;

	out[0] = '\0';
	if (!conn_pick(c, &pick) && pick.qualified)
		snprintf(out, n, "%s", pick.label);
}

/*
 * The warm paths this connection holds besides the one carrying the session:
 * how many there are, and the best-ranked of them, printable (view). This is
 * what the session would move to were the path in use to die, so it is the
 * evidence for the status row's promise that a roam is a reordering. Call it
 * after conn_pick, which is what refreshes `usable`.
 */
static int conn_warm_alts(struct conn *c, char *best, size_t n)
{
	uint64_t now = now_ms();
	int i, sel, top = -1, cnt = 0;

	best[0] = '\0';
	pthread_mutex_lock(&c->path_lock);
	sel = c->paths.sel;
	for (i = 0; i < PATH_TABLE_MAX; i++) {
		struct path *p = &c->paths.p[i];

		if (!p->used || !p->usable || i == sel)
			continue;
		if (path_warmth_of(p, now) != PATH_WARM)
			continue;
		cnt++;
		if (top < 0 || path_cmp(p, &c->paths.p[top], now) < 0)
			top = i;
	}
	if (top >= 0)
		snprintf(best, n, "%s", c->paths.p[top].label);
	pthread_mutex_unlock(&c->path_lock);
	return cnt;
}

/* Classify a bare address string by reachability scope. */
static int addr_scope(const char *addr)
{
	unsigned char b[16];

	if (strchr(addr, ':')) {
		if (inet_pton(AF_INET6, addr, b) != 1)
			return NET_SCOPE_GLOBAL;
		if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)	/* fe80::/10 */
			return NET_SCOPE_LAN;
		if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0)	/* fec0::/10 site-local */
			return NET_SCOPE_LAN;
		if ((b[0] & 0xfe) == 0xfc)			/* fc00::/7 ULA */
			return NET_SCOPE_LAN;
		return NET_SCOPE_GLOBAL;
	}
	if (inet_pton(AF_INET, addr, b) != 1)
		return NET_SCOPE_GLOBAL;
	if (b[0] == 10 || (b[0] == 192 && b[1] == 168) ||
	    (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
	    (b[0] == 169 && b[1] == 254))
		return NET_SCOPE_LAN;
	if (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
		return NET_SCOPE_CGNAT;
	return NET_SCOPE_GLOBAL;
}

/* How an endpoint on the shared lanlink socket is come by: one on the local
 * segment, or any other the same socket can reach. A description of the
 * endpoint and nothing more -- neither kind ranks above the other. */
static enum path_kind ep_kind(const struct path_ep *ep)
{
	struct in6_addr a6;
	struct in_addr a4;
	char host[64];

	if (path_ep_is_v4(ep)) {
		memcpy(&a4, ep->addr + 12, 4);
		if (!inet_ntop(AF_INET, &a4, host, sizeof(host)))
			return PATH_ROUTED;
	} else {
		memcpy(&a6, ep->addr, 16);
		if (!inet_ntop(AF_INET6, &a6, host, sizeof(host)))
			return PATH_ROUTED;
	}
	return addr_scope(host) == NET_SCOPE_LAN ? PATH_SEGMENT : PATH_ROUTED;
}

/*
 * An endpoint the peer advertised over CTLM_CAND: one more candidate on the
 * shared lanlink socket, its kind following the source exactly as an adopted
 * one's does. It is a claim rather than evidence -- nothing has been seen to
 * arrive from it -- so it takes a free slot or a dead one and is otherwise
 * declined, and ranking decides from there whether it ever carries anything.
 * Runs on the connection's own loop thread.
 */
static void conn_offer_path(struct conn *c, const struct sockaddr *sa,
			    socklen_t len)
{
	char added[PATH_LABEL_MAX];
	struct sockaddr_in6 remote;
	struct path_ep ep;
	struct path *p;
	int fresh;

	if (lanlink_map_peer(sa, len, &remote) ||
	    path_ep_from_sockaddr(&ep, (struct sockaddr *)&remote,
				  sizeof(remote)))
		return;
	if (path_ep_any(&ep) || !ep.port)
		return;
	added[0] = '\0';
	pthread_mutex_lock(&c->path_lock);
	fresh = path_table_find_ep(&c->paths, &ep) == NULL;
	p = path_table_offer(&c->paths, ep_kind(&ep), &remote, now_ms());
	if (p && fresh)
		snprintf(added, sizeof(added), "%s", p->label);
	pthread_mutex_unlock(&c->path_lock);
	if (added[0])
		dbg_logf("path advertised: %s", added);
}

/*
 * Publish each local ICE candidate to the observer, classified by scope (LAN /
 * CGNAT / global) and how it was learnt (direct host candidate, or srflx via
 * STUN). Re-run as candidates trickle in -- srflx arrive a round-trip after the
 * host ones -- and let the view de-duplicate, so STUN paths and the NAT verdict
 * they imply appear the moment they are known.
 */
static void report_candidates(struct sess *s, const char *sdp)
{
	const struct session_obs *o = s->cfg->obs;
	const char *p = sdp;

	if (!o || !o->net)
		return;
	/* Match "candidate:" so both a full sdp ("a=candidate:...") and a lone
	 * trickled line ("[a=]candidate:...") are handled. */
	while ((p = strstr(p, "candidate:")) != NULL) {
		char addr[64], typ[16];
		int via, fam;

		if (sscanf(p, "candidate:%*s %*d %*s %*u %63s %*d typ %15s",
			   addr, typ) == 2) {
			if (!strcmp(typ, "host"))
				via = NET_VIA_DIRECT;
			else if (!strcmp(typ, "srflx"))
				via = NET_VIA_STUN;
			else
				via = -1;
			if (via >= 0) {
				int scope = addr_scope(addr);
				int drop6;

				fam = strchr(addr, ':') ? 6 : 4;
				if (fam == 4 && via == NET_VIA_STUN)
					s->have_srflx4 = 1;
				else if (fam == 4 && via == NET_VIA_DIRECT &&
					 scope != NET_SCOPE_GLOBAL)
					s->have_priv4 = 1;
				/* A STUN-reflexive global v6 is the public address a
				 * NAT66 host presents to peers, so always surface it
				 * -- it is exactly the "global v6" the dashboard must
				 * show. For a *direct* global v6 only the address we
				 * source outbound from matters (source_addr's connect
				 * trick, as canon_v6 already enforces for the sent
				 * SDP): libjuice also enumerates the stable/DHCPv6
				 * address, which we neither source from nor listen on
				 * for punching, so drop that one once we know our
				 * source; otherwise show what was gathered. */
				drop6 = fam == 6 && scope == NET_SCOPE_GLOBAL &&
					via == NET_VIA_DIRECT && s->src6[0] &&
					strcmp(addr, s->src6);
				if (!drop6)
					o->net(o->arg, fam, scope, via, addr);
			}
		}
		p += 10;
	}
}

static void obs_report_net(struct sess *s)
{
	report_candidates(s, s->local_sdp);
}

/*
 * The rendezvous node for `family` (4 or 6), printable ("addr:port"). Prefer a
 * node located this session -- our own kept-warm one, or the peer's adopted over
 * the control channel -- so both families show once the in-band exchange has
 * caught up; fall back to whatever the token carried for that family.
 */
static void fmt_rdv_fam(struct sess *s, int family, char *out, size_t n)
{
	const struct token *t = &s->cfg->tok;
	int i = fam_idx(family);
	char ip[64];

	out[0] = '\0';
	if (s->rdv[i].have)
		fmt_sockaddr((struct sockaddr *)&s->rdv[i].sa, s->rdv[i].len,
			     out, n);
	else if (family == 6 &&
		 token_family_state(t, 6) == TOKEN_STATE_RENDEZVOUS &&
		 inet_ntop(AF_INET6, t->ep6_addr, ip, sizeof(ip)))
		snprintf(out, n, "[%s]:%u", ip, t->ep6_port);
	else if (family == 4 &&
		 token_family_state(t, 4) == TOKEN_STATE_RENDEZVOUS &&
		 inet_ntop(AF_INET, t->ep4_addr, ip, sizeof(ip)))
		snprintf(out, n, "%s:%u", ip, t->ep4_port);
}

/*
 * Fill the structured connection status (no display text -- the view renders
 * it) and stash it: in memory for the client's in-process renderer, and, for
 * the host, in a tmpfs file the operator's separate process reads.
 */
static void publish_status(struct conn *c, int state)
{
	struct sess *s = c->sess;
	struct conn_status cs;

	memset(&cs, 0, sizeof(cs));
	cs.state = state;
	/* A view-only client marks its own status line; the host's operator is
	 * never view-only, so its status line (this same struct, via the tmpfs
	 * file) leaves it clear and marks read-only guests on the dashboard. */
	cs.read_only = !s->cfg->is_host &&
		       (s->cfg->tok.flags & TOKEN_FLAG_RO) != 0;
	/* Show the endpoint that is actually carrying KCP right now: the path
	 * in use when it names one, otherwise the selected -- proven -- ICE
	 * pair. Never a mere gathered candidate. */
	conn_path_label(c, cs.peer, sizeof(cs.peer));
	cs.warm_alt = conn_warm_alts(c, cs.alt, sizeof(cs.alt));
	if (!cs.peer[0] && c->nat && nat_connected(c->nat)) {
		char loc[192], rem[192];

		if (!nat_selected(c->nat, loc, sizeof(loc), rem, sizeof(rem)))
			cand_addr(rem, cs.peer, sizeof(cs.peer));
	}
	/* Both families, so a session that started on one can be seen to gain the
	 * other once the in-band rendezvous exchange propagates it. */
	fmt_rdv_fam(s, 4, cs.rdv, sizeof(cs.rdv));
	fmt_rdv_fam(s, 6, cs.rdv6, sizeof(cs.rdv6));
	/* Prefer the heartbeat's round trip (measured even when idle); the stream
	 * RTT only moves when SSH data flows. Report how long a loss has lasted. */
	pthread_mutex_lock(&c->hb_lock);
	cs.rtt_ms = c->hb_rtt > 0 ? c->hb_rtt :
		(c->stream ? stream_rtt(c->stream) : 0);
	if (state == CONN_LOST && c->lost_since_ms)
		cs.since_s = (int)((now_ms() - c->lost_since_ms) / 1000);
	pthread_mutex_unlock(&c->hb_lock);

	pthread_mutex_lock(&c->status_lock);
	c->status = cs;
	pthread_mutex_unlock(&c->status_lock);

	if (s->cfg->status_path)
		conn_write(s->cfg->status_path, &cs);
}

/* sshc status callback: hand the client's renderer the current status data. */
static void session_status(void *arg, struct conn_status *out)
{
	struct conn *c = arg;

	pthread_mutex_lock(&c->status_lock);
	*out = c->status;
	pthread_mutex_unlock(&c->status_lock);
}

/* Keep only candidate lines of the requested family (0 = all). */
static void sdp_filter(const char *in, int family, char *out, size_t outlen)
{
	struct cand_policy pol;

	cand_policy_default(&pol);
	cand_sdp_filter(in, family, &pol, out, outlen);
}

/*
 * Fan the description about to be posted across every public v4 this
 * network's NAT has shown for our sockets, so a peer behind a carrier pool
 * that picks its egress per destination still aims a check at the member
 * chosen for it. With the single address of an ordinary NAT this is a no-op.
 */
static int fan_local_sdp(struct sess *s)
{
	uint8_t pool[POOL4_MAX][4];
	int n, i, st;

	pthread_mutex_lock(&s->trickle_lock);
	n = s->npool4;
	for (i = 0; i < n; i++)
		memcpy(pool[i], s->pool4[i], 4);
	st = stun_mapping_result(&s->map4);
	pthread_mutex_unlock(&s->trickle_lock);
	if (n >= 2)
		cand_sdp_fan_v4(s->local_sdp, sizeof(s->local_sdp), pool,
				(size_t)n, st == STUN_MAPPING_DEPENDENT);
	return n;
}

/*
 * Members the probe found since the last pass: put them on the dashboard the
 * moment they are known, and -- where the caller says a posted description may
 * be replaced -- widen it with them and post again. The peer treats the
 * re-post as a candidate trickle for the agent it already primed, so a punch
 * in flight only gains targets.
 */
static void pool_pump(struct sess *s, int repost_ok)
{
	const struct session_obs *o = s->cfg->obs;
	uint8_t pool[POOL4_MAX][4];
	int n, i, st, rep;

	pthread_mutex_lock(&s->trickle_lock);
	n = s->npool4;
	for (i = 0; i < n; i++)
		memcpy(pool[i], s->pool4[i], 4);
	st = stun_mapping_result(&s->map4);
	pthread_mutex_unlock(&s->trickle_lock);
	if (o && o->net) {
		for (i = s->pool_reported; i < n; i++) {
			char ip[64];

			if (inet_ntop(AF_INET, pool[i], ip, sizeof(ip)))
				o->net(o->arg, 4, addr_scope(ip),
				       NET_VIA_STUN, ip);
		}
	}
	s->pool_reported = n;
	if (st != STUN_MAPPING_UNKNOWN) {
		rep = st == STUN_MAPPING_DEPENDENT ? 2 : 1;
		if (rep != s->mapping_reported) {
			s->mapping_reported = rep;
			if (o && o->mapping4)
				o->mapping4(o->arg, rep == 2);
		}
	}
	if (repost_ok && s->have_local_sdp && n >= 2 && n > s->pool_posted) {
		s->pool_posted = fan_local_sdp(s);
		sig_post(s->sig, (const uint8_t *)s->local_sdp,
			 strlen(s->local_sdp));
	}
}

/* Like sdp_filter(), for a peer's SDP: also drops any host candidate that
 * names one of our own local addresses (see cand_sdp_drop_self). */
static void sdp_filter_peer(const char *in, int family, char *out, size_t outlen)
{
	struct netmon_addr local[NETMON_MAX_ADDRS];
	size_t nlocal = netmon_snapshot(local, NETMON_MAX_ADDRS);
	char tmp[NAT_SDP_MAX];

	sdp_filter(in, family, tmp, sizeof(tmp));
	cand_sdp_drop_self(tmp, local, nlocal, out, outlen);
	if (strlen(out) != strlen(tmp))
		dbg_logf("sdp_filter_peer: dropped self-address host candidate(s)");
}

/*
 * The rendezvous node a fresh sig should be seeded with for `family`: the one
 * this session located and keeps warm, or the peer's adopted over the control
 * channel (s->rdv[]); the token's slot only where we hold neither, since a
 * token minted long ago can name a node that has since gone. Returns 0 and
 * fills sa/len, -1 when neither has one for this family.
 */
static int seed_node_for(struct sess *s, int family, struct sockaddr_storage *sa,
			 socklen_t *len)
{
	const struct token *t = &s->cfg->tok;
	int i = fam_idx(family);

	if (s->rdv[i].have) {
		*sa = s->rdv[i].sa;
		*len = s->rdv[i].len;
		return 0;
	}
	if (family == 6 && token_family_state(t, 6) == TOKEN_STATE_RENDEZVOUS) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)sa;

		memset(a, 0, sizeof(*a));
		a->sin6_family = AF_INET6;
		memcpy(&a->sin6_addr, t->ep6_addr, TOKEN_EP6_LEN);
		a->sin6_port = htons(t->ep6_port);
		*len = sizeof(*a);
		return 0;
	}
	if (family == 4 && token_family_state(t, 4) == TOKEN_STATE_RENDEZVOUS) {
		struct sockaddr_in *a = (struct sockaddr_in *)sa;

		memset(a, 0, sizeof(*a));
		a->sin_family = AF_INET;
		memcpy(&a->sin_addr, t->ep4_addr, TOKEN_EP4_LEN);
		a->sin_port = htons(t->ep4_port);
		*len = sizeof(*a);
		return 0;
	}
	return -1;
}

/*
 * Plant a rendezvous node per family into a newly created sig: a client seeds
 * it as a sticky DHT hint, queried before the global DHT has converged, while a
 * host adopts and reinforces it as its anchor, so a token already in somebody's
 * clipboard keeps naming a node that serves this mailbox.
 */
static void seed_rendezvous(struct sess *s)
{
	static const int famv[2] = { 4, 6 };
	const struct session_obs *o = s->cfg->obs;
	int i;

	for (i = 0; i < 2; i++) {
		struct sockaddr_storage sa;
		socklen_t sl = 0;

		if (seed_node_for(s, famv[i], &sa, &sl))
			continue;
		if (s->cfg->is_host) {
			sig_reinforce(s->sig, famv[i], (struct sockaddr *)&sa,
				      sl);
		} else if (!sig_seed_node(s->sig, (struct sockaddr *)&sa, sl) &&
			   o && o->rendezvous) {
			char b[80];

			addr_str((struct sockaddr *)&sa, b, sizeof(b));
			o->rendezvous(o->arg, famv[i], b, 0);
		}
	}
}

/*
 * Client accelerator (mirror of seed_rendezvous): for each family whose slot is
 * DIRECT -- which in 0.1.x only an older host mints -- enter the host's
 * endpoint as a path at t=0, so KCP starts toward the host immediately instead
 * of waiting to hear its multicast announcement. The host still learns us from
 * our own sealed announcement; this only primes the reverse direction. A later
 * multicast on_direct_peer names the same endpoint, which is the same path.
 * Only called once s->lan exists (transport_send would otherwise send on a NULL
 * socket).
 */
static void client_direct_connect(struct sess *s)
{
	const struct token *t = &s->cfg->tok;
	struct sockaddr_in6 np;

	if (token_family_state(t, 6) == TOKEN_STATE_DIRECT) {
		struct sockaddr_in6 a;

		memset(&a, 0, sizeof(a));
		a.sin6_family = AF_INET6;
		memcpy(&a.sin6_addr, t->ep6_addr, TOKEN_EP6_LEN);
		a.sin6_port = htons(t->ep6_port);
		if (!lanlink_map_peer((struct sockaddr *)&a, sizeof(a), &np))
			conn_add_lan_path(&s->c, PATH_SEGMENT, &np, NULL, 0);
	}
	if (token_family_state(t, 4) == TOKEN_STATE_DIRECT) {
		struct sockaddr_in a;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		memcpy(&a.sin_addr, t->ep4_addr, TOKEN_EP4_LEN);
		a.sin_port = htons(t->ep4_port);
		if (!lanlink_map_peer((struct sockaddr *)&a, sizeof(a), &np))
			conn_add_lan_path(&s->c, PATH_SEGMENT, &np, NULL, 0);
	}
}

/*
 * "v6 direct": a host reaches its own global v6 at the address the kernel
 * sources outbound from, which we learn without STUN via source_addr's connect
 * trick. That is the privacy (temporary) address where RFC 4941 is enabled and
 * the stable one otherwise -- either way, the address we effectively listen on.
 * libjuice instead enumerates the interface's stable address, which need not be
 * the source and is a tracking handle besides. So rewrite the one global v6
 * candidate to our real source and drop the rest (any other global v6 host
 * candidate, and the redundant v6 srflx), leaving v4 untouched. With no global
 * v6 source, leave v6 as gathered.
 */
static void canon_v6(const char *in, const char *src6, char *out, size_t cap)
{
	const char *line = in;
	size_t o = 0;
	int kept6 = 0;

	while (*line) {
		const char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line + 1) : strlen(line);
		char addr[64], typ[16];
		int drop = 0, rewrite = 0, a0 = 0, a1 = 0;

		if (src6[0] && !strncmp(line, "a=candidate:", 12) &&
		    sscanf(line, "a=candidate:%*s %*d %*s %*u %63s %*d typ %15s",
			   addr, typ) == 2 && strchr(addr, ':') &&
		    addr_scope(addr) == NET_SCOPE_GLOBAL) {
			if (strcmp(typ, "host"))
				drop = 1;	/* global v6 srflx: source covers it */
			else if (kept6)
				drop = 1;	/* only one global v6 */
			else
				rewrite = 1;
		}
		if (drop) {
			if (!nl)
				break;
			line = nl + 1;
			continue;
		}
		if (rewrite)
			sscanf(line, "a=candidate:%*s %*d %*s %*u %n%*s%n", &a0, &a1);
		if (rewrite && a1 > a0 && a0 > 0 && (size_t)a1 <= len) {
			size_t plen = strlen(src6);

			if (o + (size_t)a0 + plen + (len - (size_t)a1) < cap) {
				memcpy(out + o, line, (size_t)a0);
				o += (size_t)a0;
				memcpy(out + o, src6, plen);
				o += plen;
				memcpy(out + o, line + a1, len - (size_t)a1);
				o += len - (size_t)a1;
				kept6 = 1;
			}
		} else if (o + len < cap) {
			memcpy(out + o, line, len);
			o += len;
		}
		if (!nl)
			break;
		line = nl + 1;
	}
	out[o] = '\0';
}

static void on_local_sdp(void *arg, const char *sdp)
{
	struct sess *s = ((struct conn *)arg)->sess;

	canon_v6(sdp, s->src6, s->local_sdp, sizeof(s->local_sdp));
	s->have_local_sdp = 1;
}

/* libjuice gather thread: a candidate is ready. Append it for the main loop,
 * and note the v4 facts the STUN watchdog runs on -- here rather than in the
 * observer report, which not every caller wires up. */
/* One more public v4 the NAT has been seen mapping us to; from the gather
 * thread and the probe thread alike. */
static void pool_note(struct sess *s, const uint8_t b[4])
{
	int i;

	pthread_mutex_lock(&s->trickle_lock);
	for (i = 0; i < s->npool4; i++)
		if (!memcmp(s->pool4[i], b, 4))
			break;
	if (i == s->npool4 && i < POOL4_MAX)
		memcpy(s->pool4[s->npool4++], b, 4);
	pthread_mutex_unlock(&s->trickle_lock);
}

static void mapping_note(struct sess *s, const uint8_t addr[4], uint16_t port)
{
	pthread_mutex_lock(&s->trickle_lock);
	stun_mapping_add(&s->map4, addr, port);
	pthread_mutex_unlock(&s->trickle_lock);
}

static void probe_hit(void *arg, const uint8_t addr[4], uint16_t port)
{
	pool_note(arg, addr);
	mapping_note(arg, addr, port);
}

static void *stun_probe_thread(void *arg)
{
	struct sess *s = arg;
	char *targets[STUN_PROBE_SERVERS];
	uint8_t seed[STUN_PROBE_TXID_LEN];
	int n = 0, i;

	for (i = 0; i < s->stun_count && n < STUN_PROBE_SERVERS; i++)
		targets[n++] = s->stun_servers[(s->ice_attempt + i) %
					       s->stun_count];
	random_bytes(seed, sizeof(seed));
	stun_probe_run(targets, n, STUN_PROBE_MS, seed, &s->probe_stop,
		       probe_hit, s);
	return NULL;
}

static void stun_probe_halt(struct sess *s)
{
	if (!s->probe_running)
		return;
	s->probe_stop = 1;
	pthread_join(s->probe_th, NULL);
	s->probe_running = 0;
}

/* (Re)start the pool probe: at session start, and on each new network. An
 * operator-pinned server is theirs alone to talk to, so no probing then. */
static void stun_probe_kick(struct sess *s)
{
	if (s->cfg->stun_host || !s->cfg->stun_auto || s->stun_count < 1)
		return;
	stun_probe_halt(s);
	s->probe_stop = 0;
	if (!pthread_create(&s->probe_th, NULL, stun_probe_thread, s))
		s->probe_running = 1;
}

static void on_ice_candidate(void *arg, const char *cand)
{
	struct sess *s = ((struct conn *)arg)->sess;
	size_t used, room, n = strlen(cand);
	const char *p = strstr(cand, "candidate:");
	char addr[64], typ[16];

	if (p && sscanf(p, "candidate:%*s %*d %*s %*u %63s %*d typ %15s",
			addr, typ) == 2 && !strchr(addr, ':')) {
		if (!strcmp(typ, "srflx")) {
			uint8_t b[4];

			s->have_srflx4 = 1;
			if (inet_pton(AF_INET, addr, b) == 1)
				pool_note(s, b);
		} else if (!strcmp(typ, "host") &&
			   addr_scope(addr) != NET_SCOPE_GLOBAL)
			s->have_priv4 = 1;
	}
	pthread_mutex_lock(&s->trickle_lock);
	used = strlen(s->trickle_sdp);
	room = sizeof(s->trickle_sdp) - used - 1;
	if (n + 1 <= room) {
		memcpy(s->trickle_sdp + used, cand, n);
		s->trickle_sdp[used + n] = '\n';
		s->trickle_sdp[used + n + 1] = '\0';
		s->trickle_dirty = 1;
	}
	pthread_mutex_unlock(&s->trickle_lock);
}


/* Send over whichever transport carries the stream right now. Used for the KCP
 * stream and the liveness heartbeat. */
static int transport_send(struct conn *c, const uint8_t *data, size_t len)
{
	struct sess *s = c->sess;
	struct path_pick pick;

	if (conn_pick(c, &pick))
		return -1;
	if (pick.blackholed)
		return 0;
	if (pick.kind == PATH_ICE)
		return pick.agent ? nat_send(pick.agent, data, len) : -1;
	return s->lan ? lanlink_send(s->lan, &pick.remote, data, len) : -1;
}

/*
 * Suppress SIGPIPE for writes on fd. Linux carries that per-write in
 * ctl_send's MSG_NOSIGNAL; macOS has no such flag and wants the socket option
 * instead, so the two together cover both. Returns 0 when nothing was needed.
 */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int nosigpipe(sock_t fd)
{
#ifdef SO_NOSIGPIPE
	int on = 1;

	return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const char *)&on,
			  sizeof(on));
#else
	(void)fd;
	return 0;
#endif
}

/* Send one control message to the peer over the comrade-ctl channel. Best
 * effort: SIGPIPE is suppressed (see nosigpipe) so a closed channel during
 * teardown cannot kill us, and a full/short write only ever drops a
 * heartbeat, which the next tick repeats. */
static void ctl_send(struct conn *c, int type, const uint8_t *payload,
		     size_t plen)
{
	uint8_t buf[CTL_FRAME_MAX];
	size_t n;
	ssize_t w;

	n = ctl_frame(buf, type, payload, plen);
	if (!sock_valid(c->ctl_fd) || !n)
		return;
	w = send(c->ctl_fd, (const char *)buf, (int)n, MSG_NOSIGNAL);
	(void)w;
}

/* Act on one decoded control message (a ctl_reframer callback): answer a ping,
 * record a pong's round trip, stash the peer's announced rendezvous node for
 * rdv_maintain to adopt, or enter an endpoint it advertises as one more path.
 * Runs on the connection's own loop thread, the same one as path_tick. */
static void ctl_dispatch(void *arg, int type, const uint8_t *pl, size_t plen)
{
	struct conn *c = arg;

	if (type == CTLM_PING && plen >= CTL_TS_LEN) {
		if (!c->sess->cfg->test_drop_pong || c->pongs_sent < 2) {
			c->pongs_sent++;
			ctl_send(c, CTLM_PONG, pl, CTL_TS_LEN);
		}
	} else if (type == CTLM_PONG && plen >= CTL_TS_LEN) {
		uint64_t now = now_ms();

		pthread_mutex_lock(&c->hb_lock);
		c->hb_last_pong = now;
		c->hb_rtt = (int)(now - ctl_get_u64(pl));
		c->hb_pong_seen = 1;
		pthread_mutex_unlock(&c->hb_lock);
	} else if (type == CTLM_RDV && plen >= CTL_RDV_PLEN) {
		struct sockaddr_storage sa;
		socklen_t sl = 0;
		int fam = ctl_rdv_decode(pl, plen, &sa, &sl);

		if (fam) {
			int i = fam_idx(fam);

			pthread_mutex_lock(&c->rdv_lock);
			c->rdv_in[i].sa = sa;
			c->rdv_in[i].len = sl;
			c->rdv_in[i].have = 1;
			c->rdv_in_dirty = 1;
			pthread_mutex_unlock(&c->rdv_lock);
		}
	} else if (type == CTLM_CAND && plen >= CTL_RDV_PLEN) {
		struct sockaddr_storage sa;
		socklen_t sl = 0;

		if (ctl_rdv_decode(pl, plen, &sa, &sl))
			conn_offer_path(c, (struct sockaddr *)&sa, sl);
	}
}

/* Drain the comrade-ctl fd and dispatch each complete message the read yields
 * (reframing across read boundaries lives in the reframer). */
static void ctl_readable(struct conn *c)
{
	uint8_t tmp[64];
	ssize_t n = sock_read(c->ctl_fd, tmp, sizeof(tmp));

	if (n > 0)
		ctl_reframer_feed(&c->ctl_rf, tmp, (size_t)n, ctl_dispatch, c);
}

/*
 * Transport receive: with the control protocol now inside the SSH session,
 * everything arriving on the raw path is KCP stream data. May run on
 * libjuice's thread.
 */
/*
 * The transport probe (frame and codec in path.h). Every KCP datagram opens
 * with the conversation id, which ikcp_input rejects on mismatch, and comrade
 * uses one fixed conv -- so a datagram opening with a different 32-bit magic is
 * unambiguously not stream data and can be split off ahead of it for the cost
 * of one compare.
 */

/* Seal one probe for this connection into out (>= PROBE_MAX); 0 on failure.
 * The claimant ufrag is this connection's, whoever filled the rest in. */
static size_t conn_probe_seal(struct conn *c, struct path_probe *pr,
			      uint8_t *out)
{
	snprintf(pr->ufrag, sizeof(pr->ufrag), "%s", c->claim_ufrag);
	return path_probe_build(out, PROBE_MAX, c->sess->keys.sig_key, pr);
}

/*
 * The path a frame arrived on: the agent for ICE, which reports no source, and
 * the source endpoint for the lanlink kinds. NULL when this end holds no path
 * naming it -- not an error, only a source it has nothing to say about yet.
 * Called with path_lock held.
 */
static struct path *conn_recv_path(struct conn *c, enum path_kind kind,
				   const struct path_ep *src)
{
	if (kind == PATH_ICE)
		return path_table_find_agent(&c->paths, c->nat);
	return path_table_find_ep(&c->paths, src);
}

/*
 * The path a pong answers. The nonce names it: one was drawn for one probe on
 * one path, so it identifies the round trip being measured whatever source the
 * answer came back from -- which a multi-homed peer's need not match. Called
 * with path_lock held.
 */
static struct path *conn_pong_path(struct conn *c, uint64_t nonce)
{
	int i;

	for (i = 0; i < PATH_TABLE_MAX; i++)
		if (c->paths.p[i].used && c->paths.p[i].outstanding &&
		    c->paths.p[i].nonce == nonce)
			return &c->paths.p[i];
	return NULL;
}

/*
 * An authenticated probe for this connection, arrived on `kind` and from `src`
 * for the lanlink kinds. A ping is answered to the endpoint it came from, so a
 * multi-homed peer is answered where it asked, and the answer echoes that
 * endpoint so the prober learns its own reflexive address for free; a pong is
 * named by its nonce, records the round trip and qualifies the path. Either
 * carries this end's view of the path in its tail and takes the peer's from
 * theirs. Anything else is dropped in silence.
 *
 * A ping from a source no path names adds one, whatever source that is: an end
 * whose address changed keeps the session by probing from the new one. Add,
 * never replace -- it enters as one more candidate and ranking decides whether
 * it ever carries anything, so a late datagram from an address that has gone
 * away cannot flap the binding.
 */
static void probe_apply(struct conn *c, const struct path_probe *pr,
			enum path_kind kind, const struct sockaddr_in6 *src)
{
	struct sess *s = c->sess;
	struct path_probe rp;
	struct path_ep from;
	uint8_t out[PROBE_MAX];
	struct path *p;
	char label[PATH_LABEL_MAX], added[PATH_LABEL_MAX];
	int rtt = -1, drop = 0;
	size_t o;

	memset(&from, 0, sizeof(from));
	if (src)
		path_ep_from_sockaddr(&from, (const struct sockaddr *)src,
				      sizeof(*src));
	if (pr->type == PROBE_PING) {
		enum path_kind srck = kind == PATH_ICE ? kind : ep_kind(&from);

		added[0] = '\0';
		memset(&rp, 0, sizeof(rp));
		rp.type = PROBE_PONG;
		rp.nonce = pr->nonce;
		pthread_mutex_lock(&c->path_lock);
		p = conn_recv_path(c, kind, &from);
		if (!p && src && kind != PATH_ICE) {
			p = path_table_add(&c->paths, srck, src, NULL,
					   now_ms());
			if (p)
				snprintf(added, sizeof(added), "%s", p->label);
		}
		drop = path_blackholed(c, (int)(p ? p->kind : srck), src);
		if (p) {
			if (path_ep_any(&from))
				from = p->peer_ep;	/* ICE: no source */
			path_saw_inbound(p, &from);
			path_apply_tail(p, pr, s->keys.sig_key);
			path_fill_tail(p, &rp);
		} else {
			rp.have_tail = 1;
			rp.echo = from;
		}
		pthread_mutex_unlock(&c->path_lock);
		if (added[0])
			dbg_logf("path adopted: %s", added);
		if (drop)
			return;
		o = conn_probe_seal(c, &rp, out);
		if (!o)
			return;
		if (kind == PATH_ICE) {
			if (c->nat)
				nat_send(c->nat, out, o);
		} else if (src && s->lan) {
			lanlink_send(s->lan, src, out, o);
		}
		return;
	}
	if (pr->type != PROBE_PONG)
		return;
	label[0] = '\0';
	pthread_mutex_lock(&c->path_lock);
	p = conn_pong_path(c, pr->nonce);
	if (p) {
		int fresh = !p->qualified;

		if (path_ep_any(&from))
			from = p->peer_ep;
		path_saw_inbound(p, &from);
		path_apply_tail(p, pr, s->keys.sig_key);
		if (path_probe_pong(p, pr->nonce, now_ms()) && fresh) {
			rtt = path_srtt_ms(p);
			snprintf(label, sizeof(label), "%s", p->label);
		}
	}
	pthread_mutex_unlock(&c->path_lock);
	if (rtt >= 0)
		dbg_logf("path qualified: %s rtt~%dms",
			 label[0] ? label : "ICE", rtt);
}

/* Unseal a probe and act on it, if it names the claimant this connection
 * serves. Anything else is dropped in silence. */
static void probe_recv(struct conn *c, const uint8_t *data, size_t len,
		       enum path_kind kind, const struct sockaddr_in6 *src)
{
	struct path_probe pr;

	if (path_probe_parse(&pr, c->sess->keys.sig_key, data, len))
		return;
	if (strcmp(pr.ufrag, c->claim_ufrag))
		return;			/* not the claimant this conn serves */
	probe_apply(c, &pr, kind, src);
}

/*
 * The adoption budget: PATH_ADOPT_RATE datagrams a second from sources no path
 * names, in bursts of PATH_ADOPT_DEPTH. A stranger who can seal nothing must
 * not be the one setting the rate at which we open seals, so this is consulted
 * before the AEAD open rather than after. It belongs to the listening socket,
 * and only the thread dispatching that socket ever touches it.
 */
static int adopt_allow(struct sess *s, uint64_t now)
{
	const int cap = PATH_ADOPT_DEPTH * 1000;
	uint64_t gained = (now - s->adopt_ms) * PATH_ADOPT_RATE;

	s->adopt_ms = now;
	if (gained >= (uint64_t)cap || s->adopt_tokens + (int)gained >= cap)
		s->adopt_tokens = cap;
	else
		s->adopt_tokens += (int)gained;
	if (s->adopt_tokens < 1000)
		return 0;
	s->adopt_tokens -= 1000;
	return 1;
}

/*
 * May this datagram be opened? Only a frame opening with PROBE_MAGIC is a
 * candidate for adoption at all; anything else is stream data, which
 * ikcp_input rejects for the cost of one compare. A probe from a source one of
 * `c`'s paths already names is ordinary traffic, and one from any other source
 * is admitted to the seal only while the budget has a token. c may be NULL,
 * which is a source no connection at all is known to hold.
 */
static int probe_gate(struct sess *s, struct conn *c, const struct path_ep *ep,
		      const uint8_t *data, size_t len)
{
	if (!path_probe_is(data, len))
		return 1;
	if (c && conn_holds_ep(c, ep, 1))
		return 1;
	return adopt_allow(s, now_ms());
}

/*
 * Host: a probe from a source no worker holds. The seal makes it ours and the
 * claimant ufrag inside names which connection it belongs to, so the connection
 * serving that claimant gains a path over the source it arrived from -- which
 * is how an ICE-admitted client that turns up on the segment, or one whose
 * address changed, is picked up. Host main thread.
 */
static void probe_adopt(struct sess *s, const uint8_t *data, size_t len,
			const struct sockaddr_in6 *src)
{
	struct path_probe pr;
	int i;

	if (path_probe_parse(&pr, s->keys.sig_key, data, len) ||
	    pr.type != PROBE_PING || !pr.ufrag[0])
		return;
	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->conns[i] &&
		    !strcmp(s->conns[i]->claim_ufrag, pr.ufrag)) {
			probe_apply(s->conns[i], &pr, PATH_SEGMENT, src);
			return;
		}
}

/* Deliver received transport bytes into the conn's KCP stream, under the lock
 * that guards a concurrent teardown clearing c->stream from another thread.
 * A probe is split off first: it is not stream data (see probe_recv). Stream
 * data is accepted on every path this end holds, not only the one it sends on,
 * so selection is never a negotiation. */
static void deliver_stream_from(struct conn *c, const uint8_t *data, size_t len,
				enum path_kind kind,
				const struct sockaddr_in6 *src)
{
	uint64_t now = now_ms();

	if (c->bh_mute)		/* a staged total outage swallows receives */
		return;
	/* The unlocked read only coarsens the update to ~100ms; the store is
	 * what the liveness verdict reads, and it is taken under the lock. */
	if (now - c->hb_last_heard >= 100) {
		pthread_mutex_lock(&c->hb_lock);
		c->hb_last_heard = now;
		pthread_mutex_unlock(&c->hb_lock);
	}
	if (path_probe_is(data, len)) {
		probe_recv(c, data, len, kind, src);
		return;
	}
	pthread_mutex_lock(&c->stream_lock);
	if (c->stream)
		stream_input(c->stream, data, len);
	pthread_mutex_unlock(&c->stream_lock);
}

static void deliver_stream(struct conn *c, const uint8_t *data, size_t len)
{
	deliver_stream_from(c, data, len, PATH_ICE, NULL);
}

/*
 * The remote endpoint of this connection's ICE path, when its agent has
 * nominated one. Kept out of path_lock: it reaches into the agent, which
 * formats the pair under its own lock, so it is asked at the probe cadence
 * rather than on every pass of a loop that turns a hundred times a second.
 */
static int conn_ice_ep(struct conn *c, uint64_t now, struct path_ep *ep)
{
	char loc[192], rem[192];

	if (!c->nat || !nat_connected(c->nat) || now < c->next_ice_ep_ms)
		return -1;
	c->next_ice_ep_ms = now + PATH_KEEP_MS;
	if (nat_selected(c->nat, loc, sizeof(loc), rem, sizeof(rem)))
		return -1;
	return cand_ep(rem, ep);
}

/*
 * Probe every path whose turn has come, every path being kept warm rather than
 * only the one in use. One probe is outstanding per path, carrying its own send
 * timestamp -- so a round trip is measured from the probe that was actually
 * answered -- and its own nonce, drawn at random because a guessable one is the
 * only thing between a stranger and a forged pong. Both ends run this: a host
 * probes as well as answering, or it would never learn its own reflexive
 * endpoint and could rank nothing.
 */
static void path_tick(struct conn *c, uint64_t now)
{
	struct sess *s = c->sess;
	struct sockaddr_in6 to[PATH_TABLE_MAX];
	struct path_probe pr[PATH_TABLE_MAX];
	uint64_t nonce[PATH_TABLE_MAX];
	struct path_ep ice;
	uint8_t out[PROBE_MAX];
	int kind[PATH_TABLE_MAX], drop[PATH_TABLE_MAX], due[PATH_TABLE_MAX];
	int i, n = 0, m = 0, have_ice, ice_ok;
	size_t len;

	if (!c->claim_ufrag[0])
		return;
	have_ice = !conn_ice_ep(c, now, &ice);
	ice_ok = c->nat && nat_connected(c->nat);
	pthread_mutex_lock(&c->path_lock);
	for (i = 0; i < PATH_TABLE_MAX; i++) {
		struct path *p = &c->paths.p[i];

		if (!p->used)
			continue;
		p->usable = p->kind != PATH_ICE || ice_ok;
		path_probe_expire(p, now);
		if (p->kind == PATH_ICE && have_ice)
			path_set_peer_ep(p, &ice, s->keys.sig_key);
		if (p->usable && path_probe_due(p, now))
			due[n++] = i;
	}
	pthread_mutex_unlock(&c->path_lock);
	if (!n)
		return;
	if (random_bytes(nonce, n * sizeof(nonce[0])))
		return;			/* a guessable nonce is no probe at all */
	pthread_mutex_lock(&c->path_lock);
	for (i = 0; i < n; i++) {
		struct path *p = &c->paths.p[due[i]];

		if (!p->usable || !path_probe_due(p, now))
			continue;
		memset(&pr[m], 0, sizeof(pr[m]));
		pr[m].type = PROBE_PING;
		pr[m].nonce = nonce[i];
		path_fill_tail(p, &pr[m]);
		path_probe_sent(p, nonce[i], now);
		kind[m] = (int)p->kind;
		drop[m] = path_blackholed(c, kind[m], &p->remote);
		to[m] = p->remote;
		m++;
	}
	pthread_mutex_unlock(&c->path_lock);
	for (i = 0; i < m; i++) {
		if (drop[i])
			continue;
		len = conn_probe_seal(c, &pr[i], out);
		if (!len)
			return;
		if (kind[i] == PATH_ICE)
			nat_send(c->nat, out, len);
		else if (s->lan)
			lanlink_send(s->lan, &to[i], out, len);
	}
}

/*
 * Is any path qualified? A host is exempt -- not for want of probing, which it
 * does too, but because its worker exists only once the turnstile has decided
 * this client is the one it serves. This answers "may the session start", never
 * "which path carries it", and it is the whole of the remaining asymmetry: the
 * host speaks first, and that banner arriving is the client's proof of it.
 */
static int path_ready(struct conn *c)
{
	int ready;

	if (c->sess->cfg->is_host)
		return conn_lan_paths(c, 0) > 0 ||
		       (c->nat && nat_connected(c->nat));
	pthread_mutex_lock(&c->path_lock);
	ready = path_table_any_qualified(&c->paths);
	pthread_mutex_unlock(&c->path_lock);
	return ready;
}

/*
 * Has this attempt run out of probing? A client that has qualified nothing by
 * now has almost certainly lost a turnstile round -- its checks were answered by
 * an agent serving somebody else -- and only a fresh identity and a fresh claim
 * recover.
 */
static int path_probe_expired(struct conn *c)
{
	if (path_ready(c) || !c->claim_released_ms)
		return 0;
	return now_ms() - c->claim_released_ms >
	       (uint64_t)(c->claim_lost ? PATH_LOST_MS : PATH_PROBE_MS);
}

/*
 * Has the host rotated past the offer this agent is primed against, with this
 * agent out of the running? Only meaningful for a client that has primed one
 * and not yet qualified. A rotation alone proves nothing: release-on-pickup
 * mints a fresh offer the instant the host takes a claim up, so the winner
 * sees its own pickup as a rotation too -- and the rotated offer routinely
 * outruns every signal that could say which one we are, because the claim
 * slot's transitions ride the same eventually-consistent GET (measured: the
 * rotation arrived 2-5s after pickup and aborted every punch slower than
 * that, which through carrier-grade NAT is all of them). So the rotation is
 * read as a loss only once the attempt has had its probe window from the
 * moment this agent was primed, or once the slot has said outright that a
 * rival overwrote us.
 */
static int offer_moved_on(struct conn *c)
{
	const struct sess *s = c->sess;

	if (s->cfg->is_host || path_ready(c))
		return 0;
	if (!c->remote_ufrag[0] || !s->cur_offer_ufrag[0])
		return 0;
	if (!strcmp(s->cur_offer_ufrag, c->remote_ufrag))
		return 0;
	if (!c->claim_lost &&
	    now_ms() - s->ice_attempt_start <= PATH_PROBE_MS)
		return 0;
	/*
	 * Only a client that has actually reached the answer slot is queued
	 * against the stale offer; one still working its way in will prime
	 * against whatever is current when it gets there. And act once per
	 * rotation, so a burst of joiners does not re-gather in lockstep.
	 */
	return strcmp(s->cur_offer_ufrag, s->regathered_for) != 0;
}

/*
 * Track the claim through the turnstile. Called each pass while a client is
 * waiting for a path; a host has no claim of its own to watch.
 */
static void claim_watch(struct conn *c)
{
	enum sig_claim st;

	if (c->sess->cfg->is_host)
		return;
	st = sig_claim_status(c->sess->sig);
	if (st == SIG_CLAIM_HELD) {
		c->claim_held_seen = 1;
		c->claim_lost = 0;
		c->claim_released_ms = 0;
		return;
	}
	if (c->claim_held_seen && !c->claim_released_ms &&
	    (st == SIG_CLAIM_FREE || st == SIG_CLAIM_BUSY)) {
		c->claim_released_ms = now_ms();
		c->claim_lost = st == SIG_CLAIM_BUSY;
	}
}

static void on_transport_recv(void *arg, const uint8_t *data, size_t len)
{
	deliver_stream((struct conn *)arg, data, len);
}

/* Single-connection lanlink receive (client, or a single-connection host): its
 * one conn, source ignored -- it only ever talks to the one peer. */
static void client_lan_recv(void *arg, const struct sockaddr *src,
			    socklen_t srclen, const uint8_t *data, size_t len)
{
	struct conn *c = arg;
	struct sockaddr_in6 mapped;
	struct path_ep ep;

	if (lanlink_map_peer(src, srclen, &mapped) ||
	    path_ep_from_sockaddr(&ep, (struct sockaddr *)&mapped,
				  sizeof(mapped)))
		return;
	if (!probe_gate(c->sess, c, &ep, data, len))
		return;
	deliver_stream_from(c, data, len, PATH_SEGMENT, &mapped);
}

/*
 * A LAN peer's identity on the segment is its lanlink port. The client announces
 * that one port (inside the seal, so it is authenticated) and always sends from
 * it, while its multicast announcement is heard once PER FAMILY from a different
 * source address; keying on the port -- not the address -- folds those into one
 * client, so a dual-stack peer is admitted once, not twice. The dual-stack socket
 * receives either family, so the worker's send address may differ from the
 * client's send address without harm (KCP tolerates an asymmetric path).
 */
static int lan_peer_same(const struct sockaddr_in6 *a, const struct sockaddr_in6 *b)
{
	return a->sin6_port == b->sin6_port;
}

static void on_direct_peer(void *arg, const struct sockaddr *peer, socklen_t len,
			   const uint8_t *sdp, size_t sdp_len)
{
	struct conn *c = arg;
	struct sockaddr_in6 np;

	(void)sdp;
	(void)sdp_len;
	if (lanlink_map_peer(peer, len, &np))
		return;
	/*
	 * A link-local lanlink target needs a zone id that does not reliably
	 * survive the announcement path, so it often cannot be reached: take
	 * one on only while nothing routable is held.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&np.sin6_addr) && conn_lan_paths(c, 1))
		return;
	/*
	 * The same peer is heard from every address it has, so these announcements
	 * differ in source but carry the one lanlink port that identifies it.
	 * Each is one more candidate: the proof a probe leaves on one of them
	 * ranks it above the untried rest, so arrival order discards nothing.
	 */
	conn_add_lan_path(c, PATH_SEGMENT, &np, NULL, 0);
}

/*
 * Which connection of `tab` holds this endpoint? The whole endpoint first, so
 * two clients that happen to share a lanlink port are told apart, then the port
 * alone. Host main thread.
 */
static struct conn *ep_owner(struct conn *const *tab, const struct path_ep *ep)
{
	int i, exact;

	for (exact = 1; exact >= 0; exact--)
		for (i = 0; i < HOST_MAX_WORKERS; i++)
			if (tab[i] && conn_holds_ep(tab[i], ep, exact))
				return tab[i];
	return NULL;
}

/* Which LAN worker holds this endpoint? Admission asks this: an endpoint being
 * served over the segment is not a fresh claimant. Host main thread. */
static struct conn *lan_owner(struct sess *s, const struct path_ep *ep)
{
	return ep_owner(s->lan_conns, ep);
}

/* Is this endpoint already an active LAN worker? (host main thread only) */
static int lan_conn_active(struct sess *s, const struct sockaddr_in6 *peer)
{
	struct path_ep ep;

	if (path_ep_from_sockaddr(&ep, (const struct sockaddr *)peer,
				  sizeof(*peer)))
		return 0;
	return lan_owner(s, &ep) != NULL;
}

/* The ICE ufrag of an answer (its client's single-use identity), into out
 * (>= 40 bytes). candpack round-trips it, so it is stable across the mailbox. */
static void sdp_ufrag(const char *sdp, char *out)
{
	const char *p = strstr(sdp, "ice-ufrag:");

	out[0] = '\0';
	if (p)
		sscanf(p, "ice-ufrag:%39s", out);
}

/* Is this claimant already admitted over the direct path -- served by a LAN
 * worker, or queued for one? (host main thread only) */
static int conn_is_lost(struct conn *c);

/*
 * A claimant already served over lanlink is refused a second admission -- once
 * per client, not once per transport. Unless the connection serving it is
 * lost: then the claim is that client returning, over whichever transport
 * reaches us now (a host that roamed off the shared segment hears its old
 * LAN clients over the DHT), and admission or resumption is what it needs.
 */
static int lan_ufrag_claimed(const struct sess *s, const char *ufrag)
{
	int i;

	if (!ufrag[0])
		return 0;
	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->lan_conns[i] &&
		    !strcmp(s->lan_conns[i]->claim_ufrag, ufrag))
			return !conn_is_lost(s->lan_conns[i]);
	for (i = 0; i < s->lan_pending_n; i++)
		if (!strcmp(s->lan_pending[i].ufrag, ufrag))
			return 1;
	return 0;
}

/* Is this claimant one of the ICE punches already in flight? (host main
 * thread only) */
static int ufrag_admitted(const struct sess *s, const char *ufrag)
{
	int i;

	if (!ufrag[0])
		return 0;
	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (!strcmp(s->punch_ufrag[i], ufrag))
			return 1;
	return 0;
}

/*
 * Host: a sealed multicast answer from a LAN-scope source is a direct claim.
 * Its (source, announced-port) endpoint is where it is served, but its identity
 * is the ICE ufrag inside the seal -- the same one its DHT answer carries, so a
 * claimant that reaches us over both transports is admitted once, not once per
 * path. Queue it unless it is already served, punching, active or queued, and
 * drop any pending offer of its own that the turnstile is still holding. Runs
 * on the host main thread (from sig_dispatch in pump_once); no worker work here.
 */
static void on_direct_claim(void *arg, const struct sockaddr *src, socklen_t srclen,
			    const uint8_t *sdp, size_t sdp_len)
{
	struct sess *s = arg;
	struct sockaddr_in6 mapped, qmapped;
	char claim_sdp[NAT_SDP_MAX], ufrag[40], queued[40];
	int i;

	if (!sdp || sdp_len >= NAT_SDP_MAX)
		return;
	memcpy(claim_sdp, sdp, sdp_len);
	claim_sdp[sdp_len] = '\0';
	sdp_ufrag(claim_sdp, ufrag);
	if (lanlink_map_peer(src, srclen, &mapped))
		return;
	if (ufrag_admitted(s, ufrag) ||
	    (s->have_served && !strcmp(ufrag, s->last_served_ufrag)))
		return;
	if (lan_conn_active(s, &mapped))
		return;
	if (lan_ufrag_claimed(s, ufrag))
		return;
	if (s->have_peer_sdp) {
		sdp_ufrag(s->peer_sdp, queued);
		if (!strcmp(ufrag, queued))
			s->have_peer_sdp = 0;
	}
	for (i = 0; i < s->lan_pending_n; i++)
		if (lanlink_map_peer((struct sockaddr *)&s->lan_pending[i].sa,
				     s->lan_pending[i].len, &qmapped) == 0 &&
		    lan_peer_same(&qmapped, &mapped))
			return;
	if (s->lan_pending_n >= HOST_MAX_WORKERS)
		return;			/* full: the 1 Hz re-broadcast re-offers */
	memcpy(&s->lan_pending[s->lan_pending_n].sa, src, srclen);
	s->lan_pending[s->lan_pending_n].len = srclen;
	snprintf(s->lan_pending[s->lan_pending_n].ufrag,
		 sizeof(s->lan_pending[s->lan_pending_n].ufrag), "%s", ufrag);
	s->lan_pending_n++;
}

/*
 * Host: an inbound lanlink datagram. Demultiplex it by source into the owning
 * connection's stream; a probe from a source no connection holds is offered to
 * adoption instead, within the budget probe_gate keeps. Runs on the host main
 * thread (lanlink_dispatch from pump_once); conns[] is mutated only on that
 * thread, so no lock beyond the conn's stream_lock (taken by deliver_stream
 * against a teardown).
 */
static void host_lan_recv(void *arg, const struct sockaddr *src, socklen_t srclen,
			  const uint8_t *data, size_t len)
{
	struct sess *s = arg;
	struct sockaddr_in6 mapped;
	struct path_ep ep;
	struct conn *c;

	if (lanlink_map_peer(src, srclen, &mapped) ||
	    path_ep_from_sockaddr(&ep, (struct sockaddr *)&mapped,
				  sizeof(mapped)))
		return;
	c = ep_owner(s->conns, &ep);
	if (!probe_gate(s, c, &ep, data, len))
		return;
	if (c)
		deliver_stream_from(c, data, len, PATH_SEGMENT, &mapped);
	else if (path_probe_is(data, len))
		probe_adopt(s, data, len, &mapped);
}

static void on_peer_offer(void *arg, const uint8_t *data, size_t len)
{
	struct sess *s = arg;
	struct conn *c = s->offer_conn;
	char incoming[NAT_SDP_MAX];
	char filtered[NAT_SDP_MAX];
	char ufrag[40];

	if (!c)
		return;
	/*
	 * Stage the arrival before adopting it. The host rotates a fresh offer the
	 * instant it picks a claim up, so a description belonging to the offer that
	 * replaced this agent's can still arrive; it names a different peer identity
	 * and feeding it to an agent already primed with another would churn the
	 * punch. Whatever is rejected here must not have overwritten peer_sdp.
	 */
	if (len >= sizeof(incoming))
		len = sizeof(incoming) - 1;
	memcpy(incoming, data, len);
	incoming[len] = '\0';
	sdp_ufrag(incoming, ufrag);
	snprintf(s->cur_offer_ufrag, sizeof(s->cur_offer_ufrag), "%s", ufrag);
	if (c->remote_ufrag[0] && strcmp(ufrag, c->remote_ufrag)) {
		dbg_logf("session: ignore rotated offer while punching");
		return;
	}
	snprintf(s->peer_sdp, sizeof(s->peer_sdp), "%s", incoming);
	if (lan_ufrag_claimed(s, ufrag)) {
		dbg_logf("session: claimant already served over lanlink -- drop");
		s->have_peer_sdp = 0;
		return;
	}
	s->have_peer_sdp = 1;
	/* Later arrivals are fresh candidates (multicast trickles one source at
	 * a time); feed them straight into the already-primed agent -- but not
	 * once connected, when the mailbox GET keeps redelivering the same set and
	 * re-adding it only churns the agent (and logs "max candidates"). */
	if (c->nat && s->remote_set && !nat_connected(c->nat)) {
		sdp_filter_peer(s->peer_sdp, s->cfg->family, filtered, sizeof(filtered));
		nat_set_remote_description(c->nat, filtered);
	}
}

/*
 * Prefer the link-local direct path whenever it is up (stable address, no NAT
 * binding to expire, no STUN mapping to lose, and its announcement proved it
 * works); fall back to ICE only when there is no link-local peer. Both paths
 * are still received from, so the peer's own choice is honoured.
 */
static int on_stream_output(void *arg, const uint8_t *data, size_t len)
{
	return transport_send((struct conn *)arg, data, len);
}

/*
 * Ask the kernel which local address it would source outbound packets from
 * toward a generic global destination. UDP connect() sends no packet; it only
 * triggers route and source-address selection, disclosing nothing. Used to
 * bind ICE to its real source so its host candidate matches what the peer
 * sees, which is what a no-STUN path needs.
 */
static int source_addr(int family, char *out, size_t outlen)
{
	static const char *probe6 = "2001:db8::1";
	static const char *probe4 = "192.0.2.1";
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	sock_t fd;
	int rc = -1;

	if (wsock_init())
		return -1;
	fd = socket(family, SOCK_DGRAM, 0);
	if (!sock_valid(fd))
		return -1;
	memset(&ss, 0, sizeof(ss));
	if (family == AF_INET6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;

		a->sin6_family = AF_INET6;
		a->sin6_port = htons(9);
		if (inet_pton(AF_INET6, probe6, &a->sin6_addr) != 1 ||
		    connect(fd, (struct sockaddr *)a, sizeof(*a)))
			goto out;
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;

		a->sin_family = AF_INET;
		a->sin_port = htons(9);
		if (inet_pton(AF_INET, probe4, &a->sin_addr) != 1 ||
		    connect(fd, (struct sockaddr *)a, sizeof(*a)))
			goto out;
	}
	memset(&ss, 0, sizeof(ss));
	if (getsockname(fd, (struct sockaddr *)&ss, &slen))
		goto out;
	if (family == AF_INET6)
		rc = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr,
			       out, outlen) ? 0 : -1;
	else
		rc = inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr,
			       out, outlen) ? 0 : -1;
out:
	sock_close(fd);
	return rc;
}

/* Fill a connection's ICE identity: a fresh ufrag/pwd and a random bind port.
 * The host uses a new one per offer (single-use per join, so two clients never
 * share credentials); the client keeps its one for the whole session. */
static void conn_gen_ice(struct conn *c)
{
	static const char hx[] = "0123456789abcdef";
	uint8_t rb[16];
	int j;

	random_bytes(rb, 4);
	for (j = 0; j < 4; j++) {
		c->ice_ufrag[j * 2] = hx[rb[j] >> 4];
		c->ice_ufrag[j * 2 + 1] = hx[rb[j] & 0xf];
	}
	c->ice_ufrag[8] = '\0';
	random_bytes(rb, 16);
	for (j = 0; j < 16; j++) {
		c->ice_pwd[j * 2] = hx[rb[j] >> 4];
		c->ice_pwd[j * 2 + 1] = hx[rb[j] & 0xf];
	}
	c->ice_pwd[32] = '\0';
	random_bytes(rb, 2);
	c->bind_port = (uint16_t)(40000 + (((rb[0] << 8) | rb[1]) % 20000));
	/* A client probes under its own identity; a host overwrites this with the
	 * claimant it admitted (lan_drain, the turnstile at pickup, and the
	 * single-connection state machine when it takes an answer up). */
	if (c->sess && !c->sess->cfg->is_host)
		snprintf(c->claim_ufrag, sizeof(c->claim_ufrag), "%s",
			 c->ice_ufrag);
	/* What a probe proved was proved for one claimant identity, so a fresh
	 * one voids every measurement; the endpoints themselves stand. */
	pthread_mutex_lock(&c->path_lock);
	path_table_reset_stats(&c->paths);
	pthread_mutex_unlock(&c->path_lock);
	c->claim_held_seen = 0;
	c->claim_lost = 0;
	c->claim_released_ms = 0;
	c->remote_ufrag[0] = '\0';
}

static int nat_setup(struct conn *c)
{
	struct sess *s = c->sess;
	static char bind_addr[64];
	struct nat_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	if (source_addr(AF_INET6, s->src6, sizeof(s->src6)))
		s->src6[0] = '\0';		/* no global v6 source */
	cfg.stun_host = s->cfg->stun_host;
	cfg.stun_port = s->cfg->stun_port;
	if (!cfg.stun_host && s->cfg->stun_auto && s->stun_count > 0) {
		/* Rotate the managed pool across retries, splitting host:port. */
		const char *e = s->stun_servers[s->ice_attempt % s->stun_count];
		const char *colon = strrchr(e, ':');
		size_t hl = colon ? (size_t)(colon - e) : strlen(e);

		if (hl >= sizeof(s->stun_host))
			hl = sizeof(s->stun_host) - 1;
		memcpy(s->stun_host, e, hl);
		s->stun_host[hl] = '\0';
		cfg.stun_host = s->stun_host;
		cfg.stun_port = colon ? (uint16_t)atoi(colon + 1) : 3478;
		if (!cfg.stun_port)
			cfg.stun_port = 3478;
	}
	if (!cfg.stun_host && !(s->cfg->sig_flags & SIG_MCAST)) {
		int af = s->cfg->family == 4 ? AF_INET : AF_INET6;

		if (!source_addr(af, bind_addr, sizeof(bind_addr)))
			cfg.bind_address = bind_addr;
	}
	cfg.bind_port = c->bind_port;
	cfg.ice_ufrag = c->ice_ufrag;
	cfg.ice_pwd = c->ice_pwd;
	cfg.on_local_sdp = on_local_sdp;
	cfg.on_recv = on_transport_recv;
	cfg.on_candidate = on_ice_candidate;
	cfg.arg = c;

	s->remote_set = 0;
	c->nat = nat_create(&cfg);
	if (!c->nat || nat_gather(c->nat))
		return -1;
	s->stun_since_ms = now_ms();
	conn_add_ice_path(c);
	return 0;
}

static void pump_once(struct sess *s, int timeout_cap_ms)
{
	struct pollfd fds[6];
	int timeout, nfds, lnf = 0;

	nfds = sig_prepare(s->sig, fds, 5, &timeout);
	if (s->lan)
		lnf = lanlink_prepare(s->lan, fds + nfds, 6 - nfds, &timeout);
	if (timeout > timeout_cap_ms)
		timeout = timeout_cap_ms;
	sock_poll(fds, (nfds_t)(nfds + lnf), timeout);
	sig_dispatch(s->sig, fds, nfds);
	if (s->lan)
		lanlink_dispatch(s->lan, fds + nfds, lnf);
}

/* From the ssh thread: does the KCP stream take more bulk? (The thread is
 * joined before the stream dies; the lock covers future reordering.) */
static int conn_tx_room(void *arg)
{
	struct conn *c = arg;
	int room = 1;

	pthread_mutex_lock(&c->stream_lock);
	if (c->stream)
		room = stream_tx_room(c->stream);
	pthread_mutex_unlock(&c->stream_lock);
	return room;
}

static void *ssh_srv_thread(void *p)
{
	struct conn *c = p;
	struct sess *s = c->sess;
	struct sshd_opts o;

	memset(&o, 0, sizeof(o));
	o.hostkey = s->cfg->hostkey;
	memcpy(o.auth, s->auth, sizeof(o.auth));
	keys_derive_ro_auth(o.auth_ro, s->auth);
	o.have_ro = 1;
	o.command = s->cfg->ssh_command;	/* NULL => tmux default */
	o.command_ro = s->cfg->ssh_command_ro;
	o.use_pty = s->cfg->use_pty;
	o.end_fd = s->cfg->ssh_end_fd;
	o.ctl_fd = c->ssh_ctl_fd;
	o.no_fwd = s->cfg->no_fwd;
	o.forward_only = s->cfg->forward_only;
	o.ro_out = &c->read_only;
	o.fwd_refused_out = &c->fwd_refused;
	o.tx_room = conn_tx_room;
	o.tx_room_arg = c;
	sshd_serve_fd(c->ssh_fd, &o);
	return NULL;
}

static void *ssh_cli_thread(void *p)
{
	struct conn *c = p;
	struct sess *s = c->sess;
	struct sshc_opts o;

	memset(&o, 0, sizeof(o));
	memcpy(o.host_fp, s->cfg->tok.hostpub, 32);
	memcpy(o.auth, s->auth, sizeof(o.auth));
	o.interactive = s->cfg->interactive && !s->cfg->forward_only;
	o.forward_only = s->cfg->forward_only;
	o.read_only = (s->cfg->tok.flags & TOKEN_FLAG_RO) != 0;
	o.connect_timeout_s = s->cfg->connect_timeout_s;
	o.ctl_fd = c->ssh_ctl_fd;
	o.fwd_l = s->cfg->fwd_l;
	o.nfwd_l = s->cfg->nfwd_l;
	o.fwd_r = s->cfg->fwd_r;
	o.nfwd_r = s->cfg->nfwd_r;
	o.tx_room = conn_tx_room;
	o.tx_room_arg = c;
	o.status = session_status;
	o.status_arg = c;
	o.send = s->cfg->test_send;
	o.send_len = s->cfg->test_send_len;
	o.recv = s->cfg->test_recv;
	o.recv_cap = s->cfg->test_recv_cap;
	o.recv_len = s->cfg->test_recv_len;
	o.hold_ms = s->cfg->test_hold_ms;
	c->ssh_cli_rc = sshc_connect_fd(c->ssh_fd, &o);
	return NULL;
}

/* One interface address of a netmon snapshot as a sockaddr at `port`. Returns
 * the family (4 or 6), or 0 for a record neither family names. */
static int addr_sockaddr(const struct netmon_addr *a, uint16_t port,
			 struct sockaddr_storage *out)
{
	memset(out, 0, sizeof(*out));
	if (a->family == AF_INET && a->addrlen == 4) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)out;

		s4->sin_family = AF_INET;
		s4->sin_port = htons(port);
		memcpy(&s4->sin_addr, a->addr, 4);
		return 4;
	}
	if (a->family == AF_INET6 && a->addrlen == 16) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)out;

		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons(port);
		memcpy(&s6->sin6_addr, a->addr, 16);
		return 6;
	}
	return 0;
}

/*
 * Advertise our own local endpoints to the peer over CTLM_CAND, so it probes
 * and holds them rather than exploring only the pair admission produced. The
 * port is the shared lanlink socket's: that is the one transport able to send
 * to an arbitrary endpoint, so an advertised endpoint always becomes a SEGMENT
 * or ROUTED path and never an ICE one. The addresses come from the interface
 * snapshot, which already leaves out loopback (which names this machine to
 * nobody else) and IPv6 link-local (which travels without the zone id it cannot
 * be reached without). A session with no lanlink socket advertises nothing.
 * Self-throttled; runs from the connection's own loop.
 */
static void cand_tell(struct conn *c, uint64_t now)
{
	struct netmon_addr addrs[NETMON_MAX_ADDRS];
	struct sess *s = c->sess;
	size_t naddrs, i;
	uint16_t port;

	if (now < c->next_cand_ms)
		return;
	c->next_cand_ms = now + CAND_TELL_MS;
	if (!s->lan)
		return;
	port = lanlink_port(s->lan);
	if (!port)
		return;
	naddrs = netmon_snapshot(addrs, NETMON_MAX_ADDRS);
	for (i = 0; i < naddrs; i++) {
		struct sockaddr_storage sa;
		uint8_t pl[CTL_RDV_PLEN];
		int fam = addr_sockaddr(&addrs[i], port, &sa);

		if (!fam)
			continue;
		ctl_rdv_encode(pl, fam, (struct sockaddr *)&sa);
		ctl_send(c, CTLM_CAND, pl, sizeof(pl));
	}
}

/*
 * Keep a rendezvous node warm on each reachable family, re-announce them to the
 * peer in-band, and adopt the peer's node for any family we cannot reach yet.
 * The result is that both ends hold both families' rendezvous nodes, kept fresh
 * and validated for the whole session, so a forced family downgrade can
 * re-signal over the survivor. Self-throttled; runs from the
 * live loop's thread, where sig is single-threaded.
 */
static void rdv_maintain(struct conn *c)
{
	struct sess *s = c->sess;
	static const int famv[2] = { 4, 6 };
	uint64_t now = now_ms();
	int i;

	if (!(s->cfg->sig_flags & SIG_DHT))
		return;

	/* Re-validate and keep warm each family we can reach ourselves. Rare (a
	 * held node dying inside the window is unlikely and the DHT lookup is the
	 * fallback), but poll faster until the first node has been captured. */
	if (now >= s->next_rdv_warm_ms) {
		int captured = 0;

		for (i = 0; i < 2; i++) {
			struct sockaddr_storage sa;
			socklen_t sl = sizeof(sa);

			if (!sig_located(s->sig, famv[i],
					 (struct sockaddr *)&sa, &sl))
				continue;
			captured = 1;
			if (!s->rdv[i].have || s->rdv[i].len != sl ||
			    memcmp(&s->rdv[i].sa, &sa, sl)) {
				s->rdv[i].sa = sa;
				s->rdv[i].len = sl;
				s->rdv[i].have = 1;
			}
			sig_reinforce(s->sig, famv[i],
				      (struct sockaddr *)&sa, sl);
		}
		s->next_rdv_warm_ms = now + (captured ? RDV_WARM_MS : RDV_POLL_MS);
	}

	/* Tell the peer our nodes, so it has fresh ones to reconnect through even
	 * if the token only carried one family. */
	if (now >= c->next_rdv_tell_ms) {
		for (i = 0; i < 2; i++)
			if (s->rdv[i].have) {
				uint8_t pl[CTL_RDV_PLEN];

				ctl_rdv_encode(pl, famv[i],
					       (struct sockaddr *)&s->rdv[i].sa);
				ctl_send(c, CTLM_RDV, pl, sizeof(pl));
			}
		c->next_rdv_tell_ms = now + RDV_TELL_MS;
	}

	/* Adopt the peer's announcement for any family we cannot reach ourselves,
	 * readying us to roam onto it (e.g. a v4-only host gaining v6, told a v6
	 * node by a dual-stack client). */
	if (c->rdv_in_dirty) {
		struct rdv_node in[2];

		pthread_mutex_lock(&c->rdv_lock);
		memcpy(in, c->rdv_in, sizeof(in));
		c->rdv_in_dirty = 0;
		pthread_mutex_unlock(&c->rdv_lock);
		for (i = 0; i < 2; i++) {
			struct sockaddr_storage sa;
			socklen_t sl = sizeof(sa);

			if (in[i].have && !sig_located(s->sig, famv[i],
						(struct sockaddr *)&sa, &sl))
				s->rdv[i] = in[i];
		}
	}
}

static int net_changed(struct sess *s);
static int sig_rebuild(struct sess *s);

/*
 * A fresh ICE password under the same ufrag: the identity naming this
 * connection stays, the claim's bytes do not -- an unchanged claim would be
 * deduplicated away by the peer's redelivery guard and never seen at all.
 */
static void conn_fresh_pwd(struct conn *c)
{
	static const char hx[] = "0123456789abcdef";
	uint8_t rb[16];
	int j;

	random_bytes(rb, 16);
	for (j = 0; j < 16; j++) {
		c->ice_pwd[j * 2] = hx[rb[j] >> 4];
		c->ice_pwd[j * 2 + 1] = hx[rb[j] & 0xf];
	}
	c->ice_pwd[32] = '\0';
}

/*
 * How long a link stays lost before the client re-claims in place, and how
 * long each such attempt runs before regathering. Short on purpose: the
 * attempt is non-destructive -- every warm path stays in the table, the SSH
 * session above never pauses more than the outage itself -- so trying early
 * costs nothing and beats the host's reap comfortably.
 */
#define RESUME_AFTER_MS 3000
#define RESUME_ATTEMPT_MS 10000

/*
 * Client-side in-place resume: while the link is lost, run the claim half of
 * the join machinery from inside the live connection -- gather a fresh agent
 * under this connection's own session-stable ICE identity, post the claim,
 * prime the current offer -- so the host recognises the claimant and grafts
 * the punch into the worker it already runs for us. Nothing above the
 * transport is touched: the SSH session, the forwards and their carried TCP
 * streams ride out the gap on KCP retransmission. The caller has just
 * dispatched sig, so no callback is in flight when the signalling is rebuilt
 * for a roam.
 */
static void resume_tick(struct conn *c)
{
	struct sess *s = c->sess;
	uint64_t now = now_ms();
	int lost;

	pthread_mutex_lock(&c->hb_lock);
	lost = c->lost_since_ms != 0 &&
	       now - c->lost_since_ms >= RESUME_AFTER_MS;
	pthread_mutex_unlock(&c->hb_lock);
	if (!lost) {
		if (c->rs_state) {
			c->rs_state = 0;
			sig_withdraw(s->sig);
			dbg_logf("resume: link back");
		}
		return;
	}
	switch (c->rs_state) {
	case 0:
		if (net_changed(s) && sig_rebuild(s))
			return;
		conn_drop_ice_path(c);
		if (c->nat) {
			nat_destroy(c->nat);
			c->nat = NULL;
		}
		conn_fresh_pwd(c);
		s->have_local_sdp = 0;
		s->have_peer_sdp = 0;
		s->remote_set = 0;
		c->remote_ufrag[0] = '\0';
		pthread_mutex_lock(&s->trickle_lock);
		s->trickle_sdp[0] = '\0';
		s->trickle_dirty = 0;
		pthread_mutex_unlock(&s->trickle_lock);
		if (nat_setup(c))
			return;
		c->rs_state = 1;
		c->rs_deadline = now + RESUME_ATTEMPT_MS;
		dbg_logf("resume: re-claiming under the session identity");
		return;
	case 1:
		if (s->have_local_sdp) {
			char filtered[NAT_SDP_MAX];

			sdp_filter(s->local_sdp, s->cfg->family, filtered,
				   sizeof(filtered));
			snprintf(s->local_sdp, sizeof(s->local_sdp), "%s",
				 filtered);
			s->pool_posted = fan_local_sdp(s);
			sig_post(s->sig, (const uint8_t *)s->local_sdp,
				 strlen(s->local_sdp));
			sig_redeliver(s->sig);
			dbg_logf("resume: claim posted");
			c->rs_state = 2;
		} else if (now >= c->rs_deadline) {
			c->rs_state = 0;
		}
		return;
	default:
		if (s->have_peer_sdp && !s->remote_set) {
			char filtered[NAT_SDP_MAX];
			char ufrag[40];

			sdp_filter_peer(s->peer_sdp, s->cfg->family, filtered,
					sizeof(filtered));
			if (!nat_set_remote_description(c->nat, filtered)) {
				sdp_ufrag(s->peer_sdp, ufrag);
				snprintf(c->remote_ufrag,
					 sizeof(c->remote_ufrag), "%s", ufrag);
				s->remote_set = 1;
				dbg_logf("resume: primed offer %s", ufrag);
			}
		}
		if (now >= c->rs_deadline)
			c->rs_state = 0;
		return;
	}
}

/*
 * Run one connection's SSH session over its connected stream until it ends.
 * Sets up the KCP stream, the ssh thread (sshd on a host, sshc on a client) and
 * its comrade-ctl channel, then pumps the bridge, the heartbeat and the status.
 * A failed bring-up (the peer is not serving yet) ends the ssh thread quickly,
 * so this returns to be retried; a live session ends only when a side closes it.
 *
 * drive_sig: also pump the signalling (sig/lanlink) and rendezvous keep-warm
 * from this loop. The single-connection path (client, or a host with one
 * connection) sets it; a host worker does not -- sig is single-threaded and
 * stays owned by the host's main loop, so a worker only pumps its own transport.
 */
static int conn_run(struct conn *c, int drive_sig)
{
	struct sess *s = c->sess;
	struct sshbridge *br;
	struct stream *st;
	pthread_t th;
	sock_t sp[2], cp[2];
	int done = 0, link_lost = 0;
	uint64_t next_hb, conn_start;

	/* Both pairs must be sockets, not pipes: they are polled in the same
	 * set as the transport, and WSAPoll takes nothing else (see wsock.h). */
	if (sock_pair(sp))
		return -1;
	if (sock_pair(cp)) {
		sock_close(sp[0]);
		sock_close(sp[1]);
		return -1;
	}
	if (nosigpipe(cp[0])) {		/* see ctl_send */
		/* best effort: without it a closed channel raises SIGPIPE */
	}
	c->stream = stream_create(SESSION_CONV, on_stream_output, c);
	if (!c->stream) {
		sock_close(sp[0]);
		sock_close(sp[1]);
		sock_close(cp[0]);
		sock_close(cp[1]);
		return -1;
	}
	c->ssh_fd = sp[1];
	c->ssh_ctl_fd = cp[1];
	c->ctl_fd = cp[0];
	c->ctl_rf.len = 0;
	dbg_logf("conn_run: sock_pair ok sp=%d/%d cp=%d/%d, starting ssh thread",
		 (int)sp[0], (int)sp[1], (int)cp[0], (int)cp[1]);
	if (pthread_create(&th, NULL,
			   s->cfg->is_host ? ssh_srv_thread : ssh_cli_thread, c)) {
		dbg_logf("conn_run: pthread_create failed");
		sock_close(sp[0]);
		sock_close(sp[1]);
		sock_close(cp[0]);
		sock_close(cp[1]);
		c->ctl_fd = INVALID_SOCK;
		stream_destroy(c->stream);
		c->stream = NULL;
		return -1;
	}
	br = sshbridge_create(sp[0], c->stream,
			      s->cfg->is_host ? LINGER_HOST_MS : LINGER_CLIENT_MS);

	/* The path is up on entry, so start the liveness clock as alive. */
	pthread_mutex_lock(&c->hb_lock);
	c->hb_last_pong = now_ms();
	c->hb_last_heard = c->hb_last_pong;
	c->hb_pong_seen = 0;
	c->lost_since_ms = 0;
	pthread_mutex_unlock(&c->hb_lock);
	next_hb = now_ms();
	conn_start = now_ms();
	c->next_cand_ms = conn_start;

	if (drive_sig) {
		/* Capture a rendezvous node per family for reconnection (the host
		 * was already locating; ask on the client side too). */
		if (s->cfg->sig_flags & SIG_DHT)
			sig_locate(s->sig);
		/*
		 * Now connected, a client stops advertising its answer: otherwise
		 * it would keep re-claiming the single mailbox slot the host clears
		 * after serving it, hogging it for the whole session so no other
		 * client could ever join. A rejoin re-posts (ST_GATHER). The host
		 * (mcast single-connection path) keeps advertising its offer.
		 */
		if (!s->cfg->is_host)
			sig_withdraw(s->sig);
		s->next_rdv_warm_ms = now_ms();
		c->next_rdv_tell_ms = now_ms() + 1500;
	}

	while (!done) {
		struct pollfd fds[9];
		int timeout = 10, nfds = 0, lnf = 0, bidx, cidx;

		/* A re-punched agent the turnstile grafted for us: adopt it
		 * here, on the one thread that owns c->nat. Its callbacks were
		 * re-pointed at this connection before it was parked, so its
		 * packets have been landing in the stream all along; this
		 * makes it the sending agent too. */
		if (c->resume_agent) {
			struct nat_agent *old = c->nat;

			conn_drop_ice_path(c);
			c->nat = c->resume_agent;
			c->resume_agent = NULL;
			conn_add_ice_path(c);
			if (old)
				nat_destroy(old);
			c->bh_mute = 0;
			/* The resumed link earns a full liveness window; without
			 * this it is judged by silence that predates it. */
			pthread_mutex_lock(&c->hb_lock);
			c->hb_last_heard = now_ms();
			pthread_mutex_unlock(&c->hb_lock);
			dbg_logf("resume: adopted the re-punched agent");
		}
		if (drive_sig) {
			nfds = sig_prepare(s->sig, fds, 5, &timeout);
			if (s->lan)
				lnf = lanlink_prepare(s->lan, fds + nfds,
						      9 - nfds - 2, &timeout);
			if (timeout < 0 || timeout > 10)
				timeout = 10;
		}
		bidx = nfds + lnf;
		fds[bidx].fd = sshbridge_fd(br);
		fds[bidx].events = sshbridge_events(br);
		fds[bidx].revents = 0;
		cidx = bidx + 1;
		fds[cidx].fd = c->ctl_fd;
		fds[cidx].events = POLLIN;
		fds[cidx].revents = 0;
		sock_poll(fds, (nfds_t)(cidx + 1), timeout);
		if (drive_sig) {
			sig_dispatch(s->sig, fds, nfds);
			if (s->lan)
				lanlink_dispatch(s->lan, fds + nfds, lnf);
		}
		if (sshbridge_pump(br, fds[bidx].revents, (uint32_t)now_ms()) < 0)
			done = 1;
		if (fds[cidx].revents & (POLLIN | POLLHUP | POLLERR))
			ctl_readable(c);

		/* Every path is kept warm for the whole session, not merely the
		 * one carrying it, so a switch is an immediate reordering rather
		 * than a rediscovery. */
		path_tick(c, now_ms());
		cand_tell(c, now_ms());
		if (s->cfg->test_blackhole_ms > 0 && c->bh_kind < 0 &&
		    !c->bh_done &&
		    now_ms() - conn_start >
		    (uint64_t)s->cfg->test_blackhole_ms) {
			struct path_pick pick;

			if (s->cfg->test_blackhole_all) {
				c->bh_mute = 1;
				c->bh_done = 1;
				dbg_logf("path blackholed: all");
			} else if (!conn_pick(c, &pick)) {
				pthread_mutex_lock(&c->path_lock);
				memset(&c->bh_ep, 0, sizeof(c->bh_ep));
				path_ep_from_sockaddr(&c->bh_ep,
					(struct sockaddr *)&pick.remote,
					sizeof(pick.remote));
				c->bh_kind = pick.kind;
				c->bh_done = 1;
				pthread_mutex_unlock(&c->path_lock);
				dbg_logf("path blackholed: %s",
					 pick.label[0] ? pick.label : "ICE");
			}
		}
		if ((c->bh_kind >= 0 || c->bh_mute) &&
		    s->cfg->test_blackhole_lift_ms > 0 &&
		    now_ms() - conn_start >
		    (uint64_t)s->cfg->test_blackhole_lift_ms) {
			pthread_mutex_lock(&c->path_lock);
			c->bh_kind = -1;
			pthread_mutex_unlock(&c->path_lock);
			c->bh_mute = 0;
			dbg_logf("path blackhole lifted");
		}

		if (now_ms() >= next_hb) {
			uint8_t ts[CTL_TS_LEN];

			ctl_put_u64(ts, now_ms());
			ctl_send(c, CTLM_PING, ts, sizeof(ts));
			next_hb = now_ms() + HB_INTERVAL_MS;
		}
		if (drive_sig)
			rdv_maintain(c);
		if (drive_sig && !s->cfg->is_host)
			resume_tick(c);
		if (now_ms() >= c->next_status_ms) {
			uint64_t now = now_ms(), lp;
			int state, pong_seen;

			pthread_mutex_lock(&c->hb_lock);
			lp = c->hb_last_pong;
			if (c->hb_last_heard > lp)
				lp = c->hb_last_heard;
			pong_seen = c->hb_pong_seen;
			if (pong_seen) {
				if (now - lp > HB_LOST_MS) {
					if (!c->lost_since_ms)
						c->lost_since_ms = now;
				} else {
					c->lost_since_ms = 0;
				}
			}
			state = c->lost_since_ms ? CONN_LOST : CONN_LIVE;
			pthread_mutex_unlock(&c->hb_lock);
			publish_status(c, state);
			/* The heartbeat is end to end, so this says the
			 * session stopped getting through -- not that any one
			 * path did. A path dying is a reordering the heartbeat
			 * never sees; this is what it looks like when there is
			 * nothing left to reorder to. */
			if (state == CONN_LOST && !link_lost) {
				link_lost = 1;
				dbg_logf("link lost: nothing heard for %ums",
					 (unsigned)(now - lp));
			} else if (state == CONN_LIVE && link_lost) {
				link_lost = 0;
				dbg_logf("link back");
			}
			c->next_status_ms = now + 500;
			/* A host reaps a client that has been silent too long --
			 * the bridge would otherwise never end for one that
			 * vanished (roamed) without a clean disconnect, leaving
			 * the host wedged on a dead link and unable to re-serve.
			 * This holds for both the worker (drive_sig 0) and the
			 * single-connection host (drive_sig 1); only the client
			 * (never is_host) stays up on loss, showing the outage
			 * and letting the user quit or roam. Before the first pong,
			 * the comrade-ctl channel may still be mid-handshake, so
			 * silence is bounded by connect_timeout_s instead of the
			 * tighter heartbeat-loss window. */
			if (s->cfg->is_host) {
				/* A recent resume pickup restarts the clock: the
				 * client is actively coming back, and its half of
				 * the punch may still be completing. */
				if (pong_seen && c->lost_since_ms &&
				    !c->resume_pending &&
				    now - c->lost_since_ms > HOST_REAP_MS &&
				    (!c->resume_last_ms ||
				     now - c->resume_last_ms > HOST_REAP_MS))
					done = 1;
				else if (!pong_seen && now - conn_start >
					 (uint64_t)s->cfg->connect_timeout_s * 1000) {
					done = 1;
					if (s->cfg->obs && s->cfg->obs->escalate)
						s->cfg->obs->escalate(
							s->cfg->obs->arg,
							"a peer connected but never "
							"finished the handshake -- "
							"check your firewall allows "
							"comrade");
				}
			}
		}
	}

	/*
	 * Unblock the ssh thread before joining. When a peer roams away it stops
	 * answering without ever closing the transport, so the thread is parked
	 * in a blocking libssh read that never sees EOF -- joining it directly
	 * would hang the reap forever (the very wedge that kept a host from
	 * re-serving). Shutting our ends of the ssh and control socketpairs hands
	 * the thread the EOF it is waiting for, so it returns and the join below
	 * completes. A clean end has already exited the thread; the shutdown is
	 * then a harmless no-op.
	 */
	sock_shutdown(sp[0], SHUT_RDWR);
	sock_shutdown(cp[0], SHUT_RDWR);
	pthread_join(th, NULL);
	sshbridge_destroy(br);
	sock_close(sp[0]);		/* sp[1] is closed by the ssh module */
	/* Both control-socket ends are ours to close: the ssh module bridges
	 * cp[1] but never closes it. Mark the fd gone first so a stray ctl_send
	 * is a no-op. */
	c->ctl_fd = INVALID_SOCK;
	sock_close(cp[0]);
	sock_close(cp[1]);
	/* Clear the stream under the lock before destroying it: a transport
	 * receive thread (or the host's main-thread demux) may be about to call
	 * stream_input on it. After this, deliver_stream sees NULL and no-ops. */
	pthread_mutex_lock(&c->stream_lock);
	st = c->stream;
	c->stream = NULL;
	pthread_mutex_unlock(&c->stream_lock);
	stream_destroy(st);

	if (s->cfg->is_host)
		return 0;
	return c->ssh_cli_rc;
}

/*
 * Drop this attempt's ICE identity and start over: destroy the agent, mint a
 * fresh ufrag/pwd/port, flush the descriptions gathered against the old one and
 * re-enter ST_GATHER, which re-posts and claims again. Both callers have proof
 * the current agent is finished -- a roam, or a turnstile race this client lost
 * -- and neither can recover by re-entering ST_WAIT_ICE, because the agent
 * still reports the pair it nominated as connected. Returns 0, or -1 if the new
 * agent could not be created.
 */
static int client_regather(struct sess *s)
{
	const struct session_obs *o = s->cfg->obs;

	if (o && o->reset)
		o->reset(o->arg);
	s->established_fired = 0;
	conn_drop_ice_path(&s->c);
	if (s->c.nat)
		nat_destroy(s->c.nat);
	s->c.nat = NULL;
	conn_gen_ice(&s->c);
	s->have_local_sdp = 0;
	s->have_peer_sdp = 0;
	s->remote_set = 0;
	s->local_sdp[0] = '\0';
	s->peer_sdp[0] = '\0';
	pthread_mutex_lock(&s->trickle_lock);
	s->trickle_sdp[0] = '\0';	/* drop the old agent's trickle */
	s->trickle_dirty = 0;
	pthread_mutex_unlock(&s->trickle_lock);
	s->peer_state = SESSION_PEER_SEEN;
	sig_redeliver(s->sig);		/* we discarded the offer we were given */
	return nat_setup(&s->c) ? -1 : 0;
}

/*
 * The current agent's STUN attempt has run its course with no reflexive v4
 * while one is called for (a private/CGNAT v4 and no public one on the
 * table). Only for the rotated pool -- an explicit --stun server is the
 * operator's to keep alive -- and only while the rotation budget lasts.
 */
static int stun_stall(struct sess *s)
{
	if (s->cfg->stun_host || !s->cfg->stun_auto || s->stun_count < 2)
		return 0;
	if (!s->have_priv4 || s->have_srflx4)
		return 0;
	if (s->stun_rotations >= STUN_ROTATE_MAX)
		return 0;
	return now_ms() - s->stun_since_ms > STUN_ROTATE_MS;
}

/* The single-connection path (client, or a host serving one connection): run
 * the session's one connection, driving signalling from the same loop. */
static int run_ssh(struct sess *s)
{
	return conn_run(&s->c, 1);
}

/* Note which DHT families this host can reach, from its own candidates: any v4
 * candidate implies the v4 DHT (reachable outbound, NAT or not); a v6 one needs
 * global scope, since the v6 DHT is not reachable from a ULA or link-local. */
static void update_expect(struct sess *s)
{
	const char *p = s->local_sdp;
	char addr[64];

	while ((p = strstr(p, "a=candidate:")) != NULL) {
		if (sscanf(p, "a=candidate:%*s %*d %*s %*u %63s", addr) == 1) {
			if (!strchr(addr, ':'))
				s->expect4 = 1;
			else if (addr_scope(addr) == NET_SCOPE_GLOBAL)
				s->expect6 = 1;
		}
		p += 12;
	}
}

/*
 * How long a DHT attempt is given before it has run its course, so a family
 * with a route but no ack settles at NONE rather than staying PENDING (a
 * captive portal, or UDP blocked outbound). It bounds a family sig has stopped
 * working on; one still inside sig's own locate window waits for that to close
 * first, so the second family gets its full run before the verdict.
 */
#define DHT_CONCLUDE_MS 25000

/*
 * Is there a usable address of `family` on an interface: netmon's snapshot
 * already drops loopback interfaces and v6 link-local, which reach nothing off
 * the segment they are on. The interfaces rather than our ICE candidates,
 * because the candidate policy answers who we can punch with and says nothing
 * about the family's reach to the DHT, which binds its own sockets.
 */
static int fam_usable_addr(const struct netmon_addr *addrs, size_t naddrs,
			   int family)
{
	int af = family == 6 ? AF_INET6 : AF_INET;
	size_t i;

	for (i = 0; i < naddrs; i++)
		if (addrs[i].family == af)
			return 1;
	return 0;
}

/*
 * This family's DHT attempt can no longer produce an ack worth waiting for:
 * the operator declined the DHT outright, or the attempt armed with the
 * current sig has had its grace and sig is no longer storing to locate this
 * family. A rebuild on a roam re-arms it, so a move onto a network that does
 * reach the DHT is given a fresh run.
 */
static int dht_attempt_concluded(struct sess *s, int family)
{
	if (!(s->cfg->sig_flags & SIG_DHT))
		return 1;
	if (now_ms() - s->dht_since_ms <= DHT_CONCLUDE_MS)
		return 0;
	return !sig_locating(s->sig, family);
}

/* Gather the tokgen facts for `family`, over an interface snapshot the caller
 * already holds. */
static void gather_facts(struct sess *s, int family,
			 const struct netmon_addr *addrs, size_t naddrs,
			 struct tokgen_facts *f)
{
	int af = family == 6 ? AF_INET6 : AF_INET;
	char buf[64];

	memset(f, 0, sizeof(*f));
	f->has_usable_addr = fam_usable_addr(addrs, naddrs, family);
	f->has_default_route = source_addr(af, buf, sizeof(buf)) == 0;
	f->dht_acked = sig_dht_acked(s->sig, family);
	f->dht_attempt_concluded = dht_attempt_concluded(s, family);
	f->public_port_proven = 0;	/* no UPnP/NAT-PMP/PCP in the tree */
}

/*
 * Report the host's rendezvous progress to the view: which family has a node,
 * how far each is through locating one, and the endpoint the local status line
 * shows. What goes into the token is token_pump's.
 */
static void maybe_announce_rendezvous(struct sess *s)
{
	const struct session_obs *o = s->cfg->obs;
	struct sockaddr_storage a4, a6;
	socklen_t l4 = sizeof(a4), l6 = sizeof(a6);
	int have4, have6;

	if (!s->cfg->is_host)
		return;
	if (!s->have_local_sdp)		/* no candidates yet: cannot decide */
		return;

	update_expect(s);
	have4 = sig_located(s->sig, 4, (struct sockaddr *)&a4, &l4);
	have6 = sig_located(s->sig, 6, (struct sockaddr *)&a6, &l6);

	/* Remember the located rendezvous endpoint for the local status line,
	 * preferring v6 to match how the token renders it. */
	if (have6)
		fmt_sockaddr((struct sockaddr *)&a6, l6,
			     s->status_rdv, sizeof(s->status_rdv));
	else if (have4)
		fmt_sockaddr((struct sockaddr *)&a4, l4,
			     s->status_rdv, sizeof(s->status_rdv));

	if (o && o->rdv_stage) {		/* drive the RENDEZVOUS spinner */
		if (s->expect4)
			o->rdv_stage(o->arg, 4, sig_rdv_stage(s->sig, 4));
		if (s->expect6)
			o->rdv_stage(o->arg, 6, sig_rdv_stage(s->sig, 6));
	}

	/* Tell the view each family's state -- located, or expected-but-pending --
	 * so the invite can say "IPv4 ready, locating IPv6" rather than warn early. */
	if (o && o->rendezvous) {
		char b[80];

		if (have4) {
			addr_str((struct sockaddr *)&a4, b, sizeof(b));
			o->rendezvous(o->arg, 4, b, 1);
		} else if (s->expect4) {
			o->rendezvous(o->arg, 4, "", 0);
		}
		if (have6) {
			addr_str((struct sockaddr *)&a6, b, sizeof(b));
			o->rendezvous(o->arg, 6, b, 1);
		} else if (s->expect6) {
			o->rendezvous(o->arg, 6, "", 0);
		}
	}
}

/*
 * The token's view of a sockaddr: the bare address bytes, and the port in host
 * order. NULL for a family the token cannot carry.
 */
static const uint8_t *ep_bytes(const struct sockaddr *sa, uint16_t *port)
{
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		*port = ntohs(a->sin6_port);
		return (const uint8_t *)&a->sin6_addr;
	}
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		*port = ntohs(a->sin_port);
		return (const uint8_t *)&a->sin_addr;
	}
	return NULL;
}

/*
 * The address bytes and host-order port a carried token already holds for
 * `family`, so a state seeded from it is re-reported with the endpoint it
 * names rather than a fresh one.
 */
static void carried_ep(const struct token *t, int family, uint8_t *addr,
		       uint16_t *port)
{
	memset(addr, 0, TOKEN_EP6_LEN);
	if (family == 6) {
		memcpy(addr, t->ep6_addr, TOKEN_EP6_LEN);
		*port = t->ep6_port;
	} else {
		memcpy(addr, t->ep4_addr, TOKEN_EP4_LEN);
		*port = t->ep4_port;
	}
}

/*
 * Resolve one family's tokgen verdict into the state its slot carries; `addr`
 * (TOKEN_EP6_LEN bytes) and `port` receive what a RENDEZVOUS or DIRECT slot
 * embeds. A verdict whose address is not to hand yet stays PENDING.
 */
static int advert_state(struct sess *s, int fam, enum tok_advert adv,
			uint8_t *addr, uint16_t *port)
{
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	const uint8_t *b;

	memset(addr, 0, TOKEN_EP6_LEN);
	*port = 0;
	switch (adv) {
	case TOK_ADVERT_RENDEZVOUS:
		if (!sig_located(s->sig, fam, (struct sockaddr *)&ss, &sl))
			break;
		b = ep_bytes((struct sockaddr *)&ss, port);
		if (!b)
			break;
		memcpy(addr, b, fam == 6 ? TOKEN_EP6_LEN : TOKEN_EP4_LEN);
		return TOKEN_STATE_RENDEZVOUS;
	case TOK_ADVERT_NONE:
		return TOKEN_STATE_NONE;
	case TOK_ADVERT_ENDPOINT:	/* a proven endpoint; the prover that
					 * fills this arm is the RFC 5780 probe */
	case TOK_ADVERT_PENDING:
		break;
	}
	return TOKEN_STATE_PENDING;
}

/*
 * Host token minting: decide each family from the pure tokgen tree over the
 * facts observed now, and report the ones that changed, so the token follows
 * the host's situation in both directions -- a family that settled at NONE is
 * upgraded when a late DHT convergence gives it a node, and one that had a
 * node drops back when a move takes it away. Both families report once per
 * session, so a host that reaches nothing still has a token to show at t=0. If
 * neither family has an address the operator is told, rather than the host
 * hanging silently.
 */
static void token_pump(struct sess *s)
{
	static const int famv[2] = { 4, 6 };
	const struct session_obs *o = s->cfg->obs;
	enum tok_advert adv[2] = { TOK_ADVERT_PENDING, TOK_ADVERT_PENDING };
	struct netmon_addr addrs[NETMON_MAX_ADDRS];
	struct tokgen_facts f4, f6;
	struct tokgen_result verdict;
	size_t naddrs;
	int i;

	if (!s->cfg->is_host || !s->cfg->on_token_state)
		return;
	if (now_ms() < s->next_tok_ms)
		return;
	s->next_tok_ms = now_ms() + 1000;	/* the route probe is cheap,
						 * not free */
	/* Before the local candidates exist there are no facts to decide on, so
	 * each family holds the state it was seeded with -- which is how the
	 * t=0 report happens with no special case, and how a re-gather holds
	 * the token steady instead of flapping it back to PENDING. */
	if (s->have_local_sdp) {
		naddrs = netmon_snapshot(addrs, NETMON_MAX_ADDRS);
		gather_facts(s, 4, addrs, naddrs, &f4);
		gather_facts(s, 6, addrs, naddrs, &f6);
		if (tokgen_decide_host(&f4, &f6, &verdict) < 0) {
			if (o && o->escalate && !s->noconn_warned &&
			    now_ms() - s->start_ms > 3000) {
				o->escalate(o->arg,
					    "no usable address on any family -- "
					    "nothing to host over; check the network");
				s->noconn_warned = 1;
			}
		} else if (s->noconn_warned) {
			/* The fact the warning reported has stopped being true:
			 * a roam brought addresses back. */
			s->noconn_warned = 0;
			if (o && o->escalate_clear)
				o->escalate_clear(o->arg);
		}
		adv[0] = verdict.v4;
		adv[1] = verdict.v6;
	}
	for (i = 0; i < 2; i++) {
		uint8_t a[TOKEN_EP6_LEN];
		uint16_t port = 0;
		int st;

		if (s->have_local_sdp) {
			st = advert_state(s, famv[i], adv[i], a, &port);
		} else {
			st = s->tok_state[i];
			carried_ep(&s->cfg->tok, famv[i], a, &port);
		}
		if (s->tok_told[i] && st == s->tok_state[i])
			continue;
		s->tok_state[i] = st;
		s->tok_told[i] = 1;
		s->cfg->on_token_state(s->cfg->arg, famv[i], st, a, port);
	}
}

/* Keep the located rendezvous nodes warm (host, main thread only -- sig is
 * single-threaded). The per-connection announce/adopt lives in rdv_maintain. */
static void rdv_keep_warm(struct sess *s)
{
	static const int famv[2] = { 4, 6 };
	uint64_t now = now_ms();
	int i, captured = 0;

	if (!(s->cfg->sig_flags & SIG_DHT) || now < s->next_rdv_warm_ms)
		return;
	for (i = 0; i < 2; i++) {
		struct sockaddr_storage sa;
		socklen_t sl = sizeof(sa);

		if (!sig_located(s->sig, famv[i], (struct sockaddr *)&sa, &sl))
			continue;
		captured = 1;
		if (!s->rdv[i].have || s->rdv[i].len != sl ||
		    memcmp(&s->rdv[i].sa, &sa, sl)) {
			s->rdv[i].sa = sa;
			s->rdv[i].len = sl;
			s->rdv[i].have = 1;
		}
		sig_reinforce(s->sig, famv[i], (struct sockaddr *)&sa, sl);
	}
	s->next_rdv_warm_ms = now + (captured ? RDV_WARM_MS : RDV_POLL_MS);
}

/*
 * The host's registry of the connections it serves, which is what lets an
 * authenticated probe from an unknown source find the connection it belongs to
 * (probe_adopt). Registered at admission and cleared in conn_free, so nothing
 * can reach a connection through it after it has gone; host main thread only,
 * which is where admission and reaping both happen.
 */
static void conn_register(struct sess *s, struct conn *c)
{
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (!s->conns[i]) {
			s->conns[i] = c;
			return;
		}
}

static void conn_unregister(struct sess *s, struct conn *c)
{
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->conns[i] == c)
			s->conns[i] = NULL;
}

static struct conn *conn_alloc(struct sess *s)
{
	struct conn *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	c->sess = s;
	c->ctl_fd = INVALID_SOCK;
	c->bh_kind = -1;
	pthread_mutex_init(&c->hb_lock, NULL);
	pthread_mutex_init(&c->rdv_lock, NULL);
	pthread_mutex_init(&c->status_lock, NULL);
	pthread_mutex_init(&c->stream_lock, NULL);
	pthread_mutex_init(&c->path_lock, NULL);
	path_table_init(&c->paths);
	conn_gen_ice(c);
	return c;
}

static void conn_free(struct conn *c)
{
	if (!c)
		return;
	conn_unregister(c->sess, c);
	conn_drop_ice_path(c);
	if (c->nat)
		nat_destroy(c->nat);
	pthread_mutex_destroy(&c->hb_lock);
	pthread_mutex_destroy(&c->rdv_lock);
	pthread_mutex_destroy(&c->status_lock);
	pthread_mutex_destroy(&c->stream_lock);
	pthread_mutex_destroy(&c->path_lock);
	free(c);
}

#define HOST_IDLE_MS 3000		/* exit after this idle once we have served */

struct worker {
	pthread_t th;
	struct conn *c;
	volatile int done;
	int used;
};

/* A worker runs one connected client's session on the shared command (tmux
 * attach), without driving sig -- that stays with the host's main thread. */
static void *worker_thread(void *p)
{
	struct worker *w = p;

	conn_run(w->c, 0);
	w->done = 1;
	return NULL;
}

static int worker_spawn(struct worker *ws, struct conn *c)
{
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (!ws[i].used) {
			ws[i].c = c;
			ws[i].done = 0;
			ws[i].used = 1;
			if (pthread_create(&ws[i].th, NULL, worker_thread,
					   &ws[i])) {
				ws[i].used = 0;
				return -1;
			}
			return 0;
		}
	return -1;			/* worker table full */
}

/* The running worker serving this claimant, if any: a client's ICE identity
 * is session-stable, so the ufrag names the same client across its claims. */
static struct conn *worker_by_ufrag(struct worker *ws, const char *ufrag)
{
	int i;

	if (!ufrag[0])
		return NULL;
	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (ws[i].used && !ws[i].done &&
		    !strcmp(ws[i].c->claim_ufrag, ufrag))
			return ws[i].c;
	return NULL;
}

static int conn_is_lost(struct conn *c)
{
	int lost;

	pthread_mutex_lock(&c->hb_lock);
	lost = c->lost_since_ms != 0;
	pthread_mutex_unlock(&c->hb_lock);
	return lost;
}

/* Is this claimant queued for LAN admission (not yet a worker)? */
static int lan_pending_ufrag(const struct sess *s, const char *ufrag)
{
	int i;

	for (i = 0; i < s->lan_pending_n; i++)
		if (!strcmp(s->lan_pending[i].ufrag, ufrag))
			return 1;
	return 0;
}

/* Is a punch for this claimant running right now? Narrower than
 * ufrag_admitted, whose slots keep naming a claimant for the worker's whole
 * life -- residue that must not veto that same claimant's resumption. */
static int punch_in_flight(const struct sess *s, struct conn *const *punching,
			   const char *ufrag)
{
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (punching[i] && !strcmp(s->punch_ufrag[i], ufrag))
			return 1;
	return 0;
}

/*
 * Admit each newly-claimed LAN endpoint: allocate a conn bound to that peer over
 * the shared lanlink socket (no ICE, no punch -- a multicast claimant is already
 * directly reachable) and spawn a worker for it, alongside the ICE turnstile.
 * Runs on the host main thread each loop, fully concurrent with the ICE state
 * machine. Endpoints that overflow the worker budget are dropped; the client's
 * 1 Hz re-broadcast re-offers them.
 */
static void lan_drain(struct sess *s, struct worker *ws, int *dash_seq)
{
	const struct session_obs *o = s->cfg->obs;
	int p, i;

	for (p = 0; p < s->lan_pending_n; p++) {
		struct sockaddr_in6 mapped;
		char addr[PATH_LABEL_MAX];
		struct conn *c;
		int slot = -1;

		if (lanlink_map_peer((struct sockaddr *)&s->lan_pending[p].sa,
				     s->lan_pending[p].len, &mapped))
			continue;
		if (lan_conn_active(s, &mapped))
			continue;		/* a re-broadcast during setup */
		if (s->cfg->host_admit_max &&
		    s->admitted_n >= s->cfg->host_admit_max)
			continue;		/* the admission budget is spent */
		for (i = 0; i < HOST_MAX_WORKERS; i++)
			if (!s->lan_conns[i]) {
				slot = i;
				break;
			}
		if (slot < 0)
			break;			/* worker table full */
		c = conn_alloc(s);
		if (!c)
			break;
		/* c->nat stays NULL: this worker is lanlink only. */
		if (conn_add_lan_path(c, PATH_SEGMENT, &mapped, addr,
				      sizeof(addr))) {
			conn_free(c);
			break;
		}
		snprintf(c->claim_ufrag, sizeof(c->claim_ufrag), "%s",
			 s->lan_pending[p].ufrag);
		if (c->claim_ufrag[0]) {
			snprintf(s->last_served_ufrag,
				 sizeof(s->last_served_ufrag), "%s",
				 c->claim_ufrag);
			s->have_served = 1;
		}
		s->admitted_n++;
		c->dash_id = ++*dash_seq;
		snprintf(c->status_peer, sizeof(c->status_peer), "%s", addr);
		s->lan_conns[slot] = c;
		conn_register(s, c);
		if (o && o->peer) {
			o->peer(o->arg, c->dash_id, SESSION_PEER_SEEN, addr);
			o->peer(o->arg, c->dash_id, SESSION_PEER_LIVE, addr);
		}
		if (worker_spawn(ws, c)) {	/* worker table full */
			if (o && o->peer)
				o->peer(o->arg, c->dash_id, SESSION_PEER_GONE,
					addr);
			s->lan_conns[slot] = NULL;
			conn_free(c);
		}
	}
	s->lan_pending_n = 0;			/* drained; overflow re-offered */
}

/*
 * Advance each in-flight ICE punch. Release-on-pickup means the listener has
 * already rotated on, so a wedged punch here never head-of-line-blocks the next
 * joiner. A connected punch becomes a worker (its dashboard row opens here); a
 * failed or timed-out one is freed and its slot reused. On connect the served
 * identity is recorded so the stale-claim guard ignores a lagging DHT re-read of
 * it. test_stuck_punches forces the first punches to stay wedged (never spawn,
 * only time out), which the L1-stuck e2e uses to prove the no-block property.
 * Host main thread.
 */
static void punch_scan(struct sess *s, struct worker *ws, struct conn **punching,
		       struct conn **punch_resume, uint64_t *punch_start,
		       int *punch_stuck, int *dash_seq)
{
	const struct session_obs *o = s->cfg->obs;
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++) {
		struct conn *c = punching[i];

		if (!c)
			continue;
		if (!punch_stuck[i] && nat_connected(c->nat)) {
			char loc[192], rem[192], addr[80];

			snprintf(s->last_served_ufrag, sizeof(s->last_served_ufrag),
				 "%.39s", s->punch_ufrag[i]);
			s->have_served = 1;
			/*
			 * A resumption: hand the punched agent to the worker
			 * already serving this claimant. Its callbacks are
			 * re-pointed first, so packets land in the worker's
			 * stream from this instant; the worker's own thread
			 * adopts it as the sending agent on its next pass
			 * (c->nat belongs to that thread). The punch shell is
			 * dissolved without a worker, a dashboard row, or a
			 * registration of its own.
			 */
			if (punch_resume[i]) {
				struct conn *t = punch_resume[i];

				dbg_logf("host: punch connected -> resume "
					 "worker");
				nat_rebind(c->nat, t);
				t->resume_agent = c->nat;
				c->nat = NULL;
				t->resume_pending = 0;
				punching[i] = NULL;
				punch_resume[i] = NULL;
				conn_free(c);
				continue;
			}
			addr[0] = '\0';
			if (!nat_selected(c->nat, loc, sizeof(loc), rem,
					  sizeof(rem))) {
				cand_addr(rem, addr, sizeof(addr));
				dbg_logf("host: punch connected -> spawn worker "
					 "loc=[%s] rem=[%s]", loc, rem);
			}
			if (o && o->peer) {
				/* SEEN opens this client's row, LIVE marks it up;
				 * dash_id keys the row for updates and GONE. */
				c->dash_id = ++*dash_seq;
				snprintf(c->status_peer, sizeof(c->status_peer),
					 "%s", addr);
				o->peer(o->arg, c->dash_id, SESSION_PEER_SEEN,
					addr);
				o->peer(o->arg, c->dash_id, SESSION_PEER_LIVE,
					addr);
			}
			punching[i] = NULL;
			conn_register(s, c);
			if (worker_spawn(ws, c)) {
				s->punch_ufrag[i][0] = '\0';
				conn_free(c);		/* table full */
			}
		} else if (now_ms() - punch_start[i] > ICE_ATTEMPT_MS ||
			   (!punch_stuck[i] && nat_failed(c->nat))) {
			dbg_logf("host: punch %s -> drop",
				 punch_stuck[i] ? "wedged (test)" : "failed");
			if (punch_resume[i]) {
				punch_resume[i]->resume_pending = 0;
				punch_resume[i] = NULL;
			}
			punching[i] = NULL;
			s->punch_ufrag[i][0] = '\0';
			conn_free(c);
		}
	}
}

/*
 * A host with any signalling backend serves many clients through the turnstile:
 * DHT/ICE joins arrive over the mailbox, and same-segment multicast claimants
 * are admitted over the one shared lanlink socket (demultiplexed by source),
 * both concurrently on the shared tmux. An isolated LAN with no DHT is no longer
 * capped at one client. Only the test-only single-connection flag forces the
 * sequential re-serve state machine instead.
 */
static int host_is_multiuser(const struct session_cfg *cfg)
{
	return cfg->is_host && (cfg->sig_flags & (SIG_DHT | SIG_MCAST)) &&
	       !cfg->test_single_conn;
}

/*
 * Has the local network moved? The interfaces are the answer; test_roam_ms
 * manufactures one on a period instead, so the rebuild below can be exercised
 * without a second network to walk between.
 */
static int net_changed(struct sess *s)
{
	const struct session_cfg *cfg = s->cfg;
	uint64_t now = now_ms();

	if (cfg->test_roam_ms > 0 && now >= s->next_roam_ms &&
	    (cfg->test_roam_max <= 0 || s->roams < cfg->test_roam_max)) {
		s->next_roam_ms = now + (uint64_t)cfg->test_roam_ms;
		s->roams++;
		return 1;
	}
	return netmon_changed(&s->netmon, now);
}

/*
 * Create the signalling and arm it: subscribe the callbacks, advertise the
 * direct transport's port and seed the rendezvous. The lanlink socket itself is
 * not touched here -- it belongs to the session rather than to sig, and worker
 * threads send on it without a lock. Returns 0 on success.
 */
static int sig_arm(struct sess *s)
{
	const struct session_cfg *cfg = s->cfg;

	s->sig = sig_create(cfg->tok.rdv, cfg->sig_flags, cfg->is_host);
	if (!s->sig)
		return -1;
	s->dht_since_ms = now_ms();	/* a rebuild is a fresh attempt, and a
					 * fresh grace, on the new network */
	sig_subscribe(s->sig, on_peer_offer, s);
	if (s->lan) {
		sig_set_direct_port(s->sig, lanlink_port(s->lan));
		if (host_is_multiuser(cfg)) {
			sig_subscribe_direct(s->sig, on_direct_claim, s);
			sig_set_mcast_claims(s->sig, 1);
		} else {
			sig_subscribe_direct(s->sig, on_direct_peer, &s->c);
		}
	}
	seed_rendezvous(s);
	return 0;
}

/*
 * Rebuild the signalling on a move. A fresh sig binds a new DHT socket and
 * joins the multicast groups on the interfaces that exist now, where the old
 * one stays bound to the one that vanished -- which is why a manual restart
 * reconnects instantly and a reused socket does not. The old sig is discarded
 * first: jech/dht is a process-global singleton, so two nodes cannot overlap,
 * and its node set is not persisted because the fresh one is what the run
 * should leave behind. The lanlink socket is deliberately left as it is, since
 * worker threads and libjuice's receive thread send on it unlocked and a host's
 * direct endpoint names its port. The new sig is seeded from the rendezvous
 * nodes this session kept warm and exchanged over CTLM_RDV, so it starts from a
 * node the peer holds too.
 *
 * Callers must run this on the thread that owns sig, with no sig callback in
 * flight: at the top of the owning loop, between one sig_dispatch and the next
 * sig_prepare, never from a callback sig_dispatch is still unwinding. Returns 0,
 * or -1 when there is no signalling left to run the session on.
 */
static int sig_rebuild(struct sess *s)
{
	sig_discard(s->sig);
	s->sig = NULL;
	if (sig_arm(s)) {
		dbg_logf("sig: rebuild failed -- giving up the session");
		return -1;
	}
	s->next_rdv_warm_ms = now_ms();
	dbg_logf("sig: rebuilt on the new network");
	return 0;
}

/*
 * Host turnstile: advertise one offer at a time (a fresh ICE identity per
 * offer) and accept a client's claimed answer. On pickup the listener hands the
 * punch to an in-flight set (punching[]) and rotates a fresh offer at once, so
 * the next client is admitted immediately instead of after the punch completes
 * (release-on-pickup); punch_scan turns a connected punch into a worker and
 * frees a wedged one. DHT/ICE joins are serialised through the single mailbox
 * slot; same-segment multicast claimants are admitted directly over the shared
 * lanlink socket (lan_drain), fully concurrently. The worker sessions run
 * concurrently. Signalling and the rendezvous keep-warm stay on this thread
 * (sig is single-threaded); workers only pump their own transport.
 */
static int host_turnstile(struct sess *s)
{
	const struct session_cfg *cfg = s->cfg;
	const struct session_obs *o = cfg->obs;
	struct worker ws[HOST_MAX_WORKERS];
	struct conn *listen = NULL;
	struct conn *punching[HOST_MAX_WORKERS];	/* in-flight ICE punches */
	struct conn *punch_resume[HOST_MAX_WORKERS];	/* worker each punch
							 * resumes, if any */
	uint64_t punch_start[HOST_MAX_WORKERS];
	int punch_stuck[HOST_MAX_WORKERS];		/* test: never connect */
	enum { TS_GATHER, TS_WAIT_CLAIM } ts = TS_GATHER;
	uint64_t deadline = now_ms() + (uint64_t)cfg->connect_timeout_s * 1000;
	uint64_t last_active = now_ms();
	char filtered[NAT_SDP_MAX];
	sock_t end_fd = cfg->ssh_end_fd;
	int served = 0, dash_seq = 0, i, j;
	int stuck_left = cfg->test_stuck_punches;

	memset(ws, 0, sizeof(ws));
	memset(punching, 0, sizeof(punching));
	memset(punch_resume, 0, sizeof(punch_resume));
	memset(punch_stuck, 0, sizeof(punch_stuck));
	s->last_served_ufrag[0] = '\0';
	s->have_served = 0;
	memset(s->punch_ufrag, 0, sizeof(s->punch_ufrag));

	while (cfg->host_serve_max == 0 || served < cfg->host_serve_max) {
		int active = 0;

		pump_once(s, 100);		/* the main thread owns sig + lan */
		maybe_announce_rendezvous(s);	/* report the rendezvous */
		token_pump(s);			/* mint and advertise the token */
		rdv_keep_warm(s);
		lan_drain(s, ws, &dash_seq);	/* admit same-segment claimants */

		/*
		 * Roamed while waiting for the next client: the signalling is
		 * bound to the network that just vanished and the current offer
		 * advertises its candidates, so rebuild sig on the interfaces that
		 * exist now, drop the listening agent and re-gather, and flush the
		 * stale local addresses from the dashboard (the live client rows,
		 * and the workers behind them, stay). This is the top of the loop:
		 * pump_once has finished dispatching, so no sig callback is in
		 * flight and the rebuild is safe here.
		 */
		if (net_changed(s)) {
			if (listen) {
				conn_free(listen);
				listen = NULL;
				s->offer_conn = NULL;
			}
			if (cfg->test_roam_hard)
				for (i = 0; i < HOST_MAX_WORKERS; i++)
					if (ws[i].used)
						ws[i].c->bh_mute = 1;
			if (sig_rebuild(s))
				break;
			s->have_local_sdp = 0;
			s->have_peer_sdp = 0;
			s->remote_set = 0;
			s->local_sdp[0] = '\0';
			s->peer_sdp[0] = '\0';
			pthread_mutex_lock(&s->trickle_lock);
			s->trickle_sdp[0] = '\0';
			s->trickle_dirty = 0;
			s->npool4 = 0;
			stun_mapping_reset(&s->map4);
			pthread_mutex_unlock(&s->trickle_lock);
			ts = TS_GATHER;
			s->stun_rotations = 0;	/* fresh budget on the new network */
			s->have_priv4 = 0;	/* and fresh v4 facts to run it on */
			s->have_srflx4 = 0;
			s->pool_reported = 0;
			s->pool_posted = 0;
			s->mapping_reported = 0;
			stun_probe_kick(s);
			if (o && o->net_reset)
				o->net_reset(o->arg);
		}

		if (o) {			/* dashboard: local candidates */
			if (o->net && s->trickle_dirty) {
				char buf[NAT_SDP_MAX];

				pthread_mutex_lock(&s->trickle_lock);
				memcpy(buf, s->trickle_sdp, sizeof(buf));
				s->trickle_sdp[0] = '\0';
				s->trickle_dirty = 0;
				pthread_mutex_unlock(&s->trickle_lock);
				report_candidates(s, buf);
			}
			if (o->net && s->have_local_sdp)
				obs_report_net(s);
			if (o->tick)
				o->tick(o->arg);
		}

		for (i = 0; i < HOST_MAX_WORKERS; i++) {
			if (ws[i].used && ws[i].done) {
				pthread_join(ws[i].th, NULL);
				if (o && o->peer)
					o->peer(o->arg, ws[i].c->dash_id,
						SESSION_PEER_GONE,
						ws[i].c->status_peer);
				/* Unregister a LAN worker so a rejoining client
				 * (same endpoint) is admitted afresh. */
				for (j = 0; j < HOST_MAX_WORKERS; j++)
					if (s->lan_conns[j] == ws[i].c)
						s->lan_conns[j] = NULL;
				/* A punch that was resuming this worker loses
				 * its target and proceeds as a fresh admission
				 * -- the client wanted its session back, but a
				 * new one beats none. */
				for (j = 0; j < HOST_MAX_WORKERS; j++)
					if (punch_resume[j] == ws[i].c)
						punch_resume[j] = NULL;
				if (ws[i].c->claim_ufrag[0])
					for (j = 0; j < HOST_MAX_WORKERS; j++)
						if (!strcmp(s->punch_ufrag[j],
							    ws[i].c->claim_ufrag)) {
							s->punch_ufrag[j][0] = '\0';
							break;
						}
				conn_free(ws[i].c);
				ws[i].used = 0;
				served++;
			}
			if (!ws[i].used)
				continue;
			active = 1;
			/* Relay the pair actually carrying this worker now, so the
			 * dashboard tracks ICE re-nomination instead of freezing the
			 * address captured at connect. status.peer is the in-use
			 * remote (see publish_status); status_peer caches what the
			 * row last showed. */
			if (o && o->peer) {
				char cur[80];

				pthread_mutex_lock(&ws[i].c->status_lock);
				snprintf(cur, sizeof(cur), "%s", ws[i].c->status.peer);
				pthread_mutex_unlock(&ws[i].c->status_lock);
				if (cur[0] && strcmp(cur, ws[i].c->status_peer)) {
					snprintf(ws[i].c->status_peer,
						 sizeof(ws[i].c->status_peer),
						 "%s", cur);
					o->peer(o->arg, ws[i].c->dash_id,
						SESSION_PEER_LIVE, cur);
				}
			}
			/* The ssh thread learns the grade a beat after the row
			 * appears (it is decided at auth); mark it once known. */
			if (o && o->peer_ro && ws[i].c->read_only &&
			    !ws[i].c->ro_reported) {
				ws[i].c->ro_reported = 1;
				o->peer_ro(o->arg, ws[i].c->dash_id);
			}
			/* A forwarding attempt the ssh thread refused: surface
			 * it once so the operator sees the attempted tunnel. */
			if (o && o->peer_fwd_refused && ws[i].c->fwd_refused &&
			    !ws[i].c->fwd_reported) {
				ws[i].c->fwd_reported = 1;
				o->peer_fwd_refused(o->arg, ws[i].c->dash_id);
			}
		}

		/* Advance in-flight punches (connect -> worker, wedged -> freed),
		 * concurrently with the listener below. An in-flight punch keeps the
		 * host non-idle. */
		punch_scan(s, ws, punching, punch_resume, punch_start,
			   punch_stuck, &dash_seq);
		for (i = 0; i < HOST_MAX_WORKERS; i++)
			if (punching[i])
				active = 1;

		/*
		 * The advertised offer was gathered through a pool server that
		 * produced no public v4: retire the listener and offer again
		 * through the next one. Claims in flight are untouched -- only
		 * the listener rotates, exactly as when an answer cannot be
		 * taken up.
		 */
		pool_pump(s, ts == TS_WAIT_CLAIM && !s->have_peer_sdp);
		if (ts == TS_WAIT_CLAIM && listen && !s->have_peer_sdp &&
		    stun_stall(s)) {
			s->ice_attempt++;
			s->stun_rotations++;
			conn_free(listen);
			listen = NULL;
			s->offer_conn = NULL;
			s->have_local_sdp = 0;
			s->local_sdp[0] = '\0';
			ts = TS_GATHER;
		}

		switch (ts) {
		case TS_GATHER:
			if (!listen) {
				listen = conn_alloc(s);
				if (!listen)
					break;
				s->have_local_sdp = 0;
				s->have_peer_sdp = 0;
				s->remote_set = 0;
				s->local_sdp[0] = '\0';
				s->peer_sdp[0] = '\0';
				s->offer_conn = listen;
				sig_subscribe(s->sig, on_peer_offer, s);
				if (nat_setup(listen)) {
					conn_free(listen);
					listen = NULL;
					s->offer_conn = NULL;
					break;
				}
			}
			if (s->have_local_sdp) {
				sdp_filter(s->local_sdp, cfg->family, filtered,
					   sizeof(filtered));
				snprintf(s->local_sdp, sizeof(s->local_sdp),
					 "%s", filtered);
				s->pool_posted = fan_local_sdp(s);
				sig_rotate(s->sig, (const uint8_t *)s->local_sdp,
					   strlen(s->local_sdp));
				sig_locate(s->sig);
				dbg_logf("host: offer published (served=%d "
					 "active=%d)", served, active);
				ts = TS_WAIT_CLAIM;
			}
			break;
		case TS_WAIT_CLAIM:
			if (s->have_peer_sdp && !s->remote_set) {
				struct conn *resume = NULL;
				char cu[40];
				int pslot = -1, inflight = 0;

				/*
				 * A claim naming a claimant already on the books is
				 * one of two things. From a worker that has lost its
				 * client, it is that client returning -- the ICE
				 * identity is session-stable -- and the punch it asks
				 * for is a resumption of the worker's connection, not
				 * a duplicate join. From anywhere else -- a healthy
				 * worker, a punch in flight, a queued LAN admission,
				 * the claimant just served -- it is the eventually-
				 * consistent DHT re-serving a stale value, ignored as
				 * before (either would be punched again: double-serve).
				 */
				sdp_ufrag(s->peer_sdp, cu);
				if (cu[0]) {
					struct conn *w = worker_by_ufrag(ws, cu);

					if (w && conn_is_lost(w) &&
					    !punch_in_flight(s, punching, cu) &&
					    now_ms() - w->resume_last_ms >
					    RESUME_ATTEMPT_MS) {
						resume = w;
					} else if (w || ufrag_admitted(s, cu) ||
						   lan_pending_ufrag(s, cu) ||
						   (s->have_served &&
						    !strcmp(cu, s->last_served_ufrag))) {
						dbg_logf("host: ignore stale/in-flight claim");
						s->have_peer_sdp = 0;
						break;
					}
				}
				/* A fresh claimant past the admission budget is
				 * left unserved; a resumption always passes. */
				if (!resume && cfg->host_admit_max &&
				    s->admitted_n >= cfg->host_admit_max) {
					dbg_logf("host: admission budget spent "
						 "-- claim ignored");
					s->have_peer_sdp = 0;
					break;
				}
				/* Room to punch? (a free in-flight slot within the
				 * combined worker + punch budget). If not, keep the
				 * claim advertised and pick it up once room frees. */
				for (i = 0; i < HOST_MAX_WORKERS; i++) {
					if (ws[i].used)
						inflight++;
					if (punching[i]) {
						inflight++;
						continue;
					}
					if (pslot < 0)
						pslot = i;
				}
				if (pslot < 0 || inflight >= HOST_MAX_WORKERS)
					break;
				dbg_logf(resume ?
					 "host: resume claim -> punch (release)" :
					 "host: claim received -> punch (release)");
				sdp_filter_peer(s->peer_sdp, cfg->family, filtered,
					   sizeof(filtered));
				if (nat_set_remote_description(listen->nat,
							       filtered)) {
					conn_free(listen);
					listen = NULL;
					s->offer_conn = NULL;
					ts = TS_GATHER;
					break;
				}
				snprintf(listen->remote_ufrag,
					 sizeof(listen->remote_ufrag), "%s", cu);
				/* Release on pickup: hand the punch to the in-flight
				 * set and rotate a fresh offer at once, so the next
				 * client is admitted without waiting for this punch. */
				punching[pslot] = listen;
				punch_resume[pslot] = resume;
				if (resume) {
					resume->resume_pending = 1;
					resume->resume_last_ms = now_ms();
				} else {
					s->admitted_n++;
				}
				snprintf(listen->claim_ufrag,
					 sizeof(listen->claim_ufrag), "%s", cu);
				punch_start[pslot] = now_ms();
				punch_stuck[pslot] = stuck_left > 0;
				if (stuck_left > 0)
					stuck_left--;
				snprintf(s->punch_ufrag[pslot],
					 sizeof(s->punch_ufrag[pslot]),
					 "%s", cu);
				listen = NULL;
				ts = TS_GATHER;
			}
			break;
		}

		/*
		 * The real host runs until its shared tmux ends (the end monitor
		 * signals end_fd, as it does for each worker's sshd). The test
		 * harness passes no end monitor, so there it is bounded by the
		 * deadline, or exits once idle having served at least one client.
		 */
		if (sock_isset(end_fd)) {
			struct pollfd ef;

			ef.fd = end_fd;
			ef.events = POLLIN;
			ef.revents = 0;
			if (sock_poll(&ef, 1, 0) > 0 &&
			    (ef.revents & (POLLIN | POLLHUP | POLLERR)))
				break;
		} else if (now_ms() >= deadline) {
			break;
		} else if (active || ts != TS_GATHER) {
			last_active = now_ms();
		} else if (served > 0 && now_ms() - last_active > HOST_IDLE_MS) {
			break;			/* served all, now idle */
		}
	}

	s->offer_conn = NULL;
	conn_free(listen);
	for (i = 0; i < HOST_MAX_WORKERS; i++) {
		if (punching[i])
			conn_free(punching[i]);
		if (ws[i].used) {
			pthread_join(ws[i].th, NULL);
			conn_free(ws[i].c);
		}
	}
	return 0;
}

/*
 * Bring the signalling up at session start: the link-local transport first, on
 * an ephemeral port -- no token names it, since a proven public endpoint would
 * name the external mapping rather than this local port -- then the signalling
 * armed over it. A roam rebuilds only the sig half (sig_rebuild); the lanlink
 * socket outlives it.
 *
 * The direct transport comes up for host and client alike whenever multicast is
 * on (the old !host_is_multiuser gate is gone): a multi-user host demultiplexes
 * the one shared socket by source into per-worker streams and admits claimants
 * (host_lan_recv / on_direct_claim), while a client or single-connection host
 * carries its one peer (client_lan_recv / on_direct_peer). The host advertises
 * the shared port in its offer. Returns 0 on success.
 */
static int sig_setup(struct sess *s)
{
	const struct session_cfg *cfg = s->cfg;

	if (cfg->sig_flags & SIG_MCAST) {
		int mu = host_is_multiuser(cfg);

		s->lan = lanlink_create(mu ? host_lan_recv : client_lan_recv,
					mu ? (void *)s : (void *)&s->c, 0);
	}
	s->offer_conn = &s->c;
	if (sig_arm(s))
		return -1;
	if (s->lan) {
		if (cfg->obs && cfg->obs->link) {
			struct sig_mcast_if ifs[16];
			int ni = sig_link_ifaces(s->sig, ifs, 16), k;

			for (k = 0; k < ni; k++)
				cfg->obs->link(cfg->obs->arg, ifs[k].name,
					       ifs[k].has4, ifs[k].has6);
		}
		if (!cfg->is_host)
			client_direct_connect(s);
	}
	return 0;
}

int session_run(const struct session_cfg *cfg)
{
	struct sess s;
	enum state st = ST_WAIT_DHT;
	uint64_t deadline;
	int rc;

	memset(&s, 0, sizeof(s));
	s.cfg = cfg;
	s.c.sess = &s;
	s.c.ctl_fd = INVALID_SOCK;		/* no control channel until run_ssh */
	s.c.bh_kind = -1;
	memcpy(s.auth, cfg->tok.auth, TOKEN_AUTH_LEN);
	/* Seed each family from the token handed in, so a re-serve carries the
	 * anchor it already published forward instead of wiping the slot. */
	s.tok_state[0] = token_family_state(&cfg->tok, 4);
	s.tok_state[1] = token_family_state(&cfg->tok, 6);
	pthread_mutex_init(&s.trickle_lock, NULL);
	pthread_mutex_init(&s.c.status_lock, NULL);	/* s.c.status zeroed = connecting */
	pthread_mutex_init(&s.c.hb_lock, NULL);
	pthread_mutex_init(&s.c.rdv_lock, NULL);
	pthread_mutex_init(&s.c.stream_lock, NULL);
	pthread_mutex_init(&s.c.path_lock, NULL);
	path_table_init(&s.c.paths);
	netmon_init(&s.netmon);
	s.next_roam_ms = now_ms() + (uint64_t)cfg->test_roam_ms;
	if (keys_derive(&s.keys, cfg->tok.rdv))
		return 1;
	if (cfg->stun_auto)
		s.stun_servers = stunlist_load(&s.stun_count);
	/* Start the rotation at a random server: it spreads the install base
	 * across the community pool instead of hammering whoever is listed
	 * first, and one dead head entry no longer disables STUN for
	 * everybody. */
	if (s.stun_count > 1) {
		uint8_t rb[2];

		random_bytes(rb, 2);
		s.ice_attempt = ((rb[0] << 8) | rb[1]) % s.stun_count;
	}
	stun_probe_kick(&s);
	nat_log_level(cfg->log_level);	/* < 0 silences libjuice (see nat_log_level) */

	conn_gen_ice(&s.c);

	if (sig_setup(&s)) {
		rc = 1;
		goto done;
	}

	s.start_ms = now_ms();
	deadline = s.start_ms + (uint64_t)cfg->connect_timeout_s * 1000;

	/*
	 * A DHT host serves many clients through the turnstile (multi-user),
	 * whether or not multicast is also on -- it serves same-LAN clients over
	 * ICE too (see host_is_multiuser). Only a host with no DHT at all (an
	 * isolated LAN) falls through to the single-connection state machine.
	 */
	if (host_is_multiuser(cfg)) {
		rc = host_turnstile(&s);
		goto done;
	}

	while (st != ST_DONE && st != ST_FAIL && now_ms() < deadline) {
		char filtered[NAT_SDP_MAX];
		const struct session_obs *o = cfg->obs;

		pump_once(&s, 100);
		maybe_announce_rendezvous(&s);
		token_pump(&s);
		/*
		 * Roamed before the link came up: rebuild the signalling on the
		 * interfaces that exist now, re-gather there and flush the
		 * dashboard's stale local addresses. Once running, a roam instead
		 * drops the link and returns through SSHC_RECONNECT, which rebuilds
		 * from there. pump_once above has finished dispatching, so no sig
		 * callback is in flight.
		 */
		if (st != ST_RUN && net_changed(&s)) {
			if (sig_rebuild(&s)) {
				st = ST_FAIL;
				break;
			}
			if (s.c.nat) {
				conn_drop_ice_path(&s.c);
				nat_destroy(s.c.nat);
				s.c.nat = NULL;
			}
			conn_gen_ice(&s.c);
			pthread_mutex_lock(&s.c.path_lock);
			path_table_clear(&s.c.paths);
			pthread_mutex_unlock(&s.c.path_lock);
			s.have_local_sdp = 0;
			s.have_peer_sdp = 0;
			s.remote_set = 0;
			s.local_sdp[0] = '\0';
			s.peer_sdp[0] = '\0';
			pthread_mutex_lock(&s.trickle_lock);
			s.trickle_sdp[0] = '\0';
			s.trickle_dirty = 0;
			s.npool4 = 0;
			stun_mapping_reset(&s.map4);
			pthread_mutex_unlock(&s.trickle_lock);
			st = ST_WAIT_DHT;
			s.stun_rotations = 0;	/* fresh budget on the new network */
			s.have_priv4 = 0;	/* and fresh v4 facts to run it on */
			s.have_srflx4 = 0;
			s.pool_reported = 0;
			s.pool_posted = 0;
			s.mapping_reported = 0;
			stun_probe_kick(&s);
			if (o && o->net_reset)
				o->net_reset(o->arg);
		}
		/*
		 * No peer has answered yet and the pool server this attempt drew
		 * produced no public v4: re-claim through the next one. Once an
		 * answer is in play the ICE retry path below owns rotation.
		 */
		if ((st == ST_GATHER || st == ST_SIGNAL) && stun_stall(&s)) {
			s.ice_attempt++;
			s.stun_rotations++;
			st = client_regather(&s) ? ST_FAIL : ST_GATHER;
		}
		pool_pump(&s, st == ST_SIGNAL || st == ST_WAIT_ICE);
		if (now_ms() >= s.c.next_status_ms) {
			publish_status(&s.c,
				       st == ST_WAIT_ICE ? CONN_PUNCHING :
				       (st == ST_GATHER || st == ST_SIGNAL) ?
				       CONN_GATHERING : CONN_CONNECTING);
			s.c.next_status_ms = now_ms() + 500;
		}
		if (o) {
			if (o->net && s.trickle_dirty) {
				char buf[NAT_SDP_MAX];

				pthread_mutex_lock(&s.trickle_lock);
				memcpy(buf, s.trickle_sdp, sizeof(buf));
				s.trickle_sdp[0] = '\0';
				s.trickle_dirty = 0;
				pthread_mutex_unlock(&s.trickle_lock);
				report_candidates(&s, buf);
			}
			if (o->net && s.have_local_sdp)
				obs_report_net(&s);	/* view de-dups */
			if (o->tick)
				o->tick(o->arg);
			if (o->escalate && !cfg->is_host && !s.escalated &&
			    st == ST_WAIT_DHT && now_ms() - s.start_ms > 3000) {
				o->escalate(o->arg, "rendezvous node quiet -- "
					    "warming the full DHT");
				s.escalated = 1;
			}
			if (o->escalate && !s.stun_warned &&
			    (cfg->sig_flags & SIG_DHT) && s.have_priv4 &&
			    !s.have_srflx4 && s.stun_count > 0 &&
			    now_ms() - s.start_ms > STUN_WARN_MS) {
				o->escalate(o->arg, "no public IPv4 from STUN -- "
					    "the server list may be stale; run "
					    "`comrade stun-update`");
				s.stun_warned = 1;
			}
			/* The fact the warning reported has stopped being true:
			 * a reflexive v4 did arrive, just late. */
			if (s.stun_warned && s.have_srflx4) {
				s.stun_warned = 0;
				if (o->escalate_clear)
					o->escalate_clear(o->arg);
			}
			if (o->peer && s.have_peer_sdp &&
			    s.peer_state < SESSION_PEER_SEEN) {
				char b[64];

				b[0] = '\0';
				sdp_first_addr(s.peer_sdp, b, sizeof(b));
				o->peer(o->arg, 0, SESSION_PEER_SEEN, b);
				s.peer_state = SESSION_PEER_SEEN;
			}
		}

		switch (st) {
		case ST_WAIT_DHT:
			if (sig_ready(s.sig)) {
				if (nat_setup(&s.c))
					st = ST_FAIL;
				else
					st = ST_GATHER;
			}
			break;
		case ST_GATHER:
			if (s.have_local_sdp) {
				sdp_filter(s.local_sdp, cfg->family, filtered,
					   sizeof(filtered));
				snprintf(s.local_sdp, sizeof(s.local_sdp),
					 "%s", filtered);
				s.pool_posted = fan_local_sdp(&s);
				sig_post(s.sig, (const uint8_t *)s.local_sdp,
					 strlen(s.local_sdp));
				if (cfg->is_host && (cfg->sig_flags & SIG_DHT))
					sig_locate(s.sig);
				st = ST_SIGNAL;
			}
			break;
		case ST_SIGNAL:
			if (s.have_peer_sdp && !s.remote_set) {
				char ufrag[40];

				sdp_filter_peer(s.peer_sdp, cfg->family, filtered,
					   sizeof(filtered));
				if (nat_set_remote_description(s.c.nat, filtered)) {
					st = ST_FAIL;
					break;
				}
				sdp_ufrag(s.peer_sdp, ufrag);
				snprintf(s.c.remote_ufrag, sizeof(s.c.remote_ufrag),
					 "%s", ufrag);
				/* The claimant a single-connection host serves is
				 * the identity in the answer it takes up, as
				 * lan_drain and the turnstile record theirs. */
				if (cfg->is_host)
					snprintf(s.c.claim_ufrag,
						 sizeof(s.c.claim_ufrag), "%s",
						 ufrag);
				s.pool_posted = fan_local_sdp(&s);
							/* members learnt since
							 * the ST_GATHER post */
				sig_post(s.sig, (const uint8_t *)s.local_sdp,
					 strlen(s.local_sdp));
				s.remote_set = 1;
				s.ice_attempt_start = now_ms();
				if (o && o->peer &&
				    s.peer_state < SESSION_PEER_PUNCHING) {
					o->peer(o->arg, 0, SESSION_PEER_PUNCHING, "");
					s.peer_state = SESSION_PEER_PUNCHING;
				}
				st = ST_WAIT_ICE;
			}
			break;
		case ST_WAIT_ICE:
			/*
			 * ICE connecting does not mean this client is the one
			 * being served: until the host retires the agent it
			 * offered, it answers every claimant's checks with the
			 * credentials they all read, so a client that lost the
			 * round nominates a pair that belongs to the winner. Only
			 * a probe round-tripped under our own claimant identity
			 * settles that, and only the two rules below get a client
			 * that lost back into the running.
			 */
			claim_watch(&s.c);
			path_tick(&s.c, now_ms());
			if (offer_moved_on(&s.c)) {
				snprintf(s.regathered_for,
					 sizeof(s.regathered_for), "%s",
					 s.cur_offer_ufrag);
				dbg_logf("session: offer rotated past us -- "
					 "re-claiming against the current one");
				st = client_regather(&s) ? ST_FAIL : ST_GATHER;
				break;
			}
			if (path_probe_expired(&s.c)) {
				/*
				 * Nothing answered. On a busy host that means a
				 * turnstile round this client lost: its checks
				 * were answered by an agent serving somebody
				 * else, so re-entering here would only find the
				 * same pair still nominated.
				 */
				dbg_logf("session: claim taken up by another "
					 "peer -- re-claiming");
				st = client_regather(&s) ? ST_FAIL : ST_GATHER;
				break;
			}
			if (path_ready(&s.c)) {
				if (s.peer_state < SESSION_PEER_LIVE) {
					char loc[192], rem[192];

					s.c.status_peer[0] = '\0';
					if (nat_connected(s.c.nat) &&
					    !nat_selected(s.c.nat, loc, sizeof(loc),
							  rem, sizeof(rem))) {
						dbg_logf("client: ice connected "
							 "loc=[%s] rem=[%s]",
							 loc, rem);
						cand_addr(rem, s.c.status_peer,
							  sizeof(s.c.status_peer));
					}
					else
						conn_path_label(&s.c,
						  s.c.status_peer,
						  sizeof(s.c.status_peer));
					if (o && o->peer)
						o->peer(o->arg, 0,
							SESSION_PEER_LIVE,
							s.c.status_peer);
					s.peer_state = SESSION_PEER_LIVE;
				}
				st = ST_RUN;
				break;
			}
			if (nat_failed(s.c.nat) ||
			    now_ms() - s.ice_attempt_start > ICE_ATTEMPT_MS) {
				s.ice_attempt++;
				conn_drop_ice_path(&s.c);
				nat_destroy(s.c.nat);
				s.c.nat = NULL;
				if (nat_setup(&s.c))
					st = ST_FAIL;
				else
					st = ST_GATHER;
			}
			break;
		case ST_RUN: {
			int r;

			if (!s.established_fired) {
				if (o && o->established)
					o->established(o->arg);
				s.established_fired = 1;
			}
			r = run_ssh(&s);
			dbg_logf("session: run_ssh rc=%d", r);
			/* The host's connection just ended (the client left or was
			 * reaped); drop its dashboard row so the next serve does not
			 * stack a stale peer over the real one. */
			if (cfg->is_host && o && o->peer &&
			    s.peer_state >= SESSION_PEER_LIVE) {
				o->peer(o->arg, 0, SESSION_PEER_GONE,
					s.c.status_peer);
				s.peer_state = SESSION_PEER_SEEN;
			}
			if (r == 0) {
				st = ST_DONE;
			} else if (r == SSHC_RECONNECT) {
				/*
				 * The link stayed down past the grace window: rejoin
				 * as a fresh client -- a new ICE identity, a new
				 * punch and a new claim -- re-attaching to the session
				 * that lives on the host. netmon is not polled while
				 * the link is up, so this is where a move is first
				 * seen: rebuild the signalling on the new network
				 * before re-claiming, and keep the signalling as it is
				 * for a rejoin that is not a move (a host that went
				 * away and came back). Reset the deadline so the
				 * reconnect is not bounded by the original connect
				 * budget. conn_run has returned, so nothing is
				 * dispatching sig.
				 */
				dbg_logf("session: rejoin (roam)");
				deadline = now_ms() +
					(uint64_t)cfg->connect_timeout_s * 1000;
				if (net_changed(&s)) {
					s.stun_rotations = 0;
					s.have_priv4 = 0;
					s.have_srflx4 = 0;
					pthread_mutex_lock(&s.trickle_lock);
					s.npool4 = 0;
					stun_mapping_reset(&s.map4);
					pthread_mutex_unlock(&s.trickle_lock);
					s.pool_reported = 0;
					s.pool_posted = 0;
					s.mapping_reported = 0;
					stun_probe_kick(&s);
					if (o && o->net_reset)
						o->net_reset(o->arg);
					pthread_mutex_lock(&s.c.path_lock);
					path_table_clear(&s.c.paths);
					pthread_mutex_unlock(&s.c.path_lock);
					if (sig_rebuild(&s)) {
						st = ST_FAIL;
						break;
					}
				}
				st = client_regather(&s) ? ST_FAIL :
							   ST_GATHER;
			} else if (!cfg->is_host && now_ms() + 10000 < deadline) {
				/*
				 * The nominated pair never carried a session. It is
				 * not a host that is merely slow to serve: the SSH
				 * bring-up ran to its own timeout against it. The
				 * usual cause is a turnstile race this client lost,
				 * whose agent answers our checks while serving
				 * somebody else, so re-entering ST_WAIT_ICE would
				 * only find the same pair still "connected".
				 */
				dbg_logf("session: bring-up failed -- re-claiming");
				st = client_regather(&s) ? ST_FAIL : ST_GATHER;
			} else if (now_ms() + 10000 < deadline) {
				/* A host retries its own listener rather than
				 * re-gathering: the turnstile owns the offer. */
				st = ST_WAIT_ICE;
			} else {
				st = ST_FAIL;
			}
			break;
		}
		default:
			break;
		}
	}

	rc = (st == ST_DONE) ? 0 : 1;
done:
	if (s.c.stream)
		stream_destroy(s.c.stream);
	conn_drop_ice_path(&s.c);
	if (s.c.nat)
		nat_destroy(s.c.nat);
	if (s.lan)
		lanlink_destroy(s.lan);
	sig_destroy(s.sig);
	stun_probe_halt(&s);
	stunlist_free(s.stun_servers, s.stun_count);
	pthread_mutex_destroy(&s.trickle_lock);
	pthread_mutex_destroy(&s.c.status_lock);
	pthread_mutex_destroy(&s.c.hb_lock);
	pthread_mutex_destroy(&s.c.rdv_lock);
	pthread_mutex_destroy(&s.c.stream_lock);
	pthread_mutex_destroy(&s.c.path_lock);
	return rc;
}
