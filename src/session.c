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
#include "ctlplane.h"
#include "ctlproto.h"
#include "dbg.h"
#include "ccrypto.h"
#include "keys.h"
#include "lanlink.h"
#include "nat.h"
#include "netmon.h"
#include "netroute.h"
#include "netstate.h"
#include "obsemit.h"
#include "peering.h"
#include "claimlog.h"
#include "hbeat.h"
#include "hostreap.h"
#include "nsfacts.h"
#include "path.h"
#include "pathplane.h"
#include "probeplane.h"
#include "session.h"
#include "sig.h"
#include "sshbridge.h"
#include "sshc.h"
#include "sshd.h"
#include "stream.h"
#include "stunlist.h"
#include "stunprobe.h"
#include "tokgen.h"


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
 * The same for a host's punch at a claimant joining afresh, where the wait
 * costs somebody else. That punch holds the claimant's identity, and every
 * further claim from it is refused as already in flight -- so a client that
 * dies mid-punch, or gives up and comes back, is turned away for as long as
 * this lasts.
 *
 * Only the punch. Both ends stamp it where they set the peer's description, so
 * the mailbox exchange before it -- an offer being stored, a claim being
 * noticed, a convergent lookup for a token that named no node -- is outside
 * this and stays unbounded, as it must: how long the DHT takes is not ours to
 * predict. Once both hold each other's candidates the scale is a human one,
 * and a terminal session whose round trip nears ten seconds is unusable
 * however patient we are.
 *
 * A resumption is not this case and keeps the backstop above. The claimant is
 * a client already admitted, coming back after a move, so it is not competing
 * for admission with anyone -- and it is rebuilding its signalling and
 * re-gathering as it comes, which is exactly the slow, unpredictable path this
 * must not cut short.
 */
#define HOST_PUNCH_MS 15000
/*
 * How many punches for one claimant may be in flight at once. A returning
 * client's fresh attempt is launched alongside the running one, not in place
 * of it, so the ranking carries whichever connects; a low cap bounds the poll
 * threads and sockets one claimant can hold.
 */
#define PUNCH_PARALLEL_MAX 3
/*
 * The counter and tag the transport puts under every stream datagram, and the
 * wire budget they share with KCP: the stream is given the rest (stream.h), so
 * a datagram is no larger on the wire than it was without them.
 */
#if DATAAUTH_OVERHEAD != STREAM_OVERHEAD
#error "the stream's budget and the transport's framing must agree"
#endif
#if CTL_KEY_PLEN != KEYS_HALF_LEN
#error "the control message and the key schedule must agree on a half"
#endif

/* Between attempts to gather an offer worth publishing. Gathering costs an
 * agent and a round of STUN, and the thing being waited for -- an interface
 * finishing coming up after a move -- takes about this long anyway. */
#define HOST_REGATHER_MS 1000

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
/*
 * What a transport callback is told it belongs to. A connection can hold two
 * agents at once -- the one a resume is punching and the one it set aside --
 * and libjuice reports no source address with a datagram, so without this each
 * one's traffic would be credited to whichever agent is current.
 */
/*
 * A callback's way back to the connection it serves. The loop re-points c
 * when a punched agent is grafted onto another connection, while libjuice's
 * threads are reading it, so it is touched atomically at both ends. A
 * callback that loads the old value delivers one last frame to the previous
 * owner -- the behaviour nat_rebind already documents, and which the punch
 * shell being dissolved and the connection adopting it both tolerate. agent
 * is set when the context is made and never changes, so a context names its
 * agent for life.
 */
struct ice_ctx {
	struct conn *c;
	struct nat_agent *agent;
	/*
	 * The connection that lent this agent away and is waiting to be
	 * released. A callback that loaded c before it was re-pointed is still
	 * inside the old connection, so the lender cannot be freed on the spot
	 * -- nat_destroy is the only moment at which nothing can be inside the
	 * callbacks any more, and that is where it goes.
	 */
	struct conn *shell;
};

/* Agents this connection maintains beyond c->nat: a resume sets one aside
 * rather than destroy it, punches launch more in parallel, and the path
 * ranking decides which carries. Allocated as needed up to the ceiling. */
#define ICE_HOLD_MAX 16
struct ice_hold {
	struct nat_agent *agent;
	struct ice_ctx *ctx;
	uint64_t until_ms;	/* reaped once past this with nothing carrying it */
};

struct conn {
	struct sess *sess;		/* the session this connection belongs to */

	/* This connection's ICE identity. A fresh one per host offer (single-use
	 * per join, so two clients never share credentials); the client keeps its
	 * one identity for the session. */
	char ice_ufrag[16];
	char ice_pwd[40];
	/* The peer ICE identity that primed this agent. Candidate trickles from
	 * a rotated offer must not be sent to an agent for an older offer. */
	char remote_ufrag[40];
	char remote_pwd[40];		/* which attempt of that peer, so a later
					 * one can take this punch's place */
	uint32_t remote_gen;		/* the offer's network generation when it
					 * primed us: a higher one now is a move,
					 * not a mere pickup rotation */

	/*
	 * The three planes this connection peers through: what its probes and
	 * stream datagrams are sealed under, the paths that carry them, and the
	 * channel the pair talks over.
	 */
	struct peering pr;

	struct nat_agent *nat;
	struct ice_ctx *nat_ctx;
	/*
	 * Agents set aside rather than destroyed. Each path stays in the table
	 * and is probed like any other, so the ranking decides which carries;
	 * nothing promotes one, because a path already names the agent it sends
	 * through.
	 */
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
	 * The computations under the path plane's lock are the ranking, a
	 * handful of integer compares over at most PATH_TABLE_MAX entries, and
	 * the path id, a keyed digest over 36 bytes taken when an endpoint of
	 * the pair is learnt or changes.
	 */
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
	 * host, the turnstile hands the punched agent to the worker's own
	 * thread, under the contract below.
	 *
	 * WHO OWNS AN AGENT. A connection's agent and its context (c->nat and
	 * c->nat_ctx, which always move as a pair) belong to exactly one
	 * thread: the worker running conn_run for this connection if there is
	 * one, and the loop otherwise. The loop never writes them for a
	 * connection that has a worker; it hands over instead.
	 *
	 * HOW A HANDOVER IS PUBLISHED. One pointer, once. A context is bound
	 * for life to the agent it was created for (ice_ctx.agent), so naming
	 * the context names the agent, and the slot below is the whole of the
	 * handover -- publishing an agent and a context as two stores is how a
	 * worker came to see one of them and not the other. The loop re-points
	 * the context's connection and the agent's callback argument first and
	 * publishes the slot last, with release; the worker takes it with
	 * acquire, which is what makes those earlier stores visible to it.
	 *
	 * resume_pending counts the punches in flight resuming this worker; the
	 * reap is held off while any remains. It and the stamps below are written
	 * by the loop and read by the worker, so they are atomic: each is
	 * advisory, and a reader wants the latest count rather than a synchronised
	 * one.
	 */
	int rs_state;
	uint64_t rs_deadline;
	uint32_t rs_backoff;		/* the answer-wait between re-claims, from
					 * RESUME_FIRST_MS up to RESUME_ATTEMPT_MS */
	struct ice_ctx *resume_q[ICE_HOLD_MAX];	/* graft handoff queue; see above */
	volatile int resume_pending;
	uint64_t resume_last_ms;	/* host: when a resume punch last began,
					 * so a redelivered claim in the window
					 * between graft and first probe does
					 * not punch the same worker twice */
	struct conn *punch_resume;	/* host: the worker this punch resumes,
					 * NULL for a fresh admit; non-owning */
	uint64_t punch_start_ms;
	int punch_stuck;
	char punch_ufrag[40];		/* host: claimant id while punching;
					 * cleared at reap while the conn lives,
					 * so distinct from claim_ufrag */
	/* The claimant's ICE ufrag, carried for the worker's whole lifetime so the
	 * host recognises the same client arriving over the other transport. */
	/*
	 * The claimant identity this connection serves. Written by the loop
	 * when a claim is taken up and read by the transport receive thread on
	 * every probe, so claim_lock covers both -- held only long enough to
	 * copy the string, never across a call.
	 */
	char claim_ufrag[40];
	pthread_mutex_t claim_lock;
	volatile int ice_up;		/* the agent is connected, for readers
					 * that may not touch the agent */
	volatile uint32_t carry_epoch;	/* ++ on a qualified carry switch (roam) */
	int bh_done;			/* the test hook has fired once, so a
					 * lift does not re-arm it */

	sock_t ssh_fd;			/* the ssh thread's socketpair end */
	sock_t ssh_ctl_fd;		/* the ssh thread's comrade-ctl end */
	sock_t ctl_fd;			/* our end of the comrade-ctl socketpair */
	struct ctl_reframer ctl_rf;	/* reassembles ctl messages across reads */
	int ssh_cli_rc;
	/*
	 * The end of the shared session, said on the control channel. A host
	 * sends it once its tmux is gone; a client that has heard it knows the
	 * connection ended because there is nothing left to be connected to,
	 * which is the difference between offering a rejoin and refusing one.
	 */
	int bye_sent;			/* host: told this client */
	int shell_ended;		/* host: sshd's SSHD_END_* verdict, set on
					 * the ssh thread */
	int peer_ended;			/* client: was told the session ended */
	int end_verdict;		/* client: an end verdict arrived, read by
					 * the ssh thread's post-close wait */

	/*
	 * What the pair says to each other over the comrade-ctl channel, and
	 * how the link is faring: the key halves, the rendezvous nodes, the
	 * reachability, the requests, and the ping and pong a dead link is
	 * noticed by even when nobody is typing.
	 */
	/*
	 * The last link state and round trip reported to the view, and whether
	 * anything has been. Cleared whenever this connection's row is created,
	 * because a row that has just appeared has been told nothing -- and the
	 * report is only made when one of the two CHANGES, so a state believed
	 * already told is a row left showing whatever it had.
	 */
	int link_told, rtt_told, paths_told, link_told_any;

	/* This connection's status (data only; the view renders it). */
	pthread_mutex_t status_lock;
	struct conn_status status;
	char status_peer[80];		/* address of the chosen pair, once live */
	uint64_t next_status_ms;

	/* Read-only grade (host): the ssh thread sets it once the client has
	 * authenticated (which secret it used), the main loop reports it to the
	 * dashboard once. Written from the ssh thread, so volatile like done. */
	/* Set by the ssh server thread once it knows which credential
	 * the peer used, read by the loop that reports the peer's row. */
	volatile int read_only;
	int ro_reported;		/* main-thread only: sent to the view yet */
	int peer_fresh;			/* the host said it is serving us from a
					 * worker we were never part of; atomic,
					 * set by a worker, read by the main loop */
	volatile int fwd_refused;	/* forwards the ssh thread refused */
	int fwd_reported;		/* main-thread only: refusal surfaced yet */
};

struct sess {
	const struct session_cfg *cfg;

	uint8_t auth[TOKEN_AUTH_LEN];

	/*
	 * The key a claimant boxes its claim to, held here rather than by the
	 * signaller: a signaller is rebuilt on every move, and the claim a
	 * client had in flight when the host roamed is boxed to the old one.
	 */
	struct lanlink *lan;
	struct session_keys keys;	/* sig_key, for sealing transport probes */

	struct netmon netmon;		/* detect a roam while still waiting */
	uint64_t next_roam_ms;		/* next synthetic change (test_roam_ms) */
	int roams;			/* synthetic changes reported so far */

	char local_sdp[NAT_SDP_MAX];
	int have_local_sdp;
	/*
	 * The description libjuice hands back, staged for the loop. The
	 * callback runs on libjuice's thread while the loop is reading
	 * local_sdp and rewriting it (fan_local_sdp), so the two cannot share
	 * that buffer: the callback leaves the description here under
	 * trickle_lock and pool_pump takes it, which is the same shape as the
	 * candidates trickling in below. local_sdp and have_local_sdp are the
	 * loop's alone.
	 */
	char pending_sdp[NAT_SDP_MAX];
	int pending_sdp_set;
	/* Some peer, at some point, got all the way through the control
	 * handshake here. Written by whichever connection's thread sees the
	 * first pong; only ever set, so a stale read costs one round. */
	volatile int handshake_seen;
	/*
	 * Candidates as they trickle in (libjuice's gather thread appends here
	 * under trickle_lock; the main loop drains and reports them), so the local
	 * addresses show at once instead of waiting for gathering -- which can
	 * stall behind a slow STUN server -- to finish.
	 */
	char trickle_sdp[NAT_SDP_MAX];
	pthread_mutex_t trickle_lock;
	volatile int trickle_dirty;
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

	uint64_t next_gather_ms;	/* backoff after a gather found nothing */
	uint64_t ice_attempt_start;
	/* Which STUN server this attempt starts from. The loop advances it
	 * while a probe thread is indexing with it, so both ends are atomic
	 * and each thread takes one snapshot for the round it is running. */
	int ice_attempt;
	int expect4, expect6;		/* host has DHT reach on this family */
	int tok_state[2];
	uint8_t tok_ep[2][TOKEN_EP6_LEN];	/* client: the node last told,
						 * so an unchanged one is not
						 * re-encoded every round */
	uint16_t tok_port[2];		/* per family [0]=v4 [1]=v6, TOKEN_STATE_* */
	int tok_told[2];		/* the state has been reported at least once */
	int noconn_warned;		/* operator told no family can be advertised */
	uint64_t next_tok_ms;		/* throttle the per-family advert decision */

	uint64_t start_ms;		/* observer: session start, for escalation */
	int escalated;			/* observer: client warned of DHT warm */
	int peer_state;			/* observer: highest SESSION_PEER_* sent */
	int established_fired;		/* observer: established sent once */
	int was_live;			/* a path carried this session at some
					 * point; unlike established_fired it
					 * survives a re-gather, because what it
					 * answers is whether this client was
					 * ever in the shared session -- which
					 * decides whether an ended session is
					 * news or a spent invitation */
	int peer_ended;			/* client: the host said the shared
					 * session is over (control channel), or
					 * the mailbox carries its tombstone */
	int session_over;		/* host: the shared tmux is gone, so this
					 * invitation leads nowhere from now on */
	uint64_t tomb_deadline;		/* host: how long the end of the session
					 * is published for before we go */
	/* Set from libjuice's gather thread as candidates arrive and cleared
	 * by the loop on a regather, so every access is a relaxed atomic: the
	 * reader wants the latest answer, not a synchronised one. */
	volatile int have_priv4;	/* a private/CGNAT v4 host candidate (needs
					 * STUN); set from the gather thread */
	volatile int have_srflx4;	/* STUN gave us a public v4 (reflexive) */
	int stun_warned;		/* warned once that STUN produced nothing */
	uint64_t stun_since_ms;		/* current agent started gathering */
	int stun_rotations;		/* pool servers written off this network */

	char status_rdv[80];		/* located rendezvous endpoint (host side) */

	/*
	 * This session's side of its one mailbox: the reachability model, where
	 * it is served and what it can reach as told to every peer, and the
	 * standing requests its peers have made of it.
	 */
	struct peering_model pm;

	char **stun_servers;		/* rotated across ICE retries (host:port) */
	int stun_count;
	char stun_host[128];		/* the current attempt's host, split out */
	/*
	 * What belongs to this machine whichever peer it is talking to: the
	 * crossing its producer threads post through, the egress addresses its
	 * carrier maps it to, and the rounds that find them.
	 */
	struct peering_net net;
	pthread_t warm_th;		/* resolves the STUN pool into the cache */
	int warm_running;
	volatile int warm_stop;
	unsigned netgen;		/* bumped by any move; a path proven on an
					 * earlier one proves nothing here.
					 * The loop bumps it and the workers
					 * read it, so every access is atomic:
					 * it is only ever compared for
					 * equality, which needs no ordering
					 * against anything else. */
	int mapping_reported;		/* 0 not yet, 1 sent independent, 2 sent dependent */

	/*
	 * Reachability per family. Producers off this thread leave facts in the
	 * crossing; the loop feeds them in, so nothing outside it writes the
	 * model or reaches the view.
	 */
	struct netstate ns;
	unsigned net_ch;		/* families whose move the loop still owes
					 * its own teardown for */
	unsigned net_pending;		/* a move seen but not yet released to
					 * net_ch, held until a roam's burst of
					 * interface changes settles */
	uint64_t net_hold_ms;		/* release once quiet this long */
	/* The epoch each gather was started for, stamped by the loop before it
	 * starts and read by the gather thread as it reports. */
	volatile uint32_t gather_epoch[2];

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
	 * names -- and the budget that bounds what a stranger can make us open.
	 * Both belong to the thread that dispatches the shared
	 * lanlink socket, which is this one.
	 */
	struct conn *conns[HOST_MAX_WORKERS];
	struct path_adopt adopt;
	struct conn *punching[HOST_MAX_WORKERS];	/* in-flight ICE punches */
	char last_served_ufrag[40];
	struct claim_served served;	/* claimants this host has served */
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

/* Printable "addr:port" ("[v6]:port") for a sockaddr; empty on failure. */
/*
 * Our own listening endpoint: both ends of one session hold the same key, so a
 * probe sent there is answered by us and the path looks alive while carrying
 * nothing. Only this exact endpoint is refused -- our address on another port
 * is another process, which is what a peer sharing this machine looks like,
 * and what a peer that merely shares an address (a VM and its host under
 * passt) offers is left to fail its probes like any other dead path.
 *
 * An endpoint reaches the table from a peer that names one, from the source of
 * a sealed announcement and from the source of a probe, and a source is as
 * freely chosen as anything else in a datagram. The test is the same at each.
 */
/* An endpoint this node answers on itself: the shared socket is the session's,
 * so the question is asked of it and not of one connection. */
static int sess_ep_is_self(struct sess *s, const struct path_ep *ep)
{
	struct netmon_addr local[NETMON_MAX_ADDRS];

	if (!s->lan || ep->port != lanlink_port(s->lan))
		return 0;

	return cand_ep_is_local(ep->addr, local,
				netmon_snapshot(local, NETMON_MAX_ADDRS));
}

/*
 * WHAT THE PATH PLANE ASKS OF THIS PLAYBOOK.
 *
 * The plane owns the table, the probe cadence and the answers; the carriers
 * the probes ride, and which of them may carry right now, are this session's.
 * Each of these answers one such question for one connection.
 */

/* Whether an endpoint is one of this node's own, which would be a pair talking
 * to itself. */
static int conn_ep_is_self(void *arg, const struct path_ep *ep)
{
	struct conn *c = arg;

	return sess_ep_is_self(c->sess, ep);
}

/* How an endpoint on the shared lanlink socket is come by: one on the local
 * segment, or any other the same socket can reach. A description of the
 * endpoint and nothing more -- neither kind ranks above the other. */
static enum path_kind conn_ep_kind(void *arg, const struct path_ep *ep)
{
	struct in6_addr a6;
	struct in_addr a4;
	char host[64];

	(void)arg;
	if (path_ep_is_v4(ep)) {
		memcpy(&a4, ep->addr + 12, 4);
		if (!inet_ntop(AF_INET, &a4, host, sizeof(host)))
			return PATH_ROUTED;
	} else {
		memcpy(&a6, ep->addr, 16);
		if (!inet_ntop(AF_INET6, &a6, host, sizeof(host)))
			return PATH_ROUTED;
	}

	return net_addr_scope(host) == NET_SCOPE_LAN ? PATH_SEGMENT :
						       PATH_ROUTED;
}

/* The claimant identity, copied out under its lock. */
static void conn_ident(void *arg, char *out, size_t n)
{
	struct conn *c = arg;

	pthread_mutex_lock(&c->claim_lock);
	snprintf(out, n, "%s", c->claim_ufrag);
	pthread_mutex_unlock(&c->claim_lock);
}

/* Put a sealed probe on the carrier this path names. */
static void conn_probe_send(void *arg, enum path_kind kind,
			    struct nat_agent *agent,
			    const struct sockaddr_in6 *to, const uint8_t *b,
			    size_t n)
{
	struct conn *c = arg;

	if (kind == PATH_ICE) {
		if (agent)
			nat_send(agent, b, n);
	} else if (to && c->sess->lan) {
		lanlink_send(c->sess->lan, to, b, n);
	}
}

/*
 * The agents that can carry a datagram right now. Asked before the table is
 * locked, since an agent call may not be made under it.
 */
static int conn_live_agents(void *arg, struct nat_agent **live, int max)
{
	struct conn *c = arg;
	int n = 0, i;

	struct nat_agent *held[PATHPLANE_HOLD_MAX];
	int nheld;

	if (c->nat && nat_connected(c->nat) && n < max)
		live[n++] = c->nat;
	nheld = pathplane_holds_agents(&c->pr.pl, held, PATHPLANE_HOLD_MAX);
	for (i = 0; i < nheld && n < max; i++)
		if (nat_connected(held[i]))
			live[n++] = held[i];

	return n;
}

/*
 * The remote endpoint this agent has nominated. Kept out of the table lock: it
 * reaches into the agent, which formats the pair under its own lock, so it is
 * asked at the probe cadence rather than on every pass of a loop that turns a
 * hundred times a second.
 */
static int conn_ice_ep(void *arg, struct nat_agent *agent, struct path_ep *ep)
{
	char loc[192], rem[192];

	(void)arg;
	if (!agent || !nat_connected(agent))
		return -1;
	if (nat_selected(agent, loc, sizeof(loc), rem, sizeof(rem)))
		return -1;

	return cand_ep_parse(rem, ep);
}

/*
 * Something arrived that this end could make sense of. Liveness is the whole
 * traffic and not the pong alone -- a pong crosses the same queues as bulk
 * data and arrives late on a busy link -- but it has to be traffic that
 * authenticated: a datagram anyone can send is not evidence a peer is there,
 * and taking it as such lets a spoofed packet every couple of seconds hold a
 * dead session open, with the resume machinery never arming and the panel
 * reporting the link as live throughout.
 *
 * The unlocked read only coarsens the update to ~100ms; the store is what the
 * liveness verdict reads, and it is taken under the lock.
 */
static void conn_heard(void *arg, uint64_t now)
{
	struct conn *c = arg;

	ctlplane_heard(&c->pr.cp, now);
}

/* A path becoming usable is the moment to retransmit the stream's backlog,
 * whether the carry switched to it before it qualified (its srtt still zero
 * then) or it is the one already carrying. */
static void conn_carry_moved(void *arg)
{
	struct conn *c = arg;

	__atomic_add_fetch(&c->carry_epoch, 1, __ATOMIC_RELAXED);
}

/*
 * Tell the claimant that what it has reached is a new worker, not the one it
 * left. Only a client coming back has anything to do with this; one joining
 * for the first time has no session to lose and ignores it.
 */
static void conn_peer_fresh(void *arg, const struct path_probe *pr,
			    enum path_kind kind, int held)
{
	struct ctlplane_live live;
	struct conn *c = arg;

	(void)kind;
	if (pr->type != PROBE_FRESH || !held)
		return;
	ctlplane_liveness(&c->pr.cp, &live);
	/* A connection that never carried a session has none to be told about:
	 * this is the answer to a resume, and a first join is not one. */
	if (!live.pong_seen || c->sess->cfg->is_host ||
	    __atomic_load_n(&c->peer_fresh, __ATOMIC_RELAXED))
		return;
	__atomic_store_n(&c->peer_fresh, 1, __ATOMIC_RELAXED);
	dbg_logf("peer: served by a new worker -- this session is over, "
		 "rejoining");
}

/*
 * The connection itself. Only ever after nat_destroy has returned for any
 * agent whose callbacks could still name it -- see ice_ctx.shell.
 */
static void conn_release(struct conn *c)
{
	peering_destroy(&c->pr);
	pthread_mutex_destroy(&c->status_lock);
	pthread_mutex_destroy(&c->stream_lock);
	pthread_mutex_destroy(&c->claim_lock);
	free(c);
}

/*
 * Let one carrier's context go. Past nat_destroy nothing can be inside this
 * agent's callbacks, so a connection that lent it away can finally be given
 * back.
 */
static void conn_agent_free(void *arg, struct nat_agent *agent, void *ctxp)
{
	struct ice_ctx *ctx = ctxp;

	(void)arg;
	if (agent)
		nat_destroy(agent);
	if (ctx && ctx->shell)
		conn_release(ctx->shell);
	free(ctx);
}

static int conn_agent_failed(void *arg, struct nat_agent *agent)
{
	(void)arg;

	return nat_failed(agent);
}

static void conn_sinks(struct conn *c, struct pathplane_sinks *k)
{
	memset(k, 0, sizeof(*k));
	k->send = conn_probe_send;
	k->ident = conn_ident;
	k->live = conn_live_agents;
	k->ice_ep = conn_ice_ep;
	k->is_self = conn_ep_is_self;
	k->kind_of = conn_ep_kind;
	k->heard = conn_heard;
	k->qualified = conn_carry_moved;
	k->agent_free = conn_agent_free;
	k->agent_failed = conn_agent_failed;
	k->other = conn_peer_fresh;
	k->arg = c;
}

/* Enter one endpoint on the shared lanlink socket as a path, or find the path
 * already naming it; its printable form goes to label when one is asked for.
 * Returns 0 when the connection holds the path afterwards. */
static int conn_add_lan_path(struct conn *c, enum path_kind kind,
			     const struct sockaddr_in6 *remote,
			     char *label, size_t label_len)
{
	return peering_add_path(&c->pr, kind, remote, label, label_len,
				now_ms());
}

static void conn_add_ice_path(struct conn *c)
{
	pathplane_add_ice(&c->pr.pl, c->nat, now_ms());
}

static void conn_drop_ice_path(struct conn *c)
{
	pathplane_drop_ice(&c->pr.pl);
}

/* Every one of these is the path plane's, over the carriers it has set aside;
 * the sinks say how this session lets one go. */
static void conn_free_agent(struct conn *c, struct nat_agent *agent,
			    struct ice_ctx *ctx)
{
	struct pathplane_sinks k;

	conn_sinks(c, &k);
	pathplane_free_agent(&c->pr.pl, &k, agent, ctx);
}

static void conn_reap_holds(struct conn *c)
{
	struct pathplane_sinks k;

	conn_sinks(c, &k);
	pathplane_holds_free_all(&c->pr.pl, &k);
}

static void conn_hold_add(struct conn *c, struct nat_agent *agent,
			  struct ice_ctx *ctx, uint64_t until)
{
	struct pathplane_sinks k;

	conn_sinks(c, &k);
	pathplane_hold_add(&c->pr.pl, &k, agent, ctx, until);
}

static void conn_holds_gc(struct conn *c, uint64_t now)
{
	struct pathplane_sinks k;

	conn_sinks(c, &k);
	pathplane_holds_reap(&c->pr.pl, &k, now);
}

static void conn_route_dedup(struct conn *c)
{
	struct pathplane_sinks k;

	conn_sinks(c, &k);
	pathplane_route_dedup(&c->pr.pl, &k, c->nat);
}

/*
 * A resume replaces the agent, and the one being replaced is not known to be
 * dead: it stopped answering, which is also what a drop that ends in a moment
 * looks like. Set it aside with its path rather than destroy it, so the
 * ranking can find it alive and keep carrying on it -- a punch costs a round
 * trip to rebuild and its bindings may still be good. One is held at a time,
 * for as long as a claim gets.
 */
static void conn_park_ice(struct conn *c, uint64_t now)
{
	conn_reap_holds(c);
	conn_hold_add(c, c->nat, c->nat_ctx, now + RESUME_ATTEMPT_MS);
	c->nat = NULL;
	c->nat_ctx = NULL;
}

/* How many lanlink paths this connection holds; routable_only leaves out the
 * link-local endpoints a lanlink send cannot reliably reach. */
static int conn_lan_paths(struct conn *c, int routable_only)
{
	return pathplane_lan_paths(&c->pr.pl, routable_only);
}

/* Does this connection hold a lanlink path naming this endpoint? exact asks for
 * the whole endpoint; otherwise the lanlink port alone identifies the peer. */
static int conn_holds_ep(struct conn *c, const struct path_ep *ep, int exact)
{
	return pathplane_holds_ep(&c->pr.pl, ep, exact);
}

/* What a caller needs of the path carrying the session, copied out under the
 * lock so nothing reaches into the table without it. */
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
/*
 * Can this path's transport carry a datagram right now? A lanlink path always
 * can; an ICE path only while the agent that owns it holds a pair. Both agents
 * are asked before the table is locked, since an agent call may not be made
 * under it.
 */
static int conn_pick(struct conn *c, struct pathplane_pick *out)
{
	int rc = peering_pick(&c->pr, now_ms(), out);

	/*
	 * Published whether or not anything carries, and for the threads that
	 * may not touch the agent: it belongs to this connection's own thread,
	 * which destroys it on a resume graft, so a reader elsewhere holding
	 * the pointer holds freed memory. An int can only ever be a turn out
	 * of date, which is what a status line is anyway.
	 */
	c->ice_up = out->nlive > 0;
	/* A path becoming the one that carries is the moment to retransmit the
	 * stream's backlog. */
	if (out->moved && out->qualified)
		__atomic_add_fetch(&c->carry_epoch, 1, __ATOMIC_RELAXED);

	return rc;
}

/* The endpoint the session is on right now, printable (view). Empty for an ICE
 * path whose agent has not yet reported the pair it nominated, or for any
 * path -- an advertised candidate included -- nothing has actually answered
 * on yet: a claim is not evidence. */
static void conn_path_label(struct conn *c, char *out, size_t n)
{
	struct pathplane_pick pick;

	out[0] = '\0';
	if (!conn_pick(c, &pick) && pick.qualified)
		snprintf(out, n, "%s", pick.label);
}

/*
 * The round trip to show for this connection, and whether there is one to
 * show. It is the carrying path's, as its probes measured it on the wire, so
 * it is the figure ping would give; 0 there means under a millisecond rather
 * than unknown, the probes being timed in whole ones.
 *
 * The heartbeat's own figure stands in until a path has been probed, and only
 * then. That one crosses the control stream through KCP, which flushes on its
 * own interval at each end, so it reads tens of milliseconds on a link that
 * answers in under one -- fine for deciding a link has gone quiet, which is
 * what it is for, and misleading as a link's round trip.
 *
 * Reads the selection rather than running it, so any thread may ask.
 */
static int conn_rtt_ms(struct conn *c, int *out)
{
	struct ctlplane_live live;

	if (pathplane_carry_rtt(&c->pr.pl, out))
		return 1;
	ctlplane_liveness(&c->pr.cp, &live);
	*out = live.rtt_ms;
	/* The stream is the worker thread's to destroy, and it clears the
	 * pointer under this lock before doing so; every other thread reads it
	 * the same way or reads freed memory. */
	pthread_mutex_lock(&c->stream_lock);
	if (!*out && c->stream)
		*out = stream_rtt(c->stream);
	pthread_mutex_unlock(&c->stream_lock);
	return *out > 0;
}

/* How many distinct paths to this peer a probe has ever qualified. `qualified`
 * latches and never clears on silence, so this is the count of endpoints the
 * connection was actually proven on, stable as they later fall dead. */
static int conn_proven_paths(struct conn *c)
{
	return pathplane_proven(&c->pr.pl);
}

/* An endpoint the peer advertised over CTLM_CAND, entered as one more
 * candidate on the shared lanlink socket. Runs on the connection's own loop
 * thread. */
static void conn_offer_path(struct conn *c, const struct sockaddr *sa,
			    socklen_t len)
{
	struct sockaddr_in6 remote;

	if (lanlink_map_peer(sa, len, &remote))
		return;
	peering_offer_path(&c->pr, &remote, now_ms());
}

/*
 * Hand each local ICE candidate to the model, classified by scope and how it
 * was learnt. Re-run as they trickle in; the model de-duplicates.
 *
 * Stamped with the epoch the agent that gathered it was built under, never
 * the one current when the line is finally read -- they are routinely
 * different. A description gathered before a move is still in the trickle
 * buffer when the move lands, and stamping it with the network we are on now
 * makes it a fact about a place it was never seen: a public v6 learnt through
 * STUN on the last network survives onto one with no global v6 at all. The
 * round trips from this same agent already carry gather_epoch, so this was the
 * one thing left disagreeing with them.
 */
static void report_candidates(struct sess *s, const char *sdp)
{
	const char *p = sdp;

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
				int scope = net_addr_scope(addr);
				uint8_t raw[16];
				int len;

				fam = strchr(addr, ':') ? 6 : 4;
				if (fam == 4 && via == NET_VIA_STUN)
					__atomic_store_n(&s->have_srflx4, 1,
							 __ATOMIC_RELAXED);
				else if (fam == 4 && via == NET_VIA_DIRECT &&
					 scope != NET_SCOPE_GLOBAL)
					__atomic_store_n(&s->have_priv4, 1,
							 __ATOMIC_RELAXED);
				len = fam == 6 ? 16 : 4;
				if (inet_pton(fam == 6 ? AF_INET6 : AF_INET,
					      addr, raw) == 1)
					netstate_on_candidate(&s->pm.ns, fam,
							      __atomic_load_n(
							      &s->gather_epoch[fam_idx(fam)],
							      __ATOMIC_RELAXED),
							      scope, via, raw,
							      len, addr);
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
 * The rendezvous node for `family` (4 or 6), printable ("addr:port"). The
 * published one, so both families show once the in-band exchange has caught up;
 * fall back to whatever the token carried for that family. Called from each
 * connection's own thread, hence the lock.
 */
static void fmt_rdv_fam(struct sess *s, int family, char *out, size_t n)
{
	const struct token *t = &s->cfg->tok;
	struct peering_rdv r;
	char ip[64];

	pthread_mutex_lock(&s->pm.pub_lock);
	r = s->pm.rdv[fam_idx(family)];
	pthread_mutex_unlock(&s->pm.pub_lock);

	out[0] = '\0';
	if (r.have)
		peering_sockaddr_text((struct sockaddr *)&r.sa, r.len, out, n);
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
	struct ctlplane_live live;
	struct sess *s = c->sess;
	struct conn_status cs;

	memset(&cs, 0, sizeof(cs));
	cs.state = state;
	/* A view-only client marks its own status line; the host's operator is
	 * never view-only, so its status line (this same struct, via the tmpfs
	 * file) leaves it clear and marks read-only guests on the dashboard. */
	cs.read_only = !s->cfg->is_host &&
		       (s->cfg->tok.flags & TOKEN_FLAG_RO) != 0;
	/* Only the selected, proven path -- never a gathered candidate or an ICE
	 * pair that answered nothing -- so a roam updates it and a loss does not
	 * cycle it through the addresses being retried. */
	conn_path_label(c, cs.peer, sizeof(cs.peer));
	cs.nproven = conn_proven_paths(c);
	/* Both families, so a session that started on one can be seen to gain the
	 * other once the in-band rendezvous exchange propagates it. */
	fmt_rdv_fam(s, 4, cs.rdv, sizeof(cs.rdv));
	fmt_rdv_fam(s, 6, cs.rdv6, sizeof(cs.rdv6));
	/*
	 * The round trip is the path's, measured by the probes on the wire, so
	 * it is the same figure ping would give. The heartbeat's is not: it
	 * rides the control stream through KCP, which flushes on its own
	 * interval at each end and adds tens of milliseconds to a link that
	 * answers in one. It stands in only while no path has been probed yet,
	 * where a figure that is too high beats none at all. Report how long a
	 * loss has lasted.
	 */
	cs.rtt_known = conn_rtt_ms(c, &cs.rtt_ms);
	ctlplane_liveness(&c->pr.cp, &live);
	if (state == CONN_LOST && live.lost_since_ms)
		cs.since_s = (int)((now_ms() - live.lost_since_ms) / 1000);
	cs.silent_s = live.pong_seen ?
		(int)((now_ms() - live.last_pong_ms) / 1000) : -1;
	cs.gone = __atomic_load_n(&c->peer_fresh, __ATOMIC_RELAXED);

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
	uint8_t pool[PEERING_POOL4_MAX][4];
	int n, moves;

	n = peering_pool_copy(&s->net.pool, pool);
	/*
	 * A dependent mapping is the case this exists for, not a reason to skip
	 * it: a carrier handing out an egress address per destination is
	 * exactly why naming one of them is a guess. What the fan cannot
	 * survive is the PORT moving too, since it names the pool's addresses
	 * against this description's own reflexive port, so that, and only
	 * that, calls it off.
	 */
	moves = !peering_pool_port_stable(&s->net.pool);
	if (n >= 2)
		cand_sdp_fan_v4(s->local_sdp, sizeof(s->local_sdp), pool,
				(size_t)n, moves);
	return n;
}

/*
 * Members the probe found since the last pass: put them on the dashboard the
 * moment they are known, widen the posted description with them and post
 * again. The peer treats the re-post as a candidate trickle for the agent it
 * already primed (on_peer_offer feeds a repeat straight in), so a punch in
 * flight only gains targets, and a claimant that has not read the mailbox yet
 * finds the wider set waiting.
 *
 * Whenever the pool grows, not only while nobody has answered. How long a
 * carrier takes to show all of its egress addresses is not ours to know, so
 * the ones that arrive late are exactly the ones a peer would otherwise never
 * be told about -- and being unable to punch to the address the NAT picked
 * for that peer is how a link fails outright. Only our own slot is written
 * (sig_post, not sig_rotate), so the turnstile's answer slot is untouched and
 * the credentials do not change.
 */

/*
 * "v6 direct": a host reaches its own global v6 at the address the kernel
 * sources outbound from, which we learn without STUN via net_source_addr.
 * That is the privacy (temporary) address where RFC 4941 is enabled and
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
		    net_addr_scope(addr) == NET_SCOPE_GLOBAL) {
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

/*
 * What went into the offer a peer is about to read.
 *
 * An offer with nothing in it a peer could reach looks, from this end, exactly
 * like one that works: the host publishes, the client claims, the punch is made
 * and simply never connects. Behind a carrier NAT the difference is one
 * candidate -- whether STUN answered before the offer went out -- and there was
 * no way to tell the two apart from a log.
 *
 * Reflexive is counted rather than "reachable", because the two are not the
 * same: a globally routable IPv6 host candidate needs no STUN and is reachable
 * with none, so on a v6 network a count of zero here is the ordinary case and
 * says nothing is wrong.
 */
static void log_offer(const char *sdp, int served, int active)
{
	const char *p;
	int cands = 0, reflexive = 0;

	for (p = sdp; (p = strstr(p, "a=candidate:")) != NULL; p += 12) {
		const char *end = strchr(p, '\n');
		const char *t = strstr(p, "typ ");

		cands++;
		if (!t || (end && t > end))
			continue;
		if (!strncmp(t, "typ srflx", 9) ||
		    !strncmp(t, "typ prflx", 9) ||
		    !strncmp(t, "typ relay", 9))
			reflexive++;
	}
	if (served < 0)
		dbg_logf("host: offer re-posted, fanned across %d egress "
			 "address(es): %d candidate(s), %d reflexive",
			 active, cands, reflexive);
	else
		dbg_logf("host: offer published (served=%d active=%d) "
			 "%d candidate(s), %d reflexive",
			 served, active, cands, reflexive);
}

/*
 * Whether the description libjuice produced is in hand, taking it out of the
 * staging buffer first if it is waiting there.
 *
 * The callback that produces it runs on libjuice's thread and can leave one at
 * any moment, so every reader has to look -- not just the one in the loop that
 * posts it. Reading it anywhere else would see the description a whole
 * iteration late, and a caller that gathers and then immediately asks whether
 * it may post would see "not yet" and never post at all.
 */
static int sdp_ready(struct sess *s)
{
	char raw[NAT_SDP_MAX];
	int staged;

	pthread_mutex_lock(&s->trickle_lock);
	staged = s->pending_sdp_set;
	if (staged) {
		memcpy(raw, s->pending_sdp, sizeof(raw));
		s->pending_sdp_set = 0;
	}
	pthread_mutex_unlock(&s->trickle_lock);
	if (staged) {
		canon_v6(raw, netstate_src_text(&s->pm.ns, 6), s->local_sdp,
			 sizeof(s->local_sdp));
		s->have_local_sdp = 1;
	}
	return s->have_local_sdp;
}

static void pool_pump(struct sess *s)
{
	const struct session_obs *o = s->cfg->obs;
	uint8_t pool[PEERING_POOL4_MAX][4];
	int n, i, st, rep;

	n = peering_pool_copy(&s->net.pool, pool);
	st = peering_pool_mapping(&s->net.pool);
	for (i = s->net.pool.reported; i < n; i++) {
		char ip[64];

		if (inet_ntop(AF_INET, pool[i], ip, sizeof(ip)))
			netstate_on_candidate(&s->pm.ns, 4,
					      netstate_epoch(&s->pm.ns, 4),
					      net_addr_scope(ip), NET_VIA_STUN,
					      pool[i], 4, ip);
	}
	s->net.pool.reported = n;
	if (st != STUN_MAPPING_UNKNOWN) {
		rep = st == STUN_MAPPING_DEPENDENT ? 2 : 1;
		if (rep != s->mapping_reported) {
			s->mapping_reported = rep;
			if (o && o->mapping4)
				o->mapping4(o->arg, rep == 2);
		}
	}
	if (sdp_ready(s) && n >= 2 && n > s->net.pool.posted) {
		s->net.pool.posted = fan_local_sdp(s);
		sig_set_claim_offer(s->pm.sig, s->c.remote_ufrag);
		sig_post(s->pm.sig, (const uint8_t *)s->local_sdp,
			 strlen(s->local_sdp));
		/* The fan is the whole answer to a carrier that picks a
		 * different egress address per destination, and it reaches a
		 * peer only through this re-post -- which is not the publish
		 * the offer log reports, so without this the one thing that
		 * makes such a network work is invisible. */
		log_offer(s->local_sdp, -1, n);
	}
}

/* Re-post the offer with the candidates libjuice gathered since it was first
 * published: a late srflx otherwise reaches only the dashboard, never the peer's
 * mailbox (fan_local_sdp re-posts the prober's pool, not libjuice's own). */
static void offer_refresh(struct sess *s)
{
	char raw[NAT_SDP_MAX];
	char filtered[NAT_SDP_MAX];

	/* The host's listener only: the client's own claim slot is posted by the
	 * resume machinery, and re-posting it from here races that. */
	if (!s->pm.sig || !s->offer_conn || s->offer_conn == &s->c ||
	    !s->offer_conn->nat)
		return;
	if (nat_local_description(s->offer_conn->nat, raw, sizeof(raw)))
		return;
	pthread_mutex_lock(&s->trickle_lock);
	snprintf(s->pending_sdp, sizeof(s->pending_sdp), "%s", raw);
	s->pending_sdp_set = 1;
	pthread_mutex_unlock(&s->trickle_lock);
	if (!sdp_ready(s))
		return;
	sdp_filter(s->local_sdp, s->cfg->family, filtered, sizeof(filtered));
	snprintf(s->local_sdp, sizeof(s->local_sdp), "%s", filtered);
	fan_local_sdp(s);
	sig_post(s->pm.sig, (const uint8_t *)s->local_sdp, strlen(s->local_sdp));
}

/* A late local candidate reached the model: re-post it to the mailbox (so the
 * peer sees what was gathered, not just the dashboard) and show it locally.
 * repost is set only once an offer is live (TS_WAIT_CLAIM), so a re-post never
 * outruns the turnstile's gated first publish. */
static void trickle_flush(struct sess *s, const struct session_obs *o, int repost)
{
	char buf[NAT_SDP_MAX];

	if (!__atomic_load_n(&s->trickle_dirty, __ATOMIC_RELAXED))
		return;
	pthread_mutex_lock(&s->trickle_lock);
	memcpy(buf, s->trickle_sdp, sizeof(buf));
	s->trickle_sdp[0] = '\0';
	__atomic_store_n(&s->trickle_dirty, 0, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&s->trickle_lock);
	if (repost)
		offer_refresh(s);
	if (o && o->net)
		report_candidates(s, buf);
}

/*
 * Like sdp_filter(), for a peer's SDP.
 *
 * A candidate naming one of our own addresses is kept. ICE checks carry
 * credentials, so one aimed at ourselves reaches an agent expecting a
 * different username and the pair fails on its own; and two peers that really
 * are on one machine -- a VM and its host under passt, both ends of a test --
 * have no other address to meet at. The transport that must not take a peer
 * at its word is the segment one, and the rule lives there (conn_offer_path).
 */
static void sdp_filter_peer(const char *in, int family, char *out, size_t outlen)
{
	sdp_filter(in, family, out, outlen);
}

/*
 * The rendezvous node a fresh sig should be seeded with for `family`: the
 * anchor the model holds, whether this end found it or the peer handed it over
 * the control channel; the token's slot only where the model has none, since a
 * token minted long ago can name a node that has since gone. Returns 0 and
 * fills sa/len, -1 when neither has one for this family.
 */
static int seed_node_for(struct sess *s, int family, struct sockaddr_storage *sa,
			 socklen_t *len)
{
	const struct token *t = &s->cfg->tok;
	uint8_t node[NETSTATE_SA_MAX], nlen = 0;

	if (netstate_anchor(&s->pm.ns, family, node, &nlen, NULL) && nlen) {
		memcpy(sa, node, nlen);
		*len = nlen;
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
	int i;

	for (i = 0; i < 2; i++) {
		struct sockaddr_storage sa;
		socklen_t sl = 0;

		if (seed_node_for(s, famv[i], &sa, &sl))
			continue;
		if (s->cfg->is_host)
			sig_reinforce(s->pm.sig, famv[i], (struct sockaddr *)&sa,
				      sl);
		else if (sig_seed_node(s->pm.sig, (struct sockaddr *)&sa, sl))
			continue;
		/* Adopted, not confirmed: whoever minted this node did so on
		 * another network, and report_rendezvous says so until it has
		 * answered here. */
		netstate_on_rdv_offered(&s->pm.ns, famv[i], (const uint8_t *)&sa,
					(int)sl, now_ms());
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


static void on_local_sdp(void *arg, const char *sdp)
{
	struct conn *cc = __atomic_load_n(&((struct ice_ctx *)arg)->c,
					  __ATOMIC_ACQUIRE);
	struct sess *s = cc->sess;

	/*
	 * Staged exactly as libjuice gave it. Canonicalising here would mean
	 * reading netstate from this thread, and a callback thread owns none
	 * of the model -- the loop was writing the same source address
	 * through netstate_on_src while this read it. The loop canonicalises
	 * when it takes the description, where it owns both sides.
	 */
	pthread_mutex_lock(&s->trickle_lock);
	snprintf(s->pending_sdp, sizeof(s->pending_sdp), "%s", sdp);
	s->pending_sdp_set = 1;
	pthread_mutex_unlock(&s->trickle_lock);
}

/* Leave a fact for the loop: called from threads that own none of the model,
 * sig or the view. */
static void ns_post(struct sess *s, int kind, int family, uint32_t epoch)
{
	peering_facts_post(&s->net.facts, kind, family, epoch);
}

/* One more public v4 the carrier has been seen mapping us to, from the gather
 * thread; the probe round notes its own. */
static void pool_note(struct sess *s, const uint8_t b[4])
{
	int added = peering_pool_note(&s->net.pool, b);

	if (added)
		dbg_logf("stun: egress +%u.%u.%u.%u (pool now %d)",
			 b[0], b[1], b[2], b[3], added);
}

/* libjuice gather thread: a candidate is ready. Append it for the main loop,
 * and note the v4 facts the STUN watchdog runs on -- here rather than in the
 * observer report, which not every caller wires up. */
static void on_ice_candidate(void *arg, const char *cand)
{
	struct conn *cc = __atomic_load_n(&((struct ice_ctx *)arg)->c,
					  __ATOMIC_ACQUIRE);
	struct sess *s = cc->sess;
	size_t used, room, n = strlen(cand);
	const char *p = strstr(cand, "candidate:");
	char addr[64], typ[16];

	if (p && sscanf(p, "candidate:%*s %*d %*s %*u %63s %*d typ %15s",
			addr, typ) == 2) {
		if (strchr(addr, ':')) {
			if (!strcmp(typ, "srflx"))	/* a real v6 STUN reply */
				ns_post(s, NSF_ROUNDTRIP, 6,
					__atomic_load_n(&s->gather_epoch[1],
							__ATOMIC_RELAXED));
		} else if (!strcmp(typ, "srflx")) {
			uint8_t b[4];

			__atomic_store_n(&s->have_srflx4, 1, __ATOMIC_RELAXED);
			ns_post(s, NSF_ROUNDTRIP, 4,
				__atomic_load_n(&s->gather_epoch[0],
						__ATOMIC_RELAXED));
			if (inet_pton(AF_INET, addr, b) == 1)
				pool_note(s, b);
		} else if (!strcmp(typ, "host") &&
			   net_addr_scope(addr) != NET_SCOPE_GLOBAL) {
			__atomic_store_n(&s->have_priv4, 1, __ATOMIC_RELAXED);
		}
	}
	pthread_mutex_lock(&s->trickle_lock);
	used = strlen(s->trickle_sdp);
	room = sizeof(s->trickle_sdp) - used - 1;
	if (n + 1 <= room) {
		memcpy(s->trickle_sdp + used, cand, n);
		s->trickle_sdp[used + n] = '\n';
		s->trickle_sdp[used + n + 1] = '\0';
		__atomic_store_n(&s->trickle_dirty, 1, __ATOMIC_RELAXED);
	}
	pthread_mutex_unlock(&s->trickle_lock);
}


/* Send over whichever transport carries the stream right now, under a counter
 * and a tag that say this end sent it. */
static int transport_send(struct conn *c, const uint8_t *data, size_t len)
{
	struct sess *s = c->sess;
	uint8_t buf[STREAM_MTU];
	struct pathplane_pick pick;
	size_t n;

	n = probeplane_wrap(&c->pr.pp, buf, sizeof(buf), data, len);
	if (!n)
		return -1;
	if (conn_pick(c, &pick))
		return -1;
	if (pick.blackholed)
		return 0;
	if (pick.kind == PATH_ICE)
		return pick.agent ? nat_send(pick.agent, buf, n) : -1;
	return s->lan ? lanlink_send(s->lan, &pick.remote, buf, n) : -1;
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
static void conn_ctl_send(void *arg, int type, const uint8_t *payload,
			  size_t plen)
{
	uint8_t buf[CTL_FRAME_MAX];
	struct conn *c = arg;
	size_t n;
	ssize_t w;

	n = ctl_frame(buf, type, payload, plen);
	if (!sock_valid(c->ctl_fd) || !n)
		return;
	w = send(c->ctl_fd, (const char *)buf, (int)n, MSG_NOSIGNAL);
	(void)w;
}

/* Whether this ping is answered: the test hook lets a link go quiet on
 * purpose. */
static int conn_answer_ping(void *arg)
{
	struct conn *c = arg;

	if (c->sess->cfg->test_drop_pong && c->pongs_sent >= 2)
		return 0;
	c->pongs_sent++;

	return 1;
}

/* A pong came back, so a pair has spoken here at least once. */
static void conn_pong_seen(void *arg)
{
	struct conn *c = arg;

	__atomic_store_n(&c->sess->handshake_seen, 1, __ATOMIC_RELAXED);
}

static void conn_ctl_offer_path(void *arg, const struct sockaddr *sa,
				socklen_t len)
{
	conn_offer_path(arg, sa, len);
}

/*
 * What the control plane carries that is about the shared session rather than
 * about the pair: the two statements the host makes about the session ending.
 */
static void conn_ctl_other(void *arg, int type, const uint8_t *pl, size_t plen)
{
	struct conn *c = arg;

	(void)pl;
	(void)plen;
	if (type == CTLM_BYE) {
		/*
		 * The host's shared session has ended. It arrives inside the
		 * SSH session, so it is the one statement about the end that
		 * cannot be forged, and it beats the mailbox tombstone by the
		 * time a store takes. Recorded on the session as well as the
		 * connection: what it changes is whether this client rejoins,
		 * and that decision outlives this connection.
		 */
		dbg_logf("ctl: the host says the shared session has ended");
		c->peer_ended = 1;
		c->sess->peer_ended = 1;
		__atomic_store_n(&c->end_verdict, 1, __ATOMIC_RELAXED);
	} else if (type == CTLM_DETACHED) {
		/* The attach ended but the session lives, so the rejoin on
		 * offer is a real one. The verdict releases the client's
		 * post-close wait; that no peer_ended came with it keeps the
		 * rejoin. */
		dbg_logf("ctl: the host says we detached; the session lives");
		__atomic_store_n(&c->end_verdict, 1, __ATOMIC_RELAXED);
	}
}

/* Whether the comrade-ctl channel exists yet: a frame written into one that
 * does not is dropped, and a half spent that way is spent for nothing. */
static int conn_ctl_ready(void *arg)
{
	struct conn *c = arg;

	return sock_valid(c->ctl_fd);
}

static void conn_ctl_sinks(struct conn *c, struct ctlplane_sinks *k)
{
	memset(k, 0, sizeof(*k));
	k->send = conn_ctl_send;
	k->offer_path = conn_ctl_offer_path;
	k->answer_ping = conn_answer_ping;
	k->ready = conn_ctl_ready;
	k->pong = conn_pong_seen;
	k->other = conn_ctl_other;
	k->arg = c;
}

/*
 * What this session does for one peer, set as the peer is built: a path is
 * entered and a probe arrives before the connection ever runs, so this cannot
 * wait for the loop.
 */
static void conn_peering_sinks(struct conn *c)
{
	struct pathplane_sinks pk;
	struct ctlplane_sinks ck;

	conn_sinks(c, &pk);
	conn_ctl_sinks(c, &ck);
	peering_sinks(&c->pr, &pk, &ck);
}

/* Act on one decoded control message (a ctl_reframer callback). Runs on the
 * connection's own loop thread, the same one as the probe cadence. */
static void ctl_dispatch(void *arg, int type, const uint8_t *pl, size_t plen)
{
	struct ctlplane_sinks k;
	struct conn *c = arg;

	conn_ctl_sinks(c, &k);
	ctlplane_on_msg(&c->pr.cp, &k, type, pl, plen,
			__atomic_load_n(&c->sess->netgen, __ATOMIC_RELAXED),
			now_ms());
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
	char mine[40];

	conn_ident(c, mine, sizeof(mine));

	return probeplane_seal(&c->pr.pp, pr, mine, out, PROBE_MAX);
}


/*
 * The path a frame arrived on: the agent for ICE, which reports no source, and
 * the source endpoint for the lanlink kinds. NULL when this end holds no path
 * naming it -- not an error, only a source it has nothing to say about yet.
 * Called with path_lock held.
 */
/*
 * Tell the claimant that what it has reached is a new worker, not the one it
 * left. Only a client coming back has anything to do with this; one joining
 * for the first time has no session to lose and ignores it. Sealed and
 * addressed to its own claimant identity like any other probe.
 *
 * On whichever transport is about to carry it: a punched connection has an
 * agent, and one admitted over the segment has only the endpoint it announced
 * itself from, which the caller has to hand. Roaming is how a segment path
 * ends -- one end leaves the segment the other is on -- so a client that comes
 * back to a host over the segment is in exactly the position this is for.
 */
static void conn_tell_fresh(struct conn *c, const struct sockaddr_in6 *lan_to)
{
	struct sess *s = c->sess;
	struct path_probe pr;
	uint8_t out[PROBE_MAX];
	size_t o;

	if (!c->claim_ufrag[0])
		return;
	memset(&pr, 0, sizeof(pr));
	pr.type = PROBE_FRESH;
	random_bytes((uint8_t *)&pr.nonce, sizeof(pr.nonce));
	snprintf(pr.ufrag, sizeof(pr.ufrag), "%s", c->claim_ufrag);
	/*
	 * Carry the tail every other type carries, though nothing reads it
	 * here. Without it this frame is the only short one on the wire, so
	 * the one datagram that ends a session announces itself by its length
	 * to anyone counting bytes -- and dropping exactly those is cheaper
	 * for an adversary than dropping anything else.
	 */
	pr.have_tail = 1;
	o = conn_probe_seal(c, &pr, out);
	if (!o)
		return;
	if (c->nat)
		nat_send(c->nat, out, o);
	else if (lan_to && s->lan)
		lanlink_send(s->lan, lan_to, out, o);
}

/* Unseal a probe and act on it, if it names the claimant this connection
 * serves. Anything else is dropped in silence. */
static void probe_recv(struct conn *c, const uint8_t *data, size_t len,
		       enum path_kind kind, const struct sockaddr_in6 *src,
		       struct nat_agent *agent)
{
	peering_recv(&c->pr, data, len, kind, src, agent, now_ms());
}

/*
 * May this datagram be opened? Only a frame opening with this session's probe
 * tag is a candidate for adoption at all; anything else is stream data, which
 * ikcp_input rejects for the cost of one compare. A probe from a source one of
 * `c`'s paths already names is ordinary traffic, and one from any other source
 * is admitted to the seal only while the budget has a token. c may be NULL,
 * which is a source no connection at all is known to hold.
 */
static int probe_gate(struct sess *s, struct conn *c, const struct path_ep *ep,
		      const uint8_t *data, size_t len)
{
	return pathplane_gate(c ? &c->pr.pl : NULL, &s->adopt,
			      s->keys.probe_magic, ep, data, len, now_ms());
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
	int i;

	/*
	 * Each connection has its own key once it has bound one, so which
	 * connection a frame belongs to is answered by which key opens it --
	 * the ufrag inside then has to agree. A worker that has bound will not
	 * open a frame meant for another, which is the point of binding.
	 */
	for (i = 0; i < HOST_MAX_WORKERS; i++) {
		struct conn *c = s->conns[i];

		if (!c)
			continue;
		if (!peering_claims(&c->pr, data, len, PATH_SEGMENT, src,
				    now_ms()))
			continue;
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
				const struct sockaddr_in6 *src,
				struct nat_agent *agent)
{
	uint64_t now = now_ms();
	int took = 0;

	if (pathplane_muted(&c->pr.pl))
				/* a staged total outage swallows receives */
		return;
	if (pathplane_is_probe(&c->pr.pl, data, len)) {
		probe_recv(c, data, len, kind, src, agent);
		return;
	}
	if (probeplane_unwrap(&c->pr.pp, data, &len))
		return;
	pthread_mutex_lock(&c->stream_lock);
	if (c->stream)
		took = stream_input(c->stream, data, len) >= 0;
	pthread_mutex_unlock(&c->stream_lock);
	if (took)
		conn_heard(c, now);
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
	if (c->sess->cfg->is_host)
		return conn_lan_paths(c, 0) > 0 ||
		       (c->nat && nat_connected(c->nat));

	return pathplane_any_qualified(&c->pr.pl);
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
	/* A higher generation than primed us is a move, not a pickup rotation:
	 * the offer's candidates are new, so re-claim at once with no floor. */
	if (sig_peer_gen(s->pm.sig) > c->remote_gen)
		return strcmp(s->cur_offer_ufrag, s->regathered_for) != 0;
	/* The long floor is only for a client being punched, whose claim was
	 * taken up; one never picked up, never in the slot or queued over by a
	 * rival, re-claims on the short floor, not a punch window it is not in. */
	if (now_ms() - s->ice_attempt_start <=
	    (uint64_t)((c->claim_lost || !c->claim_held_seen) ?
		       PATH_LOST_MS : PATH_PROBE_MS))
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
	st = sig_claim_status(c->sess->pm.sig);
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
	struct ice_ctx *x = arg;
	struct conn *cc = __atomic_load_n(&x->c, __ATOMIC_ACQUIRE);

	deliver_stream_from(cc, data, len, PATH_ICE, NULL, x->agent);
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
	/*
	 * A probe brings its own proof and may arrive from an address this
	 * connection has never held -- that is how the peer's other address is
	 * picked up. Stream data may not: it is accepted from an endpoint we
	 * hold, or the socket is open to anyone who can reach the port.
	 */
	if (!path_probe_is(c->sess->keys.probe_magic, data, len) && !conn_holds_ep(c, &ep, 1))
		return;
	deliver_stream_from(c, data, len, PATH_SEGMENT, &mapped, NULL);
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
 * two clients that happen to share a lanlink port are told apart.
 *
 * `by_port` then allows the port alone, which is how the same peer heard from
 * a second address of its own is folded into the one connection rather than
 * admitted twice. That is a claim about identity made by nothing but a source
 * port, so it is offered only where the datagram carries its own proof: a
 * sealed probe. Stream data is taken from an endpoint we hold outright or not
 * at all, since a stranger may choose its source port as freely as anything
 * else it puts in a datagram.
 *
 * Host main thread.
 */
static struct conn *ep_owner(struct conn *const *tab, const struct path_ep *ep,
			     int by_port)
{
	int i, exact;

	for (exact = 1; exact >= (by_port ? 0 : 1); exact--)
		for (i = 0; i < HOST_MAX_WORKERS; i++)
			if (tab[i] && conn_holds_ep(tab[i], ep, exact))
				return tab[i];
	return NULL;
}

/* Which LAN worker holds this endpoint? Admission asks this: an endpoint being
 * served over the segment is not a fresh claimant. Host main thread. */
static struct conn *lan_owner(struct sess *s, const struct path_ep *ep)
{
	return ep_owner(s->lan_conns, ep, 1);
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
/*
 * The password of the claim, which is what separates a claimant trying again
 * from the DHT handing us its previous try a second time. The ufrag is the
 * claimant's identity and is deliberately kept across a resumption, so it
 * cannot tell the two apart; the password is minted fresh for every attempt
 * (conn_fresh_pwd) precisely so an unchanged claim is recognisable as one.
 */
static void sdp_pwd(const char *sdp, char *out)
{
	const char *p = strstr(sdp, "ice-pwd:");

	out[0] = '\0';
	if (p)
		sscanf(p, "ice-pwd:%39s", out);
}

static int conn_is_lost(struct conn *c)
{
	int lost;

	lost = ctlplane_lost(&c->pr.cp);
	return lost;
}

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
		if (s->punching[i] &&
		    !strcmp(s->punching[i]->punch_ufrag, ufrag))
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
	cand_sdp_ufrag(claim_sdp, ufrag, sizeof(ufrag));
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
		cand_sdp_ufrag(s->peer_sdp, queued, sizeof(queued));
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
	c = ep_owner(s->conns, &ep, path_probe_is(s->keys.probe_magic, data, len));
	if (!probe_gate(s, c, &ep, data, len))
		return;
	if (c)
		deliver_stream_from(c, data, len, PATH_SEGMENT, &mapped, NULL);
	else if (path_probe_is(s->keys.probe_magic, data, len))
		probe_adopt(s, data, len, &mapped);
}

/* Trickle the peer's latest candidates into an agent still punching; same
 * credentials let libjuice add the new lines and ignore repeats. Skipped once
 * connected, when redelivered dups only churn the candidate table. */
static void conn_amend_remote(struct conn *c, struct sess *s)
{
	char filtered[NAT_SDP_MAX];

	if (!c || !c->nat || nat_connected(c->nat))
		return;
	sdp_filter_peer(s->peer_sdp, s->cfg->family, filtered,
			sizeof(filtered));
	nat_set_remote_description(c->nat, filtered);
}

/* True when a freshly-seen offer names a different peer identity than the one
 * this end primed against: a rotation or a move, not the primed offer's own
 * later candidates. */
static int offer_rotated(const char *primed_ufrag, const char *offer_ufrag)
{
	return primed_ufrag[0] && strcmp(offer_ufrag, primed_ufrag) != 0;
}

static void on_peer_offer(void *arg, const uint8_t *data, size_t len)
{
	struct sess *s = arg;
	struct conn *c = s->offer_conn;
	char incoming[NAT_SDP_MAX];
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
	cand_sdp_ufrag(incoming, ufrag, sizeof(ufrag));
	snprintf(s->cur_offer_ufrag, sizeof(s->cur_offer_ufrag), "%s", ufrag);
	if (offer_rotated(c->remote_ufrag, ufrag)) {
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
	 * a time); feed them into the already-primed agent. */
	if (s->remote_set)
		conn_amend_remote(c, s);
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

/* A fresh source port: one port carries one path, so each re-gather draws its
 * own rather than colliding with the port a parked agent still holds. */
/* Fill a connection's ICE identity: a fresh ufrag/pwd. The host uses a new one
 * per offer (single-use per join, so two clients never share credentials); the
 * client keeps its one for the whole session. */
static void conn_gen_ice(struct conn *c)
{
	peering_ice_gen(c->ice_ufrag, sizeof(c->ice_ufrag), c->ice_pwd,
			sizeof(c->ice_pwd));
	/* A client probes under its own identity; a host overwrites this with the
	 * claimant it admitted (lan_drain, the turnstile at pickup, and the
	 * single-connection state machine when it takes an answer up). */
	if (c->sess && !c->sess->cfg->is_host) {
		pthread_mutex_lock(&c->claim_lock);
		snprintf(c->claim_ufrag, sizeof(c->claim_ufrag), "%s",
			 c->ice_ufrag);
		pthread_mutex_unlock(&c->claim_lock);
	}
	/* What a probe proved was proved for one claimant identity, so a fresh
	 * one voids every measurement; the endpoints themselves stand. */
	pathplane_reset_stats(&c->pr.pl, now_ms());
	c->claim_held_seen = 0;
	c->claim_lost = 0;
	c->claim_released_ms = 0;
	c->remote_ufrag[0] = '\0';
}

static int nat_setup(struct conn *c)
{
	struct sess *s = c->sess;
	struct nat_config cfg;
	struct ice_ctx *ctx;

	memset(&cfg, 0, sizeof(cfg));
	cfg.stun_host = s->cfg->stun_host;
	cfg.stun_port = s->cfg->stun_port;
	if (!cfg.stun_host && s->cfg->stun_auto &&
	    !peering_net_stun_pick(&s->net,
				   (unsigned)__atomic_load_n(&s->ice_attempt,
							     __ATOMIC_RELAXED),
				   s->stun_host, sizeof(s->stun_host),
				   &cfg.stun_port))
		cfg.stun_host = s->stun_host;
	cfg.ice_ufrag = c->ice_ufrag;
	cfg.ice_pwd = c->ice_pwd;
	cfg.on_local_sdp = on_local_sdp;
	cfg.on_recv = on_transport_recv;
	cfg.on_candidate = on_ice_candidate;
	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;
	__atomic_store_n(&ctx->c, c, __ATOMIC_RELAXED);
	cfg.arg = ctx;

	s->remote_set = 0;
	/* Stamp before the gather thread can report from it. One agent gathers
	 * both families, but they move apart, so each gets its own. */
	__atomic_store_n(&s->gather_epoch[0], netstate_epoch(&s->pm.ns, 4),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&s->gather_epoch[1], netstate_epoch(&s->pm.ns, 6),
			 __ATOMIC_RELAXED);
	c->nat = nat_create(&cfg);
	ctx->agent = c->nat;
	c->nat_ctx = ctx;
	if (!c->nat) {
		c->nat_ctx = NULL;
		free(ctx);
		return -1;
	}
	if (nat_gather(c->nat))
		return -1;
	s->stun_since_ms = now_ms();
	conn_add_ice_path(c);
	return 0;
}


static void pump_once(struct sess *s, int timeout_cap_ms)
{
	int timeout, nfds, lnf = 0, mnf;
	struct pollfd fds[7];

	nfds = sig_prepare(s->pm.sig, fds, 5, &timeout);
	if (s->lan)
		lnf = lanlink_prepare(s->lan, fds + nfds, 6 - nfds, &timeout);
	mnf = netmon_prepare(&s->netmon, fds + nfds + lnf, 7 - nfds - lnf);
	if (timeout > timeout_cap_ms)
		timeout = timeout_cap_ms;
	sock_poll(fds, (nfds_t)(nfds + lnf + mnf), timeout);
	sig_dispatch(s->pm.sig, fds, nfds);
	if (s->lan)
		lanlink_dispatch(s->lan, fds + nfds, lnf);
	netmon_drain_event(&s->netmon);
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
	o.spawner = s->cfg->spawner;
	o.end_fd = s->cfg->ssh_end_fd;
	o.ctl_fd = c->ssh_ctl_fd;
	o.no_fwd = s->cfg->no_fwd;
	o.forward_only = s->cfg->forward_only;
	o.ro_out = &c->read_only;
	o.fwd_refused_out = &c->fwd_refused;
	o.ended_out = &c->shell_ended;
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
	o.end_verdict = &c->end_verdict;
	o.send = s->cfg->test_send;
	o.send_len = s->cfg->test_send_len;
	o.recv = s->cfg->test_recv;
	o.recv_cap = s->cfg->test_recv_cap;
	o.recv_len = s->cfg->test_recv_len;
	o.hold_ms = s->cfg->test_hold_ms;
	o.stop = s->cfg->test_stop;
	c->ssh_cli_rc = sshc_connect_fd(c->ssh_fd, &o);
	return NULL;
}

/*
 * Publish the anchor each family holds, for the connections to read.
 *
 * Only a qualified one is handed to a peer: a node that has not proven itself
 * here is one we may still replace, and handing it over is the churn the
 * qualification exists to prevent. Unqualified ones are published all the same,
 * because the status line has to be able to say where this end is meeting even
 * while that is still being settled.
 *
 * Nothing is ever retracted, and nothing needs to be: the announcement can name
 * a node but has no way to unname one, so a peer keeps what it was last told
 * until it is told somewhere better.
 *
 * Runs on the thread that owns the model; every connection reads the result on
 * its own thread, which is what the lock is for.
 */
/*
 * Tell this peer where we rendezvous, whenever what we have told it is no
 * longer what we publish. A connection starts owing the whole set, so a client
 * that arrives on a token minted before a family had a node is told of it as it
 * joins rather than at its next reconnection, and a node found or replaced
 * mid-session reaches every peer at once. That is what lets a peer follow us
 * across a move instead of falling back on a full DHT search.
 *
 * Runs on the connection's own thread and touches nothing but the published
 * copy, so a host worker announces exactly as the thread driving the
 * signalling does.
 */
/* The bare address bytes and host-order port a token slot carries. */
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

/* A client's way back in: the rendezvous it holds now, as the host named it
 * over the control channel, written into the token it arrived on. A DIRECT
 * slot is the host's own endpoint and stays; a family with no node keeps
 * whatever that token said. Model thread only. */
static void client_token_pump(struct sess *s)
{
	static const int famv[2] = { 4, 6 };
	int i;

	if (s->cfg->is_host || !s->cfg->on_token_state)
		return;
	for (i = 0; i < 2; i++) {
		uint8_t node[NETSTATE_SA_MAX], nlen = 0;
		uint8_t a[TOKEN_EP6_LEN];
		uint16_t port = 0;
		const uint8_t *b;

		if (s->tok_state[i] == TOKEN_STATE_DIRECT)
			continue;
		if (!netstate_anchor(&s->pm.ns, famv[i], node, &nlen, NULL) ||
		    !nlen)
			continue;
		b = ep_bytes((struct sockaddr *)node, &port);
		if (!b)
			continue;
		memset(a, 0, sizeof(a));
		memcpy(a, b, famv[i] == 6 ? TOKEN_EP6_LEN : TOKEN_EP4_LEN);
		if (s->tok_told[i] &&
		    s->tok_state[i] == TOKEN_STATE_RENDEZVOUS &&
		    !memcmp(s->tok_ep[i], a, sizeof(a)) &&
		    s->tok_port[i] == port)
			continue;
		s->tok_state[i] = TOKEN_STATE_RENDEZVOUS;
		s->tok_told[i] = 1;
		memcpy(s->tok_ep[i], a, sizeof(a));
		s->tok_port[i] = port;
		s->cfg->on_token_state(s->cfg->arg, famv[i],
				       TOKEN_STATE_RENDEZVOUS, a, port);
	}
}

/* Everything each served connection's peer has said about itself, drained on
 * the host's own thread: a worker runs the transport and never touches the
 * model. */
static void peer_in_drain(struct sess *s)
{
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->conns[i])
			peering_absorb(&s->conns[i]->pr, now_ms());
}


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

static int host_is_multiuser(const struct session_cfg *cfg)
{
	return cfg->is_host && (cfg->sig_flags & (SIG_DHT | SIG_MCAST)) &&
	       !cfg->test_single_conn;
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
	struct sig *sig;

	sig = sig_create(cfg->tok.rdv, cfg->sig_flags, cfg->is_host);
	if (!sig)
		return -1;
	/* What the model already holds, before anything is published. */
	if (peering_model_sig(&s->pm, sig, now_ms()))
		return -1;
	sig_subscribe(s->pm.sig, on_peer_offer, s);
	/* Our offer carries the generation of the network it was gathered on, so
	 * a peer tells a move from a mere credential rotation. A rebuild follows
	 * a move, so the current netgen is what this fresh signaller stamps. */
	sig_set_gen(s->pm.sig, __atomic_load_n(&s->netgen, __ATOMIC_RELAXED));
	if (s->lan) {
		sig_set_direct_port(s->pm.sig, lanlink_port(s->lan));
		if (host_is_multiuser(cfg)) {
			sig_subscribe_direct(s->pm.sig, on_direct_claim, s);
			sig_set_mcast_claims(s->pm.sig, 1);
		} else {
			sig_subscribe_direct(s->pm.sig, on_direct_peer, &s->c);
		}
	}
	seed_rendezvous(s);

	return 0;
}

/* Re-run on a rebuild: a cable going in adds one that was not there at
 * startup. */
static void report_links(struct sess *s)
{
	struct sig_mcast_if ifs[16];

	if (!s->lan || !s->pm.sig)
		return;
	obsemit_links(&s->pm.oe, ifs, sig_link_ifaces(s->pm.sig, ifs, 16));
}

/*
 * Clear the move debt when re-establishing a link. Only ever reached off a lost
 * or not-yet-connected link, so a live link is never torn down by an address
 * change: those are folded in per-family by net_settle. netgen bumps here, not
 * on the netmon poll, so a temporary address coming or going under a live link
 * does not mark it moved.
 */
static int net_moved(struct sess *s)
{
	unsigned ch = s->net_ch;

	s->net_ch = 0;
	/* Only a v4 change re-establishes: a v6 or interface flap must not
	 * disrupt a live v4 link or discard its accumulated egress pool
	 * (netstate tracks v6 candidates on its own). */
	if (!(ch & NETMON_CH_V4))
		return 0;
	/* The move is acted on now; drop any burst remnant still coalescing in
	 * net_pending so a trailing v6/iface flap cannot re-commit this v4 and
	 * fire a second, redundant re-gather. A genuine later change re-arms. */
	s->net_pending = 0;
	__atomic_add_fetch(&s->netgen, 1, __ATOMIC_RELAXED);
	return 1;
}

static int sig_rebuild(struct sess *s, const char *why)
{
	sig_discard(s->pm.sig);
	peering_model_sig(&s->pm, NULL, 0);
	if (sig_arm(s)) {
		dbg_logf("sig: rebuild failed -- giving up the session");
		return -1;
	}
	report_links(s);
	dbg_logf("sig: rebuilt %s", why);
	return 0;
}

/* The answer-wait between re-claims: short at first, so a claim that lost the
 * race with the host's regather is re-posted in seconds, backing off to the
 * host's own cadence so a peer that is simply gone is not hammered. */
#define RESUME_FIRST_MS 2000

static uint32_t resume_backoff(struct conn *c)
{
	if (!c->rs_backoff)
		c->rs_backoff = RESUME_FIRST_MS;
	else if (c->rs_backoff < RESUME_ATTEMPT_MS)
		c->rs_backoff *= 2;
	if (c->rs_backoff > RESUME_ATTEMPT_MS)
		c->rs_backoff = RESUME_ATTEMPT_MS;
	return c->rs_backoff;
}

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

/* A roam surfaces as a burst of interface changes (down, link-local, v4, v6,
 * a temporary address); coalesce them into one acted-on change by holding it
 * until the interfaces are quiet, each new change restarting the hold. */
#define NET_HOLD_MS 750
#define NET_HOLD_POLL_MS 250

/* Split from net_pump so the in-place resume can watch the interfaces too. */
static void net_watch(struct sess *s, uint64_t now)
{
	struct netmon_addr addrs[NETMON_MAX_ADDRS];
	const struct session_cfg *cfg = s->cfg;
	uint8_t fp4[32], fp6[32], fpif[32];
	unsigned ch = 0;
	int synth = 0;
	size_t n;

	netmon_drain_event(&s->netmon);
	if (cfg->test_roam_ms > 0 && s->next_roam_ms && now >= s->next_roam_ms &&
	    (cfg->test_roam_max <= 0 || s->roams < cfg->test_roam_max)) {
		s->next_roam_ms = now + (uint64_t)cfg->test_roam_ms;
		s->roams++;
		ch = cfg->test_roam_mask ? cfg->test_roam_mask :
		     (NETMON_CH_V4 | NETMON_CH_V6 | NETMON_CH_IFACE);
		synth = 1;
	}
	if (!synth && now < s->netmon.next_check_ms)
		return;
	n = netmon_snapshot(addrs, NETMON_MAX_ADDRS);
	netmon_fingerprint(fp4, fp6, fpif, addrs, n);
	ch |= netmon_changed_fam_fp(&s->netmon, now, fp4, fp6, fpif);
	netstate_on_netmon(&s->pm.ns, ch, fam_usable_addr(addrs, n, 4),
			   fam_usable_addr(addrs, n, 6), now);
	if (ch) {
		dbg_logf("net: change v4=%d v6=%d iface=%d",
			 !!(ch & NETMON_CH_V4), !!(ch & NETMON_CH_V6),
			 !!(ch & NETMON_CH_IFACE));
		s->net_pending |= ch;
		s->net_hold_ms = synth ? now : now + NET_HOLD_MS;
	}
	if (s->net_pending && now >= s->net_hold_ms) {
		s->net_ch |= s->net_pending;
		s->net_pending = 0;
	} else if (s->net_pending) {
		s->netmon.next_check_ms = now + NET_HOLD_POLL_MS;
	}
}

static void net_change_reset(struct sess *s)
{
	s->have_local_sdp = 0;
	s->have_peer_sdp = 0;
	s->remote_set = 0;
	s->local_sdp[0] = '\0';
	s->peer_sdp[0] = '\0';
	pthread_mutex_lock(&s->trickle_lock);
	s->trickle_sdp[0] = '\0';
	__atomic_store_n(&s->trickle_dirty, 0, __ATOMIC_RELAXED);
	s->pending_sdp_set = 0;
	pthread_mutex_unlock(&s->trickle_lock);
	peering_pool_reset(&s->net.pool);
	s->stun_rotations = 0;
	/* a fresh index: the per-session walk can leave a stale one on a dead
	 * server, whose offer then carries no reflexive address */
	if (s->stun_count > 0) {
		uint8_t rb[2];

		random_bytes(rb, 2);
		__atomic_store_n(&s->ice_attempt,
				 ((rb[0] << 8) | rb[1]) % s->stun_count,
				 __ATOMIC_RELAXED);
	}
	__atomic_store_n(&s->have_priv4, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&s->have_srflx4, 0, __ATOMIC_RELAXED);
	s->net.pool.reported = 0;
	s->net.pool.posted = 0;
	s->mapping_reported = 0;
}

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
	struct ctlplane_live live;
	struct ice_ctx *spare_ctx;
	struct nat_agent *spare;
	struct sess *s;
	uint64_t now;
	int lost, hi;
	int moved;
	int n;

	s = c->sess;
	now = now_ms();
	/* Watch interfaces every tick, not only once lost: a roam onto a limping
	 * path never trips "lost" (KCP still trickles), so it must be seen here. */
	net_watch(s, now);
	moved = net_moved(s);
	ctlplane_liveness(&c->pr.cp, &live);
	lost = live.lost_since_ms != 0 &&
	       now - live.lost_since_ms >= RESUME_AFTER_MS;
	if (!lost && !moved) {
		if (c->rs_state) {
			c->rs_state = 0;
			c->rs_backoff = 0;
			sig_withdraw(s->pm.sig);
			dbg_logf("resume: link back");
		}
		/*
		 * It came back on the agent set aside, so that is the one
		 * carrying: it takes the current role and the punch being
		 * built in its place is let go.
		 */
		hi = pathplane_hold_carrying(&c->pr.pl);
		if (hi >= 0) {
			spare = c->nat;
			spare_ctx = c->nat_ctx;
			c->nat = pathplane_hold_take(&c->pr.pl, hi,
						     (void **)&c->nat_ctx);
			conn_free_agent(c, spare, spare_ctx);
			dbg_logf("resume: carried by the agent set aside");
		} else if (pathplane_has_hold(&c->pr.pl)) {
			/* A non-held path carries, so free the set-aside agents
			 * now, not at their deadline: a second punch would else
			 * ride along on its own port for the whole span. */
			conn_reap_holds(c);
			dbg_logf("resume: the agent set aside answered "
				 "nothing");
		}
		return;
	}
	conn_holds_gc(c, now);
	if (moved) {
		if (sig_rebuild(s, "on the new network"))
			return;
		net_change_reset(s);
		c->rs_state = 0;
	}
	switch (c->rs_state) {
	case 0:
		conn_park_ice(c, now);
		conn_fresh_pwd(c);
		s->have_local_sdp = 0;
		s->have_peer_sdp = 0;
		s->remote_set = 0;
		c->remote_ufrag[0] = '\0';
		pthread_mutex_lock(&s->trickle_lock);
		s->trickle_sdp[0] = '\0';
		__atomic_store_n(&s->trickle_dirty, 0, __ATOMIC_RELAXED);
		s->pending_sdp_set = 0;
		pthread_mutex_unlock(&s->trickle_lock);
		if (nat_setup(c))
			return;
		c->rs_state = 1;
		c->rs_deadline = now + RESUME_ATTEMPT_MS;
		dbg_logf("resume: re-claiming under the session identity");
		return;
	case 1:
		if (sdp_ready(s)) {
			char filtered[NAT_SDP_MAX];

			sdp_filter(s->local_sdp, s->cfg->family, filtered,
				   sizeof(filtered));
			snprintf(s->local_sdp, sizeof(s->local_sdp), "%s",
				 filtered);
			s->net.pool.posted = fan_local_sdp(s);
			sig_set_claim_offer(s->pm.sig, c->remote_ufrag);
			sig_post(s->pm.sig, (const uint8_t *)s->local_sdp,
				 strlen(s->local_sdp));
			sig_redeliver(s->pm.sig);
			dbg_logf("resume: claim posted");
			c->rs_state = 2;
			c->rs_deadline = now + resume_backoff(c);
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
				cand_sdp_ufrag(s->peer_sdp, ufrag, sizeof(ufrag));
				snprintf(c->remote_ufrag,
					 sizeof(c->remote_ufrag), "%s", ufrag);
				c->remote_gen = sig_peer_gen(s->pm.sig);
				s->remote_set = 1;
				dbg_logf("resume: primed offer %s", ufrag);
				/* Named, and posted only once primed: the host
				 * punches the agent this end punches, not whatever
				 * listener a rotation left in the slot. */
				sig_set_claim_offer(s->pm.sig, c->remote_ufrag);
				sig_post(s->pm.sig, (const uint8_t *)s->local_sdp,
					 strlen(s->local_sdp));
				dbg_logf("resume: claim posted for %s", ufrag);
			}
		}
		/* Late pool addresses reach the host's in-flight punch only
		 * through a re-post under the same credentials (a fresh gather
		 * would mint a password and abort the punch). */
		if (s->remote_set && s->have_local_sdp) {
			n = peering_pool_count(&s->net.pool);
			if (n >= 2 && n > s->net.pool.posted) {
				s->net.pool.posted = fan_local_sdp(s);
				sig_set_claim_offer(s->pm.sig, c->remote_ufrag);
				sig_post(s->pm.sig, (const uint8_t *)s->local_sdp,
					 strlen(s->local_sdp));
				dbg_logf("resume: trickled pool -> %d", n);
			}
		}
		/* A higher generation is the host having moved, its candidates
		 * gone: re-gather. A same-generation rotation is pickup churn,
		 * and chasing it aborts a punch still in flight. */
		if (s->remote_set && s->cur_offer_ufrag[0] &&
		    offer_rotated(c->remote_ufrag, s->cur_offer_ufrag) &&
		    sig_peer_gen(s->pm.sig) > c->remote_gen) {
			c->rs_state = 0;
			return;
		}
		if (now >= c->rs_deadline) {
			/* Hold the credentials and let ICE keep punching every
			 * pair until it proves one or gives the pair up; re-gather
			 * only when this end moved or the agent is spent, not on a
			 * clock that would abort a punch still landing. */
			if (!s->remote_set || s->net_ch || nat_failed(c->nat)) {
				c->rs_state = 0;
				return;
			}
			/* Re-post the claim, not only the offer: the host reaps
			 * the worker on a stale claim, and losing it forces a
			 * full re-join. Same credentials, punch undisturbed. */
			if (s->have_local_sdp) {
				sig_set_claim_offer(s->pm.sig, c->remote_ufrag);
				sig_post(s->pm.sig, (const uint8_t *)s->local_sdp,
					 strlen(s->local_sdp));
			}
			sig_redeliver(s->pm.sig);
			c->rs_deadline = now + resume_backoff(c);
		}
		return;
	}
}

/*
 * Longest the operator's shell is held while the end of the session is
 * published. The usual cost is a round trip to the rendezvous node the token
 * already names, so this is the ceiling on a bad network, not the price of a
 * quit. Waiting at all is the point: a comrade that returned the prompt and
 * finished the publish behind the operator's back would be the background
 * process this whole path exists to avoid.
 */
#define SESSION_TOMB_MS 4000

/*
 * The shared session is over: leave that where the invitation points.
 *
 * Everything a client holds says where to meet a host that is still there, and
 * nothing in it can say the opposite -- so a token outliving its session sends
 * every holder into a wait with no end. The tombstone is the missing answer,
 * and it has to be placed from here, while this session's rendezvous node is
 * still warm and pinned: a process that has already torn its signalling down
 * would have to converge on the DHT from cold to say a single word.
 *
 * The DHT is the only place there is to leave it, so a link-local session has
 * nothing to do here and returns at once -- see sig_end.
 *
 * Started as early as the end is known and finished last, because the operator
 * is waiting on it: the deadline runs from the start, so whatever winding down
 * happens in between -- workers lingering to land their end-of-session signal
 * on clients that are slow to ack -- is time the store has been using rather
 * than time added to it.
 */
static void session_entomb_start(struct sess *s)
{
	if (!s->pm.sig || s->tomb_deadline)
		return;
	s->tomb_deadline = now_ms() + SESSION_TOMB_MS;
	sig_end(s->pm.sig);
}

/* A validated get proves the family, and says whether the rendezvous we hold
 * is the one still answering. */
/*
 * Tell the view each family's rendezvous: the node the model holds, and
 * whether it has qualified to go into a token.
 *
 * The same fact token_pump mints from, so the panel cannot name a node while
 * the invite line is still saying it is looking for one -- a contradiction the
 * operator sees for as long as qualifying takes, and which then resolves as a
 * token changing under a shared invite for no visible reason.
 */
/*
 * What the session still has a say in while the model is settled: where a v6
 * round begins, and which families it is still looking for a node on. Only a
 * host looks for one it has not got; a client is told where to meet.
 */
static void session_settle_cfg(struct sess *s, struct peering_settle *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->start6 = __atomic_load_n(&s->ice_attempt, __ATOMIC_RELAXED);
	cfg->expect4 = s->cfg->is_host && s->expect4;
	cfg->expect6 = s->cfg->is_host && s->expect6;
}

static void report_rendezvous(struct sess *s)
{
	struct peering_settle cfg;

	session_settle_cfg(s, &cfg);
	obsemit_rendezvous(&s->pm.oe, cfg.expect4, cfg.expect6);
}

/* One pass over the model: what the signaller learnt, what it settles on, and
 * what it publishes for this mailbox's peers to pass on. */
static void session_advance(struct sess *s)
{
	struct peering_settle cfg;

	session_settle_cfg(s, &cfg);
	peering_advance(&s->pm, &s->net, &cfg, now_ms());
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
	uint64_t conn_start;
	int done = 0, link_lost = 0;
	struct sess *s = c->sess;
	uint32_t carry_seen = 0;
	int detached_sent = 0;
	struct sshbridge *br;
	sock_t sp[2], cp[2];
	struct stream *st;
	pthread_t th;
	int qi;

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
	/*
	 * Built first and published under the lock the readers take: a
	 * transport receive thread is already running by now and reaches
	 * c->stream through deliver_stream_from, so assigning it in the open
	 * was a race with every one of those reads.
	 */
	st = stream_create(s->keys.conv, on_stream_output, c);
	if (!st) {
		sock_close(sp[0]);
		sock_close(sp[1]);
		sock_close(cp[0]);
		sock_close(cp[1]);
		return -1;
	}
	pthread_mutex_lock(&c->stream_lock);
	c->stream = st;
	pthread_mutex_unlock(&c->stream_lock);
	c->ssh_fd = sp[1];
	c->ssh_ctl_fd = cp[1];
	c->ctl_fd = cp[0];
	c->ctl_rf.len = 0;
	c->shell_ended = 0;
	c->end_verdict = 0;
	/* The probe key belongs to the channel that agreed it. */
	peering_reset(&c->pr);
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
		pthread_mutex_lock(&c->stream_lock);
		st = c->stream;
		c->stream = NULL;
		pthread_mutex_unlock(&c->stream_lock);
		stream_destroy(st);
		return -1;
	}
	br = sshbridge_create(sp[0], c->stream,
			      s->cfg->is_host ? LINGER_HOST_MS : LINGER_CLIENT_MS);

	/* The path is up on entry, so start the liveness clock as alive, and
	 * what was said about the session before this one is spent. */
	__atomic_store_n(&c->peer_fresh, 0, __ATOMIC_RELAXED);
	ctlplane_live_reset(&c->pr.cp, now_ms());
	/*
	 * And say so before the session starts. Status is published on a
	 * cadence, so until the first turn of the loop below the last one
	 * still standing describes the session that just ended -- which for a
	 * client that has just been told its worker was replaced reads as
	 * "rejoin", and it would tear this one down before it carried
	 * anything.
	 */
	publish_status(c, CONN_LIVE);
	conn_start = now_ms();
	/* A fresh connection is owed the whole set, whatever an earlier one on
	 * this struct was told. */
	peering_owed(&c->pr, conn_start);

	if (drive_sig) {
		/* Capture a rendezvous node per family for reconnection (the host
		 * was already locating; ask on the client side too). */
		if (s->cfg->sig_flags & SIG_DHT)
			sig_locate(s->pm.sig);
		/*
		 * Now connected, a client stops advertising its answer: otherwise
		 * it would keep re-claiming the single mailbox slot the host clears
		 * after serving it, hogging it for the whole session so no other
		 * client could ever join. A rejoin re-posts (ST_GATHER). The host
		 * (mcast single-connection path) keeps advertising its offer.
		 */
		if (!s->cfg->is_host)
			sig_withdraw(s->pm.sig);
	}

	while (!done) {
		struct pollfd fds[9];
		struct ice_ctx *got;
		int timeout = 10, nfds = 0, lnf = 0, bidx, cidx;

		/* A re-punched agent the turnstile grafted for us: adopt it
		 * here, on the one thread that owns c->nat. Its callbacks were
		 * re-pointed at this connection before it was parked, so its
		 * packets have been landing in the stream all along; this
		 * makes it the sending agent too. */
		for (qi = 0; qi < ICE_HOLD_MAX; qi++) {
			got = __atomic_load_n(&c->resume_q[qi], __ATOMIC_ACQUIRE);
			if (!got)
				continue;
			__atomic_store_n(&c->resume_q[qi], (struct ice_ctx *)0,
					 __ATOMIC_RELAXED);
			/* Keep the incumbent as a hold; the ranking decides
			 * which agent carries, a silent one ages out. */
			if (c->nat)
				conn_hold_add(c, c->nat, c->nat_ctx,
					      now_ms() + RESUME_ATTEMPT_MS);
			c->nat = got->agent;	/* bound to it for life */
			c->nat_ctx = got;
			conn_add_ice_path(c);
			pathplane_blackhole_mute(&c->pr.pl, 0);
			/* The resumed link earns a full liveness window; without
			 * this it is judged by silence that predates it. */
			ctlplane_heard(&c->pr.cp, now_ms());
			dbg_logf("resume: adopted the re-punched agent");
		}
		if (drive_sig) {
			nfds = sig_prepare(s->pm.sig, fds, 5, &timeout);
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
			sig_dispatch(s->pm.sig, fds, nfds);
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
		peering_paths(&c->pr, now_ms());
		conn_holds_gc(c, now_ms());
		conn_route_dedup(c);
		if (__atomic_load_n(&c->carry_epoch, __ATOMIC_RELAXED) !=
		    carry_seen) {
			carry_seen = __atomic_load_n(&c->carry_epoch,
						    __ATOMIC_RELAXED);
			stream_kick(st);
		}
		peering_say(&c->pr, s->lan ? lanlink_port(s->lan) : 0,
			    now_ms());
		if (s->cfg->test_blackhole_ms > 0 &&
		    pathplane_blackhole_kind(&c->pr.pl) < 0 && !c->bh_done &&
		    now_ms() - conn_start >
		    (uint64_t)s->cfg->test_blackhole_ms) {
			struct pathplane_pick pick;

			if (s->cfg->test_blackhole_all) {
				pathplane_blackhole_mute(&c->pr.pl, 1);
				c->bh_done = 1;
				dbg_logf("path blackholed: all");
			} else if (!conn_pick(c, &pick)) {
				pathplane_blackhole_arm(&c->pr.pl, pick.kind,
							&pick.remote);
				c->bh_done = 1;
				dbg_logf("path blackholed: %s",
					 pick.label[0] ? pick.label : "ICE");
			}
		}
		if (pathplane_blackhole_armed(&c->pr.pl) &&
		    s->cfg->test_blackhole_lift_ms > 0 &&
		    now_ms() - conn_start >
		    (uint64_t)s->cfg->test_blackhole_lift_ms) {
			pathplane_blackhole_lift(&c->pr.pl);
			dbg_logf("path blackhole lifted");
		}

		/*
		 * The shared session ended under us. sshd is closing the shell
		 * channel on the same signal, and a channel closing on its own
		 * looks exactly like the guest detaching, so say which it was
		 * while the control channel is still up. Polled here rather
		 * than added to the set above: the fd is only ever readable at
		 * EOF and nothing consumes it, so every worker sees it.
		 */
		if (s->cfg->is_host && !c->bye_sent &&
		    sock_isset(s->cfg->ssh_end_fd)) {
			struct pollfd ef;

			ef.fd = s->cfg->ssh_end_fd;
			ef.events = POLLIN;
			ef.revents = 0;
			if (sock_poll(&ef, 1, 0) > 0 &&
			    (ef.revents & (POLLIN | POLLHUP | POLLERR))) {
				dbg_logf("ctl: telling the client the shared "
					 "session has ended");
				conn_ctl_send(c, CTLM_BYE, NULL, 0);
				c->bye_sent = 1;
				/*
				 * On the single-connection path this loop owns
				 * the signalling, so the end starts being
				 * published here rather than after the
				 * teardown -- which is a client's departure,
				 * and can take seconds the operator would
				 * otherwise wait through twice. A worker
				 * leaves it alone: there, sig belongs to the
				 * turnstile thread, which does the same at its
				 * own exit.
				 */
				if (drive_sig) {
					s->session_over = 1;
					session_entomb_start(s);
				}
			}
		}
		/* The guest detached and the session lives (sshd waited the end
		 * monitor out and it stayed silent): say so, so the client offers
		 * a rejoin rather than waiting on a CTLM_BYE that never comes. */
		if (s->cfg->is_host && !c->bye_sent && !detached_sent &&
		    __atomic_load_n(&c->shell_ended, __ATOMIC_RELAXED) ==
		    SSHD_END_DETACH) {
			dbg_logf("ctl: telling the client it detached");
			conn_ctl_send(c, CTLM_DETACHED, NULL, 0);
			detached_sent = 1;
		}
		if (drive_sig) {
			/*
			 * This loop owns the model here, so what the peer has
			 * told us is acted on now rather than at the end of the
			 * session: the pin is what a re-claim goes out through,
			 * which is the whole point of following the host.
			 *
			 * Nothing watches the interfaces while a link is up (a
			 * move drops it and comes back through the reconnect),
			 * but the DHT keeps answering, and its answers are what
			 * a peer relying on us would be relying on -- so they
			 * are taken here and reported as they change.
			 */
			peering_absorb(&c->pr, now_ms());
			session_advance(s);
			client_token_pump(s);
		}
		if (drive_sig && !s->cfg->is_host)
			resume_tick(c);
		if (now_ms() >= c->next_status_ms) {
			uint64_t now = now_ms(), lp;
			int state;

			state = ctlplane_judge(&c->pr.cp, now, &lp) ? CONN_LOST :
								    CONN_LIVE;
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
			 * silence is bounded by the handshake grace instead of the
			 * tighter heartbeat-loss window. */
			if (s->cfg->is_host && s->cfg->test_reap_ms > 0 &&
			    now - conn_start > (uint64_t)s->cfg->test_reap_ms) {
				done = 1;
			} else if (s->cfg->is_host) {
				struct ctlplane_live live;
				struct host_reap hr;
				int verdict;

				ctlplane_liveness(&c->pr.cp, &live);
				hr.conn_start_ms = conn_start;
				hr.lost_since_ms = live.lost_since_ms;
				hr.resume_last_ms =
					__atomic_load_n(&c->resume_last_ms,
							__ATOMIC_RELAXED);
				hr.resume_pending =
					__atomic_load_n(&c->resume_pending,
							__ATOMIC_RELAXED);
				hr.pong_seen = live.pong_seen;
				verdict = host_reap_due(&hr, now);
				if (verdict != HOST_REAP_KEEP)
					done = 1;
				/*
				 * Only where NOBODY has ever got through. The
				 * advice is about a firewall in front of this
				 * host, and one peer that finished the
				 * handshake is proof there is not one -- a
				 * later attempt that dies mid-handshake is
				 * that attempt's problem, and sending the
				 * operator after their firewall points them
				 * at something that demonstrably works.
				 */
				if (verdict == HOST_REAP_NO_HANDSHAKE &&
				    !__atomic_load_n(&s->handshake_seen,
						     __ATOMIC_RELAXED) &&
				    s->cfg->obs && s->cfg->obs->escalate)
					s->cfg->obs->escalate(
						s->cfg->obs->arg,
						"a peer connected but never "
						"finished the handshake -- "
						"check your firewall allows "
						"comrade");
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
	/*
	 * The probe key went with that channel. What comes back may be a new
	 * worker holding only the session key, and the path it has to be found
	 * on is built before the next channel exists, so the binding cannot
	 * outlive the session that agreed it.
	 */
	peering_reset(&c->pr);
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
	netstate_resync(&s->pm.ns);	/* the reset above cleared rows and the
					 * verdict; neither has actually moved */
	s->established_fired = 0;
	conn_drop_ice_path(&s->c);
	conn_free_agent(&s->c, s->c.nat, s->c.nat_ctx);
	s->c.nat = NULL;
	s->c.nat_ctx = NULL;
	conn_gen_ice(&s->c);
	s->have_local_sdp = 0;
	s->have_peer_sdp = 0;
	s->remote_set = 0;
	s->local_sdp[0] = '\0';
	s->peer_sdp[0] = '\0';
	pthread_mutex_lock(&s->trickle_lock);
	s->trickle_sdp[0] = '\0';	/* drop the old agent's trickle */
	__atomic_store_n(&s->trickle_dirty, 0, __ATOMIC_RELAXED);
	s->pending_sdp_set = 0;
	pthread_mutex_unlock(&s->trickle_lock);
	s->peer_state = SESSION_PEER_SEEN;
	sig_redeliver(s->pm.sig);		/* we discarded the offer we were given */
	return nat_setup(&s->c) ? -1 : 0;
}

/*
 * The current agent's STUN attempt has run its course with no reflexive v4
 * while one is called for (a private/CGNAT v4 and no public one on the
 * table). Only for the rotated pool -- an explicit --stun server is the
 * operator's to keep alive -- and only while the rotation budget lasts.
 */
/*
 * May a rotation be spent at all: an automatic pool with somewhere else to go,
 * a private v4 to explain a missing public one, and budget left on this
 * network.
 */
static int stun_rotate_ok(const struct sess *s)
{
	if (s->cfg->stun_host || !s->cfg->stun_auto || s->stun_count < 2)
		return 0;
	if (!__atomic_load_n(&s->have_priv4, __ATOMIC_RELAXED))
		return 0;
	return s->stun_rotations < STUN_ROTATE_MAX;
}

static int stun_stall(struct sess *s)
{
	if (!stun_rotate_ok(s) ||
	    __atomic_load_n(&s->have_srflx4, __ATOMIC_RELAXED))
		return 0;
	return now_ms() - s->stun_since_ms > STUN_ROTATE_MS;
}

/*
 * A zero connect budget means keep trying, so every test of it goes through
 * these two: "no deadline" must never read as "already past it".
 */
static int deadline_passed(uint64_t deadline, uint64_t now)
{
	return deadline && now >= deadline;
}

static int deadline_room(uint64_t deadline, uint64_t now, uint64_t need)
{
	return !deadline || now + need < deadline;
}


/*
 * And the longest a worker is given to wind down while that goes on. Sized
 * above LINGER_HOST_MS, which is what a worker spends flushing its own
 * end-of-session signal at a client that has stopped acknowledging: the two
 * are meant to run together, so the wait is the longer of them rather than one
 * after the other -- and past this the worker is simply joined, since a
 * departed guest is not something to hold a shell open for.
 */
#define SESSION_WIND_MS (LINGER_HOST_MS + 1000)


static void session_entomb(struct sess *s)
{
	if (!s->pm.sig)
		return;
	session_entomb_start(s);
	while (!deadline_passed(s->tomb_deadline, now_ms())) {
		pump_once(s, 100);
		if (sig_end_placed(s->pm.sig))
			break;
	}
	dbg_logf("session: tombstone %s", sig_end_placed(s->pm.sig) ?
		 "placed (or nowhere to place it)" : "not placed in time");
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

	/* Recomputed, not accumulated: otherwise a family lost in a move is
	 * expected, and reported as still being looked for, forever. */
	s->expect4 = 0;
	s->expect6 = 0;
	while ((p = strstr(p, "a=candidate:")) != NULL) {
		if (sscanf(p, "a=candidate:%*s %*d %*s %*u %63s", addr) == 1) {
			if (!strchr(addr, ':'))
				s->expect4 = 1;
			else if (net_addr_scope(addr) == NET_SCOPE_GLOBAL)
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
 * This family's DHT attempt can no longer produce an ack worth waiting for:
 * the operator declined the DHT outright, or its grace has passed with
 * neither family ever captured -- sig itself never stops trying a family
 * once the other one has proven the DHT reachable, so past that point this
 * only settles a family that looks isolated from the start (a captive
 * portal, UDP blocked outbound). A rebuild on a roam re-arms it, so a move
 * onto a network that does reach the DHT is given a fresh run.
 */
static int dht_attempt_concluded(struct sess *s, int family)
{
	if (!(s->cfg->sig_flags & SIG_DHT))
		return 1;
	/* Holding a rendezvous node is an attempt still running, whether it has
	 * answered here yet or not: saying the family has none while one is on
	 * the screen is worse than saying it is still being checked. */
	if (netstate_anchor(&s->pm.ns, family, NULL, NULL, NULL))
		return 0;
	if (now_ms() - s->pm.dht_since_ms <= DHT_CONCLUDE_MS)
		return 0;
	return !sig_locating(s->pm.sig, family);
}

/* The tokgen facts: the model holds all but the one reaching into sig. */
static void gather_facts(struct sess *s, int family, struct tokgen_facts *f)
{
	netstate_on_dht_concluded(&s->pm.ns, family,
				  dht_attempt_concluded(s, family));
	netstate_facts(&s->pm.ns, family, f);
}






/*
 * The per-loop network tick: notice a change (net_watch), take the DHT acks,
 * drain the STUN facts, then apply what the model decided. What a move leaves
 * for each loop to finish is taken from net_moved.
 */
static void net_pump(struct sess *s, uint64_t now)
{
	net_watch(s, now);
	session_advance(s);
}

static int conn_link_state(const struct sess *s, struct conn *c)
{
	return peering_link(&c->pr,
			    __atomic_load_n(&s->netgen, __ATOMIC_RELAXED),
			    c->ice_up, now_ms());
}

/*
 * Tell the view what the mailbox is doing, when it changes. Both ends run
 * this: everything before a punch happens through that one item, so a join
 * that is not progressing is nearly always visible here first -- our slot
 * never stored, or the peer's never seen.
 *
 * The ages are seconds rather than timestamps because that is what the view
 * would compute anyway, and it keeps the clock on this side of the seam.
 */
static void report_mailbox(struct sess *s)
{
	struct sig_mailbox sm;

	if (!s->pm.sig)
		return;
	sig_mailbox_state(s->pm.sig, &sm);
	obsemit_mailbox(&s->pm.oe, &sm, now_ms());
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
	if (!sdp_ready(s))		/* no candidates yet: cannot decide */
		return;

	update_expect(s);
	have4 = sig_located(s->pm.sig, 4, (struct sockaddr *)&a4, &l4);
	have6 = sig_located(s->pm.sig, 6, (struct sockaddr *)&a6, &l6);

	/* Remember the located rendezvous endpoint for the local status line,
	 * preferring v6 to match how the token renders it. */
	if (have6)
		peering_sockaddr_text((struct sockaddr *)&a6, l6,
			     s->status_rdv, sizeof(s->status_rdv));
	else if (have4)
		peering_sockaddr_text((struct sockaddr *)&a4, l4,
			     s->status_rdv, sizeof(s->status_rdv));

	if (o && o->rdv_stage) {		/* drive the RENDEZVOUS spinner */
		if (s->expect4)
			o->rdv_stage(o->arg, 4, sig_rdv_stage(s->pm.sig, 4));
		if (s->expect6)
			o->rdv_stage(o->arg, 6, sig_rdv_stage(s->pm.sig, 6));
	}
	report_rendezvous(s);		/* also for a family still expected */
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
		if (!sig_located(s->pm.sig, fam, (struct sockaddr *)&ss, &sl))
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
	struct tokgen_facts f4, f6;
	struct tokgen_result verdict;
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
	if (sdp_ready(s)) {
		gather_facts(s, 4, &f4);
		gather_facts(s, 6, &f6);
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

		if (sdp_ready(s)) {
			st = advert_state(s, famv[i], adv[i], a, &port);
		} else {
			st = s->tok_state[i];
			carried_ep(&s->cfg->tok, famv[i], a, &port);
		}
		/* Re-proving the node the token already names is not a reason
		 * to take it back: while we still hold it, a family only ever
		 * moves to a different rendezvous or to a settled verdict. */
		if (st == TOKEN_STATE_PENDING &&
		    s->tok_state[i] == TOKEN_STATE_RENDEZVOUS &&
		    netstate_anchor(&s->pm.ns, famv[i], NULL, NULL, NULL))
			st = advert_state(s, famv[i], TOK_ADVERT_RENDEZVOUS,
					  a, &port);
		if (s->tok_told[i] && st == s->tok_state[i])
			continue;
		s->tok_state[i] = st;
		s->tok_told[i] = 1;
		s->cfg->on_token_state(s->cfg->arg, famv[i], st, a, port);
	}
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
	peering_init(&c->pr, &s->pm, s->keys.probe_magic, s->keys.sig_key,
		     now_ms());
	conn_peering_sinks(c);
	pthread_mutex_init(&c->status_lock, NULL);
	pthread_mutex_init(&c->stream_lock, NULL);
	pthread_mutex_init(&c->claim_lock, NULL);
	conn_gen_ice(c);
	return c;
}

/*
 * Give back everything a connection holds except the connection itself. Safe
 * the moment it is dissolved: nothing here is reachable from a callback.
 */
static void conn_dissolve(struct conn *c)
{
	struct ice_ctx *got;
	int i;

	conn_unregister(c->sess, c);
	conn_reap_holds(c);
	conn_drop_ice_path(c);
	conn_free_agent(c, c->nat, c->nat_ctx);
	/* A re-punch grafted for a worker that left its loop before adopting
	 * it: nobody else will. */
	for (i = 0; i < ICE_HOLD_MAX; i++) {
		got = __atomic_exchange_n(&c->resume_q[i], (struct ice_ctx *)0,
					  __ATOMIC_ACQUIRE);
		if (got)
			conn_free_agent(c, got->agent, got);
	}
}


static void conn_free(struct conn *c)
{
	if (!c)
		return;
	conn_dissolve(c);
	conn_release(c);
}

#define HOST_IDLE_MS 3000		/* exit after this idle once we have served */

struct worker {
	pthread_t th;
	struct conn *c;
	/*
	 * Set by the worker as it returns, polled by the main thread to know
	 * the thread can be joined and the peer's row taken down. Volatile
	 * orders nothing between threads; a lock does.
	 */
	pthread_mutex_t done_lock;
	int done;
	int used;
};

static void worker_set_done(struct worker *w)
{
	pthread_mutex_lock(&w->done_lock);
	w->done = 1;
	pthread_mutex_unlock(&w->done_lock);
}

static int worker_done(struct worker *w)
{
	int v;

	pthread_mutex_lock(&w->done_lock);
	v = w->done;
	pthread_mutex_unlock(&w->done_lock);
	return v;
}

/* Each served peer's link, whenever one moves. */
static void report_peer_link_one(const struct session_obs *o, struct sess *s,
				 struct conn *c)
{
	int st = conn_link_state(s, c);
	int np = conn_proven_paths(c);
	int rtt = 0;

	if (!conn_rtt_ms(c, &rtt))
		rtt = -1;		/* nothing measured; 0 is under a ms */
	if (c->link_told_any && c->link_told == st && c->rtt_told == rtt &&
	    c->paths_told == np)
		return;
	c->link_told = st;
	c->rtt_told = rtt;
	c->paths_told = np;
	c->link_told_any = 1;
	o->peer_link(o->arg, c->pr.id, st, rtt, np);
}

static void report_peer_links(struct sess *s, struct worker *ws)
{
	const struct session_obs *o = s->cfg->obs;
	int i;

	if (!o || !o->peer_link)
		return;
	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (ws[i].used)
			report_peer_link_one(o, s, ws[i].c);
}

/* The peer's stable identity for the dashboard: a truncated copy of the claim
 * ufrag, sent once as its row is opened. */
static void emit_peer_ident(const struct session_obs *o, struct conn *c)
{
	char id8[9];

	if (!o || !o->peer_ident || !c->claim_ufrag[0])
		return;
	snprintf(id8, sizeof(id8), "%.8s", c->claim_ufrag);
	o->peer_ident(o->arg, c->pr.id, id8);
}

/* A worker runs one connected client's session on the shared command (tmux
 * attach), without driving sig -- that stays with the host's main thread. */
static void *worker_thread(void *p)
{
	struct worker *w = p;

	conn_run(w->c, 0);
	worker_set_done(w);
	return NULL;
}

static int worker_spawn(struct worker *ws, struct conn *c)
{
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (!ws[i].used) {
			ws[i].c = c;
			if (pthread_mutex_init(&ws[i].done_lock, NULL))
				return -1;
			ws[i].done = 0;
			ws[i].used = 1;
			/* The DHT host's clock starts here, where a client is
			 * actually being served. Anything else armed at the
			 * start and has a deadline already. */
			if (c->sess->cfg->test_roam_ms > 0 &&
			    !c->sess->next_roam_ms)
				c->sess->next_roam_ms = now_ms() +
					(uint64_t)c->sess->cfg->test_roam_ms;
			if (pthread_create(&ws[i].th, NULL, worker_thread,
					   &ws[i])) {
				pthread_mutex_destroy(&ws[i].done_lock);
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
		if (ws[i].used && !worker_done(&ws[i]) &&
		    !strcmp(ws[i].c->claim_ufrag, ufrag))
			return ws[i].c;
	return NULL;
}


/*
 * Has anything ever come back over this connection? A punch connecting proves
 * the host's half of it and says nothing whatever about the client's, so until
 * a pong has arrived there is no evidence a session exists here at all -- and
 * "lost" cannot stand in, since a link that was never up never goes down.
 */
static int conn_is_proven(struct conn *c)
{
	struct ctlplane_live live;

	ctlplane_liveness(&c->pr.cp, &live);

	return live.pong_seen;
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

/*
 * A claimant we are already punching at has asked again, under a password we
 * have not punched at. Its previous attempt is over as far as it is concerned
 * -- it would not have minted a new one otherwise -- so let the new one take
 * that punch's place instead of being refused until the old one times out.
 *
 * This is what carries a resumption through. The returning client keeps its
 * ufrag so the worker holding its session is found again, and everything that
 * session owns comes back with it: the shell, the forwarded ports, whatever
 * is queued in either direction. Making it wait out a punch it has already
 * abandoned is how that gets thrown away instead.
 *
 * The same password is the opposite case: the DHT serving its previous claim
 * again, which must not disturb the punch already running for it.
 */
static int punch_tried_again(const struct sess *s, const char *ufrag,
			     const char *pwd)
{
	int i;

	if (!ufrag[0] || !pwd[0])
		return 0;
	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->punching[i] &&
		    !strcmp(s->punching[i]->punch_ufrag, ufrag))
			return strcmp(s->punching[i]->remote_pwd, pwd) != 0;
	return 0;
}

static struct conn *punch_by_ufrag(struct sess *s, const char *ufrag)
{
	int i;

	if (!ufrag[0])
		return NULL;
	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->punching[i] &&
		    !strcmp(s->punching[i]->punch_ufrag, ufrag))
			return s->punching[i];
	return NULL;
}

static void punch_amend_repost(struct sess *s, const char *ufrag,
			       const char *pwd)
{
	struct conn *pc = punch_by_ufrag(s, ufrag);

	if (pc && !strcmp(pc->remote_pwd, pwd))
		conn_amend_remote(pc, s);
}

/* Is a punch for this exact claim (ufrag and password) already in flight? A
 * repeat under the same password is the DHT re-serving a claim being punched. */
static int punch_dup(const struct sess *s, const char *ufrag, const char *pwd)
{
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->punching[i] &&
		    !strcmp(s->punching[i]->punch_ufrag, ufrag) &&
		    !strcmp(s->punching[i]->remote_pwd, pwd))
			return 1;
	return 0;
}

/* How many punches for this claimant are in flight. */
static int punch_count(const struct sess *s, const char *ufrag)
{
	int i, n = 0;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->punching[i] &&
		    !strcmp(s->punching[i]->punch_ufrag, ufrag))
			n++;
	return n;
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
		struct path_ep self_ep;
		struct conn *c;
		int slot = -1;

		if (lanlink_map_peer((struct sockaddr *)&s->lan_pending[p].sa,
				     s->lan_pending[p].len, &mapped))
			continue;
		if (lan_conn_active(s, &mapped))
			continue;		/* a re-broadcast during setup */
		if (!path_ep_from_sockaddr(&self_ep,
					   (const struct sockaddr *)&mapped,
					   sizeof(mapped)) &&
		    sess_ep_is_self(s, &self_ep))
			continue;		/* a claim aimed at ourselves */
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
		pthread_mutex_lock(&c->claim_lock);
		snprintf(c->claim_ufrag, sizeof(c->claim_ufrag), "%s",
			 s->lan_pending[p].ufrag);
		pthread_mutex_unlock(&c->claim_lock);
		if (c->claim_ufrag[0]) {
			snprintf(s->last_served_ufrag,
				 sizeof(s->last_served_ufrag), "%s",
				 c->claim_ufrag);
			s->have_served = 1;
		}
		s->admitted_n++;
		c->pr.id = ++*dash_seq;
		snprintf(c->status_peer, sizeof(c->status_peer), "%s", addr);
		s->lan_conns[slot] = c;
		/* Said here too: a client whose segment path ended because one
		 * of them roamed comes back this way when they are on a
		 * segment again, and it is no better placed to tell a new
		 * worker from its old one than a punched one is. */
		conn_tell_fresh(c, &mapped);
		conn_register(s, c);
		if (o && o->peer) {
			o->peer(o->arg, c->pr.id, SESSION_PEER_SEEN, addr);
			o->peer(o->arg, c->pr.id, SESSION_PEER_LIVE, addr);
			emit_peer_ident(o, c);
			c->link_told_any = 0;
		}
		if (worker_spawn(ws, c)) {	/* worker table full */
			if (o && o->peer)
				o->peer(o->arg, c->pr.id, SESSION_PEER_GONE,
					addr);
			s->lan_conns[slot] = NULL;
			conn_free(c);
		}
	}
	s->lan_pending_n = 0;			/* drained; overflow re-offered */
}

/* Hand a grafted agent's context to the worker through a free queue slot. The
 * worker drains every slot each pass, so a free one is normally there. */
static void resume_q_publish(struct conn *t, struct ice_ctx *ctx)
{
	int i;

	for (i = 0; i < ICE_HOLD_MAX; i++)
		if (!__atomic_load_n(&t->resume_q[i], __ATOMIC_ACQUIRE)) {
			__atomic_store_n(&t->resume_q[i], ctx, __ATOMIC_RELEASE);
			return;
		}
	dbg_logf("host: resume queue full -- graft dropped");
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
static void punch_scan(struct sess *s, struct worker *ws, int *dash_seq)
{
	const struct session_obs *o = s->cfg->obs;
	char loc[192], rem[192], addr[80];
	struct conn *c;
	struct conn *t;
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++) {
		c = s->punching[i];
		if (!c)
			continue;
		if (!c->punch_stuck && nat_connected(c->nat)) {
			snprintf(s->last_served_ufrag, sizeof(s->last_served_ufrag),
				 "%.39s", c->punch_ufrag);
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
			t = c->punch_resume;
			if (!t)
				t = worker_by_ufrag(ws, c->punch_ufrag);
			if (t) {
				dbg_logf("host: punch connected -> resume "
					 "worker");
				if (c->nat_ctx) {
					/* Re-pointed before it is published:
					 * the release below is what makes both
					 * of these visible to the worker. */
					c->nat_ctx->shell = c;
					__atomic_store_n(&c->nat_ctx->c, t,
							 __ATOMIC_RELAXED);
					nat_rebind(c->nat, c->nat_ctx);
					resume_q_publish(t, c->nat_ctx);
				}
				c->nat = NULL;
				c->nat_ctx = NULL;
				snprintf(t->remote_pwd, sizeof(t->remote_pwd),
					 "%s", c->remote_pwd);
				if (c->punch_resume)
					__atomic_sub_fetch(&t->resume_pending, 1,
							   __ATOMIC_RELAXED);
				else if (s->admitted_n > 0)
					s->admitted_n--;
				s->punching[i] = NULL;
				/*
				 * Dissolved now, released when the agent it
				 * lent is destroyed: a callback that loaded
				 * this connection before the context was
				 * re-pointed is still inside it, and freeing
				 * it here tore the mutexes out from under
				 * that callback.
				 */
				conn_dissolve(c);
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
				 * pr.id keys the row for updates and GONE. */
				c->pr.id = ++*dash_seq;
				snprintf(c->status_peer, sizeof(c->status_peer),
					 "%s", addr);
				o->peer(o->arg, c->pr.id, SESSION_PEER_SEEN,
					addr);
				o->peer(o->arg, c->pr.id, SESSION_PEER_LIVE,
					addr);
				emit_peer_ident(o, c);
				c->link_told_any = 0;
			}
			s->punching[i] = NULL;
			/*
			 * Said before it is served, and only to a claimant we
			 * have served before: that one thought it was resuming
			 * and learns here that it is not, so it can go round
			 * again at once rather than waiting out the silence
			 * that would eventually tell it. A claimant joining for
			 * the first time has no session of its own to be told
			 * about, and telling it would end the one it is in.
			 */
			if (claim_served_has(&s->served, c->punch_ufrag))
				conn_tell_fresh(c, NULL);
			claim_served_note(&s->served, c->punch_ufrag,
					  c->remote_pwd);
			conn_register(s, c);
			if (worker_spawn(ws, c))
				conn_free(c);		/* table full */
		/*
		 * A resumption gets the long budget because a client coming
		 * back may be slow to reappear -- but only one that has a
		 * session to come back to. Resuming a worker that never carried
		 * anything is a first punch in all but name, and giving it the
		 * long budget holds the claimant's identity for a minute and a
		 * half while the client it belongs to is asking once a second
		 * and being told a punch is already running for it.
		 */
		} else if (now_ms() - c->punch_start_ms >
			   ((c->punch_resume && conn_is_proven(c->punch_resume)) ?
			    ICE_ATTEMPT_MS : HOST_PUNCH_MS) ||
			   (!c->punch_stuck && nat_failed(c->nat))) {
			dbg_logf("host: punch %s -> drop",
				 c->punch_stuck ? "wedged (test)" : "failed");
			if (c->punch_resume) {
				__atomic_sub_fetch(&c->punch_resume->resume_pending,
						   1, __ATOMIC_RELAXED);
			} else if (s->admitted_n > 0) {
				/* It was counted against the grant when it was
				 * picked up, and it admitted nobody. Left spent,
				 * one failed punch is enough to close a
				 * --max-clients 1 grant against the very client
				 * it was opened for. A resumption never counted
				 * in the first place. */
				s->admitted_n--;
			}
			s->punching[i] = NULL;
			conn_free(c);
		}
	}
}

/* Free the longest-running punch for a claimant, to admit a fresher one at the
 * parallel cap: the oldest is on the oldest offer generation, so it is the one
 * a returning client is least likely to still be answering. */
static void punch_reap_oldest(struct sess *s, const char *ufrag)
{
	uint64_t oldest = 0;
	int i, victim = -1;
	struct conn *c;

	for (i = 0; i < HOST_MAX_WORKERS; i++) {
		c = s->punching[i];
		if (!c || strcmp(c->punch_ufrag, ufrag))
			continue;
		if (victim < 0 || c->punch_start_ms < oldest) {
			oldest = c->punch_start_ms;
			victim = i;
		}
	}
	if (victim < 0)
		return;
	c = s->punching[victim];
	if (c->punch_resume)
		__atomic_sub_fetch(&c->punch_resume->resume_pending, 1,
				   __ATOMIC_RELAXED);
	else if (s->admitted_n > 0)
		s->admitted_n--;
	s->punching[victim] = NULL;
	conn_free(c);
}

/*
 * A host with any signalling backend serves many clients through the turnstile:
 * DHT/ICE joins arrive over the mailbox, and same-segment multicast claimants
 * are admitted over the one shared lanlink socket (demultiplexed by source),
 * both concurrently on the shared tmux. An isolated LAN with no DHT is no longer
 * capped at one client. Only the test-only single-connection flag forces the
 * sequential re-serve state machine instead.
 */

/* Whether an offer has anything in it at all for a peer to aim at. */
static int sdp_has_candidate(const char *sdp)
{
	return strstr(sdp, "a=candidate:") != NULL;
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
 * direct endpoint names its port. The new sig is seeded from the anchors the
 * model holds -- found here, or handed over CTLM_RDV -- so it starts from a
 * node the peer holds too.
 *
 * Callers must run this on the thread that owns sig, with no sig callback in
 * flight: at the top of the owning loop, between one sig_dispatch and the next
 * sig_prepare, never from a callback sig_dispatch is still unwinding. Returns 0,
 * or -1 when there is no signalling left to run the session on.
 */
/*
 * The mailbox is engaged and nothing answers it: reads were coming back and
 * now none does. A rendezvous that died, a mapping the carrier moved, a
 * middlebox that timed the flow out -- none of which changes an address here,
 * so the move machinery never fires and the session sits on a slot nobody is
 * serving, with nothing to say so. Rebuilding is invisible to a peer -- the
 * mailbox is the same, only the socket and the node behind it are new -- so
 * the cost of being wrong is one bootstrap. sig_quiet() weighs it.
 */
static int sig_idle_s(struct sig *sig)
{
	struct sig_mailbox sm;

	sig_mailbox_state(sig, &sm);
	if (!sm.last_get_ms)
		return -1;
	return (int)((now_ms() - sm.last_get_ms) / 1000);
}


/* Offer agents rotated away but kept un-primed, so a claim naming one is
 * punched with the exact agent the client primed. Each is a poll thread. */
#define OFFER_KEEP_MAX 3
#define OFFER_KEEP_MS 10000
struct kept_offer {
	struct conn *c;
	uint64_t until_ms;
};

static void offer_retire(struct sess *s, struct kept_offer *ring,
			 struct conn **lp, int published, uint64_t now)
{
	struct conn *c = *lp;
	int i;

	*lp = NULL;
	s->offer_conn = NULL;
	if (!c)
		return;
	if (published)
		for (i = 0; i < OFFER_KEEP_MAX; i++)
			if (!ring[i].c) {
				ring[i].c = c;
				ring[i].until_ms = now + OFFER_KEEP_MS;
				return;
			}
	conn_free(c);
}

static void offer_gc(struct kept_offer *ring, uint64_t now)
{
	int i;

	for (i = 0; i < OFFER_KEEP_MAX; i++) {
		if (!ring[i].c)
			continue;
		if (now < ring[i].until_ms && !nat_failed(ring[i].c->nat))
			continue;
		conn_free(ring[i].c);
		ring[i].c = NULL;
		ring[i].until_ms = 0;
	}
}

static void offer_free_all(struct kept_offer *ring)
{
	int i;

	for (i = 0; i < OFFER_KEEP_MAX; i++) {
		conn_free(ring[i].c);
		ring[i].c = NULL;
		ring[i].until_ms = 0;
	}
}

static int offer_find(struct kept_offer *ring, const char *uf)
{
	int i;

	if (!uf || !uf[0])
		return -1;
	for (i = 0; i < OFFER_KEEP_MAX; i++)
		if (ring[i].c && !strcmp(ring[i].c->ice_ufrag, uf))
			return i;
	return -1;
}

static int punch_take(struct sess *s, struct conn *pc, struct conn *resume,
		      int pslot, const char *cu, const char *cp,
		      const char *filtered, int stuck)
{
	if (nat_set_remote_description(pc->nat, filtered))
		return -1;
	snprintf(pc->remote_ufrag, sizeof(pc->remote_ufrag), "%s", cu);
	snprintf(pc->remote_pwd, sizeof(pc->remote_pwd), "%s", cp);
	if (resume) {
		__atomic_add_fetch(&resume->resume_pending, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&resume->resume_last_ms, now_ms(),
				 __ATOMIC_RELAXED);
	} else if (!ufrag_admitted(s, cu)) {
		s->admitted_n++;
	}
	s->punching[pslot] = pc;
	pc->punch_resume = resume;
	pthread_mutex_lock(&pc->claim_lock);
	snprintf(pc->claim_ufrag, sizeof(pc->claim_ufrag), "%s", cu);
	pthread_mutex_unlock(&pc->claim_lock);
	pc->punch_start_ms = now_ms();
	pc->punch_stuck = stuck;
	snprintf(pc->punch_ufrag, sizeof(pc->punch_ufrag), "%s", cu);
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
	struct kept_offer kept[OFFER_KEEP_MAX];
	struct worker ws[HOST_MAX_WORKERS];
	struct conn *listen = NULL;
	struct conn *pc;
	char co[40];
	int again;
	int ko;
	enum { TS_GATHER, TS_WAIT_CLAIM } ts = TS_GATHER;
	uint64_t deadline = now_ms() + (uint64_t)cfg->connect_timeout_s * 1000;
	uint64_t last_active = now_ms();
	uint64_t wind;
	char filtered[NAT_SDP_MAX];
	sock_t end_fd = cfg->ssh_end_fd;
	int served = 0, dash_seq = 0, i, j;
	int stuck_left = cfg->test_stuck_punches;

	memset(ws, 0, sizeof(ws));
	memset(kept, 0, sizeof(kept));
	memset(s->punching, 0, sizeof(s->punching));
	s->last_served_ufrag[0] = '\0';
	s->have_served = 0;

	while (cfg->host_serve_max == 0 || served < cfg->host_serve_max) {
		int active = 0;

		pump_once(s, 100);		/* the main thread owns sig + lan */
		net_watch(s, now_ms());		/* notice a move first: a pass
						 * that adopted a node and then
						 * found the network gone would
						 * have adopted it onto the one
						 * we have left */
		peer_in_drain(s);		/* what each peer has said */
		session_advance(s);		/* settle it, and publish */
		maybe_announce_rendezvous(s);	/* report the rendezvous */
		report_mailbox(s);
		token_pump(s);			/* mint and advertise the token */
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
		if (net_moved(s)) {
			if (listen) {
				conn_free(listen);
				listen = NULL;
				s->offer_conn = NULL;
			}
			offer_free_all(kept);
			if (cfg->test_roam_hard)
				for (i = 0; i < HOST_MAX_WORKERS; i++)
					if (ws[i].used)
						pathplane_blackhole_mute(
							&ws[i].c->pr.pl, 1);
			if (sig_rebuild(s, "on the new network"))
				break;
			net_change_reset(s);
			ts = TS_GATHER;
		}
		/*
		 * Or nothing moved and the rendezvous went quiet anyway. What
		 * is published stays published, but a mailbox that answers
		 * nothing serves nobody, so arm a fresh signaller and offer
		 * through it. The network's own facts -- the egress pool, the
		 * mapping -- are still this network's and are kept.
		 */
		if (sig_quiet(s->pm.sig)) {
			dbg_logf("sig: nothing back from the rendezvous for "
				 "%ds -- rebuilding", sig_idle_s(s->pm.sig));
			if (listen)
				offer_retire(s, kept, &listen,
					     ts == TS_WAIT_CLAIM, now_ms());
			if (sig_rebuild(s, "after the rendezvous went quiet"))
				break;
			ts = TS_GATHER;
		}

		trickle_flush(s, o, ts == TS_WAIT_CLAIM);
		if (o) {			/* dashboard: local candidates */
			if (o->net && sdp_ready(s))
				obs_report_net(s);
			if (o->tick)
				o->tick(o->arg);
		}

		for (i = 0; i < HOST_MAX_WORKERS; i++) {
			if (ws[i].used && worker_done(&ws[i])) {
				pthread_join(ws[i].th, NULL);
				if (o && o->peer)
					o->peer(o->arg, ws[i].c->pr.id,
						SESSION_PEER_GONE,
						ws[i].c->status_peer);
				/* Unregister a LAN worker so a rejoining client
				 * (same endpoint) is admitted afresh. */
				pthread_mutex_destroy(&ws[i].done_lock);
				for (j = 0; j < HOST_MAX_WORKERS; j++)
					if (s->lan_conns[j] == ws[i].c)
						s->lan_conns[j] = NULL;
				/* A punch that was resuming this worker loses
				 * its target and proceeds as a fresh admission
				 * -- the client wanted its session back, but a
				 * new one beats none. */
				for (j = 0; j < HOST_MAX_WORKERS; j++)
					if (s->punching[j] &&
					    s->punching[j]->punch_resume == ws[i].c)
						s->punching[j]->punch_resume = NULL;
				if (ws[i].c->claim_ufrag[0])
					for (j = 0; j < HOST_MAX_WORKERS; j++)
						if (s->punching[j] &&
						    !strcmp(s->punching[j]->punch_ufrag,
							    ws[i].c->claim_ufrag)) {
							s->punching[j]->punch_ufrag[0]
								= '\0';
							break;
						}
				/*
				 * And it stops being the claimant we have just
				 * served. That memory exists to keep one pickup
				 * from being served twice while its claim is
				 * still in the slot; once the session it was
				 * served for is gone, the same claimant asking
				 * again is a client wanting in, not a repeat.
				 * A claimant identity is stable across a
				 * rejoin, so leaving it here refused that
				 * client for the rest of the session.
				 */
				dbg_logf("host: reap worker %.8s",
					 ws[i].c->claim_ufrag);
				if (ws[i].c->claim_ufrag[0] && s->have_served &&
				    !strcmp(s->last_served_ufrag,
					    ws[i].c->claim_ufrag)) {
					s->last_served_ufrag[0] = '\0';
					s->have_served = 0;
				}
				/*
				 * Counted as served only if it ever carried
				 * anything. A punch that connected on this side
				 * and then produced no session served nobody,
				 * and a host told to serve N would otherwise
				 * spend its whole grant on failed punches and
				 * exit while the client it was meant for was
				 * still asking. Its admission goes back for the
				 * same reason.
				 */
				if (conn_is_proven(ws[i].c)) {
					served++;
				} else if (s->admitted_n > 0) {
					s->admitted_n--;
					dbg_logf("host: worker %.8s carried "
						 "nothing -- not counted",
						 ws[i].c->claim_ufrag);
				}
				conn_free(ws[i].c);
				ws[i].used = 0;
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
					o->peer(o->arg, ws[i].c->pr.id,
						SESSION_PEER_LIVE, cur);
				}
			}
			/* The ssh thread learns the grade a beat after the row
			 * appears (it is decided at auth); mark it once known. */
			if (o && o->peer_ro &&
			    __atomic_load_n(&ws[i].c->read_only,
					    __ATOMIC_RELAXED) &&
			    !ws[i].c->ro_reported) {
				ws[i].c->ro_reported = 1;
				o->peer_ro(o->arg, ws[i].c->pr.id);
			}
			/* A forwarding attempt the ssh thread refused: surface
			 * it once so the operator sees the attempted tunnel. */
			if (o && o->peer_fwd_refused && ws[i].c->fwd_refused &&
			    !ws[i].c->fwd_reported) {
				ws[i].c->fwd_reported = 1;
				o->peer_fwd_refused(o->arg, ws[i].c->pr.id);
			}
		}

		/* Advance in-flight punches (connect -> worker, wedged -> freed),
		 * concurrently with the listener below. An in-flight punch keeps the
		 * host non-idle. */
		report_peer_links(s, ws);
		punch_scan(s, ws, &dash_seq);
		offer_gc(kept, now_ms());
		for (i = 0; i < HOST_MAX_WORKERS; i++)
			if (s->punching[i])
				active = 1;

		/*
		 * The advertised offer was gathered through a pool server that
		 * produced no public v4: retire the listener and offer again
		 * through the next one. Claims in flight are untouched -- only
		 * the listener rotates, exactly as when an answer cannot be
		 * taken up.
		 */
		pool_pump(s);
		if (ts == TS_WAIT_CLAIM && listen && !s->have_peer_sdp &&
		    stun_stall(s)) {
			/* Named, like the claim verdicts: an offer with no
			 * public address in it looks from here exactly like one
			 * that works, and this is the only thing that says
			 * which pool server it was gathered through. */
			dbg_logf("host: no public v4 through pool server %d "
				 "-- offering through the next (%d of %d)",
				 s->ice_attempt % s->stun_count,
				 s->stun_rotations + 1, STUN_ROTATE_MAX);
			__atomic_add_fetch(&s->ice_attempt, 1, __ATOMIC_RELAXED);
			s->stun_rotations++;
			offer_retire(s, kept, &listen, 1, now_ms());
			s->have_local_sdp = 0;
			s->local_sdp[0] = '\0';
			ts = TS_GATHER;
		}

		switch (ts) {
		case TS_GATHER:
			if (!listen && now_ms() >= s->next_gather_ms) {
				listen = conn_alloc(s);
				if (!listen)
					break;
				s->have_local_sdp = 0;
				s->have_peer_sdp = 0;
				s->remote_set = 0;
				s->local_sdp[0] = '\0';
				s->peer_sdp[0] = '\0';
				s->offer_conn = listen;
				sig_subscribe(s->pm.sig, on_peer_offer, s);
				if (nat_setup(listen)) {
					conn_free(listen);
					listen = NULL;
					s->offer_conn = NULL;
					break;
				}
			}
			if (sdp_ready(s)) {
				sdp_filter(s->local_sdp, cfg->family, filtered,
					   sizeof(filtered));
				snprintf(s->local_sdp, sizeof(s->local_sdp),
					 "%s", filtered);
				/*
				 * Gathering finished and found nothing -- the
				 * interfaces were still coming up when this
				 * agent was made, which is exactly what a move
				 * looks like from here. The description is a
				 * snapshot taken when gathering ended, so
				 * nothing will be added to it later: waiting
				 * would wait for ever.
				 *
				 * Publishing it is worse than waiting. The
				 * mailbox holds one offer, so an empty one does
				 * not merely fail to help, it replaces the
				 * working offer a peer was about to claim
				 * against with one that names nowhere to go.
				 * Start again instead, and leave what is
				 * published alone until there is something
				 * better to say.
				 */
				if (!sdp_has_candidate(s->local_sdp)) {
					dbg_logf("host: gathered no candidates "
						 "-- not offering, regathering");
					conn_free(listen);
					listen = NULL;
					s->offer_conn = NULL;
					s->have_local_sdp = 0;
					s->local_sdp[0] = '\0';
					s->next_gather_ms = now_ms() +
							    HOST_REGATHER_MS;
					break;
				}
				/*
				 * Gathered something, but nothing a peer off
				 * this segment could aim at: the pool server
				 * this description was gathered through said
				 * nothing, and what is left is private host
				 * candidates. Publishing that fills the one
				 * mailbox slot with an offer only the segment
				 * can take up, which is indistinguishable from
				 * a working one until a punch fails. Gather
				 * again through the next server instead, while
				 * the budget lasts; when it is spent, a
				 * segment-only offer is still better than
				 * none, and the peer may well be on it.
				 */
				if (!cand_sdp_reaches_off_segment(s->local_sdp) &&
				    stun_rotate_ok(s)) {
					dbg_logf("host: nothing off-segment to "
						 "offer through pool server %d "
						 "-- gathering through the next "
						 "(%d of %d)",
						 s->ice_attempt % s->stun_count,
						 s->stun_rotations + 1,
						 STUN_ROTATE_MAX);
					__atomic_add_fetch(&s->ice_attempt, 1, __ATOMIC_RELAXED);
					s->stun_rotations++;
					conn_free(listen);
					listen = NULL;
					s->offer_conn = NULL;
					s->have_local_sdp = 0;
					s->local_sdp[0] = '\0';
					s->next_gather_ms = now_ms() +
							    HOST_REGATHER_MS;
					break;
				}
				s->net.pool.posted = fan_local_sdp(s);
				sig_rotate(s->pm.sig, (const uint8_t *)s->local_sdp,
					   strlen(s->local_sdp));
				sig_locate(s->pm.sig);
				log_offer(s->local_sdp, served, active);
				ts = TS_WAIT_CLAIM;
			}
			break;
		case TS_WAIT_CLAIM:
			if (s->have_peer_sdp && !s->remote_set) {
				struct conn *resume = NULL;
				char cu[40], cp[40];
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
				cand_sdp_ufrag(s->peer_sdp, cu, sizeof(cu));
				sdp_pwd(s->peer_sdp, cp);
				sig_claim_offer(s->pm.sig, co, sizeof(co));
				if (cu[0]) {
					struct conn *w = worker_by_ufrag(ws, cu);
					int adm = ufrag_admitted(s, cu);
					int lanq = lan_pending_ufrag(s, cu);
					int just = s->have_served &&
						   !strcmp(cu,
							   s->last_served_ufrag);
					int made = w && claim_made(w->remote_pwd,
								   cp);

					again = punch_tried_again(s, cu, cp);
					if (!made)
						made = claim_served_made(&s->served,
									 cu, cp);
					/* Named, because which of these decided
					 * it is the whole story when a client
					 * cannot get in and nobody can say why. */
					dbg_logf("host: claim %.8s pwd %.6s: "
						 "worker=%d again=%d admitted=%d "
						 "lanq=%d justserved=%d made=%d "
						 "offer=%.8s",
						 cu, cp, w ? 1 : 0, again, adm,
						 lanq, just, made,
						 co[0] ? co : "-");

					punch_amend_repost(s, cu, cp);

					/*
					 * The very attempt this worker was
					 * punched for, handed back by the
					 * mailbox a moment later. A client
					 * that wants a resumption mints a new
					 * password for it (conn_fresh_pwd), so
					 * an unchanged one is the DHT talking,
					 * not the client -- and punching it
					 * again disturbs the session it just
					 * got.
					 */
					/* The DHT re-serving a claim already in
					 * hand: leave it and free the mutex slot. */
					if (made || punch_dup(s, cu, cp) || lanq) {
						dbg_logf("host: claim %.8s already "
							 "in hand -- leaving it",
							 cu);
						sig_release(s->pm.sig);
						s->have_peer_sdp = 0;
						break;
					}
					if (w && !conn_is_lost(w) &&
					    conn_is_proven(w)) {
						dbg_logf("host: ignore claim %.8s "
							 "(healthy worker)", cu);
						sig_release(s->pm.sig);
						s->have_peer_sdp = 0;
						break;
					}
					if (punch_count(s, cu) >=
					    PUNCH_PARALLEL_MAX) {
						dbg_logf("host: claim %.8s at the "
							 "cap -- reap the oldest",
							 cu);
						punch_reap_oldest(s, cu);
					}
					resume = w;
				}
				/* Neither listening nor kept: the listener's
				 * credentials are not the ones it primed, so a
				 * punch cannot land. */
				if (co[0] && offer_find(kept, co) < 0 &&
				    strcmp(co, listen->ice_ufrag)) {
					dbg_logf("host: claim %.8s names the retired "
						 "offer %.8s -- released", cu, co);
					sig_release(s->pm.sig);
					s->have_peer_sdp = 0;
					break;
				}
				/* A fresh claimant past the admission budget is
				 * left unserved; a resumption always passes. */
				if (!resume && !ufrag_admitted(s, cu) &&
				    cfg->host_admit_max &&
				    s->admitted_n >= cfg->host_admit_max) {
					dbg_logf("host: admission budget spent "
						 "-- claim ignored");
					sig_release(s->pm.sig);
					s->have_peer_sdp = 0;
					break;
				}
				/* Room to punch? (a free in-flight slot within the
				 * combined worker + punch budget). If not, keep the
				 * claim advertised and pick it up once room frees. */
				for (i = 0; i < HOST_MAX_WORKERS; i++) {
					if (ws[i].used)
						inflight++;
					if (s->punching[i]) {
						inflight++;
						continue;
					}
					if (pslot < 0)
						pslot = i;
				}
				if (pslot < 0 || inflight >= HOST_MAX_WORKERS)
					break;
				dbg_logf(resume ?
					 "host: resume claim -> punch (release) %.8s" :
					 "host: claim received -> punch (release) %.8s",
					 cu);
				sdp_filter_peer(s->peer_sdp, cfg->family, filtered,
					   sizeof(filtered));
				ko = offer_find(kept, co);
				pc = ko >= 0 ? kept[ko].c : listen;
				if (punch_take(s, pc, resume, pslot, cu, cp,
					       filtered, stuck_left > 0)) {
					conn_free(pc);
					if (ko >= 0) {
						kept[ko].c = NULL;
						kept[ko].until_ms = 0;
						break;
					}
					listen = NULL;
					s->offer_conn = NULL;
					ts = TS_GATHER;
					break;
				}
				if (stuck_left > 0)
					stuck_left--;
				if (ko >= 0) {
					dbg_logf("host: punched %.8s on the kept "
						 "offer %.8s", cu, co);
					kept[ko].c = NULL;
					kept[ko].until_ms = 0;
					sig_release(s->pm.sig);
					s->have_peer_sdp = 0;
				} else {
					listen = NULL;
					ts = TS_GATHER;
				}
			}
			break;
		}

		/*
		 * The real host runs until its shared tmux ends (the end monitor
		 * signals end_fd, as it does for each worker's sshd), and the
		 * harness answers the same monitor from its own SIGTERM, so a
		 * host under test stops when it is asked to rather than running
		 * to its deadline. Without a monitor at all it is bounded by the
		 * deadline, or exits once idle having served at least one
		 * client.
		 */
		if (sock_isset(end_fd)) {
			struct pollfd ef;

			ef.fd = end_fd;
			ef.events = POLLIN;
			ef.revents = 0;
			if (sock_poll(&ef, 1, 0) > 0 &&
			    (ef.revents & (POLLIN | POLLHUP | POLLERR))) {
				/* Not this attempt running out: the shared
				 * session is gone, and the invitation to it
				 * has to stop saying otherwise. */
				s->session_over = 1;
				break;
			}
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
	offer_free_all(kept);
	/*
	 * Say the session is over before winding the workers down, and keep
	 * driving the model while they go. A worker lingers to land its
	 * end-of-session signal on a client that may be slow to ack, and a join
	 * that stopped pumping for that long would put the whole store behind
	 * it -- with the operator's shell waiting on the sum of the two rather
	 * than on the longer of them.
	 */
	if (s->session_over)
		session_entomb_start(s);
	wind = now_ms() + SESSION_WIND_MS;
	for (i = 0; i < HOST_MAX_WORKERS; i++) {
		if (s->punching[i])
			conn_free(s->punching[i]);
		if (!ws[i].used)
			continue;
		while (s->session_over && !worker_done(&ws[i]) &&
		       !deadline_passed(wind, now_ms()))
			pump_once(s, 50);
		pthread_join(ws[i].th, NULL);
		pthread_mutex_destroy(&ws[i].done_lock);
		conn_free(ws[i].c);
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
		report_links(s);
		if (!cfg->is_host)
			client_direct_connect(s);
	}
	return 0;
}

int session_run(const struct session_cfg *cfg)
{
	struct sess s;
	enum state st = ST_WAIT_DHT;
	struct stream *st_done;
	uint64_t deadline;
	int ended = 0;			/* SESSION_ENDED / SESSION_GONE */
	int rc;

	memset(&s, 0, sizeof(s));
	s.cfg = cfg;
	s.c.sess = &s;
	s.c.ctl_fd = INVALID_SOCK;		/* no control channel until run_ssh */
	memcpy(s.auth, cfg->tok.auth, TOKEN_AUTH_LEN);
	/* Seed each family from the token handed in, so a re-serve carries the
	 * anchor it already published forward instead of wiping the slot. */
	s.tok_state[0] = token_family_state(&cfg->tok, 4);
	s.tok_state[1] = token_family_state(&cfg->tok, 6);
	if (keys_derive(&s.keys, cfg->tok.rdv))
		return 1;
	pthread_mutex_init(&s.trickle_lock, NULL);
	pthread_mutex_init(&s.c.status_lock, NULL);	/* s.c.status zeroed = connecting */
	peering_init(&s.c.pr, &s.pm, s.keys.probe_magic, s.keys.sig_key,
		     now_ms());
	conn_peering_sinks(&s.c);
	pthread_mutex_init(&s.c.stream_lock, NULL);
	pthread_mutex_init(&s.c.claim_lock, NULL);
	netmon_init(&s.netmon);
	netmon_src_open(&s.netmon);
	peering_model_init(&s.pm, cfg->is_host,
			   (cfg->sig_flags & SIG_DHT) != 0, cfg->obs,
			   now_ms());
	/*
	 * When the synthetic change is armed follows the path the session
	 * meets over, and nothing else. A host whose rendezvous is the DHT
	 * waits for the first client it serves: the arrival it has to be
	 * disturbing is gated on a lookup with no bound, so a clock started
	 * here is a race the margin only hides for as long as the lookup
	 * stays quick. Every other session arms now, because there is nothing
	 * unbounded to wait for -- a client roams from its own start, and a
	 * host on a LAN segment is reachable the moment it is up, so it can
	 * be moved before anyone has arrived.
	 */
	s.next_roam_ms = (host_is_multiuser(cfg) && (cfg->sig_flags & SIG_DHT))
		? 0 : now_ms() + (uint64_t)cfg->test_roam_ms;
	if (cfg->stun_auto)
		s.stun_servers = stunlist_load(&s.stun_count);
	/* An operator-pinned STUN server is theirs alone to talk to, so the
	 * machine is told whether it may ask the list at all. */
	peering_net_init(&s.net, s.stun_servers, s.stun_count,
			 !cfg->stun_host && cfg->stun_auto);
	/* Start the rotation at a random server: it spreads the install base
	 * across the community pool instead of hammering whoever is listed
	 * first, and one dead head entry no longer disables STUN for
	 * everybody. */
	if (s.stun_count > 1) {
		uint8_t rb[2];

		random_bytes(rb, 2);
		__atomic_store_n(&s.ice_attempt,
				 ((rb[0] << 8) | rb[1]) % s.stun_count,
				 __ATOMIC_RELAXED);
	}
	/* Resolve the pool into the cache off the loop, so the probe threads read
	 * addresses instead of blocking on a name lookup after a move. */
	if (cfg->stun_auto && s.stun_count > 0 &&
	    !stun_pool_warm_start(s.stun_servers, s.stun_count, &s.warm_stop,
				  &s.warm_th))
		s.warm_running = 1;
	/* The probes are scheduled by the reachability model, which asks for the
	 * first round on its first tick. */
	nat_log_level(cfg->log_level);	/* < 0 silences libjuice (see nat_log_level) */

	conn_gen_ice(&s.c);

	if (sig_setup(&s)) {
		rc = 1;
		goto done;
	}

	s.start_ms = now_ms();
	/*
	 * Zero means keep trying. Nothing about a rendezvous that has not
	 * answered yet says it never will -- a DHT converges when it converges,
	 * a network comes back when the operator walks into range -- so a
	 * deadline can only ever end an attempt that would have succeeded. The
	 * operator ends it instead, which is the one judgement that is never
	 * wrong.
	 */
	deadline = cfg->connect_timeout_s > 0 ?
		   s.start_ms + (uint64_t)cfg->connect_timeout_s * 1000 : 0;

	/*
	 * A DHT host serves many clients through the turnstile (multi-user),
	 * whether or not multicast is also on -- it serves same-LAN clients over
	 * ICE too (see host_is_multiuser). Only a host with no DHT at all (an
	 * isolated LAN) falls through to the single-connection state machine.
	 */
	if (host_is_multiuser(cfg)) {
		rc = host_turnstile(&s);
		if (s.session_over)
			session_entomb(&s);
		goto done;
	}

	while (st != ST_DONE && st != ST_FAIL && !ended &&
	       !(cfg->test_stop &&
		 __atomic_load_n(cfg->test_stop, __ATOMIC_RELAXED)) &&
	       !deadline_passed(deadline, now_ms())) {
		char filtered[NAT_SDP_MAX];
		const struct session_obs *o = cfg->obs;

		pump_once(&s, 100);
		net_pump(&s, now_ms());
		maybe_announce_rendezvous(&s);
		report_mailbox(&s);
		token_pump(&s);
		client_token_pump(&s);
		/*
		 * A host with one connection has no turnstile to notice the end
		 * in, so it is noticed here: the shared session is gone, and
		 * what is left to do is say so and stop offering it.
		 */
		if (cfg->is_host && sock_isset(cfg->ssh_end_fd) &&
		    !s.session_over) {
			struct pollfd ef;

			ef.fd = cfg->ssh_end_fd;
			ef.events = POLLIN;
			ef.revents = 0;
			if (sock_poll(&ef, 1, 0) > 0 &&
			    (ef.revents & (POLLIN | POLLHUP | POLLERR))) {
				s.session_over = 1;
				break;
			}
		}
		/*
		 * The mailbox says the session behind this invitation is over.
		 * A client that has been in it is being told the shared session
		 * ended; one that never got in is being told its invitation is
		 * spent. Either way there is nothing left to wait for, which is
		 * the whole reason the tombstone exists.
		 */
		if (!cfg->is_host && sig_peer_ended(s.pm.sig)) {
			ended = s.was_live ? SESSION_ENDED : SESSION_GONE;
			break;
		}
		/*
		 * Roamed before the link came up: rebuild the signalling on the
		 * interfaces that exist now, re-gather there and flush the
		 * dashboard's stale local addresses. Once running, a roam instead
		 * drops the link and returns through SSHC_RECONNECT, which rebuilds
		 * from there. pump_once above has finished dispatching, so no sig
		 * callback is in flight.
		 */
		if (st != ST_RUN && net_moved(&s)) {
			if (sig_rebuild(&s, "on the new network")) {
				st = ST_FAIL;
				break;
			}
			if (s.c.nat) {
				conn_drop_ice_path(&s.c);
				conn_free_agent(&s.c, s.c.nat, s.c.nat_ctx);
				s.c.nat = NULL;
				s.c.nat_ctx = NULL;
			}
			conn_gen_ice(&s.c);
			pathplane_clear(&s.c.pr.pl);
			net_change_reset(&s);
			st = ST_WAIT_DHT;
		}
		/*
		 * Or nothing moved and the rendezvous went quiet: the claim is
		 * written where nothing reads it. Arm a fresh signaller and
		 * claim through that instead, keeping what this network has
		 * already told us about itself.
		 */
		if (st != ST_RUN && sig_quiet(s.pm.sig)) {
			dbg_logf("sig: nothing back from the rendezvous for "
				 "%ds -- rebuilding", sig_idle_s(s.pm.sig));
			if (sig_rebuild(&s, "after the rendezvous went quiet")) {
				st = ST_FAIL;
				break;
			}
			st = client_regather(&s) ? ST_FAIL : ST_GATHER;
		}
		/*
		 * No peer has answered yet and the pool server this attempt drew
		 * produced no public v4: re-claim through the next one. Once an
		 * answer is in play the ICE retry path below owns rotation.
		 */
		if ((st == ST_GATHER || st == ST_SIGNAL) && stun_stall(&s)) {
			__atomic_add_fetch(&s.ice_attempt, 1, __ATOMIC_RELAXED);
			s.stun_rotations++;
			st = client_regather(&s) ? ST_FAIL : ST_GATHER;
		}
		pool_pump(&s);
		if (now_ms() >= s.c.next_status_ms) {
			publish_status(&s.c,
				       st == ST_WAIT_ICE ? CONN_PUNCHING :
				       (st == ST_GATHER || st == ST_SIGNAL) ?
				       CONN_GATHERING : CONN_CONNECTING);
			s.c.next_status_ms = now_ms() + 500;
		}
		trickle_flush(&s, o, 0);
		if (o) {
			if (o->net && sdp_ready(&s))
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
			    (cfg->sig_flags & SIG_DHT) && __atomic_load_n(&s.have_priv4, __ATOMIC_RELAXED) &&
			    !__atomic_load_n(&s.have_srflx4, __ATOMIC_RELAXED) &&
			    s.stun_count > 0 &&
			    now_ms() - s.start_ms > STUN_WARN_MS) {
				o->escalate(o->arg, "no public IPv4 from STUN -- "
					    "the server list may be stale; run "
					    "`comrade stun-update`");
				s.stun_warned = 1;
			}
			/* The fact the warning reported has stopped being true:
			 * a reflexive v4 did arrive, just late. */
			if (s.stun_warned &&
			    __atomic_load_n(&s.have_srflx4, __ATOMIC_RELAXED)) {
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
			if (sig_ready(s.pm.sig)) {
				if (nat_setup(&s.c))
					st = ST_FAIL;
				else
					st = ST_GATHER;
			}
			break;
		case ST_GATHER:
			if (sdp_ready(&s)) {
				sdp_filter(s.local_sdp, cfg->family, filtered,
					   sizeof(filtered));
				snprintf(s.local_sdp, sizeof(s.local_sdp),
					 "%s", filtered);
				s.net.pool.posted = fan_local_sdp(&s);
				sig_set_claim_offer(s.pm.sig, s.c.remote_ufrag);
				sig_post(s.pm.sig, (const uint8_t *)s.local_sdp,
					 strlen(s.local_sdp));
				if (cfg->is_host && (cfg->sig_flags & SIG_DHT))
					sig_locate(s.pm.sig);
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
				cand_sdp_ufrag(s.peer_sdp, ufrag, sizeof(ufrag));
				snprintf(s.c.remote_ufrag, sizeof(s.c.remote_ufrag),
					 "%s", ufrag);
				s.c.remote_gen = sig_peer_gen(s.pm.sig);
				/* The claimant a single-connection host serves is
				 * the identity in the answer it takes up, as
				 * lan_drain and the turnstile record theirs. */
				if (cfg->is_host) {
					pthread_mutex_lock(&s.c.claim_lock);
					snprintf(s.c.claim_ufrag,
						 sizeof(s.c.claim_ufrag), "%s",
						 ufrag);
					pthread_mutex_unlock(&s.c.claim_lock);
				}
				s.net.pool.posted = fan_local_sdp(&s);
							/* members learnt since
							 * the ST_GATHER post */
				sig_set_claim_offer(s.pm.sig, s.c.remote_ufrag);
				sig_post(s.pm.sig, (const uint8_t *)s.local_sdp,
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
			peering_paths(&s.c.pr, now_ms());
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
				__atomic_add_fetch(&s.ice_attempt, 1, __ATOMIC_RELAXED);
				conn_drop_ice_path(&s.c);
				conn_free_agent(&s.c, s.c.nat, s.c.nat_ctx);
				s.c.nat = NULL;
				s.c.nat_ctx = NULL;
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
				s.was_live = 1;
			}
			r = run_ssh(&s);
			dbg_logf("session: run_ssh rc=%d", r);
			/*
			 * The host said the shared session ended (CTLM_BYE).
			 * Whatever the connection did afterwards, there is
			 * nothing on the other end to rejoin, so this is where
			 * the client stops rather than re-claiming.
			 */
			if (!cfg->is_host && s.peer_ended) {
				ended = SESSION_ENDED;
				st = ST_DONE;
				break;
			}
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
				deadline = cfg->connect_timeout_s > 0 ?
					now_ms() +
					(uint64_t)cfg->connect_timeout_s * 1000 : 0;
				/* Nothing has been watching the interfaces
				 * while the link was up, so look now. */
				net_pump(&s, now_ms());
				if (net_moved(&s)) {
					net_change_reset(&s);
					pathplane_clear(&s.c.pr.pl);
					if (sig_rebuild(&s,
							"on the new network")) {
						st = ST_FAIL;
						break;
					}
				}
				st = client_regather(&s) ? ST_FAIL :
							   ST_GATHER;
			} else if (!cfg->is_host &&
				   deadline_room(deadline, now_ms(), 10000)) {
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
			} else if (deadline_room(deadline, now_ms(), 10000)) {
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

	if (s.session_over)
		session_entomb(&s);
	/*
	 * A stop that was asked for is not a failure. The loop above leaves st
	 * at whatever it had reached when the flag was seen, and only one of
	 * those states is ST_DONE -- so a harness that signalled a client it
	 * had already watched establish was told the run had failed. It is a
	 * failure only if nothing was ever established, which is the same
	 * question as before for a session that never got going.
	 */
	if (!ended && st != ST_DONE && cfg->test_stop &&
	    __atomic_load_n(cfg->test_stop, __ATOMIC_RELAXED) &&
	    s.established_fired)
		st = ST_DONE;
	rc = ended ? ended : ((st == ST_DONE) ? 0 : 1);
done:
	/* Cleared under the lock before it is freed, as run_ssh does: the ICE
	 * agent's poll thread lives until conn_free_agent below, and it reaches
	 * the stream through this field. After this, deliver_stream_from sees
	 * NULL and no-ops. */
	pthread_mutex_lock(&s.c.stream_lock);
	st_done = s.c.stream;
	s.c.stream = NULL;
	pthread_mutex_unlock(&s.c.stream_lock);
	if (st_done)
		stream_destroy(st_done);
	conn_reap_holds(&s.c);
	conn_drop_ice_path(&s.c);
	conn_free_agent(&s.c, s.c.nat, s.c.nat_ctx);
	if (s.lan)
		lanlink_destroy(s.lan);
	sig_destroy(s.pm.sig);
	netmon_src_close(&s.netmon);
	/* Teardown, and the one place waiting is right: the session these
	 * threads write into is about to go away with this frame. */
	peering_net_stop(&s.net);
	if (s.warm_running) {
		__atomic_store_n(&s.warm_stop, 1, __ATOMIC_RELAXED);
		pthread_join(s.warm_th, NULL);
		s.warm_running = 0;
	}
	stunlist_free(s.stun_servers, s.stun_count);
	pthread_mutex_destroy(&s.trickle_lock);
	pthread_mutex_destroy(&s.c.status_lock);
	peering_destroy(&s.c.pr);
	pthread_mutex_destroy(&s.c.claim_lock);
	pthread_mutex_destroy(&s.c.stream_lock);
	peering_model_destroy(&s.pm);
	peering_net_destroy(&s.net);
	return rc;
}
