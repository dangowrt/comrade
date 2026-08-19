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
#include "session.h"
#include "sig.h"
#include "sshbridge.h"
#include "sshc.h"
#include "sshd.h"
#include "stream.h"
#include "stunlist.h"
#include "tokgen.h"

#define SESSION_CONV 0x70326531

/*
 * Liveness heartbeat cadence over the comrade-ctl control channel (framing in
 * ctlproto.h): a ping every HB_INTERVAL_MS, and the link is declared lost when
 * no pong has come back for HB_LOST_MS.
 */
#define HB_INTERVAL_MS 700
#define HB_LOST_MS 2500
/*
 * A host worker whose client has been silent this long is presumed gone and the
 * worker reaps itself: with no clean disconnect the SSH bridge never ends on its
 * own (KCP buffers a dead path indefinitely), so the heartbeat is what frees the
 * worker (and its tmux client). Well above HB_LOST_MS so a brief outage, during
 * which the client may still be reconnecting, does not tear a live worker down.
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
 * A path is qualified when an authenticated probe has round-tripped on it, so
 * these bound the wait rather than the truth: how often to re-probe a path that
 * has not answered, and how long a client keeps probing before it concludes it
 * lost the turnstile round and claims again. See PROTOCOL.md, "Transport probe".
 */
#define PROBE_EVERY_MS 200
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

	/* This connection's direct (lanlink) peer on the shared segment, if any;
	 * a v4 peer is kept v4-mapped. transport_send prefers it over ICE, and
	 * the host demultiplexes inbound datagrams to the conn whose lan_peer
	 * matches the source. */
	struct sockaddr_in6 lan_peer;
	int have_lan_peer;
	/*
	 * Path qualification. A transport reporting a pair says only that packets
	 * move; it does not say the far end is serving *us* -- a host answers a
	 * losing claimant's ICE checks with credentials every reader of its offer
	 * holds. So each path carries the session only once a probe has
	 * round-tripped on it bearing our own claimant identity, and among
	 * qualified paths the lowest class wins (see path_class).
	 */
	volatile int lan_qualified;
	volatile int ice_qualified;
	volatile int lan_rtt_ms;
	volatile int ice_rtt_ms;
	uint64_t probe_start_ms;	/* first probe of this attempt, for rtt */
	uint64_t next_probe_ms;
	uint64_t probe_nonce;
	char direct_addr[80];		/* the lan_peer, printable (view) */
	/* The claimant's ICE ufrag, carried for the worker's whole lifetime so the
	 * host recognises the same client arriving over the other transport. */
	char claim_ufrag[40];

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
	int hb_rtt;			/* round trip from the last pong, ms */
	int hb_pong_seen;		/* a pong has ever come back on this conn */
	uint64_t lost_since_ms;		/* when the link was first seen lost, 0 if live */

	/* The peer's rendezvous announcement, handed from the ctl reader to the
	 * loop; [0]=v4 [1]=v6. */
	struct rdv_node rdv_in[2];
	pthread_mutex_t rdv_lock;
	int rdv_in_dirty;
	uint64_t next_rdv_tell_ms;

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
};

struct sess {
	const struct session_cfg *cfg;

	uint8_t auth[TOKEN_AUTH_LEN];

	struct sig *sig;
	struct lanlink *lan;
	struct session_keys keys;	/* sig_key, for sealing transport probes */

	struct netmon netmon;		/* detect a roam while still waiting */

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
	struct conn *offer_conn;		/* live conn the peer-offer callback feeds */

	uint64_t ice_attempt_start;
	int ice_attempt;
	int expect4, expect6;		/* host has DHT reach on this family */
	int minted4, minted6;		/* family's endpoint/rendezvous is in the token */
	int noconn_warned;		/* operator told no family can be advertised */
	uint64_t next_mint_ms;		/* throttle the per-family advert decision */

	uint64_t start_ms;		/* observer: session start, for escalation */
	int escalated;			/* observer: client warned of DHT warm */
	int peer_state;			/* observer: highest SESSION_PEER_* sent */
	int established_fired;		/* observer: established sent once */
	int have_priv4;			/* a private/CGNAT v4 host candidate (needs STUN) */
	int have_srflx4;		/* STUN gave us a public v4 (reflexive) */
	int stun_warned;		/* warned once that STUN produced nothing */

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
	char punch_ufrag[HOST_MAX_WORKERS][40];	/* each punch's claimant id */
	char last_served_ufrag[40];		/* the most recently served one */
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
	else if (family == 6 && (t->flags & TOKEN_FLAG_EP6_RDV) &&
		 inet_ntop(AF_INET6, t->ep6_addr, ip, sizeof(ip)))
		snprintf(out, n, "[%s]:%u", ip, t->ep6_port);
	else if (family == 4 && (t->flags & TOKEN_FLAG_EP4_RDV) &&
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
	/* Show the endpoint that is actually carrying KCP right now: the
	 * link-local direct peer when that path is up (it is preferred in
	 * transport_send), otherwise the selected -- proven -- ICE pair. Never a
	 * mere gathered candidate. */
	if (c->have_lan_peer && c->direct_addr[0]) {
		snprintf(cs.peer, sizeof(cs.peer), "%s", c->direct_addr);
	} else if (c->nat && nat_connected(c->nat)) {
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

/* Plant the token's rendezvous node(s) as sticky DHT hints (client). */
static int client_seed_rendezvous(struct sess *s)
{
	const struct session_obs *o = s->cfg->obs;
	const struct token *t = &s->cfg->tok;
	int n = 0;

	if (t->flags & TOKEN_FLAG_EP6_RDV) {
		struct sockaddr_in6 a;

		memset(&a, 0, sizeof(a));
		a.sin6_family = AF_INET6;
		memcpy(&a.sin6_addr, t->ep6_addr, TOKEN_EP6_LEN);
		a.sin6_port = htons(t->ep6_port);
		if (!sig_seed_node(s->sig, (struct sockaddr *)&a, sizeof(a))) {
			n++;
			if (o && o->rendezvous) {
				char b[80];

				addr_str((struct sockaddr *)&a, b, sizeof(b));
				o->rendezvous(o->arg, 6, b, 0);
			}
		}
	}
	if (t->flags & TOKEN_FLAG_EP4_RDV) {
		struct sockaddr_in a;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		memcpy(&a.sin_addr, t->ep4_addr, TOKEN_EP4_LEN);
		a.sin_port = htons(t->ep4_port);
		if (!sig_seed_node(s->sig, (struct sockaddr *)&a, sizeof(a))) {
			n++;
			if (o && o->rendezvous) {
				char b[80];

				addr_str((struct sockaddr *)&a, b, sizeof(b));
				o->rendezvous(o->arg, 4, b, 0);
			}
		}
	}
	return n;
}

/*
 * Client accelerator (mirror of client_seed_rendezvous): for each family whose
 * endpoint is direct (EPx_RDV clear) and non-zero, preload the host's endpoint
 * as our lanlink peer at t=0, so KCP starts toward the host immediately instead
 * of waiting to hear its multicast announcement. The host still learns us from
 * our own sealed announcement; this only primes the reverse direction. A later
 * multicast on_direct_peer overwrites this with the same endpoint. Only called
 * once s->lan exists (transport_send would otherwise send on a NULL socket).
 */
static void client_direct_connect(struct sess *s)
{
	const struct token *t = &s->cfg->tok;
	int i, any;

	if (!(t->flags & TOKEN_FLAG_EP6_RDV) && t->ep6_port) {
		struct sockaddr_in6 a;

		for (i = 0, any = 0; i < TOKEN_EP6_LEN; i++)
			if (t->ep6_addr[i])
				any = 1;
		if (any) {
			memset(&a, 0, sizeof(a));
			a.sin6_family = AF_INET6;
			memcpy(&a.sin6_addr, t->ep6_addr, TOKEN_EP6_LEN);
			a.sin6_port = htons(t->ep6_port);
			if (!lanlink_map_peer((struct sockaddr *)&a, sizeof(a),
					      &s->c.lan_peer)) {
				s->c.have_lan_peer = 1;
				fmt_sockaddr((struct sockaddr *)&a, sizeof(a),
					     s->c.direct_addr,
					     sizeof(s->c.direct_addr));
			}
		}
	}
	if (!(t->flags & TOKEN_FLAG_EP4_RDV) && t->ep4_port) {
		struct sockaddr_in a;

		for (i = 0, any = 0; i < TOKEN_EP4_LEN; i++)
			if (t->ep4_addr[i])
				any = 1;
		if (any) {
			memset(&a, 0, sizeof(a));
			a.sin_family = AF_INET;
			memcpy(&a.sin_addr, t->ep4_addr, TOKEN_EP4_LEN);
			a.sin_port = htons(t->ep4_port);
			if (!lanlink_map_peer((struct sockaddr *)&a, sizeof(a),
					      &s->c.lan_peer)) {
				s->c.have_lan_peer = 1;
				fmt_sockaddr((struct sockaddr *)&a, sizeof(a),
					     s->c.direct_addr,
					     sizeof(s->c.direct_addr));
			}
		}
	}
}

/* Host: if the token already carries rendezvous nodes -- a persisted anchor
 * from a previous idle attempt -- adopt and reinforce them instead of locating
 * fresh ones, so the shared token stays valid and the node does not churn. */
static void host_seed_anchor(struct sess *s)
{
	const struct token *t = &s->cfg->tok;

	if (t->flags & TOKEN_FLAG_EP6_RDV) {
		struct sockaddr_in6 a;

		memset(&a, 0, sizeof(a));
		a.sin6_family = AF_INET6;
		memcpy(&a.sin6_addr, t->ep6_addr, TOKEN_EP6_LEN);
		a.sin6_port = htons(t->ep6_port);
		sig_reinforce(s->sig, 6, (struct sockaddr *)&a, sizeof(a));
	}
	if (t->flags & TOKEN_FLAG_EP4_RDV) {
		struct sockaddr_in a;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		memcpy(&a.sin_addr, t->ep4_addr, TOKEN_EP4_LEN);
		a.sin_port = htons(t->ep4_port);
		sig_reinforce(s->sig, 4, (struct sockaddr *)&a, sizeof(a));
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

/* libjuice gather thread: a candidate is ready. Append it for the main loop. */
static void on_ice_candidate(void *arg, const char *cand)
{
	struct sess *s = ((struct conn *)arg)->sess;
	size_t used, room, n = strlen(cand);

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


/* Send over whichever transport carries the stream right now (see the priority
 * in on_stream_output). Used for the KCP stream and the liveness heartbeat. */
static int transport_send(struct conn *c, const uint8_t *data, size_t len)
{
	struct sess *s = c->sess;

	/*
	 * Class before anything else: a qualified LAN path stays on the segment,
	 * needs no NAT binding and no ICE keepalive, and never asks the gateway to
	 * reflect a packet back at the segment it came from. A host has nothing to
	 * qualify -- see path_ready -- so it keeps the old preference.
	 */
	if (c->lan_qualified || (s->cfg->is_host && c->have_lan_peer))
		return lanlink_send(s->lan, &c->lan_peer, data, len);
	if (c->nat && nat_connected(c->nat))
		return nat_send(c->nat, data, len);
	if (c->have_lan_peer)
		return lanlink_send(s->lan, &c->lan_peer, data, len);
	return -1;
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
 * record a pong's round trip, or stash the peer's announced rendezvous node for
 * rdv_maintain to adopt. */
static void ctl_dispatch(void *arg, int type, const uint8_t *pl, size_t plen)
{
	struct conn *c = arg;

	if (type == CTLM_PING && plen >= CTL_TS_LEN) {
		ctl_send(c, CTLM_PONG, pl, CTL_TS_LEN);
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
 * The transport probe. Every KCP datagram opens with the conversation id, which
 * ikcp_input rejects on mismatch, and comrade uses one fixed conv -- so a
 * datagram opening with a different 32-bit magic is unambiguously not stream
 * data and can be split off ahead of it for the cost of one compare.
 *
 *   [4 magic][sealed: [1 type][8 nonce][1 ulen][ulen claimant ufrag]]
 *
 * The seal is not defending against the peer, who holds the token and is trusted
 * by construction; it stops a stranger who can guess an endpoint from forging a
 * reply and making us adopt a path that does not work.
 *
 * The ufrag is the claimant identity the turnstile already uses. A host answers
 * only for the claimant its worker was admitted for, and that single test is
 * what separates the winner of a turnstile round from the losers whose checks
 * its agent answered on the way past.
 */
#define PROBE_MAGIC 0x434d5250U		/* "CMRP"; must differ from SESSION_CONV */
#define PROBE_PING 1
#define PROBE_PONG 2
#define PROBE_PLAIN_MAX (1 + 8 + 1 + 40)
#define PROBE_MAX (4 + PROBE_PLAIN_MAX + SEAL_OVERHEAD)

static void probe_put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t probe_get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Build one probe into out (>= PROBE_MAX); returns its length, or 0. */
static size_t probe_build(struct conn *c, int type, uint64_t nonce,
			  uint8_t *out)
{
	uint8_t plain[PROBE_PLAIN_MAX];
	size_t ul = strlen(c->claim_ufrag);
	int n, i;

	if (ul > 40)
		return 0;
	plain[0] = (uint8_t)type;
	for (i = 0; i < 8; i++)
		plain[1 + i] = (uint8_t)(nonce >> (8 * (7 - i)));
	plain[9] = (uint8_t)ul;
	memcpy(plain + 10, c->claim_ufrag, ul);
	probe_put32(out, PROBE_MAGIC);
	n = msg_seal(out + 4, PROBE_MAX - 4, c->sess->keys.sig_key, plain,
		     10 + ul);
	return n < 0 ? 0 : (size_t)n + 4;
}

/*
 * A probe arrived on `lan` (1) or ICE (0). A ping addressed to the claimant we
 * serve is answered on the transport it came in on; a pong qualifies that path
 * and records its round trip. Anything else is dropped in silence.
 */
static void probe_recv(struct conn *c, const uint8_t *data, size_t len, int lan)
{
	uint8_t plain[PROBE_PLAIN_MAX + 1], out[PROBE_MAX];
	struct sess *s = c->sess;
	uint64_t nonce = 0;
	size_t ul, o;
	int n, i;

	n = msg_open(plain, sizeof(plain), s->keys.sig_key, data + 4, len - 4);
	if (n < 10)
		return;
	for (i = 0; i < 8; i++)
		nonce = (nonce << 8) | plain[1 + i];
	ul = plain[9];
	if ((size_t)n < 10 + ul || ul > 40)
		return;
	if (ul != strlen(c->claim_ufrag) ||
	    memcmp(plain + 10, c->claim_ufrag, ul))
		return;			/* not the claimant this conn serves */

	if (plain[0] == PROBE_PING) {
		o = probe_build(c, PROBE_PONG, nonce, out);
		if (!o)
			return;
		if (lan)
			lanlink_send(s->lan, &c->lan_peer, out, o);
		else if (c->nat)
			nat_send(c->nat, out, o);
		return;
	}
	if (plain[0] != PROBE_PONG || nonce != c->probe_nonce)
		return;
	if (lan) {
		c->lan_rtt_ms = (int)(now_ms() - c->probe_start_ms);
		c->lan_qualified = 1;
	} else {
		c->ice_rtt_ms = (int)(now_ms() - c->probe_start_ms);
		c->ice_qualified = 1;
	}
	dbg_logf("path qualified: %s rtt~%dms", lan ? "LAN" : "ICE",
		 lan ? c->lan_rtt_ms : c->ice_rtt_ms);
}

/* Deliver received transport bytes into the conn's KCP stream, under the lock
 * that guards a concurrent teardown clearing c->stream from another thread.
 * A probe is split off first: it is not stream data (see probe_recv). */
static void deliver_stream_from(struct conn *c, const uint8_t *data, size_t len,
				int lan)
{
	if (len >= 4 && probe_get32(data) == PROBE_MAGIC) {
		probe_recv(c, data, len, lan);
		return;
	}
	pthread_mutex_lock(&c->stream_lock);
	if (c->stream)
		stream_input(c->stream, data, len);
	pthread_mutex_unlock(&c->stream_lock);
}

static void deliver_stream(struct conn *c, const uint8_t *data, size_t len)
{
	deliver_stream_from(c, data, len, 0);
}

/*
 * Send a probe on every path this conn has a candidate for. Cheap enough to
 * repeat: two datagrams of ~70 bytes, and only while nothing has qualified.
 */
static void probe_pump(struct conn *c)
{
	struct sess *s = c->sess;
	uint8_t out[PROBE_MAX];
	size_t n;

	if (s->cfg->is_host || !c->claim_ufrag[0])
		return;
	if (!c->probe_start_ms)
		c->probe_start_ms = now_ms();
	if (now_ms() < c->next_probe_ms)
		return;
	c->next_probe_ms = now_ms() + PROBE_EVERY_MS;
	c->probe_nonce = now_ms();
	n = probe_build(c, PROBE_PING, c->probe_nonce, out);
	if (!n)
		return;
	if (c->have_lan_peer && !c->lan_qualified)
		lanlink_send(s->lan, &c->lan_peer, out, n);
	if (c->nat && nat_connected(c->nat) && !c->ice_qualified)
		nat_send(c->nat, out, n);
}

/*
 * Is any path qualified? A host is exempt: it answers probes rather than sending
 * them, and its worker exists only because the turnstile already decided this
 * client is the one it serves.
 */
static int path_ready(const struct conn *c)
{
	if (c->sess->cfg->is_host)
		return c->have_lan_peer || (c->nat && nat_connected(c->nat));
	return c->lan_qualified || c->ice_qualified;
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

	(void)src;
	(void)srclen;
	deliver_stream_from(c, data, len, 1);
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
	 * Prefer a non-link-local endpoint. A host on several interfaces announces
	 * from each, so its link-local IPv6 source can arrive last and overwrite a
	 * usable v4 or loopback endpoint (such as the one preloaded from the token);
	 * but a link-local lanlink target needs a zone id that does not reliably
	 * survive the announcement path, so it often cannot be reached. Never
	 * downgrade a usable endpoint to a link-local one; a non-link-local wins.
	 */
	if (c->have_lan_peer && IN6_IS_ADDR_LINKLOCAL(&np.sin6_addr) &&
	    !IN6_IS_ADDR_LINKLOCAL(&c->lan_peer.sin6_addr))
		return;
	/*
	 * The same peer is heard from every address it has, so these announcements
	 * differ in source but carry the one lanlink port that identifies it. Once
	 * one of those addresses has answered a probe, keep it -- the others are
	 * the same peer, and moving to an untried one would discard the proof.
	 */
	if (!c->have_lan_peer || !lan_peer_same(&c->lan_peer, &np))
		c->lan_qualified = 0;
	else if (c->lan_qualified)
		return;
	c->lan_peer = np;
	c->have_lan_peer = 1;
	fmt_sockaddr(peer, len, c->direct_addr, sizeof(c->direct_addr));
}

/* Is this endpoint already an active LAN worker? (host main thread only) */
static int lan_conn_active(struct sess *s, const struct sockaddr_in6 *peer)
{
	int i;

	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->lan_conns[i] && s->lan_conns[i]->have_lan_peer &&
		    lan_peer_same(&s->lan_conns[i]->lan_peer, peer))
			return 1;
	return 0;
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
static int lan_ufrag_claimed(const struct sess *s, const char *ufrag)
{
	int i;

	if (!ufrag[0])
		return 0;
	for (i = 0; i < HOST_MAX_WORKERS; i++)
		if (s->lan_conns[i] &&
		    !strcmp(s->lan_conns[i]->claim_ufrag, ufrag))
			return 1;
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
 * worker's stream. Runs on the host main thread (lanlink_dispatch from
 * pump_once); lan_conns[] is mutated only here on the main thread, so no lock
 * beyond the conn's stream_lock (taken by deliver_stream against a teardown).
 */
static void host_lan_recv(void *arg, const struct sockaddr *src, socklen_t srclen,
			  const uint8_t *data, size_t len)
{
	struct sess *s = arg;
	struct sockaddr_in6 mapped;
	int i;

	if (lanlink_map_peer(src, srclen, &mapped))
		return;
	for (i = 0; i < HOST_MAX_WORKERS; i++) {
		struct conn *c = s->lan_conns[i];

		if (c && c->have_lan_peer && lan_peer_same(&c->lan_peer, &mapped)) {
			deliver_stream_from(c, data, len, 1);
			return;
		}
	}
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
	 * claimant it admitted (lan_drain, and the turnstile at pickup). */
	if (c->sess && !c->sess->cfg->is_host)
		snprintf(c->claim_ufrag, sizeof(c->claim_ufrag), "%s",
			 c->ice_ufrag);
	c->lan_qualified = 0;
	c->ice_qualified = 0;
	c->probe_start_ms = 0;
	c->next_probe_ms = 0;
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
	o.ro_out = &c->read_only;
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
	o.interactive = s->cfg->interactive;
	o.read_only = (s->cfg->tok.flags & TOKEN_FLAG_RO) != 0;
	o.connect_timeout_s = s->cfg->connect_timeout_s;
	o.ctl_fd = c->ssh_ctl_fd;
	o.fwd_l = s->cfg->fwd_l;
	o.nfwd_l = s->cfg->nfwd_l;
	o.fwd_r = s->cfg->fwd_r;
	o.nfwd_r = s->cfg->nfwd_r;
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
	int done = 0;
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
	c->hb_pong_seen = 0;
	c->lost_since_ms = 0;
	pthread_mutex_unlock(&c->hb_lock);
	next_hb = now_ms();
	conn_start = now_ms();

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

		if (now_ms() >= next_hb) {
			uint8_t ts[CTL_TS_LEN];

			ctl_put_u64(ts, now_ms());
			ctl_send(c, CTLM_PING, ts, sizeof(ts));
			next_hb = now_ms() + HB_INTERVAL_MS;
		}
		if (drive_sig)
			rdv_maintain(c);
		if (now_ms() >= c->next_status_ms) {
			uint64_t now = now_ms(), lp;
			int state, pong_seen;

			pthread_mutex_lock(&c->hb_lock);
			lp = c->hb_last_pong;
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
				if (pong_seen && c->lost_since_ms &&
				    now - c->lost_since_ms > HOST_REAP_MS)
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
 * Route-up but the DHT never acked (captive portal / UDP-blocked): mint the LAN
 * endpoint only after this grace, well beyond DHT convergence, so a merely-slow
 * global host is not mislabelled isolated.
 */
#define ISOLATED_ROUTE_GRACE_MS 25000

/*
 * First usable direct-endpoint address of `family` in the sdp: a "host" ICE
 * candidate that is neither loopback nor -- for v6 -- link-local (a fe80
 * address cannot be embedded in the 16-byte slot without a zone id). The bare
 * address goes into out (out may be NULL to only test presence); 1 if found.
 */
static int fam_usable_addr(const char *sdp, int family, char *out, size_t n)
{
	const char *p = sdp;
	char addr[64], typ[16];
	unsigned char b[16];

	while ((p = strstr(p, "candidate:")) != NULL) {
		if (sscanf(p, "candidate:%*s %*d %*s %*u %63s %*d typ %15s",
			   addr, typ) == 2 && !strcmp(typ, "host")) {
			if (family == 6 && strchr(addr, ':') &&
			    inet_pton(AF_INET6, addr, b) == 1) {
				int ll = b[0] == 0xfe && (b[1] & 0xc0) == 0x80;
				int lo = b[15] == 1, i;

				for (i = 0; i < 15; i++)
					if (b[i])
						lo = 0;
				if (!ll && !lo) {
					if (out)
						snprintf(out, n, "%s", addr);
					return 1;
				}
			} else if (family == 4 && !strchr(addr, ':') &&
				   inet_pton(AF_INET, addr, b) == 1) {
				if (b[0] != 127) {
					if (out)
						snprintf(out, n, "%s", addr);
					return 1;
				}
			}
		}
		p += 10;
	}
	return 0;
}

/* Build the host's own direct endpoint for `family`: its first usable host
 * address at the shared lanlink port (0 if lanlink is not up yet). 1 if built. */
static int fam_endpoint(struct sess *s, int family,
			struct sockaddr_storage *ss, socklen_t *slen)
{
	char addr[64];
	uint16_t port = s->lan ? lanlink_port(s->lan) : 0;

	if (!fam_usable_addr(s->local_sdp, family, addr, sizeof(addr)))
		return 0;
	memset(ss, 0, sizeof(*ss));
	if (family == 6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;

		a->sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, addr, &a->sin6_addr) != 1)
			return 0;
		a->sin6_port = htons(port);
		*slen = sizeof(*a);
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)ss;

		a->sin_family = AF_INET;
		if (inet_pton(AF_INET, addr, &a->sin_addr) != 1)
			return 0;
		a->sin_port = htons(port);
		*slen = sizeof(*a);
	}
	return 1;
}

/* Gather the four tokgen facts for `family`. */
static void gather_facts(struct sess *s, int family, struct tokgen_facts *f)
{
	int af = family == 6 ? AF_INET6 : AF_INET;
	char buf[64];

	memset(f, 0, sizeof(*f));
	f->has_usable_addr = fam_usable_addr(s->local_sdp, family, NULL, 0);
	f->has_default_route = source_addr(af, buf, sizeof(buf)) == 0;
	f->dht_acked = sig_dht_acked(s->sig, family);
	f->public_port_proven = 0;	/* no UPnP/NAT-PMP/PCP in the tree */
}

/*
 * An ENDPOINT family is "settled" -- safe to mint -- when it can no longer turn
 * out to be global: at once when the host is not on the DHT by policy or has no
 * default route (the DHT can never ack), otherwise only after a grace so a
 * genuinely global family that is merely slow to ack still mints RENDEZVOUS.
 */
static int endpoint_settled(struct sess *s, const struct tokgen_facts *f)
{
	if (!(s->cfg->sig_flags & SIG_DHT))
		return 1;
	if (!f->has_default_route)
		return 1;
	return now_ms() - s->start_ms > ISOLATED_ROUTE_GRACE_MS;
}

/* Mint the host's own LAN endpoint for `family` (EPx_RDV clear, NODHT set). */
static void mint_endpoint(struct sess *s, int family)
{
	struct sockaddr_storage ss;
	socklen_t slen = 0;

	if (!fam_endpoint(s, family, &ss, &slen))
		return;
	s->cfg->on_endpoint(s->cfg->arg, (struct sockaddr *)&ss, slen);
	if (family == 6)
		s->minted6 = 1;
	else
		s->minted4 = 1;
}

/*
 * Host token minting. A globally reachable family is located on the DHT and
 * embedded as a RENDEZVOUS node the moment it is ready (upgraded in place when
 * the second family converges). An isolated (LAN-only) family instead mints the
 * host's own direct ENDPOINT once it is settled -- decided per family by the
 * pure tokgen tree from four observed facts. If neither family can be
 * advertised the operator is told, rather than the host hanging silently.
 */
static void maybe_announce_rendezvous(struct sess *s)
{
	const struct session_obs *o = s->cfg->obs;
	struct sockaddr_storage a4, a6;
	socklen_t l4 = sizeof(a4), l6 = sizeof(a6);
	struct tokgen_facts f4, f6;
	struct tokgen_result verdict;
	int have4, have6;

	if (!s->cfg->is_host || !s->cfg->on_rendezvous)
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

	/* Mint a RENDEZVOUS family as soon as it is located, upgrading the token
	 * in place when the other arrives: a single-family host publishes at once,
	 * and a dual-stack host gains the second family when its DHT converges. */
	if (have4 && !s->minted4) {
		s->cfg->on_rendezvous(s->cfg->arg, (struct sockaddr *)&a4, l4);
		s->minted4 = 1;
	}
	if (have6 && !s->minted6) {
		s->cfg->on_rendezvous(s->cfg->arg, (struct sockaddr *)&a6, l6);
		s->minted6 = 1;
	}

	/* Decide the isolated (ENDPOINT) families and the no-connectivity case
	 * from the tokgen tree, throttled (its route probe is cheap but not free).
	 * A family the DHT acked is never minted as an endpoint -- it took the
	 * RENDEZVOUS path above. */
	if ((s->minted4 && s->minted6) || now_ms() < s->next_mint_ms)
		return;
	s->next_mint_ms = now_ms() + 1000;

	gather_facts(s, 4, &f4);
	gather_facts(s, 6, &f6);
	if (tokgen_decide_host(&f4, &f6, &verdict) < 0) {
		if (o && o->escalate && !s->noconn_warned &&
		    now_ms() - s->start_ms > 3000) {
			o->escalate(o->arg, "no usable address on any family -- "
				    "nothing to host over; check the network");
			s->noconn_warned = 1;
		}
		return;
	}
	if (!s->cfg->on_endpoint)
		return;
	if (verdict.v4 == TOK_ADVERT_ENDPOINT && !s->minted4 &&
	    !f4.dht_acked && endpoint_settled(s, &f4))
		mint_endpoint(s, 4);
	if (verdict.v6 == TOK_ADVERT_ENDPOINT && !s->minted6 &&
	    !f6.dht_acked && endpoint_settled(s, &f6))
		mint_endpoint(s, 6);
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

static struct conn *conn_alloc(struct sess *s)
{
	struct conn *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	c->sess = s;
	c->ctl_fd = INVALID_SOCK;
	pthread_mutex_init(&c->hb_lock, NULL);
	pthread_mutex_init(&c->rdv_lock, NULL);
	pthread_mutex_init(&c->status_lock, NULL);
	pthread_mutex_init(&c->stream_lock, NULL);
	conn_gen_ice(c);
	return c;
}

static void conn_free(struct conn *c)
{
	if (!c)
		return;
	if (c->nat)
		nat_destroy(c->nat);
	pthread_mutex_destroy(&c->hb_lock);
	pthread_mutex_destroy(&c->rdv_lock);
	pthread_mutex_destroy(&c->status_lock);
	pthread_mutex_destroy(&c->stream_lock);
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
		struct conn *c;
		int slot = -1;

		if (lanlink_map_peer((struct sockaddr *)&s->lan_pending[p].sa,
				     s->lan_pending[p].len, &mapped))
			continue;
		if (lan_conn_active(s, &mapped))
			continue;		/* a re-broadcast during setup */
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
		c->lan_peer = mapped;
		c->have_lan_peer = 1;		/* c->nat stays NULL: lanlink only */
		snprintf(c->claim_ufrag, sizeof(c->claim_ufrag), "%s",
			 s->lan_pending[p].ufrag);
		if (c->claim_ufrag[0]) {
			snprintf(s->last_served_ufrag,
				 sizeof(s->last_served_ufrag), "%s",
				 c->claim_ufrag);
			s->have_served = 1;
		}
		fmt_sockaddr((struct sockaddr *)&s->lan_pending[p].sa,
			     s->lan_pending[p].len, c->direct_addr,
			     sizeof(c->direct_addr));
		c->dash_id = ++*dash_seq;
		snprintf(c->status_peer, sizeof(c->status_peer), "%s",
			 c->direct_addr);
		s->lan_conns[slot] = c;
		if (o && o->peer) {
			o->peer(o->arg, c->dash_id, SESSION_PEER_SEEN,
				c->direct_addr);
			o->peer(o->arg, c->dash_id, SESSION_PEER_LIVE,
				c->direct_addr);
		}
		if (worker_spawn(ws, c)) {	/* worker table full */
			if (o && o->peer)
				o->peer(o->arg, c->dash_id, SESSION_PEER_GONE,
					c->direct_addr);
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
		       uint64_t *punch_start, int *punch_stuck,
		       int *dash_seq)
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
			if (worker_spawn(ws, c)) {
				s->punch_ufrag[i][0] = '\0';
				conn_free(c);		/* table full */
			}
		} else if (now_ms() - punch_start[i] > ICE_ATTEMPT_MS ||
			   (!punch_stuck[i] && nat_failed(c->nat))) {
			dbg_logf("host: punch %s -> drop",
				 punch_stuck[i] ? "wedged (test)" : "failed");
			punching[i] = NULL;
			s->punch_ufrag[i][0] = '\0';
			conn_free(c);
		}
	}
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
	memset(punch_stuck, 0, sizeof(punch_stuck));
	s->last_served_ufrag[0] = '\0';
	s->have_served = 0;
	memset(s->punch_ufrag, 0, sizeof(s->punch_ufrag));

	while (cfg->host_serve_max == 0 || served < cfg->host_serve_max) {
		int active = 0;

		pump_once(s, 100);		/* the main thread owns sig + lan */
		maybe_announce_rendezvous(s);	/* mint and advertise the token */
		rdv_keep_warm(s);
		lan_drain(s, ws, &dash_seq);	/* admit same-segment claimants */

		/*
		 * Roamed while waiting for the next client: the current offer
		 * advertises the old network's candidates, so drop the listening
		 * agent and re-gather on the new interfaces, and flush the stale
		 * local addresses from the dashboard (the live client rows stay).
		 */
		if (netmon_changed(&s->netmon, now_ms())) {
			if (listen) {
				conn_free(listen);
				listen = NULL;
			}
			s->have_local_sdp = 0;
			s->have_peer_sdp = 0;
			s->remote_set = 0;
			s->local_sdp[0] = '\0';
			s->peer_sdp[0] = '\0';
			pthread_mutex_lock(&s->trickle_lock);
			s->trickle_sdp[0] = '\0';
			s->trickle_dirty = 0;
			pthread_mutex_unlock(&s->trickle_lock);
			ts = TS_GATHER;
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
		}

		/* Advance in-flight punches (connect -> worker, wedged -> freed),
		 * concurrently with the listener below. An in-flight punch keeps the
		 * host non-idle. */
		punch_scan(s, ws, punching, punch_start, punch_stuck, &dash_seq);
		for (i = 0; i < HOST_MAX_WORKERS; i++)
			if (punching[i])
				active = 1;

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
				char cu[40];
				int pslot = -1, inflight = 0;

				/*
				 * Ignore an answer that is already being served or
				 * punched: the DHT is eventually consistent, so a
				 * lagging node re-serves a just-picked-up answer, and
				 * a still-punching client keeps re-claiming the slot
				 * the rotate cleared; either would be punched again
				 * (double-serve). The claimant is its ICE ufrag. This
				 * is the stale-claim guard (have_served/last_served),
				 * keyed by ufrag so it covers concurrent punches.
				 */
				sdp_ufrag(s->peer_sdp, cu);
				if (cu[0] && ((s->have_served &&
					       !strcmp(cu, s->last_served_ufrag)) ||
					      ufrag_admitted(s, cu) ||
					      lan_ufrag_claimed(s, cu))) {
					dbg_logf("host: ignore stale/in-flight claim");
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
				dbg_logf("host: claim received -> punch (release)");
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
 * Create the signalling (and, for multicast, the link-local transport),
 * subscribe the callbacks and seed the rendezvous. Used at start and, for a
 * client, again on a roam: a fresh sig binds a new DHT socket on the new
 * network, whereas the old one stays stuck on the interface that just vanished
 * (which is why a manual restart reconnects instantly but a reused socket does
 * not). Returns 0 on success.
 */
/*
 * The lanlink port a host should re-bind: the shared port already printed in a
 * carried-forward direct endpoint token, so it stays valid across the re-serve
 * loop. Either family's endpoint carries the one shared port. 0 (ephemeral) for
 * a client, or a host with no direct endpoint.
 */
static uint16_t carried_lanlink_port(const struct session_cfg *cfg)
{
	const struct token *t = &cfg->tok;

	if (!cfg->is_host)
		return 0;
	if (!(t->flags & TOKEN_FLAG_EP6_RDV) && t->ep6_port)
		return t->ep6_port;
	if (!(t->flags & TOKEN_FLAG_EP4_RDV) && t->ep4_port)
		return t->ep4_port;
	return 0;
}

static int sig_setup(struct sess *s)
{
	const struct session_cfg *cfg = s->cfg;

	s->sig = sig_create(cfg->tok.rdv, cfg->sig_flags, cfg->is_host);
	if (!s->sig)
		return -1;
	s->offer_conn = &s->c;
	sig_subscribe(s->sig, on_peer_offer, s);
	/*
	 * The direct transport comes up for host and client alike whenever
	 * multicast is on (the old !host_is_multiuser gate is gone): a multi-user
	 * host demultiplexes the one shared socket by source into per-worker
	 * streams and admits claimants (host_lan_recv / on_direct_claim), while a
	 * client or single-connection host carries its one peer (client_lan_recv /
	 * on_direct_peer). The host advertises the shared port in its offer.
	 */
	if (cfg->sig_flags & SIG_MCAST) {
		int mu = host_is_multiuser(cfg);

		s->lan = lanlink_create(mu ? host_lan_recv : client_lan_recv,
					mu ? (void *)s : (void *)&s->c,
					carried_lanlink_port(cfg));
		if (s->lan) {
			sig_set_direct_port(s->sig, lanlink_port(s->lan));
			if (mu) {
				sig_subscribe_direct(s->sig, on_direct_claim, s);
				sig_set_mcast_claims(s->sig, 1);
			} else {
				sig_subscribe_direct(s->sig, on_direct_peer,
						     &s->c);
			}
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
	}
	if (!cfg->is_host)
		client_seed_rendezvous(s);
	else
		host_seed_anchor(s);
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
	memcpy(s.auth, cfg->tok.auth, TOKEN_AUTH_LEN);
	pthread_mutex_init(&s.trickle_lock, NULL);
	pthread_mutex_init(&s.c.status_lock, NULL);	/* s.c.status zeroed = connecting */
	pthread_mutex_init(&s.c.hb_lock, NULL);
	pthread_mutex_init(&s.c.rdv_lock, NULL);
	pthread_mutex_init(&s.c.stream_lock, NULL);
	netmon_init(&s.netmon);
	if (keys_derive(&s.keys, cfg->tok.rdv))
		return 1;
	if (cfg->stun_auto)
		s.stun_servers = stunlist_load(&s.stun_count);
	nat_log_level(cfg->log_level);	/* < 0 silences libjuice (see nat_log_level) */

	conn_gen_ice(&s.c);

	if (sig_setup(&s))
		return 1;

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
		/*
		 * Roamed before the link came up: re-gather on the new interfaces
		 * and flush the dashboard's stale local addresses. Once running, a
		 * roam instead drops the link and returns through SSHC_RECONNECT.
		 */
		if (st != ST_RUN && netmon_changed(&s.netmon, now_ms())) {
			if (s.c.nat) {
				nat_destroy(s.c.nat);
				s.c.nat = NULL;
			}
			conn_gen_ice(&s.c);
			s.have_local_sdp = 0;
			s.have_peer_sdp = 0;
			s.remote_set = 0;
			s.local_sdp[0] = '\0';
			s.peer_sdp[0] = '\0';
			pthread_mutex_lock(&s.trickle_lock);
			s.trickle_sdp[0] = '\0';
			s.trickle_dirty = 0;
			pthread_mutex_unlock(&s.trickle_lock);
			st = ST_WAIT_DHT;
			if (o && o->net_reset)
				o->net_reset(o->arg);
		}
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
			probe_pump(&s.c);
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
					else if (s.c.direct_addr[0])
						snprintf(s.c.status_peer,
							 sizeof(s.c.status_peer),
							 "%s", s.c.direct_addr);
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
				 * that lives on the host. Reuse the signalling; reset
				 * the deadline so the reconnect is not bounded by the
				 * original connect budget.
				 */
				dbg_logf("session: rejoin (roam)");
				if (o && o->reset)
					o->reset(o->arg);
				s.established_fired = 0;
				nat_destroy(s.c.nat);
				s.c.nat = NULL;
				conn_gen_ice(&s.c);
				s.have_local_sdp = 0;
				s.have_peer_sdp = 0;
				s.remote_set = 0;
				s.local_sdp[0] = '\0';
				s.peer_sdp[0] = '\0';
				pthread_mutex_lock(&s.trickle_lock);
				s.trickle_sdp[0] = '\0';
				s.trickle_dirty = 0;
				pthread_mutex_unlock(&s.trickle_lock);
				s.peer_state = SESSION_PEER_SEEN;
				deadline = now_ms() +
					(uint64_t)cfg->connect_timeout_s * 1000;
				if (nat_setup(&s.c))
					st = ST_FAIL;
				else
					st = ST_GATHER;
			} else if (now_ms() + 10000 < deadline) {
				/* ICE reported a path but the peer is not serving
				 * yet; keep signalling and re-check rather than give
				 * up, so the reverse channel can complete. */
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
	if (s.c.nat)
		nat_destroy(s.c.nat);
	if (s.lan)
		lanlink_destroy(s.lan);
	sig_destroy(s.sig);
	stunlist_free(s.stun_servers, s.stun_count);
	pthread_mutex_destroy(&s.trickle_lock);
	pthread_mutex_destroy(&s.c.status_lock);
	pthread_mutex_destroy(&s.c.hb_lock);
	pthread_mutex_destroy(&s.c.rdv_lock);
	pthread_mutex_destroy(&s.c.stream_lock);
	return rc;
}
