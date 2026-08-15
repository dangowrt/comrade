/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "candpolicy.h"
#include "conn.h"
#include "ctlproto.h"
#include "keys.h"
#include "lanlink.h"
#include "nat.h"
#include "session.h"
#include "sig.h"
#include "sshbridge.h"
#include "sshc.h"
#include "sshd.h"
#include "stream.h"
#include "stunlist.h"

#define SESSION_CONV 0x70326531

/*
 * Liveness heartbeat cadence over the comrade-ctl control channel (framing in
 * ctlproto.h): a ping every HB_INTERVAL_MS, and the link is declared lost when
 * no pong has come back for HB_LOST_MS.
 */
#define HB_INTERVAL_MS 700
#define HB_LOST_MS 2500
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

enum state {
	ST_WAIT_DHT,
	ST_GATHER,
	ST_SIGNAL,
	ST_WAIT_ICE,
	ST_RUN,
	ST_DONE,
	ST_FAIL,
};

struct sess {
	const struct session_cfg *cfg;

	uint16_t bind_port;
	char ice_ufrag[16];
	char ice_pwd[40];
	uint8_t auth[TOKEN_AUTH_LEN];

	struct sig *sig;
	struct nat_agent *nat;
	struct lanlink *lan;
	struct stream *stream;

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

	uint64_t ice_attempt_start;
	int ice_attempt;
	int expect4, expect6;		/* host has DHT reach on this family */
	int minted4, minted6;		/* family's rendezvous node is in the token */
	int mcast_minted;		/* multicast-only: token published */

	uint64_t start_ms;		/* observer: session start, for escalation */
	int escalated;			/* observer: client warned of DHT warm */
	int peer_state;			/* observer: highest SESSION_PEER_* sent */
	int established_fired;		/* observer: established sent once */
	char direct_addr[80];		/* observer: link-local peer, printable */
	int have_priv4;			/* a private/CGNAT v4 host candidate (needs STUN) */
	int have_srflx4;		/* STUN gave us a public v4 (reflexive) */
	int stun_warned;		/* warned once that STUN produced nothing */

	/* Local connection status (data only; the view renders it). */
	pthread_mutex_t status_lock;
	struct conn_status status;
	char status_peer[80];		/* address of the chosen pair, once live */
	char status_rdv[80];		/* located rendezvous endpoint (host side) */
	uint64_t next_status_ms;

	/* Liveness heartbeat: a tiny ping/pong over the comrade-ctl channel, so a
	 * dead link is noticed even when nobody is typing. Riding the reliable
	 * SSH/KCP stream, it measures end-to-end liveness -- a pong stops arriving
	 * once the link has truly stalled, which is exactly the signal we want. */
	pthread_mutex_t hb_lock;
	uint64_t hb_last_pong;		/* when a pong last came back */
	int hb_rtt;			/* round trip from the last pong, ms */
	uint64_t lost_since_ms;		/* when the link was first seen lost, 0 if live */

	/*
	 * Rendezvous nodes kept warm and exchanged in-band for a fast reconnect:
	 * [0]=v4 [1]=v6. rdv is our current best per family (our own located node
	 * where we reach the family, or the peer's for one we might roam to);
	 * rdv_in is a pending peer announcement the recv thread hands to the loop.
	 */
	struct rdv_node rdv[2];
	pthread_mutex_t rdv_lock;
	struct rdv_node rdv_in[2];
	int rdv_in_dirty;
	uint64_t next_rdv_warm_ms, next_rdv_tell_ms;

	int ssh_fd;			/* the ssh thread's socketpair end */
	int ssh_ctl_fd;			/* the ssh thread's comrade-ctl end */
	int ctl_fd;			/* our end of the comrade-ctl socketpair */
	struct ctl_reframer ctl_rf;	/* reassembles ctl messages across reads */
	int ssh_cli_rc;

	char **stun_servers;		/* rotated across ICE retries (host:port) */
	int stun_count;
	char stun_host[128];		/* the current attempt's host, split out */
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
	char host[64], serv[16];

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
				/* A global v6 only ever matters at the address we
				 * source outbound from (source_addr's connect
				 * trick, as canon_v6 already enforces for the sent
				 * SDP). libjuice also enumerates the stable/DHCPv6
				 * address, which we neither source from nor listen
				 * on for punching -- never surface it. Only when we
				 * know our source do we judge; otherwise show what
				 * was gathered, matching canon_v6. */
				drop6 = fam == 6 && scope == NET_SCOPE_GLOBAL &&
					s->src6[0] &&
					(via != NET_VIA_DIRECT ||
					 strcmp(addr, s->src6));
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

/* The mutual rendezvous node from the token, printable ("addr:port"). */
static void fmt_token_rdv(const struct token *t, char *out, size_t n)
{
	char ip[64];

	out[0] = '\0';
	if ((t->flags & TOKEN_FLAG_EP6_RDV) &&
	    inet_ntop(AF_INET6, t->ep6_addr, ip, sizeof(ip)))
		snprintf(out, n, "[%s]:%u", ip, t->ep6_port);
	else if ((t->flags & TOKEN_FLAG_EP4_RDV) &&
		 inet_ntop(AF_INET, t->ep4_addr, ip, sizeof(ip)))
		snprintf(out, n, "%s:%u", ip, t->ep4_port);
}

/*
 * Fill the structured connection status (no display text -- the view renders
 * it) and stash it: in memory for the client's in-process renderer, and, for
 * the host, in a tmpfs file the operator's separate process reads.
 */
static void publish_status(struct sess *s, int state)
{
	struct conn_status cs;

	memset(&cs, 0, sizeof(cs));
	cs.state = state;
	snprintf(cs.peer, sizeof(cs.peer), "%s", s->status_peer);
	/* The host learns its rendezvous endpoint mid-session (after the token
	 * snapshot this run was started with), so prefer the located address; the
	 * client, whose token already carries it, falls back to the token. */
	if (s->status_rdv[0])
		snprintf(cs.rdv, sizeof(cs.rdv), "%s", s->status_rdv);
	else
		fmt_token_rdv(&s->cfg->tok, cs.rdv, sizeof(cs.rdv));
	/* Prefer the heartbeat's round trip (measured even when idle); the stream
	 * RTT only moves when SSH data flows. Report how long a loss has lasted. */
	pthread_mutex_lock(&s->hb_lock);
	cs.rtt_ms = s->hb_rtt > 0 ? s->hb_rtt :
		(s->stream ? stream_rtt(s->stream) : 0);
	if (state == CONN_LOST && s->lost_since_ms)
		cs.since_s = (int)((now_ms() - s->lost_since_ms) / 1000);
	pthread_mutex_unlock(&s->hb_lock);

	pthread_mutex_lock(&s->status_lock);
	s->status = cs;
	pthread_mutex_unlock(&s->status_lock);

	if (s->cfg->status_path)
		conn_write(s->cfg->status_path, &cs);
}

/* sshc status callback: hand the client's renderer the current status data. */
static void session_status(void *arg, struct conn_status *out)
{
	struct sess *s = arg;

	pthread_mutex_lock(&s->status_lock);
	*out = s->status;
	pthread_mutex_unlock(&s->status_lock);
}

/* Keep only candidate lines of the requested family (0 = all). */
static void sdp_filter(const char *in, int family, char *out, size_t outlen)
{
	struct cand_policy pol;

	cand_policy_default(&pol);
	cand_sdp_filter(in, family, &pol, out, outlen);
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
		if (rewrite && a1 > a0 && a0 > 0) {
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
	struct sess *s = arg;

	canon_v6(sdp, s->src6, s->local_sdp, sizeof(s->local_sdp));
	s->have_local_sdp = 1;
}

/* libjuice gather thread: a candidate is ready. Append it for the main loop. */
static void on_ice_candidate(void *arg, const char *cand)
{
	struct sess *s = arg;
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
static int transport_send(struct sess *s, const uint8_t *data, size_t len)
{
	if (s->lan && lanlink_have_peer(s->lan))
		return lanlink_send(s->lan, data, len);
	if (s->nat && nat_connected(s->nat))
		return nat_send(s->nat, data, len);
	return -1;
}

/* Send one control message to the peer over the comrade-ctl channel. Best
 * effort: MSG_NOSIGNAL so a closed channel during teardown cannot raise
 * SIGPIPE, and a full/short write only ever drops a heartbeat, which the next
 * tick repeats. */
static void ctl_send(struct sess *s, int type, const uint8_t *payload,
		     size_t plen)
{
	uint8_t buf[CTL_FRAME_MAX];
	size_t n;
	ssize_t w;

	n = ctl_frame(buf, type, payload, plen);
	if (s->ctl_fd < 0 || !n)
		return;
	w = send(s->ctl_fd, buf, n, MSG_NOSIGNAL);
	(void)w;
}

/* Act on one decoded control message (a ctl_reframer callback): answer a ping,
 * record a pong's round trip, or stash the peer's announced rendezvous node for
 * rdv_maintain to adopt. */
static void ctl_dispatch(void *arg, int type, const uint8_t *pl, size_t plen)
{
	struct sess *s = arg;

	if (type == CTLM_PING && plen >= CTL_TS_LEN) {
		ctl_send(s, CTLM_PONG, pl, CTL_TS_LEN);
	} else if (type == CTLM_PONG && plen >= CTL_TS_LEN) {
		uint64_t now = now_ms();

		pthread_mutex_lock(&s->hb_lock);
		s->hb_last_pong = now;
		s->hb_rtt = (int)(now - ctl_get_u64(pl));
		pthread_mutex_unlock(&s->hb_lock);
	} else if (type == CTLM_RDV && plen >= CTL_RDV_PLEN) {
		struct sockaddr_storage sa;
		socklen_t sl = 0;
		int fam = ctl_rdv_decode(pl, &sa, &sl);

		if (fam) {
			int i = fam_idx(fam);

			pthread_mutex_lock(&s->rdv_lock);
			s->rdv_in[i].sa = sa;
			s->rdv_in[i].len = sl;
			s->rdv_in[i].have = 1;
			s->rdv_in_dirty = 1;
			pthread_mutex_unlock(&s->rdv_lock);
		}
	}
}

/* Drain the comrade-ctl fd and dispatch each complete message the read yields
 * (reframing across read boundaries lives in the reframer). */
static void ctl_readable(struct sess *s)
{
	uint8_t tmp[64];
	ssize_t n = read(s->ctl_fd, tmp, sizeof(tmp));

	if (n > 0)
		ctl_reframer_feed(&s->ctl_rf, tmp, (size_t)n, ctl_dispatch, s);
}

/*
 * Transport receive: with the control protocol now inside the SSH session,
 * everything arriving on the raw path is KCP stream data. May run on
 * libjuice's thread.
 */
static void on_transport_recv(void *arg, const uint8_t *data, size_t len)
{
	struct sess *s = arg;

	if (s->stream)
		stream_input(s->stream, data, len);
}

static void on_direct_peer(void *arg, const struct sockaddr *peer, socklen_t len)
{
	struct sess *s = arg;

	if (s->lan)
		lanlink_set_peer(s->lan, peer, len);
	fmt_sockaddr(peer, len, s->direct_addr, sizeof(s->direct_addr));
}

static void on_peer_offer(void *arg, const uint8_t *data, size_t len)
{
	struct sess *s = arg;
	char filtered[NAT_SDP_MAX];

	if (len >= sizeof(s->peer_sdp))
		len = sizeof(s->peer_sdp) - 1;
	memcpy(s->peer_sdp, data, len);
	s->peer_sdp[len] = '\0';
	s->have_peer_sdp = 1;
	/* Later arrivals are fresh candidates (multicast trickles one source at
	 * a time); feed them straight into the already-primed agent -- but not
	 * once connected, when the mailbox GET keeps redelivering the same set and
	 * re-adding it only churns the agent (and logs "max candidates"). */
	if (s->nat && s->remote_set && !nat_connected(s->nat)) {
		sdp_filter(s->peer_sdp, s->cfg->family, filtered, sizeof(filtered));
		nat_set_remote_description(s->nat, filtered);
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
	return transport_send((struct sess *)arg, data, len);
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
	int fd, rc = -1;

	fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0)
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
	close(fd);
	return rc;
}

static int nat_setup(struct sess *s)
{
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
	cfg.bind_port = s->bind_port;
	cfg.ice_ufrag = s->ice_ufrag;
	cfg.ice_pwd = s->ice_pwd;
	cfg.on_local_sdp = on_local_sdp;
	cfg.on_recv = on_transport_recv;
	cfg.on_candidate = on_ice_candidate;
	cfg.arg = s;

	s->remote_set = 0;
	s->nat = nat_create(&cfg);
	if (!s->nat || nat_gather(s->nat))
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
	poll(fds, (nfds_t)(nfds + lnf), timeout);
	sig_dispatch(s->sig, fds, nfds);
	if (s->lan)
		lanlink_dispatch(s->lan, fds + nfds, lnf);
}

static void *ssh_srv_thread(void *p)
{
	struct sess *s = p;
	struct sshd_opts o;

	memset(&o, 0, sizeof(o));
	o.hostkey = s->cfg->hostkey;
	memcpy(o.auth, s->auth, sizeof(o.auth));
	o.command = s->cfg->ssh_command;	/* NULL => tmux default */
	o.use_pty = s->cfg->use_pty;
	o.end_fd = s->cfg->ssh_end_fd;
	o.ctl_fd = s->ssh_ctl_fd;
	sshd_serve_fd(s->ssh_fd, &o);
	return NULL;
}

static void *ssh_cli_thread(void *p)
{
	struct sess *s = p;
	struct sshc_opts o;

	memset(&o, 0, sizeof(o));
	memcpy(o.host_fp, s->cfg->tok.hostpub, 32);
	memcpy(o.auth, s->auth, sizeof(o.auth));
	o.interactive = s->cfg->interactive;
	o.ctl_fd = s->ssh_ctl_fd;
	o.status = session_status;
	o.status_arg = s;
	o.send = s->cfg->test_send;
	o.send_len = s->cfg->test_send_len;
	o.recv = s->cfg->test_recv;
	o.recv_cap = s->cfg->test_recv_cap;
	o.recv_len = s->cfg->test_recv_len;
	s->ssh_cli_rc = sshc_connect_fd(s->ssh_fd, &o);
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
static void rdv_maintain(struct sess *s)
{
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
	if (now >= s->next_rdv_tell_ms) {
		for (i = 0; i < 2; i++)
			if (s->rdv[i].have) {
				uint8_t pl[CTL_RDV_PLEN];

				ctl_rdv_encode(pl, famv[i],
					       (struct sockaddr *)&s->rdv[i].sa);
				ctl_send(s, CTLM_RDV, pl, sizeof(pl));
			}
		s->next_rdv_tell_ms = now + RDV_TELL_MS;
	}

	/* Adopt the peer's announcement for any family we cannot reach ourselves,
	 * readying us to roam onto it (e.g. a v4-only host gaining v6, told a v6
	 * node by a dual-stack client). */
	if (s->rdv_in_dirty) {
		struct rdv_node in[2];

		pthread_mutex_lock(&s->rdv_lock);
		memcpy(in, s->rdv_in, sizeof(in));
		s->rdv_in_dirty = 0;
		pthread_mutex_unlock(&s->rdv_lock);
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
 * Run the SSH session over the connected stream until it ends. A failed
 * bring-up (the peer is not serving yet) ends the ssh thread quickly, so this
 * returns to be retried; a live session ends only when a side closes it.
 */
static int run_ssh(struct sess *s)
{
	struct sshbridge *br;
	pthread_t th;
	int sp[2], cp[2];
	int done = 0;
	uint64_t next_hb;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		return -1;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, cp)) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}
	s->stream = stream_create(SESSION_CONV, on_stream_output, s);
	if (!s->stream) {
		close(sp[0]);
		close(sp[1]);
		close(cp[0]);
		close(cp[1]);
		return -1;
	}
	s->ssh_fd = sp[1];
	s->ssh_ctl_fd = cp[1];
	s->ctl_fd = cp[0];
	s->ctl_rf.len = 0;
	if (pthread_create(&th, NULL,
			   s->cfg->is_host ? ssh_srv_thread : ssh_cli_thread, s)) {
		close(sp[0]);
		close(sp[1]);
		close(cp[0]);
		close(cp[1]);
		s->ctl_fd = -1;
		stream_destroy(s->stream);
		s->stream = NULL;
		return -1;
	}
	br = sshbridge_create(sp[0], s->stream,
			      s->cfg->is_host ? LINGER_HOST_MS : LINGER_CLIENT_MS);

	/* The path is up on entry, so start the liveness clock as alive. */
	pthread_mutex_lock(&s->hb_lock);
	s->hb_last_pong = now_ms();
	s->lost_since_ms = 0;
	pthread_mutex_unlock(&s->hb_lock);
	next_hb = now_ms();

	/* Capture a rendezvous node per family for reconnection (the host was
	 * already locating; ask on the client side too). */
	if (s->cfg->sig_flags & SIG_DHT)
		sig_locate(s->sig);
	s->next_rdv_warm_ms = now_ms();
	s->next_rdv_tell_ms = now_ms() + 1500;

	while (!done) {
		struct pollfd fds[9];
		int timeout, nfds, lnf = 0, bidx, cidx;

		nfds = sig_prepare(s->sig, fds, 5, &timeout);
		if (s->lan)
			lnf = lanlink_prepare(s->lan, fds + nfds, 9 - nfds - 2,
					      &timeout);
		if (timeout < 0 || timeout > 10)
			timeout = 10;
		bidx = nfds + lnf;
		fds[bidx].fd = sshbridge_fd(br);
		fds[bidx].events = sshbridge_events(br);
		fds[bidx].revents = 0;
		cidx = bidx + 1;
		fds[cidx].fd = s->ctl_fd;
		fds[cidx].events = POLLIN;
		fds[cidx].revents = 0;
		poll(fds, (nfds_t)(cidx + 1), timeout);
		sig_dispatch(s->sig, fds, nfds);
		if (s->lan)
			lanlink_dispatch(s->lan, fds + nfds, lnf);
		if (sshbridge_pump(br, fds[bidx].revents, (uint32_t)now_ms()) < 0)
			done = 1;
		if (fds[cidx].revents & (POLLIN | POLLHUP | POLLERR))
			ctl_readable(s);

		if (now_ms() >= next_hb) {
			uint8_t ts[CTL_TS_LEN];

			ctl_put_u64(ts, now_ms());
			ctl_send(s, CTLM_PING, ts, sizeof(ts));
			next_hb = now_ms() + HB_INTERVAL_MS;
		}
		rdv_maintain(s);
		if (now_ms() >= s->next_status_ms) {
			uint64_t now = now_ms(), lp;
			int state;

			pthread_mutex_lock(&s->hb_lock);
			lp = s->hb_last_pong;
			if (now - lp > HB_LOST_MS) {
				if (!s->lost_since_ms)
					s->lost_since_ms = now;
			} else {
				s->lost_since_ms = 0;
			}
			state = s->lost_since_ms ? CONN_LOST : CONN_LIVE;
			pthread_mutex_unlock(&s->hb_lock);
			publish_status(s, state);
			s->next_status_ms = now + 500;
		}
	}

	pthread_join(th, NULL);
	sshbridge_destroy(br);
	close(sp[0]);			/* sp[1] is closed by the ssh module */
	/* Both control-socket ends are ours to close: the ssh module bridges
	 * cp[1] but never closes it. Mark the fd gone first so a stray ctl_send
	 * is a no-op. */
	s->ctl_fd = -1;
	close(cp[0]);
	close(cp[1]);
	stream_destroy(s->stream);
	s->stream = NULL;

	if (s->cfg->is_host)
		return 0;
	return s->ssh_cli_rc;
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
 * Host rendezvous minting. Each family's node is located independently; report
 * both to the view as they arrive, and embed a family in the token the moment
 * it is ready. Hold the token until every reachable family is located (v4+v6 is
 * ideal, so a v4-only peer and a v6-only peer can both reach), but never past
 * the grace, so one slow family cannot block a usable single-family invite. A
 * family found after minting upgrades the token in place.
 */
static void maybe_announce_rendezvous(struct sess *s)
{
	const struct session_obs *o = s->cfg->obs;
	struct sockaddr_storage a4, a6;
	socklen_t l4 = sizeof(a4), l6 = sizeof(a6);
	int have4, have6;

	if (!s->cfg->is_host || !s->cfg->on_rendezvous)
		return;
	if (!(s->cfg->sig_flags & SIG_DHT)) {		/* nothing to locate */
		if (!s->mcast_minted) {
			s->cfg->on_rendezvous(s->cfg->arg, NULL, 0);
			s->mcast_minted = 1;
		}
		return;
	}

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

	/* Mint as soon as a family is ready, then upgrade the token in place when
	 * the other arrives: a single-family-reachable host publishes at once, and
	 * a dual-stack host's invite gains the second family the moment its DHT
	 * converges. */
	if (have4 && !s->minted4) {
		s->cfg->on_rendezvous(s->cfg->arg, (struct sockaddr *)&a4, l4);
		s->minted4 = 1;
	}
	if (have6 && !s->minted6) {
		s->cfg->on_rendezvous(s->cfg->arg, (struct sockaddr *)&a6, l6);
		s->minted6 = 1;
	}
}

int session_run(const struct session_cfg *cfg)
{
	static const char hx[] = "0123456789abcdef";
	struct sess s;
	enum state st = ST_WAIT_DHT;
	uint64_t deadline;
	uint8_t rb[16];
	int j, rc;

	memset(&s, 0, sizeof(s));
	s.cfg = cfg;
	s.ctl_fd = -1;			/* no control channel until run_ssh */
	memcpy(s.auth, cfg->tok.auth, TOKEN_AUTH_LEN);
	pthread_mutex_init(&s.trickle_lock, NULL);
	pthread_mutex_init(&s.status_lock, NULL);	/* s.status zeroed = connecting */
	pthread_mutex_init(&s.hb_lock, NULL);
	pthread_mutex_init(&s.rdv_lock, NULL);
	if (cfg->stun_auto)
		s.stun_servers = stunlist_load(&s.stun_count);
	nat_log_level(cfg->log_level);	/* < 0 silences libjuice (see nat_log_level) */

	/* Stable ICE identity, reused across re-gathers (see nat_config). */
	random_bytes(rb, 4);
	for (j = 0; j < 4; j++) {
		s.ice_ufrag[j * 2] = hx[rb[j] >> 4];
		s.ice_ufrag[j * 2 + 1] = hx[rb[j] & 0xf];
	}
	s.ice_ufrag[8] = '\0';
	random_bytes(rb, 16);
	for (j = 0; j < 16; j++) {
		s.ice_pwd[j * 2] = hx[rb[j] >> 4];
		s.ice_pwd[j * 2 + 1] = hx[rb[j] & 0xf];
	}
	s.ice_pwd[32] = '\0';
	random_bytes(rb, 2);
	s.bind_port = (uint16_t)(40000 + (((rb[0] << 8) | rb[1]) % 20000));

	s.sig = sig_create(cfg->tok.rdv, cfg->sig_flags, cfg->is_host);
	if (!s.sig)
		return 1;
	sig_subscribe(s.sig, on_peer_offer, &s);
	if (cfg->sig_flags & SIG_MCAST) {
		s.lan = lanlink_create(on_transport_recv, &s);
		if (s.lan) {
			sig_set_direct_port(s.sig, lanlink_port(s.lan));
			sig_subscribe_direct(s.sig, on_direct_peer, &s);
			if (cfg->obs && cfg->obs->link) {
				struct sig_mcast_if ifs[16];
				int ni = sig_link_ifaces(s.sig, ifs, 16), k;

				for (k = 0; k < ni; k++)
					cfg->obs->link(cfg->obs->arg, ifs[k].name,
						       ifs[k].has4, ifs[k].has6);
			}
		}
	}
	if (!cfg->is_host)
		client_seed_rendezvous(&s);
	else
		host_seed_anchor(&s);

	s.start_ms = now_ms();
	deadline = s.start_ms + (uint64_t)cfg->connect_timeout_s * 1000;

	while (st != ST_DONE && st != ST_FAIL && now_ms() < deadline) {
		char filtered[NAT_SDP_MAX];
		const struct session_obs *o = cfg->obs;

		pump_once(&s, 100);
		maybe_announce_rendezvous(&s);
		if (now_ms() >= s.next_status_ms) {
			publish_status(&s,
				       st == ST_WAIT_ICE ? CONN_PUNCHING :
				       (st == ST_GATHER || st == ST_SIGNAL) ?
				       CONN_GATHERING : CONN_CONNECTING);
			s.next_status_ms = now_ms() + 500;
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
				o->peer(o->arg, SESSION_PEER_SEEN, b);
				s.peer_state = SESSION_PEER_SEEN;
			}
		}

		switch (st) {
		case ST_WAIT_DHT:
			if (sig_ready(s.sig)) {
				if (nat_setup(&s))
					st = ST_FAIL;
				else
					st = ST_GATHER;
			}
			break;
		case ST_GATHER:
			if (s.have_local_sdp) {
				sdp_filter(s.local_sdp, cfg->family, filtered,
					   sizeof(filtered));
				strncpy(s.local_sdp, filtered,
					sizeof(s.local_sdp) - 1);
				sig_post(s.sig, (const uint8_t *)s.local_sdp,
					 strlen(s.local_sdp));
				if (cfg->is_host && (cfg->sig_flags & SIG_DHT))
					sig_locate(s.sig);
				st = ST_SIGNAL;
			}
			break;
		case ST_SIGNAL:
			if (s.have_peer_sdp && !s.remote_set) {
				sdp_filter(s.peer_sdp, cfg->family, filtered,
					   sizeof(filtered));
				if (nat_set_remote_description(s.nat, filtered)) {
					st = ST_FAIL;
					break;
				}
				s.remote_set = 1;
				s.ice_attempt_start = now_ms();
				if (o && o->peer &&
				    s.peer_state < SESSION_PEER_PUNCHING) {
					o->peer(o->arg, SESSION_PEER_PUNCHING, "");
					s.peer_state = SESSION_PEER_PUNCHING;
				}
				st = ST_WAIT_ICE;
			}
			break;
		case ST_WAIT_ICE:
			if (nat_connected(s.nat) ||
			    (s.lan && lanlink_have_peer(s.lan))) {
				if (s.peer_state < SESSION_PEER_LIVE) {
					char loc[192], rem[192];

					s.status_peer[0] = '\0';
					if (nat_connected(s.nat) &&
					    !nat_selected(s.nat, loc, sizeof(loc),
							  rem, sizeof(rem)))
						cand_addr(rem, s.status_peer,
							  sizeof(s.status_peer));
					else if (s.direct_addr[0])
						snprintf(s.status_peer,
							 sizeof(s.status_peer),
							 "%s", s.direct_addr);
					if (o && o->peer)
						o->peer(o->arg,
							SESSION_PEER_LIVE,
							s.status_peer);
					s.peer_state = SESSION_PEER_LIVE;
				}
				st = ST_RUN;
				break;
			}
			if (nat_failed(s.nat) ||
			    now_ms() - s.ice_attempt_start > ICE_ATTEMPT_MS) {
				s.ice_attempt++;
				nat_destroy(s.nat);
				s.nat = NULL;
				if (nat_setup(&s))
					st = ST_FAIL;
				else
					st = ST_GATHER;
			}
			break;
		case ST_RUN:
			if (o && o->established && !s.established_fired) {
				o->established(o->arg);
				s.established_fired = 1;
			}
			if (run_ssh(&s) == 0) {
				st = ST_DONE;
			} else if (now_ms() + 10000 < deadline) {
				/* ICE reported a path but the peer is not serving
				 * yet; keep signalling and re-check rather than
				 * give up, so the reverse channel can complete. */
				st = ST_WAIT_ICE;
			} else {
				st = ST_FAIL;
			}
			break;
		default:
			break;
		}
	}

	rc = (st == ST_DONE) ? 0 : 1;
	if (s.stream)
		stream_destroy(s.stream);
	if (s.nat)
		nat_destroy(s.nat);
	if (s.lan)
		lanlink_destroy(s.lan);
	sig_destroy(s.sig);
	stunlist_free(s.stun_servers, s.stun_count);
	pthread_mutex_destroy(&s.trickle_lock);
	pthread_mutex_destroy(&s.status_lock);
	pthread_mutex_destroy(&s.hb_lock);
	pthread_mutex_destroy(&s.rdv_lock);
	return rc;
}
