/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <arpa/inet.h>
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
#include "keys.h"
#include "lanlink.h"
#include "nat.h"
#include "session.h"
#include "sig.h"
#include "sshbridge.h"
#include "sshc.h"
#include "sshd.h"
#include "stream.h"

#define SESSION_CONV 0x70326531
/*
 * Backstop only, well above real-internet connect time: libjuice reaches its
 * own FAILED verdict after a full ICE negotiation, which drives retry; this
 * catches an agent that neither connects nor fails.
 */
#define ICE_ATTEMPT_MS 90000

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

	int ssh_fd;			/* the ssh thread's socketpair end */
	int ssh_cli_rc;
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
static void obs_report_net(struct sess *s)
{
	const struct session_obs *o = s->cfg->obs;
	const char *p = s->local_sdp;

	if (!o || !o->net)
		return;
	while ((p = strstr(p, "a=candidate:")) != NULL) {
		char addr[64], typ[16];
		int via, fam;

		if (sscanf(p, "a=candidate:%*s %*d %*s %*u %63s %*d typ %15s",
			   addr, typ) == 2) {
			if (!strcmp(typ, "host"))
				via = NET_VIA_DIRECT;
			else if (!strcmp(typ, "srflx"))
				via = NET_VIA_STUN;
			else
				via = -1;
			if (via >= 0) {
				fam = strchr(addr, ':') ? 6 : 4;
				o->net(o->arg, fam, addr_scope(addr), via, addr);
			}
		}
		p += 12;
	}
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
	 * a time); feed them straight into the already-primed agent. */
	if (s->nat && s->remote_set) {
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
	struct sess *s = arg;

	if (s->lan && lanlink_have_peer(s->lan))
		return lanlink_send(s->lan, data, len);
	if (s->nat && nat_connected(s->nat))
		return nat_send(s->nat, data, len);
	return -1;
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

/*
 * Independent community STUN servers for stun_auto, rotated across re-gathers
 * so one being down does not sink NAT discovery. No big-tech defaults.
 * TODO: source the hourly-validated set from the always-online-stun project at
 * build time rather than hardcoding.
 */
static const char *stun_auto_servers[] = {
	"stun.nextcloud.com",
	"stun.ipfire.org",
	"stun.sipgate.net",
};

static int nat_setup(struct sess *s)
{
	static char bind_addr[64];
	struct nat_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	if (source_addr(AF_INET6, s->src6, sizeof(s->src6)))
		s->src6[0] = '\0';		/* no global v6 source */
	cfg.stun_host = s->cfg->stun_host;
	cfg.stun_port = s->cfg->stun_port;
	if (!cfg.stun_host && s->cfg->stun_auto) {
		int n = (int)(sizeof(stun_auto_servers) /
			      sizeof(stun_auto_servers[0]));

		cfg.stun_host = stun_auto_servers[s->ice_attempt % n];
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
	o.send = s->cfg->test_send;
	o.send_len = s->cfg->test_send_len;
	o.recv = s->cfg->test_recv;
	o.recv_cap = s->cfg->test_recv_cap;
	o.recv_len = s->cfg->test_recv_len;
	s->ssh_cli_rc = sshc_connect_fd(s->ssh_fd, &o);
	return NULL;
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
	int sp[2];
	int done = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		return -1;
	s->stream = stream_create(SESSION_CONV, on_stream_output, s);
	if (!s->stream) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}
	s->ssh_fd = sp[1];
	if (pthread_create(&th, NULL,
			   s->cfg->is_host ? ssh_srv_thread : ssh_cli_thread, s)) {
		close(sp[0]);
		close(sp[1]);
		stream_destroy(s->stream);
		s->stream = NULL;
		return -1;
	}
	br = sshbridge_create(sp[0], s->stream);

	while (!done) {
		struct pollfd fds[8];
		int timeout, nfds, lnf = 0, bidx;

		nfds = sig_prepare(s->sig, fds, 5, &timeout);
		if (s->lan)
			lnf = lanlink_prepare(s->lan, fds + nfds, 8 - nfds - 1,
					      &timeout);
		if (timeout < 0 || timeout > 10)
			timeout = 10;
		bidx = nfds + lnf;
		fds[bidx].fd = sshbridge_fd(br);
		fds[bidx].events = sshbridge_events(br);
		fds[bidx].revents = 0;
		poll(fds, (nfds_t)(bidx + 1), timeout);
		sig_dispatch(s->sig, fds, nfds);
		if (s->lan)
			lanlink_dispatch(s->lan, fds + nfds, lnf);
		if (sshbridge_pump(br, fds[bidx].revents, (uint32_t)now_ms()) < 0)
			done = 1;
	}

	pthread_join(th, NULL);
	sshbridge_destroy(br);
	close(sp[0]);			/* sp[1] is closed by the ssh module */
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
	memcpy(s.auth, cfg->tok.auth, TOKEN_AUTH_LEN);
	if (cfg->log_level >= 0)
		nat_log_level(cfg->log_level);

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
		if (o) {
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
				if (o && o->peer &&
				    s.peer_state < SESSION_PEER_LIVE) {
					o->peer(o->arg, SESSION_PEER_LIVE, "");
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
	return rc;
}
