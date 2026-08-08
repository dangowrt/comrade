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
	char peer_sdp[NAT_SDP_MAX];
	volatile int have_peer_sdp;
	int remote_set;

	uint64_t ice_attempt_start;
	int ice_attempt;
	int rendezvous_announced;

	int ssh_fd;			/* the ssh thread's socketpair end */
	int ssh_cli_rc;
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
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
	const struct token *t = &s->cfg->tok;
	int n = 0;

	if (t->flags & TOKEN_FLAG_EP6_RDV) {
		struct sockaddr_in6 a;

		memset(&a, 0, sizeof(a));
		a.sin6_family = AF_INET6;
		memcpy(&a.sin6_addr, t->ep6_addr, TOKEN_EP6_LEN);
		a.sin6_port = htons(t->ep6_port);
		if (!sig_seed_node(s->sig, (struct sockaddr *)&a, sizeof(a)))
			n++;
	}
	if (t->flags & TOKEN_FLAG_EP4_RDV) {
		struct sockaddr_in a;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		memcpy(&a.sin_addr, t->ep4_addr, TOKEN_EP4_LEN);
		a.sin_port = htons(t->ep4_port);
		if (!sig_seed_node(s->sig, (struct sockaddr *)&a, sizeof(a)))
			n++;
	}
	return n;
}

static void on_local_sdp(void *arg, const char *sdp)
{
	struct sess *s = arg;

	strncpy(s->local_sdp, sdp, sizeof(s->local_sdp) - 1);
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

static int nat_setup(struct sess *s)
{
	static char bind_addr[64];
	struct nat_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.stun_host = s->cfg->stun_host;
	cfg.stun_port = s->cfg->stun_port;
	if (!s->cfg->stun_host && !(s->cfg->sig_flags & SIG_MCAST)) {
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

/* Host: advertise the rendezvous once, via the located DHT node or (multicast
 * only) immediately, so the caller can publish the token. */
static void maybe_announce_rendezvous(struct sess *s)
{
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);

	if (!s->cfg->is_host || s->rendezvous_announced || !s->cfg->on_rendezvous)
		return;
	if (!(s->cfg->sig_flags & SIG_DHT)) {
		s->cfg->on_rendezvous(s->cfg->arg, NULL, 0);
		s->rendezvous_announced = 1;
		return;
	}
	if (sig_located(s->sig, (struct sockaddr *)&ss, &sl)) {
		s->cfg->on_rendezvous(s->cfg->arg, (struct sockaddr *)&ss, sl);
		s->rendezvous_announced = 1;
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
		}
	}
	if (!cfg->is_host)
		client_seed_rendezvous(&s);

	deadline = now_ms() + (uint64_t)cfg->connect_timeout_s * 1000;

	while (st != ST_DONE && st != ST_FAIL && now_ms() < deadline) {
		char filtered[NAT_SDP_MAX];

		pump_once(&s, 100);
		maybe_announce_rendezvous(&s);

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
				st = ST_WAIT_ICE;
			}
			break;
		case ST_WAIT_ICE:
			if (nat_connected(s.nat) ||
			    (s.lan && lanlink_have_peer(s.lan))) {
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
