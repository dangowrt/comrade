/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "base64.h"
#include "candpolicy.h"
#include "keys.h"
#include "nat.h"
#include "sig.h"
#include "sshbridge.h"
#include "sshc.h"
#include "sshd.h"
#include "stream.h"
#include "token.h"

#define E2E_PAYLOAD (64 * 1024)
#define E2E_CONV 0x70326531
/*
 * Retry is driven by libjuice's own FAILED verdict (nat_failed), which it
 * reaches after its full ICE negotiation (~tens of seconds). This is only a
 * backstop against an agent that neither connects nor fails; it must stay
 * well above the real-internet connect time or it would abort attempts that
 * are still in progress.
 */
#define ICE_ATTEMPT_MS 90000

enum state {
	ST_WAIT_DHT,
	ST_GATHER,
	ST_SIGNAL,
	ST_WAIT_ICE,
	ST_RUN,
	ST_LINGER,
	ST_DONE,
	ST_FAIL,
};

static struct {
	int role_a;
	int family;
	const char *stun_host;
	uint16_t stun_port;
	int log_level;
	int stun_auto;			/* rotate community STUN servers on retry */
	unsigned sig_flags;

	/* Stable ICE identity, reused across every retry (see nat_config). */
	uint16_t bind_port;
	char ice_ufrag[16];
	char ice_pwd[40];

	struct sig *sig;
	struct nat_agent *nat;
	struct stream *stream;

	char local_sdp[NAT_SDP_MAX];
	volatile int have_local_sdp;

	char peer_sdp[NAT_SDP_MAX];
	volatile int have_peer_sdp;
	int remote_set;

	uint8_t *tx;
	uint8_t *rx_expect;
	uint8_t *rx;
	size_t rx_got;
	int tx_sent;
	uint64_t linger_deadline;
	uint64_t ice_attempt_start;
	int ice_attempt;

	/* SSH-over-stream mode (--ssh). */
	int ssh_mode;
	int ssh_ok;
	void *hostkey;			/* host: ephemeral ssh_key */
	uint8_t auth[TOKEN_AUTH_LEN];	/* shared session secret */
	uint8_t host_fp[32];		/* host key fingerprint */
	volatile int have_fp;		/* client: fingerprint received */
} g;

#define SSH_FP_CHANNEL "sshfp"
#define SSH_NONCE 4096

static uint8_t ssh_tx[SSH_NONCE];
static uint8_t ssh_rx[SSH_NONCE];
static size_t ssh_rx_got;
static int ssh_cli_rc;
static int ssh_fd;			/* the ssh thread's socketpair end */

/* Dual-stack servers first, so an IPv6 auto pick is likely to land on one
 * that answers over v6. stunserver.stunprotocol.org was dropped: it is
 * defunct and no longer resolves. */
static const struct {
	const char *host;
	uint16_t port;
} stun_servers[] = {
	{ "stun.cloudflare.com", 3478 },	/* dual-stack */
	{ "stun.l.google.com", 19302 },		/* dual-stack */
	{ "stun.nextcloud.com", 443 },		/* dual-stack */
	{ "stun.antisip.com", 3478 },		/* dual-stack */
	{ "stun.linphone.org", 3478 },
	{ "stun.sipgate.net", 3478 },
	{ "stun.voipgate.com", 3478 },
};

/*
 * Pick a STUN server, walking the list so successive calls (the retry path)
 * rotate to a different server. A dead or unresponsive server therefore only
 * costs one attempt, not the whole run.
 */
static void stun_pick_default(void)
{
	static int idx = -1;
	int n = (int)(sizeof(stun_servers) / sizeof(stun_servers[0]));

	if (idx < 0) {
		uint8_t r = 0;

		random_bytes(&r, 1);
		idx = (int)r % n;
	} else {
		idx = (idx + 1) % n;
	}
	g.stun_host = stun_servers[idx].host;
	g.stun_port = stun_servers[idx].port;
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static const char *put_channel(void)
{
	return g.role_a ? "e2e-a" : "e2e-b";
}

static const char *get_channel(void)
{
	return g.role_a ? "e2e-b" : "e2e-a";
}

static void sdp_filter(const char *in, int family, char *out, size_t outlen)
{
	struct cand_policy pol;

	cand_policy_default(&pol);
	cand_sdp_filter(in, family, &pol, out, outlen);
}

static void on_local_sdp(void *arg, const char *sdp)
{
	(void)arg;
	strncpy(g.local_sdp, sdp, sizeof(g.local_sdp) - 1);
	g.have_local_sdp = 1;
}

static void on_nat_recv(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	if (g.stream)
		stream_input(g.stream, data, len);
}

static void on_nat_state(void *arg, int connected, int failed)
{
	(void)arg;
	fprintf(stderr, "[e2e] ICE state change: connected=%d failed=%d at %llums\n",
		connected, failed, (unsigned long long)now_ms());
}

static void on_peer_offer(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	if (len >= sizeof(g.peer_sdp))
		len = sizeof(g.peer_sdp) - 1;
	memcpy(g.peer_sdp, data, len);
	g.peer_sdp[len] = '\0';
	g.have_peer_sdp = 1;
	fprintf(stderr, "[e2e] peer offer received (%zu bytes)\n", len);
}

static void on_host_fp(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	if (len != 32)
		return;
	memcpy(g.host_fp, data, 32);
	g.have_fp = 1;
	fprintf(stderr, "[e2e] host key fingerprint received\n");
}

static void dump_sdp(const char *label, const char *sdp)
{
	const char *line = sdp;

	fprintf(stderr, "[e2e] %s:\n", label);
	while (*line) {
		const char *nl = strchr(line, '\n');
		int len = nl ? (int)(nl - line) : (int)strlen(line);

		if (strstr(line, "candidate:") && strstr(line, "candidate:") < line + len)
			fprintf(stderr, "        %.*s\n", len, line);
		if (!nl)
			break;
		line = nl + 1;
	}
}

static int on_stream_output(void *arg, const uint8_t *data, size_t len)
{
	(void)arg;
	return nat_send(g.nat, data, len);
}

/*
 * Ask the kernel which local address it would source outbound packets from
 * toward a generic global destination of the given family. UDP connect()
 * sends no packet; it only triggers route and source-address selection, so
 * this discloses nothing to any third party (unlike STUN). Used to bind the
 * ICE agent to its real source so its host candidate matches what the peer
 * will actually see, which is what the no-STUN path needs.
 */
static int source_addr(int family, char *out, size_t outlen)
{
	static const char *probe6 = "2001:db8::1";
	static const char *probe4 = "192.0.2.1";
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	int s, rc = -1;

	s = socket(family, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	memset(&ss, 0, sizeof(ss));
	if (family == AF_INET6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;

		a->sin6_family = AF_INET6;
		a->sin6_port = htons(9);
		if (inet_pton(AF_INET6, probe6, &a->sin6_addr) != 1 ||
		    connect(s, (struct sockaddr *)a, sizeof(*a)))
			goto out;
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;

		a->sin_family = AF_INET;
		a->sin_port = htons(9);
		if (inet_pton(AF_INET, probe4, &a->sin_addr) != 1 ||
		    connect(s, (struct sockaddr *)a, sizeof(*a)))
			goto out;
	}

	memset(&ss, 0, sizeof(ss));
	if (getsockname(s, (struct sockaddr *)&ss, &slen))
		goto out;
	if (family == AF_INET6)
		rc = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr,
			       out, outlen) ? 0 : -1;
	else
		rc = inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr,
			       out, outlen) ? 0 : -1;
out:
	close(s);
	return rc;
}

static int nat_setup(void)
{
	static char bind_addr[64];
	struct nat_config cfg;

	if (g.stun_auto) {
		stun_pick_default();
		fprintf(stderr, "[e2e] STUN: %s:%u\n", g.stun_host, g.stun_port);
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.stun_host = g.stun_host;
	cfg.stun_port = g.stun_port;
	if (!g.stun_host) {
		int af = g.family == 6 ? AF_INET6 : AF_INET;

		if (!source_addr(af, bind_addr, sizeof(bind_addr))) {
			cfg.bind_address = bind_addr;
			fprintf(stderr,
				"[e2e] no STUN: binding ICE to discovered source %s\n",
				bind_addr);
		}
	}
	cfg.bind_port = g.bind_port;
	cfg.ice_ufrag = g.ice_ufrag;
	cfg.ice_pwd = g.ice_pwd;
	cfg.on_local_sdp = on_local_sdp;
	cfg.on_state = on_nat_state;
	cfg.on_recv = on_nat_recv;

	g.have_local_sdp = 0;
	g.local_sdp[0] = '\0';
	g.remote_set = 0;

	g.nat = nat_create(&cfg);
	if (!g.nat || nat_gather(g.nat))
		return -1;
	return 0;
}

static void pump_once(int timeout_cap_ms)
{
	struct pollfd fds[4];
	int timeout, nfds;

	nfds = sig_prepare(g.sig, fds, 4, &timeout);
	if (timeout > timeout_cap_ms)
		timeout = timeout_cap_ms;
	poll(fds, (nfds_t)nfds, timeout);
	sig_dispatch(g.sig, fds, nfds);
}

static void state_run_step(void)
{
	int n;

	if (!g.stream) {
		char loc[256];
		char rem[256];

		g.stream = stream_create(E2E_CONV, on_stream_output, NULL);
		if (!g.stream) {
			g.tx = NULL;
			return;
		}
		if (!nat_selected(g.nat, loc, sizeof(loc), rem, sizeof(rem)))
			fprintf(stderr, "[e2e] selected pair:\n  local  %s\n  remote %s\n",
				loc, rem);
	}
	if (!g.tx_sent) {
		stream_send(g.stream, g.tx, E2E_PAYLOAD);
		g.tx_sent = 1;
	}
	stream_update(g.stream, (uint32_t)now_ms());
	while ((n = stream_recv(g.stream, g.rx + g.rx_got,
				(int)(E2E_PAYLOAD - g.rx_got))) > 0)
		g.rx_got += (size_t)n;
}

static void *ssh_srv_thread(void *p)
{
	struct sshd_opts o;

	(void)p;
	memset(&o, 0, sizeof(o));
	o.hostkey = g.hostkey;
	memcpy(o.auth, g.auth, sizeof(o.auth));
	o.command = "cat";	/* deterministic echo for the test oracle */
	o.use_pty = 0;
	sshd_serve_fd(ssh_fd, &o);
	return NULL;
}

static void *ssh_cli_thread(void *p)
{
	struct sshc_opts o;

	(void)p;
	memset(&o, 0, sizeof(o));
	memcpy(o.host_fp, g.host_fp, 32);
	memcpy(o.auth, g.auth, sizeof(o.auth));
	o.interactive = 0;
	o.send = ssh_tx;
	o.send_len = SSH_NONCE;
	o.recv = ssh_rx;
	o.recv_cap = SSH_NONCE;
	o.recv_len = &ssh_rx_got;
	ssh_cli_rc = sshc_connect_fd(ssh_fd, &o);
	return NULL;
}

/*
 * Run the SSH session over the connected KCP stream. The host serves cat and
 * the client sends a nonce and verifies the echo, so a byte-exact round-trip
 * proves the whole stack: sealed signalling, ICE punch, KCP, and libssh with
 * a pinned host key, over the real path.
 */
static int run_ssh(void)
{
	struct sshbridge *br;
	pthread_t th;
	int sp[2];
	int done = 0;
	uint64_t deadline = now_ms() + 30000;

	if (!g.role_a) {
		uint64_t fp_deadline = now_ms() + 15000;

		while (!g.have_fp && now_ms() < fp_deadline)
			pump_once(100);
		if (!g.have_fp) {
			fprintf(stderr, "[e2e] host fingerprint never arrived\n");
			return -1;
		}
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		return -1;
	g.stream = stream_create(E2E_CONV, on_stream_output, NULL);
	if (!g.stream) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}
	{
		char loc[256], rem[256];

		if (!nat_selected(g.nat, loc, sizeof(loc), rem, sizeof(rem)))
			fprintf(stderr, "[e2e] selected pair:\n  local  %s\n  remote %s\n",
				loc, rem);
	}

	ssh_fd = sp[1];
	if (pthread_create(&th, NULL,
			   g.role_a ? ssh_srv_thread : ssh_cli_thread, NULL)) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}

	br = sshbridge_create(sp[0], g.stream);
	fprintf(stderr, "[e2e] ssh %s running over the stream...\n",
		g.role_a ? "server" : "client");

	while (!done && now_ms() < deadline) {
		struct pollfd fds[8];
		int timeout, nfds;

		nfds = sig_prepare(g.sig, fds, 6, &timeout);
		if (timeout < 0 || timeout > 10)
			timeout = 10;
		fds[nfds].fd = sshbridge_fd(br);
		fds[nfds].events = sshbridge_events(br);
		fds[nfds].revents = 0;
		poll(fds, (nfds_t)(nfds + 1), timeout);
		sig_dispatch(g.sig, fds, nfds);
		if (sshbridge_pump(br, fds[nfds].revents, (uint32_t)now_ms()) < 0)
			done = 1;
	}

	pthread_join(th, NULL);
	sshbridge_destroy(br);
	close(sp[0]);	/* sp[1] is closed by the ssh module */

	if (!done) {
		fprintf(stderr, "[e2e] ssh session did not close in time\n");
		return -1;
	}
	if (g.role_a) {
		fprintf(stderr, "[e2e] host: ssh session served and closed\n");
		return 0;
	}
	if (ssh_cli_rc != 0 || ssh_rx_got != SSH_NONCE ||
	    memcmp(ssh_rx, ssh_tx, SSH_NONCE)) {
		fprintf(stderr, "[e2e] client: echo mismatch rc=%d got=%zu/%d\n",
			ssh_cli_rc, ssh_rx_got, SSH_NONCE);
		return -1;
	}
	fprintf(stderr, "[e2e] client: %d-byte echo verified over ssh\n", SSH_NONCE);
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t rdv[TOKEN_RDV_LEN];
	const char *secret = NULL;
	enum state st = ST_WAIT_DHT;
	uint64_t start, deadline;
	int timeout_s = 120;
	int i;
	size_t k;
	const char *stun_arg = NULL;

	memset(&g, 0, sizeof(g));
	g.family = 6;
	g.stun_port = 3478;
	g.log_level = -1;
	g.sig_flags = SIG_DHT;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--secret") && i + 1 < argc)
			secret = argv[++i];
		else if (!strcmp(argv[i], "--role") && i + 1 < argc)
			g.role_a = !strcmp(argv[++i], "a");
		else if (!strcmp(argv[i], "--family") && i + 1 < argc)
			g.family = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--stun") && i + 1 < argc)
			stun_arg = argv[++i];
		else if (!strcmp(argv[i], "--stun-port") && i + 1 < argc)
			g.stun_port = (uint16_t)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
			timeout_s = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--log") && i + 1 < argc)
			g.log_level = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--mcast"))
			g.sig_flags |= SIG_MCAST;
		else if (!strcmp(argv[i], "--no-dht"))
			g.sig_flags &= ~SIG_DHT;
		else if (!strcmp(argv[i], "--ssh"))
			g.ssh_mode = 1;
		else {
			fprintf(stderr,
				"usage: %s --secret <b64> --role {a|b} --family {4|6}\n"
				"          [--stun host|none --stun-port p] [--timeout s]\n"
				"          [--log N]  (libjuice level: 0 verbose .. 5 fatal)\n"
				"          [--mcast] [--no-dht]  (link-local multicast; LAN-only)\n"
				"          [--ssh]  (run a real libssh session over the stream)\n"
				"  --stun defaults to a random community STUN server;\n"
				"         pass 'none' to force a direct (no-STUN) path.\n",
				argv[0]);
			return 2;
		}
	}
	if (g.log_level >= 0)
		nat_log_level(g.log_level);

	if (!stun_arg)
		g.stun_auto = 1;
	else if (strcmp(stun_arg, "none"))
		g.stun_host = stun_arg;
	if (g.stun_auto)
		fprintf(stderr, "[e2e] STUN: auto (rotating community servers)\n");
	else if (g.stun_host)
		fprintf(stderr, "[e2e] STUN: %s:%u\n", g.stun_host, g.stun_port);
	else
		fprintf(stderr, "[e2e] STUN: none (direct)\n");
	if (!secret) {
		fprintf(stderr, "error: --secret required\n");
		return 2;
	}
	if (base64url_decode(secret, strlen(secret), rdv, sizeof(rdv)) !=
	    (int)sizeof(rdv)) {
		fprintf(stderr, "error: bad secret\n");
		return 2;
	}

	{
		static const char hx[] = "0123456789abcdef";
		uint8_t rb[16];
		int j;

		random_bytes(rb, 4);
		for (j = 0; j < 4; j++) {
			g.ice_ufrag[j * 2] = hx[rb[j] >> 4];
			g.ice_ufrag[j * 2 + 1] = hx[rb[j] & 0xf];
		}
		g.ice_ufrag[8] = '\0';
		random_bytes(rb, 16);
		for (j = 0; j < 16; j++) {
			g.ice_pwd[j * 2] = hx[rb[j] >> 4];
			g.ice_pwd[j * 2 + 1] = hx[rb[j] & 0xf];
		}
		g.ice_pwd[32] = '\0';
		random_bytes(rb, 2);
		g.bind_port = (uint16_t)(40000 + (((rb[0] << 8) | rb[1]) % 20000));
		fprintf(stderr, "[e2e] stable ICE identity: port %u ufrag %s\n",
			g.bind_port, g.ice_ufrag);
	}

	g.tx = malloc(E2E_PAYLOAD);
	g.rx = malloc(E2E_PAYLOAD);
	g.rx_expect = malloc(E2E_PAYLOAD);
	if (!g.tx || !g.rx || !g.rx_expect)
		return 1;
	for (k = 0; k < E2E_PAYLOAD; k++) {
		g.tx[k] = (uint8_t)((g.role_a ? 0xA0 : 0xB0) ^ (k * 131 + 7));
		g.rx_expect[k] = (uint8_t)((g.role_a ? 0xB0 : 0xA0) ^ (k * 131 + 7));
	}

	g.sig = sig_create(rdv, g.sig_flags);
	if (!g.sig) {
		fprintf(stderr, "error: sig_create failed\n");
		return 1;
	}
	sig_subscribe(g.sig, get_channel(), on_peer_offer, NULL);

	if (g.ssh_mode) {
		memcpy(g.auth, rdv, sizeof(g.auth));
		if (g.role_a) {
			g.hostkey = sshd_hostkey_new(g.host_fp);
			if (!g.hostkey) {
				fprintf(stderr, "error: host key generation failed\n");
				return 1;
			}
			for (k = 0; k < SSH_NONCE; k++)
				ssh_tx[k] = (uint8_t)(k * 97 + 13);
		} else {
			for (k = 0; k < SSH_NONCE; k++)
				ssh_tx[k] = (uint8_t)(k * 97 + 13);
			sig_subscribe(g.sig, SSH_FP_CHANNEL, on_host_fp, NULL);
		}
	}

	fprintf(stderr, "[e2e] role %s, family IPv%d, signalling%s%s%s...\n",
		g.role_a ? "a" : "b", g.family,
		(g.sig_flags & SIG_MCAST) ? " mcast" : "",
		(g.sig_flags & SIG_DHT) ? " dht" : "",
		g.ssh_mode ? " +ssh" : "");

	start = now_ms();
	deadline = start + (uint64_t)timeout_s * 1000;

	while (st != ST_DONE && st != ST_FAIL && now_ms() < deadline) {
		pump_once(100);

		switch (st) {
		case ST_WAIT_DHT:
			if (sig_ready(g.sig)) {
				if (nat_setup()) {
					st = ST_FAIL;
					break;
				}
				fprintf(stderr, "[e2e] DHT ready, gathering candidates...\n");
				st = ST_GATHER;
			}
			break;
		case ST_GATHER:
			if (g.have_local_sdp) {
				char filtered[NAT_SDP_MAX];

				dump_sdp("all gathered local candidates", g.local_sdp);
				sdp_filter(g.local_sdp, g.family, filtered, sizeof(filtered));
				strncpy(g.local_sdp, filtered, sizeof(g.local_sdp) - 1);
				dump_sdp("published local candidates (filtered)", g.local_sdp);
				sig_publish(g.sig, put_channel(),
					    (const uint8_t *)g.local_sdp, strlen(g.local_sdp));
				if (g.ssh_mode && g.role_a)
					sig_publish(g.sig, SSH_FP_CHANNEL, g.host_fp, 32);
				st = ST_SIGNAL;
			}
			break;
		case ST_SIGNAL:
			if (g.have_peer_sdp && !g.remote_set) {
				char filtered[NAT_SDP_MAX];

				dump_sdp("peer candidates received", g.peer_sdp);
				sdp_filter(g.peer_sdp, g.family, filtered, sizeof(filtered));
				if (nat_set_remote_description(g.nat, filtered)) {
					st = ST_FAIL;
					break;
				}
				g.remote_set = 1;
				g.ice_attempt_start = now_ms();
				fprintf(stderr, "[e2e] remote set, running ICE (attempt %d)...\n",
					g.ice_attempt + 1);
				st = ST_WAIT_ICE;
			}
			break;
		case ST_WAIT_ICE:
			if (nat_connected(g.nat)) {
				st = ST_RUN;
				break;
			}
			if (nat_failed(g.nat) ||
			    now_ms() - g.ice_attempt_start > ICE_ATTEMPT_MS) {
				g.ice_attempt++;
				fprintf(stderr,
					"[e2e] ICE attempt %d %s, re-gathering with fresh mappings...\n",
					g.ice_attempt,
					nat_failed(g.nat) ? "failed (libjuice gave up)"
							  : "backstop timeout");
				nat_destroy(g.nat);
				g.nat = NULL;
				if (nat_setup())
					st = ST_FAIL;
				else
					st = ST_GATHER;
			}
			break;
		case ST_RUN:
			if (g.ssh_mode) {
				g.ssh_ok = (run_ssh() == 0);
				st = g.ssh_ok ? ST_DONE : ST_FAIL;
				break;
			}
			state_run_step();
			if (!g.stream) {
				st = ST_FAIL;
				break;
			}
			if (g.rx_got >= E2E_PAYLOAD) {
				g.linger_deadline = now_ms() + 15000;
				fprintf(stderr, "[e2e] received full payload, draining sent data...\n");
				st = ST_LINGER;
			}
			break;
		case ST_LINGER:
			stream_update(g.stream, (uint32_t)now_ms());
			if (stream_waitsnd(g.stream) == 0 ||
			    now_ms() >= g.linger_deadline)
				st = ST_DONE;
			break;
		default:
			break;
		}
	}

	if (g.ssh_mode) {
		if (st == ST_DONE && g.ssh_ok)
			printf("E2E PASS role=%s family=%d ssh session over stream in %llums\n",
			       g.role_a ? "a" : "b", g.family,
			       (unsigned long long)(now_ms() - start));
		else
			printf("E2E FAIL role=%s family=%d state=%d (ssh)\n",
			       g.role_a ? "a" : "b", g.family, st);
	} else if (st == ST_DONE && !memcmp(g.rx, g.rx_expect, E2E_PAYLOAD)) {
		printf("E2E PASS role=%s family=%d %zu bytes verified in %llums\n",
		       g.role_a ? "a" : "b", g.family, (size_t)E2E_PAYLOAD,
		       (unsigned long long)(now_ms() - start));
		st = ST_DONE;
	} else {
		printf("E2E FAIL role=%s family=%d state=%d rx=%zu/%d\n",
		       g.role_a ? "a" : "b", g.family, st, g.rx_got, E2E_PAYLOAD);
	}

	if (g.stream)
		stream_destroy(g.stream);
	if (g.nat)
		nat_destroy(g.nat);
	if (g.hostkey)
		sshd_hostkey_free(g.hostkey);
	sig_destroy(g.sig);
	free(g.tx);
	free(g.rx);
	free(g.rx_expect);
	return st == ST_DONE ? 0 : 1;
}
