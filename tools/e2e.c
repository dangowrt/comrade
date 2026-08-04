#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base64.h"
#include "bencode.h"
#include "bep44.h"
#include "candpolicy.h"
#include "dhtnode.h"
#include "keys.h"
#include "nat.h"
#include "stream.h"
#include "token.h"

#define E2E_PAYLOAD (64 * 1024)
#define E2E_CONV 0x70326531

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
	struct session_keys keys;

	struct dhtnode *node;
	struct bep44_engine *engine;
	struct nat_agent *nat;
	struct stream *stream;

	char local_sdp[NAT_SDP_MAX];
	volatile int have_local_sdp;

	char peer_sdp[NAT_SDP_MAX];
	volatile int have_peer_sdp;

	int64_t put_seq;
	uint64_t next_put_ms;
	uint64_t next_get_ms;
	int remote_set;

	uint8_t *tx;
	uint8_t *rx_expect;
	uint8_t *rx;
	size_t rx_got;
	int tx_sent;
	uint64_t linger_deadline;
} g;

static const struct {
	const char *host;
	uint16_t port;
} stun_servers[] = {
	{ "stun.linphone.org", 3478 },
	{ "stun.sipgate.net", 3478 },
	{ "stunserver.stunprotocol.org", 3478 },
	{ "stun.nextcloud.com", 443 },
	{ "stun.antisip.com", 3478 },
	{ "stun.voipgate.com", 3478 },
	{ "stun.cloudflare.com", 3478 },
};

static void stun_pick_default(void)
{
	uint8_t r = 0;
	size_t n = sizeof(stun_servers) / sizeof(stun_servers[0]);

	random_bytes(&r, 1);
	g.stun_host = stun_servers[r % n].host;
	g.stun_port = stun_servers[r % n].port;
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static const char *put_salt(void)
{
	return g.role_a ? "e2e-a" : "e2e-b";
}

static const char *get_salt(void)
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

static void on_put(void *arg, int stored)
{
	(void)arg;
	fprintf(stderr, "[e2e] offer stored on %d nodes\n", stored);
}

static void on_get(void *arg, const uint8_t *v, size_t v_len, int64_t seq)
{
	const uint8_t *sealed;
	size_t sealed_len;
	uint8_t plain[NAT_SDP_MAX];
	int n;

	(void)arg;
	(void)seq;
	if (!v || g.have_peer_sdp)
		return;
	if (benc_str_get(v, v_len, &sealed, &sealed_len))
		return;
	n = msg_open(plain, sizeof(plain) - 1, g.keys.sig_key, sealed, sealed_len);
	if (n < 0)
		return;
	plain[n] = '\0';
	memcpy(g.peer_sdp, plain, (size_t)n + 1);
	g.have_peer_sdp = 1;
	fprintf(stderr, "[e2e] peer offer received (%d bytes)\n", n);
}

static void publish_offer(void)
{
	uint8_t sealed[NAT_SDP_MAX + SEAL_OVERHEAD];
	uint8_t value[BEP44_MAX_VALUE];
	struct benc_buf vb;
	int slen;

	slen = msg_seal(sealed, sizeof(sealed), g.keys.sig_key,
			(const uint8_t *)g.local_sdp, strlen(g.local_sdp));
	if (slen < 0)
		return;
	benc_buf_init(&vb, value, sizeof(value));
	benc_str_add(&vb, sealed, (size_t)slen);
	if (vb.err) {
		fprintf(stderr, "[e2e] offer too large for DHT value (%d sealed)\n", slen);
		return;
	}
	bep44_put(g.engine, g.keys.bep44_sk, g.keys.bep44_pk, put_salt(),
		  value, vb.len, ++g.put_seq, on_put, NULL);
}

static void pump_once(int timeout_cap_ms)
{
	struct pollfd fds[4];
	int timeout, nfds;

	nfds = dhtnode_prepare(g.node, fds, 4, &timeout);
	if (timeout > timeout_cap_ms)
		timeout = timeout_cap_ms;
	poll(fds, (nfds_t)nfds, timeout);
	dhtnode_dispatch(g.node, fds, nfds);
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
		else {
			fprintf(stderr,
				"usage: %s --secret <b64> --role {a|b} --family {4|6}\n"
				"          [--stun host|none --stun-port p] [--timeout s]\n"
				"          [--log N]  (libjuice level: 0 verbose .. 5 fatal)\n"
				"  --stun defaults to a random community STUN server;\n"
				"         pass 'none' to force a direct (no-STUN) path.\n",
				argv[0]);
			return 2;
		}
	}
	if (g.log_level >= 0)
		nat_log_level(g.log_level);

	if (!stun_arg)
		stun_pick_default();
	else if (strcmp(stun_arg, "none"))
		g.stun_host = stun_arg;
	if (g.stun_host)
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
	keys_derive(&g.keys, rdv);

	g.tx = malloc(E2E_PAYLOAD);
	g.rx = malloc(E2E_PAYLOAD);
	g.rx_expect = malloc(E2E_PAYLOAD);
	if (!g.tx || !g.rx || !g.rx_expect)
		return 1;
	for (k = 0; k < E2E_PAYLOAD; k++) {
		g.tx[k] = (uint8_t)((g.role_a ? 0xA0 : 0xB0) ^ (k * 131 + 7));
		g.rx_expect[k] = (uint8_t)((g.role_a ? 0xB0 : 0xA0) ^ (k * 131 + 7));
	}

	g.node = dhtnode_create();
	if (!g.node) {
		fprintf(stderr, "error: dhtnode_create failed\n");
		return 1;
	}
	g.engine = dhtnode_engine(g.node);

	fprintf(stderr, "[e2e] role %s, family IPv%d, joining DHT...\n",
		g.role_a ? "a" : "b", g.family);

	start = now_ms();
	deadline = start + (uint64_t)timeout_s * 1000;

	while (st != ST_DONE && st != ST_FAIL && now_ms() < deadline) {
		pump_once(100);

		switch (st) {
		case ST_WAIT_DHT:
			if (dhtnode_ready(g.node)) {
				struct nat_config cfg;

				memset(&cfg, 0, sizeof(cfg));
				cfg.stun_host = g.stun_host;
				cfg.stun_port = g.stun_port;
				cfg.on_local_sdp = on_local_sdp;
				cfg.on_state = on_nat_state;
				cfg.on_recv = on_nat_recv;
				g.nat = nat_create(&cfg);
				if (!g.nat || nat_gather(g.nat)) {
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
				st = ST_SIGNAL;
				g.next_put_ms = 0;
				g.next_get_ms = 0;
			}
			break;
		case ST_SIGNAL:
			if (now_ms() >= g.next_put_ms) {
				publish_offer();
				g.next_put_ms = now_ms() + 4000;
			}
			if (!g.have_peer_sdp && now_ms() >= g.next_get_ms) {
				bep44_get(g.engine, g.keys.bep44_pk, get_salt(),
					  on_get, NULL);
				g.next_get_ms = now_ms() + 2000;
			}
			if (g.have_peer_sdp && !g.remote_set) {
				char filtered[NAT_SDP_MAX];

				dump_sdp("peer candidates received", g.peer_sdp);
				sdp_filter(g.peer_sdp, g.family, filtered, sizeof(filtered));
				if (nat_set_remote_description(g.nat, filtered)) {
					st = ST_FAIL;
					break;
				}
				g.remote_set = 1;
				fprintf(stderr, "[e2e] remote set, running ICE...\n");
				st = ST_WAIT_ICE;
			}
			break;
		case ST_WAIT_ICE:
			if (now_ms() >= g.next_put_ms) {
				publish_offer();
				g.next_put_ms = now_ms() + 4000;
			}
			if (nat_connected(g.nat))
				st = ST_RUN;
			else if (nat_failed(g.nat))
				st = ST_FAIL;
			break;
		case ST_RUN:
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

	if (st == ST_DONE && !memcmp(g.rx, g.rx_expect, E2E_PAYLOAD)) {
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
	dhtnode_free(g.node);
	free(g.tx);
	free(g.rx);
	free(g.rx_expect);
	return st == ST_DONE ? 0 : 1;
}
