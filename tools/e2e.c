/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * End-to-end test harness: drives the shared session core (src/session.c) with
 * an echo oracle instead of a terminal, so a byte-exact round-trip proves the
 * whole stack -- sealed signalling, ICE / link-local direct punch, KCP, and
 * pinned libssh -- over the real path. The product CLI (comrade) uses the same
 * core with a real tmux session.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "keys.h"
#include "session.h"
#include "sig.h"
#include "sig_mcast.h"
#include "sshd.h"
#include "token.h"

#define SSH_NONCE 4096

static struct {
	struct token tok;
	int printed;
} host;

/* Encode host.tok and print it for the operator to carry to the client. */
static void print_token(void)
{
	char tokbuf[TOKEN_STR_LEN + 1];

	if (token_encode(&host.tok, tokbuf, sizeof(tokbuf))) {
		fprintf(stderr, "error: token_encode failed\n");
		return;
	}
	printf("COMRADE TOKEN: %s\n", tokbuf);
	fflush(stdout);
	host.printed = 1;
}

/* Embed a located rendezvous node in the token and print it for the operator to
 * carry to the client; called with NULL when there is no node (multicast). */
static void on_rendezvous(void *arg, const struct sockaddr *sa, socklen_t len)
{
	(void)arg;
	(void)len;
	if (host.printed)
		return;
	if (sa && sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		memcpy(host.tok.ep6_addr, &a->sin6_addr, TOKEN_EP6_LEN);
		host.tok.ep6_port = ntohs(a->sin6_port);
		host.tok.flags |= TOKEN_FLAG_EP6_RDV;
		fprintf(stderr, "[e2e] rendezvous node located, embedded in token\n");
	} else if (sa && sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		memcpy(host.tok.ep4_addr, &a->sin_addr, TOKEN_EP4_LEN);
		host.tok.ep4_port = ntohs(a->sin_port);
		host.tok.flags |= TOKEN_FLAG_EP4_RDV;
		fprintf(stderr, "[e2e] rendezvous node located, embedded in token\n");
	}
	print_token();
}

/* Isolated-LAN sibling: embed our own direct endpoint (EPx_RDV clear), mark the
 * token NODHT, and print it. Proves the B2 mint path from the harness. */
static void on_endpoint(void *arg, const struct sockaddr *sa, socklen_t len)
{
	(void)arg;
	(void)len;
	if (host.printed)
		return;
	if (sa && sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		memcpy(host.tok.ep6_addr, &a->sin6_addr, TOKEN_EP6_LEN);
		host.tok.ep6_port = ntohs(a->sin6_port);
		host.tok.flags &= ~TOKEN_FLAG_EP6_RDV;
	} else if (sa && sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		memcpy(host.tok.ep4_addr, &a->sin_addr, TOKEN_EP4_LEN);
		host.tok.ep4_port = ntohs(a->sin_port);
		host.tok.flags &= ~TOKEN_FLAG_EP4_RDV;
	}
	host.tok.flags |= TOKEN_FLAG_NODHT;
	fprintf(stderr, "[e2e] isolated LAN: own endpoint embedded, NODHT set\n");
	print_token();
}

/* `comrade-e2e token <TOKEN>`: decode and print the token's flags/endpoints in a
 * greppable form, so the shell harness can assert the mint (NODHT, EPx_RDV). */
static int inspect_token(const char *s)
{
	struct token t;
	char ip[64];

	if (token_decode(&t, s)) {
		fprintf(stderr, "error: invalid token\n");
		return 2;
	}
	printf("flags=0x%02x nodht=%d ro=%d ep6_rdv=%d ep4_rdv=%d\n",
	       t.flags, !!(t.flags & TOKEN_FLAG_NODHT), !!(t.flags & TOKEN_FLAG_RO),
	       !!(t.flags & TOKEN_FLAG_EP6_RDV), !!(t.flags & TOKEN_FLAG_EP4_RDV));
	if (inet_ntop(AF_INET6, t.ep6_addr, ip, sizeof(ip)))
		printf("ep6=[%s]:%u\n", ip, t.ep6_port);
	if (inet_ntop(AF_INET, t.ep4_addr, ip, sizeof(ip)))
		printf("ep4=%s:%u\n", ip, t.ep4_port);
	return 0;
}

static void mcast_probe_cb(void *arg, const char *salt, const uint8_t *data,
			   size_t len, const struct sockaddr *src, socklen_t srclen)
{
	(void)salt;
	(void)src;
	(void)srclen;
	if (len == 8 && !memcmp(data, "PROBE-OK", 8))
		*(int *)arg = 1;
}

int main(int argc, char **argv)
{
	struct session_cfg cfg;
	uint8_t tx[SSH_NONCE], rx[SSH_NONCE];
	size_t rx_got = 0, k;
	const char *stun_arg = NULL;
	int is_host, i, rc;

	if (argc >= 3 && !strcmp(argv[1], "token"))
		return inspect_token(argv[2]);

	/* Deterministic skip signal for the LAN harnesses: 0 if a usable
	 * multicast interface exists, 77 (ctest SKIP) if not. */
	if (argc >= 2 && !strcmp(argv[1], "mcast-probe")) {
		struct sig_mcast *m = sig_mcast_open();
		struct pollfd fds[8];
		int got = 0, t, nf;

		if (!m)
			return 77;
		/*
		 * A socket opening is not enough: some sandboxed hosts (certain
		 * macOS CI runners) open a multicast socket but deliver nothing.
		 * Send a probe datagram and confirm it loops back before the LAN
		 * e2e tests rely on multicast; SKIP (77) where it does not actually
		 * work, exactly as the DHT tests skip without internet.
		 */
		for (t = 0; t < 20 && !got; t++) {
			sig_mcast_send(m, "P", (const uint8_t *)"PROBE-OK", 8);
			nf = sig_mcast_prepare(m, fds, 8);
			sock_poll(fds, (nfds_t)nf, 100);
			sig_mcast_dispatch(m, fds, nf, mcast_probe_cb, &got);
		}
		sig_mcast_close(m);
		return got ? 0 : 77;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.family = 0;
	cfg.stun_port = 3478;
	cfg.log_level = -1;
	cfg.connect_timeout_s = 120;
	cfg.sig_flags = SIG_DHT;

	if (argc >= 2 && !strcmp(argv[1], "host")) {
		is_host = 1;
		i = 2;
	} else if (argc >= 3 && !strcmp(argv[1], "client") && argv[2][0] != '-') {
		is_host = 0;
		if (token_decode(&cfg.tok, argv[2])) {
			fprintf(stderr, "error: invalid token\n");
			return 2;
		}
		i = 3;
	} else {
		fprintf(stderr,
			"usage: %s host    [--stun host|none] [--family 4|6] [opts]\n"
			"       %s client <TOKEN>          [--stun ...]      [opts]\n"
			"  opts: [--stun-port p] [--timeout s] [--log N]\n"
			"        [--mcast] [--no-dht]\n", argv[0], argv[0]);
		return 2;
	}
	cfg.is_host = is_host;

	for (; i < argc; i++) {
		if (!strcmp(argv[i], "--family") && i + 1 < argc)
			cfg.family = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--stun") && i + 1 < argc)
			stun_arg = argv[++i];
		else if (!strcmp(argv[i], "--stun-port") && i + 1 < argc)
			cfg.stun_port = (uint16_t)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
			cfg.connect_timeout_s = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--serve") && i + 1 < argc)
			cfg.host_serve_max = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--hold-ms") && i + 1 < argc)
			cfg.test_hold_ms = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--single"))
			cfg.test_single_conn = 1;
		else if (!strcmp(argv[i], "--stuck") && i + 1 < argc)
			cfg.test_stuck_punches = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--log") && i + 1 < argc)
			cfg.log_level = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--mcast"))
			cfg.sig_flags |= SIG_MCAST;
		else if (!strcmp(argv[i], "--no-dht"))
			cfg.sig_flags &= ~SIG_DHT;
		else {
			fprintf(stderr, "unknown option: %s\n", argv[i]);
			return 2;
		}
	}
	if (!stun_arg)
		cfg.stun_auto = 1;
	else if (strcmp(stun_arg, "none"))
		cfg.stun_host = stun_arg;

	if (is_host) {
		cfg.tok.version = TOKEN_VERSION;
		cfg.hostkey = sshd_hostkey_new(cfg.tok.hostpub);
		if (!cfg.hostkey) {
			fprintf(stderr, "error: host key generation failed\n");
			return 1;
		}
		random_bytes(cfg.tok.rdv, TOKEN_RDV_LEN);
		random_bytes(cfg.tok.auth, TOKEN_AUTH_LEN);
		host.tok = cfg.tok;
		cfg.ssh_command = "cat";	/* echo oracle, not tmux */
		cfg.use_pty = 0;
		cfg.on_rendezvous = on_rendezvous;
		cfg.on_endpoint = on_endpoint;
	} else {
		/* Honour a NODHT token exactly as the product client does: the host
		 * is not on the DHT, so drop the dead path and find it over mcast. */
		if (cfg.tok.flags & TOKEN_FLAG_NODHT)
			cfg.sig_flags &= ~SIG_DHT;
		for (k = 0; k < SSH_NONCE; k++)
			tx[k] = (uint8_t)(k * 97 + 13);
		cfg.interactive = 0;
		cfg.test_send = tx;
		cfg.test_send_len = SSH_NONCE;
		cfg.test_recv = rx;
		cfg.test_recv_cap = SSH_NONCE;
		cfg.test_recv_len = &rx_got;
	}

	if (is_host && cfg.test_single_conn && cfg.host_serve_max > 0) {
		/* Mirror the product host's run_service: serve one client per
		 * session_run, again after each, so the sequential re-serve
		 * (client roams/vanishes -> reap -> serve the next) is exercised. */
		int n;

		rc = 0;
		for (n = 0; n < cfg.host_serve_max && !rc; n++)
			rc = session_run(&cfg);
	} else {
		rc = session_run(&cfg);
	}
	if (cfg.hostkey)
		sshd_hostkey_free(cfg.hostkey);

	if (rc) {
		printf("E2E FAIL %s\n", is_host ? "host" : "client");
		return 1;
	}
	if (!is_host && (rx_got != SSH_NONCE || memcmp(rx, tx, SSH_NONCE))) {
		printf("E2E FAIL client: echo mismatch got=%zu/%d\n", rx_got,
		       SSH_NONCE);
		return 1;
	}
	printf("E2E PASS %s ssh session\n", is_host ? "host" : "client");
	return 0;
}
