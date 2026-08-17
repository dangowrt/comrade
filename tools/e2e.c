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
#include "sshd.h"
#include "token.h"

#define SSH_NONCE 4096

static struct {
	struct token tok;
	int printed;
} host;

/* Embed a located rendezvous node in the token and print it for the operator to
 * carry to the client; called with NULL when there is no node (multicast). */
static void on_rendezvous(void *arg, const struct sockaddr *sa, socklen_t len)
{
	char tokbuf[TOKEN_STR_LEN + 1];

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
	if (token_encode(&host.tok, tokbuf, sizeof(tokbuf))) {
		fprintf(stderr, "error: token_encode failed\n");
		return;
	}
	printf("COMRADE TOKEN: %s\n", tokbuf);
	fflush(stdout);
	host.printed = 1;
}

int main(int argc, char **argv)
{
	struct session_cfg cfg;
	uint8_t tx[SSH_NONCE], rx[SSH_NONCE];
	size_t rx_got = 0, k;
	const char *stun_arg = NULL;
	int is_host, i, rc;

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
	} else {
		for (k = 0; k < SSH_NONCE; k++)
			tx[k] = (uint8_t)(k * 97 + 13);
		cfg.interactive = 0;
		cfg.test_send = tx;
		cfg.test_send_len = SSH_NONCE;
		cfg.test_recv = rx;
		cfg.test_recv_cap = SSH_NONCE;
		cfg.test_recv_len = &rx_got;
	}

	rc = session_run(&cfg);
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
