/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>

#include "host.h"
#include "token.h"

#ifdef COMRADE_HAVE_SESSION
#include "session.h"
#include "sig.h"
#endif

/* CLI splash wordmark, ready for the interactive UX work. 7-bit ASCII. */
static const char comrade_splash[] =
" ______ _______ _______ ______ _______ _____  _______\n"
"|      |       |   |   |   __ \\   _   |     \\|    ___|\n"
"|   ---|   -   |       |      <       |  --  |    ___|\n"
"|______|_______|__|_|__|___|__|___|___|_____/|_______|\n"
"-=[ no server ]=--=[ no relay ]=--=[ just a punched p2p link ]=-\n";

static int usage(int ret)
{
	(void)comrade_splash;
	fprintf(stderr,
		"usage: comrade            start a shared session\n"
		"       comrade <token>    connect to a shared session\n"
		"       comrade show       print the tokens of the running session\n");
	return ret;
}

static int session_connect(const char *arg)
{
#ifdef COMRADE_HAVE_SESSION
	struct session_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	if (token_decode(&cfg.tok, arg)) {
		fprintf(stderr, "comrade: invalid token\n");
		return 1;
	}
	/* Race the LAN (multicast) and the DHT: whichever reaches the host wins. */
	cfg.sig_flags = SIG_DHT | SIG_MCAST;
	cfg.stun_port = 3478;
	cfg.stun_auto = 1;
	cfg.log_level = -1;
	cfg.connect_timeout_s = 120;
	cfg.interactive = 1;
	if (session_run(&cfg)) {
		fprintf(stderr, "comrade: could not connect to the session\n");
		return 1;
	}
	return 0;
#else
	struct token tok;

	if (token_decode(&tok, arg))
		fprintf(stderr, "comrade: invalid token\n");
	fprintf(stderr, "comrade: built without the session stack\n");
	return 1;
#endif
}

int main(int argc, char **argv)
{
	if (argc == 1)
		return host_run();
	if (argc != 2)
		return usage(1);
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
		return usage(0);
	if (!strcmp(argv[1], "show"))
		return host_show();

	return session_connect(argv[1]);
}
