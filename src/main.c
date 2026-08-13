/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>

#include "host.h"
#include "stunlist.h"
#include "token.h"
#include "ui.h"			/* UI_* enums used by main() in every build */

#ifdef COMRADE_HAVE_SESSION
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
		"       comrade show       print the tokens of the running session\n"
		"       comrade stun-update  refresh the STUN server list\n"
		"opts:  -v, --verbose      log lines instead of the dashboard\n"
		"       --no-multicast     skip link-local discovery, DHT/STUN only\n");
	return ret;
}

static int session_connect(const char *arg, int ui_mode, int no_mcast)
{
#ifdef COMRADE_HAVE_SESSION
	struct session_cfg cfg;
	struct session_obs obs;
	struct ui *u;
	int rc;

	memset(&cfg, 0, sizeof(cfg));
	if (token_decode(&cfg.tok, arg)) {
		fprintf(stderr, "comrade: invalid token\n");
		return 1;
	}
	/* Race the LAN (multicast) and the DHT: whichever reaches the host wins.
	 * --no-multicast drops the LAN path, so two hosts on one segment can be
	 * forced onto the DHT/STUN path for testing. */
	cfg.sig_flags = SIG_DHT | (no_mcast ? 0 : SIG_MCAST);
	cfg.stun_port = 3478;
	cfg.stun_auto = 1;
	cfg.log_level = -1;
	cfg.connect_timeout_s = 120;
	cfg.interactive = 1;
	u = ui_create(UI_ROLE_CLIENT, ui_mode);	/* the view drives the dashboard */
	if (u) {
		ui_bind(u, &obs);
		cfg.obs = &obs;
	}
	rc = session_run(&cfg);
	ui_destroy(u);
	if (rc) {
		fprintf(stderr, "comrade: could not connect to the session\n");
		return 1;
	}
	return 0;
#else
	struct token tok;

	(void)ui_mode;
	(void)no_mcast;
	if (token_decode(&tok, arg))
		fprintf(stderr, "comrade: invalid token\n");
	fprintf(stderr, "comrade: built without the session stack\n");
	return 1;
#endif
}

int main(int argc, char **argv)
{
	int ui_mode = UI_AUTO, no_mcast = 0;
	const char *pos = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
			return usage(0);
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
			ui_mode = UI_VERBOSE;
		else if (!strcmp(argv[i], "--no-multicast"))
			no_mcast = 1;
		else if (argv[i][0] == '-')
			return usage(1);
		else if (!pos)
			pos = argv[i];
		else
			return usage(1);
	}

	if (!pos)
		return host_run(ui_mode, no_mcast);
	if (!strcmp(pos, "show"))
		return host_show();
	if (!strcmp(pos, "stun-update")) {
		int count = 0;

		if (stunlist_update(&count))
			return 1;
		fprintf(stderr, "comrade: saved %d STUN servers to\n  %s\n",
			count, stunlist_path());
		return 0;
	}
	return session_connect(pos, ui_mode, no_mcast);
}
