/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "fwdspec.h"
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
		"       --no-multicast     skip link-local discovery, DHT/STUN only\n"
		"client: -L [bind:]port:host:hostport  forward a local port via the host\n"
		"        -R [bind:]port:host:hostport  forward a host-side port back here\n"
		"host:  --no-forwarding    decline all client port forwarding\n");
	return ret;
}

#define FWD_SPECS_MAX 8

static int session_connect(const char *arg, int ui_mode, int no_mcast,
			   const struct fwdspec *fwd_l, int nfwd_l,
			   const struct fwdspec *fwd_r, int nfwd_r)
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
	cfg.fwd_l = fwd_l;
	cfg.nfwd_l = nfwd_l;
	cfg.fwd_r = fwd_r;
	cfg.nfwd_r = nfwd_r;
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
	(void)fwd_l;
	(void)nfwd_l;
	(void)fwd_r;
	(void)nfwd_r;
	if (token_decode(&tok, arg))
		fprintf(stderr, "comrade: invalid token\n");
	fprintf(stderr, "comrade: built without the session stack\n");
	return 1;
#endif
}

/* Collect one -L/-R argument: the spec may be glued to the flag (ssh style,
 * "-L8080:host:80") or the next argv entry. Returns 0 on success. */
static int fwd_arg(char **argv, int argc, int *i, struct fwdspec *specs,
		   int *nspecs)
{
	const char *flag = argv[*i];
	const char *arg = flag + 2;

	if (!*arg) {
		if (*i + 1 >= argc)
			return -1;
		arg = argv[++*i];
	}
	if (*nspecs >= FWD_SPECS_MAX) {
		fprintf(stderr, "comrade: too many %.2s options (max %d)\n",
			flag, FWD_SPECS_MAX);
		return -1;
	}
	if (fwdspec_parse(arg, &specs[*nspecs])) {
		fprintf(stderr, "comrade: bad forward specification '%s'\n", arg);
		return -1;
	}
	(*nspecs)++;
	return 0;
}

int main(int argc, char **argv)
{
	static struct fwdspec fwd_l[FWD_SPECS_MAX], fwd_r[FWD_SPECS_MAX];
	int nfwd_l = 0, nfwd_r = 0, no_fwd = 0;
	int ui_mode = UI_AUTO, no_mcast = 0;
	const char *pos = NULL;
	int i;

	/* Writes race teardown all over this program -- the ssh socketpair, the
	 * forwarding bridges, the status pipe -- and a peer closing first must
	 * never kill us outright. The host service already did this for itself;
	 * do it once here so the client and every other path is covered too. */
	signal(SIGPIPE, SIG_IGN);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
			return usage(0);
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
			ui_mode = UI_VERBOSE;
		else if (!strcmp(argv[i], "--no-multicast"))
			no_mcast = 1;
		else if (!strcmp(argv[i], "--no-forwarding"))
			no_fwd = 1;
		else if (!strncmp(argv[i], "-L", 2)) {
			if (fwd_arg(argv, argc, &i, fwd_l, &nfwd_l))
				return usage(1);
		} else if (!strncmp(argv[i], "-R", 2)) {
			if (fwd_arg(argv, argc, &i, fwd_r, &nfwd_r))
				return usage(1);
		} else if (argv[i][0] == '-')
			return usage(1);
		else if (!pos)
			pos = argv[i];
		else
			return usage(1);
	}

	if (!pos) {
		if (nfwd_l || nfwd_r) {
			fprintf(stderr, "comrade: -L/-R need a token "
				"(they are client options)\n");
			return usage(1);
		}
		return host_run(ui_mode, no_mcast, no_fwd);
	}
	if (no_fwd) {
		fprintf(stderr, "comrade: --no-forwarding is a host option\n");
		return usage(1);
	}
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
	return session_connect(pos, ui_mode, no_mcast,
			       fwd_l, nfwd_l, fwd_r, nfwd_r);
}
