/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fwdspec.h"
#include "host.h"
#include "showfmt.h"
#include "stunlist.h"
#include "token.h"
#include "ui.h"			/* UI_* enums used by main() in every build */
#include "version.h"		/* generated: COMRADE_GIT_HASH/DATE/RELEASE */
#include "wsock.h"		/* WSAStartup before any socket is created */

#include "sig.h"

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
		"       comrade --headless [--id NAME] [--expire SECONDS]\n"
		"                          [--max-clients N]  host as a service:\n"
		"                          no tty, JSON state file + events on stdout\n"
		"       comrade <token>    connect to a shared session\n"
		"       comrade show       print the tokens of the running session\n"
		"         --token | --token-ro   just the one token, for scripts,\n"
		"                                clipboards and screen readers\n"
		"         --json                 machine-readable (INTEGRATION.md)\n"
		"       comrade stop [--id NAME]     end a session (idempotent)\n"
		"       comrade capture [--id NAME] [--ansi]  print the shared\n"
		"                                    terminal's current contents\n"
		"       comrade attach [--id NAME] [-r]  exec tmux attach (for a\n"
		"                                    web front end on a PTY)\n"
		"       comrade stun-update  refresh the STUN server list\n"
		"opts:  -v, --verbose      log lines instead of the dashboard\n"
		"       --plain            log lines, no colour, no animation\n"
		"       -V, --version      print the version and exit\n"
		"       --no-multicast     skip link-local discovery, DHT/STUN only\n"
		"       --no-dht           skip the DHT, link-local discovery only\n"
		"client: -L [bind:]port:host:hostport  forward a local port via the host\n"
		"        -R [bind:]port:host:hostport  forward a host-side port back here\n"
		"        -N, --forward-only  no shell, only the -L/-R forwards\n"
		"host:  --no-forwarding    decline all client port forwarding\n"
		"       -N, --forward-only  with --headless: serve no shell,\n"
		"                          only forwarding (no tmux)\n");
	return ret;
}

static int print_version(void)
{
	if (COMRADE_RELEASE[0])
		printf("comrade %s (%s, %s)\n", COMRADE_RELEASE,
		       COMRADE_GIT_HASH, COMRADE_GIT_DATE);
	else
		printf("comrade %s (%s)\n", COMRADE_GIT_HASH,
		       COMRADE_GIT_DATE);
	return 0;
}

#define FWD_SPECS_MAX 8

static int session_connect(const char *arg, int ui_mode, int no_mcast,
			   int no_dht, const struct fwdspec *fwd_l, int nfwd_l,
			   const struct fwdspec *fwd_r, int nfwd_r,
			   int forward_only)
{
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
	 * forced onto the DHT/STUN path for testing, and --no-dht drops the DHT.
	 * Only the operator drops a transport: a token saying the host was not on
	 * the DHT when it was minted is no reason to stop running the one
	 * rendezvous that survives either end moving off the LAN. */
	cfg.sig_flags = (no_dht ? 0 : SIG_DHT) | (no_mcast ? 0 : SIG_MCAST);
	cfg.stun_port = 3478;
	cfg.stun_auto = 1;
	cfg.log_level = -1;
	cfg.connect_timeout_s = 0;	/* keep trying; the operator ends it */
	cfg.interactive = 1;
	cfg.forward_only = forward_only;	/* -N: no shell, forwarding only */
	if (forward_only && !nfwd_l && !nfwd_r)
		fprintf(stderr, "comrade: -N/--forward-only with no -L/-R "
			"forwards nothing\n");
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
	/*
	 * Detaching is meant to feel like detaching from a local tmux: the
	 * terminal comes back and the session carries on without us. Say so and
	 * name the way in again, because unlike a local tmux there is no
	 * `tmux ls` to find it with -- the token is the only handle, and it has
	 * just scrolled away with the session.
	 */
	fprintf(stderr, "comrade: left the shared session "
		"(comrade %s   to rejoin)\n", arg);
	return 0;
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
	static char stdout_buf[65536];
	int nfwd_l = 0, nfwd_r = 0, no_fwd = 0;
	int ui_mode = UI_AUTO, no_mcast = 0, no_dht = 0;
	int headless = 0, expire_s = 0, max_clients = 0;
	int no_shell = 0;
	const char *host_id = NULL;
	const char *pos = NULL;
	int i;

	/*
	 * Before any other stdout operation (setvbuf's own requirement): a full
	 * frame of the dashboard's animation is many short writes otherwise, and
	 * a console handle's default buffering is not guaranteed to coalesce
	 * them into one -- costly on some Windows consoles.
	 */
	setvbuf(stdout, stdout_buf, _IOFBF, sizeof(stdout_buf));

	/* Writes race teardown all over this program -- the ssh socketpair, the
	 * forwarding bridges, the status pipe -- and a peer closing first must
	 * never kill us outright. The host service already did this for itself;
	 * do it once here so the client and every other path is covered too.
	 * Windows has no SIGPIPE at all: a write to a dead peer just returns
	 * WSAECONNRESET, which every caller here already handles. */
#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif
	/* Winsock needs starting before the first socket() anywhere, including
	 * inside libjuice and libssh; ref-counted, so the modules may repeat it. */
	if (wsock_init()) {
		fprintf(stderr, "comrade: could not initialise networking\n");
		return 1;
	}

#ifdef _WIN32
	/*
	 * The host's connection service, re-entered detached. Windows has no
	 * fork, so the process that outlives the operator's terminal has to be
	 * a fresh comrade.exe rather than a copy of this one; it is handed the
	 * session down the inherited socket named here. Deliberately absent
	 * from usage(): nobody types this. Checked before the option loop so
	 * it can never be confused with a token.
	 */
	if (argc == 3 && !strcmp(argv[1], "--win-service"))
		return host_win_service(argv[2]);
#endif

	/* The machine verbs before the option loop: their flags are not
	 * session options. */
	if (argc >= 2 && !strcmp(argv[1], "show")) {
		int what = SHOWFMT_HUMAN;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--token"))
				what = SHOWFMT_TOKEN;
			else if (!strcmp(argv[i], "--token-ro"))
				what = SHOWFMT_TOKEN_RO;
			else if (!strcmp(argv[i], "--json"))
				what = SHOWFMT_JSON;
			else
				return usage(1);
		}
		return host_show(what);
	}
	if (argc >= 2 && !strcmp(argv[1], "stop")) {
		const char *sid = NULL;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--id") && i + 1 < argc)
				sid = argv[++i];
			else
				return usage(1);
		}
		return host_stop(sid);
	}
	if (argc >= 2 && !strcmp(argv[1], "capture")) {
		const char *sid = NULL;
		int ansi = 0;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--id") && i + 1 < argc)
				sid = argv[++i];
			else if (!strcmp(argv[i], "--ansi"))
				ansi = 1;
			else
				return usage(1);
		}
		return host_capture(sid, ansi);
	}
	if (argc >= 2 && !strcmp(argv[1], "attach")) {
		const char *sid = NULL;
		int ro = 0;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--id") && i + 1 < argc)
				sid = argv[++i];
			else if (!strcmp(argv[i], "--read-only") ||
				 !strcmp(argv[i], "-r"))
				ro = 1;
			else
				return usage(1);
		}
		return host_attach(sid, ro);
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
			return usage(0);
		if (!strcmp(argv[i], "-V") || !strcmp(argv[i], "--version"))
			return print_version();
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
			ui_mode = UI_VERBOSE;
		else if (!strcmp(argv[i], "--plain"))
			ui_mode = UI_PLAIN;
		else if (!strcmp(argv[i], "--no-multicast"))
			no_mcast = 1;
		else if (!strcmp(argv[i], "--no-dht"))
			no_dht = 1;
		else if (!strcmp(argv[i], "--no-forwarding"))
			no_fwd = 1;
		/* One thing under two names: serve no shell. What that means
		 * differs by side -- a host offers only forwarding, a client
		 * asks for none -- but it is the same request either way, and
		 * having to remember which spelling this side wanted was a
		 * needless way to be told to go and try the other one. */
		else if (!strcmp(argv[i], "-N") ||
			 !strcmp(argv[i], "--forward-only"))
			no_shell = 1;
		else if (!strcmp(argv[i], "--headless"))
			headless = 1;
		else if (!strcmp(argv[i], "--id") && i + 1 < argc)
			host_id = argv[++i];
		else if (!strcmp(argv[i], "--expire") && i + 1 < argc)
			expire_s = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--max-clients") && i + 1 < argc)
			max_clients = atoi(argv[++i]);
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

	if (no_mcast && no_dht) {
		fprintf(stderr, "comrade: --no-multicast with --no-dht leaves no "
			"way to reach a peer\n");
		return usage(1);
	}
	if (!pos) {
		if (nfwd_l || nfwd_r) {
			fprintf(stderr, "comrade: -L/-R need a token "
				"(they are client options)\n");
			return usage(1);
		}
		if (no_shell && !headless) {
			fprintf(stderr, "comrade: -N/--forward-only needs "
				"--headless on a host (there is no terminal "
				"to enter)\n");
			return usage(1);
		}
		if (headless)
			return host_headless(host_id, no_mcast, no_dht, no_fwd,
					     no_shell, expire_s, max_clients);
		if (host_id || expire_s || max_clients) {
			fprintf(stderr, "comrade: --id/--expire/--max-clients "
				"need --headless\n");
			return usage(1);
		}
		return host_run(ui_mode, no_mcast, no_dht, no_fwd);
	}
	if (headless || host_id || expire_s || max_clients) {
		fprintf(stderr, "comrade: --headless/--id/--expire/"
			"--max-clients are host options\n");
		return usage(1);
	}
	if (no_fwd) {
		fprintf(stderr, "comrade: --no-forwarding is a host option\n");
		return usage(1);
	}
	if (!strcmp(pos, "show"))
		return host_show(SHOWFMT_HUMAN);
	if (!strcmp(pos, "stun-update")) {
		int count = 0;

		if (stunlist_update(&count))
			return 1;
		fprintf(stderr, "comrade: saved %d STUN servers to\n  %s\n",
			count, stunlist_path());
		return 0;
	}
	return session_connect(pos, ui_mode, no_mcast, no_dht,
			       fwd_l, nfwd_l, fwd_r, nfwd_r, no_shell);
}
