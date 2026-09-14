/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SESSION_H
#define COMRADE_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include "wsock.h"

#include "netstate.h"
#include "obs.h"
#include "token.h"

struct fwdspec;
struct spawner;

/*
 * One comrade session: rendezvous over sig (DHT and/or multicast), punch a path
 * (ICE for routable, direct UDP for link-local), bring up KCP, and run SSH on
 * top -- a host serving a command, or a client attaching to it. This is the
 * connect+SSH core the e2e test harness and the product CLI both build on.
 */

struct session_cfg {
	int is_host;
	struct token tok;		/* rdv/auth/hostpub, and (client) the
					 * rendezvous node(s) to seed */

	unsigned sig_flags;		/* SIG_DHT | SIG_MCAST */
	int family;			/* 0 = every family */
	const char *stun_host;		/* NULL with stun_auto=0 => no STUN */
	uint16_t stun_port;
	int stun_auto;			/* rotate community STUN servers */
	int log_level;			/* libjuice log level, <0 = quiet */
	int connect_timeout_s;		/* give up establishing after this;
					 * 0 = keep trying indefinitely */

	/* Host only. */
	void *hostkey;			/* ssh_key (private) */
	int no_fwd;			/* refuse all client port forwarding */
	int forward_only;		/* serve no shell: forwarding + control
					 * only, no tmux (host) */
	int host_serve_max;		/* stop after serving this many clients
					 * (0 = until the deadline / operator) */
	/*
	 * Cap on how many claimants are admitted over the session's lifetime
	 * (0 = no cap). A resumption of an admitted client never counts.
	 * With host_serve_max it gives a bounded grant: --max-clients N
	 * admits N and ends once they are gone.
	 */
	int host_admit_max;
	const char *ssh_command;	/* command to serve; NULL => tmux default */
	const char *ssh_command_ro;	/* command for a read-only client; NULL => none */
	int use_pty;			/* allocate a pty (interactive/tmux) */
	/*
	 * Optional tmux spawner (see spawner.h): when set, the host serves each
	 * client's shell through it instead of execing tmux from this sandboxed
	 * process. NULL keeps the direct path. Set by the host only.
	 */
	struct spawner *spawner;
	/*
	 * Optional end-of-session fd, polled while a client is attached. It
	 * becoming readable (EOF from a liveness monitor that exits with the
	 * shared session) closes the connection to the client at once, rather
	 * than leaving it hanging -- the `tmux attach` command does not reliably
	 * exit on its own when the session dies. 0 disables it.
	 */
	sock_t ssh_end_fd;
	/*
	 * Where to write the one-line connection status (host only): the operator
	 * runs in a separate process from this service, so it reads the line from
	 * this file. Put it on tmpfs (the runtime dir) -- it is rewritten often.
	 * NULL for the client, which reads its status in-process.
	 */
	const char *status_path;
	/*
	 * Called when a family's token state is first determined and whenever
	 * it changes: the host writes `state` (TOKEN_STATE_*) into that
	 * family's slot and re-emits the token. `addr` is the family's address
	 * bytes (4 or 16), read only for RENDEZVOUS and DIRECT; `port` is in
	 * host byte order. Both families report once at session start, so a
	 * host that reaches nothing still has a token to show.
	 */
	void (*on_token_state)(void *arg, int family, int state,
			       const uint8_t *addr, uint16_t port);
	void *arg;

	/* Progress observer (the view); NULL for a headless run. */
	const struct session_obs *obs;

	/* Client only. */
	int interactive;		/* bridge the local terminal */
	/* -L/-R TCP port forwarding specs (OpenSSH semantics), served over
	 * the session by the SSH layer; NULL/0 for none. */
	const struct fwdspec *fwd_l;
	int nfwd_l;
	const struct fwdspec *fwd_r;
	int nfwd_r;
	/* Client non-interactive test mode (e2e): send a buffer, collect echo. */
	const uint8_t *test_send;
	size_t test_send_len;
	uint8_t *test_recv;
	size_t test_recv_cap;
	size_t *test_recv_len;
	int test_hold_ms;		/* keep the session open this long after echo */
	int test_drop_pong;		/* answer only the first pings, then never
					 * again: a link whose pongs starve
					 * mid-session, staged */
	int test_blackhole_lift_ms;	/* restore the blackholed path this long
					 * after the connection starts, so what
					 * follows an outage can be staged too */
	int test_blackhole_all;		/* blackhole every path and mute receive:
					 * a total outage, not a path failure */
	int test_single_conn;		/* host: force the single-connection path even
					 * on DHT (exercise the sequential re-serve
					 * loop that the product host uses) */
	int test_stuck_punches;		/* host: force the first N ICE pickups to
					 * never connect (a wedged punch), so the
					 * release-on-pickup turnstile can be shown
					 * not to head-of-line-block (L1-stuck) */
	int test_roam_ms;		/* report a network change this often, as
					 * if netmon had seen the interfaces move
					 * (0 = never), so the rebuild on a roam
					 * runs without one. A period, not a
					 * one-shot: a rebuild has to leave the
					 * live workers alone every time, not
					 * once */
	int test_roam_max;		/* stop after this many of them (0 = keep
					 * going). A session that has to finish
					 * connecting needs the moves to end, or
					 * the period races its own connect
					 * attempt and nothing ever completes */
	/* Which families a synthetic roam reports as moved (NETMON_CH_*);
	 * 0 means all of them, as a real move between networks usually is. */
	unsigned test_roam_mask;
	int test_roam_hard;		/* a roam also silences every live
					 * worker's transport, as a real move off
					 * the network does; the resume graft
					 * unmutes on adoption */
	int test_blackhole_ms;		/* this long into a live session, stop
					 * sending on the path then carrying it
					 * (0 = never), as if that path had been
					 * taken away. A real one cannot be
					 * without CAP_NET_ADMIN, and dropping
					 * our own sends is enough to make the
					 * path die at both ends: the probes
					 * that keep it warm are ours */
	volatile int *test_stop;	/* wind up now (see sshc_opts.stop):
					 * checked while a session is held and
					 * again between attempts, so a client
					 * that is back to rejoining winds up
					 * with the rest */
	int test_reap_ms;		/* host: end the worker this long into
					 * the session (0 = never), as the reap
					 * does for a client that went quiet.
					 * The turnstile keeps serving, so what
					 * the client is left holding is a path
					 * with no session behind it -- which is
					 * what it must notice */
};

/*
 * How a client's session finished, beyond success and failure. The shared
 * session living on the host is what a token is a way back to, so whether it
 * is still there decides what the caller may offer the operator next.
 */
#define SESSION_ENDED 2			/* we were in it and the host ended it */
#define SESSION_GONE 3			/* the invitation names one already over */

/* Run the session to completion; returns 0 on success, non-zero on failure. */
int session_run(const struct session_cfg *cfg);

#endif
