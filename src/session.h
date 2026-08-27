/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SESSION_H
#define COMRADE_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include "wsock.h"

#include "netstate.h"
#include "token.h"

struct fwdspec;

/*
 * One comrade session: rendezvous over sig (DHT and/or multicast), punch a path
 * (ICE for routable, direct UDP for link-local), bring up KCP, and run SSH on
 * top -- a host serving a command, or a client attaching to it. This is the
 * connect+SSH core the e2e test harness and the product CLI both build on.
 */

/*
 * MVC seam. session_run is the controller: it drives the model (sig/nat/...)
 * and publishes semantic progress here, knowing nothing about how -- or
 * whether -- it is drawn. A view (src/ui.c) subscribes; the e2e harness passes
 * none. Every field is optional; a NULL callback is simply skipped.
 */
/* NET_SCOPE_*, NET_VIA_* and NET_CONN_* belong to the reachability model that
 * decides them, and are shared with the view from there. */
enum {					/* peer lifecycle for obs.peer */
	SESSION_PEER_SEEN,		/* mailbox read: peer endpoints known */
	SESSION_PEER_PUNCHING,		/* negotiating a path */
	SESSION_PEER_LIVE,		/* a path carries the session */
	SESSION_PEER_GONE		/* this peer's connection ended (reaped) */
};
enum {					/* per-family rendezvous progress (spinner) */
	RDV_COLD,			/* the DHT is not warm yet */
	RDV_WARMUP,			/* finding nodes close to the key */
	RDV_STORE,			/* placing the mailbox on them */
	RDV_GET,			/* reading it back */
	RDV_READY			/* the rendezvous node is captured */
};

/*
 * The shared BEP44 mailbox, as the controller sees it. Mirrors sig's own view
 * so the display never reaches into sig.
 */
struct session_mailbox {
	int engaged;			/* the DHT is up and being asked */
	int stage;			/* RDV_* */
	int have_mine;			/* we have something to publish */
	int mine_stored;		/* the last read showed it stored */
	int peer_seen;			/* the peer's slot was in that read */
	int64_t seq;			/* container sequence, -1 unread */
	int gets;			/* validated reads */
	int puts;			/* stores that found a home */
	int claim;			/* SESSION_CLAIM_* */
	/*
	 * The item being stored and a node being worth naming are two claims
	 * about two things, and they are minutes apart in the worst case. A
	 * store is proven the moment a read hands it back; a node has to keep
	 * answering for a while before a token points anyone at it, and until
	 * it does the invite cannot name it.
	 */
	int rdv_holding;		/* a node answered, still being proven */
	int rdv_proven;			/* one has, and the token can name it */
	int age_get_s;			/* since the last read, -1 = never */
	int age_put_s;
};

enum {					/* the answer slot, from where we sit */
	SESSION_CLAIM_UNKNOWN,		/* nothing read yet */
	SESSION_CLAIM_FREE,		/* empty: a client may take it */
	SESSION_CLAIM_HELD,		/* ours is in it */
	SESSION_CLAIM_BUSY		/* somebody else's is */
};

struct session_obs {
	void *arg;
	/* A local path (family 4/6), classified by scope and how it was learnt;
	 * the pair fixes the label, e.g. GLOBAL+STUN is "global, behind NAT". */
	void (*net)(void *arg, int family, int scope, int via, const char *addr);
	/* This network's NAT maps our probe socket differently per destination
	 * server (1) or the same way to all of them (0) -- known only once the
	 * STUN pool probe has heard back from at least two servers. */
	void (*mapping4)(void *arg, int dependent);
	/* A family's connectivity verdict changed (NET_CONN_* or 0). */
	void (*net_conn)(void *arg, int family, int status);
	/* An up multicast interface being serviced, and the families it has.
	 * The set is re-sent whenever it changes, preceded by link_reset. */
	void (*link)(void *arg, const char *ifname, int have4, int have6);
	/* Forget the interfaces: a cable going in or out changes which exist,
	 * and what is listed has to be the machine as it is now. */
	void (*link_reset)(void *arg);
	/* A per-family rendezvous node: located (host) or seeded (client). */
	void (*rendezvous)(void *arg, int family, const char *addr, int ready);
	/* A family's rendezvous progress advanced (RDV_*); drives the spinner. */
	void (*rdv_stage)(void *arg, int family, int stage);
	/* The invite token is minted and ready to share (host). */
	void (*token)(void *arg, const char *token_str);
	/* The read-only twin of the invite token (host); grants view-only. */
	void (*token_ro)(void *arg, const char *token_str);
	/* A peer identified by `id` advanced to `state` (SESSION_PEER_*); addr may
	 * be "". `id` is stable for one connection's lifetime, so a multi-user
	 * host addresses each attached client's row independently (and can update
	 * its address as ICE re-nominates); the single-connection client uses 0. */
	void (*peer)(void *arg, int id, int state, const char *addr);
	/* The peer identified by `id` authenticated read-only (view-only guest);
	 * fired once, after its row exists, so the dashboard can mark it. */
	void (*peer_ro)(void *arg, int id);
	/* A forwarding request from peer `id` was refused (the host declines
	 * forwarding, or the guest is read-only). Fired once, so an operator
	 * sees an attempted tunnel rather than the guest failing silently. */
	void (*peer_fwd_refused)(void *arg, int id);
	/* The connection context was torn down and is being rebuilt (a roam or
	 * reconnect): drop stale local candidates, the peer, and the "link up"
	 * state, so the dashboard reflects the fresh attempt rather than the
	 * addresses of the network that just went away. */
	void (*reset)(void *arg);
	/* The local network changed (a roam while still waiting, not an
	 * established-link drop): drop the stale local-candidate rows so the
	 * dashboard shows only the current interfaces, while leaving any peer
	 * rows in place (a multi-user host keeps its live clients listed). */
	void (*net_reset)(void *arg, int family);
	/* The client had to fall back from a seeded node to a full DHT warm. */
	void (*escalate)(void *arg, const char *why);
	/* The condition the last escalation warned about has resolved. */
	void (*escalate_clear)(void *arg);
	/* A path is up and the session is about to seize the terminal. */
	void (*established)(void *arg);
	/*
	 * The mailbox moved. Everything before a punch goes through it, so
	 * this is what turns "waiting" into a place to look when a join is
	 * not happening.
	 */
	void (*mailbox)(void *arg, const struct session_mailbox *m);
	/*
	 * One candidate from the description peer `id` sent us, and a signal
	 * to forget that peer's set because a fresh description replaced it.
	 * Both ends' candidates have to be visible to tell a punch that never
	 * had a usable pair from one that had pairs and still failed.
	 *
	 * `id` is the peer row it belongs to: a host serves several clients at
	 * once and each has its own set.
	 */
	void (*peer_cand)(void *arg, int id, int family, int scope, int via,
			  const char *addr);
	void (*peer_cand_reset)(void *arg, int id);
	/*
	 * One transport path under peer `id`: where it goes, whether it is
	 * carrying the session now, and its smoothed round trip in ms (-1 if
	 * not yet known). A client that roamed and came back is served over a
	 * second path while the first is still listed, which is exactly what
	 * makes a resumption legible.
	 */
	void (*peer_path)(void *arg, int id, const char *addr, int carrying,
			  int rtt_ms);
	void (*peer_path_reset)(void *arg, int id);
	/*
	 * Peer `id`'s link, on the same scale the local status bar uses
	 * (enum conn_state), with its smoothed round trip in ms (0 unknown).
	 * A move puts every peer back to unknown: what proved a path was
	 * traffic arriving on the network we have left.
	 */
	void (*peer_link)(void *arg, int id, int state, int rtt_ms);
	/* Periodic heartbeat, ~10/s: advance spinners, repaint. */
	void (*tick)(void *arg);
};

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
	volatile int *test_stop;	/* wind up a held session now (see
					 * sshc_opts.stop) */
	int test_reap_ms;		/* host: end the worker this long into
					 * the session (0 = never), as the reap
					 * does for a client that went quiet.
					 * The turnstile keeps serving, so what
					 * the client is left holding is a path
					 * with no session behind it -- which is
					 * what it must notice */
};

/* Run the session to completion; returns 0 on success, non-zero on failure. */
int session_run(const struct session_cfg *cfg);

#endif
