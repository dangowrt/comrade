/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * WHAT A WATCHER IS TOLD.
 *
 * The seam between whatever is establishing a peering and whatever draws it.
 * A controller publishes semantic progress here, knowing nothing about how --
 * or whether -- it is drawn; a view subscribes, and a headless consumer passes
 * none. Every field is optional; a NULL callback is simply skipped.
 */
#ifndef COMRADE_OBS_H
#define COMRADE_OBS_H

#include <stddef.h>
#include <stdint.h>

/* NET_SCOPE_*, NET_VIA_* and NET_CONN_* belong to the reachability model that
 * decides them, and are shared with the view from there. */
enum {					/* peer lifecycle for obs.peer */
	SESSION_PEER_SEEN,		/* mailbox read: peer endpoints known */
	SESSION_PEER_PUNCHING,		/* negotiating a path */
	SESSION_PEER_LIVE,		/* a path carries the session */
	SESSION_PEER_GONE		/* this peer's connection ended (reaped) */
};
enum {					/* what is known about a rendezvous node */
	RDV_ROW_CHECKING = 0,		/* held, and owed a proof from us */
	RDV_ROW_PROVEN,			/* it has answered us */
	RDV_ROW_VOUCHED			/* an end that can reach it proved it */
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
	/*
	 * A per-family rendezvous node: located (host) or seeded (client).
	 *
	 * `ready` is RDV_ROW_*. Three states rather than two, because "not
	 * proven here" and "not proven at all" are different things to be
	 * told: a node another end vouched for is good, and a host with no
	 * route to that family will never confirm it itself. Reporting that
	 * as still being checked leaves it checking for the whole session.
	 */
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
	/* A stable printable identity for peer `id` (the host's truncated claim
	 * ufrag), fired once after its row exists. It labels the peer when the
	 * link is lost and the in-use address is no longer meaningful. */
	void (*peer_ident)(void *arg, int id, const char *ident);
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
	 * (enum conn_state), with its smoothed round trip in ms (0 unknown) and
	 * the number of distinct paths to it a probe has ever qualified. A move
	 * puts every peer back to unknown: what proved a path was traffic
	 * arriving on the network we have left.
	 */
	void (*peer_link)(void *arg, int id, int state, int rtt_ms, int nproven);
	/* Periodic heartbeat, ~10/s: advance spinners, repaint. */
	void (*tick)(void *arg);
};

#endif
