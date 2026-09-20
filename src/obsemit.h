/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * WHAT A PLAYBOOK TELLS ITS WATCHER ABOUT THE NETWORK IT IS ON.
 *
 * The model decides these things and the view draws them; between the two
 * there is only this, and there is one of it because every playbook has the
 * same things to say. Nothing here reads a playbook's own state: an observer
 * and a reachability model are the whole of it, and what comes off a
 * signaller is handed in, so a playbook with no terminal to draw in can say
 * exactly what a terminal session says.
 */
#ifndef COMRADE_OBSEMIT_H
#define COMRADE_OBSEMIT_H

#include <stdint.h>

#include "netstate.h"
#include "obs.h"
#include "sig.h"

struct obsemit {
	const struct session_obs *o;	/* may be NULL: then nothing is said */
	struct netstate *ns;
	/* The last mailbox reported, so an unchanged one is not repeated. */
	struct session_mailbox told;
	int told_any;
};

void obsemit_init(struct obsemit *e, const struct session_obs *o,
		  struct netstate *ns);

/*
 * The model's rows for one family, rebuilt rather than added to: an address
 * the kernel no longer reports has to be able to go away again.
 */
void obsemit_rows(struct obsemit *e, int family);

/* A family's connectivity verdict. */
void obsemit_conn(struct obsemit *e, int family, int conn);

/*
 * The multicast interfaces being serviced, re-sent whole, because a cable
 * going in or out changes which exist and what is listed has to be the
 * machine as it is now.
 */
void obsemit_links(struct obsemit *e, const struct sig_mcast_if *ifs, int n);

/* The mailbox, if anything about it has changed since it was last said. */
void obsemit_mailbox(struct obsemit *e, const struct sig_mailbox *sm,
		     uint64_t now);

/*
 * Each family's rendezvous node and what is known about it (RDV_ROW_*). A
 * family holding none is told it is still being checked when `expect` says one
 * is looked for, and nothing otherwise.
 */
void obsemit_rendezvous(struct obsemit *e, int expect4, int expect6);

#endif
