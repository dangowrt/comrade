/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_CONN_H
#define COMRADE_CONN_H

/*
 * Structured connection status -- plain data the controller (session.c) fills
 * in and the view (statusbar.c) renders. No display text or terminal I/O here;
 * that keeps the model/controller side free of view concerns (see the MVC
 * split). The host's service and its operator run in separate processes, so the
 * struct is also serialised to a small tmpfs file for the operator to read.
 */

enum conn_state {
	CONN_CONNECTING,
	CONN_GATHERING,
	CONN_PUNCHING,
	CONN_LIVE,
	CONN_LOST
};

struct conn_status {
	int state;			/* enum conn_state */
	char peer[80];			/* chosen pair's remote addr, "" if none */
	char rdv[80];			/* mutual rendezvous node, "" if none */
	int rtt_ms;			/* smoothed RTT, 0 if unknown */
};

/* Serialise/parse to a tmpfs file. Return 0 on success, -1 on failure. */
int conn_write(const char *path, const struct conn_status *st);
int conn_read(const char *path, struct conn_status *st);

#endif
