/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_MVIEW_H
#define COMRADE_MVIEW_H

#include "session.h"

/*
 * The machine view: the observer a headless host binds instead of the
 * dashboard. It keeps the same model the dashboard would and renders it
 * two ways -- one JSON event line on stdout per change (a supervisor's
 * log), and the whole state as a single JSON document in a file, written
 * to a temporary name and renamed so a reader never sees half of one.
 * INTEGRATION.md carries the schema. Single-threaded by contract: every
 * call arrives on the session thread.
 */

struct mview;

struct mview *mview_create(const char *id, const char *state_path,
			   const char *tmux_sock);
void mview_bind(struct mview *m, struct session_obs *obs);

/* Advertise the configured bounds in the state document (0 = unbounded). */
void mview_limits(struct mview *m, int expire_s, int max_clients);

/*
 * What the self-sandbox engaged (the SANDBOX_L_* mask sandbox_apply returned)
 * and how long the syscall filter it installed is, so a supervisor can see
 * whether the confinement took on this machine without a debug build.
 */
void mview_sandbox(struct mview *m, int layers, int filter_insns);

/* A fatal setup condition (stable enum, e.g. "no_tmux"): state file says
 * state=error so a supervisor's page can name the problem. */
void mview_error(struct mview *m, const char *err);

/* Remove the state file (a stopped session is an absent document). */
void mview_destroy(struct mview *m);

#endif
