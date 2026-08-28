/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SPAWNER_H
#define COMRADE_SPAWNER_H

#include "wsock.h"

/*
 * The tmux spawner: the one process on the host that keeps the power the
 * connection service gives up.
 *
 * The service faces the network, so it is sandboxed -- and part of that is
 * denying it execve outright (see sandbox.h). But hosting is built on tmux: the
 * service must check the shared session is alive, wait for it to end, and, for
 * every client that joins, run `tmux attach` on a fresh pseudo-terminal. So
 * before it is sandboxed the service forks this spawner, an ordinary child with
 * the caller's full permissions and filesystem, and hands every such spawn to
 * it across a socketpair. The spawner is not privileged; it is simply the one
 * process still allowed to exec, and it can exec nothing but the tmux commands
 * pinned into it at creation -- there is no path for the service to ask it to
 * run something else, because no request carries a command.
 *
 * It is single-threaded and answers requests in the order they arrive, so a
 * caller that holds the control channel across its request and reply always
 * reads its own answer; the service serialises callers with a mutex. It never
 * blocks on a child that will not die: a close hangs up the terminal, escalates
 * to a kill from its own loop, and reaps asynchronously, so one wedged client
 * cannot stall the others. When a spawned child exits, the spawner reports it
 * by closing an exit-notify pipe handed back with the child, so the service
 * learns of it without a round trip.
 *
 * Everything here is POSIX. On Windows the connection service is not sandboxed
 * this way (SetProcessMitigationPolicy cannot deny CreateProcess), so it drives
 * tmux directly and this file is not built.
 */

struct spawner;

/*
 * Fork the spawner, pinning the tmux -S socket path (from which it builds every
 * argv it will ever run: has-session, wait-for, kill-server and the two attach
 * commands). Call it from the service before the service sandboxes itself, so
 * the child inherits none of the confinement. Returns NULL on failure, in which
 * case the caller keeps driving tmux directly and must not deny its own exec.
 */
struct spawner *spawner_create(const char *tmux_sock);

/* spawner_alive's answers. */
#define SPAWNER_NO_SESSION	0	/* tmux says the session is gone */
#define SPAWNER_ALIVE		1	/* the shared session is up */
#define SPAWNER_GONE		(-1)	/* the spawner itself has died */

/* Is the shared tmux session still alive? (`tmux has-session`.) */
int spawner_alive(struct spawner *sp);

/* Run `tmux kill-server`, ending the shared session for everyone. */
void spawner_kill_server(struct spawner *sp);

/*
 * Start the end-of-session monitor (`tmux wait-for`); returns its readable fd,
 * which reaches EOF when the session ends, and stores an opaque handle in
 * *handle to release it later with spawner_close. Returns INVALID_SOCK on
 * failure.
 */
sock_t spawner_endmon(struct spawner *sp, int *handle);

/*
 * Run a `tmux attach` (read-only when ro) on a pseudo-terminal `rows` x `cols`
 * with TERM set to `term`; use_pty == 0 runs it on plain pipes. On success
 * returns 0 and fills *in (the end to write toward the child), *out (the end to
 * read from it; equal to *in for a pty), *exit_fd (readable when the child
 * exits) and *handle. Returns -1 on failure.
 */
int spawner_spawn(struct spawner *sp, int ro, int use_pty, int rows, int cols,
		  const char *term, sock_t *in, sock_t *out, sock_t *exit_fd,
		  int *handle);

/* Stop the child behind `handle` (SIGHUP, then a kill from the spawner's loop
 * if it lingers) and let it be reaped; its exit is delivered on the exit fd. */
void spawner_close(struct spawner *sp, int handle);

/* Shut the spawner down: closing the control channel makes the child exit, and
 * its remaining children go with it. */
void spawner_destroy(struct spawner *sp);

#endif
