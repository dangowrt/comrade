/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SSHFWD_H
#define COMRADE_SSHFWD_H

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "fwdspec.h"

/*
 * TCP port forwarding with OpenSSH semantics, riding the already
 * authenticated comrade SSH session as ordinary SSH channels -- so it
 * inherits the session's pinned host key and token auth, adds nothing to
 * the pre-auth surface, and needs no transport-layer changes.
 *
 * One engine instance serves one ssh_session and its ssh_event, on that
 * session's own thread:
 *
 * - client -L: sshfwd_cli_local() binds the listener; each accepted
 *   connection opens a direct-tcpip channel to the host, which connects
 *   to the target and bridges.
 * - client -R: sshfwd_cli_remote() asks the host to listen (tcpip-forward
 *   global request); the host opens a forwarded-tcpip channel back for
 *   each connection it accepts, and the engine connects to the local
 *   target and bridges.
 * - host: sshfwd_srv_message() consumes direct-tcpip channel opens and
 *   tcpip-forward/cancel global requests. A host declining all forwarding
 *   simply runs no engine, and the caller's default reply refuses each
 *   request -- exactly what an unpatched peer would do.
 *
 * Everything is capped (bridges, listeners, in-flight connects); beyond a
 * cap requests are refused, never queued.
 */

struct sshfwd;

struct sshfwd *sshfwd_create(ssh_session s, ssh_event ev);
void sshfwd_destroy(struct sshfwd *f);

/*
 * Optional transport back-pressure: when set, bridge data is fed toward the
 * peer only while fn(arg) is nonzero, so bulk forwards cannot pool a whole
 * channel window in the transport's send queue ahead of the terminal and the
 * control plane. Unset means always room (a plain TCP-backed session).
 */
void sshfwd_set_tx_room(struct sshfwd *f, int (*fn)(void *arg), void *arg);

/*
 * One housekeeping pass from the session's poll loop: accept on
 * listeners, progress pending connects and channel opens, pick up
 * host-accepted -R connections, reap finished bridges. Non-blocking.
 */
void sshfwd_tick(struct sshfwd *f);

/*
 * Host side: offer a message to the engine. Returns 1 when consumed
 * (the engine then owns the message and replies, now or later), 0 when
 * it is not a forwarding message and the caller should handle it.
 */
int sshfwd_srv_message(struct sshfwd *f, ssh_message m);

/*
 * Client side. Both return 0 on success, -1 on failure (reported on
 * stderr; a failed forward does not fail the session, matching ssh).
 */
int sshfwd_cli_local(struct sshfwd *f, const struct fwdspec *sp);
int sshfwd_cli_remote(struct sshfwd *f, const struct fwdspec *sp);

#endif
