/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SANDBOX_H
#define COMRADE_SANDBOX_H

/*
 * Self-sandboxing: comrade shrinks its own privileges to what the work in
 * front of it needs, using only what the running kernel already offers and
 * never a helper binary. It is best-effort by construction -- every layer is
 * tried and a kernel that lacks one is no error -- so the same call does as
 * much as the platform allows and no less, from a hardened desktop down to a
 * stock OpenWrt router.
 *
 * The shape of the thing being protected decides the profile:
 *
 *   SANDBOX_CLIENT     The joining process. It never spawns anything and holds
 *                      no durable secrets past the token, so it takes the
 *                      tightest profile: execve denied outright, capabilities
 *                      and the ability to gain them gone, and its view of the
 *                      filesystem narrowed to its own data directory plus the
 *                      read-only pieces the C library and TLS stack still read
 *                      (resolver config, shared objects). It keeps the whole
 *                      network stack -- it is a network program.
 *
 *   SANDBOX_SERVICE    The host's connection service: the process that faces
 *                      the network and runs the punched sessions. It must keep
 *                      launching tmux and per-client shells forever, so before
 *                      it is sandboxed it forks a spawner (see spawner.h) that
 *                      keeps exec and the real filesystem; the service then
 *                      denies its own execve just like the client and delegates
 *                      every spawn across a socketpair. Its writable set adds
 *                      the host state directory (status, token, pid files).
 *
 *   SANDBOX_FOREGROUND The operator's dashboard/attach process. The mirror
 *                      image of the service: it drives a local tmux (so it
 *                      keeps exec and a pty) but never opens a network socket,
 *                      so its profile forbids INET/INET6 sockets and leaves
 *                      exec alone.
 *
 * Applied at a single-threaded moment on each path (the client just before it
 * runs a session, the host children right after they fork and before the first
 * socket), so the per-thread Linux primitives -- capset, seccomp, namespace
 * entry -- need no cross-thread synchronisation and every later thread inherits
 * the result.
 *
 * The environment variable COMRADE_SANDBOX=0 turns the whole thing off, for
 * diagnosing a confinement that gets in the way on some unusual system.
 */

/* Which process is being confined; see the block comment above. */
#define SANDBOX_CLIENT		0
#define SANDBOX_SERVICE		1
#define SANDBOX_FOREGROUND	2

/*
 * Layers actually engaged, OR-ed together into sandbox_apply's return value so
 * a caller can log what took and a test can assert it. A return of 0 means
 * nothing was applied (disabled, or a kernel too old for any layer). The set is
 * a superset across platforms; only the bits meaningful on the host can appear.
 */
#define SANDBOX_L_USERNS	0x0001	/* entered a user namespace */
#define SANDBOX_L_MOUNTNS	0x0002	/* confined the mount namespace */
#define SANDBOX_L_LANDLOCK	0x0004	/* access-based filesystem confinement:
					 * Linux Landlock, or a macOS Seatbelt
					 * file ruleset */
#define SANDBOX_L_SECCOMP	0x0008	/* a syscall/operation filter is active:
					 * a Linux seccomp filter, or a macOS
					 * Seatbelt profile */
#define SANDBOX_L_CAPS		0x0010	/* capabilities + bounding set dropped */
#define SANDBOX_L_NONEWPRIVS	0x0020	/* PR_SET_NO_NEW_PRIVS / equivalent */
#define SANDBOX_L_MDWE		0x0040	/* memory write-xor-execute enforced */
#define SANDBOX_L_RLIMIT	0x0080	/* resource limits (fork/core) clamped */
#define SANDBOX_L_NODUMP	0x0100	/* core dumps / ptrace-attach refused */
#define SANDBOX_L_JOB		0x0200	/* Windows job object (child ban) */
#define SANDBOX_L_MITIGATION	0x0400	/* Windows process mitigation policies */

struct sandbox_cfg {
	int role;			/* one of SANDBOX_* above */
	const char *data_dir;		/* appdir_data(), made writable; may be
					 * NULL to grant no data directory */
	const char *state_dir;		/* host state dir, writable; NULL unless
					 * role == SANDBOX_SERVICE */
	/*
	 * SANDBOX_SERVICE only: whether this process will exec nothing itself,
	 * which is what the filesystem confinement and the exec denial actually
	 * depend on. Two different services satisfy it -- one whose spawning is
	 * done by a broker forked beforehand (see spawner.h), and a
	 * forwarding-only host, which runs no tmux at all. A service that still
	 * forks tmux itself satisfies neither, and those two layers would be
	 * wrongly inherited by every shell. The rest apply either way.
	 */
	int no_exec;
};

/*
 * Whether the host should fork a spawner before sandboxing its service: true
 * where the service profile will actually deny exec (Linux with seccomp
 * available; macOS), false where it will not (a seccompless kernel; Windows).
 * Lets the host skip the broker where it would add nothing.
 */
int sandbox_needs_spawner(void);

/*
 * Confine this process according to cfg. Returns the OR of the SANDBOX_L_*
 * layers that engaged (0 if disabled or unsupported). Never fails in a way the
 * caller must handle: a layer the kernel refuses is skipped, not fatal, so the
 * program keeps running with whatever confinement it could get. Not reversible.
 */
int sandbox_apply(const struct sandbox_cfg *cfg);

#endif
