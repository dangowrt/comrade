/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "sandbox.h"

#ifdef _WIN32

/*
 * The Windows self-sandbox. An already-running Windows process cannot have its
 * filesystem access narrowed without a broker or a re-exec under a restricted
 * token, so this side does what a running process can apply to itself: an
 * unnamed job object with a one-process limit (the irrevocable child-process
 * ban, for the client), and the runtime process mitigation policies that block
 * dynamic code, remote and non-Microsoft image loads, extension-point DLL
 * injection and loose handle use. Filled in a later commit; kept a stub so the
 * executable builds and links on Windows from the first commit.
 */

int sandbox_apply(const struct sandbox_cfg *cfg)
{
	(void)cfg;
	return 0;
}

/* Windows cannot deny an already-running process CreateProcess, so its service
 * drives tmux directly and needs no spawner. */
int sandbox_needs_spawner(void)
{
	return 0;
}

#endif /* _WIN32 */
