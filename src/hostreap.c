/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "hostreap.h"

int host_reap_due(const struct host_reap *r, uint64_t now)
{
	if (!r->pong_seen) {
		if (now - r->conn_start_ms > HOST_HANDSHAKE_MS)
			return HOST_REAP_NO_HANDSHAKE;
		return HOST_REAP_KEEP;
	}
	if (!r->lost_since_ms)
		return HOST_REAP_KEEP;
	/* A punch in flight, or a claim recent enough, is the client working
	 * its way back: the span runs from the last thing heard of it. */
	if (r->resume_pending)
		return HOST_REAP_KEEP;
	if (now - r->lost_since_ms <= HOST_REAP_MS)
		return HOST_REAP_KEEP;
	if (r->resume_last_ms && now - r->resume_last_ms <= HOST_REAP_MS)
		return HOST_REAP_KEEP;
	return HOST_REAP_SILENT;
}
