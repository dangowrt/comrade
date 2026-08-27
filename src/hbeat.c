/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "hbeat.h"

unsigned hb_lost_ms(int rtt_ms)
{
	unsigned rtt = 0;

	if (rtt_ms > 0)
		rtt = rtt_ms > HB_RTT_CAP_MS ? HB_RTT_CAP_MS :
					       (unsigned)rtt_ms;
	return HB_SILENT_TRIES * HB_INTERVAL_MS + rtt;
}
