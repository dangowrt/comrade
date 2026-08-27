/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>

#include "hbeat.h"

/* With nothing measured yet, the count is the whole of it. */
static void an_unmeasured_link_waits_for_the_pings(void)
{
	assert(hb_lost_ms(0) == HB_SILENT_TRIES * HB_INTERVAL_MS);
	assert(hb_lost_ms(-1) == HB_SILENT_TRIES * HB_INTERVAL_MS);
}

/* A slow peer is given its own round-trip on top: the pong it sends inside
 * the last interval has to have time to arrive. */
static void a_slow_peer_is_given_its_round_trip(void)
{
	assert(hb_lost_ms(40) == HB_SILENT_TRIES * HB_INTERVAL_MS + 40);
	assert(hb_lost_ms(400) == HB_SILENT_TRIES * HB_INTERVAL_MS + 400);
	assert(hb_lost_ms(400) > hb_lost_ms(40));
}

/* But not without end: a round-trip past the cap says the path is unusable,
 * and waiting longer on it only delays the resume. */
static void patience_stops_where_the_path_is_useless(void)
{
	assert(hb_lost_ms(HB_RTT_CAP_MS) == hb_lost_ms(HB_RTT_CAP_MS + 1));
	assert(hb_lost_ms(60000) ==
	       HB_SILENT_TRIES * HB_INTERVAL_MS + HB_RTT_CAP_MS);
}

/* However the figure moves, the span never shrinks below the pings. */
static void it_never_dips_under_the_count(void)
{
	int rtt;

	for (rtt = -100; rtt < 3000; rtt += 37)
		assert(hb_lost_ms(rtt) >= HB_SILENT_TRIES * HB_INTERVAL_MS);
}

int main(void)
{
	an_unmeasured_link_waits_for_the_pings();
	a_slow_peer_is_given_its_round_trip();
	patience_stops_where_the_path_is_useless();
	it_never_dips_under_the_count();
	printf("hbeat_test: ok\n");
	return 0;
}
