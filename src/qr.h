/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_QR_H
#define COMRADE_QR_H

/*
 * Token QR codes as terminal cell art, for the dashboard. A pure view
 * helper: it builds UTF-8 rows into a caller's buffer and writes nothing
 * itself. Two pixel geometries: half blocks (two modules per cell --
 * square pixels on the usual 1:2 cell, every font has them) and sextants
 * (2x3 modules per cell, Unicode 13 Symbols for Legacy Computing, a third
 * of the height but inherently stretched ~4:3 tall on a 1:2 cell, so a
 * last resort for terminals nothing else fits). The art is the module
 * grid alone: the caller owes the quiet zone -- a blank line above and
 * below, two blank columns beside -- which the dashboard's margins
 * provide for free. Modules render as filled blocks: on the usual
 * light-on-dark terminal that is a consistently inverted code, which
 * scanners accept, and on a dark-on-light one the normal polarity.
 */

#define QR_HALF_BLOCK 0
#define QR_SEXTANT 1

#define QR_ART_ROWS 34			/* enough for version 10 half blocks */
#define QR_ART_LINE 200

struct qr_art {
	int rows, cols;			/* size in character cells */
	int mode;
	char row[QR_ART_ROWS][QR_ART_LINE];
};

/* Render text in one geometry. 0, or -1 when it cannot be encoded. */
int qr_render(const char *text, int mode, struct qr_art *art);

/*
 * Render into at most rows x cols cells: half blocks where they fit (the
 * more robust pixels), sextants where only they do, -1 where neither.
 */
int qr_render_fit(const char *text, int rows, int cols, struct qr_art *art);

#endif
