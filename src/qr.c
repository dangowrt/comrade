/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "qr.h"
#include "qrcodegen.h"

#define QR_VMAX 10			/* 57x57 modules: room for any token */

static size_t utf8_put(unsigned long cp, char *out)
{
	if (cp < 0x80) {
		out[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800) {
		out[0] = (char)(0xC0 | (cp >> 6));
		out[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	}
	if (cp < 0x10000) {
		out[0] = (char)(0xE0 | (cp >> 12));
		out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[2] = (char)(0x80 | (cp & 0x3F));
		return 3;
	}
	out[0] = (char)(0xF0 | (cp >> 18));
	out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
	out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
	out[3] = (char)(0x80 | (cp & 0x3F));
	return 4;
}

/*
 * One sextant cell from its six pixels, bit i = cell i+1 of the character
 * name (1 top-left, 2 top-right, 3 mid-left, 4 mid-right, 5 bottom-left,
 * 6 bottom-right). U+1FB00..U+1FB3B run in that binary order but OMIT the
 * four combinations older Unicode already had -- empty, the left column
 * (U+258C), the right column (U+2590) and full (U+2588) -- so those are
 * emitted from their own code points and the rest shift down past them.
 */
static size_t sextant_put(unsigned bits, char *out)
{
	unsigned long cp;

	if (bits == 0) {
		out[0] = ' ';
		return 1;
	}
	if (bits == 21)
		cp = 0x258C;
	else if (bits == 42)
		cp = 0x2590;
	else if (bits == 63)
		cp = 0x2588;
	else
		cp = 0x1FB00 + bits - 1 - (bits > 21) - (bits > 42);
	return utf8_put(cp, out);
}

/* A pixel of the art; the ragged last cell row/column reads as blank. */
static unsigned px(const uint8_t *qr, int size, int x, int y)
{
	if (x >= size || y >= size)
		return 0;
	return qrcodegen_getModule(qr, x, y) ? 1 : 0;
}

int qr_render(const char *text, int mode, struct qr_art *art)
{
	uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_VMAX)];
	uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_VMAX)];
	char enc[QR_ART_LINE];
	int size, x, y, r;

	if (!text || strlen(text) >= sizeof(enc))
		return -1;
	snprintf(enc, sizeof(enc), "%s", text);
	if (!qrcodegen_encodeText(enc, tmp, qr, qrcodegen_Ecc_LOW,
				  qrcodegen_VERSION_MIN, QR_VMAX,
				  qrcodegen_Mask_AUTO, true))
		return -1;
	size = qrcodegen_getSize(qr);

	art->mode = mode;
	if (mode == QR_SEXTANT) {
		art->cols = (size + 1) / 2;
		art->rows = (size + 2) / 3;
		x = art->cols * 4;
	} else if (mode == QR_HALF_BLOCK) {
		art->cols = size;
		art->rows = (size + 1) / 2;
		x = art->cols * 3;
	} else {
		art->cols = size * 2;
		art->rows = size;
		/* two spaces per module, reverse video toggled per run */
		x = size * 2 + (size / 2 + 2) * 9;
	}
	if (art->rows > QR_ART_ROWS || x + 1 > QR_ART_LINE)
		return -1;

	for (r = 0; r < art->rows; r++) {
		char *o = art->row[r];

		if (mode == QR_DOUBLE) {
			int on = 0;

			for (x = 0; x < size; x++) {
				unsigned m = px(qr, size, x, r);

				if (m && !on) {
					memcpy(o, "\033[7m", 4);
					o += 4;
					on = 1;
				} else if (!m && on) {
					memcpy(o, "\033[27m", 5);
					o += 5;
					on = 0;
				}
				*o++ = ' ';
				*o++ = ' ';
			}
			if (on) {
				memcpy(o, "\033[27m", 5);
				o += 5;
			}
			*o = '\0';
			continue;
		}
		for (x = 0; x < art->cols; x++) {
			if (mode == QR_SEXTANT) {
				unsigned bits = 0;

				y = r * 3;
				bits |= px(qr, size, x * 2, y) << 0;
				bits |= px(qr, size, x * 2 + 1, y) << 1;
				bits |= px(qr, size, x * 2, y + 1) << 2;
				bits |= px(qr, size, x * 2 + 1, y + 1) << 3;
				bits |= px(qr, size, x * 2, y + 2) << 4;
				bits |= px(qr, size, x * 2 + 1, y + 2) << 5;
				o += sextant_put(bits, o);
			} else {
				unsigned top, bot;

				y = r * 2;
				top = px(qr, size, x, y);
				bot = px(qr, size, x, y + 1);
				if (top && bot)
					o += utf8_put(0x2588, o);
				else if (top)
					o += utf8_put(0x2580, o);
				else if (bot)
					o += utf8_put(0x2584, o);
				else
					*o++ = ' ';
			}
		}
		*o = '\0';
	}
	return 0;
}

int qr_render_fit(const char *text, int rows, int cols, struct qr_art *art)
{
	if (!qr_render(text, QR_DOUBLE, art) &&
	    art->rows <= rows && art->cols <= cols)
		return 0;
	if (!qr_render(text, QR_HALF_BLOCK, art) &&
	    art->rows <= rows && art->cols <= cols)
		return 0;
	if (!qr_render(text, QR_SEXTANT, art) &&
	    art->rows <= rows && art->cols <= cols)
		return 0;
	return -1;
}
