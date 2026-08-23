/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * QR cell-art rendering: every rendered pixel is read back out of the
 * UTF-8 art and compared against the encoder's module grid, for both
 * geometries (the reverse-video double-space form through an SGR state
 * machine) -- which proves the sextant mapping across the four code
 * points the U+1FB00 block omits (empty, U+258C, U+2590, U+2588), the
 * exact mistake that broke sextant rendering everywhere else. All 64
 * sextant patterns are checked exhaustively, and the fit chooser must
 * prefer half blocks and fall back to sextants.
 *
 * qr.c is included, not linked, to reach the static sextant_put: its
 * symbols being defined here keeps the archive's own qr.o out of the
 * link, so nothing is duplicated.
 */
#include "../src/qr.c"

#include <assert.h>
#include <stdio.h>

#define TOKEN "comrade:112FXX3fMmPhatk9xzmzCQ53HqnPDoj9e9rjKhTnQDHabEP8z" \
	      "MdWnqrbYyL51c4LJQTezewDkmAv3C4D4Snwt4UmBoiVAnFK372B5kiRJGVpF" \
	      "tst5vmvdbbm17sg26BhdU"

/* Decode one UTF-8 cell of art; returns bytes consumed, bits in *out. */
static size_t cell_bits(const char *p, int mode, unsigned *out)
{
	const unsigned char *b = (const unsigned char *)p;
	unsigned long cp;
	size_t n;

	if (b[0] == ' ') {
		*out = 0;
		return 1;
	}
	if ((b[0] & 0xE0) == 0xC0) {
		cp = ((unsigned long)(b[0] & 0x1F) << 6) | (b[1] & 0x3F);
		n = 2;
	} else if ((b[0] & 0xF0) == 0xE0) {
		cp = ((unsigned long)(b[0] & 0x0F) << 12) |
		     ((unsigned long)(b[1] & 0x3F) << 6) | (b[2] & 0x3F);
		n = 3;
	} else {
		cp = ((unsigned long)(b[0] & 0x07) << 18) |
		     ((unsigned long)(b[1] & 0x3F) << 12) |
		     ((unsigned long)(b[2] & 0x3F) << 6) | (b[3] & 0x3F);
		n = 4;
	}
	if (mode == QR_HALF_BLOCK) {
		assert(cp == 0x2580 || cp == 0x2584 || cp == 0x2588);
		*out = cp == 0x2580 ? 1 : cp == 0x2584 ? 2 : 3;
		return n;
	}
	if (cp == 0x258C)
		*out = 21;
	else if (cp == 0x2590)
		*out = 42;
	else if (cp == 0x2588)
		*out = 63;
	else {
		unsigned long off = cp - 0x1FB00;

		assert(off <= 0x3B);
		if (off <= 19)
			*out = (unsigned)off + 1;
		else if (off <= 39)
			*out = (unsigned)off + 2;
		else
			*out = (unsigned)off + 3;
	}
	return n;
}

/* One reverse-video double-space row back into modules. */
static void double_row(const char *p, int size, unsigned char *out)
{
	int on = 0, x = 0;

	while (*p) {
		if (!strncmp(p, "\033[7m", 4)) {
			on = 1;
			p += 4;
		} else if (!strncmp(p, "\033[27m", 5)) {
			on = 0;
			p += 5;
		} else {
			assert(p[0] == ' ' && p[1] == ' ');
			assert(x < size);
			out[x++] = (unsigned char)on;
			p += 2;
		}
	}
	assert(x == size);
	assert(!on);			/* every lit run is closed */
}

/* Rebuild the pixel grid from the art and diff it against the modules. */
static void roundtrip(const char *text, int mode)
{
	uint8_t ref[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_VMAX)];
	uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_VMAX)];
	static unsigned char got[QR_ART_ROWS * 3][QR_ART_ROWS * 3 * 2];
	struct qr_art art;
	int size, r, x, y;
	int cw = mode == QR_SEXTANT ? 2 : 1;
	int chh = mode == QR_SEXTANT ? 3 : 2;

	assert(qr_render(text, mode, &art) == 0);
	assert(art.mode == mode);
	assert(qrcodegen_encodeText(text, tmp, ref, qrcodegen_Ecc_LOW,
				    qrcodegen_VERSION_MIN, QR_VMAX,
				    qrcodegen_Mask_AUTO, true));
	size = qrcodegen_getSize(ref);
	if (mode == QR_DOUBLE) {
		assert(art.cols == size * 2);
		assert(art.rows == size);
		for (r = 0; r < size; r++) {
			unsigned char bits[QR_ART_ROWS];

			double_row(art.row[r], size, bits);
			for (x = 0; x < size; x++)
				assert(bits[x] ==
				       (qrcodegen_getModule(ref, x, r) ? 1 : 0));
		}
		return;
	}
	assert(art.cols == (size + cw - 1) / cw);
	assert(art.rows == (size + chh - 1) / chh);

	memset(got, 0, sizeof(got));
	for (r = 0; r < art.rows; r++) {
		const char *p = art.row[r];
		int col = 0;

		while (*p) {
			unsigned bits;
			int k;

			p += cell_bits(p, mode, &bits);
			for (k = 0; k < cw * chh; k++)
				got[r * chh + k / cw][col * cw + k % cw] =
					(bits >> k) & 1;
			col++;
		}
		assert(col == art.cols);
	}

	for (y = 0; y < art.rows * chh; y++)
		for (x = 0; x < art.cols * cw; x++) {
			int want = x < size && y < size &&
				   qrcodegen_getModule(ref, x, y);

			assert(got[y][x] == (unsigned char)want);
		}
}

int main(void)
{
	struct qr_art art;
	unsigned bits, back;
	char cell[8];
	size_t n;

	/* Every sextant pattern maps to a glyph and back, the four gaps in
	 * the U+1FB00 block included. */
	for (bits = 0; bits < 64; bits++) {
		n = sextant_put(bits, cell);
		cell[n] = '\0';
		assert(cell_bits(cell, QR_SEXTANT, &back) == n);
		assert(back == bits);
	}

	roundtrip(TOKEN, QR_DOUBLE);
	roundtrip(TOKEN, QR_HALF_BLOCK);
	roundtrip(TOKEN, QR_SEXTANT);

	/* The chooser walks the geometries largest first -- double spaces,
	 * half blocks, sextants -- and reports a terminal none fits. */
	assert(qr_render_fit(TOKEN, 200, 200, &art) == 0);
	assert(art.mode == QR_DOUBLE);
	assert(qr_render_fit(TOKEN, art.rows - 1, 200, &art) == 0);
	assert(art.mode == QR_HALF_BLOCK);
	assert(qr_render_fit(TOKEN, 200, art.cols * 2 - 1, &art) == 0);
	assert(art.mode == QR_HALF_BLOCK);
	assert(qr_render_fit(TOKEN, art.rows - 1, 200, &art) == 0);
	assert(art.mode == QR_SEXTANT);
	assert(qr_render_fit(TOKEN, 4, 200, &art) == -1);
	assert(qr_render_fit(TOKEN, 200, 10, &art) == -1);

	printf("QR PASS: all three geometries round-trip module-exact, "
	       "all 64 sextants map, fit walks largest first\n");
	return 0;
}
