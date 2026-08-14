/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>

#include "termfilter.h"

void termfilter_init(struct termfilter *f, int reserve)
{
	f->reserve = reserve;
	f->npend = 0;
}

/* Emit the held bytes unchanged and clear the buffer; returns bytes written. */
static size_t flush_pend(struct termfilter *f, char *out)
{
	int n = f->npend;

	memcpy(out, f->pend, (size_t)n);
	f->npend = 0;
	return (size_t)n;
}

/*
 * The buffer holds one complete control sequence ("\033[" ... final byte). If
 * it is the size answer "CSI 8 ; rows ; cols t", re-emit it with rows reduced by
 * the reserve; otherwise pass it through unchanged.
 */
static size_t emit_seq(struct termfilter *f, char *out)
{
	int rows = 0, cols = 0, n;

	f->pend[f->npend] = '\0';
	if (f->pend[f->npend - 1] == 't' && f->reserve > 0 &&
	    sscanf(f->pend, "\033[8;%d;%dt", &rows, &cols) == 2 &&
	    rows > f->reserve) {
		n = snprintf(out, sizeof(f->pend), "\033[8;%d;%dt",
			     rows - f->reserve, cols);
		f->npend = 0;
		return n > 0 ? (size_t)n : 0;
	}
	return flush_pend(f, out);
}

size_t termfilter_run(struct termfilter *f, const char *in, size_t len,
		      char *out)
{
	size_t oi = 0, i;

	for (i = 0; i < len; i++) {
		char c = in[i];
		unsigned char uc = (unsigned char)c;

		if (f->npend == 0) {			/* outside a sequence */
			if (c == 033)
				f->pend[f->npend++] = c;
			else
				out[oi++] = c;
			continue;
		}
		if (f->npend == 1) {			/* after ESC, expect '[' */
			if (c == '[') {
				f->pend[f->npend++] = c;
			} else {
				oi += flush_pend(f, out + oi);
				if (c == 033)
					f->pend[f->npend++] = c;
				else
					out[oi++] = c;
			}
			continue;
		}
		/* within a CSI: parameter/intermediate bytes until a final byte,
		 * or give up if it runs longer than any sequence we rewrite. */
		if (f->npend >= (int)sizeof(f->pend) - 1) {
			oi += flush_pend(f, out + oi);
			if (c == 033)
				f->pend[f->npend++] = c;
			else
				out[oi++] = c;
			continue;
		}
		f->pend[f->npend++] = c;
		if (uc >= 0x40 && uc <= 0x7e)		/* CSI final byte */
			oi += emit_seq(f, out + oi);
	}
	return oi;
}
