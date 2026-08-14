/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "termfilter.h"

/* Run one buffer through a fresh filter and NUL-terminate the result. */
static size_t one(int reserve, const char *in, size_t len, char *out)
{
	struct termfilter f;
	size_t n;

	termfilter_init(&f, reserve);
	n = termfilter_run(&f, in, len, out);
	out[n] = '\0';
	return n;
}

int main(void)
{
	char out[256];
	struct termfilter f;
	size_t n;

	/* The size answer is rewritten one row shorter. */
	one(1, "\033[8;45;181t", 11, out);
	assert(strcmp(out, "\033[8;44;181t") == 0);

	/* A different reserve subtracts that many rows. */
	one(2, "\033[8;45;181t", 11, out);
	assert(strcmp(out, "\033[8;43;181t") == 0);

	/* reserve 0 leaves it untouched. */
	one(0, "\033[8;45;181t", 11, out);
	assert(strcmp(out, "\033[8;45;181t") == 0);

	/* Row shrinks across a digit boundary (100 -> 99). */
	one(1, "\033[8;100;181t", 12, out);
	assert(strcmp(out, "\033[8;99;181t") == 0);

	/* Surrounding bytes are preserved and only the answer is changed. */
	n = one(1, "ab\033[8;45;181tcd", 15, out);
	assert(strcmp(out, "ab\033[8;44;181tcd") == 0 && n == 15);

	/* Unrelated control sequences pass through unchanged (arrow key, a
	 * plain CSI m, and a one-parameter CSI ...t which is not the answer). */
	one(1, "\033[A\033[0m\033[8;2t", 13, out);
	assert(strcmp(out, "\033[A\033[0m\033[8;2t") == 0);

	/* Plain text passes through. */
	one(1, "hello world", 11, out);
	assert(strcmp(out, "hello world") == 0);

	/* The answer split across two reads is still rewritten. */
	termfilter_init(&f, 1);
	n = termfilter_run(&f, "\033[8;45", 6, out);		/* partial */
	n += termfilter_run(&f, ";181t", 5, out + n);
	out[n] = '\0';
	assert(strcmp(out, "\033[8;44;181t") == 0);

	/* A too-small terminal answer (rows <= reserve) is left alone. */
	one(1, "\033[8;1;80t", 9, out);
	assert(strcmp(out, "\033[8;1;80t") == 0);

	printf("termfilter: PASS\n");
	return 0;
}
