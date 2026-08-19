/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fwdspec.h"

/*
 * Split arg on ':' outside square brackets, stripping the brackets from
 * each token. Returns the token count, or -1 on malformed brackets or
 * overflow. Tokens land NUL-terminated in tok[], each at most tlen-1.
 */
static int split(const char *arg, char tok[][256], int maxtok, size_t tlen)
{
	int n = 0, depth = 0;
	size_t len = 0;

	if (!arg)
		return -1;
	for (;; arg++) {
		char c = *arg;

		if (c == '[' && !depth && !len) {
			depth = 1;
			continue;
		}
		if (c == ']' && depth) {
			depth = 0;
			continue;
		}
		if ((c == ':' && !depth) || c == '\0') {
			if (n >= maxtok)
				return -1;
			tok[n][len] = '\0';
			n++;
			len = 0;
			if (c == '\0')
				return depth ? -1 : n;
			continue;
		}
		/* Bound the token index here too, not only at a separator: a spec
		 * with more fields than tok[] holds reaches this write with n
		 * already past the end. */
		if (n >= maxtok || len + 1 >= tlen)
			return -1;
		tok[n][len++] = c;
	}
}

/* Parse a decimal port. allow_zero admits 0 ("any", -R's let-the-peer-pick).
 * Returns 0 on success. */
static int parse_port(const char *s, int allow_zero, uint16_t *out)
{
	char *end;
	long v;

	if (!*s)
		return -1;
	v = strtol(s, &end, 10);
	if (*end || v < 0 || v > 65535 || (!v && !allow_zero))
		return -1;
	*out = (uint16_t)v;
	return 0;
}

int fwdspec_parse(const char *arg, struct fwdspec *sp)
{
	char tok[4][256];
	int n = split(arg, tok, 4, sizeof(tok[0]));
	int i = 0;

	size_t len;

	memset(sp, 0, sizeof(*sp));
	if (n != 3 && n != 4)
		return -1;
	if (n == 4) {
		len = strlen(tok[0]);
		if (len >= sizeof(sp->bind))
			return -1;
		memcpy(sp->bind, tok[0], len + 1);
		i = 1;
	}
	if (parse_port(tok[i], 1, &sp->bind_port))
		return -1;
	len = strlen(tok[i + 1]);
	if (!len || len >= sizeof(sp->host))
		return -1;
	memcpy(sp->host, tok[i + 1], len + 1);
	if (parse_port(tok[i + 2], 0, &sp->port))
		return -1;
	return 0;
}
