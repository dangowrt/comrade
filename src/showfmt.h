/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_SHOWFMT_H
#define COMRADE_SHOWFMT_H

#include <stdio.h>

/*
 * The output side of `comrade show`, shared by the POSIX and Windows hosts:
 * the caller walks the live sessions and feeds each one in; this formats.
 * Four shapes: the human two-liner, the bare token (either grade, for
 * scripts, clipboards and screen readers -- exactly one line, so it needs
 * exactly one live session), and machine JSON (INTEGRATION.md carries the
 * schema; sessions the machine view already describes hand their state
 * file through verbatim, the rest are summarised from the token).
 */

enum {
	SHOWFMT_HUMAN,
	SHOWFMT_TOKEN,			/* the read-write token, bare */
	SHOWFMT_TOKEN_RO,		/* the read-only token, bare */
	SHOWFMT_JSON
};

struct showfmt {
	int what;
	int n;				/* sessions seen */
	FILE *out;
	char keep[2][256];		/* the only session's tokens, for
					 * the bare-token shapes */
};

void showfmt_begin(struct showfmt *f, int what, FILE *out);

/*
 * One live session. tok_ro may be "" when the session mints none. statejson,
 * when non-NULL, is the session's own state-file document (a complete JSON
 * object, trusted verbatim); otherwise a summary object is derived from the
 * decoded token.
 */
void showfmt_session(struct showfmt *f, const char *id, const char *sock,
		     const char *tok, const char *tok_ro,
		     const char *statejson);

/* Close the output; the exit code for main (0 ok, 1 nothing to show /
 * ambiguous). JSON with no sessions is an empty list and exits 0. */
int showfmt_end(struct showfmt *f);

struct token;

/* JSON building blocks shared with the machine view: a minimally escaped
 * string, and both families' reach object derived from a decoded token. */
void showfmt_json_str(FILE *out, const char *s);
void showfmt_json_reach(FILE *out, const struct token *t);

#endif
