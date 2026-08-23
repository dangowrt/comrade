/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The `comrade show` shapes: the human two-liner, the bare-token forms
 * with their one-session discipline, and the machine JSON -- escaping,
 * reach derivation from a decoded token, state-file passthrough, and the
 * exit codes each shape owes its caller.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "showfmt.h"
#include "token.h"

/* Run one shape over n scripted sessions; the output lands in buf. */
static int run(int what, int nses, int with_ro, const char *statejson,
	       char *buf, size_t buflen)
{
	FILE *f = tmpfile();
	struct showfmt sf;
	struct token t;
	char tok[TOKEN_STR_LEN + 1], ro[TOKEN_STR_LEN + 1];
	static const uint8_t a4[4] = { 192, 0, 2, 7 };
	size_t got;
	int i, rc;

	assert(f);
	memset(&t, 0, sizeof(t));
	t.version = TOKEN_VERSION;
	token_set_family(&t, 4, TOKEN_STATE_RENDEZVOUS, a4, 6881);
	token_set_family(&t, 6, TOKEN_STATE_NONE, NULL, 0);
	assert(!token_encode(&t, tok, sizeof(tok)));
	t.flags |= TOKEN_FLAG_RO;
	assert(!token_encode(&t, ro, sizeof(ro)));

	showfmt_begin(&sf, what, f);
	for (i = 0; i < nses; i++)
		showfmt_session(&sf, i ? "beta" : "alpha", "/run/x.sock",
				tok, with_ro ? ro : "", statejson);
	rc = showfmt_end(&sf);
	rewind(f);
	got = fread(buf, 1, buflen - 1, f);
	buf[got] = '\0';
	fclose(f);
	return rc;
}

int main(void)
{
	char out[4096];

	/* Human: both grades, one line each. */
	assert(run(SHOWFMT_HUMAN, 1, 1, NULL, out, sizeof(out)) == 0);
	assert(strstr(out, "read-write  1") && strstr(out, "read-only   1"));

	/* Bare token: exactly the token, exactly one session required. */
	assert(run(SHOWFMT_TOKEN, 1, 1, NULL, out, sizeof(out)) == 0);
	assert(out[0] == '1' && strchr(out, '\n') && !strchr(out, ' '));
	assert(run(SHOWFMT_TOKEN, 0, 1, NULL, out, sizeof(out)) == 1);
	assert(run(SHOWFMT_TOKEN, 2, 1, NULL, out, sizeof(out)) == 1);
	assert(run(SHOWFMT_TOKEN_RO, 1, 1, NULL, out, sizeof(out)) == 0);
	assert(run(SHOWFMT_TOKEN_RO, 1, 0, NULL, out, sizeof(out)) == 1);

	/* JSON: an empty list is fine (exit 0), a session carries the
	 * decoded reach and omits an absent read-only token. */
	assert(run(SHOWFMT_JSON, 0, 1, NULL, out, sizeof(out)) == 0);
	assert(!strcmp(out, "{\"schema\":1,\"sessions\":[]}\n"));
	assert(run(SHOWFMT_JSON, 1, 0, NULL, out, sizeof(out)) == 0);
	assert(strstr(out, "\"id\":\"alpha\""));
	assert(strstr(out, "\"token\":\"1"));
	assert(!strstr(out, "token_ro"));
	assert(strstr(out, "\"v4\":{\"state\":\"ready\",\"kind\":"
		      "\"rendezvous\",\"addr\":\"192.0.2.7\",\"port\":6881}"));
	assert(strstr(out, "\"v6\":{\"state\":\"none\"}"));
	assert(strstr(out, "\"tmux\":{\"socket\":\"/run/x.sock\","
		      "\"session\":\"comrade\"}"));

	/* A state document passes through verbatim, comma-joined. */
	assert(run(SHOWFMT_JSON, 2, 1, "{\"id\":\"x\",\"state\":\"ready\"}",
		   out, sizeof(out)) == 0);
	assert(strstr(out, "[{\"id\":\"x\",\"state\":\"ready\"},"
		      "{\"id\":\"x\",\"state\":\"ready\"}]"));

	printf("SHOWFMT PASS: human, bare-token discipline, JSON shapes\n");
	return 0;
}
