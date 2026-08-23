/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "showfmt.h"
#include "token.h"
#include "wsock.h"

/* Minimal JSON string escape: quote, backslash, and control bytes. */
void showfmt_json_str(FILE *out, const char *s)
{
	fputc('"', out);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\')
			fprintf(out, "\\%c", c);
		else if (c < 0x20)
			fprintf(out, "\\u%04x", c);
		else
			fputc(c, out);
	}
	fputc('"', out);
}

/* A family's reach object from its token state, machine-facing enums. */
static void json_reach_fam(FILE *out, const struct token *t, int family)
{
	static const char *st[4] = { "pending", "none", "ready", "ready" };
	int state = token_family_state(t, family);
	char ip[64];

	fprintf(out, "{\"state\":\"%s\"", st[state & 3]);
	if (state == TOKEN_STATE_RENDEZVOUS || state == TOKEN_STATE_DIRECT) {
		const char *p;
		uint16_t port;

		fprintf(out, ",\"kind\":\"%s\"",
			state == TOKEN_STATE_DIRECT ? "direct" : "rendezvous");
		if (family == 6) {
			p = inet_ntop(AF_INET6, t->ep6_addr, ip, sizeof(ip));
			port = t->ep6_port;
		} else {
			p = inet_ntop(AF_INET, t->ep4_addr, ip, sizeof(ip));
			port = t->ep4_port;
		}
		if (p)
			fprintf(out, ",\"addr\":\"%s\",\"port\":%u", ip, port);
	}
	fputc('}', out);
}

/* Both families' reach as one object. */
void showfmt_json_reach(FILE *out, const struct token *t)
{
	fputs("{\"v4\":", out);
	json_reach_fam(out, t, 4);
	fputs(",\"v6\":", out);
	json_reach_fam(out, t, 6);
	fputc('}', out);
}

void showfmt_begin(struct showfmt *f, int what, FILE *out)
{
	memset(f, 0, sizeof(*f));
	f->what = what;
	f->out = out;
	if (what == SHOWFMT_JSON)
		fputs("{\"schema\":1,\"sessions\":[", out);
}

void showfmt_session(struct showfmt *f, const char *id, const char *sock,
		     const char *tok, const char *tok_ro,
		     const char *statejson)
{
	FILE *out = f->out;

	if (f->what == SHOWFMT_HUMAN) {
		fprintf(out, "read-write  %s\n", tok);
		if (tok_ro[0])
			fprintf(out, "read-only   %s\n", tok_ro);
	} else if (f->what == SHOWFMT_TOKEN || f->what == SHOWFMT_TOKEN_RO) {
		snprintf(f->keep[0], sizeof(f->keep[0]), "%s", tok);
		snprintf(f->keep[1], sizeof(f->keep[1]), "%s", tok_ro);
	} else {
		struct token t;

		fputs(f->n ? "," : "", out);
		if (statejson) {
			fputs(statejson, out);
			f->n++;
			return;
		}
		fputs("{\"id\":", out);
		showfmt_json_str(out, id);
		fputs(",\"token\":", out);
		showfmt_json_str(out, tok);
		if (tok_ro[0]) {
			fputs(",\"token_ro\":", out);
			showfmt_json_str(out, tok_ro);
		}
		if (!token_decode(&t, tok)) {
			fputs(",\"reach\":", out);
			showfmt_json_reach(out, &t);
		}
		fputs(",\"tmux\":{\"socket\":", out);
		showfmt_json_str(out, sock);
		fputs(",\"session\":\"comrade\"}}", out);
	}
	f->n++;
}

int showfmt_end(struct showfmt *f)
{
	const char *want;

	switch (f->what) {
	case SHOWFMT_JSON:
		fputs("]}\n", f->out);
		return 0;
	case SHOWFMT_TOKEN:
	case SHOWFMT_TOKEN_RO:
		if (f->n == 0) {
			fprintf(stderr, "comrade: no running session\n");
			return 1;
		}
		if (f->n > 1) {
			fprintf(stderr, "comrade: several sessions running "
				"-- use `comrade show --json`\n");
			return 1;
		}
		want = f->keep[f->what == SHOWFMT_TOKEN_RO];
		if (!want[0]) {
			fprintf(stderr, "comrade: the session has no "
				"read-only token\n");
			return 1;
		}
		fprintf(f->out, "%s\n", want);
		return 0;
	default:
		if (!f->n) {
			fprintf(stderr, "comrade: no running session\n");
			return 1;
		}
		return 0;
	}
}
