/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mview.h"
#include "oscompat.h"
#include "showfmt.h"
#include "token.h"

#define MV_PEERS 8

struct mv_peer {
	int id;
	int state;			/* SESSION_PEER_* */
	int read_only;
	char addr[80];
};

struct mview {
	char id[64];
	char state_path[512];
	char tmux_sock[512];
	char token[256];
	char token_ro[256];
	char error[32];
	char escalate[160];
	struct mv_peer peer[MV_PEERS];
	int npeer;
	int expire_s;
	int max_clients;
	double expire_deadline;		/* os_uptime_s() at which the grant ends */
};

/* The stable service-state enum, derived from what has been observed. */
static const char *mv_state(const struct mview *m)
{
	struct token t;
	int i;

	if (m->error[0])
		return "error";
	for (i = 0; i < m->npeer; i++)
		if (m->peer[i].state == SESSION_PEER_LIVE)
			return "serving";
	if (!m->token[0])
		return "starting";
	if (!token_decode(&t, m->token) &&
	    (token_family_state(&t, 4) == TOKEN_STATE_RENDEZVOUS ||
	     token_family_state(&t, 4) == TOKEN_STATE_DIRECT ||
	     token_family_state(&t, 6) == TOKEN_STATE_RENDEZVOUS ||
	     token_family_state(&t, 6) == TOKEN_STATE_DIRECT))
		return "ready";
	return "rendezvous";
}

static const char *mv_peer_state(int state)
{
	switch (state) {
	case SESSION_PEER_SEEN:		return "seen";
	case SESSION_PEER_PUNCHING:	return "punching";
	case SESSION_PEER_LIVE:		return "connected";
	default:			return "gone";
	}
}

/* The session document, the same object `comrade show --json` embeds. */
static void mv_doc(const struct mview *m, FILE *out)
{
	struct token t;
	int i, first = 1;

	fputs("{\"schema\":1,\"id\":", out);
	showfmt_json_str(out, m->id);
	fprintf(out, ",\"pid\":%ld,\"state\":\"%s\"", (long)os_getpid(),
		mv_state(m));
	/* The write stamp a stateless reader age-corrects every relative
	 * duration against: remaining = field - (uptime_now - doc_uptime_s). */
	fprintf(out, ",\"doc_uptime_s\":%.1f", os_uptime_s());
	if (m->expire_s) {
		long rem = (long)(m->expire_deadline - os_uptime_s());

		fprintf(out, ",\"expire_s\":%d,\"expires_in_s\":%ld",
			m->expire_s, rem > 0 ? rem : 0);
	}
	if (m->max_clients)
		fprintf(out, ",\"max_clients\":%d", m->max_clients);
	if (m->error[0])
		fprintf(out, ",\"error\":\"%s\"", m->error);
	if (m->token[0]) {
		fputs(",\"token\":", out);
		showfmt_json_str(out, m->token);
	}
	if (m->token_ro[0]) {
		fputs(",\"token_ro\":", out);
		showfmt_json_str(out, m->token_ro);
	}
	if (m->token[0] && !token_decode(&t, m->token)) {
		fputs(",\"reach\":", out);
		showfmt_json_reach(out, &t);
	}
	fputs(",\"tmux\":{\"socket\":", out);
	showfmt_json_str(out, m->tmux_sock);
	fputs(",\"session\":\"comrade\"},\"peers\":[", out);
	for (i = 0; i < m->npeer; i++) {
		const struct mv_peer *p = &m->peer[i];

		if (p->state == SESSION_PEER_GONE)
			continue;
		fprintf(out, "%s{\"id\":%d,\"state\":\"%s\",\"grade\":\"%s\"",
			first ? "" : ",", p->id, mv_peer_state(p->state),
			p->read_only ? "ro" : "rw");
		if (p->addr[0] && p->addr[0] != '-') {
			fputs(",\"addr\":", out);
			showfmt_json_str(out, p->addr);
		}
		fputc('}', out);
		first = 0;
	}
	fputc(']', out);
	if (m->escalate[0]) {
		fputs(",\"warning\":", out);
		showfmt_json_str(out, m->escalate);
	}
	fputc('}', out);
}

/* Rewrite the state file (tmp + rename, never half a document). */
static void mv_write(const struct mview *m)
{
	char tmp[520];
	FILE *f;

	snprintf(tmp, sizeof(tmp), "%s.tmp", m->state_path);
	f = fopen(tmp, "w");
	if (!f)
		return;
	mv_doc(m, f);
	fputc('\n', f);
	if (fclose(f) || os_rename_replace(tmp, m->state_path))
		remove(tmp);
}

/* One event line on stdout: what changed, then the resulting state. */
static void mv_event(const struct mview *m, const char *ev,
		     void (*detail)(const struct mview *, FILE *, int),
		     int a)
{
	printf("{\"event\":\"%s\"", ev);
	if (detail)
		detail(m, stdout, a);
	printf(",\"state\":\"%s\"}\n", mv_state(m));
	fflush(stdout);
}

static void det_token(const struct mview *m, FILE *out, int a)
{
	(void)a;
	fputs(",\"token\":", out);
	showfmt_json_str(out, m->token);
	if (m->token_ro[0]) {
		fputs(",\"token_ro\":", out);
		showfmt_json_str(out, m->token_ro);
	}
}

static void det_peer(const struct mview *m, FILE *out, int i)
{
	const struct mv_peer *p = &m->peer[i];

	fprintf(out, ",\"peer\":{\"id\":%d,\"peer_state\":\"%s\","
		"\"grade\":\"%s\"", p->id, mv_peer_state(p->state),
		p->read_only ? "ro" : "rw");
	if (p->addr[0] && p->addr[0] != '-') {
		fputs(",\"addr\":", out);
		showfmt_json_str(out, p->addr);
	}
	fputc('}', out);
}

static void det_warning(const struct mview *m, FILE *out, int a)
{
	(void)a;
	fputs(",\"warning\":", out);
	showfmt_json_str(out, m->escalate);
}

static struct mv_peer *mv_peer_slot(struct mview *m, int id)
{
	int i;

	for (i = 0; i < m->npeer; i++)
		if (m->peer[i].id == id)
			return &m->peer[i];
	if (m->npeer < MV_PEERS) {
		memset(&m->peer[m->npeer], 0, sizeof(m->peer[0]));
		m->peer[m->npeer].id = id;
		return &m->peer[m->npeer++];
	}
	return NULL;
}

/* ---- observer callbacks ---- */

static void mv_token(void *arg, const char *tok)
{
	struct mview *m = arg;

	if (!strcmp(m->token, tok))
		return;
	snprintf(m->token, sizeof(m->token), "%s", tok);
	mv_write(m);
	mv_event(m, "token", det_token, 0);
}

static void mv_token_ro(void *arg, const char *tok)
{
	struct mview *m = arg;

	if (!strcmp(m->token_ro, tok))
		return;
	snprintf(m->token_ro, sizeof(m->token_ro), "%s", tok);
	mv_write(m);
	mv_event(m, "token", det_token, 0);
}

static void mv_peer_cb(void *arg, int id, int state, const char *addr)
{
	struct mview *m = arg;
	struct mv_peer *p = mv_peer_slot(m, id);

	if (!p)
		return;
	p->state = state;
	if (addr && addr[0])
		snprintf(p->addr, sizeof(p->addr), "%s", addr);
	mv_write(m);
	mv_event(m, "peer", det_peer, (int)(p - m->peer));
}

static void mv_peer_ro(void *arg, int id)
{
	struct mview *m = arg;
	struct mv_peer *p = mv_peer_slot(m, id);

	if (!p || p->read_only)
		return;
	p->read_only = 1;
	mv_write(m);
	mv_event(m, "peer", det_peer, (int)(p - m->peer));
}

static void mv_escalate(void *arg, const char *why)
{
	struct mview *m = arg;

	snprintf(m->escalate, sizeof(m->escalate), "%s", why);
	mv_write(m);
	mv_event(m, "warning", det_warning, 0);
}

static void mv_escalate_clear(void *arg)
{
	struct mview *m = arg;

	if (!m->escalate[0])
		return;
	m->escalate[0] = '\0';
	mv_write(m);
	mv_event(m, "warning_cleared", NULL, 0);
}

/* ---- lifecycle ---- */

struct mview *mview_create(const char *id, const char *state_path,
			   const char *tmux_sock)
{
	struct mview *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	snprintf(m->id, sizeof(m->id), "%s", id);
	snprintf(m->state_path, sizeof(m->state_path), "%s", state_path);
	snprintf(m->tmux_sock, sizeof(m->tmux_sock), "%s", tmux_sock);
	mv_write(m);
	mv_event(m, "started", NULL, 0);
	return m;
}

void mview_limits(struct mview *m, int expire_s, int max_clients)
{
	m->expire_s = expire_s;
	m->max_clients = max_clients;
	if (expire_s > 0)
		m->expire_deadline = os_uptime_s() + expire_s;
	mv_write(m);
}

void mview_bind(struct mview *m, struct session_obs *obs)
{
	memset(obs, 0, sizeof(*obs));
	obs->arg = m;
	obs->token = mv_token;
	obs->token_ro = mv_token_ro;
	obs->peer = mv_peer_cb;
	obs->peer_ro = mv_peer_ro;
	obs->escalate = mv_escalate;
	obs->escalate_clear = mv_escalate_clear;
}

void mview_error(struct mview *m, const char *err)
{
	snprintf(m->error, sizeof(m->error), "%s", err);
	mv_write(m);
	mv_event(m, "error", NULL, 0);
}

void mview_destroy(struct mview *m)
{
	if (!m)
		return;
	mv_event(m, "stopped", NULL, 0);
	remove(m->state_path);
	free(m);
}
