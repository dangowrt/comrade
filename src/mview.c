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
	int fwd_refused;		/* a forwarding attempt was declined */
	char addr[80];
};

struct mview {
	struct session_mailbox mb;	/* the last mailbox state seen */
	int have_mb;
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
	int sb_layers;			/* SANDBOX_L_* the confinement engaged */
	int sb_insns;			/* its syscall filter's length, 0 = none */
	int have_sb;			/* the confinement has been applied */
};

/*
 * How the engaged sandbox layers are spelled in the document, by bit position,
 * lowest first: SANDBOX_L_USERNS is bit 0. The names are contract
 * (INTEGRATION.md) and the bits are sandbox.h's, so a layer added there needs
 * a name added here. A bit with no name is reported by its number rather than
 * dropped: a document that quietly omitted the very layer being asked about
 * would be worse than an ugly one.
 */
static const char *const mv_sb_name[] = {
	"userns", "mountns", "landlock", "seccomp", "caps", "nonewprivs",
	"mdwe", "rlimit", "nodump", "job", "mitigation"
};

/*
 * What the confinement did, for the report that arrives saying it died on
 * somebody's box: the mask exactly as sandbox_apply() returned it, the layers
 * by name, and the syscall filter's length where the platform has one.
 */
static void mv_sandbox(const struct mview *m, FILE *out)
{
	int bit, first = 1, named = (int)(sizeof(mv_sb_name) /
					  sizeof(mv_sb_name[0]));

	fprintf(out, ",\"sandbox\":{\"mask\":%d,\"layers\":[", m->sb_layers);
	for (bit = 0; bit < 31; bit++) {
		if (!(m->sb_layers & (1 << bit)))
			continue;
		if (bit < named)
			fprintf(out, "%s\"%s\"", first ? "" : ",",
				mv_sb_name[bit]);
		else
			fprintf(out, "%s\"bit%d\"", first ? "" : ",", bit);
		first = 0;
	}
	fputc(']', out);
	if (m->sb_insns)
		fprintf(out, ",\"filter_insns\":%d", m->sb_insns);
	fputc('}', out);
}

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
	if (m->have_sb)
		mv_sandbox(m, out);
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
		if (p->fwd_refused)
			fputs(",\"forward_refused\":true", out);
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

/*
 * The mailbox, on every transition. A supervisor or a test watching a host
 * that is not being joined has the same question an operator has -- did our
 * slot reach the DHT, has the peer's appeared, is the node worth naming yet --
 * and the terminal is where the answer used to be, which is no use to either.
 */
static void det_mailbox(const struct mview *m, FILE *out, int a)
{
	const struct session_mailbox *b = &m->mb;
	static const char *claims[] = { "unknown", "free", "held", "busy" };
	static const char *stages[] = { "cold", "warmup", "store", "get",
					"ready" };
	const char *node = b->rdv_proven ? "proven" :
			   b->rdv_holding ? "proving" : "none";
	int st = b->stage < 0 ? 0 : b->stage > 4 ? 4 : b->stage;

	(void)a;
	fprintf(out, ",\"mailbox\":{\"engaged\":%s,\"dht\":\"%s\","
		"\"ours\":\"%s\","
		"\"peer\":\"%s\",\"node\":\"%s\","
		"\"proving\":%s,\"proven\":%s,\"seq\":%lld,"
		"\"reads\":%d,\"writes\":%d,\"claim\":\"%s\","
		"\"read_age_s\":%d,\"write_age_s\":%d}",
		b->engaged ? "true" : "false", stages[st],
		b->mine_stored ? "stored" : b->have_mine ? "unstored" : "none",
		b->peer_seen ? "present" : "absent", node,
		b->rdv_holding ? "true" : "false",
		b->rdv_proven ? "true" : "false", (long long)b->seq,
		b->gets, b->puts, claims[b->claim & 3],
		b->age_get_s, b->age_put_s);
}

static void mv_mailbox(void *arg, const struct session_mailbox *b)
{
	struct mview *m = arg;
	struct session_mailbox now = *b, was = m->mb;
	int changed = !m->have_mb || memcmp(&was, &now, sizeof(now));

	/*
	 * Two audiences. The state document is a snapshot, so it carries the
	 * counters and ages and is rewritten whenever any of them move. The
	 * event stream is a log, so it gets a line when the mailbox actually
	 * reached a new state -- our slot stored, the peer's appeared, a node
	 * proven -- and counting reads is not that.
	 */
	now.age_get_s = was.age_get_s = 0;
	now.age_put_s = was.age_put_s = 0;
	now.gets = was.gets = 0;
	now.puts = was.puts = 0;
	now.seq = was.seq = 0;		/* a re-store is upkeep, not a new state */
	if (!changed)
		return;
	m->mb = *b;
	if (m->have_mb && !memcmp(&was, &now, sizeof(now))) {
		m->have_mb = 1;
		mv_write(m);		/* the snapshot moved, the state did not */
		return;
	}
	m->have_mb = 1;
	mv_write(m);
	mv_event(m, "mailbox", det_mailbox, 0);
}

static void det_peer(const struct mview *m, FILE *out, int i)
{
	const struct mv_peer *p = &m->peer[i];

	fprintf(out, ",\"peer\":{\"id\":%d,\"peer_state\":\"%s\","
		"\"grade\":\"%s\"", p->id, mv_peer_state(p->state),
		p->read_only ? "ro" : "rw");
	if (p->fwd_refused)
		fputs(",\"forward_refused\":true", out);
	if (p->addr[0] && p->addr[0] != '-') {
		fputs(",\"addr\":", out);
		showfmt_json_str(out, p->addr);
	}
	fputc('}', out);
}

static void det_sandbox(const struct mview *m, FILE *out, int a)
{
	(void)a;
	mv_sandbox(m, out);
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

static void mv_peer_fwd_refused(void *arg, int id)
{
	struct mview *m = arg;
	struct mv_peer *p = mv_peer_slot(m, id);

	if (!p || p->fwd_refused)
		return;
	p->fwd_refused = 1;
	mv_write(m);
	mv_event(m, "forward_refused", det_peer, (int)(p - m->peer));
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

/*
 * The confinement is applied once, during startup, and is never reversed, so
 * this arrives once. It is an event as well as a document field because the
 * document is removed when the session ends: a supervisor's log is then the
 * only place the answer survives a session that is over, which is exactly the
 * session anybody asks about.
 */
void mview_sandbox(struct mview *m, int layers, int filter_insns)
{
	m->sb_layers = layers;
	m->sb_insns = filter_insns;
	m->have_sb = 1;
	mv_write(m);
	mv_event(m, "sandbox", det_sandbox, 0);
}

void mview_bind(struct mview *m, struct session_obs *obs)
{
	memset(obs, 0, sizeof(*obs));
	obs->arg = m;
	obs->token = mv_token;
	obs->token_ro = mv_token_ro;
	obs->peer = mv_peer_cb;
	obs->peer_ro = mv_peer_ro;
	obs->peer_fwd_refused = mv_peer_fwd_refused;
	obs->escalate = mv_escalate;
	obs->escalate_clear = mv_escalate_clear;
	obs->mailbox = mv_mailbox;
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
