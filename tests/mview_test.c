/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The machine view: the state document a headless host writes and a
 * supervisor polls. Drives the observer callbacks and reads the rendered
 * file back, checking the schema, the derived service state, the reach
 * enums, the bounded-grant fields with their monotonic write stamp, the
 * per-peer grade and forward-refusal, and that a stopped session leaves no
 * document. The contract, exercised without a DHT or a real session.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mview.h"
#include "sandbox.h"
#include "token.h"

/* Slurp the state file; returns the bytes read (0 if absent). */
static size_t slurp(const char *path, char *buf, size_t n)
{
	FILE *f = fopen(path, "r");
	size_t got;

	if (!f)
		return 0;
	got = fread(buf, 1, n - 1, f);
	fclose(f);
	buf[got] = '\0';
	return got;
}

int main(void)
{
	static const uint8_t a4[4] = { 192, 0, 2, 7 };
	char path[] = "/tmp/comrade-mview-XXXXXX";
	char buf[8192];
	char tok[TOKEN_STR_LEN + 1];
	struct token t;
	struct mview *m;
	struct session_obs obs;
	int fd = mkstemp(path);

	assert(fd >= 0);
	close(fd);

	memset(&t, 0, sizeof(t));
	t.version = TOKEN_VERSION;
	token_set_family(&t, 4, TOKEN_STATE_RENDEZVOUS, a4, 6881);
	token_set_family(&t, 6, TOKEN_STATE_NONE, NULL, 0);
	assert(!token_encode(&t, tok, sizeof(tok)));

	m = mview_create("remoteassist", path, "/var/run/comrade/x.sock");
	assert(m);
	mview_limits(m, 1800, 1);
	mview_bind(m, &obs);

	/* Freshly created, before any token: starting, and stamped. Nothing
	 * has been confined yet, so the document claims nothing about it. */
	assert(slurp(path, buf, sizeof(buf)));
	assert(!strstr(buf, "\"sandbox\""));
	assert(strstr(buf, "\"schema\":1"));
	assert(strstr(buf, "\"id\":\"remoteassist\""));
	assert(strstr(buf, "\"state\":\"starting\""));
	assert(strstr(buf, "\"doc_uptime_s\":"));
	assert(strstr(buf, "\"expire_s\":1800"));
	assert(strstr(buf, "\"expires_in_s\":"));
	assert(strstr(buf, "\"max_clients\":1"));

	/*
	 * What the confinement engaged, by mask and by name, with the length of
	 * the filter it installed. The names are the contract INTEGRATION.md
	 * carries; the bits are sandbox.h's, lowest first.
	 */
	mview_sandbox(m, 0x013b, 74);
	assert(slurp(path, buf, sizeof(buf)));
	assert(strstr(buf, "\"sandbox\":{\"mask\":315,\"layers\":[\"userns\","
		      "\"mountns\",\"seccomp\",\"caps\",\"nonewprivs\","
		      "\"nodump\"],\"filter_insns\":74}"));

	/* A layer with no filter behind it says so by leaving the length out,
	 * and a confinement that engaged nothing at all -- COMRADE_SANDBOX=0,
	 * or a kernel too old for any of it -- is reported, not omitted. */
	mview_sandbox(m, SANDBOX_L_RLIMIT, 0);
	assert(slurp(path, buf, sizeof(buf)));
	assert(strstr(buf, "\"sandbox\":{\"mask\":128,\"layers\":[\"rlimit\"]}"));
	mview_sandbox(m, 0, 0);
	assert(slurp(path, buf, sizeof(buf)));
	assert(strstr(buf, "\"sandbox\":{\"mask\":0,\"layers\":[]}"));

	/* Token minted with a v4 rendezvous: state advances to ready, the
	 * reach carries the enum and endpoint, v6 is none. */
	obs.token(obs.arg, tok);
	assert(slurp(path, buf, sizeof(buf)));
	assert(strstr(buf, "\"state\":\"ready\""));
	assert(strstr(buf, "\"token\":\"1"));
	assert(strstr(buf, "\"v4\":{\"state\":\"ready\",\"kind\":"
		      "\"rendezvous\",\"addr\":\"192.0.2.7\",\"port\":6881}"));
	assert(strstr(buf, "\"v6\":{\"state\":\"none\"}"));

	/* A connected read-write peer: state serving, grade rw. */
	obs.peer(obs.arg, 1, SESSION_PEER_LIVE, "198.51.100.4:41641");
	assert(slurp(path, buf, sizeof(buf)));
	assert(strstr(buf, "\"state\":\"serving\""));
	assert(strstr(buf, "\"peers\":[{\"id\":1,\"state\":\"connected\","
		      "\"grade\":\"rw\""));
	assert(strstr(buf, "\"addr\":\"198.51.100.4:41641\""));

	/* A second peer, read-only, whose forward attempt is refused. */
	obs.peer(obs.arg, 2, SESSION_PEER_LIVE, "203.0.113.9:5000");
	obs.peer_ro(obs.arg, 2);
	obs.peer_fwd_refused(obs.arg, 2);
	assert(slurp(path, buf, sizeof(buf)));
	assert(strstr(buf, "\"id\":2,\"state\":\"connected\",\"grade\":\"ro\","
		      "\"forward_refused\":true"));

	/* A gone peer drops out of the list. */
	obs.peer(obs.arg, 1, SESSION_PEER_GONE, "");
	assert(slurp(path, buf, sizeof(buf)));
	assert(!strstr(buf, "\"id\":1,"));
	assert(strstr(buf, "\"id\":2,"));

	/* An escalation shows as a warning, and clears. */
	obs.escalate(obs.arg, "no public IPv4 from STUN");
	assert(slurp(path, buf, sizeof(buf)));
	assert(strstr(buf, "\"warning\":\"no public IPv4 from STUN\""));
	obs.escalate_clear(obs.arg);
	assert(slurp(path, buf, sizeof(buf)));
	assert(!strstr(buf, "\"warning\""));

	/* A stopped session is an absent document. */
	mview_destroy(m);
	assert(slurp(path, buf, sizeof(buf)) == 0);

	/* An error document names the failure. */
	m = mview_create("remoteassist", path, "/var/run/comrade/x.sock");
	assert(m);
	mview_error(m, "no_tmux");
	assert(slurp(path, buf, sizeof(buf)));
	assert(strstr(buf, "\"state\":\"error\""));
	assert(strstr(buf, "\"error\":\"no_tmux\""));
	mview_destroy(m);
	remove(path);

	printf("MVIEW PASS: state document schema, sandbox report, reach, "
	       "peers, grants, refusal, error, stop\n");
	return 0;
}
