/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdlib.h>
#include <string.h>

#include <juice/juice.h>

#include "nat.h"

struct nat_agent {
	juice_agent_t *agent;
	nat_cb_local_sdp *on_local_sdp;
	nat_cb_state *on_state;
	nat_cb_recv *on_recv;
	void *arg;
	int connected;
	int failed;
	int gathered;
	int remote_set;
};

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user)
{
	struct nat_agent *a = user;

	(void)agent;
	a->connected = state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED;
	a->failed = state == JUICE_STATE_FAILED;
	if (a->on_state)
		a->on_state(a->arg, a->connected, a->failed);
}

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user)
{
	(void)agent;
	(void)sdp;
	(void)user;
}

static void on_gathering_done(juice_agent_t *agent, void *user)
{
	struct nat_agent *a = user;
	char sdp[NAT_SDP_MAX];

	(void)agent;
	a->gathered = 1;
	if (a->on_local_sdp &&
	    juice_get_local_description(a->agent, sdp, sizeof(sdp)) >= 0)
		a->on_local_sdp(a->arg, sdp);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user)
{
	struct nat_agent *a = user;

	(void)agent;
	if (a->on_recv)
		a->on_recv(a->arg, (const uint8_t *)data, size);
}

struct nat_agent *nat_create(const struct nat_config *cfg)
{
	struct nat_agent *a = calloc(1, sizeof(*a));
	juice_config_t jc;

	if (!a)
		return NULL;
	a->on_local_sdp = cfg->on_local_sdp;
	a->on_state = cfg->on_state;
	a->on_recv = cfg->on_recv;
	a->arg = cfg->arg;

	memset(&jc, 0, sizeof(jc));
	jc.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL;
	jc.stun_server_host = cfg->stun_host;
	jc.stun_server_port = cfg->stun_port;
	jc.bind_address = cfg->bind_address;
	if (cfg->bind_port) {
		jc.local_port_range_begin = cfg->bind_port;
		jc.local_port_range_end = cfg->bind_port;
	}
	jc.cb_state_changed = on_state_changed;
	jc.cb_candidate = on_candidate;
	jc.cb_gathering_done = on_gathering_done;
	jc.cb_recv = on_recv;
	jc.user_ptr = a;

	a->agent = juice_create(&jc);
	if (!a->agent) {
		free(a);
		return NULL;
	}
	if (cfg->ice_ufrag && cfg->ice_pwd)
		juice_set_local_ice_attributes(a->agent, cfg->ice_ufrag,
					       cfg->ice_pwd);
	return a;
}

void nat_destroy(struct nat_agent *a)
{
	if (!a)
		return;
	if (a->agent)
		juice_destroy(a->agent);
	free(a);
}

int nat_gather(struct nat_agent *a)
{
	return juice_gather_candidates(a->agent) == JUICE_ERR_SUCCESS ? 0 : -1;
}

int nat_local_description(struct nat_agent *a, char *sdp, size_t len)
{
	return juice_get_local_description(a->agent, sdp, len) >= 0 ? 0 : -1;
}

/* Trickle every candidate line in sdp; libjuice ignores duplicates. */
static void trickle_candidates(struct nat_agent *a, const char *sdp)
{
	const char *line = sdp;
	const char *nl;
	size_t n;
	char buf[256];

	while (line && *line) {
		nl = strchr(line, '\n');
		n = nl ? (size_t)(nl - line) : strlen(line);
		if (!strncmp(line, "a=candidate:", 12) && n < sizeof(buf)) {
			memcpy(buf, line, n);
			buf[n] = '\0';
			juice_add_remote_candidate(a->agent, buf);
		}
		if (!nl)
			break;
		line = nl + 1;
	}
}

/*
 * The first call sets the peer's credentials and candidates. Later calls carry
 * the same credentials but fresh candidates (multicast delivers them one source
 * at a time); add those by trickle rather than replacing the description.
 */
int nat_set_remote_description(struct nat_agent *a, const char *sdp)
{
	if (!a->remote_set) {
		if (juice_set_remote_description(a->agent, sdp) != JUICE_ERR_SUCCESS)
			return -1;
		a->remote_set = 1;
		return 0;
	}
	trickle_candidates(a, sdp);
	return 0;
}

int nat_send(struct nat_agent *a, const uint8_t *data, size_t len)
{
	return juice_send(a->agent, (const char *)data, len) == JUICE_ERR_SUCCESS ? 0 : -1;
}

int nat_connected(struct nat_agent *a)
{
	return a->connected;
}

int nat_failed(struct nat_agent *a)
{
	return a->failed;
}

int nat_selected(struct nat_agent *a, char *local, size_t local_len,
		 char *remote, size_t remote_len)
{
	return juice_get_selected_candidates(a->agent, local, local_len,
					     remote, remote_len) == JUICE_ERR_SUCCESS ? 0 : -1;
}

void nat_log_level(int level)
{
	juice_set_log_level((juice_log_level_t)level);
}
