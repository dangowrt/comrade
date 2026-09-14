/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>

#include "wsock.h"

#include "obsemit.h"

void obsemit_init(struct obsemit *e, const struct session_obs *o,
		  struct netstate *ns)
{
	memset(e, 0, sizeof(*e));
	e->o = o;
	e->ns = ns;
}

void obsemit_rows(struct obsemit *e, int family)
{
	const struct session_obs *o = e->o;
	const struct netstate_row *rows;
	int n, k;

	if (!o || !o->net_reset || !o->net)
		return;
	n = netstate_rows(e->ns, family, &rows);
	o->net_reset(o->arg, family);
	for (k = 0; k < n; k++)
		if (rows[k].shown)
			o->net(o->arg, family, rows[k].scope,
			       netstate_row_via(e->ns, family, &rows[k]),
			       rows[k].text);
}

void obsemit_conn(struct obsemit *e, int family, int conn)
{
	const struct session_obs *o = e->o;

	if (o && o->net_conn)
		o->net_conn(o->arg, family, conn);
}

void obsemit_links(struct obsemit *e, const struct sig_mcast_if *ifs, int n)
{
	const struct session_obs *o = e->o;
	int k;

	if (!o || !o->link)
		return;
	if (o->link_reset)
		o->link_reset(o->arg);
	for (k = 0; k < n; k++)
		o->link(o->arg, ifs[k].name, ifs[k].has4, ifs[k].has6);
}

/*
 * The ages are seconds rather than timestamps because that is what the view
 * would compute anyway, and it keeps the clock on this side of the seam.
 */
void obsemit_mailbox(struct obsemit *e, const struct sig_mailbox *sm,
		     uint64_t now)
{
	static const int famv[2] = { 4, 6 };
	const struct session_obs *o = e->o;
	struct session_mailbox m;
	int i;

	if (!o || !o->mailbox)
		return;
	memset(&m, 0, sizeof(m));
	m.engaged = sm->engaged;
	m.stage = sm->stage;
	m.have_mine = sm->have_mine;
	m.mine_stored = sm->mine_stored;
	m.peer_seen = sm->peer_seen;
	m.seq = sm->seq;
	m.gets = sm->gets;
	m.puts = sm->puts;
	m.claim = sm->claim;
	m.age_get_s = sm->last_get_ms ? (int)((now - sm->last_get_ms) / 1000) :
				        -1;
	m.age_put_s = sm->last_put_ms ? (int)((now - sm->last_put_ms) / 1000) :
				        -1;
	for (i = 0; i < 2; i++) {
		int proven = 0;

		if (!netstate_anchor(e->ns, famv[i], NULL, NULL, &proven))
			continue;
		if (proven)
			m.rdv_proven = 1;
		else
			m.rdv_holding = 1;
	}
	if (e->told_any && !memcmp(&m, &e->told, sizeof(m)))
		return;
	e->told = m;
	e->told_any = 1;
	o->mailbox(o->arg, &m);
}

/* Printable "addr:port" for a sockaddr; empty on failure. */
static void addr_str(const struct sockaddr *sa, char *out, size_t n)
{
	char host[64];

	out[0] = '\0';
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		if (inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof(host)))
			snprintf(out, n, "%s:%u", host, ntohs(a->sin6_port));
	} else if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		if (inet_ntop(AF_INET, &a->sin_addr, host, sizeof(host)))
			snprintf(out, n, "%s:%u", host, ntohs(a->sin_port));
	}
}

void obsemit_rendezvous(struct obsemit *e, int expect4, int expect6)
{
	static const int famv[2] = { 4, 6 };
	const struct session_obs *o = e->o;
	int i;

	if (!o || !o->rendezvous)
		return;
	for (i = 0; i < 2; i++) {
		uint8_t node[NETSTATE_SA_MAX], nlen = 0;
		int proven = 0, vouched = 0, row;
		char b[80];

		if (netstate_anchor(e->ns, famv[i], node, &nlen, NULL) && nlen) {
			netstate_anchor_state(e->ns, famv[i], &proven, &vouched,
					      NULL);
			row = proven ? RDV_ROW_PROVEN :
			      vouched ? RDV_ROW_VOUCHED : RDV_ROW_CHECKING;
			addr_str((const struct sockaddr *)node, b, sizeof(b));
			o->rendezvous(o->arg, famv[i], b, row);
		} else if (famv[i] == 4 ? expect4 : expect6) {
			o->rendezvous(o->arg, famv[i], "", RDV_ROW_CHECKING);
		}
	}
}
