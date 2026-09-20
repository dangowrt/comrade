/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "wsock.h"

#include "obsemit.h"

/* What a watcher was told, in the order it was told. */
struct watcher {
	int resets;
	int rows;
	char last_row[64];
	int conn_family;
	int conn_state;
	int conns;
	int link_resets;
	int links;
	char last_link[32];
	int mailboxes;
	struct session_mailbox last_mailbox;
	int rdv_calls;
	int rdv_family[4];
	int rdv_row[4];
	char rdv_addr[4][80];
};

static void on_net_reset(void *arg, int family)
{
	(void)family;
	((struct watcher *)arg)->resets++;
}

static void on_net(void *arg, int family, int scope, int via,
		   const char *addr)
{
	struct watcher *w = arg;

	(void)family;
	(void)scope;
	(void)via;
	snprintf(w->last_row, sizeof(w->last_row), "%s", addr);
	w->rows++;
}

static void on_net_conn(void *arg, int family, int status)
{
	struct watcher *w = arg;

	w->conn_family = family;
	w->conn_state = status;
	w->conns++;
}

static void on_link_reset(void *arg)
{
	((struct watcher *)arg)->link_resets++;
}

static void on_link(void *arg, const char *ifname, int have4, int have6)
{
	struct watcher *w = arg;

	(void)have4;
	(void)have6;
	snprintf(w->last_link, sizeof(w->last_link), "%s", ifname);
	w->links++;
}

static void on_mailbox(void *arg, const struct session_mailbox *m)
{
	struct watcher *w = arg;

	w->last_mailbox = *m;
	w->mailboxes++;
}

static void on_rendezvous(void *arg, int family, const char *addr, int ready)
{
	struct watcher *w = arg;

	assert(w->rdv_calls < 4);
	w->rdv_family[w->rdv_calls] = family;
	w->rdv_row[w->rdv_calls] = ready;
	snprintf(w->rdv_addr[w->rdv_calls], sizeof(w->rdv_addr[0]), "%s", addr);
	w->rdv_calls++;
}

static void obs_of(struct session_obs *o, struct watcher *w)
{
	memset(o, 0, sizeof(*o));
	o->net_reset = on_net_reset;
	o->net = on_net;
	o->net_conn = on_net_conn;
	o->link_reset = on_link_reset;
	o->link = on_link;
	o->mailbox = on_mailbox;
	o->rendezvous = on_rendezvous;
	o->arg = w;
}

static void v6_node(struct sockaddr_in6 *sa, uint8_t last)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons(6881);
	sa->sin6_addr.s6_addr[0] = 0x20;
	sa->sin6_addr.s6_addr[1] = 0x01;
	sa->sin6_addr.s6_addr[15] = last;
}

/* Rows are rebuilt rather than added to, so an address the kernel has stopped
 * reporting can go away again. The text a watcher sees is the model's. */
static void rows_are_rebuilt_whole(void)
{
	struct session_obs o;
	struct watcher w;
	struct obsemit e;
	struct netstate ns;
	uint8_t raw[4] = { 203, 0, 113, 7 };

	memset(&w, 0, sizeof(w));
	obs_of(&o, &w);
	netstate_init(&ns, 1, 1000);
	obsemit_init(&e, &o, &ns);

	obsemit_rows(&e, 4);
	assert(w.resets == 1);
	assert(!w.rows);

	netstate_on_reflexive(&ns, 4, netstate_epoch(&ns, 4), raw, 4);
	obsemit_rows(&e, 4);
	assert(w.resets == 2);
	assert(w.rows == 1);
	assert(!strcmp(w.last_row, "203.0.113.7"));
}

/* A watcher that does not want a thing is not told it, and a missing observer
 * is not a special case anywhere. */
static void a_watcher_that_asks_for_nothing_is_told_nothing(void)
{
	struct sig_mailbox sm;
	struct session_obs o;
	struct watcher w;
	struct obsemit e;
	struct netstate ns;

	memset(&w, 0, sizeof(w));
	memset(&o, 0, sizeof(o));
	memset(&sm, 0, sizeof(sm));
	o.arg = &w;
	netstate_init(&ns, 1, 1000);

	obsemit_init(&e, &o, &ns);
	obsemit_rows(&e, 4);
	obsemit_conn(&e, 4, NET_CONN_UP);
	obsemit_links(&e, NULL, 0);
	obsemit_mailbox(&e, &sm, 1000);
	obsemit_rendezvous(&e, 1, 1);

	obsemit_init(&e, NULL, &ns);
	obsemit_rows(&e, 4);
	obsemit_conn(&e, 4, NET_CONN_UP);
	obsemit_links(&e, NULL, 0);
	obsemit_mailbox(&e, &sm, 1000);
	obsemit_rendezvous(&e, 1, 1);
	assert(!w.resets && !w.rows && !w.conns && !w.links && !w.mailboxes &&
	       !w.rdv_calls);
}

static void the_connectivity_verdict_is_passed_on(void)
{
	struct session_obs o;
	struct watcher w;
	struct obsemit e;
	struct netstate ns;

	memset(&w, 0, sizeof(w));
	obs_of(&o, &w);
	netstate_init(&ns, 1, 1000);
	obsemit_init(&e, &o, &ns);

	obsemit_conn(&e, 6, NET_CONN_UP);
	assert(w.conns == 1);
	assert(w.conn_family == 6);
	assert(w.conn_state == NET_CONN_UP);
}

/* The interfaces are re-sent whole, because a cable going in or out changes
 * which exist. */
static void the_interfaces_are_sent_whole(void)
{
	struct sig_mcast_if ifs[2];
	struct session_obs o;
	struct watcher w;
	struct obsemit e;
	struct netstate ns;

	memset(&w, 0, sizeof(w));
	memset(ifs, 0, sizeof(ifs));
	snprintf(ifs[0].name, sizeof(ifs[0].name), "eth0");
	snprintf(ifs[1].name, sizeof(ifs[1].name), "wlan0");
	obs_of(&o, &w);
	netstate_init(&ns, 1, 1000);
	obsemit_init(&e, &o, &ns);

	obsemit_links(&e, ifs, 2);
	assert(w.link_resets == 1);
	assert(w.links == 2);
	assert(!strcmp(w.last_link, "wlan0"));

	obsemit_links(&e, ifs, 1);
	assert(w.link_resets == 2);
	assert(w.links == 3);
	assert(!strcmp(w.last_link, "eth0"));
}

/* The mailbox is said when it changes, and not otherwise. */
static void the_mailbox_is_said_only_when_it_moves(void)
{
	struct sig_mailbox sm;
	struct session_obs o;
	struct watcher w;
	struct obsemit e;
	struct netstate ns;

	memset(&w, 0, sizeof(w));
	memset(&sm, 0, sizeof(sm));
	obs_of(&o, &w);
	netstate_init(&ns, 1, 1000);
	obsemit_init(&e, &o, &ns);

	sm.engaged = 1;
	sm.stage = RDV_GET;
	sm.seq = 3;
	sm.last_get_ms = 1000;
	obsemit_mailbox(&e, &sm, 6000);
	assert(w.mailboxes == 1);
	assert(w.last_mailbox.stage == RDV_GET);
	assert(w.last_mailbox.age_get_s == 5);
	assert(w.last_mailbox.age_put_s == -1);	/* never stored */

	obsemit_mailbox(&e, &sm, 6000);
	assert(w.mailboxes == 1);		/* unchanged, unsaid */

	sm.peer_seen = 1;
	obsemit_mailbox(&e, &sm, 6000);
	assert(w.mailboxes == 2);
	assert(w.last_mailbox.peer_seen);
}

/*
 * A node held but unproven is being checked; one an end that can reach it
 * proved is vouched for; a family with nothing is mentioned only while one is
 * being looked for.
 */
static void a_rendezvous_row_says_what_is_known_of_the_node(void)
{
	struct sockaddr_in6 node;
	struct session_obs o;
	struct watcher w;
	struct obsemit e;
	struct netstate ns;

	memset(&w, 0, sizeof(w));
	obs_of(&o, &w);
	netstate_init(&ns, 1, 1000);
	obsemit_init(&e, &o, &ns);

	obsemit_rendezvous(&e, 0, 0);
	assert(!w.rdv_calls);			/* nothing held, none looked for */

	obsemit_rendezvous(&e, 1, 0);
	assert(w.rdv_calls == 1);
	assert(w.rdv_family[0] == 4);
	assert(w.rdv_row[0] == RDV_ROW_CHECKING);
	assert(!w.rdv_addr[0][0]);

	w.rdv_calls = 0;
	v6_node(&node, 9);
	netstate_on_rdv_vouched(&ns, 6, (const uint8_t *)&node, sizeof(node),
				1000);
	obsemit_rendezvous(&e, 0, 0);
	assert(w.rdv_calls == 1);
	assert(w.rdv_family[0] == 6);
	assert(w.rdv_row[0] == RDV_ROW_VOUCHED);
	assert(!strcmp(w.rdv_addr[0], "2001::9:6881"));
}

int main(void)
{
	/* The row text a watcher is told is the model's, and this case runs on
	 * Windows too, where the socket library comes up before anything else. */
	assert(!wsock_init());
	rows_are_rebuilt_whole();
	a_watcher_that_asks_for_nothing_is_told_nothing();
	the_connectivity_verdict_is_passed_on();
	the_interfaces_are_sent_whole();
	the_mailbox_is_said_only_when_it_moves();
	a_rendezvous_row_says_what_is_known_of_the_node();
	printf("obsemit_test: ok\n");

	return 0;
}
