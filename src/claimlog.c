/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "claimlog.h"

void claimlog_note(struct claimlog *l, const char *ufrag, const char *pwd)
{
	struct claimlog_entry *e;

	if (!ufrag || !pwd || !ufrag[0] || !pwd[0])
		return;
	if (claimlog_seen(l, ufrag, pwd))
		return;
	e = &l->e[l->next];
	memset(e, 0, sizeof(*e));
	strncpy(e->ufrag, ufrag, sizeof(e->ufrag) - 1);
	strncpy(e->pwd, pwd, sizeof(e->pwd) - 1);
	l->next = (l->next + 1) % CLAIMLOG_MAX;
}

int claimlog_seen(const struct claimlog *l, const char *ufrag,
		  const char *pwd)
{
	int i;

	if (!ufrag || !pwd || !ufrag[0] || !pwd[0])
		return 0;
	for (i = 0; i < CLAIMLOG_MAX; i++)
		if (!strcmp(l->e[i].ufrag, ufrag) &&
		    !strcmp(l->e[i].pwd, pwd))
			return 1;
	return 0;
}

int claim_made(const char *conn_pwd, const char *claim_pwd)
{
	if (!conn_pwd || !claim_pwd || !conn_pwd[0] || !claim_pwd[0])
		return 0;
	return !strcmp(conn_pwd, claim_pwd);
}
