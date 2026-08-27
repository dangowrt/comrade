/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "claimlog.h"

int claim_made(const char *conn_pwd, const char *claim_pwd)
{
	if (!conn_pwd || !claim_pwd || !conn_pwd[0] || !claim_pwd[0])
		return 0;
	return !strcmp(conn_pwd, claim_pwd);
}

void claim_served_note(struct claim_served *l, const char *ufrag)
{
	if (!ufrag || !ufrag[0] || claim_served_has(l, ufrag))
		return;
	memset(l->ufrag[l->next], 0, CLAIM_UFRAG_LEN);
	strncpy(l->ufrag[l->next], ufrag, CLAIM_UFRAG_LEN - 1);
	l->next = (l->next + 1) % CLAIM_SERVED_MAX;
}

int claim_served_has(const struct claim_served *l, const char *ufrag)
{
	int i;

	if (!ufrag || !ufrag[0])
		return 0;
	for (i = 0; i < CLAIM_SERVED_MAX; i++)
		if (!strcmp(l->ufrag[i], ufrag))
			return 1;
	return 0;
}
