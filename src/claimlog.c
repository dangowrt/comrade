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

static int served_find(const struct claim_served *l, const char *ufrag)
{
	int i;

	if (!ufrag || !ufrag[0])
		return -1;
	for (i = 0; i < CLAIM_SERVED_MAX; i++)
		if (!strcmp(l->ufrag[i], ufrag))
			return i;
	return -1;
}

void claim_served_note(struct claim_served *l, const char *ufrag,
		       const char *pwd)
{
	int i = served_find(l, ufrag);

	if (!ufrag || !ufrag[0])
		return;
	if (i < 0) {
		i = l->next;
		l->next = (l->next + 1) % CLAIM_SERVED_MAX;
		memset(l->ufrag[i], 0, CLAIM_UFRAG_LEN);
		strncpy(l->ufrag[i], ufrag, CLAIM_UFRAG_LEN - 1);
	}
	memset(l->pwd[i], 0, CLAIM_PWD_LEN);
	if (pwd)
		strncpy(l->pwd[i], pwd, CLAIM_PWD_LEN - 1);
}

int claim_served_has(const struct claim_served *l, const char *ufrag)
{
	return served_find(l, ufrag) >= 0;
}

int claim_served_made(const struct claim_served *l, const char *ufrag,
		      const char *pwd)
{
	int i = served_find(l, ufrag);

	return i >= 0 && claim_made(l->pwd[i], pwd);
}
