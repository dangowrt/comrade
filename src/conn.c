/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conn.h"
#include "oscompat.h"

int conn_write(const char *path, const struct conn_status *st)
{
	char tmp[700];
	FILE *f;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	/* stdio rather than open()+dprintf(): dprintf is POSIX-only and the
	 * write is one short line, so the buffering costs nothing. */
	f = fopen(tmp, "w");
	if (!f)
		return -1;
	/* Append-only: an older reader stops at the last field it knows and a
	 * newer one reading an older line leaves the rest zero, so the host's
	 * service and a differently-versioned operator process still read each
	 * other. */
	fprintf(f, "%d\t%s\t%s\t%d\t%d\t%s\t%d\t%s\t%d\n", st->state,
		st->peer[0] ? st->peer : "-", st->rdv[0] ? st->rdv : "-",
		st->rtt_ms, st->since_s, st->rdv6[0] ? st->rdv6 : "-",
		st->read_only, st->alt[0] ? st->alt : "-", st->warm_alt);
	fclose(f);
	if (os_rename_replace(tmp, path)) {
		remove(tmp);
		return -1;
	}
	return 0;
}

int conn_read(const char *path, struct conn_status *st)
{
	FILE *f = fopen(path, "r");
	char line[600], *nl, *tok;
	int i = 0;

	if (!f)
		return -1;
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	memset(st, 0, sizeof(*st));
	nl = strchr(line, '\n');
	if (nl)
		*nl = '\0';
	for (tok = strtok(line, "\t"); tok; tok = strtok(NULL, "\t"), i++) {
		switch (i) {
		case 0:
			st->state = atoi(tok);
			break;
		case 1:
			if (strcmp(tok, "-"))
				snprintf(st->peer, sizeof(st->peer), "%s", tok);
			break;
		case 2:
			if (strcmp(tok, "-"))
				snprintf(st->rdv, sizeof(st->rdv), "%s", tok);
			break;
		case 3:
			st->rtt_ms = atoi(tok);
			break;
		case 4:
			st->since_s = atoi(tok);
			break;
		case 5:
			if (strcmp(tok, "-"))
				snprintf(st->rdv6, sizeof(st->rdv6), "%s", tok);
			break;
		case 6:
			st->read_only = atoi(tok);
			break;
		case 7:
			if (strcmp(tok, "-"))
				snprintf(st->alt, sizeof(st->alt), "%s", tok);
			break;
		case 8:
			st->warm_alt = atoi(tok);
			break;
		default:
			break;
		}
	}
	return 0;
}
