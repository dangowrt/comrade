/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "conn.h"

int conn_write(const char *path, const struct conn_status *st)
{
	char tmp[600];
	int fd;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	dprintf(fd, "%d\t%s\t%s\t%d\t%d\t%s\n", st->state,
		st->peer[0] ? st->peer : "-", st->rdv[0] ? st->rdv : "-",
		st->rtt_ms, st->since_s, st->rdv6[0] ? st->rdv6 : "-");
	close(fd);
	if (rename(tmp, path)) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

int conn_read(const char *path, struct conn_status *st)
{
	FILE *f = fopen(path, "r");
	char line[512], *nl, *tok;
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
		default:
			break;
		}
	}
	return 0;
}
